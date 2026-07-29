import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix

final class InboundAdmissionGate: @unchecked Sendable {
    private let lock = NSLock()
    private let maxConnections: Int
    private let maxConnectionsPerNetgroup: Int
    private var accepting = true
    private var count = 0
    private var countsByNetgroup: [String: Int] = [:]

    init(maxConnections: Int, maxConnectionsPerNetgroup: Int) {
        self.maxConnections = maxConnections
        self.maxConnectionsPerNetgroup = maxConnectionsPerNetgroup
    }

    func reserve(observedHost: String?) -> InboundAdmissionLease? {
        let netgroup = NetGroup.group(observedHost ?? "unknown")
        return lock.withLock {
            guard accepting,
                  count < maxConnections,
                  countsByNetgroup[netgroup, default: 0] < maxConnectionsPerNetgroup else {
                return nil
            }
            count += 1
            countsByNetgroup[netgroup, default: 0] += 1
            return InboundAdmissionLease { [weak self] in self?.release(netgroup: netgroup) }
        }
    }

    func invalidate() {
        lock.withLock { accepting = false }
    }

    private func release(netgroup: String) {
        lock.withLock {
            count -= 1
            if countsByNetgroup[netgroup] == 1 {
                countsByNetgroup.removeValue(forKey: netgroup)
            } else {
                countsByNetgroup[netgroup, default: 0] -= 1
            }
        }
    }
}

final class InboundAdmissionLease: @unchecked Sendable {
    private let lock = NSLock()
    private var releaseAction: (() -> Void)?

    init(release: @escaping () -> Void) {
        releaseAction = release
    }

    func release() {
        let action = lock.withLock { () -> (() -> Void)? in
            defer { releaseAction = nil }
            return releaseAction
        }
        action?()
    }

    deinit { release() }
}

final class InboundByteBudget: @unchecked Sendable {
    private let lock = NSLock()
    let limit: Int
    private var used = 0

    init(limit: Int) {
        self.limit = limit
    }

    fileprivate func reserve(_ byteCount: Int) -> Bool {
        guard byteCount >= 0 else { return false }
        return lock.withLock {
            guard byteCount <= limit - used else { return false }
            used += byteCount
            return true
        }
    }

    var currentUsage: Int { lock.withLock { used } }

    fileprivate func release(_ byteCount: Int) {
        lock.withLock { used -= byteCount }
    }
}

final class InboundByteReservation: @unchecked Sendable {
    private let budgets: [InboundByteBudget]
    private var byteCount = 0

    init(budgets: [InboundByteBudget]) {
        self.budgets = budgets
    }

    func acquire(_ count: Int) -> Bool {
        var acquired: [InboundByteBudget] = []
        for budget in budgets {
            guard budget.reserve(count) else {
                for budget in acquired { budget.release(count) }
                return false
            }
            acquired.append(budget)
        }
        byteCount += count
        return true
    }

    deinit {
        for budget in budgets { budget.release(byteCount) }
    }
}

struct InboundFrame: Sendable {
    let bytes: Data
    private let reservation: InboundByteReservation

    init(bytes: Data, reservation: InboundByteReservation) {
        self.bytes = bytes
        self.reservation = reservation
    }
}

/// Carries the connection built inside a transport's channel initializer back to the dialer.
private final class DialedConnectionBox: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: PeerConnection?

    func store(_ connection: PeerConnection) {
        lock.withLock { self.connection = connection }
    }

    func take() -> PeerConnection? {
        lock.withLock {
            defer { connection = nil }
            return connection
        }
    }
}

private final class WritabilityWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Bool, Never>?
    private var result: Bool?

    func install(_ continuation: CheckedContinuation<Bool, Never>) {
        let result = lock.withLock { () -> Bool? in
            guard let result = self.result else {
                self.continuation = continuation
                return nil
            }
            return result
        }
        if let result { continuation.resume(returning: result) }
    }

    func resume(_ result: Bool) {
        let continuation = lock.withLock { () -> CheckedContinuation<Bool, Never>? in
            guard self.result == nil else { return nil }
            self.result = result
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume(returning: result)
    }
}

final class PeerConnection: TransportConnectionSink, @unchecked Sendable {
    static let maxInboundBufferedRecords = 4
    static let maxInboundBufferedBytes = 2 * Int(IvyConfig.protocolMaxFrameSize) + 4

    let connectionID = UUID()
    var endpoint: PeerEndpoint
    var observedHost: String?
    /// Whether this node accepted the connection rather than dialing it. Fixed at
    /// construction, so it cannot race with session bookkeeping.
    let isAccepted: Bool

    enum Transport {
        case direct(any TransportConnection)
        case relayed(routeID: Data, carrier: PeerKey)
    }

    enum SendResult: Sendable, Equatable {
        case sent
        case backpressured
        case locallyRejected
        case notConnected
    }

    enum SendReadiness: Sendable, Equatable {
        case ready
        case backpressured
        case notConnected
    }

    let transport: Transport
    let inboundBufferLimit: Int
    private let stateLock = NSLock()
    private var closed = false
    private var writable: Bool
    private var closeHandler: (@Sendable () -> Void)?
    private var writabilityWaiters: [UUID: WritabilityWaiter] = [:]
    private var inboundAdmission: InboundAdmissionLease?
    private let inboundByteBudget: InboundByteBudget
    private let connectionInboundByteBudget: InboundByteBudget
    private var accumulator: FrameAccumulator?
    private var pendingFrames: [InboundFrame] = []
    private let inbound: AsyncStream<InboundFrame>
    private let inboundContinuation: AsyncStream<InboundFrame>.Continuation

    var directConnection: (any TransportConnection)? {
        guard case .direct(let connection) = transport else { return nil }
        return connection
    }

    /// Address this connection leaves from, which a hole punch advertises.
    var localHost: String? { directConnection?.localHost }

    var route: AuthenticatedRoute {
        switch transport {
        case .direct:
            return .direct
        case .relayed(let routeID, let carrier):
            return .relayed(carrier: carrier, routeID: routeID)
        }
    }

    init(
        endpoint: PeerEndpoint,
        connection: any TransportConnection,
        inboundAdmission: InboundAdmissionLease? = nil,
        inboundByteBudget: InboundByteBudget = InboundByteBudget(
            limit: IvyConfig.defaultMaxInboundBufferedBytes),
        connectionInboundByteBudget: InboundByteBudget? = nil,
        isAccepted: Bool = false
    ) {
        self.endpoint = endpoint
        self.isAccepted = isAccepted
        self.transport = .direct(connection)
        self.writable = connection.isWritable
        self.inboundAdmission = inboundAdmission
        self.inboundByteBudget = inboundByteBudget
        let connectionBudget = connectionInboundByteBudget
            ?? InboundByteBudget(limit: Self.maxInboundBufferedBytes)
        self.connectionInboundByteBudget = connectionBudget
        self.inboundBufferLimit = Self.maxInboundBufferedRecords
        (self.inbound, self.inboundContinuation) = AsyncStream<InboundFrame>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
        self.accumulator = FrameAccumulator(
            maxFrameSize: IvyConfig.protocolMaxFrameSize,
            budgets: [connectionBudget, inboundByteBudget])
        connection.attach(self)
    }

    /// Builds a connection over a NIO channel, installing the handler that feeds
    /// it. Used by tests and by any caller that already holds a channel.
    convenience init(
        endpoint: PeerEndpoint,
        channel: Channel,
        inboundAdmission: InboundAdmissionLease? = nil,
        inboundByteBudget: InboundByteBudget = InboundByteBudget(
            limit: IvyConfig.defaultMaxInboundBufferedBytes),
        connectionInboundByteBudget: InboundByteBudget? = nil,
        isAccepted: Bool = false
    ) {
        let transportConnection = NIOTransportConnection(channel: channel)
        self.init(
            endpoint: endpoint,
            connection: transportConnection,
            inboundAdmission: inboundAdmission,
            inboundByteBudget: inboundByteBudget,
            connectionInboundByteBudget: connectionInboundByteBudget,
            isAccepted: isAccepted)
        // Not `syncOperations`: the caller may not be on the channel's loop.
        channel.pipeline.addHandler(
            NIOTransportHandler(connection: transportConnection),
            position: .last
        ).whenComplete { _ in }
        observedHost = transportConnection.observedHost
    }

    init(
        endpoint: PeerEndpoint,
        routeID: Data,
        carrier: PeerKey,
        inboundByteBudget: InboundByteBudget = InboundByteBudget(
            limit: IvyConfig.defaultMaxInboundBufferedBytes),
        connectionInboundByteBudget: InboundByteBudget? = nil,
        isAccepted: Bool = false
    ) {
        self.endpoint = endpoint
        self.isAccepted = isAccepted
        self.transport = .relayed(routeID: routeID, carrier: carrier)
        self.writable = false
        self.inboundByteBudget = inboundByteBudget
        self.connectionInboundByteBudget = connectionInboundByteBudget
            ?? InboundByteBudget(limit: Self.maxInboundBufferedBytes)
        self.inboundBufferLimit = Self.maxInboundBufferedRecords
        (self.inbound, self.inboundContinuation) = AsyncStream<InboundFrame>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
    }

    static func dial(
        endpoint: PeerEndpoint,
        transport: any IvyTransport,
        group: EventLoopGroup,
        inboundByteBudget: InboundByteBudget,
        boundToPort: UInt16? = nil
    ) async throws -> PeerConnection {
        let transportConnection = try await transport.dial(
            host: endpoint.host,
            port: endpoint.port,
            group: group,
            boundToPort: boundToPort)
        let connection = PeerConnection(
            endpoint: endpoint,
            connection: transportConnection,
            inboundByteBudget: inboundByteBudget)
        connection.observedHost = transportConnection.observedHost
        return connection
    }

    @discardableResult
    func sendRecord(_ record: SessionWireRecord) -> SendResult {
        sendSerializedRecord(record.serialize())
    }

    @discardableResult
    func sendSerializedRecord(_ payload: Data) -> SendResult {
        guard !payload.isEmpty,
              payload.count <= Int(IvyConfig.protocolMaxFrameSize) else {
            return .locallyRejected
        }
        switch sendReadiness() {
        case .ready:
            break
        case .backpressured:
            return .backpressured
        case .notConnected:
            return .notConnected
        }
        switch transport {
        case .direct(let connection):
            var framed = Data()
            framed.appendUInt32(UInt32(payload.count))
            framed.append(payload)
            connection.send(framed)
        case .relayed:
            return .notConnected
        }
        return .sent
    }

    func sendReadiness() -> SendReadiness {
        stateLock.withLock {
            guard !closed else { return .notConnected }
            return writable ? .ready : .backpressured
        }
    }

    func waitUntilWritable() async -> Bool {
        guard directConnection != nil else { return false }
        let id = UUID()
        let waiter = WritabilityWaiter()
        let result = stateLock.withLock { () -> Bool? in
            guard !closed else { return false }
            guard !writable else { return true }
            writabilityWaiters[id] = waiter
            return nil
        }
        if let result { return result }
        return await withTaskCancellationHandler(operation: {
            await withCheckedContinuation { waiter.install($0) }
        }, onCancel: {
            self.finishWritabilityWaiter(id, result: false)
        })
    }

    func channelWritabilityChanged(isWritable: Bool) {
        let waiters = stateLock.withLock { () -> [WritabilityWaiter] in
            guard !closed else { return [] }
            writable = isWritable
            guard isWritable else { return [] }
            let waiters = Array(writabilityWaiters.values)
            writabilityWaiters.removeAll()
            return waiters
        }
        for waiter in waiters { waiter.resume(true) }
    }

    var records: AsyncStream<InboundFrame> { inbound }
    var isDirect: Bool { if case .direct = transport { return true }; return false }
    var isLive: Bool { !isClosed && (directConnection?.isActive ?? true) }

    private var isClosed: Bool {
        stateLock.withLock { closed }
    }

    private func markClosed() -> (
        didClose: Bool,
        closeHandler: (@Sendable () -> Void)?
    ) {
        stateLock.withLock {
            guard !closed else { return (false, nil) }
            closed = true
            defer { closeHandler = nil }
            return (true, closeHandler)
        }
    }

    private func finishWritabilityWaiter(_ id: UUID, result: Bool) {
        let waiter = stateLock.withLock { writabilityWaiters.removeValue(forKey: id) }
        waiter?.resume(result)
    }

    private func finishWritabilityWaiters(result: Bool) {
        let waiters = stateLock.withLock { () -> [WritabilityWaiter] in
            let waiters = Array(writabilityWaiters.values)
            writabilityWaiters.removeAll()
            return waiters
        }
        for waiter in waiters { waiter.resume(result) }
    }

    func installCloseHandler(_ handler: @escaping @Sendable () -> Void) {
        let invokeNow = stateLock.withLock {
            if closed { return true }
            guard closeHandler == nil else { return false }
            closeHandler = handler
            return false
        }
        if invokeNow { handler() }
    }

    func adoptInboundAdmission(_ lease: InboundAdmissionLease) {
        stateLock.withLock { inboundAdmission = lease }
    }

    func releaseInboundAdmission() {
        let lease = stateLock.withLock { () -> InboundAdmissionLease? in
            defer { inboundAdmission = nil }
            return inboundAdmission
        }
        lease?.release()
    }

    @discardableResult
    func feedRecord(_ data: Data) -> Bool {
        let reservation = InboundByteReservation(
            budgets: [connectionInboundByteBudget, inboundByteBudget])
        guard !data.isEmpty,
              data.count <= Int(IvyConfig.protocolMaxFrameSize),
              reservation.acquire(data.count) else {
            cancel()
            return false
        }
        return feedFrame(InboundFrame(bytes: data, reservation: reservation))
    }

    @discardableResult
    func feedFrame(_ frame: InboundFrame) -> Bool {
        guard !isClosed else { return false }
        switch inboundContinuation.yield(frame) {
        case .enqueued:
            return true
        case .dropped, .terminated:
            cancel()
            return false
        @unknown default:
            cancel()
            return false
        }
    }

    // MARK: - TransportConnectionSink

    func transportDidReceive(_ bytes: Data) {
        let outcome = stateLock.withLock { () -> FrameAccumulator.Outcome in
            guard accumulator != nil else { return .incomplete }
            return accumulator!.consume(bytes) { frame in
                pendingFrames.append(frame)
            }
        }
        let frames = stateLock.withLock { () -> [InboundFrame] in
            defer { pendingFrames.removeAll(keepingCapacity: true) }
            return pendingFrames
        }
        for frame in frames {
            guard feedFrame(frame) else { return }
        }
        guard outcome != .failed else {
            cancel()
            return
        }
        // Ask for the next delivery only once this one is handed on, so a slow
        // session stops the peer rather than letting bytes pile up.
        directConnection?.requestBytes()
    }

    func transportWritabilityChanged(isWritable: Bool) {
        channelWritabilityChanged(isWritable: isWritable)
    }

    func transportDidClose() {
        stateLock.withLock { accumulator?.reset() }
        connectionClosed()
    }

    /// Begins reading. Called once admission has granted this connection a slot,
    /// so nothing is read from an unadmitted peer (IVY-001).
    func startReading() {
        directConnection?.requestBytes()
    }

    func connectionClosed() {
        let state = markClosed()
        guard state.didClose else { return }
        releaseInboundAdmission()
        finishWritabilityWaiters(result: false)
        inboundContinuation.finish()
        state.closeHandler?()
    }

    func cancel() {
        let state = markClosed()
        guard state.didClose else { return }
        releaseInboundAdmission()
        finishWritabilityWaiters(result: false)
        directConnection?.close()
        inboundContinuation.finish()
        state.closeHandler?()
    }
}

final class SessionFrameDecoder: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = InboundFrame

    private var accumulator: FrameAccumulator

    init(
        maxFrameSize: UInt32 = IvyConfig.protocolMaxFrameSize,
        budget: InboundByteBudget,
        connectionBudget: InboundByteBudget
    ) {
        accumulator = FrameAccumulator(
            maxFrameSize: maxFrameSize,
            budgets: [connectionBudget, budget])
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        guard let bytes = incoming.readData(length: incoming.readableBytes) else { return }
        let outcome = accumulator.consume(bytes) { frame in
            context.fireChannelRead(self.wrapInboundOut(frame))
        }
        if outcome == .failed {
            context.close(promise: nil)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        accumulator.reset()
    }

    func channelInactive(context: ChannelHandlerContext) {
        accumulator.reset()
        context.fireChannelInactive()
    }
}
