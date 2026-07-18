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

final class PeerConnection: @unchecked Sendable {
    static let maxInboundBufferedRecords = 4
    static let maxInboundBufferedBytes = 2 * Int(IvyConfig.protocolMaxFrameSize) + 4

    let connectionID = UUID()
    var endpoint: PeerEndpoint
    var observedHost: String?

    enum Transport {
        case direct(Channel)
        case relayed(routeID: Data, carrier: PeerKey)
    }

    let transport: Transport
    let inboundBufferLimit: Int
    private let stateLock = NSLock()
    private var closed = false
    private var closeHandler: (@Sendable () -> Void)?
    private var inboundAdmission: InboundAdmissionLease?
    private let inboundByteBudget: InboundByteBudget
    private let connectionInboundByteBudget: InboundByteBudget
    private let inbound: AsyncStream<InboundFrame>
    private let inboundContinuation: AsyncStream<InboundFrame>.Continuation

    var channel: Channel? {
        guard case .direct(let channel) = transport else { return nil }
        return channel
    }

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
        channel: Channel,
        inboundAdmission: InboundAdmissionLease? = nil,
        inboundByteBudget: InboundByteBudget = InboundByteBudget(
            limit: IvyConfig.defaultMaxInboundBufferedBytes),
        connectionInboundByteBudget: InboundByteBudget? = nil
    ) {
        self.endpoint = endpoint
        self.transport = .direct(channel)
        self.inboundAdmission = inboundAdmission
        self.inboundByteBudget = inboundByteBudget
        self.connectionInboundByteBudget = connectionInboundByteBudget
            ?? InboundByteBudget(limit: Self.maxInboundBufferedBytes)
        self.inboundBufferLimit = Self.maxInboundBufferedRecords
        (self.inbound, self.inboundContinuation) = AsyncStream<InboundFrame>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
    }

    init(
        endpoint: PeerEndpoint,
        routeID: Data,
        carrier: PeerKey,
        inboundByteBudget: InboundByteBudget = InboundByteBudget(
            limit: IvyConfig.defaultMaxInboundBufferedBytes),
        connectionInboundByteBudget: InboundByteBudget? = nil
    ) {
        self.endpoint = endpoint
        self.transport = .relayed(routeID: routeID, carrier: carrier)
        self.inboundByteBudget = inboundByteBudget
        self.connectionInboundByteBudget = connectionInboundByteBudget
            ?? InboundByteBudget(limit: Self.maxInboundBufferedBytes)
        self.inboundBufferLimit = Self.maxInboundBufferedRecords
        (self.inbound, self.inboundContinuation) = AsyncStream<InboundFrame>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
    }

    static func dial(
        endpoint: PeerEndpoint,
        group: EventLoopGroup,
        inboundByteBudget: InboundByteBudget
    ) async throws -> PeerConnection {
        let connectionInboundByteBudget = InboundByteBudget(limit: Self.maxInboundBufferedBytes)
        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.seconds(5))
            .channelInitializer { channel in
                channel.pipeline.addHandler(SessionFrameDecoder(
                    budget: inboundByteBudget,
                    connectionBudget: connectionInboundByteBudget))
            }

        let channel = try await bootstrap.connect(host: endpoint.host, port: Int(endpoint.port)).get()
        let connection = PeerConnection(
            endpoint: endpoint,
            channel: channel,
            inboundByteBudget: inboundByteBudget,
            connectionInboundByteBudget: connectionInboundByteBudget)
        connection.observedHost = channel.remoteAddress?.ipAddress
        try await channel.pipeline.addHandler(PeerChannelHandler(connection: connection)).get()
        return connection
    }

    @discardableResult
    func sendRecord(_ record: SessionWireRecord) -> Bool {
        sendSerializedRecord(record.serialize())
    }

    @discardableResult
    func sendSerializedRecord(_ payload: Data) -> Bool {
        guard !isClosed,
              !payload.isEmpty,
              payload.count <= Int(IvyConfig.protocolMaxFrameSize) else { return false }
        switch transport {
        case .direct(let channel):
            guard channel.isActive, channel.isWritable else { return false }
            var buffer = channel.allocator.buffer(capacity: 4 + payload.count)
            buffer.writeInteger(UInt32(payload.count), endianness: .big)
            buffer.writeBytes(payload)
            channel.writeAndFlush(buffer, promise: nil)
        case .relayed:
            return false
        }
        return true
    }

    var records: AsyncStream<InboundFrame> { inbound }
    var isDirect: Bool { if case .direct = transport { return true }; return false }
    var isLive: Bool { !isClosed && (channel?.isActive ?? true) }

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

    func installCloseHandler(_ handler: @escaping @Sendable () -> Void) {
        let invokeNow = stateLock.withLock {
            if closed { return true }
            guard closeHandler == nil else { return false }
            closeHandler = handler
            return false
        }
        if invokeNow { handler() }
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

    func connectionClosed() {
        let state = markClosed()
        guard state.didClose else { return }
        releaseInboundAdmission()
        inboundContinuation.finish()
        state.closeHandler?()
    }

    func cancel() {
        let state = markClosed()
        guard state.didClose else { return }
        releaseInboundAdmission()
        channel?.close(promise: nil)
        inboundContinuation.finish()
        state.closeHandler?()
    }
}

final class SessionFrameDecoder: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = InboundFrame

    private let maxFrameSize: UInt32
    private let budget: InboundByteBudget
    private let connectionBudget: InboundByteBudget
    private var header: [UInt8] = []
    private var headerReservation: InboundByteReservation?
    private var expectedBodyLength: Int?
    private var body = Data()
    private var bodyReservation: InboundByteReservation?

    init(
        maxFrameSize: UInt32 = IvyConfig.protocolMaxFrameSize,
        budget: InboundByteBudget,
        connectionBudget: InboundByteBudget
    ) {
        self.maxFrameSize = maxFrameSize
        self.budget = budget
        self.connectionBudget = connectionBudget
        header.reserveCapacity(4)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)

        while incoming.readableBytes > 0 {
            if expectedBodyLength == nil {
                if header.isEmpty {
                    let reservation = InboundByteReservation(
                        budgets: [connectionBudget, budget])
                    guard reservation.acquire(4) else {
                        close(context)
                        return
                    }
                    headerReservation = reservation
                }
                let count = min(4 - header.count, incoming.readableBytes)
                guard let bytes = incoming.readBytes(length: count) else { return }
                header.append(contentsOf: bytes)
                guard header.count == 4 else { return }

                let length = UInt32(header[0]) << 24
                    | UInt32(header[1]) << 16
                    | UInt32(header[2]) << 8
                    | UInt32(header[3])
                guard length > 0, length <= maxFrameSize else {
                    close(context)
                    return
                }
                expectedBodyLength = Int(length)
                bodyReservation = InboundByteReservation(
                    budgets: [connectionBudget, budget])
                header.removeAll(keepingCapacity: true)
                headerReservation = nil
            }

            guard let expectedBodyLength,
                  let bodyReservation else { continue }
            let count = min(expectedBodyLength - body.count, incoming.readableBytes)
            guard bodyReservation.acquire(count) else {
                close(context)
                return
            }
            guard let bytes = incoming.readData(length: count) else { return }
            body.append(bytes)
            guard body.count == expectedBodyLength else { return }

            let frame = InboundFrame(bytes: body, reservation: bodyReservation)
            body = Data()
            self.bodyReservation = nil
            self.expectedBodyLength = nil
            context.fireChannelRead(wrapInboundOut(frame))
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        reset()
    }

    func channelInactive(context: ChannelHandlerContext) {
        reset()
        context.fireChannelInactive()
    }

    private func close(_ context: ChannelHandlerContext) {
        reset()
        context.close(promise: nil)
    }

    private func reset() {
        header.removeAll(keepingCapacity: true)
        headerReservation = nil
        expectedBodyLength = nil
        body = Data()
        bodyReservation = nil
    }
}

final class PeerChannelHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = InboundFrame

    let connection: PeerConnection

    init(connection: PeerConnection) {
        self.connection = connection
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if !connection.feedFrame(unwrapInboundIn(data)) {
            context.close(promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        connection.connectionClosed()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

final class InboundConnectionAcceptor: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = InboundFrame

    weak var ivy: Ivy?
    private let generation: UInt64
    private let admissionGate: InboundAdmissionGate
    private let inboundByteBudget: InboundByteBudget
    private let connectionInboundByteBudget: InboundByteBudget
    private var connection: PeerConnection?

    init(
        ivy: Ivy,
        generation: UInt64,
        admissionGate: InboundAdmissionGate,
        inboundByteBudget: InboundByteBudget,
        connectionInboundByteBudget: InboundByteBudget
    ) {
        self.ivy = ivy
        self.generation = generation
        self.admissionGate = admissionGate
        self.inboundByteBudget = inboundByteBudget
        self.connectionInboundByteBudget = connectionInboundByteBudget
    }

    func channelActive(context: ChannelHandlerContext) {
        guard connection == nil, let ivy else {
            context.close(promise: nil)
            return
        }
        let channel = context.channel
        let observedHost = channel.remoteAddress?.ipAddress
        guard let lease = admissionGate.reserve(observedHost: observedHost) else {
            context.close(promise: nil)
            return
        }
        let endpoint = PeerEndpoint(publicKey: "", host: "unknown", port: 0)
        let connection = PeerConnection(
            endpoint: endpoint,
            channel: channel,
            inboundAdmission: lease,
            inboundByteBudget: inboundByteBudget,
            connectionInboundByteBudget: connectionInboundByteBudget)
        connection.observedHost = observedHost
        self.connection = connection
        Task { [weak ivy] in
            guard let ivy else {
                connection.cancel()
                return
            }
            guard await ivy.registerInboundConnection(connection, generation: generation) else {
                connection.cancel()
                return
            }
            channel.setOption(ChannelOptions.autoRead, value: true).whenSuccess {
                channel.read()
            }
        }
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if connection?.feedFrame(unwrapInboundIn(data)) == false {
            context.close(promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        connection?.connectionClosed()
        connection = nil
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
