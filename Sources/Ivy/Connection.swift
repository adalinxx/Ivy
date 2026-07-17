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

final class PeerConnection: @unchecked Sendable {
    static let maxInboundBufferedRecords = 256
    static let inboundBufferByteBudget = 4 * Int(IvyConfig.protocolMaxFrameSize)

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
    private var inboundAdmission: InboundAdmissionLease?
    private let inbound: AsyncStream<Data>
    private let inboundContinuation: AsyncStream<Data>.Continuation

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
        inboundAdmission: InboundAdmissionLease? = nil
    ) {
        self.endpoint = endpoint
        self.transport = .direct(channel)
        self.inboundAdmission = inboundAdmission
        self.inboundBufferLimit = Self.bufferLimit
        (self.inbound, self.inboundContinuation) = AsyncStream<Data>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
    }

    init(
        endpoint: PeerEndpoint,
        routeID: Data,
        carrier: PeerKey
    ) {
        self.endpoint = endpoint
        self.transport = .relayed(routeID: routeID, carrier: carrier)
        self.inboundBufferLimit = Self.bufferLimit
        (self.inbound, self.inboundContinuation) = AsyncStream<Data>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
    }

    private static var bufferLimit: Int {
        max(1, min(
            maxInboundBufferedRecords,
            inboundBufferByteBudget / Int(IvyConfig.protocolMaxFrameSize)))
    }

    static func dial(
        endpoint: PeerEndpoint,
        group: EventLoopGroup
    ) async throws -> PeerConnection {
        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.seconds(5))
            .channelInitializer { channel in
                channel.pipeline.addHandler(SessionFrameDecoder())
            }

        let channel = try await bootstrap.connect(host: endpoint.host, port: Int(endpoint.port)).get()
        let connection = PeerConnection(endpoint: endpoint, channel: channel)
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

    var records: AsyncStream<Data> { inbound }
    var isDirect: Bool { if case .direct = transport { return true }; return false }
    var isLive: Bool { !isClosed && (channel?.isActive ?? true) }

    private var isClosed: Bool {
        stateLock.withLock { closed }
    }

    private func markClosed() -> Bool {
        stateLock.withLock {
            guard !closed else { return false }
            closed = true
            return true
        }
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
        guard !isClosed else { return false }
        switch inboundContinuation.yield(data) {
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
        guard markClosed() else { return }
        releaseInboundAdmission()
        inboundContinuation.finish()
    }

    func cancel() {
        guard markClosed() else { return }
        releaseInboundAdmission()
        channel?.close(promise: nil)
        inboundContinuation.finish()
    }
}

final class SessionFrameDecoder: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = Data

    private let maxFrameSize: UInt32
    private var buffer = ByteBuffer()

    init(maxFrameSize: UInt32 = IvyConfig.protocolMaxFrameSize) {
        self.maxFrameSize = maxFrameSize
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        buffer.writeBuffer(&incoming)

        while buffer.readableBytes >= 4 {
            guard let length = buffer.getInteger(
                at: buffer.readerIndex,
                endianness: .big,
                as: UInt32.self) else { break }
            guard length > 0, length <= maxFrameSize else {
                context.close(promise: nil)
                return
            }
            guard buffer.readableBytes >= 4 + Int(length) else { break }
            buffer.moveReaderIndex(forwardBy: 4)
            guard let data = buffer.readData(length: Int(length)) else { break }
            context.fireChannelRead(wrapInboundOut(data))
        }
        buffer.discardReadBytes()
    }
}

final class PeerChannelHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = Data

    let connection: PeerConnection

    init(connection: PeerConnection) {
        self.connection = connection
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if !connection.feedRecord(unwrapInboundIn(data)) {
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
    typealias InboundIn = Data

    let ivy: Ivy
    private let generation: UInt64
    private let admissionGate: InboundAdmissionGate
    private var connection: PeerConnection?

    init(
        ivy: Ivy,
        generation: UInt64,
        admissionGate: InboundAdmissionGate
    ) {
        self.ivy = ivy
        self.generation = generation
        self.admissionGate = admissionGate
    }

    func channelActive(context: ChannelHandlerContext) {
        guard connection == nil else { return }
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
            inboundAdmission: lease)
        connection.observedHost = observedHost
        self.connection = connection
        Task {
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
        if connection?.feedRecord(unwrapInboundIn(data)) == false {
            context.close(promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        connection?.connectionClosed()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
