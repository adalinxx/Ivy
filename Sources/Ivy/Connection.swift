import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix

final class PeerConnection: @unchecked Sendable {
    static let maxInboundBufferedRecords = 256
    static let inboundBufferByteBudget = Int(IvyConfig.maximumFrameSize)

    let connectionID = UUID()
    var endpoint: PeerEndpoint
    var observedHost: String?

    enum Transport {
        case direct(Channel)
        case relayed(routeID: Data, carrier: PeerKey)
    }

    let transport: Transport
    private let maxFrameSize: UInt32
    let inboundBufferLimit: Int
    private let stateLock = NSLock()
    private var closed = false
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
        maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize
    ) {
        self.endpoint = endpoint
        self.transport = .direct(channel)
        self.maxFrameSize = maxFrameSize
        self.inboundBufferLimit = Self.bufferLimit(for: maxFrameSize)
        (self.inbound, self.inboundContinuation) = AsyncStream<Data>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
    }

    init(
        endpoint: PeerEndpoint,
        routeID: Data,
        carrier: PeerKey,
        maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize
    ) {
        self.endpoint = endpoint
        self.transport = .relayed(routeID: routeID, carrier: carrier)
        self.maxFrameSize = maxFrameSize
        self.inboundBufferLimit = Self.bufferLimit(for: maxFrameSize)
        (self.inbound, self.inboundContinuation) = AsyncStream<Data>.makeStream(
            bufferingPolicy: .bufferingOldest(inboundBufferLimit))
    }

    private static func bufferLimit(for maxFrameSize: UInt32) -> Int {
        let frameSize = max(1, Int(maxFrameSize))
        return max(1, min(maxInboundBufferedRecords, inboundBufferByteBudget / frameSize))
    }

    static func dial(
        endpoint: PeerEndpoint,
        group: EventLoopGroup,
        maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize
    ) async throws -> PeerConnection {
        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.seconds(5))
            .channelInitializer { channel in
                channel.pipeline.addHandler(SessionFrameDecoder(maxFrameSize: maxFrameSize))
            }

        let channel = try await bootstrap.connect(host: endpoint.host, port: Int(endpoint.port)).get()
        let connection = PeerConnection(endpoint: endpoint, channel: channel, maxFrameSize: maxFrameSize)
        connection.observedHost = channel.remoteAddress?.ipAddress
        try await channel.pipeline.addHandler(PeerChannelHandler(connection: connection)).get()
        return connection
    }

    @discardableResult
    func sendRecord(_ record: SessionWireRecord) -> Bool {
        sendSerializedRecord(record.serialize(maxPayload: maxFrameSize))
    }

    @discardableResult
    func sendSerializedRecord(_ payload: Data) -> Bool {
        guard !isClosed, !payload.isEmpty, payload.count <= Int(maxFrameSize) else { return false }
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
        inboundContinuation.finish()
    }

    func cancel() {
        guard markClosed() else { return }
        channel?.close(promise: nil)
        inboundContinuation.finish()
    }
}

final class SessionFrameDecoder: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = Data

    private let maxFrameSize: UInt32
    private var buffer = ByteBuffer()

    init(maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize) {
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
    private let maxFrameSize: UInt32
    private var connection: PeerConnection?

    init(ivy: Ivy, maxFrameSize: UInt32) {
        self.ivy = ivy
        self.maxFrameSize = maxFrameSize
    }

    func channelActive(context: ChannelHandlerContext) {
        guard connection == nil else { return }
        let endpoint = PeerEndpoint(publicKey: "", host: "unknown", port: 0)
        let connection = PeerConnection(
            endpoint: endpoint,
            channel: context.channel,
            maxFrameSize: maxFrameSize)
        connection.observedHost = context.channel.remoteAddress?.ipAddress
        self.connection = connection
        Task { await ivy.registerInboundConnection(connection) }
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
