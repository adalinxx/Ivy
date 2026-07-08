import Foundation
import NIOCore
import NIOPosix
import NIOFoundationCompat
import Tally

public final class PeerConnection: @unchecked Sendable {
    static let inboundBufferLimit = 256

    public internal(set) var id: PeerID
    public internal(set) var endpoint: PeerEndpoint
    /// IP address observed on the accepted socket for inbound connections,
    /// independent of any self-advertised endpoint. Diversity/netgroup
    /// accounting reads THIS (never the advertised host) so a peer cannot forge
    /// its network group via the identify frame. Nil for outbound dials.
    public internal(set) var observedHost: String? = nil
    /// nil for a RELAYED connection (frames go through `relayForward` instead of
    /// a direct socket); non-nil for a normal direct TCP connection.
    let channel: Channel?
    /// When set, this connection is relayed: outbound frames are wrapped in a
    /// `relayData` envelope and sent through a relay peer, so identify/want/sync
    /// flow over it exactly like a direct connection. nil for direct connections.
    let relayForward: (@Sendable (Data) -> Void)?
    /// For a relayed connection, the public key the peer CLAIMS (used to route
    /// inbound relayData and to clean up the relay index on teardown). The claim
    /// is unverified until a signed identify re-keys the connection to its real
    /// identity — exactly like a direct inbound `inbound-<uuid>` connection.
    let relayedClaimedKey: String?
    /// For a relayed connection, the carrier connection it is routed through. When
    /// the carrier tears down, the carrier's `handleInbound` teardown reaps every
    /// relayed connection pointing at it (they are channel-less and otherwise
    /// `isLive` forever, so they'd leak a slot). nil for direct connections.
    let relayCarrierConn: PeerConnection?
    private let maxFrameSize: UInt32
    private var closed = false
    /// Last time an inbound frame arrived. For a channel-less RELAYED connection this is the
    /// only liveness signal: a healthy relay circuit delivers the peer's keepalive pongs, so no
    /// inbound for `relayedStaleTimeout` means the circuit is dead even though the carrier is up —
    /// otherwise `isLive` reads `!closed` forever. Updated on `feedMessage`.
    private var lastInboundActivity: ContinuousClock.Instant = .now
    /// Cadence of the dedicated relayed-circuit probe: Ivy pings each relayed connection over
    /// its circuit on this interval, so a HEALTHY circuit sees inbound (the pong) at least
    /// every ~probe interval + RTT. This replaces the old reliance on the health monitor's
    /// idle-gated keepalive (worst case ~240s across two hops) as the inbound floor.
    static let relayedProbeInterval: Duration = .seconds(30)
    /// A relayed connection with no inbound for this long FAILS OVER to another carrier
    /// (`scheduleRelayFailover`). With the probe loop guaranteeing a ~30s inbound floor on a
    /// healthy circuit, 90s means ~3 consecutive unanswered probes — robust to transient loss
    /// yet 3.3x faster than the old passive 300s bound (which had to sit above the health
    /// monitor's worst-case pong cadence because nothing probed the circuit directly).
    static let relayedFailoverTimeout: Duration = .seconds(90)
    /// `isLive` backstop: a relayed conn with no inbound for this long is presumed dead even
    /// if the failover path never ran (e.g. the probe task was lost). Four unanswered probes;
    /// strictly above `relayedFailoverTimeout` so failover always fires first.
    static let relayedStaleTimeout: Duration = .seconds(120)
    private let inbound: AsyncStream<Message>
    private let inboundContinuation: AsyncStream<Message>.Continuation

    init(id: PeerID, endpoint: PeerEndpoint, channel: Channel?, maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize,
         relayForward: (@Sendable (Data) -> Void)? = nil, relayedClaimedKey: String? = nil,
         relayCarrierConn: PeerConnection? = nil) {
        self.id = id
        self.endpoint = endpoint
        self.channel = channel
        self.relayForward = relayForward
        self.relayedClaimedKey = relayedClaimedKey
        self.relayCarrierConn = relayCarrierConn
        self.maxFrameSize = maxFrameSize
        let (stream, continuation) = AsyncStream<Message>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.inboundBufferLimit)
        )
        self.inbound = stream
        self.inboundContinuation = continuation
    }

    public static func dial(
        endpoint: PeerEndpoint,
        group: EventLoopGroup,
        maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize
    ) async throws -> PeerConnection {
        let id = PeerID(publicKey: endpoint.publicKey)

        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.seconds(5))
            .channelInitializer { channel in
                let handler = MessageFrameDecoder(maxFrameSize: maxFrameSize)
                return channel.pipeline.addHandler(handler)
            }

        let channel = try await bootstrap.connect(
            host: endpoint.host,
            port: Int(endpoint.port)
        ).get()

        let peerConn = PeerConnection(id: id, endpoint: endpoint, channel: channel, maxFrameSize: maxFrameSize)
        let peerHandler = PeerChannelHandler(connection: peerConn)
        try await channel.pipeline.addHandler(peerHandler).get()

        return peerConn
    }

    public func send(_ message: Message) async throws {
        let payload = message.serialize(maxFrameSize: maxFrameSize)
        if let relayForward { relayForward(payload); return }
        guard let channel else { return }
        var buf = channel.allocator.buffer(capacity: 4 + payload.count)
        buf.writeInteger(UInt32(payload.count), endianness: .big)
        buf.writeBytes(payload)
        try await channel.writeAndFlush(buf).get()
    }

    public func fireAndForget(_ payload: Data) {
        if let relayForward { relayForward(payload); return }
        guard let channel else { return }
        var buf = channel.allocator.buffer(capacity: 4 + payload.count)
        buf.writeInteger(UInt32(payload.count), endianness: .big)
        buf.writeBytes(payload)
        channel.writeAndFlush(buf, promise: nil)
    }

    public func fireAndForgetMessage(_ message: Message) {
        let payload = message.serialize(maxFrameSize: maxFrameSize)
        fireAndForget(payload)
    }

    public var messages: AsyncStream<Message> { inbound }

    var isLive: Bool {
        if let channel { return channel.isActive || !closed }
        // Relayed (channel-less): live only while un-closed AND recently active. A dead relay
        // circuit stops delivering the peer's keepalives, so inbound goes quiet — reap it so
        // the slot frees and re-dial can recreate the circuit, instead of `!closed` forever.
        return !closed && lastInboundActivity.duration(to: .now) < Self.relayedStaleTimeout
    }

    /// Time since the last inbound frame. The probe loop reads this to decide
    /// whether a relayed circuit has gone silent (see `relayedFailoverTimeout`).
    var inboundIdle: Duration {
        lastInboundActivity.duration(to: .now)
    }

#if DEBUG
    /// Backdate inbound activity so tests can exercise the silent-circuit
    /// detection without waiting wall-clock time.
    func backdateInboundActivityForTesting(by duration: Duration) {
        lastInboundActivity = ContinuousClock.now - duration
    }
#endif

    func feedMessage(_ message: Message) {
        lastInboundActivity = .now
        inboundContinuation.yield(message)
    }

    func connectionClosed() {
        closed = true
        inboundContinuation.finish()
    }

    public func cancel() {
        closed = true
        channel?.close(promise: nil)
        inboundContinuation.finish()
    }
}

final class MessageFrameDecoder: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = Message

    private let maxFrameSize: UInt32
    private var buffer: ByteBuffer = ByteBuffer()

    init(maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize) {
        self.maxFrameSize = maxFrameSize
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        buffer.writeBuffer(&incoming)

        while buffer.readableBytes >= 4 {
            guard let length = buffer.getInteger(at: buffer.readerIndex, endianness: .big, as: UInt32.self) else { break }
            if length == 0 {
                buffer.moveReaderIndex(forwardBy: 4)
                continue
            }
            guard length <= maxFrameSize else {
                context.close(promise: nil)
                return
            }
            guard buffer.readableBytes >= 4 + Int(length) else { break }
            buffer.moveReaderIndex(forwardBy: 4)
            guard let data = buffer.readData(length: Int(length)) else { break }
            if let message = Message.deserialize(data, maxDataPayload: maxFrameSize) {
                context.fireChannelRead(wrapInboundOut(message))
            }
        }

        buffer.discardReadBytes()
    }
}

final class PeerChannelHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = Message

    let connection: PeerConnection

    init(connection: PeerConnection) {
        self.connection = connection
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        connection.feedMessage(message)
    }

    func channelInactive(context: ChannelHandlerContext) {
        connection.connectionClosed()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

final class UnsafeMutableTransferBox<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

final class InboundConnectionAcceptor: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = Message

    let ivy: Ivy
    private let maxFrameSize: UInt32
    private var registered = false
    private var connection: PeerConnection?

    init(ivy: Ivy, maxFrameSize: UInt32) {
        self.ivy = ivy
        self.maxFrameSize = maxFrameSize
    }

    func channelActive(context: ChannelHandlerContext) {
        if !registered {
            registered = true
            let channel = context.channel
            let unknownID = PeerID(publicKey: "inbound-\(UUID().uuidString)")
            let endpoint = PeerEndpoint(publicKey: unknownID.publicKey, host: "unknown", port: 0)
            let conn = PeerConnection(
                id: unknownID,
                endpoint: endpoint,
                channel: channel,
                maxFrameSize: maxFrameSize
            )
            // Pin the netgroup to the unforgeable L3 source address seen on the
            // socket, captured before identify so there is no "unknown" window.
            conn.observedHost = channel.remoteAddress?.ipAddress
            connection = conn
            Task { await ivy.registerInboundConnection(conn) }
        }
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)
        connection?.feedMessage(message)
    }

    func channelInactive(context: ChannelHandlerContext) {
        connection?.connectionClosed()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
