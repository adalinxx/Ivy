import NIOCore
import NIOPosix

/// TCP transport backed by SwiftNIO sockets.
public struct TCPTransport: IvyTransport {
    public let kind: TransportKind = .tcp
    private let connectTimeout: TimeAmount
    private let backlog: Int32
    private let reusePort: Bool

    /// - Parameter reusePort: Allows a dial to leave from the listening port, so
    ///   a hole punch creates the NAT mapping this node advertises. It also lets
    ///   another socket on the host bind the same port, so it is off unless
    ///   punching needs it.
    public init(
        connectTimeout: TimeAmount = .seconds(5),
        backlog: Int32 = 256,
        reusePort: Bool = false
    ) {
        self.connectTimeout = connectTimeout
        self.backlog = backlog
        self.reusePort = reusePort
    }

    public func dial(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        boundToPort: UInt16?,
        initializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> Channel {
        func bootstrap() -> ClientBootstrap {
            ClientBootstrap(group: group)
                .connectTimeout(connectTimeout)
                .channelInitializer(initializer)
        }
        if let boundToPort, boundToPort != 0, reusePort {
            do {
                return try await bootstrap()
                    .channelOption(.socketOption(.so_reuseaddr), value: 1)
                    .channelOption(.socketOption(.init(rawValue: SO_REUSEPORT)), value: 1)
                    .bind(to: try SocketAddress(ipAddress: "0.0.0.0", port: Int(boundToPort)))
                    .connect(host: host, port: Int(port))
                    .get()
            } catch {
                // The listening port may be unusable for an outbound socket on
                // this platform; an ordinary dial is still worth trying.
            }
        }
        return try await bootstrap().connect(host: host, port: Int(port)).get()
    }

    public func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        streamInitializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> any TransportListenerHandle {
        var bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: backlog)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
        if reusePort {
            // A punch dial must be able to share this port; both sockets need the
            // option for the bind to succeed.
            bootstrap = bootstrap
                .serverChannelOption(.socketOption(.init(rawValue: SO_REUSEPORT)), value: 1)
        }
        let channel = try await bootstrap
            .childChannelOption(ChannelOptions.autoRead, value: false)
            .childChannelInitializer(streamInitializer)
            .bind(host: host, port: Int(port))
            .get()
        return TCPListenerHandle(channel: channel)
    }
}

struct TCPListenerHandle: TransportListenerHandle {
    let channel: Channel

    var localPort: UInt16? {
        channel.localAddress?.port.map(UInt16.init)
    }

    func close() async {
        try? await channel.close().get()
    }

    func closeImmediately() {
        channel.close(promise: nil)
    }
}
