import NIOCore
import NIOPosix

/// TCP transport backed by SwiftNIO sockets.
public struct TCPTransport: IvyTransport {
    public let kind: TransportKind = .tcp
    private let connectTimeout: TimeAmount
    private let backlog: Int32

    public init(connectTimeout: TimeAmount = .seconds(5), backlog: Int32 = 256) {
        self.connectTimeout = connectTimeout
        self.backlog = backlog
    }

    public func dial(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        initializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> Channel {
        try await ClientBootstrap(group: group)
            .connectTimeout(connectTimeout)
            .channelInitializer(initializer)
            .connect(host: host, port: Int(port))
            .get()
    }

    public func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        streamInitializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> any TransportListenerHandle {
        let channel = try await ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: backlog)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
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
