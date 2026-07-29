import Foundation
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
        boundToPort: UInt16?
    ) async throws -> any TransportConnection {
        let box = NIOTransportConnectionBox()
        func bootstrap() -> ClientBootstrap {
            ClientBootstrap(group: group)
                .connectTimeout(connectTimeout)
                // Reads only happen on demand, exactly as for an accepted channel.
                .channelOption(ChannelOptions.autoRead, value: false)
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        let connection = NIOTransportConnection(channel: channel)
                        try channel.pipeline.syncOperations.addHandler(
                            NIOTransportHandler(connection: connection))
                        box.store(connection)
                    }
                }
        }
        if let boundToPort, boundToPort != 0, reusePort {
            do {
                _ = try await bootstrap()
                    .channelOption(.socketOption(.so_reuseaddr), value: 1)
                    .channelOption(.socketOption(.init(rawValue: SO_REUSEPORT)), value: 1)
                    .bind(to: try SocketAddress(ipAddress: "0.0.0.0", port: Int(boundToPort)))
                    .connect(host: host, port: Int(port))
                    .get()
                guard let connection = box.take() else { throw TransportError.dialFailed }
                return connection
            } catch {
                // Sharing the listening port is best effort on some platforms.
            }
        }
        _ = try await bootstrap().connect(host: host, port: Int(port)).get()
        guard let connection = box.take() else { throw TransportError.dialFailed }
        return connection
    }

    public func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        onConnection: @Sendable @escaping (any TransportConnection) -> Void
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
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let connection = NIOTransportConnection(channel: channel)
                    try channel.pipeline.syncOperations.addHandler(
                        NIOTransportHandler(connection: connection, onActive: onConnection))
                }
            }
            .bind(host: host, port: Int(port))
            .get()
        return TCPListenerHandle(channel: channel)
    }
}

/// Carries the connection built inside a channel initializer back to the dialer.
private final class NIOTransportConnectionBox: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: NIOTransportConnection?

    func store(_ connection: NIOTransportConnection) {
        lock.withLock { self.connection = connection }
    }

    func take() -> NIOTransportConnection? {
        lock.withLock {
            defer { connection = nil }
            return connection
        }
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
