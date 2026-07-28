import Foundation
import Ivy
import Logging
import NIOCore
import NIOPosix
import NIOQUIC

/// QUIC transport for Ivy, backed by SwiftNIO QUIC.
///
/// One QUIC connection carries exactly one bidirectional stream, and that stream
/// carries the same length-prefixed session records the TCP transport carries, so
/// the session layer above is unchanged. TLS is transport plumbing only: the
/// certificate is ephemeral and unverified, and peer identity still comes from the
/// signed session handshake.
public struct QUICTransport: IvyTransport {
    public let kind: TransportKind = .quic

    private let certificate: EphemeralCertificate
    private let alpn: String
    private let connectTimeout: Duration
    private let idleTimeout: Duration
    private let sendRetry: Bool
    private let reusePort: Bool
    private let maxInboundConnections: Int
    private let logger: Logger

    /// - Parameters:
    ///   - alpn: ALPN protocol name; peers must agree on it to interoperate.
    ///   - connectTimeout: Bounds the QUIC handshake, keeping a blackholed UDP
    ///     path from stalling a dial that could fall back to TCP.
    ///   - sendRetry: Sends stateless retry packets, forcing address validation
    ///     before the server keeps connection state.
    ///   - reusePort: Lets a hole-punch dial leave from the listening port. It
    ///     also lets another process bind that port, so it is off by default.
    ///   - maxInboundConnections: Connections held before any stream reaches
    ///     Ivy's admission gate.
    public init(
        alpn: String = "ivy/9",
        connectTimeout: Duration = .seconds(3),
        idleTimeout: Duration = .seconds(30),
        sendRetry: Bool = true,
        reusePort: Bool = false,
        maxInboundConnections: Int = 256,
        logger: Logger = Logger(label: "ivy.quic")
    ) throws {
        self.certificate = try EphemeralCertificate()
        self.alpn = alpn
        self.connectTimeout = connectTimeout
        self.idleTimeout = idleTimeout
        self.sendRetry = sendRetry
        self.reusePort = reusePort
        self.maxInboundConnections = maxInboundConnections
        self.logger = logger
    }

    // Streams are capped at one bidirectional and no unidirectional stream, so a
    // peer cannot flood stream state on a connection Ivy treats as single-stream.
    private func serverConfiguration() -> QUICConfiguration {
        .server(
            serverName: "ivy",
            authenticationConfiguration: .x509Certificates(
                certificateChainFilePath: certificate.certificateChainPath,
                privateKeyFilePath: certificate.privateKeyPath),
            applicationProtocols: [alpn],
            maxIdleTimeout: idleTimeout,
            initialMaxStreamsBidi: 1,
            initialMaxStreamsUni: 0,
            sendRetry: sendRetry)
    }

    private func clientConfiguration() -> QUICConfiguration {
        .client(
            verificationConfiguration: .x509Certificates(trustRootsFilePath: nil),
            applicationProtocols: [alpn],
            maxIdleTimeout: idleTimeout,
            initialMaxStreamsBidi: 1,
            initialMaxStreamsUni: 0,
            peerCertificateVerification: .noVerification)
    }

    /// - Parameter boundToPort: Local UDP port to dial from, so a hole punch
    ///   leaves through the mapping this node advertises.
    public func dial(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        boundToPort: UInt16?,
        initializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> Channel {
        let remote = try await resolve(host: host, port: port, group: group)
        let configuration = clientConfiguration()
        let logger = self.logger

        func bind(to localPort: UInt16) async throws -> (Channel, QUICHandler.ConnectionMultiplexer<Never>) {
            var bootstrap = DatagramBootstrap(group: group)
                .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            if localPort != 0, reusePort {
                bootstrap = bootstrap
                    .channelOption(ChannelOptions.socketOption(.init(rawValue: SO_REUSEPORT)), value: 1)
            }
            return try await bootstrap
            .bind(host: "0.0.0.0", port: Int(localPort)) { channel in
                channel.eventLoop.makeCompletedFuture {
                    let (handler, multiplexer) = try QUICHandler.makeHandlerAndConnectionMultiplexer(
                        channel: channel,
                        quicConfiguration: configuration,
                        logger: logger,
                        inboundStreamChannelInitializer: { stream -> EventLoopFuture<Never> in
                            // A dialer never expects the peer to open a stream.
                            stream.close(promise: nil)
                            return stream.eventLoop.makeFailedFuture(QUICTransportError.unexpectedStream)
                        })
                    try channel.pipeline.syncOperations.addHandler(handler)
                    return (channel, multiplexer)
                }
            }
        }

        let (datagramChannel, multiplexer): (Channel, QUICHandler.ConnectionMultiplexer<Never>)
        if let boundToPort, boundToPort != 0, reusePort {
            do {
                (datagramChannel, multiplexer) = try await bind(to: boundToPort)
            } catch {
                // Sharing the listening port is best effort; an ordinary dial from
                // an ephemeral port still punches, just without matching the
                // mapping this node advertises.
                (datagramChannel, multiplexer) = try await bind(to: 0)
            }
        } else {
            (datagramChannel, multiplexer) = try await bind(to: 0)
        }

        do {
            return try await withDeadline(connectTimeout) {
                let connection = try await multiplexer.createNewConnection(
                    serverName: host,
                    remoteAddress: remote
                ) { stream -> EventLoopFuture<Never> in
                    stream.close(promise: nil)
                    return stream.eventLoop.makeFailedFuture(QUICTransportError.unexpectedStream)
                }
                return try await connection.createBidirectionalStream { parameters in
                    let stream = parameters.channel
                    return initializer(stream).flatMapThrowing {
                        // Tearing down the stream must tear down the connection it
                        // rides on, so a closed session releases its UDP socket.
                        try stream.pipeline.syncOperations.addHandler(
                            QUICStreamLifecycleHandler(datagramChannel: datagramChannel))
                        return stream
                    }
                }
            }
        } catch {
            datagramChannel.close(promise: nil)
            throw error
        }
    }

    public func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        streamInitializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> any TransportListenerHandle {
        let configuration = serverConfiguration()
        let logger = self.logger

        var listenerBootstrap = DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
        if reusePort {
            listenerBootstrap = listenerBootstrap
                .channelOption(ChannelOptions.socketOption(.init(rawValue: SO_REUSEPORT)), value: 1)
        }
        let (datagramChannel, multiplexer) = try await listenerBootstrap
            .bind(host: host, port: Int(port)) { channel in
                channel.eventLoop.makeCompletedFuture {
                    let (handler, multiplexer) = try QUICHandler.makeHandlerAndConnectionMultiplexer(
                        channel: channel,
                        quicConfiguration: configuration,
                        logger: logger,
                        inboundStreamChannelInitializer: { stream -> EventLoopFuture<any Channel> in
                            stream.eventLoop.makeCompletedFuture {
                                // Reads stay parked until admission grants this
                                // connection a slot and enables them (IVY-001).
                                try stream.syncOptions?.setOption(ChannelOptions.autoRead, value: false)
                                return stream
                            }.flatMap { stream in
                                streamInitializer(stream).map { stream }
                            }
                        })
                    try channel.pipeline.syncOperations.addHandler(handler)
                    return (channel, multiplexer)
                }
            }

        let live = InboundConnectionCount(limit: maxInboundConnections)
        let acceptor = Task {
            await withDiscardingTaskGroup { group in
                for await connection in multiplexer.inboundConnections {
                    // A QUIC connection only reaches Ivy's admission gate once it
                    // opens a stream, so bound how many this transport services
                    // before then. swift-nio-quic 0.1.0 exposes no way to close a
                    // connection, so one over the limit is left to its idle timeout
                    // rather than torn down.
                    guard live.acquire() else {
                        logger.warning("Not servicing a QUIC connection: at the inbound limit")
                        continue
                    }
                    group.addTask {
                        defer { live.release() }
                        var accepted = false
                        for await stream in connection.inboundStreams {
                            // One stream per connection; anything further is a
                            // protocol violation and costs the peer its connection.
                            guard !accepted else {
                                stream.close(promise: nil)
                                continue
                            }
                            accepted = true
                        }
                    }
                }
            }
        }

        return QUICListenerHandle(datagramChannel: datagramChannel, acceptor: acceptor)
    }

    private func resolve(
        host: String,
        port: UInt16,
        group: any EventLoopGroup
    ) async throws -> SocketAddress {
        if let literal = try? SocketAddress(ipAddress: host, port: Int(port)) { return literal }
        return try await group.next().submit {
            try SocketAddress.makeAddressResolvingHost(host, port: Int(port))
        }.get()
    }
}

enum QUICTransportError: Error, Equatable {
    case unexpectedStream
    case handshakeTimedOut
}

private func withDeadline<T: Sendable>(
    _ duration: Duration,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: duration)
            throw QUICTransportError.handshakeTimedOut
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}

/// Closes the QUIC connection's UDP socket once its stream goes away.
private final class QUICStreamLifecycleHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let datagramChannel: Channel

    init(datagramChannel: Channel) {
        self.datagramChannel = datagramChannel
    }

    func channelInactive(context: ChannelHandlerContext) {
        datagramChannel.close(promise: nil)
        context.fireChannelInactive()
    }
}

/// Bounds connections that have not yet opened the stream Ivy admits.
final class InboundConnectionCount: @unchecked Sendable {
    private let lock = NSLock()
    private let limit: Int
    private var count = 0

    init(limit: Int) {
        self.limit = limit
    }

    func acquire() -> Bool {
        lock.withLock {
            guard count < limit else { return false }
            count += 1
            return true
        }
    }

    func release() {
        lock.withLock { count -= 1 }
    }
}

struct QUICListenerHandle: TransportListenerHandle {
    let datagramChannel: Channel
    let acceptor: Task<Void, Never>

    var localPort: UInt16? {
        datagramChannel.localAddress?.port.map(UInt16.init)
    }

    func close() async {
        acceptor.cancel()
        try? await datagramChannel.close().get()
    }

    func closeImmediately() {
        acceptor.cancel()
        datagramChannel.close(promise: nil)
    }
}
