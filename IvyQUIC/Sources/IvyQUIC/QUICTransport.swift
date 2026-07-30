import Foundation
import Ivy
import Logging
import NIOCore
import NIOPosix
import QUIC

/// QUIC transport for Ivy, backed by swift-quic.
///
/// One QUIC connection carries exactly one bidirectional stream, and that stream
/// carries the same length-prefixed session records the TCP transport carries, so
/// the session layer above is unchanged. TLS is transport plumbing only: the
/// certificate is ephemeral and unverified, and peer identity still comes from the
/// signed session handshake.
public struct QUICTransport: IvyTransport {
    public let kind: TransportKind = .quic

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
    private func transportConfiguration() -> QUICTransportConfiguration {
        var configuration = QUICTransportConfiguration()
        configuration.maxIdleTimeout = idleTimeout
        configuration.maxBidirectionalStreams = 1
        configuration.maxUnidirectionalStreams = 0
        return configuration
    }

    /// - Parameter boundToPort: Local UDP port to dial from, so a hole punch
    ///   leaves through the mapping this node advertises.
    public func dial(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        boundToPort: UInt16?
    ) async throws -> any TransportConnection {
        var configuration = QUICClient.Configuration(applicationProtocols: [alpn])
        // Peer identity comes from the signed session handshake, so the
        // certificate here is unverified transport plumbing.
        configuration.certificateVerification = .none
        configuration.transport = transportConfiguration()
        configuration.connectTimeout = connectTimeout
        configuration.logger = logger

        let localAddress: SocketAddress?
        if let boundToPort, boundToPort != 0, reusePort {
            localAddress = try? SocketAddress(ipAddress: "0.0.0.0", port: Int(boundToPort))
        } else {
            localAddress = nil
        }

        let connection: QUICConnection
        do {
            connection = try await QUICClient.connect(
                to: host,
                port: Int(port),
                configuration: configuration,
                localAddress: localAddress,
                eventLoopGroup: group)
        } catch {
            // Sharing the listening port is best effort — another process may
            // hold it — and an ordinary dial from an ephemeral port still
            // punches, just without matching the mapping this node advertises.
            guard localAddress != nil else { throw error }
            connection = try await QUICClient.connect(
                to: host,
                port: Int(port),
                configuration: configuration,
                localAddress: nil,
                eventLoopGroup: group)
        }

        do {
            let stream = try await connection.openBidirectionalStream()
            return QUICStreamConnection(connection: connection, stream: stream)
        } catch {
            await connection.close()
            throw error
        }
    }

    public func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        onConnection: @Sendable @escaping (any TransportConnection) -> Void
    ) async throws -> any TransportListenerHandle {
        let selfSigned = try QUICIdentity.selfSigned(commonName: "ivy")
        var configuration = QUICServer.Configuration(
            identity: selfSigned.identity,
            applicationProtocols: [alpn])
        configuration.serverName = "ivy"
        configuration.sendRetry = sendRetry
        configuration.transport = transportConfiguration()
        configuration.logger = logger

        let server = try await QUICServer.bind(
            host: host,
            port: Int(port),
            configuration: configuration,
            eventLoopGroup: group)

        let live = InboundConnectionCount(limit: maxInboundConnections)
        let logger = self.logger
        let acceptor = Task {
            await withDiscardingTaskGroup { group in
                for await connection in server.connections {
                    // A QUIC connection only reaches Ivy's admission gate once it
                    // opens a stream, so bound how many this transport services
                    // before then.
                    guard live.acquire() else {
                        logger.warning("Not servicing a QUIC connection: at the inbound limit")
                        await connection.close()
                        continue
                    }
                    group.addTask {
                        defer { live.release() }
                        var accepted = false
                        for await stream in connection.incomingStreams {
                            // One stream per connection; anything further is a
                            // protocol violation and costs the peer its connection.
                            guard !accepted else {
                                await stream.close()
                                continue
                            }
                            accepted = true
                            onConnection(QUICStreamConnection(
                                connection: connection,
                                stream: stream))
                        }
                    }
                }
            }
        }

        return QUICListenerHandle(server: server, acceptor: acceptor)
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
    let server: QUICServer
    let acceptor: Task<Void, Never>

    var localPort: UInt16? {
        server.localAddress.port.map(UInt16.init)
    }

    func close() async {
        acceptor.cancel()
        await server.close()
    }

    func closeImmediately() {
        acceptor.cancel()
        let server = self.server
        Task { await server.close() }
    }
}
