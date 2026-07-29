import Foundation
import NIOCore
import NIOPosix
import Testing
@testable import Ivy

/// Stands in for a second transport so selection can be tested without the QUIC
/// package: it reports `.quic` but moves bytes over TCP.
final class FakeQUICTransport: IvyTransport, @unchecked Sendable {
    let kind: TransportKind = .quic
    private let backing = TCPTransport()
    private let lock = NSLock()
    private var dials: [String] = []

    var dialedHosts: [String] { lock.withLock { dials } }

    func dial(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        boundToPort: UInt16?
    ) async throws -> any TransportConnection {
        lock.withLock { dials.append("\(host):\(port)") }
        return try await backing.dial(
            host: host,
            port: port,
            group: group,
            boundToPort: boundToPort)
    }

    func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        onConnection: @Sendable @escaping (any TransportConnection) -> Void
    ) async throws -> any TransportListenerHandle {
        try await backing.listen(
            host: host, port: port, group: group, onConnection: onConnection)
    }
}

@Suite("Transport selection")
struct TransportSelectionTests {
    @Test("QUIC routes are dialed before TCP routes")
    func prefersQUICWhenInstalled() async throws {
        let ivy = Ivy(
            config: IvyConfig(publicKey: deterministicTestPeerKey("selector")),
            transports: [TCPTransport(), FakeQUICTransport()])
        let key = deterministicTestPeerKey("remote")
        let tcp = PeerEndpoint(publicKey: key, host: "1.1.1.1", port: 4001)
        let quic = PeerEndpoint(publicKey: key, host: "1.1.1.1", port: 4002, transport: .quic)

        let ordered = await ivy.orderedByDialPreference([tcp, quic])
        #expect(ordered.map(\.transport) == [.quic, .tcp])
    }

    @Test("routes for uninstalled transports sort last")
    func uninstalledTransportsSortLast() async throws {
        let ivy = Ivy(config: IvyConfig(publicKey: deterministicTestPeerKey("tcp-only")))
        let key = deterministicTestPeerKey("remote")
        let quic = PeerEndpoint(publicKey: key, host: "1.1.1.1", port: 4002, transport: .quic)
        let tcp = PeerEndpoint(publicKey: key, host: "1.1.1.1", port: 4001)

        let ordered = await ivy.orderedByDialPreference([quic, tcp])
        #expect(ordered.map(\.transport) == [.tcp, .quic])
    }

    @Test("a second transport carries a full authenticated session")
    func secondTransportCarriesSession() async throws {
        let listenerKey = deterministicTestSigningKey("quic-listener")
        let dialerKey = deterministicTestSigningKey("quic-dialer")
        let fake = FakeQUICTransport()

        let listener = Ivy(
            config: IvyConfig(
                signingKey: listenerKey,
                listenPort: 0,
                quicListenPort: 0,
                stunServers: [],
                healthConfig: PeerHealthConfig(enabled: false)),
            transports: [fake])
        let dialer = Ivy(
            config: IvyConfig(
                signingKey: dialerKey,
                listenPort: 0,
                quicListenPort: 0,
                stunServers: [],
                healthConfig: PeerHealthConfig(enabled: false)),
            transports: [FakeQUICTransport()])

        try await listener.start()
        try await dialer.start()
        defer {
            Task {
                await dialer.stop()
                await listener.stop()
            }
        }

        let port = try #require(await listener.boundPort(for: .quic))
        let endpoint = PeerEndpoint(
            publicKey: try PeerKey(rawRepresentation: listenerKey.publicKey.rawRepresentation).hex,
            host: "127.0.0.1",
            port: port,
            transport: .quic)

        try await dialer.connect(to: endpoint)
        #expect(await dialer.connectedPeers.count == 1)
    }
}

@Suite("Listening-port reuse")
struct ListenPortReuseTests {
    @Test("a dial can leave from the listening port when reuse is enabled")
    func dialReusesListeningPort() async throws {
        let group = MultiThreadedEventLoopGroup.singleton
        let transport = TCPTransport(reusePort: true)
        let listener = try await transport.listen(
            host: "127.0.0.1",
            port: 0,
            group: group,
            onConnection: { _ in })
        let listenPort = try #require(listener.localPort)

        // Somewhere to dial that is not ourselves.
        let peer = try await transport.listen(
            host: "127.0.0.1",
            port: 0,
            group: group,
            onConnection: { _ in })
        let peerPort = try #require(peer.localPort)

        let dialed = try await transport.dial(
            host: "127.0.0.1",
            port: peerPort,
            group: group,
            boundToPort: listenPort)
        // This is what makes a hole punch work: the mapping the peer sees is the
        // one this node advertises.
        #expect(dialed.localPort == listenPort)

        dialed.close()
        await listener.close()
        await peer.close()
    }

    @Test("a dial falls back to an ephemeral port when reuse is disabled")
    func dialFallsBackWithoutReuse() async throws {
        let group = MultiThreadedEventLoopGroup.singleton
        let transport = TCPTransport(reusePort: false)
        let peer = try await transport.listen(
            host: "127.0.0.1",
            port: 0,
            group: group,
            onConnection: { _ in })
        let peerPort = try #require(peer.localPort)

        let dialed = try await transport.dial(
            host: "127.0.0.1",
            port: peerPort,
            group: group,
            boundToPort: peerPort)
        #expect(dialed.localPort != peerPort)

        dialed.close()
        await peer.close()
    }
}
