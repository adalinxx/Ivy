import Foundation
import NIOCore
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
        boundToPort: UInt16?,
        initializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> Channel {
        lock.withLock { dials.append("\(host):\(port)") }
        return try await backing.dial(
            host: host,
            port: port,
            group: group,
            boundToPort: boundToPort,
            initializer: initializer)
    }

    func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        streamInitializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> any TransportListenerHandle {
        try await backing.listen(
            host: host, port: port, group: group, streamInitializer: streamInitializer)
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
