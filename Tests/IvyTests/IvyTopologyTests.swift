import XCTest
@testable import Ivy

final class IvyTopologyTests: XCTestCase {
    private let rawKey = String(repeating: "ab", count: 32)
    private let otherKey = String(repeating: "cd", count: 32)

    func testPinnedPeerCanonicalizesEquivalentKeySpellings() {
        let topology = IvyTopology.pinnedPeer(publicKey: "ed01" + rawKey.uppercased())

        XCTAssertTrue(topology.allowsPeer(publicKey: rawKey))
        XCTAssertTrue(topology.allowsPeer(publicKey: "ed01" + rawKey))
        XCTAssertFalse(topology.allowsPeer(publicKey: otherKey))
        XCTAssertFalse(topology.participatesInPublicDiscovery)
        XCTAssertFalse(topology.acceptsInboundConnections)
        XCTAssertFalse(topology.allowsRelayFallback)
    }

    func testPublicOverlayAllowsPeersAndDiscovery() {
        let topology = IvyTopology.publicOverlay

        XCTAssertTrue(topology.allowsPeer(publicKey: rawKey))
        XCTAssertTrue(topology.allowsPeer(publicKey: otherKey))
        XCTAssertTrue(topology.participatesInPublicDiscovery)
        XCTAssertTrue(topology.acceptsInboundConnections)
        XCTAssertTrue(topology.allowsRelayFallback)
    }

    func testPinnedConfigCannotBeWidenedByOverlaySettings() {
        let expected = PeerEndpoint(publicKey: rawKey, host: "127.0.0.1", port: 4001)
        let substitute = PeerEndpoint(publicKey: otherKey, host: "127.0.0.1", port: 4002)
        let relay = PeerEndpoint(publicKey: otherKey, host: "127.0.0.1", port: 5001)

        let config = IvyConfig(
            publicKey: rawKey,
            bootstrapPeers: [substitute, expected],
            enableLocalDiscovery: true,
            stunServers: [("stun.example", 3478)],
            enablePEX: true,
            relayEnabled: true,
            knownRelays: [relay],
            topology: .pinnedPeer(publicKey: rawKey)
        )

        XCTAssertEqual(config.bootstrapPeers.map(\.publicKey), [rawKey])
        XCTAssertFalse(config.enableLocalDiscovery)
        XCTAssertTrue(config.stunServers.isEmpty)
        XCTAssertFalse(config.enablePEX)
        XCTAssertFalse(config.relayEnabled)
        XCTAssertTrue(config.knownRelays.isEmpty)
        XCTAssertFalse(config.shouldRunPEX)
        XCTAssertFalse(config.shouldRunLocalDiscovery)
    }

    func testPublicConfigPreservesOverlaySettings() {
        let peer = PeerEndpoint(publicKey: otherKey, host: "127.0.0.1", port: 4002)
        let relay = PeerEndpoint(publicKey: rawKey, host: "127.0.0.1", port: 5001)

        let config = IvyConfig(
            publicKey: rawKey,
            bootstrapPeers: [peer],
            enableLocalDiscovery: true,
            stunServers: [("stun.example", 3478)],
            enablePEX: true,
            relayEnabled: true,
            knownRelays: [relay]
        )

        XCTAssertEqual(config.bootstrapPeers.map(\.publicKey), [otherKey])
        XCTAssertTrue(config.enableLocalDiscovery)
        XCTAssertEqual(config.stunServers.count, 1)
        XCTAssertTrue(config.enablePEX)
        XCTAssertTrue(config.relayEnabled)
        XCTAssertEqual(config.knownRelays.map(\.publicKey), [rawKey])
        XCTAssertTrue(config.shouldRunPEX)
        XCTAssertTrue(config.shouldRunLocalDiscovery)
    }
}
