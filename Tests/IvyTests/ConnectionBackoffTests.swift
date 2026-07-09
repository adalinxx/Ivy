import Testing
import Foundation
import NIOEmbedded
@testable import Ivy
@testable import Tally

private func connectionBackoffConfig(publicKey: String) -> IvyConfig {
    IvyConfig(
        publicKey: publicKey,
        listenPort: 0,
        bootstrapPeers: [],
        enableLocalDiscovery: false,
        healthConfig: PeerHealthConfig(
            keepaliveInterval: .seconds(999),
            staleTimeout: .seconds(999),
            maxMissedPongs: 99,
            enabled: false
        ),
        enablePEX: false
    )
}

private func durationMilliseconds(_ duration: Duration) -> Int64 {
    let components = duration.components
    return components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000
}

@Suite("Connection backoff and dial dedupe")
struct ConnectionBackoffTests {

    @Test("Only one outbound dial can be reserved per peer")
    func outboundDialReservationIsPerPeer() async {
        let node = Ivy(config: connectionBackoffConfig(publicKey: "dial-dedupe-node"))
        let endpoint = PeerEndpoint(publicKey: "dial-dedupe-peer", host: "10.3.0.1", port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)

        let first = await node.reserveOutgoingDialForTesting(to: endpoint)
        let duplicate = await node.reserveOutgoingDialForTesting(to: endpoint)
        await node.finishOutgoingDialForTesting(to: peer, connected: false)
        let afterRelease = await node.reserveOutgoingDialForTesting(to: endpoint)

        #expect(first)
        #expect(!duplicate)
        #expect(afterRelease)

        await node.finishOutgoingDialForTesting(to: peer, connected: false)
    }

    @Test("In-flight dials count toward subnet diversity")
    func inFlightDialsCountTowardSubnetDiversity() async {
        let node = Ivy(config: connectionBackoffConfig(publicKey: "subnet-dedupe-node"))
        let first = PeerEndpoint(publicKey: "subnet-peer-1", host: "10.4.0.1", port: 4001)
        let second = PeerEndpoint(publicKey: "subnet-peer-2", host: "10.4.0.2", port: 4001)
        let third = PeerEndpoint(publicKey: "subnet-peer-3", host: "10.4.0.3", port: 4001)

        let firstReserved = await node.reserveOutgoingDialForTesting(to: first)
        let secondReserved = await node.reserveOutgoingDialForTesting(to: second)
        let thirdReserved = await node.reserveOutgoingDialForTesting(to: third)

        #expect(firstReserved)
        #expect(secondReserved)
        #expect(!thirdReserved)

        await node.finishOutgoingDialForTesting(to: PeerID(publicKey: first.publicKey), connected: false)
        await node.finishOutgoingDialForTesting(to: PeerID(publicKey: second.publicKey), connected: false)
    }

    /// A direct dial that UPGRADES a peer's own stale RELAYED connection must not
    /// be blocked by the per-netgroup cap: the peer's existing connection is
    /// SUPERSEDED by the upgrade, so it must be excluded from the same-netgroup
    /// tally. A re-keyed relayed conn's endpoint.host is the peer's advertised
    /// (real target) host, so without the exclusion it occupies a netgroup slot
    /// against its own upgrade.
    ///
    /// RED before the fix: with Q (direct) and P (relayed) both in netgroup G,
    /// the upgrade dial to P sees count 2 (Q + P's own stale conn) and is rejected.
    /// GREEN after: P's own conn is excluded → count 1 (just Q) → allowed. The cap
    /// still rejects a genuinely NEW peer that would make the netgroup 3 (no
    /// existing conn to exclude).
    @Test("a direct upgrade dial excludes the peer's own stale relayed conn from the netgroup cap")
    func upgradeDialExcludesOwnStaleRelayedConn() async {
        let node = Ivy(config: connectionBackoffConfig(publicKey: "upgrade-netgroup-node"))

        // Q: an existing DIRECT peer in netgroup G (40.0/16).
        let qID = PeerID(publicKey: "netgroup-peer-Q")
        let q = PeerConnection(
            id: qID,
            endpoint: PeerEndpoint(publicKey: "netgroup-peer-Q", host: "40.0.0.1", port: 4001),
            channel: EmbeddedChannel()
        )
        await node.registerConnectionForTesting(q, as: qID)

        // P: a re-keyed RELAYED conn (channel == nil) whose endpoint.host is P's
        // advertised (real target) host — also in netgroup G.
        let pID = PeerID(publicKey: "netgroup-peer-P")
        let pRelayed = PeerConnection(
            id: pID,
            endpoint: PeerEndpoint(publicKey: "netgroup-peer-P", host: "40.0.5.5", port: 4001),
            channel: nil,
            relayForward: { _ in }
        )
        await node.registerConnectionForTesting(pRelayed, as: pID)

        // No-regression: a dial to a genuinely NEW peer in G is still rejected —
        // Q + P already fill the 2-per-netgroup cap and nothing is excluded for a
        // peer with no existing connection.
        let newPeer = PeerEndpoint(publicKey: "netgroup-peer-NEW", host: "40.0.7.7", port: 4001)
        #expect(!(await node.reserveOutgoingDialForTesting(to: newPeer)),
                "the 2-per-netgroup cap must still reject a NEW peer in a full netgroup")

        // The direct UPGRADE dial to P must be ALLOWED: P's own stale relayed conn
        // is excluded from the tally, so the netgroup count is 1 (just Q) ≤ cap.
        let pUpgrade = PeerEndpoint(publicKey: "netgroup-peer-P", host: "40.0.5.5", port: 4001)
        #expect(await node.reserveOutgoingDialForTesting(to: pUpgrade),
                "the upgrade dial must exclude P's own stale relayed conn from the netgroup tally")

        await node.finishOutgoingDialForTesting(to: pID, connected: false)
    }

    @Test("Reconnect delay backs off and caps")
    func reconnectDelayBacksOffAndCaps() async {
        let node = Ivy(config: connectionBackoffConfig(publicKey: "reconnect-backoff-node"))
        let peer = PeerID(publicKey: "reconnect-backoff-peer")

        let first = durationMilliseconds(await node.reconnectDelayForTesting(peer: peer))
        let second = durationMilliseconds(await node.reconnectDelayForTesting(peer: peer))
        var latest = second
        for _ in 0..<20 {
            latest = durationMilliseconds(await node.reconnectDelayForTesting(peer: peer))
        }

        #expect(first >= 500)
        #expect(first <= 750)
        #expect(second >= 1_000)
        #expect(second <= 1_250)
        #expect(latest >= 30_000)
        #expect(latest <= 30_250)
    }
}
