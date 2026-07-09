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
    /// be blocked by the per-netgroup cap. Since the cap now keys on the
    /// UNFORGEABLE observed netgroup, a relayed conn (channel == nil ⇒ no observed
    /// L3 address) does NOT occupy a direct-dial netgroup slot at all — so P's own
    /// stale relayed conn cannot count against its own upgrade.
    ///
    /// The netgroup cap itself is still enforced: two DIRECT peers observed in G
    /// fill the 2-per-netgroup cap and reject a genuinely NEW peer in G.
    @Test("a direct upgrade dial is not blocked by the peer's own stale relayed conn, and the netgroup cap still holds")
    func upgradeDialExcludesOwnStaleRelayedConn() async {
        let node = Ivy(config: connectionBackoffConfig(publicKey: "upgrade-netgroup-node"))

        // Q: an existing DIRECT peer OBSERVED in netgroup G (40.0/16) — occupies a
        // direct-dial slot in G.
        let qID = PeerID(publicKey: "netgroup-peer-Q")
        let q = PeerConnection(
            id: qID,
            endpoint: PeerEndpoint(publicKey: "netgroup-peer-Q", host: "40.0.0.1", port: 4001),
            channel: EmbeddedChannel()
        )
        q.observedHost = "40.0.0.1"
        await node.registerConnectionForTesting(q, as: qID)

        // P: a re-keyed RELAYED conn (channel == nil ⇒ no observed address) whose
        // endpoint.host advertises netgroup G. It does NOT occupy a direct-dial
        // slot, so it cannot block its own direct upgrade.
        let pID = PeerID(publicKey: "netgroup-peer-P")
        let pRelayed = PeerConnection(
            id: pID,
            endpoint: PeerEndpoint(publicKey: "netgroup-peer-P", host: "40.0.5.5", port: 4001),
            channel: nil,
            relayForward: { _ in }
        )
        await node.registerConnectionForTesting(pRelayed, as: pID)

        // The direct UPGRADE dial to P must be ALLOWED: only Q occupies G (P's
        // relayed conn does not), so the netgroup count is 1 ≤ cap.
        let pUpgrade = PeerEndpoint(publicKey: "netgroup-peer-P", host: "40.0.5.5", port: 4001)
        #expect(await node.reserveOutgoingDialForTesting(to: pUpgrade),
                "the upgrade dial must not be blocked by P's own stale relayed conn")
        await node.finishOutgoingDialForTesting(to: pID, connected: false)

        // No-regression: fill G with a SECOND direct peer observed in G, then a
        // dial to a genuinely NEW peer in G is rejected — the 2-per-netgroup cap
        // still holds when two real (observed) connections occupy the netgroup.
        let rID = PeerID(publicKey: "netgroup-peer-R")
        let r = PeerConnection(
            id: rID,
            endpoint: PeerEndpoint(publicKey: "netgroup-peer-R", host: "40.0.9.9", port: 4001),
            channel: EmbeddedChannel()
        )
        r.observedHost = "40.0.9.9"
        await node.registerConnectionForTesting(r, as: rID)

        let newPeer = PeerEndpoint(publicKey: "netgroup-peer-NEW", host: "40.0.7.7", port: 4001)
        #expect(!(await node.reserveOutgoingDialForTesting(to: newPeer)),
                "the 2-per-netgroup cap must still reject a NEW peer in a full netgroup")
    }

    /// The per-netgroup dial cap must key each existing connection on the
    /// UNFORGEABLE observed L3 address, not the self-advertised `endpoint.host`
    /// (which `handleIdentify` overwrites with the peer's chosen listenAddr).
    /// Otherwise a connected peer deflates its true-netgroup count by advertising
    /// a host in a different netgroup, letting us open more than the intended cap
    /// of direct dials into its real netgroup — an eclipse assist.
    ///
    /// RED before the fix (keyed on `endpoint.host`): X is counted in its forged
    /// netgroup H, so its true netgroup G shows count 0. GREEN after (keyed on the
    /// observed address via `carrierNetgroup`): X is counted in G, never H.
    @Test("the netgroup dial cap counts a connection by its unforgeable observed address, not its advertised host")
    func netgroupCapKeysOnObservedNotAdvertisedHost() async {
        let node = Ivy(config: connectionBackoffConfig(publicKey: "forge-netgroup-node"))

        let trueGroup = NetGroup.group("50.0.0.1")       // X's real (observed) netgroup
        let forgedGroup = NetGroup.group("60.0.0.1")     // X's advertised (forgeable) netgroup
        #expect(trueGroup != forgedGroup)

        // X: a direct conn whose advertised endpoint.host is in the FORGED netgroup
        // H, but whose unforgeable observed L3 address is in the TRUE netgroup G.
        let xID = PeerID(publicKey: "forge-peer-X")
        let x = PeerConnection(
            id: xID,
            endpoint: PeerEndpoint(publicKey: "forge-peer-X", host: "60.0.0.1", port: 4001),
            channel: EmbeddedChannel()
        )
        x.observedHost = "50.0.0.1"
        await node.registerConnectionForTesting(x, as: xID)

        // Counted in its TRUE (observed) netgroup, NOT its forged (advertised) one.
        #expect(await node.connectionCount(inNetgroup: trueGroup, excluding: nil) == 1,
                "must count by the unforgeable observed address")
        #expect(await node.connectionCount(inNetgroup: forgedGroup, excluding: nil) == 0,
                "must NOT count by the forgeable advertised host")

        // A RELAYED conn (channel == nil ⇒ no observed L3 address) advertises the
        // true netgroup but does NOT occupy a direct-dial slot in it.
        let rID = PeerID(publicKey: "forge-peer-R")
        let relayed = PeerConnection(
            id: rID,
            endpoint: PeerEndpoint(publicKey: "forge-peer-R", host: "50.0.9.9", port: 4001),
            channel: nil,
            relayForward: { _ in }
        )
        await node.registerConnectionForTesting(relayed, as: rID)
        #expect(await node.connectionCount(inNetgroup: trueGroup, excluding: nil) == 1,
                "a relayed conn (no observed address) must not count toward a direct-dial netgroup cap")
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
