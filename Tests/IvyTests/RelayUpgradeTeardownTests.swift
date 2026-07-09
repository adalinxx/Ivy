import Testing
import Foundation
import Crypto
import NIOCore
import NIOEmbedded
@testable import Ivy
@testable import Tally

/// A direct dial that UPGRADES a peer currently reachable only via a relayed
/// (channel-less) connection must SUPERSEDE the stale relayed connection — not
/// merely overwrite `connections[peer]`.
///
/// Threat model: `reserveOutgoingDial` permits a direct dial to a peer that
/// holds only a relayed connection (channel == nil), so the socket UPGRADES the
/// relay. If the overwrite left the old relayed conn intact, that conn would
/// leak: its `handleInbound` never sees a stream-end (only `cancel()` ends it)
/// and hits the `current !== conn` early-return, so its side-indices are never
/// cleared. `relayedConnByClaimedKey[peer]` would keep pointing at the dead conn,
/// and a later `.relayData(peerKey: peer, …)` over the carrier would be fed to
/// the DEAD handler — duplicate message processing + double tally/credit. The
/// peer would also stay in `inboundConnectionIDs` (an outbound conn miscounted
/// as inbound), skewing inbound-cap eviction. A malicious carrier could cycle
/// relayed→direct→drop→relayed to accumulate leaked tasks + stale index entries.
@Suite("Relayed→direct upgrade teardown")
struct RelayUpgradeTeardownTests {

    private func keypair() -> (pub: String, priv: Data) {
        let sk = Curve25519.Signing.PrivateKey()
        let pub = sk.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        return (pub, sk.rawRepresentation)
    }

    private func cfg(pub: String, priv: Data, port: UInt16, relay: Bool) -> IvyConfig {
        IvyConfig(
            publicKey: pub,
            listenPort: port,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            healthConfig: PeerHealthConfig(keepaliveInterval: .seconds(999), staleTimeout: .seconds(999), maxMissedPongs: 99, enabled: false),
            enablePEX: false,
            signingKey: priv,
            relayEnabled: relay
        )
    }

    /// A DIRECT carrier (live channel, distinct netgroup) to route the relayed
    /// connection through. Backed by an `EmbeddedChannel` so `channel != nil`
    /// holds without a real socket.
    private func directCarrier(_ key: String, observed: String) -> PeerConnection {
        let conn = PeerConnection(
            id: PeerID(publicKey: key),
            endpoint: PeerEndpoint(publicKey: key, host: observed, port: 4001),
            channel: EmbeddedChannel()
        )
        conn.observedHost = observed
        return conn
    }

    /// RED before the M1 teardown fix (the stale relayed conn's side-indices
    /// survive the overwrite); GREEN after (the relayed conn is superseded).
    @Test("a direct-dial upgrade supersedes the stale relayed connection and its side-indices")
    func directUpgradeSupersedesRelayedConn() async throws {
        // R is a real, reachable node so the direct upgrade dial actually connects.
        let (pubR, skR) = keypair()
        let portR: UInt16 = 19791
        let R = Ivy(config: cfg(pub: pubR, priv: skR, port: portR, relay: true))
        try await R.start()

        // A is deliberately NOT started (start() would auto-connect to knownRelays /
        // bootstrap and contaminate the setup). An outbound dial needs no listener.
        let (pubA, skA) = keypair()
        let A = Ivy(config: cfg(pub: pubA, priv: skA, port: 0, relay: false))

        let rID = PeerID(publicKey: pubR)

        // Authentic post-identify relayed connection to R, carried by an unrelated
        // direct carrier in a DISTINCT netgroup (10.0/16 vs the 127.0.0.1 upgrade).
        let carrier = directCarrier("carrier-key-up", observed: "10.0.0.1")
        let staleConn = try #require(
            await A.installReKeyedRelayedConnectionForTesting(claimedKey: pubR, via: carrier))

        // Precondition: every production relayed side-index is populated for R.
        #expect(await A.connections[rID]?.channel == nil)
        #expect(await A.connections[rID] === staleConn)
        #expect(await A.relayedConnByClaimedKeyForTesting(pubR) === staleConn)
        #expect(await A.isInboundTrackedForTesting(rID))
        #expect(staleConn.isLive)

        // Direct-dial UPGRADE to the (reachable) R.
        try await A.connect(to: PeerEndpoint(publicKey: pubR, host: "127.0.0.1", port: portR))

        // The direct channel is installed in place of the relayed conn.
        #expect(await A.connections[rID]?.channel != nil)
        // The stale relayed conn's claimed-key index no longer points at it.
        #expect(await A.relayedConnByClaimedKeyForTesting(pubR) !== staleConn)
        // R is no longer miscounted as an inbound connection.
        #expect(!(await A.isInboundTrackedForTesting(rID)))
        // The superseded relayed conn was torn down (its handleInbound loop ended).
        #expect(staleConn.isLive == false, "the superseded relayed connection must be cancelled")

        await A.stop()
        await R.stop()
    }
}
