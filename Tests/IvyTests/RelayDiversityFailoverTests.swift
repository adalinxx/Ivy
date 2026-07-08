import Testing
import Foundation
import Crypto
@testable import Ivy
@testable import Tally

/// Netgroup-diverse relay-carrier selection + fast failover.
///
/// Threat model: a relay-only node whose every circuit rides a single carrier
/// (or carriers in one netgroup) is one eclipse away from isolation — a
/// malicious carrier can keep the circuit "alive" (forwarding keepalives)
/// while selectively dropping the frames that matter. The mitigations under
/// test: (1) carrier candidates are tried netgroup-diverse-first, (2) a dead
/// or silent relayed connection fails over to another carrier far faster than
/// the legacy 300s passive bound, (3) the relay path NEVER dials a
/// peer-supplied address — it only bridges pre-existing mutual connections.
@Suite("Relay carrier diversity + failover")
struct RelayDiversityFailoverTests {
    private enum TestTimeout: Error { case timedOut }

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

    private func waitUntil(_ timeoutMs: Int = 5000, _ cond: @Sendable () async -> Bool) async -> Bool {
        var waited = 0
        while waited < timeoutMs {
            if await cond() { return true }
            try? await Task.sleep(for: .milliseconds(50))
            waited += 50
        }
        return await cond()
    }

    // MARK: - Fast failover on carrier failure (integration)

    /// A relayed connection whose CARRIER dies must re-form through another
    /// connected carrier within seconds — not sit dead until the legacy 300s
    /// stale bound (relayed conns never direct-reconnect, so without failover
    /// the link would only re-form on an unrelated future dial).
    @Test("carrier failure fails over to a second connected carrier")
    func carrierFailureFailsOverToSecondCarrier() async throws {
        let (pubR1, skR1) = keypair(); let (pubR2, skR2) = keypair()
        let (pubA, skA) = keypair(); let (pubB, skB) = keypair()
        let (portR1, portR2, portA, portB): (UInt16, UInt16, UInt16, UInt16) = (19761, 19762, 19763, 19764)
        let R1 = Ivy(config: cfg(pub: pubR1, priv: skR1, port: portR1, relay: true))
        let R2 = Ivy(config: cfg(pub: pubR2, priv: skR2, port: portR2, relay: true))
        let A = Ivy(config: cfg(pub: pubA, priv: skA, port: portA, relay: false))
        let B = Ivy(config: cfg(pub: pubB, priv: skB, port: portB, relay: false))
        try await R1.start(); try await R2.start(); try await A.start(); try await B.start()

        let r1ID = PeerID(publicKey: pubR1), r2ID = PeerID(publicKey: pubR2)
        let aID = PeerID(publicKey: pubA), bID = PeerID(publicKey: pubB)

        // A and B each hold BOTH carriers; no direct A<->B link ever forms.
        let r1Endpoint = PeerEndpoint(publicKey: pubR1, host: "127.0.0.1", port: portR1)
        let r2Endpoint = PeerEndpoint(publicKey: pubR2, host: "127.0.0.1", port: portR2)
        try await A.connect(to: r1Endpoint); try await A.connect(to: r2Endpoint)
        try await B.connect(to: r1Endpoint); try await B.connect(to: r2Endpoint)
        let allConnected = await waitUntil {
            let aR1 = await A.connections[r1ID] != nil
            let aR2 = await A.connections[r2ID] != nil
            let bR1 = await B.connections[r1ID] != nil
            let bR2 = await B.connections[r2ID] != nil
            return aR1 && aR2 && bR1 && bR2
        }
        #expect(allConnected)

        try await A.connectViaRelay(to: PeerEndpoint(publicKey: pubB, host: "relay", port: 0))
        let relayedUp = await waitUntil {
            let ab = await A.connections[bID] != nil
            let ba = await B.connections[aID] != nil
            return ab && ba
        }
        #expect(relayedUp)

        // Which carrier is the circuit riding on?
        let viaR1 = await {
            let carrier = await A.connections[bID]?.relayCarrierConn
            return carrier === (await A.connections[r1ID])
        }()
        let failedCarrier = viaR1 ? R1 : R2
        let failedID = viaR1 ? r1ID : r2ID
        let survivorConn = viaR1 ? r2ID : r1ID

        // Kill the carrier. The relayed A<->B link must fail over to the OTHER
        // carrier well within the legacy 300s bound (seconds, not minutes).
        await failedCarrier.stop()

        let failedOver = await waitUntil(30_000) {
            guard let conn = await A.connections[bID] else { return false }
            let survivor = await A.connections[survivorConn]
            return conn.relayForward != nil && survivor != nil && conn.relayCarrierConn === survivor
        }
        #expect(failedOver, "relayed connection must re-form through the surviving carrier")
        #expect(await A.connections[failedID] == nil)

        // The re-formed circuit must actually deliver frames end-to-end.
        let collectorB = MessageCollector()
        await B.setDelegate(collectorB)
        await A.broadcastMessage(topic: "failover", payload: Data("after-failover".utf8))
        let delivered = await waitUntil(10_000) {
            collectorB.allMessages.contains {
                if case .peerMessage(let t, _) = $0.message { return t == "failover" }
                return false
            }
        }
        #expect(delivered)

        await A.stop(); await B.stop(); await R2.stop()
        if !viaR1 { await R1.stop() }
    }

    // MARK: - No-dial invariant

    /// The relay path bridges only PRE-EXISTING mutual connections. A
    /// relayConnect for a target the relay is NOT connected to must fail
    /// without triggering any dial on either side — a peer-supplied key/address
    /// must never become an outbound connection attempt (SSRF/probe surface).
    @Test("relayConnect for an unconnected target fails without any dial")
    func relayConnectForUnconnectedTargetDoesNotDial() async throws {
        let (pubR, skR) = keypair(); let (pubA, skA) = keypair()
        let (portR, portA): (UInt16, UInt16) = (19765, 19766)
        let R = Ivy(config: cfg(pub: pubR, priv: skR, port: portR, relay: true))
        let A = Ivy(config: cfg(pub: pubA, priv: skA, port: portA, relay: false))
        try await R.start(); try await A.start()

        let relayID = PeerID(publicKey: pubR), aID = PeerID(publicKey: pubA)
        try await A.connect(to: PeerEndpoint(publicKey: pubR, host: "127.0.0.1", port: portR))
        let connected = await waitUntil {
            let a = await A.connections[relayID] != nil
            let r = await R.connections[aID] != nil
            return a && r
        }
        #expect(connected)

        // A target nobody is connected to. The request must FAIL — and fail
        // without the relay (or A) dialing anything.
        let (pubX, _) = keypair()
        await #expect(throws: IvyError.self) {
            try await A.connectViaRelay(to: PeerEndpoint(publicKey: pubX, host: "relay", port: 0))
        }

        #expect(await A.connections.count == 1)   // only the relay
        #expect(await R.connections.count == 1)   // only A
        #expect(await A.connectingPeers.isEmpty)  // no dial in flight
        #expect(await R.connectingPeers.isEmpty)
        #expect(await R.relayService.activeCircuitCount() == 0)

        await A.stop(); await R.stop()
    }
}

@Suite("Relay carrier ordering (pure)")
struct RelayCarrierOrderingTests {

    private func p(_ name: String) -> PeerID { PeerID(publicKey: name) }

    @Test("candidates spanning two netgroups are tried diverse-first")
    func diverseOrderCoversGroupsFirst() {
        let candidates: [(peer: PeerID, group: String)] = [
            (p("a1"), "v4:10.0"), (p("a2"), "v4:10.0"), (p("a3"), "v4:10.0"),
            (p("b1"), "v4:20.0"),
        ]
        for _ in 0..<20 {  // shuffled internally — must hold for every draw
            let order = Ivy.diverseCarrierOrder(candidates: candidates, activeCarrierGroups: [])
            #expect(order.count == 4)
            let groupOf = Dictionary(uniqueKeysWithValues: candidates.map { ($0.peer, $0.group) })
            let firstTwoGroups = Set(order.prefix(2).compactMap { groupOf[$0] })
            #expect(firstTwoGroups == ["v4:10.0", "v4:20.0"],
                    "the first two attempts must span both netgroups")
        }
    }

    @Test("a netgroup already carrying a relayed connection sorts last")
    func activeCarrierGroupDeprioritized() {
        let candidates: [(peer: PeerID, group: String)] = [
            (p("used1"), "v4:10.0"), (p("used2"), "v4:10.0"), (p("used3"), "v4:10.0"),
            (p("fresh1"), "v4:20.0"),
        ]
        for _ in 0..<20 {
            let order = Ivy.diverseCarrierOrder(candidates: candidates, activeCarrierGroups: ["v4:10.0"])
            #expect(order.first == p("fresh1"),
                    "the only fresh-netgroup candidate must be tried first, even against a larger used group")
        }
    }

    @Test("a single netgroup keeps every candidate (no starvation)")
    func singleGroupKeepsAllCandidates() {
        let candidates: [(peer: PeerID, group: String)] = [
            (p("a"), "v4:10.0"), (p("b"), "v4:10.0"), (p("c"), "v4:10.0"),
        ]
        let order = Ivy.diverseCarrierOrder(candidates: candidates, activeCarrierGroups: ["v4:10.0"])
        #expect(Set(order) == [p("a"), p("b"), p("c")],
                "deprioritized is not excluded — a one-netgroup peer set must still fail over within it")
    }
}

private final class ProbeFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    func set() { lock.lock(); flag = true; lock.unlock() }
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return flag }
}

@Suite("Relayed circuit probe / failover timing")
struct RelayedProbeTimingTests {

    private func keypair() -> (pub: String, priv: Data) {
        let sk = Curve25519.Signing.PrivateKey()
        let pub = sk.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        return (pub, sk.rawRepresentation)
    }

    private func makeNode() -> Ivy {
        let (pub, priv) = keypair()
        return Ivy(config: IvyConfig(
            publicKey: pub,
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            healthConfig: PeerHealthConfig(keepaliveInterval: .seconds(999), staleTimeout: .seconds(999), maxMissedPongs: 99, enabled: false),
            enablePEX: false,
            signingKey: priv,
            relayEnabled: false
        ))
    }

    private func makeRelayedConn(id: String, onForward: (@Sendable (Data) -> Void)? = nil) -> PeerConnection {
        PeerConnection(
            id: PeerID(publicKey: id),
            endpoint: PeerEndpoint(publicKey: id, host: "relay", port: 0),
            channel: nil,
            relayForward: onForward ?? { _ in },
            relayedClaimedKey: id
        )
    }

    @Test("failover bound is a small multiple of the probe interval and far below the legacy 300s")
    func failoverBoundsAreCoherent() {
        #expect(PeerConnection.relayedFailoverTimeout == PeerConnection.relayedProbeInterval * 3,
                "failover = 3 consecutive unanswered probes")
        #expect(PeerConnection.relayedFailoverTimeout < PeerConnection.relayedStaleTimeout,
                "active failover must fire before the passive isLive backstop")
        #expect(PeerConnection.relayedStaleTimeout < .seconds(300),
                "the passive backstop itself must beat the legacy 300s bound")
    }

    @Test("a silent relayed connection fails the probe and is torn down; a fresh one is pinged")
    func silentRelayedConnectionFailsProbe() async {
        let node = makeNode()

        // Fresh: probe keeps the loop alive and sends a ping over the circuit.
        let pinged = ProbeFlag()
        let fresh = makeRelayedConn(id: "fresh-peer", onForward: { _ in pinged.set() })
        await node.registerConnectionForTesting(fresh, as: fresh.id)
        #expect(await node.probeRelayedConnection(fresh))
        #expect(pinged.isSet, "a live probe tick must ping the circuit")

        // Silent past the failover bound: probe tears the connection down.
        let silent = makeRelayedConn(id: "silent-peer")
        await node.registerConnectionForTesting(silent, as: silent.id)
        silent.backdateInboundActivityForTesting(by: PeerConnection.relayedFailoverTimeout + .seconds(1))
        #expect(await node.probeRelayedConnection(silent) == false)
        #expect(silent.isLive == false, "a probe-declared-dead connection must be closed")

        // A connection no longer registered (superseded) stops its loop quietly.
        let gone = makeRelayedConn(id: "gone-peer")
        #expect(await node.probeRelayedConnection(gone) == false)
        #expect(gone.isLive, "an unregistered connection is not torn down by a stray probe")
    }

    @Test("isLive backstop uses the tightened stale bound")
    func isLiveUsesTightenedStaleBound() {
        let conn = makeRelayedConn(id: "stale-check")
        #expect(conn.isLive)
        conn.backdateInboundActivityForTesting(by: PeerConnection.relayedStaleTimeout + .seconds(1))
        #expect(conn.isLive == false)
    }
}

@Suite("Relay carrier seeds (keep-N pool)")
struct RelayCarrierSeedTests {

    private func makeNode() -> Ivy {
        let sk = Curve25519.Signing.PrivateKey()
        let pub = sk.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        return Ivy(config: IvyConfig(
            publicKey: pub,
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            enablePEX: false,
            signingKey: sk.rawRepresentation,
            relayEnabled: false
        ))
    }

    private func ep(_ key: String, _ host: String) -> PeerEndpoint {
        PeerEndpoint(publicKey: key, host: host, port: 4001)
    }

    @Test("seed set is bounded and prefers netgroup diversity on displacement")
    func seedsBoundedAndDiverse() async {
        let node = makeNode()
        await node.recordRelayCarrierSeed(key: "k1", endpoint: ep("k1", "10.0.0.1"))
        await node.recordRelayCarrierSeed(key: "k2", endpoint: ep("k2", "20.0.0.1"))
        await node.recordRelayCarrierSeed(key: "k3", endpoint: ep("k3", "10.0.9.9"))  // duplicates k1's /16
        #expect(await node.relayCarrierSeeds.count == 3)

        // Full + newcomer from an ALREADY-covered netgroup: no displacement.
        await node.recordRelayCarrierSeed(key: "k4", endpoint: ep("k4", "20.0.5.5"))
        #expect(await node.relayCarrierSeeds["k4"] == nil)
        #expect(await node.relayCarrierSeeds.count == 3)

        // Full + newcomer ADDING a netgroup: displaces one member of the
        // duplicated group, so the set covers {10.0, 20.0, 30.0}.
        await node.recordRelayCarrierSeed(key: "k5", endpoint: ep("k5", "30.0.0.1"))
        let seeds = await node.relayCarrierSeeds
        #expect(seeds.count == 3)
        #expect(seeds["k5"] != nil)
        #expect(seeds["k2"] != nil)
        #expect((seeds["k1"] != nil) != (seeds["k3"] != nil), "exactly one duplicated-group member survives")
    }
}

@Suite("RelayService reserved netgroup headroom")
struct RelayHeadroomTests {

    @Test("a single-netgroup flood cannot take the reserved last slots")
    func reservedHeadroomBlocksSingleNetgroupSaturation() async {
        let relay = RelayService()
        let cutoff = RelayService.maxTotalCircuits - RelayService.reservedNetgroupHeadroom
        for i in 0..<cutoff {
            #expect(await relay.createCircuit(initiator: "a\(i)", target: "b\(i)", initiatorGroup: "v4:66.66"))
        }
        // The flood's own netgroup is refused in the reserved zone…
        #expect(await relay.createCircuit(initiator: "flood", target: "x", initiatorGroup: "v4:66.66") == false)
        // …an unknown-group initiator is refused too (fail closed)…
        #expect(await relay.createCircuit(initiator: "anon", target: "y") == false)
        // …but a netgroup-novel initiator still finds room.
        #expect(await relay.createCircuit(initiator: "fresh", target: "z", initiatorGroup: "v4:77.1"))
    }
}
