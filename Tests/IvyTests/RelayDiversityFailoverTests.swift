import Testing
import Foundation
import Crypto
import NIOCore
import NIOEmbedded
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

    // MARK: - Outbound observed-address capture (H1 root cause)

    /// An OUTBOUND dial must capture the unforgeable L3 remote as `observedHost`
    /// BEFORE identify runs — otherwise carrier netgroup diversity falls through
    /// to the peer's self-advertised (forgeable) endpoint host. Before the fix
    /// outbound connections had `observedHost == nil`; after, it is the dialed IP
    /// and drives `carrierNetgroup`.
    @Test("an outbound dial captures the observed L3 address for netgroup diversity")
    func outboundDialCapturesObservedHost() async throws {
        let (pubR, skR) = keypair(); let (pubA, skA) = keypair()
        let (portR, portA): (UInt16, UInt16) = (19771, 19772)
        let R = Ivy(config: cfg(pub: pubR, priv: skR, port: portR, relay: true))
        let A = Ivy(config: cfg(pub: pubA, priv: skA, port: portA, relay: false))
        try await R.start(); try await A.start()

        let rID = PeerID(publicKey: pubR)
        try await A.connect(to: PeerEndpoint(publicKey: pubR, host: "127.0.0.1", port: portR))
        let connected = await waitUntil { await A.connections[rID] != nil }
        #expect(connected)

        let observed = await A.connections[rID]?.observedHost
        #expect(observed == "127.0.0.1", "outbound dial must record the dialed L3 remote")
        let group = await A.carrierNetgroup(A.connections[rID]!)
        #expect(group == NetGroup.group("127.0.0.1"), "carrier netgroup derives from the observed address")

        await A.stop(); await R.stop()
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

    private func waitUntil(_ timeoutMs: Int = 5000, _ cond: @Sendable () async -> Bool) async -> Bool {
        var waited = 0
        while waited < timeoutMs {
            if await cond() { return true }
            try? await Task.sleep(for: .milliseconds(50))
            waited += 50
        }
        return await cond()
    }

    /// A DIRECT connection (live channel, no relayForward) whose netgroup derives
    /// from `observed`. Backed by an `EmbeddedChannel` so `channel != nil` holds
    /// without a real socket.
    private func directCarrier(_ key: String, observed: String) -> PeerConnection {
        let conn = PeerConnection(
            id: PeerID(publicKey: key),
            endpoint: PeerEndpoint(publicKey: key, host: observed, port: 4001),
            channel: EmbeddedChannel()
        )
        conn.observedHost = observed
        return conn
    }

    // MARK: - Finding 3: carrier-seed redial must be direct-only

    /// Redialing a carrier seed must NOT fall back to `connectViaRelay`: a seed
    /// reachable only via relay is not a usable carrier (a relayed connection has
    /// `channel == nil`). The old path called the general `connect(to:)`, which
    /// on direct-dial failure opened a RELAYED connection to the seed, cleared its
    /// failure count, and — because `connections[seed] != nil` — suppressed all
    /// future direct redials, leaving the carrier pool falsely "restored".
    ///
    /// RED before the fix: with a direct carrier present, the relay-fallback fires
    /// and initiates a relay request (`nextRelayRequestNonce` advances).
    /// GREEN after: the dial fails direct-only, records a failure toward eviction,
    /// and never touches the relay path.
    @Test("carrier-seed redial is direct-only and a relay-only seed is not a restored carrier")
    func carrierSeedRedialIsDirectOnly() async {
        let node = makeNode()
        // A direct carrier so the OLD relay-fallback would have had a candidate.
        let carrier = directCarrier("carrier-key", observed: "10.0.0.1")
        await node.registerConnectionForTesting(carrier, as: carrier.id)

        let seedKey = "relay-only-seed"
        let seedID = PeerID(publicKey: seedKey)
        // Nothing listens on loopback:1 — the direct dial is refused immediately.
        let seedEndpoint = PeerEndpoint(publicKey: seedKey, host: "127.0.0.1", port: 1)

        let nonceBefore = await node.nextRelayRequestNonce
        await node.redialRelayCarrierSeed(key: seedKey, endpoint: seedEndpoint)

        // No relay request was ever initiated (direct-only: no connectViaRelay).
        #expect(await node.nextRelayRequestNonce == nonceBefore)
        // The failed dial counts toward eviction — not suppressed, not cleared.
        #expect(await node.relayCarrierSeedFailures[seedKey] == 1)
        // No relayed connection to the seed was created; it is not a live carrier.
        #expect(await node.connections[seedID] == nil)
    }

    // MARK: - Finding 2: only relay-capable direct peers count as carriers

    /// A relay-dependent node with a couple of ordinary (non-relay) direct peers
    /// must STILL replenish its relay-carrier pool — those peers ignore
    /// relayConnect and cannot carry a circuit. The carrier-sufficiency accounting
    /// must count only relay-capable direct connections; otherwise the node returns
    /// early and never re-dials its known-good relay seeds.
    ///
    /// RED before the fix: the two non-relay direct peers (distinct netgroups)
    /// satisfy the carrier floor, so `ensureRelayCarrierConnections` early-returns
    /// and no seed redial happens. GREEN after: they do not count, so the
    /// disconnected relay seed is re-dialed (its dial fails → failure recorded).
    @Test("two non-relay direct peers do not satisfy the relay-carrier floor")
    func nonRelayDirectPeersDoNotCountAsCarriers() async {
        let node = makeNode()
        // Two ordinary direct peers in DISTINCT netgroups — not relay-capable.
        let p1 = directCarrier("plain-peer-1", observed: "10.0.0.1")
        let p2 = directCarrier("plain-peer-2", observed: "20.0.0.1")
        await node.registerConnectionForTesting(p1, as: p1.id)
        await node.registerConnectionForTesting(p2, as: p2.id)

        // A known-good relay seed that is NOT currently connected (loopback:1
        // refuses, so the redial fails fast and records a failure).
        let seedKey = "carrier-seed"
        await node.recordRelayCarrierSeed(
            key: seedKey,
            endpoint: PeerEndpoint(publicKey: seedKey, host: "127.0.0.1", port: 1),
            group: NetGroup.group("30.0.0.1")
        )

        await node.ensureRelayCarrierConnections()

        // The seed must be re-dialed despite the two plain peers being present.
        let redialed = await waitUntil(3000) { await node.relayCarrierSeedFailures[seedKey] == 1 }
        #expect(redialed, "a disconnected relay seed must be re-dialed when the only direct peers are non-relay")
    }

    // MARK: - knownRelays carrier top-up must be direct-only and not suppressed by a relayed conn

    private func keypair() -> (pub: String, priv: Data) {
        let sk = Curve25519.Signing.PrivateKey()
        let pub = sk.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        return (pub, sk.rawRepresentation)
    }

    /// (a) The configured-knownRelays top-up in ensureRelayCarrierConnections must
    /// dial DIRECT-ONLY. A knownRelay reachable only via another relay is not a
    /// usable carrier, so a failed direct dial must count as a failed top-up — never
    /// open a channel-less relayed connection (which would falsely read as a restored
    /// carrier and, because connections[relay] != nil, block all future top-up).
    ///
    /// RED before the fix: the top-up's connect(to:) (allowRelayFallback defaulting
    /// true), with a direct carrier present, fires connectViaRelay on direct-dial
    /// failure, advancing nextRelayRequestNonce and opening a relayed connection.
    /// GREEN after: direct-only, no relay request, no connection to the relay.
    @Test("knownRelays carrier top-up is direct-only (no relay fallback)")
    func knownRelaysTopUpIsDirectOnly() async {
        let (pub, priv) = keypair()
        // Nothing listens on loopback:1 — a direct dial to the relay is refused fast.
        let relayEndpoint = PeerEndpoint(publicKey: "known-relay-directonly", host: "127.0.0.1", port: 1)
        let node = Ivy(config: IvyConfig(
            publicKey: pub,
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            enablePEX: false,
            signingKey: priv,
            relayEnabled: false,
            knownRelays: [relayEndpoint]
        ))

        // A direct carrier (channel != nil) so the OLD relay-fallback would have had
        // a candidate to route a circuit through.
        let carrier = directCarrier("carrier-key-a", observed: "10.0.0.1")
        await node.registerConnectionForTesting(carrier, as: carrier.id)

        // A relayed connection to an unrelated peer so ensureRelayCarrierConnections
        // passes its "has relayed conns" guard and reaches the knownRelays top-up.
        let dummyRelayed = PeerConnection(
            id: PeerID(publicKey: "dummy-relayed-a"),
            endpoint: PeerEndpoint(publicKey: "dummy-relayed-a", host: "relay", port: 0),
            channel: nil,
            relayForward: { _ in }
        )
        await node.registerConnectionForTesting(dummyRelayed, as: dummyRelayed.id)

        let relayID = PeerID(publicKey: relayEndpoint.publicKey)
        let nonceBefore = await node.nextRelayRequestNonce
        await node.ensureRelayCarrierConnections()
        // Allow the spawned top-up Task to run to completion.
        _ = await waitUntil(2000) { await node.nextRelayRequestNonce != nonceBefore }

        // No relay request was ever initiated by the top-up path (direct-only).
        #expect(await node.nextRelayRequestNonce == nonceBefore)
        // The failed direct dial opened no (relayed) connection to the relay.
        #expect(await node.connections[relayID] == nil)
    }

    /// (b) A pre-existing RELAYED connection (channel == nil) to a configured
    /// knownRelay must NOT suppress a DIRECT top-up dial — only a live DIRECT channel
    /// counts as a satisfied carrier. Otherwise the false relayed carrier permanently
    /// blocks the relay from becoming a real (direct, circuit-capable) carrier.
    ///
    /// RED before the fix: the skip check is `connections[relay] == nil`, so the
    /// relayed connection suppresses the direct dial and the relay stays relayed
    /// (channel == nil). GREEN after: the skip requires a live direct channel, so the
    /// direct top-up proceeds and (the relay being reachable) establishes a DIRECT
    /// channel, replacing the relayed connection.
    @Test("a relayed connection to a knownRelay does not suppress a direct top-up dial")
    func relayedConnDoesNotSuppressDirectTopUp() async throws {
        let (pubR, skR) = keypair()
        let portR: UInt16 = 19781
        let R = Ivy(config: IvyConfig(
            publicKey: pubR,
            listenPort: portR,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            healthConfig: PeerHealthConfig(keepaliveInterval: .seconds(999), staleTimeout: .seconds(999), maxMissedPongs: 99, enabled: false),
            enablePEX: false,
            signingKey: skR,
            relayEnabled: true
        ))
        try await R.start()

        let (pubA, skA) = keypair()
        let relayEndpoint = PeerEndpoint(publicKey: pubR, host: "127.0.0.1", port: portR)
        // A is deliberately NOT started: start() would itself auto-connect to every
        // knownRelay directly, contaminating the setup. We drive only the top-up path.
        // An outbound dial does not require A's listener to be running.
        let A = Ivy(config: IvyConfig(
            publicKey: pubA,
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            healthConfig: PeerHealthConfig(keepaliveInterval: .seconds(999), staleTimeout: .seconds(999), maxMissedPongs: 99, enabled: false),
            enablePEX: false,
            signingKey: skA,
            relayEnabled: false,
            knownRelays: [relayEndpoint]
        ))

        // The ONLY connection to the knownRelay is RELAYED (channel == nil). It also
        // satisfies the ensureRelayCarrierConnections "has relayed conns" guard.
        let relayID = PeerID(publicKey: pubR)
        let relayedConn = PeerConnection(
            id: relayID,
            endpoint: PeerEndpoint(publicKey: pubR, host: "relay", port: 0),
            channel: nil,
            relayForward: { _ in }
        )
        await A.registerConnectionForTesting(relayedConn, as: relayID)
        #expect(await A.connections[relayID]?.channel == nil)

        await A.ensureRelayCarrierConnections()

        // The direct top-up was NOT suppressed: A now holds a live DIRECT channel to
        // the relay (the relayed connection was replaced).
        let becameDirect = await waitUntil(5000) { await A.connections[relayID]?.channel != nil }
        #expect(becameDirect, "a relayed connection must not suppress the direct knownRelay top-up dial")

        await A.stop(); await R.stop()
    }

    @Test("seed set is bounded and prefers netgroup diversity on displacement")
    func seedsBoundedAndDiverse() async {
        let node = makeNode()
        // Diversity keys on the observed netgroup passed in, not the endpoint host.
        func record(_ key: String, _ host: String) async {
            await node.recordRelayCarrierSeed(key: key, endpoint: ep(key, host), group: NetGroup.group(host))
        }
        await record("k1", "10.0.0.1")
        await record("k2", "20.0.0.1")
        await record("k3", "10.0.9.9")  // duplicates k1's /16
        #expect(await node.relayCarrierSeeds.count == 3)

        // Full + newcomer from an ALREADY-covered netgroup: no displacement.
        await record("k4", "20.0.5.5")
        #expect(await node.relayCarrierSeeds["k4"] == nil)
        #expect(await node.relayCarrierSeeds.count == 3)

        // Full + newcomer ADDING a netgroup: displaces one member of the
        // duplicated group, so the set covers {10.0, 20.0, 30.0}.
        await record("k5", "30.0.0.1")
        let seeds = await node.relayCarrierSeeds
        #expect(seeds.count == 3)
        #expect(seeds["k5"] != nil)
        #expect(seeds["k2"] != nil)
        #expect((seeds["k1"] != nil) != (seeds["k3"] != nil), "exactly one duplicated-group member survives")
    }

    /// A carrier's netgroup for diversity MUST come from its unforgeable observed
    /// L3 address — never the self-advertised endpoint host, which identify
    /// overwrites with peer-controlled listenAddrs. Two carriers whose advertised
    /// hosts claim DISTINCT netgroups but whose OBSERVED sockets are the SAME
    /// netgroup must collapse to one group (RED before the fix: advertised-derived
    /// groups look distinct; GREEN after: observed collapses them).
    @Test("carrierNetgroup derives from the observed address, not the advertised host")
    func carrierNetgroupUsesObservedNotAdvertised() async {
        let node = makeNode()

        // Advertised host claims 8.8.0.0/16; observed socket is 10.0.0.0/16.
        let forged = PeerConnection(
            id: PeerID(publicKey: "forged"),
            endpoint: PeerEndpoint(publicKey: "forged", host: "8.8.4.4", port: 4001),
            channel: nil,
            relayForward: { _ in }
        )
        forged.observedHost = "10.0.7.7"
        // A second carrier advertising a DIFFERENT fake netgroup, same observed /16.
        let forged2 = PeerConnection(
            id: PeerID(publicKey: "forged2"),
            endpoint: PeerEndpoint(publicKey: "forged2", host: "9.9.9.9", port: 4001),
            channel: nil,
            relayForward: { _ in }
        )
        forged2.observedHost = "10.0.8.8"

        let g1 = await node.carrierNetgroup(forged)
        let g2 = await node.carrierNetgroup(forged2)
        #expect(g1 == NetGroup.group("10.0.7.7"), "must use the observed address")
        #expect(g1 != NetGroup.group("8.8.4.4"), "must NOT use the advertised host")
        #expect(g1 == g2, "distinct advertised netgroups collapse to one observed netgroup")

        // No observed address → single sentinel group (cannot forge freshness),
        // never the mutable advertised host.
        let noObserved = PeerConnection(
            id: PeerID(publicKey: "noobs"),
            endpoint: PeerEndpoint(publicKey: "noobs", host: "1.2.3.4", port: 4001),
            channel: nil,
            relayForward: { _ in }
        )
        let gs = await node.carrierNetgroup(noObserved)
        #expect(gs == Ivy.unknownCarrierNetgroup)
        #expect(gs != NetGroup.group("1.2.3.4"))
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
