import Testing
import Foundation
import Crypto
@testable import Ivy
@testable import Tally

/// End-to-end proof that two nodes with NO direct link reach each other through a
/// circuit relay — the Phase 1 connectivity guarantee. Real loopback TCP (the
/// relay path operates on real `connections`, not the in-memory harness), with
/// real identity keys (identify requires a valid signature).
@Suite("NAT circuit relay (integration)")
struct RelayIntegrationTests {
    private enum TestTimeout: Error {
        case timedOut
    }

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

    private func withTimeout<T: Sendable>(
        _ duration: Duration,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(for: duration)
                throw TestTimeout.timedOut
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    @Test("legacy relayStatus resolves a single pending relay request")
    func legacyRelayStatusResolvesSinglePendingRequest() async throws {
        let (pubA, skA) = keypair()
        let node = Ivy(config: cfg(pub: pubA, priv: skA, port: 0, relay: false))
        let relay = PeerID(publicKey: "legacy-relay")
        let task = Task { await node.parkRelayRequestForTesting(relayPeer: relay, nonce: 42) }

        try await Task.sleep(for: .milliseconds(20))
        await node.resolveRelayRequest(from: relay, code: 0, nonce: 0)

        let result = try await withTimeout(.milliseconds(500)) { await task.value }
        #expect(result)
        #expect(await node.pendingRelayRequests.isEmpty)
    }

    @Test("cleanupAllPending resolves pending relay requests")
    func cleanupAllPendingResolvesRelayRequests() async throws {
        let (pubA, skA) = keypair()
        let node = Ivy(config: cfg(pub: pubA, priv: skA, port: 0, relay: false))
        let relay = PeerID(publicKey: "cleanup-relay")
        let task = Task { await node.parkRelayRequestForTesting(relayPeer: relay, nonce: 7) }

        try await Task.sleep(for: .milliseconds(20))
        await node.cleanupAllPending()

        let result = try await withTimeout(.milliseconds(500)) { await task.value }
        #expect(!result)
        #expect(await node.pendingRelayRequests.isEmpty)
    }

    @Test("two NAT'd nodes exchange a message through a relay")
    func natToNatViaRelay() async throws {
        let (pubR, skR) = keypair(); let (pubA, skA) = keypair(); let (pubB, skB) = keypair()
        let (portR, portA, portB): (UInt16, UInt16, UInt16) = (19701, 19702, 19703)
        let R = Ivy(config: cfg(pub: pubR, priv: skR, port: portR, relay: true))
        let A = Ivy(config: cfg(pub: pubA, priv: skA, port: portA, relay: false))
        let B = Ivy(config: cfg(pub: pubB, priv: skB, port: portB, relay: false))
        try await R.start(); try await A.start(); try await B.start()

        let collectorB = MessageCollector()
        await B.setDelegate(collectorB)

        let relayID = PeerID(publicKey: pubR), aID = PeerID(publicKey: pubA), bID = PeerID(publicKey: pubB)

        // A and B connect ONLY to the relay (no direct A<->B link is ever formed).
        let rEndpoint = PeerEndpoint(publicKey: pubR, host: "127.0.0.1", port: portR)
        try await A.connect(to: rEndpoint)
        try await B.connect(to: rEndpoint)

        let connectedToRelay = await waitUntil {
            let aToR = await A.connections[relayID] != nil
            let bToR = await B.connections[relayID] != nil
            let rToA = await R.connections[aID] != nil
            let rToB = await R.connections[bID] != nil
            return aToR && bToR && rToA && rToB
        }
        #expect(connectedToRelay)

        // A reaches B through the relay.
        try await A.connectViaRelay(to: PeerEndpoint(publicKey: pubB, host: "relay", port: 0))

        let relayedBothSides = await waitUntil {
            let aToB = await A.connections[bID] != nil
            let bToA = await B.connections[aID] != nil
            return aToB && bToA
        }
        #expect(relayedBothSides)
        #expect(await R.relayService.activeCircuitCount() >= 1)

        // An application message A -> B travels over the circuit and surfaces at B.
        await A.broadcastMessage(topic: "relaytest", payload: Data("hello-over-relay".utf8))
        let delivered = await waitUntil {
            collectorB.allMessages.contains {
                if case .peerMessage(let topic, let payload) = $0.message {
                    return topic == "relaytest" && payload == Data("hello-over-relay".utf8)
                }
                return false
            }
        }
        #expect(delivered)

        await A.stop(); await B.stop(); await R.stop()
    }

    @Test("same relay can satisfy concurrent connectViaRelay requests")
    func concurrentConnectsViaSameRelayDoNotLeakContinuations() async throws {
        let (pubR, skR) = keypair(); let (pubA, skA) = keypair()
        let (pubB, skB) = keypair(); let (pubC, skC) = keypair()
        let (portR, portA, portB, portC): (UInt16, UInt16, UInt16, UInt16) = (19731, 19732, 19733, 19734)
        let R = Ivy(config: cfg(pub: pubR, priv: skR, port: portR, relay: true))
        let A = Ivy(config: cfg(pub: pubA, priv: skA, port: portA, relay: false))
        let B = Ivy(config: cfg(pub: pubB, priv: skB, port: portB, relay: false))
        let C = Ivy(config: cfg(pub: pubC, priv: skC, port: portC, relay: false))
        try await R.start(); try await A.start(); try await B.start(); try await C.start()

        let relayID = PeerID(publicKey: pubR), aID = PeerID(publicKey: pubA)
        let bID = PeerID(publicKey: pubB), cID = PeerID(publicKey: pubC)
        let rEndpoint = PeerEndpoint(publicKey: pubR, host: "127.0.0.1", port: portR)
        try await A.connect(to: rEndpoint)
        try await B.connect(to: rEndpoint)
        try await C.connect(to: rEndpoint)

        let connectedToRelay = await waitUntil {
            let aToR = await A.connections[relayID] != nil
            let rToA = await R.connections[aID] != nil
            let rToB = await R.connections[bID] != nil
            let rToC = await R.connections[cID] != nil
            return aToR && rToA && rToB && rToC
        }
        #expect(connectedToRelay)

        try await withTimeout(.seconds(3)) {
            async let toB: Void = A.connectViaRelay(to: PeerEndpoint(publicKey: pubB, host: "relay", port: 0))
            async let toC: Void = A.connectViaRelay(to: PeerEndpoint(publicKey: pubC, host: "relay", port: 0))
            try await toB
            try await toC
        }

        let relayedBoth = await waitUntil {
            let aToB = await A.connections[bID] != nil
            let aToC = await A.connections[cID] != nil
            let bToA = await B.connections[aID] != nil
            let cToA = await C.connections[aID] != nil
            return aToB && aToC && bToA && cToA
        }
        #expect(relayedBoth)

        await A.stop(); await B.stop(); await C.stop(); await R.stop()
    }

    @Test("connect() falls back to a relay when the direct dial fails (P0 wiring)")
    func directFailFallsBackToRelay() async throws {
        let (pubR, skR) = keypair(); let (pubA, skA) = keypair(); let (pubB, skB) = keypair()
        let (portR, portA, portB): (UInt16, UInt16, UInt16) = (19711, 19712, 19713)
        let R = Ivy(config: cfg(pub: pubR, priv: skR, port: portR, relay: true))
        let A = Ivy(config: cfg(pub: pubA, priv: skA, port: portA, relay: false))
        let B = Ivy(config: cfg(pub: pubB, priv: skB, port: portB, relay: false))
        try await R.start(); try await A.start(); try await B.start()
        let collectorB = MessageCollector(); await B.setDelegate(collectorB)
        let aID = PeerID(publicKey: pubA), bID = PeerID(publicKey: pubB), relayID = PeerID(publicKey: pubR)

        let rEndpoint = PeerEndpoint(publicKey: pubR, host: "127.0.0.1", port: portR)
        try await A.connect(to: rEndpoint); try await B.connect(to: rEndpoint)
        _ = await waitUntil {
            let a = await A.connections[relayID] != nil
            let rb = await R.connections[bID] != nil
            return a && rb
        }

        // Direct dial to B at a CLOSED port fails -> connect() must fall back to the relay.
        try? await A.connect(to: PeerEndpoint(publicKey: pubB, host: "127.0.0.1", port: 59998))
        let viaRelay = await waitUntil {
            let aToB = await A.connections[bID] != nil
            let bToA = await B.connections[aID] != nil
            return aToB && bToA
        }
        #expect(viaRelay)

        await A.broadcastMessage(topic: "fallback", payload: Data("via-fallback".utf8))
        let delivered = await waitUntil {
            collectorB.allMessages.contains {
                if case .peerMessage(let t, _) = $0.message { return t == "fallback" }
                return false
            }
        }
        #expect(delivered)
        await A.stop(); await B.stop(); await R.stop()
    }

    @Test("relay frees a peer's circuits on disconnect (H4)")
    func circuitFreedOnDisconnect() async throws {
        let (pubR, skR) = keypair(); let (pubA, skA) = keypair(); let (pubB, skB) = keypair()
        let (portR, portA, portB): (UInt16, UInt16, UInt16) = (19721, 19722, 19723)
        let R = Ivy(config: cfg(pub: pubR, priv: skR, port: portR, relay: true))
        let A = Ivy(config: cfg(pub: pubA, priv: skA, port: portA, relay: false))
        let B = Ivy(config: cfg(pub: pubB, priv: skB, port: portB, relay: false))
        try await R.start(); try await A.start(); try await B.start()
        let aID = PeerID(publicKey: pubA), bID = PeerID(publicKey: pubB), relayID = PeerID(publicKey: pubR)

        let rEndpoint = PeerEndpoint(publicKey: pubR, host: "127.0.0.1", port: portR)
        try await A.connect(to: rEndpoint); try await B.connect(to: rEndpoint)
        _ = await waitUntil {
            let aToR = await A.connections[relayID] != nil
            let rToA = await R.connections[aID] != nil
            let rToB = await R.connections[bID] != nil
            return aToR && rToA && rToB
        }

        try await A.connectViaRelay(to: PeerEndpoint(publicKey: pubB, host: "relay", port: 0))
        _ = await waitUntil { await R.relayService.activeCircuitCount() >= 1 }
        #expect(await R.relayService.activeCircuitCount() >= 1)

        // A disconnects from the relay -> the relay must free A's circuit (not leak it).
        await A.stop()
        let freed = await waitUntil { await R.relayService.activeCircuitCount() == 0 }
        #expect(freed)
        await B.stop(); await R.stop()
    }
}

private extension Ivy {
    func parkRelayRequestForTesting(relayPeer: PeerID, nonce: UInt64) async -> Bool {
        await withCheckedContinuation { cont in
            let key = PendingRelayRequestKey(relayPeer: relayPeer, nonce: nonce)
            pendingRelayRequests[key] = cont
        }
    }
}
