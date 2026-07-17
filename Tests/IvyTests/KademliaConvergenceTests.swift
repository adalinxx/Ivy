import Foundation
import Testing
@testable import Ivy
import Tally

private extension Ivy {
    func awaitKademliaTestResponse(nonce: UInt64, from peer: PeerID) async -> [PeerEndpoint] {
        await withCheckedContinuation { continuation in
            pendingNeighborResponses[nonce] = PendingNeighborResponse(
                peer: peer,
                continuation: continuation)
        }
    }

    func pendingKademliaTestResponseCount() -> Int {
        pendingNeighborResponses.count
    }

    func seedKademliaTestEndpoint(_ endpoint: PeerEndpoint) {
        let peer = PeerID(publicKey: endpoint.publicKey)
        router.addPeer(peer, endpoint: endpoint)
    }
}

@Suite("Kademlia lookup", .serialized)
struct KademliaConvergenceTests {
    @Test("findNode does not dial private third-party referrals")
    func findNodeRejectsPrivateThirdPartyRoutes() async throws {
        let identities = (0..<4).map { TransportTestHarness.identity("kad-node-\($0)") }
        let ports = (0..<4).map { _ in TransportTestHarness.nextPort() }
        let nodes = zip(identities, ports).map { identity, port in
            Ivy(config: TransportTestHarness.config(identity, port: port))
        }

        for node in nodes { try await node.start() }
        for index in 0..<3 {
            try await nodes[index].connect(to: TransportTestHarness.endpoint(
                identities[index + 1],
                port: ports[index + 1]))
        }
        #expect(try await TransportTestHarness.eventually {
            let counts = await (
                nodes[0].peerConnectionCount,
                nodes[1].peerConnectionCount,
                nodes[2].peerConnectionCount,
                nodes[3].peerConnectionCount)
            return counts == (1, 2, 2, 1)
        })

        let target = TransportTestHarness.key(identities[3]).hex
        let result = await nodes[0].findNode(target: target)
        #expect(!result.map(\.publicKey).contains(target))
        #expect(await nodes[0].peerConnectionCount == 1)

        for node in nodes.reversed() { await node.stop() }
    }

    @Test("Concurrent neighbor requests correlate reversed responses by nonce")
    func concurrentLookupsCorrelateByNonce() async throws {
        let source = Ivy(config: IvyConfig(publicKey: "nonce-source", listenPort: 0))
        let peerA = PeerID(publicKey: deterministicTestPeerKey("nonce-peer-a"))
        let peerB = PeerID(publicKey: deterministicTestPeerKey("nonce-peer-b"))
        let endpointA = testEndpoint("nonce-result-a", port: 2)
        let endpointB = testEndpoint("nonce-result-b", port: 3)

        let lookupA = Task { await source.awaitKademliaTestResponse(nonce: 10, from: peerA) }
        let lookupB = Task { await source.awaitKademliaTestResponse(nonce: 11, from: peerB) }
        #expect(try await TransportTestHarness.eventually {
            await source.pendingKademliaTestResponseCount() == 2
        })

        await source.receiveNeighborResponse(nonce: 11, endpoints: [endpointB], from: peerB)
        await source.receiveNeighborResponse(nonce: 10, endpoints: [endpointA], from: peerA)

        #expect(await lookupA.value == [endpointA])
        #expect(await lookupB.value == [endpointB])
    }

    @Test("failed routing endpoints are evicted")
    func failedEndpointIsEvicted() async throws {
        let identity = TransportTestHarness.identity("kad-failed-source")
        let node = Ivy(config: TransportTestHarness.config(
            identity,
            port: TransportTestHarness.nextPort()))
        let dead = testEndpoint("kad-dead", port: TransportTestHarness.nextPort())

        try await node.start()
        await node.seedKademliaTestEndpoint(dead)
        let result = await node.findNode(target: dead.publicKey)

        #expect(!result.contains(dead))
        #expect(!(await node.knownPeerEndpoints).contains(dead))
        await node.stop()
    }

    @Test("local dial deferral preserves routing evidence")
    func locallyDeferredEndpointIsRetained() async throws {
        let identity = TransportTestHarness.identity("kad-deferred-source")
        let node = Ivy(config: TransportTestHarness.config(
            identity,
            port: TransportTestHarness.nextPort(),
            maxConnections: 1))
        let deferred = testEndpoint("kad-deferred", port: TransportTestHarness.nextPort())

        try await node.start()
        await node.seedKademliaTestEndpoint(deferred)
        #expect(await node.reserveOutgoingDial(to: deferred))

        _ = await node.findNode(target: deferred.publicKey)

        #expect((await node.knownPeerEndpoints).contains(deferred))
        await node.stop()
    }

    @Test("stale dial completion cannot mutate a newer run")
    func staleDialCompletionIsRunScoped() async throws {
        let identity = TransportTestHarness.identity("kad-stale-dial-source")
        let node = Ivy(config: TransportTestHarness.config(
            identity,
            port: TransportTestHarness.nextPort(),
            maxConnections: 1))
        let endpoint = testEndpoint("kad-stale-dial", port: TransportTestHarness.nextPort())
        let peer = PeerID(publicKey: endpoint.publicKey)

        try await node.start()
        let oldGeneration = await node.runGeneration
        #expect(await node.reserveOutgoingDial(to: endpoint))
        await node.stop()

        try await node.start()
        let currentGeneration = await node.runGeneration
        await node.seedKademliaTestEndpoint(endpoint)
        #expect(await node.reserveOutgoingDial(to: endpoint))

        await node.finishOutgoingDial(to: peer, generation: oldGeneration, connected: false)
        #expect(!(await node.reserveOutgoingDial(to: endpoint)))
        await node.removeFailedRoutingPeer(peer, generation: oldGeneration)
        #expect((await node.knownPeerEndpoints).contains(endpoint))

        await node.finishOutgoingDial(to: peer, generation: currentGeneration, connected: false)
        #expect(await node.reserveOutgoingDial(to: endpoint))
        await node.stop()
    }
}

private func testEndpoint(_ label: String, port: UInt16) -> PeerEndpoint {
    PeerEndpoint(
        publicKey: deterministicTestPeerKey(label),
        host: "127.0.0.1",
        port: port)
}
