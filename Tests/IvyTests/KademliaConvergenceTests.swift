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

private actor SimulatedNeighborNetwork {
    private let responses: [String: [PeerEndpoint]]
    private let partitioned: Set<String>
    private var requestCount = 0
    private var released = false
    private var releaseOrder: [String] = []
    private var nextReleaseIndex = 0

    init(responses: [String: [PeerEndpoint]], partitioned: Set<String>) {
        self.responses = responses
        self.partitioned = partitioned
    }

    func request(from peer: PeerID) async -> [PeerEndpoint] {
        requestCount += 1
        guard !released else { return response(for: peer.publicKey) }
        do {
            try await TestSynchronization.wait(
                for: "simulated neighbor response from \(peer.publicKey)"
            ) {
                await self.canRelease(peer.publicKey)
            }
        } catch TestSynchronizationError.cancelled {
            return []
        } catch {
            Issue.record("\(error)")
            return []
        }
        nextReleaseIndex += 1
        return response(for: peer.publicKey)
    }

    func waitForRequests(_ count: Int) async throws {
        try await TestSynchronization.wait(for: "\(count) simulated neighbor request(s)") {
            await self.hasRequests(count)
        }
    }

    func release(in order: [String]) {
        released = true
        releaseOrder = order
    }

    private func canRelease(_ key: String) -> Bool {
        nextReleaseIndex < releaseOrder.count && releaseOrder[nextReleaseIndex] == key
    }

    private func hasRequests(_ count: Int) -> Bool { requestCount >= count }

    private func response(for key: String) -> [PeerEndpoint] {
        partitioned.contains(key) ? [] : responses[key] ?? []
    }
}

@Suite("Kademlia lookup", .serialized)
struct KademliaConvergenceTests {
    @Test("seeded reply ordering and one partition still converge")
    func seededAdversarialSchedule() async throws {
        let identity = TransportTestHarness.identity("kad-seeded-source")
        let node = Ivy(config: TransportTestHarness.config(
            identity,
            port: TransportTestHarness.nextPort()))
        let initial = (0..<3).map { testEndpoint("kad-seeded-\($0)", port: UInt16(4100 + $0)) }
        let target = testEndpoint("kad-seeded-target", port: 4200)
        var generator = TestSeededGenerator(seed: 0x1A17)
        let partitioned = initial[Int(generator.next() % UInt64(initial.count))].publicKey
        let responseOrder = generator.shuffled(initial.map(\.publicKey))
        let network = SimulatedNeighborNetwork(
            responses: Dictionary(uniqueKeysWithValues: initial.map { ($0.publicKey, [target]) }),
            partitioned: [partitioned])

        try await node.start()
        for (index, endpoint) in (initial + [target]).enumerated() {
            try await node.seedConnectedEndpointForTesting(endpoint, marker: UInt8(index + 1))
        }
        for endpoint in initial { await node.seedKademliaTestEndpoint(endpoint) }
        await node.setNeighborRequestHookForTesting { peer, _ in
            await network.request(from: peer)
        }

        let lookup = BoundedTestTask { await node.findNode(target: target.publicKey) }
        try await network.waitForRequests(initial.count)
        await network.release(in: responseOrder)

        let result = try await lookup.value(waitingFor: "seeded multi-hop lookup")
        #expect(result.contains(target))
        await node.stop()
    }

    @Test("findNode follows deterministic multi-hop referrals")
    func successfulMultiHopLookup() async throws {
        let identity = TransportTestHarness.identity("kad-multihop-source")
        let node = Ivy(config: TransportTestHarness.config(
            identity,
            port: TransportTestHarness.nextPort()))
        let first = testEndpoint("kad-multihop-first", port: 4001)
        let second = testEndpoint("kad-multihop-second", port: 4002)
        let target = testEndpoint("kad-multihop-target", port: 4003)
        let responses = [
            first.publicKey: [second],
            second.publicKey: [target],
            target.publicKey: [],
        ]

        try await node.start()
        try await node.seedConnectedEndpointForTesting(first, marker: 1)
        try await node.seedConnectedEndpointForTesting(second, marker: 2)
        try await node.seedConnectedEndpointForTesting(target, marker: 3)
        await node.seedKademliaTestEndpoint(first)
        await node.setNeighborRequestHookForTesting { peer, _ in
            responses[peer.publicKey] ?? []
        }

        let result = await node.findNode(target: target.publicKey)

        #expect(result.contains(target))
        await node.stop()
    }

    @Test("authenticated network referrals converge across multiple hops")
    func authenticatedMultiHopNetworkLookup() async throws {
        let sourceIdentity = TransportTestHarness.identity("kad-network-source")
        let firstIdentity = TransportTestHarness.identity("kad-network-first")
        let secondIdentity = TransportTestHarness.identity("kad-network-second")
        let targetIdentity = TransportTestHarness.identity("kad-network-target")
        let sourcePort = TransportTestHarness.nextPort()
        let firstPort = TransportTestHarness.nextPort()
        let secondPort = TransportTestHarness.nextPort()
        let targetPort = TransportTestHarness.nextPort()
        let firstHost = "8.8.8.8"
        let secondHost = "1.1.1.1"
        let targetHost = "9.9.9.9"

        let source = Ivy(config: TransportTestHarness.config(sourceIdentity, port: sourcePort))
        let first = Ivy(config: TransportTestHarness.config(
            firstIdentity,
            port: firstPort,
            advertisedHost: firstHost))
        let second = Ivy(config: TransportTestHarness.config(
            secondIdentity,
            port: secondPort,
            advertisedHost: secondHost))
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort,
            advertisedHost: targetHost))
        let recorder = TransportTestRecorder()
        await source.setTestDelegate(recorder)

        let localPorts = [
            firstHost: firstPort,
            secondHost: secondPort,
            targetHost: targetPort,
        ]
        await source.setDialEndpointRewriteForTesting { endpoint in
            guard let port = localPorts[endpoint.host] else { return endpoint }
            return PeerEndpoint(
                publicKey: endpoint.publicKey,
                host: "127.0.0.1",
                port: port)
        }

        try await target.start()
        try await second.start()
        try await first.start()
        try await source.start()
        try await second.connect(to: TransportTestHarness.endpoint(targetIdentity, port: targetPort))
        try await first.connect(to: TransportTestHarness.endpoint(secondIdentity, port: secondPort))
        try await source.connect(to: TransportTestHarness.endpoint(firstIdentity, port: firstPort))

        let firstID = TransportTestHarness.key(firstIdentity).peerID
        let secondID = TransportTestHarness.key(secondIdentity).peerID
        let targetKey = TransportTestHarness.key(targetIdentity)
        try await recorder.waitForConnect(firstID)

        let lookup = BoundedTestTask { await source.findNode(target: targetKey.hex) }
        let result = try await lookup.value(waitingFor: "authenticated multi-hop lookup")

        try await recorder.waitForConnect(secondID)
        try await recorder.waitForConnect(targetKey.peerID)
        #expect(result.contains(PeerEndpoint(
            publicKey: targetKey.hex,
            host: targetHost,
            port: targetPort)))
        #expect(await source.peerConnectionCount == 3)

        await source.stop()
        await first.stop()
        await second.stop()
        await target.stop()
    }

    @Test("a public lookup cannot cross stop and restart")
    func publicLookupIsRunScoped() async throws {
        let identity = TransportTestHarness.identity("kad-public-run-source")
        let node = Ivy(config: TransportTestHarness.config(
            identity,
            port: TransportTestHarness.nextPort()))
        let first = testEndpoint("kad-public-run-first", port: 4001)
        let stale = testEndpoint("kad-public-run-stale", port: 4002)
        let responseBarrier = TestBarrier("stale neighbor response")

        try await node.start()
        try await node.seedConnectedEndpointForTesting(first, marker: 1)
        await node.seedKademliaTestEndpoint(first)
        await node.setNeighborRequestHookForTesting { _, _ in
            do {
                try await responseBarrier.arriveAndWait()
            } catch {
                Issue.record("\(error)")
            }
            return [stale]
        }

        let lookup = BoundedTestTask { await node.findNode(target: stale.publicKey) }
        try await responseBarrier.waitForArrivals()
        await node.stop()
        try await node.start()
        await responseBarrier.release()

        #expect(try await lookup.value(waitingFor: "stale lookup completion").isEmpty)
        #expect(!(await node.knownPeerEndpoints).contains(stale))
        await node.stop()
    }

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

        let lookupA = BoundedTestTask {
            await source.awaitKademliaTestResponse(nonce: 10, from: peerA)
        }
        let lookupB = BoundedTestTask {
            await source.awaitKademliaTestResponse(nonce: 11, from: peerB)
        }
        #expect(try await TransportTestHarness.eventually {
            await source.pendingKademliaTestResponseCount() == 2
        })

        await source.receiveNeighborResponse(nonce: 11, endpoints: [endpointB], from: peerB)
        await source.receiveNeighborResponse(nonce: 10, endpoints: [endpointA], from: peerA)

        #expect(try await lookupA.value(waitingFor: "neighbor response A") == [endpointA])
        #expect(try await lookupB.value(waitingFor: "neighbor response B") == [endpointB])
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
