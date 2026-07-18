import Foundation
import NIOPosix
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
            maxConnections: 2))
        let referrer = testEndpoint("kad-deferred-referrer", port: 4001)
        let deferred = testEndpoint("kad-deferred", port: TransportTestHarness.nextPort())

        try await node.start()
        try await node.seedConnectedEndpointForTesting(referrer, marker: 1)
        await node.seedKademliaTestEndpoint(referrer)
        #expect(await node.reserveOutgoingDial(to: deferred))
        await node.setNeighborRequestHookForTesting { peer, _ in
            peer.publicKey == referrer.publicKey ? [deferred] : []
        }

        let result = await node.findNode(target: deferred.publicKey)

        #expect(result.contains(deferred))
        await node.finishOutgoingDial(
            to: PeerID(publicKey: deferred.publicKey),
            generation: await node.runGeneration,
            connected: false)
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
        #expect(!(await node.reserveOutgoingDial(to: endpoint)))

        await node.finishOutgoingDial(to: peer, generation: oldGeneration, connected: false)
        #expect(await node.reserveOutgoingDial(to: endpoint))
        await node.finishOutgoingDial(to: peer, generation: oldGeneration, connected: false)
        #expect(!(await node.reserveOutgoingDial(to: endpoint)))
        await node.removeFailedRoutingPeer(peer, generation: oldGeneration)
        #expect((await node.knownPeerEndpoints).contains(endpoint))

        await node.finishOutgoingDial(to: peer, generation: currentGeneration, connected: false)
        #expect(await node.reserveOutgoingDial(to: endpoint))
        await node.stop()
    }

    @Test("cancelling a lookup stops future referral rounds")
    func cancellationStopsLookupRounds() async throws {
        let identity = TransportTestHarness.identity("kad-cancel-source")
        let node = Ivy(config: TransportTestHarness.config(
            identity,
            port: TransportTestHarness.nextPort()))
        let first = testEndpoint("kad-cancel-first", port: 4001)
        let referred = PeerEndpoint(
            publicKey: deterministicTestPeerKey("kad-cancel-referred"),
            host: "1.1.1.1",
            port: 4002)
        let responseBarrier = TestBarrier("cancelled neighbor response")

        try await node.start()
        try await node.seedConnectedEndpointForTesting(first, marker: 1)
        await node.seedKademliaTestEndpoint(first)
        await node.setNeighborRequestHookForTesting { _, _ in
            try? await responseBarrier.arriveAndWait()
            return [referred]
        }

        let lookup = BoundedTestTask { await node.findNode(target: referred.publicKey) }
        try await responseBarrier.waitForArrivals()
        lookup.cancel()
        await responseBarrier.release()

        #expect(try await lookup.value(waitingFor: "cancelled Kademlia lookup").isEmpty)
        #expect(!(await node.hasEndpointSession(PeerID(publicKey: referred.publicKey))))
        await node.stop()
    }

    @Test("cancelling a lookup closes a stalled authentication")
    func cancellationClosesStalledAuthentication() async throws {
        let stalledIdentity = TransportTestHarness.identity("kad-cancel-auth-peer")
        let listener = try await ServerBootstrap(
            group: MultiThreadedEventLoopGroup.singleton
        ).childChannelInitializer { channel in
            channel.eventLoop.makeSucceededVoidFuture()
        }.bind(host: "127.0.0.1", port: 0).get()
        let rawPort = try #require(listener.localAddress?.port)
        let port = try #require(UInt16(exactly: rawPort))
        let endpoint = TransportTestHarness.endpoint(stalledIdentity, port: port)
        let node = Ivy(config: IvyConfig(
            publicKey: "kad-cancel-auth-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))

        try await node.start()
        await node.seedKademliaTestEndpoint(endpoint)
        let lookup = Task { await node.findNode(target: endpoint.publicKey) }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingSessionCountForTesting == 1
        })

        lookup.cancel()
        let completion = BoundedTestTask { await lookup.value }
        #expect(try await completion.value(waitingFor: "cancelled Kademlia authentication").isEmpty)
        #expect(try await TransportTestHarness.eventually {
            let pending = await node.pendingSessionCountForTesting
            let outgoing = await node.outgoingDialCountForTesting
            return pending == 0 && outgoing == 0
        })

        await node.stop()
        try await listener.close().get()
    }

    @Test("a new route is retried after the old session disconnects")
    func newRouteAfterDisconnectIsQueryable() async throws {
        let sourceIdentity = TransportTestHarness.identity("kad-route-retry-source")
        let targetIdentity = TransportTestHarness.identity("kad-route-retry-target")
        let targetPort = TransportTestHarness.nextPort()
        let source = Ivy(config: TransportTestHarness.config(
            sourceIdentity,
            port: TransportTestHarness.nextPort()))
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort,
            advertisedHost: "1.1.1.1"))
        let targetKey = TransportTestHarness.key(targetIdentity)
        let oldTargetRoute = PeerEndpoint(
            publicKey: targetKey.hex,
            host: "1.1.1.1",
            port: 4001)
        let replacement = PeerEndpoint(
            publicKey: targetKey.hex,
            host: "1.1.1.1",
            port: targetPort)
        let referrer = testEndpoint("kad-route-retry-referrer", port: 4002)
        let requests = TestBarrier("route replacement referrals")

        try await target.start()
        try await source.start()
        try await source.seedConnectedEndpointForTesting(oldTargetRoute, marker: 1)
        try await source.seedConnectedEndpointForTesting(referrer, marker: 2)
        await source.seedKademliaTestEndpoint(oldTargetRoute)
        await source.seedKademliaTestEndpoint(referrer)
        await source.setDialEndpointRewriteForTesting { endpoint in
            guard endpoint.publicKey == targetKey.hex else { return endpoint }
            return PeerEndpoint(
                publicKey: endpoint.publicKey,
                host: "127.0.0.1",
                port: targetPort)
        }
        await source.setNeighborRequestHookForTesting { peer, _ in
            try? await requests.arriveAndWait()
            return peer == PeerID(publicKey: referrer.publicKey) ? [replacement] : []
        }

        let lookup = BoundedTestTask { await source.findNode(target: targetKey.hex) }
        try await requests.waitForArrivals(2)
        await source.retireTransportForTesting(targetKey.peerID)
        await requests.release()

        let result = try await lookup.value(waitingFor: "replacement Kademlia route")
        #expect(await source.hasEndpointSession(targetKey.peerID))
        #expect(result.contains { $0.publicKey == targetKey.hex && $0.port == targetPort })

        await source.stop()
        await target.stop()
    }

    @Test("lookup preserves alternate routes for one referred identity")
    func referralRouteAlternatives() async throws {
        let sourceIdentity = TransportTestHarness.identity("kad-routes-source")
        let targetIdentity = TransportTestHarness.identity("kad-routes-target")
        let source = Ivy(config: TransportTestHarness.config(
            sourceIdentity,
            port: TransportTestHarness.nextPort()))
        let targetPort = TransportTestHarness.nextPort()
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort,
            advertisedHost: "1.1.1.1"))
        let initial = testEndpoint("kad-routes-initial", port: 4001)
        let targetKey = TransportTestHarness.key(targetIdentity)
        let live = PeerEndpoint(publicKey: targetKey.hex, host: "1.1.1.1", port: targetPort)
        let dead = PeerEndpoint(
            publicKey: targetKey.hex,
            host: "9.9.9.9",
            port: TransportTestHarness.nextPort())

        try await target.start()
        try await source.start()
        try await source.seedConnectedEndpointForTesting(initial, marker: 1)
        await source.seedKademliaTestEndpoint(initial)
        await source.setNeighborRequestHookForTesting { peer, _ in
            peer.publicKey == initial.publicKey ? [live, dead] : []
        }
        await source.setDialEndpointRewriteForTesting { endpoint in
            guard endpoint.publicKey == targetKey.hex else { return endpoint }
            return PeerEndpoint(
                publicKey: endpoint.publicKey,
                host: "127.0.0.1",
                port: endpoint.host == live.host ? targetPort : dead.port)
        }

        let result = await source.findNode(target: targetKey.hex)

        #expect(result.contains(live))
        #expect(await source.hasEndpointSession(targetKey.peerID))
        await source.stop()
        await target.stop()
    }

    @Test("an authenticated route survives referral alternatives")
    func authenticatedRouteIsPreserved() {
        let key = deterministicTestPeerKey("kad-preserved-route")
        let trusted = PeerEndpoint(publicKey: key, host: "1.1.1.1", port: 4001)
        var routes = [LookupRoute(endpoint: trusted, source: .authenticated)]
        for index in 0..<4 {
            routes = selectedLookupRoutes(
                routes + [LookupRoute(
                    endpoint: PeerEndpoint(
                    publicKey: key,
                    host: "8.8.8.\(index + 1)",
                    port: UInt16(4100 + index)),
                    source: .referral(deterministicTestPeerKey("kad-route-flooder")))],
                preferred: trusted)
        }

        #expect(routes.first?.endpoint == trusted)
        #expect(routes.count == Ivy.maxRoutesPerIdentity)
    }

    @Test("route source diversity survives lookup rounds")
    func referralRoutesPreserveSourceDiversity() {
        let key = deterministicTestPeerKey("kad-diverse-route")
        let honest = deterministicTestPeerKey("kad-honest-referrer")
        let flooding = deterministicTestPeerKey("kad-flooding-referrer")
        let live = PeerEndpoint(publicKey: key, host: "1.1.1.1", port: 4001)
        let poisoned = (1...3).map {
            PeerEndpoint(publicKey: key, host: "8.8.8.\($0)", port: UInt16(4100 + $0))
        }

        var selected = selectedLookupRoutes(
            [LookupRoute(endpoint: live, source: .referral(honest))],
            preferred: nil)
        for endpoint in poisoned {
            selected = selectedLookupRoutes(
                selected + [LookupRoute(endpoint: endpoint, source: .referral(flooding))],
                preferred: nil)
        }

        #expect(selected.count == Ivy.maxRoutesPerIdentity)
        #expect(selected.contains { $0.endpoint == live })

        let retired = LookupRoute(endpoint: live, source: .authenticated)
        let alternative = LookupRoute(endpoint: poisoned[0], source: .referral(honest))
        #expect(selectedLookupRoutes(
            [retired, alternative],
            preferred: live).first?.endpoint == live)
        #expect(selectedLookupRoutes(
            [retired, alternative],
            preferred: nil).first?.endpoint == alternative.endpoint)

        let attacker = "0" + String(repeating: "0", count: honest.count - 1)
        let repeated = [LookupRoute(endpoint: live, source: .referral(attacker))]
            + (1...3).map {
                LookupRoute(
                    endpoint: PeerEndpoint(
                        publicKey: key,
                        host: "0.0.0.\($0)",
                        port: UInt16(4200 + $0)),
                    source: .referral(attacker))
            }
        let deduplicated = selectedLookupRoutes(
            [LookupRoute(endpoint: live, source: .referral(honest))] + repeated,
            preferred: nil)
        #expect(deduplicated.contains { $0.endpoint == live && $0.source == .referral(honest) })
        #expect(selectedLookupRoutes(
            [LookupRoute(endpoint: live, source: .authenticated)] + repeated,
            preferred: live).first?.source == .authenticated)
    }

    @Test("later lookup rounds cannot replace every route from an earlier source")
    func referralProvenanceSurvivesLookupRounds() async throws {
        let node = Ivy(config: TransportTestHarness.config(
            TransportTestHarness.identity("kad-round-source"),
            port: TransportTestHarness.nextPort(),
            maxConnections: 3))
        let referrers = [
            testEndpoint("kad-round-referrer-a", port: 4001),
            testEndpoint("kad-round-referrer-b", port: 4002),
        ].sorted { $0.publicKey < $1.publicKey }
        let honest = referrers[0]
        let flooding = referrers[1]
        let targetKey = deterministicTestPeerKey("kad-round-target")
        let live = PeerEndpoint(publicKey: targetKey, host: "1.1.1.1", port: 4100)
        let poisoned = (1...3).map {
            PeerEndpoint(publicKey: targetKey, host: "8.8.8.\($0)", port: UInt16(4200 + $0))
        }

        try await node.start()
        try await node.seedConnectedEndpointForTesting(honest, marker: 1)
        try await node.seedConnectedEndpointForTesting(flooding, marker: 2)
        await node.seedKademliaTestEndpoint(honest)
        #expect(await node.reserveOutgoingDial(to: live))
        await node.setNeighborRequestHookForTesting { peer, _ in
            if peer.publicKey == honest.publicKey { return [live, flooding] }
            if peer.publicKey == flooding.publicKey { return poisoned }
            return []
        }

        let result = await node.findNode(target: targetKey)

        #expect(result.contains(live))
        await node.finishOutgoingDial(
            to: PeerID(publicKey: targetKey),
            generation: await node.runGeneration,
            connected: false)
        await node.stop()
    }
}

private func testEndpoint(_ label: String, port: UInt16) -> PeerEndpoint {
    PeerEndpoint(
        publicKey: deterministicTestPeerKey(label),
        host: "127.0.0.1",
        port: port)
}
