import Foundation
import Testing
@testable import Ivy
import Tally

private extension Ivy {
    func awaitTestProviderResponse(
        rootCID: String,
        requestID: UInt64,
        from peer: PeerID
    ) async -> [PeerEndpoint] {
        await awaitTestProviderResponse(
            rootCID: rootCID,
            requestID: requestID,
            from: [peer])
    }

    func awaitTestProviderResponse(
        rootCID: String,
        requestID: UInt64,
        from peers: [PeerID]
    ) async -> [PeerEndpoint] {
        await withCheckedContinuation { continuation in
            let keys = Set(peers.map(\.publicKey))
            pendingProviderQueries[rootCID] = PendingProviderQuery(
                requestID: requestID,
                continuations: [UUID(): continuation],
                expectedPeers: keys,
                responsesByPeer: [:])
        }
    }

    func hasTestProviderQuery(rootCID: String) -> Bool {
        pendingProviderQueries[rootCID] != nil
    }

    func testContentWaiterCount() -> Int {
        pendingFetches.first?.value.continuations.count ?? 0
    }

    func pendingProviderHintCount(rootCID: String, from peer: PeerID) -> Int {
        pendingProviderQueries[rootCID]?.responsesByPeer[peer.publicKey]?.count ?? 0
    }
}

private actor BlockingUnavailableSource: IvyContentSource {
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry] {
        await withCheckedContinuation { waiters.append($0) }
        return []
    }

    func startedCount() -> Int { waiters.count }

    func release() {
        let pending = waiters
        waiters.removeAll()
        for waiter in pending { waiter.resume() }
    }
}

private actor RetryAfterDisconnectSource: IvyContentSource {
    private let root: String
    private let data: Data
    private var callCount = 0
    private var firstWaiter: CheckedContinuation<Void, Never>?

    init(root: String, data: Data) {
        self.root = root
        self.data = data
    }

    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry] {
        callCount += 1
        if callCount == 1 {
            await withCheckedContinuation { firstWaiter = $0 }
            return []
        }
        return [ContentEntry(cid: root, data: data)]
    }

    func calls() -> Int { callCount }

    func releaseFirst() {
        firstWaiter?.resume()
        firstWaiter = nil
    }
}

private final class ProviderEndpointAttemptRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var endpoints: Set<PeerEndpoint> = []

    func record(_ endpoint: PeerEndpoint) -> PeerEndpoint {
        lock.withLock { _ = endpoints.insert(endpoint) }
        return endpoint
    }

    var snapshot: Set<PeerEndpoint> { lock.withLock { endpoints } }
}

@Suite("Provider refresh", .serialized)
struct ProviderRefreshTests {
    @Test("one flooding responder cannot eclipse an honest provider")
    func providerResponsesAreSourceDiverse() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "provider-diversity-node",
            listenPort: 0,
            kBucketSize: 4,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxContentCandidates: 4))
        let honestResponder = PeerID(
            publicKey: deterministicTestPeerKey("provider-diversity-honest-responder"))
        let floodingResponder = PeerID(
            publicKey: deterministicTestPeerKey("provider-diversity-flood-responder"))
        let finalResponder = PeerID(
            publicKey: deterministicTestPeerKey("provider-diversity-final-responder"))
        let honestProvider = PeerEndpoint(
            publicKey: deterministicTestPeerKey("provider-diversity-honest-provider"),
            host: "1.1.1.1",
            port: 4001)
        let root = "provider-diversity-root"
        let requestID: UInt64 = 19
        let waiting = BoundedTestTask {
            await node.awaitTestProviderResponse(
                rootCID: root,
                requestID: requestID,
                from: [honestResponder, floodingResponder, finalResponder])
        }
        #expect(try await TransportTestHarness.eventually {
            await node.hasTestProviderQuery(rootCID: root)
        })
        let expiry = await node.nowUnix() + 60

        await node.handleProvidersResponse(
            rootCID: root,
            requestID: requestID,
            records: [ProviderRecord(endpoint: honestProvider, expiresAt: expiry)],
            from: honestResponder)
        let poisonedRoutes = (0..<Ivy.maxRoutesPerIdentity).map { index in
            ProviderRecord(
                endpoint: PeerEndpoint(
                    publicKey: honestProvider.publicKey,
                    host: "8.8.4.\(index + 1)",
                    port: UInt16(3900 + index)),
                expiresAt: expiry)
        }
        let flood = (0..<Int(MessageLimits.maxNeighborCount)
            - poisonedRoutes.count).map { index in
            ProviderRecord(
                endpoint: PeerEndpoint(
                    publicKey: deterministicTestPeerKey("provider-flood-\(index)"),
                    host: "8.8.8.8",
                    port: UInt16(index + 1)),
                expiresAt: expiry)
        } + poisonedRoutes
        await node.handleProvidersResponse(
            rootCID: root,
            requestID: requestID,
            records: flood,
            from: floodingResponder)
        #expect(await node.pendingProviderHintCount(
            rootCID: root,
            from: floodingResponder) <= 4 * Ivy.maxRoutesPerIdentity)
        await node.handleProvidersResponse(
            rootCID: root,
            requestID: requestID,
            records: [],
            from: finalResponder)

        let result = try await waiting.value(waitingFor: "diverse provider response")
        #expect(result.contains(honestProvider))
        #expect(result.prefix(4).contains(honestProvider))
        #expect(result.filter { $0.publicKey == honestProvider.publicKey }.count == 3)
        #expect(await node.providers(for: root).contains(PeerID(
            publicKey: honestProvider.publicKey)))
    }

    @Test("a failed cached hint triggers fresh discovery without deleting the hint")
    func staleHintFallsBackToFreshQuery() async throws {
        let requesterIdentity = TransportTestHarness.identity("provider-refresh-requester")
        let routerIdentity = TransportTestHarness.identity("provider-refresh-router")
        let providerIdentity = TransportTestHarness.identity("provider-refresh-provider")
        let requesterPort = TransportTestHarness.nextPort()
        let routerPort = TransportTestHarness.nextPort()
        let providerPort = TransportTestHarness.nextPort()
        let root = "provider-refresh-root"
        let requester = Ivy(config: TransportTestHarness.config(
            requesterIdentity,
            port: requesterPort,
            maxContentCandidates: 1))
        let router = Ivy(config: TransportTestHarness.config(
            routerIdentity,
            port: routerPort))
        let provider = Ivy(config: TransportTestHarness.config(
            providerIdentity,
            port: providerPort))
        await provider.setContentSource(TransportTestContentSource([
            root: Data("fresh provider".utf8),
        ]))

        try await router.start()
        try await requester.start()
        try await provider.start()
        let routerEndpoint = TransportTestHarness.endpoint(routerIdentity, port: routerPort)
        try await requester.connect(to: routerEndpoint)
        try await provider.connect(to: routerEndpoint)
        #expect(try await TransportTestHarness.eventually {
            await router.peerConnectionCount == 2
        })

        let expiry = await provider.nowUnix() + 60
        await provider.announceProvider(rootCID: root, expiresAt: expiry)
        let providerID = TransportTestHarness.key(providerIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await router.providers(for: root).contains(providerID)
        })
        await router.storeProviderHint(
            rootCID: root,
            peer: providerID,
            endpoint: PeerEndpoint(
                publicKey: providerID.publicKey,
                host: "8.8.8.8",
                port: providerPort),
            expiresAt: expiry)
        try await requester.connect(to: TransportTestHarness.endpoint(
            providerIdentity,
            port: providerPort))

        let staleIdentity = TransportTestHarness.identity("provider-refresh-stale-0")
        let staleID = TransportTestHarness.key(staleIdentity).peerID
        let staleEndpoint = TransportTestHarness.endpoint(
            staleIdentity,
            port: TransportTestHarness.nextPort())
        #expect(staleID.publicKey < providerID.publicKey)
        await requester.storeProviderHint(
            rootCID: root,
            peer: staleID,
            endpoint: staleEndpoint,
            expiresAt: expiry)
        await router.storeProviderHint(
            rootCID: root,
            peer: staleID,
            endpoint: staleEndpoint,
            expiresAt: expiry)

        let response = await requester.fetchContent(rootCID: root)

        #expect(response.entries == [root: Data("fresh provider".utf8)])
        #expect(response.servedBy == providerID)
        #expect(await requester.providers(for: root).contains(staleID))

        await provider.stop()
        await requester.stop()
        await router.stop()
    }

    @Test("a connected unavailable hint cannot suppress fresh discovery")
    func connectedHintFallsBackToFreshQuery() async throws {
        let requesterIdentity = TransportTestHarness.identity("provider-connected-requester")
        let routerIdentity = TransportTestHarness.identity("provider-connected-router")
        let staleIdentity = TransportTestHarness.identity("provider-connected-stale")
        let providerIdentity = TransportTestHarness.identity("provider-connected-live")
        let requesterPort = TransportTestHarness.nextPort()
        let routerPort = TransportTestHarness.nextPort()
        let stalePort = TransportTestHarness.nextPort()
        let providerPort = TransportTestHarness.nextPort()
        let root = "provider-connected-root"
        let requester = Ivy(config: TransportTestHarness.config(requesterIdentity, port: requesterPort))
        let router = Ivy(config: TransportTestHarness.config(routerIdentity, port: routerPort))
        let stale = Ivy(config: TransportTestHarness.config(staleIdentity, port: stalePort))
        let provider = Ivy(config: TransportTestHarness.config(providerIdentity, port: providerPort))
        let staleSource = BlockingUnavailableSource()
        await stale.setContentSource(staleSource)
        await provider.setContentSource(TransportTestContentSource([
            root: Data("fresh after unavailable".utf8),
        ]))

        try await router.start()
        try await stale.start()
        try await provider.start()
        try await requester.start()
        let routerEndpoint = TransportTestHarness.endpoint(routerIdentity, port: routerPort)
        let staleEndpoint = TransportTestHarness.endpoint(staleIdentity, port: stalePort)
        try await requester.connect(to: routerEndpoint)
        try await requester.connect(to: staleEndpoint)
        try await provider.connect(to: routerEndpoint)

        let expiry = await provider.nowUnix() + 60
        await provider.announceProvider(rootCID: root, expiresAt: expiry)
        let providerID = TransportTestHarness.key(providerIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await router.providers(for: root).contains(providerID)
        })
        await router.storeProviderHint(
            rootCID: root,
            peer: providerID,
            endpoint: PeerEndpoint(
                publicKey: providerID.publicKey,
                host: "8.8.8.8",
                port: providerPort),
            expiresAt: expiry)
        try await requester.connect(to: TransportTestHarness.endpoint(
            providerIdentity,
            port: providerPort))
        await requester.storeProviderHint(
            rootCID: root,
            peer: TransportTestHarness.key(staleIdentity).peerID,
            endpoint: staleEndpoint,
            expiresAt: expiry)

        let first = Task { await requester.fetchContent(rootCID: root) }
        #expect(try await TransportTestHarness.eventually {
            await staleSource.startedCount() == 1
        })
        let second = Task { await requester.fetchContent(rootCID: root) }
        #expect(try await TransportTestHarness.eventually {
            await requester.testContentWaiterCount() == 2
        })
        await staleSource.release()

        for response in [await first.value, await second.value] {
            #expect(response.entries == [root: Data("fresh after unavailable".utf8)])
            #expect(response.servedBy == providerID)
        }

        await provider.stop()
        await stale.stop()
        await requester.stop()
        await router.stop()
    }

    @Test("fresh discovery can retry an identity whose transport was replaced")
    func replacementSessionIsRetried() async throws {
        let requesterIdentity = TransportTestHarness.identity("provider-retry-requester")
        let routerIdentity = TransportTestHarness.identity("provider-retry-router")
        let providerIdentity = TransportTestHarness.identity("provider-retry-provider")
        let requesterPort = TransportTestHarness.nextPort()
        let routerPort = TransportTestHarness.nextPort()
        let providerPort = TransportTestHarness.nextPort()
        let root = "provider-retry-root"
        let payload = Data("served after reconnect".utf8)
        let source = RetryAfterDisconnectSource(root: root, data: payload)
        let requester = Ivy(config: TransportTestHarness.config(
            requesterIdentity,
            port: requesterPort))
        let router = Ivy(config: TransportTestHarness.config(routerIdentity, port: routerPort))
        let provider = Ivy(config: TransportTestHarness.config(providerIdentity, port: providerPort))
        await provider.setContentSource(source)

        try await router.start()
        try await provider.start()
        try await requester.start()
        let routerEndpoint = TransportTestHarness.endpoint(routerIdentity, port: routerPort)
        let providerEndpoint = TransportTestHarness.endpoint(providerIdentity, port: providerPort)
        let providerID = TransportTestHarness.key(providerIdentity).peerID
        let requesterID = TransportTestHarness.key(requesterIdentity).peerID
        try await provider.connect(to: routerEndpoint)
        try await requester.connect(to: routerEndpoint)
        try await requester.connect(to: providerEndpoint)
        let expiry = await provider.nowUnix() + 60
        await router.storeProviderHint(
            rootCID: root,
            peer: providerID,
            endpoint: providerEndpoint,
            expiresAt: expiry)
        await requester.storeProviderHint(
            rootCID: root,
            peer: providerID,
            endpoint: providerEndpoint,
            expiresAt: expiry)

        let fetch = BoundedTestTask { await requester.fetchContent(rootCID: root) }
        #expect(try await TransportTestHarness.eventually { await source.calls() == 1 })
        await provider.disconnect(requesterID)
        #expect(try await TransportTestHarness.eventually {
            await source.calls() == 2
        })
        await source.releaseFirst()

        let response = try await fetch.value(waitingFor: "replacement provider session")
        #expect(response.entries == [root: payload])
        #expect(response.servedBy == providerID)
        #expect(await source.calls() == 2)

        await provider.stop()
        await requester.stop()
        await router.stop()
    }

    @Test("fresh discovery preserves replacement endpoints until exclusion")
    func replacementEndpointSurvivesExclusion() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "provider-endpoint-replacement",
            listenPort: 0,
            externalAddress: ("9.9.9.9", 4001)))
        let responder = PeerID(publicKey: deterministicTestPeerKey("provider-endpoint-responder"))
        let providerKey = deterministicTestPeerKey("provider-endpoint-identity")
        let failed = PeerEndpoint(publicKey: providerKey, host: "1.1.1.1", port: 4001)
        let replacement = PeerEndpoint(publicKey: providerKey, host: "8.8.8.8", port: 4001)
        let root = "provider-endpoint-root"
        let requestID: UInt64 = 7
        let expiry = await node.nowUnix() + 60
        let response = Task {
            await node.awaitTestProviderResponse(
                rootCID: root,
                requestID: requestID,
                from: responder)
        }
        #expect(try await TransportTestHarness.eventually {
            await node.hasTestProviderQuery(rootCID: root)
        })

        await node.handleProvidersResponse(
            rootCID: root,
            requestID: requestID,
            records: [
                ProviderRecord(endpoint: replacement, expiresAt: expiry),
                ProviderRecord(endpoint: failed, expiresAt: expiry),
            ],
            from: responder)

        let eligible = await response.value.filter { $0 != failed }
        #expect(eligible == [replacement])
    }

    @Test("provider address alternatives are tried for one identity")
    func providerAddressFailover() async throws {
        let requesterIdentity = TransportTestHarness.identity("provider-route-requester")
        let providerIdentity = TransportTestHarness.identity("provider-route-provider")
        let requesterPort = TransportTestHarness.nextPort()
        let deadProviderPort = TransportTestHarness.nextPort()
        let providerPort = TransportTestHarness.nextPort()
        let root = "provider-route-root"
        let requester = Ivy(config: TransportTestHarness.config(
            requesterIdentity,
            port: requesterPort))
        let provider = Ivy(config: TransportTestHarness.config(
            providerIdentity,
            port: providerPort))
        await provider.setContentSource(TransportTestContentSource([
            root: Data("alternate provider route".utf8),
        ]))

        try await provider.start()
        try await requester.start()
        let providerID = TransportTestHarness.key(providerIdentity).peerID
        let dead = PeerEndpoint(
            publicKey: providerID.publicKey,
            host: "127.0.0.1",
            port: deadProviderPort)
        let live = TransportTestHarness.endpoint(providerIdentity, port: providerPort)
        let generation = await requester.runGeneration

        await requester.connectToProviderEndpoints(
            [dead, live],
            generation: generation)

        let response = await requester.fetchContent(rootCID: root)

        #expect(await requester.hasEndpointSession(providerID))
        #expect(response.entries == [root: Data("alternate provider route".utf8)])
        #expect(response.servedBy == providerID)
        await requester.stop()
        await provider.stop()
    }

    @Test("provider wire limits preserve identities before route alternatives")
    func providerWireIdentityFairness() async {
        let node = Ivy(config: IvyConfig(publicKey: "provider-wire-fairness", listenPort: 0))
        let expiry = await node.nowUnix() + 60
        let hints = (0..<100).flatMap { identity -> [ProviderHint] in
            let peer = PeerID(publicKey: deterministicTestPeerKey("wire-provider-\(identity)"))
            return (0..<Ivy.maxRoutesPerIdentity).map { route in
                ProviderHint(
                    peer: peer,
                    endpoint: PeerEndpoint(
                        publicKey: peer.publicKey,
                        host: "8.\(identity / 256).\(identity % 256).\(route + 1)",
                        port: UInt16(4000 + route)),
                    expiresAt: expiry)
            }
        }

        let records = await node.providerRecordsForWire(hints)

        #expect(records.count == Int(MessageLimits.maxNeighborCount))
        #expect(Set(records.map(\.endpoint.publicKey)).count == 100)
    }

    @Test("provider identities each receive bounded route failover")
    func providerRoutesFailOverPerIdentity() async throws {
        let port = TransportTestHarness.nextPort()
        let node = Ivy(config: IvyConfig(
            publicKey: "provider-route-budget",
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxContentCandidates: 2,
            externalAddress: ("127.0.0.1", port)))
        let firstKey = deterministicTestPeerKey("provider-route-budget-first")
        let secondKey = deterministicTestPeerKey("provider-route-budget-second")
        let endpoints = [
            PeerEndpoint(
                publicKey: firstKey,
                host: "127.0.0.1",
                port: TransportTestHarness.nextPort()),
            PeerEndpoint(
                publicKey: firstKey,
                host: "127.0.0.1",
                port: TransportTestHarness.nextPort()),
            PeerEndpoint(
                publicKey: secondKey,
                host: "127.0.0.1",
                port: TransportTestHarness.nextPort()),
            PeerEndpoint(
                publicKey: secondKey,
                host: "127.0.0.1",
                port: TransportTestHarness.nextPort()),
        ]

        try await node.start()
        let attempts = ProviderEndpointAttemptRecorder()
        await node.setDialEndpointRewriteForTesting { attempts.record($0) }
        await node.connectToProviderEndpoints(
            endpoints,
            generation: await node.runGeneration)

        #expect(attempts.snapshot == Set(endpoints))
        await node.stop()
    }
}
