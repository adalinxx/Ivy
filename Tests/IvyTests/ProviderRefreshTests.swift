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
        await withCheckedContinuation { continuation in
            pendingProviderQueries[rootCID] = PendingProviderQuery(
                requestID: requestID,
                continuations: [continuation],
                expectedPeers: [peer.publicKey],
                endpoints: [])
        }
    }

    func hasTestProviderQuery(rootCID: String) -> Bool {
        pendingProviderQueries[rootCID] != nil
    }

    func testContentWaiterCount() -> Int {
        pendingNetworkFetches.first.map { 1 + $0.value.waiters.count } ?? 0
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

@Suite("Provider refresh", .serialized)
struct ProviderRefreshTests {
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
}
