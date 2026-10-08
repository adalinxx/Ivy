import Foundation
import Testing
@testable import Ivy
import Tally

private extension Ivy {
    func hasProviderRecord(rootCID: String, peer: PeerID) -> Bool {
        providerHints[rootCID]?.contains { $0.peer == peer } == true
    }

    func providerRecords(rootCID: String, peer: PeerID) -> [ProviderHint] {
        providerHints[rootCID]?.filter { $0.peer == peer } ?? []
    }

    func storedProviderRecordCount() -> Int {
        providerHints.values.reduce(0) { $0 + $1.count }
    }

    func awaitQuotaTestProviderResponse(
        rootCID: String,
        requestID: UInt64,
        from peer: PeerID
    ) async -> [PeerEndpoint] {
        await withCheckedContinuation { continuation in
            pendingProviderQueries[rootCID] = PendingProviderQuery(
                requestID: requestID,
                continuations: [UUID(): continuation],
                expectedPeers: [peer.publicKey],
                responsesByPeer: [:])
        }
    }

    func hasQuotaTestProviderQuery(rootCID: String) -> Bool {
        pendingProviderQueries[rootCID] != nil
    }
}

private struct QuotaTestVolumeSource: IvyContentSource {
    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] { [] }

    func volume(rootCID: String, maxDataBytes: Int) -> [ContentEntry] {
        [ContentEntry(cid: rootCID, data: Data(rootCID.utf8))]
    }
}

@Suite("Provider record quota")
struct ProviderQuotaTests {
    private func node(
        _ label: String, quota: Int, maxConnections: Int = 256, kBucketSize: Int = 20
    ) -> Ivy {
        Ivy(config: IvyConfig(
            signingKey: deterministicTestSigningKey(label),
            listenPort: 0,
            kBucketSize: kBucketSize,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: maxConnections,
            maxProviderRecordsPerPeer: quota))
    }

    private func peer(_ label: String) -> PeerID {
        PeerID(publicKey: deterministicTestPeerKey(label))
    }

    @Test("a flood from one peer cannot evict another peer's records")
    func floodCannotEvictOthers() async {
        let node = node("quota-flood-node", quota: 4)
        let honest = peer("quota-flood-honest")
        let flooder = peer("quota-flood-flooder")
        let expiry = await node.nowUnix() + 60
        await node.handleAnnounceProvider(rootCID: "honest-root", expiresAt: expiry, from: honest)

        let maxExpiry = await node.nowUnix() + IvyConfig.defaultMaxProviderTTLSeconds
        for index in 0..<200 {
            await node.handleAnnounceProvider(
                rootCID: "junk-\(index)", expiresAt: maxExpiry, from: flooder)
        }

        #expect(await node.hasProviderRecord(rootCID: "honest-root", peer: honest))
        #expect(await node.providerRecordCount(of: flooder) == 4)
        #expect(await node.storedProviderRecordCount() == 5)
    }

    @Test("a peer at its quota replaces only its own soonest-expiring record")
    func quotaReplacesOwnSoonest() async {
        let node = node("quota-replace-node", quota: 3)
        let honest = peer("quota-replace-honest")
        let announcer = peer("quota-replace-announcer")
        let now = await node.nowUnix()
        await node.handleAnnounceProvider(rootCID: "honest-root", expiresAt: now + 5, from: honest)
        await node.handleAnnounceProvider(rootCID: "a", expiresAt: now + 30, from: announcer)
        await node.handleAnnounceProvider(rootCID: "b", expiresAt: now + 10, from: announcer)
        await node.handleAnnounceProvider(rootCID: "c", expiresAt: now + 20, from: announcer)
        await node.handleAnnounceProvider(rootCID: "d", expiresAt: now + 40, from: announcer)

        #expect(await !node.hasProviderRecord(rootCID: "b", peer: announcer))
        for root in ["a", "c", "d"] {
            #expect(await node.hasProviderRecord(rootCID: root, peer: announcer))
        }
        #expect(await node.hasProviderRecord(rootCID: "honest-root", peer: honest))
        #expect(await node.providerRecordCount(of: announcer) == 3)
    }

    @Test("at the ceiling the heaviest source gives up a record, so honest peers still get in")
    func ceilingEvictsFromHeaviestSource() async {
        // Ceiling = maxConnections * quota = 2 * 3.
        let node = node("quota-ceiling-node", quota: 3, maxConnections: 2)
        let honest = peer("quota-ceiling-honest")
        let lateHonest = peer("quota-ceiling-late-honest")
        let flooderA = peer("quota-ceiling-flooder-a")
        let flooderB = peer("quota-ceiling-flooder-b")
        let now = await node.nowUnix()
        let maxExpiry = now + IvyConfig.defaultMaxProviderTTLSeconds
        await node.handleAnnounceProvider(rootCID: "honest", expiresAt: now + 60, from: honest)
        for index in 0..<50 {
            await node.handleAnnounceProvider(
                rootCID: "a-\(index)", expiresAt: maxExpiry, from: flooderA)
            await node.handleAnnounceProvider(
                rootCID: "b-\(index)", expiresAt: maxExpiry, from: flooderB)
        }
        #expect(await node.storedProviderRecordCount() == 6)

        await node.handleAnnounceProvider(rootCID: "late", expiresAt: now + 60, from: lateHonest)
        for index in 50..<100 {
            await node.handleAnnounceProvider(
                rootCID: "a-\(index)", expiresAt: maxExpiry, from: flooderA)
        }

        #expect(await node.hasProviderRecord(rootCID: "honest", peer: honest))
        #expect(await node.hasProviderRecord(rootCID: "late", peer: lateHonest))
        #expect(await node.storedProviderRecordCount() == 6)
    }

    @Test("admission at the ceiling does not sweep the whole table")
    func ceilingAdmissionIsNotATableSweep() async {
        let node = node("quota-sweep-node", quota: 3, maxConnections: 2)
        let stale = peer("quota-sweep-stale")
        let flooder = peer("quota-sweep-flooder")
        let honest = peer("quota-sweep-honest")
        let now = await node.nowUnix()
        await node.storeProviderHint(rootCID: "stale", peer: stale, endpoint: nil, expiresAt: now - 1)
        for index in 0..<3 {
            await node.handleAnnounceProvider(
                rootCID: "f-\(index)", expiresAt: now + 600, from: flooder)
        }
        for index in 0..<2 {
            await node.handleAnnounceProvider(
                rootCID: "h-\(index)", expiresAt: now + 600, from: honest)
        }
        #expect(await node.storedProviderRecordCount() == 6)

        await node.handleAnnounceProvider(rootCID: "h-2", expiresAt: now + 600, from: honest)

        // The expired record in an untouched root is still there: no global sweep ran;
        // the heaviest source (the flooder) gave up one record instead.
        #expect(await node.hasProviderRecord(rootCID: "stale", peer: stale))
        #expect(await node.providerRecordCount(of: flooder) == 2)
        #expect(await node.providerRecordCount(of: honest) == 3)
    }

    @Test("referred records count against the responder that relayed them")
    func referralFloodIsBounded() async throws {
        let node = node("quota-referral-node", quota: 5)
        let honest = peer("quota-referral-honest")
        let responder = peer("quota-referral-responder")
        let expiry = await node.nowUnix() + 60
        await node.handleAnnounceProvider(rootCID: "honest-root", expiresAt: expiry, from: honest)

        for rootIndex in 0..<3 {
            let root = "referral-root-\(rootIndex)"
            let requestID = UInt64(100 + rootIndex)
            let waiting = BoundedTestTask {
                await node.awaitQuotaTestProviderResponse(
                    rootCID: root, requestID: requestID, from: responder)
            }
            #expect(try await TransportTestHarness.eventually {
                await node.hasQuotaTestProviderQuery(rootCID: root)
            })
            let records = (0..<20).map { index in
                ProviderRecord(
                    endpoint: PeerEndpoint(
                        publicKey: deterministicTestPeerKey("fake-\(rootIndex)-\(index)"),
                        host: "8.8.\(rootIndex + 1).\(index + 1)",
                        port: 4001),
                    expiresAt: expiry)
            }
            await node.handleProvidersResponse(
                rootCID: root, requestID: requestID, records: records, from: responder)
            let endpoints = try await waiting.value(waitingFor: "referral response")
            #expect(endpoints.count == 20)
        }

        #expect(await node.providerRecordCount(of: responder) == 5)
        #expect(await node.storedProviderRecordCount() == 6)
        #expect(await node.hasProviderRecord(rootCID: "honest-root", peer: honest))
    }

    @Test("a referral cannot rewrite, push out, or adopt a provider's direct record")
    func referralCannotTakeOverDirectRecord() async throws {
        let node = node("quota-takeover-node", quota: 1)
        let honest = peer("quota-takeover-honest")
        let responder = peer("quota-takeover-responder")
        let now = await node.nowUnix()
        let direct = PeerEndpoint(publicKey: honest.publicKey, host: "1.1.1.1", port: 4001)
        await node.storeProviderHint(
            rootCID: "root", peer: honest, endpoint: direct, expiresAt: now + 600)

        // Same endpoint with a short expiry, plus alternative routes for the same identity.
        let records = [ProviderRecord(endpoint: direct, expiresAt: now + 5)]
            + (1...IvyConfig.defaultMaxRoutesPerIdentity).map { index in
                ProviderRecord(
                    endpoint: PeerEndpoint(
                        publicKey: honest.publicKey, host: "8.8.8.\(index)", port: 4001),
                    expiresAt: now + 5)
            }
        try await refer(node, root: "root", requestID: 200, records: records, from: responder)
        #expect(await node.providerRecords(rootCID: "root", peer: honest)
            == [ProviderHint(peer: honest, endpoint: direct, expiresAt: now + 600, source: honest)])
        #expect(await node.providerRecordCount(of: responder) == 0)

        // The responder's own quota eviction cannot reach the honest record either.
        let other = PeerEndpoint(
            publicKey: deterministicTestPeerKey("quota-takeover-other"), host: "8.8.4.4", port: 4001)
        for (index, root) in ["other-1", "other-2"].enumerated() {
            try await refer(
                node, root: root, requestID: UInt64(201 + index),
                records: [ProviderRecord(endpoint: other, expiresAt: now + 60)], from: responder)
        }
        #expect(await node.providerRecordCount(of: responder) == 1)
        #expect(await node.hasProviderRecord(rootCID: "root", peer: honest))
    }

    @Test("a provider's re-announcement replaces routes referred for it after its record expired")
    func directRecordReplacesReferredRoutes() async throws {
        let node = node("quota-supersede-node", quota: 100)
        let honest = peer("quota-supersede-honest")
        let responder = peer("quota-supersede-responder")
        let now = await node.nowUnix()
        await node.storeProviderHint(
            rootCID: "root",
            peer: honest,
            endpoint: PeerEndpoint(publicKey: honest.publicKey, host: "1.1.1.1", port: 4001),
            expiresAt: now)

        let wrong = (1...IvyConfig.defaultMaxRoutesPerIdentity).map { index in
            ProviderRecord(
                endpoint: PeerEndpoint(
                    publicKey: honest.publicKey, host: "8.8.8.\(index)", port: 4001),
                expiresAt: now + 600)
        }
        try await refer(node, root: "root", requestID: 400, records: wrong, from: responder)
        #expect(await node.providerRecordCount(of: responder) == wrong.count)

        let moved = PeerEndpoint(publicKey: honest.publicKey, host: "1.0.0.1", port: 4002)
        await node.storeProviderHint(
            rootCID: "root", peer: honest, endpoint: moved, expiresAt: now + 600)

        #expect(await node.providerRecords(rootCID: "root", peer: honest)
            == [ProviderHint(peer: honest, endpoint: moved, expiresAt: now + 600, source: honest)])
        #expect(await node.providerRecordCount(of: responder) == 0)
        #expect(await node.providerRecordCount(of: honest) == 1)
    }

    @Test("a full root sheds referred-only providers before self-announced ones")
    func fullRootShedsReferredFirst() async throws {
        let node = node("quota-shed-node", quota: 100, kBucketSize: 2)
        let honest = peer("quota-shed-honest")
        let responder = peer("quota-shed-responder")
        let now = await node.nowUnix()
        await node.handleAnnounceProvider(rootCID: "root", expiresAt: now + 600, from: honest)
        let records = (0..<4).map { index in
            ProviderRecord(
                endpoint: PeerEndpoint(
                    publicKey: deterministicTestPeerKey("quota-shed-fake-\(index)"),
                    host: "8.8.8.\(index + 1)",
                    port: 4001),
                expiresAt: now + 600)
        }
        try await refer(node, root: "root", requestID: 300, records: records, from: responder)

        #expect(await node.hasProviderRecord(rootCID: "root", peer: honest))
        #expect(await node.storedProviderRecordCount() == 2)
    }

    @Test("serving Volumes never evicts what the server announced, and the last server is asked first")
    func observationsNeverEvictAnnouncements() async throws {
        let quota = 4
        let serverIdentity = TransportTestHarness.identity("quota-observed-server")
        let serverPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: IvyConfig(
            signingKey: TransportTestHarness.identity("quota-observed-client"),
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxProviderRecordsPerPeer: quota))
        await server.setContentSource(QuotaTestVolumeSource())
        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(serverIdentity, port: serverPort))
        let serverID = TransportTestHarness.key(serverIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await server.peerConnectionCount == 1
        })

        await client.handleAnnounceProvider(
            rootCID: "rendezvous", expiresAt: await client.nowUnix() + 60, from: serverID)
        #expect(await client.providers(for: "rendezvous") == [serverID])

        for index in 0..<(quota * 3) {
            let response = await client.fetchVolume(rootCID: "volume-\(index)")
            #expect(response.servedBy == serverID)
        }

        #expect(await client.providers(for: "rendezvous") == [serverID])
        #expect(await client.providerRecordCount(of: serverID) == quota)
        #expect(await client.connectedProviderIDs(for: "volume-\(quota * 3 - 1)") == [serverID])
        #expect(await client.connectedProviderIDs(for: "volume-0").isEmpty)

        await client.stop()
        await server.stop()
    }

    @Test("an observation neither replaces an announcement nor takes its place at the quota")
    func observationYieldsToAnnouncement() async {
        let node = node("quota-yield-node", quota: 2)
        let server = peer("quota-yield-server")
        let other = peer("quota-yield-other")
        let now = await node.nowUnix()
        await node.handleAnnounceProvider(rootCID: "other", expiresAt: now + 5, from: other)
        await node.handleAnnounceProvider(rootCID: "a", expiresAt: now + 600, from: server)
        await node.handleAnnounceProvider(rootCID: "b", expiresAt: now + 30, from: server)

        // What the peer announced keeps the expiry it announced.
        await node.storeProviderHint(
            rootCID: "a", peer: server, endpoint: nil, expiresAt: now + 60, observed: true)
        // A quota full of announcements admits no observation.
        await node.storeProviderHint(
            rootCID: "c", peer: server, endpoint: nil, expiresAt: now + 60, observed: true)
        #expect(await node.providerRecords(rootCID: "a", peer: server)
            == [ProviderHint(peer: server, endpoint: nil, expiresAt: now + 600, source: server)])
        #expect(await node.hasProviderRecord(rootCID: "b", peer: server))
        #expect(await !node.hasProviderRecord(rootCID: "c", peer: server))

        // The peer's own later announcement still replaces its own soonest-expiring one.
        await node.handleAnnounceProvider(rootCID: "d", expiresAt: now + 90, from: server)
        #expect(await !node.hasProviderRecord(rootCID: "b", peer: server))
        #expect(await node.providerRecordCount(of: server) == 2)
        #expect(await node.hasProviderRecord(rootCID: "other", peer: other))
    }

    private func refer(
        _ node: Ivy,
        root: String,
        requestID: UInt64,
        records: [ProviderRecord],
        from responder: PeerID
    ) async throws {
        let waiting = BoundedTestTask {
            await node.awaitQuotaTestProviderResponse(
                rootCID: root, requestID: requestID, from: responder)
        }
        #expect(try await TransportTestHarness.eventually {
            await node.hasQuotaTestProviderQuery(rootCID: root)
        })
        await node.handleProvidersResponse(
            rootCID: root, requestID: requestID, records: records, from: responder)
        _ = try await waiting.value(waitingFor: "referral response")
    }
}
