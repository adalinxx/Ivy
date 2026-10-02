import Foundation
import Testing
@testable import Ivy
import Tally

private extension Ivy {
    func hasProviderRecord(rootCID: String, peer: PeerID) -> Bool {
        providerHints[rootCID]?.contains { $0.peer == peer } == true
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

@Suite("Provider record quota")
struct ProviderQuotaTests {
    private func node(_ label: String, quota: Int, maxConnections: Int = 256) -> Ivy {
        Ivy(config: IvyConfig(
            signingKey: deterministicTestSigningKey(label),
            listenPort: 0,
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

    @Test("the global ceiling refuses new records and never evicts")
    func ceilingRefusesWithoutEvicting() async {
        // Ceiling = maxConnections * quota = 2 * 2.
        let node = node("quota-ceiling-node", quota: 2, maxConnections: 2)
        let first = peer("quota-ceiling-first")
        let second = peer("quota-ceiling-second")
        let late = peer("quota-ceiling-late")
        let now = await node.nowUnix()
        for root in ["f1", "f2"] {
            await node.handleAnnounceProvider(rootCID: root, expiresAt: now + 60, from: first)
        }
        for root in ["s1", "s2"] {
            await node.handleAnnounceProvider(rootCID: root, expiresAt: now + 60, from: second)
        }

        await node.handleAnnounceProvider(rootCID: "late", expiresAt: now + 600, from: late)
        await node.handleAnnounceProvider(rootCID: "f1", expiresAt: now + 600, from: late)

        #expect(await node.providerRecordCount(of: late) == 0)
        #expect(await node.storedProviderRecordCount() == 4)
        for (root, owner) in [("f1", first), ("f2", first), ("s1", second), ("s2", second)] {
            #expect(await node.hasProviderRecord(rootCID: root, peer: owner))
        }

        // A peer at its own quota may still rotate its own records at the ceiling.
        await node.handleAnnounceProvider(rootCID: "f3", expiresAt: now + 90, from: first)
        #expect(await node.hasProviderRecord(rootCID: "f3", peer: first))
        #expect(await node.storedProviderRecordCount() == 4)
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
}
