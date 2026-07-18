import Foundation
import Testing
@testable import Ivy
import Tally

private actor CountingContentSource: IvyContentSource {
    private var requestCount = 0

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] {
        requestCount += 1
        return cids.map { ContentEntry(cid: $0, data: Data("available".utf8)) }
    }

    var requests: Int { requestCount }
}

@Suite("Provider suppression")
struct ProviderSuppressionTests {
    @Test("caller-reported invalid content suppresses only that root without a Tally penalty")
    func invalidContentIsRootScopedRoutingFeedback() async {
        let node = Ivy(config: IvyConfig(
            publicKey: "provider-suppression-node",
            listenPort: 0
        ))
        let peer = PeerID(publicKey: deterministicTestPeerKey("provider-peer"))
        let expiry = await node.nowUnix() + 60
        await node.storeProviderHint(rootCID: "root-a", peer: peer, endpoint: nil, expiresAt: expiry)
        await node.storeProviderHint(rootCID: "root-b", peer: peer, endpoint: nil, expiresAt: expiry)

        let tally = await node.tally
        tally.recordReceived(peer: peer, bytes: 100_000_000)
        let scoreBefore = tally.admissionScore(for: peer)
        #expect(scoreBefore > 0)

        await node.reportDeficientContent(rootCID: "root-a", servedBy: peer)

        #expect(!(await node.providers(for: "root-a")).contains(peer))
        #expect((await node.providers(for: "root-b")).contains(peer))
        #expect(await node.isDeficiencySuppressed(rootCID: "root-a", peer: peer))
        #expect(!(await node.isDeficiencySuppressed(rootCID: "root-b", peer: peer)))
        #expect(abs(tally.admissionScore(for: peer) - scoreBefore) < 0.000_001)
    }

    @Test("provider hints retain original expiry and obey the per-root cap")
    func providerHintBoundsAndExpiry() async {
        let node = Ivy(config: IvyConfig(
            publicKey: "provider-bounds-node",
            listenPort: 0,
            kBucketSize: 2))
        let now = await node.nowUnix()
        let expired = PeerID(publicKey: deterministicTestPeerKey("expired-provider"))
        await node.storeProviderHint(
            rootCID: "root",
            peer: expired,
            endpoint: nil,
            expiresAt: now)

        let retained = (0..<3).map {
            PeerID(publicKey: deterministicTestPeerKey("provider-\($0)"))
        }
        for peer in retained {
            await node.storeProviderHint(
                rootCID: "root",
                peer: peer,
                endpoint: nil,
                expiresAt: now + 60)
            await node.reportDeficientContent(rootCID: "bad-root", servedBy: peer)
        }

        #expect(await node.providers(for: "root") == Array(retained.suffix(2)))
        #expect(await node.deficiencySuppressionCount(for: "bad-root") == 2)
    }

    @Test("same-root deficiency is honored by last-resort connected fallback")
    func deficiencySuppressesConnectedFallback() async throws {
        let requesterIdentity = TransportTestHarness.identity("suppression-requester")
        let providerIdentity = TransportTestHarness.identity("suppression-provider")
        let requesterPort = TransportTestHarness.nextPort()
        let providerPort = TransportTestHarness.nextPort()
        let requester = Ivy(config: TransportTestHarness.config(
            requesterIdentity,
            port: requesterPort))
        let provider = Ivy(config: TransportTestHarness.config(
            providerIdentity,
            port: providerPort))
        let source = CountingContentSource()
        await provider.setContentSource(source)

        try await provider.start()
        try await requester.start()
        try await requester.connect(to: TransportTestHarness.endpoint(
            providerIdentity,
            port: providerPort))
        let providerID = TransportTestHarness.key(providerIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await requester.peerConnectionCount == 1
        })

        await requester.reportDeficientContent(
            rootCID: "suppressed-root",
            servedBy: providerID)
        let response = await requester.fetchContent(rootCID: "suppressed-root")

        #expect(response == .empty)
        #expect(await source.requests == 0)
        await requester.stop()
        await provider.stop()
    }
}

private extension Ivy {
    func deficiencySuppressionCount(for rootCID: String) -> Int {
        deficientPeerSuppression[rootCID]?.count ?? 0
    }
}
