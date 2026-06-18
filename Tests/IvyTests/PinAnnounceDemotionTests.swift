import Testing
import Foundation
@testable import Ivy
@testable import Tally

/// S5: a peer that advertises pin ownership but fails to serve the CID must
/// be demoted in Tally. Without this wiring, repeated liars stay in the
/// fetch pool forever — their reputation is only written by PeerHealthMonitor
/// pings, not by fetch-outcome.
///
/// These tests cover the fetch path that trusts a specific peer:
///   - `get(cid:target:)` — pinner-targeted fetch (selected via findPins).
private func makeNode(publicKey: String, requestTimeout: Duration = .milliseconds(200)) -> Ivy {
    let config = IvyConfig(
        publicKey: publicKey,
        listenPort: 0,
        bootstrapPeers: [],
        enableLocalDiscovery: false,
        requestTimeout: requestTimeout,
        healthConfig: PeerHealthConfig(keepaliveInterval: .seconds(999), staleTimeout: .seconds(999), maxMissedPongs: 99, enabled: false),
        enablePEX: false
    )
    return Ivy(config: config)
}

@Suite("Pin announce demotion")
struct PinAnnounceDemotionTests {

    @Test("get(cid:target:) records success when the peer delivers")
    func testTargetedGetSuccessRewardsPeer() async throws {
        let a = makeNode(publicKey: "reward-a")
        let b = makeNode(publicKey: "reward-b")
        await connectNodes(a, b)
        try await Task.sleep(for: .milliseconds(50))

        let bID = await b.localID

        // Stash data on B via dataSource + markAvailable so haveSet is populated
        // and handleDHTForward on B can serve the request.
        let payload = Data("hello".utf8)
        let cid = testCID(for: payload)
        let ds = DictDataSource()
        ds[cid] = payload
        await b.setDataSource(ds)
        await b.markAvailable(cids: [cid])

        let beforeSuccesses = await a.tally.peerLedger(for: bID)?.successCount.value ?? 0

        let data = await a.get(cid: cid, target: bID)
        #expect(data == payload, "successful targeted fetch must return the payload")

        let afterSuccesses = await a.tally.peerLedger(for: bID)?.successCount.value ?? 0
        #expect(afterSuccesses >= beforeSuccesses + 1, "successful targeted fetch must reward the serving peer")
    }

    @Test("get(cid:target:) records failure when the pinner lies")
    func testTargetedGetTimeoutDemotesPinner() async throws {
        let a = makeNode(publicKey: "target-a")
        let b = makeNode(publicKey: "target-b")
        await connectNodes(a, b)
        try await Task.sleep(for: .milliseconds(50))

        let bID = await b.localID

        let beforeFailures = await a.tally.peerLedger(for: bID)?.failureCount.value ?? 0

        // B never stored this CID — classic "lied in a pin announce" scenario.
        let data = await a.get(cid: "cid-announced-but-not-held", target: bID)
        #expect(data == nil)

        let afterFailures = await a.tally.peerLedger(for: bID)?.failureCount.value ?? 0
        #expect(afterFailures == beforeFailures + 1, "targeted-get timeout must demote the announcing peer")
    }
}
