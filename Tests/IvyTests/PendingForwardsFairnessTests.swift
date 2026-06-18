import Testing
import Foundation
@testable import Ivy
@testable import Tally

///: `pendingForwards` tracks relay requests we've forwarded on behalf of
/// peers, capped globally and per-peer, with a per-(cid,requester) timeout keyed
/// by generation. Two invariants matter for fairness/correctness:
///   (a) one peer filling its per-peer quota cannot starve relay capacity for an
///       honest peer (the per-peer cap, not just the global cap, gates).
///   (b) when two requesters register for the same cid at staggered times, the
///       earlier requester's expiry timer must NOT drop the later requester —
///       the generation guard is keyed per requester.
@Suite("pendingForwards fairness and timeout race")
struct PendingForwardsFairnessTests {

    private func config() -> IvyConfig {
        IvyConfig(
            publicKey: "pending-forwards-node",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            // Long enough that the real expiry timers never fire during the test;
            // we drive expiry explicitly to exercise the generation guard.
            requestTimeout: .seconds(999),
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(999),
                staleTimeout: .seconds(999),
                maxMissedPongs: 99,
                enabled: false
            ),
            enablePEX: false
        )
    }

    @Test("One peer filling its per-peer quota cannot starve an honest peer")
    func perPeerCapDoesNotStarveHonestPeer() async {
        let node = Ivy(config: config())
        let hog = PeerID(publicKey: "hog-peer")
        let honest = PeerID(publicKey: "honest-peer")
        let perPeerCap = Ivy.maxPendingForwardsPerPeer

        // Hog fills its entire per-peer quota across distinct cids.
        for i in 0..<perPeerCap {
            let ok = await node.addPendingForwardForTesting(cid: "hog-cid-\(i)", requester: hog)
            #expect(ok)
        }
        // One more for the hog must be refused by the PER-PEER cap.
        let hogOverflow = await node.addPendingForwardForTesting(cid: "hog-overflow", requester: hog)
        #expect(!hogOverflow, "hog must be capped at its per-peer quota")
        #expect(await node.pendingForwardCountForPeerForTesting(hog) == perPeerCap)

        // The honest peer still has full access to its own quota — it is not
        // starved by the hog having saturated its own.
        let honestOK = await node.addPendingForwardForTesting(cid: "honest-cid", requester: honest)
        #expect(honestOK, "honest peer must still be admitted despite the hog being full")
        #expect(await node.pendingForwardCountForPeerForTesting(honest) == 1)
    }

    @Test("Earlier requester's expiry timer does not drop a later requester on the same cid")
    func earlierTimerDoesNotDropLaterRequester() async {
        let node = Ivy(config: config())
        let cid = "shared-cid"
        let early = PeerID(publicKey: "early-requester")
        let late = PeerID(publicKey: "late-requester")

        // Early requester registers first (lower generation).
        #expect(await node.addPendingForwardForTesting(cid: cid, requester: early))
        let earlyGen = await node.pendingForwardGenerationForTesting(cid: cid, requester: early)
        #expect(earlyGen != nil)

        // Later requester registers for the SAME cid (higher generation).
        #expect(await node.addPendingForwardForTesting(cid: cid, requester: late))
        let lateGen = await node.pendingForwardGenerationForTesting(cid: cid, requester: late)
        #expect(lateGen != nil)
        #expect(lateGen! > earlyGen!, "later registration must have a newer generation")

        // The early requester's timer fires (with the early generation). It must
        // only drop the early requester, never the later one.
        await node.expirePendingForwardForTesting(cid: cid, requester: early, generation: earlyGen!)

        #expect(await node.pendingForwardGenerationForTesting(cid: cid, requester: early) == nil,
                "early requester should be expired")
        #expect(await node.pendingForwardGenerationForTesting(cid: cid, requester: late) == lateGen,
                "later requester must survive the earlier requester's timeout")
        #expect(await node.pendingForwardCountForPeerForTesting(late) == 1)
    }

    @Test("A stale expiry generation is a no-op (re-registration is not dropped)")
    func staleGenerationDoesNotDropReRegistration() async {
        let node = Ivy(config: config())
        let cid = "rereg-cid"
        let peer = PeerID(publicKey: "rereg-peer")

        #expect(await node.addPendingForwardForTesting(cid: cid, requester: peer))
        let firstGen = await node.pendingForwardGenerationForTesting(cid: cid, requester: peer)!

        // Simulate: the entry is removed and the peer re-registers (new generation),
        // then the OLD timer fires with the stale generation. It must not drop the
        // fresh entry.
        await node.expirePendingForwardForTesting(cid: cid, requester: peer, generation: firstGen)
        #expect(await node.pendingForwardGenerationForTesting(cid: cid, requester: peer) == nil)

        #expect(await node.addPendingForwardForTesting(cid: cid, requester: peer))
        let secondGen = await node.pendingForwardGenerationForTesting(cid: cid, requester: peer)!
        #expect(secondGen > firstGen)

        // Stale timer from the first registration fires — must be a no-op.
        await node.expirePendingForwardForTesting(cid: cid, requester: peer, generation: firstGen)
        #expect(await node.pendingForwardGenerationForTesting(cid: cid, requester: peer) == secondGen,
                "stale-generation expiry must not drop the re-registered entry")
    }
}
