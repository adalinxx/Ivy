import Testing
import Foundation
@testable import Ivy
import Tally
/// UNSTOPPABLE_LATTICE I11: `pendingRequests` and `pendingVolumeRequests` must
/// not grow unbounded. A runaway local caller (or peer echoing distinct CIDs
/// faster than requestTimeout drains) would otherwise allocate continuations
/// forever. Caps force over-budget callers to receive nil immediately instead
/// of enqueueing one more waiter.
@Suite("Pending-request capacity caps")
struct PendingRequestCapsTests {

    private func cappedConfig(
        maxPending: Int,
        maxWaiters: Int
    ) -> IvyConfig {
        IvyConfig(
            publicKey: "capped-node",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            // Timeouts long enough that the first waves are definitely still
            // in flight when we probe the cap, but short enough that the
            // leftover tasks drain quickly at teardown. Nil returns from the
            // cap-probe must be immediate (<100ms), never from these timeouts.
            requestTimeout: .seconds(1),
            relayTimeout: .seconds(1),
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(999),
                staleTimeout: .seconds(999),
                maxMissedPongs: 99,
                enabled: false
            ),
            enablePEX: false,
            maxPendingRequests: maxPending,
            maxWaitersPerPendingCID: maxWaiters
        )
    }

    /// Register a silent local peer (never answers) so `get(cid:target:)`
    /// fires a request and parks a continuation until requestTimeout.
    private func attachSilentPeer(to node: Ivy, key: String) async -> PeerID {
        let peer = PeerID(publicKey: key)
        let silent = LocalPeerConnection(id: await node.localID)
        await node.registerLocalPeer(silent, as: peer)
        await node.addToRouter(peer, endpoint: PeerEndpoint(publicKey: key, host: "local", port: 0))
        return peer
    }

    @Test("get returns nil immediately when the pending dict is full")
    func testGlobalPendingCap() async throws {
        let node = Ivy(config: cappedConfig(maxPending: 2, maxWaiters: 64))
        let peer = await attachSilentPeer(to: node, key: "caps-silent-peer")

        // Launch two fetches for distinct CIDs. The silent peer never
        // answers, so they register and block on requestTimeout.
        let a = Task { await node.get(cid: "cid-a", target: peer) }
        let b = Task { await node.get(cid: "cid-b", target: peer) }

        // Give the two fetches time to register before we probe the cap.
        try await Task.sleep(for: .milliseconds(50))

        // Third distinct CID must bounce off the cap; measure wall time to
        // prove it didn't block on the request timeout.
        let start = ContinuousClock.now
        let c = await node.get(cid: "cid-c", target: peer)
        let elapsed = ContinuousClock.now - start

        #expect(c == nil, "third distinct CID should be rejected")
        #expect(elapsed < .milliseconds(100),
                "rejection must be immediate, not wait on requestTimeout — got \(elapsed)")

        // Drain the two still-pending entries so the task doesn't leak.
        await node.cleanupAllPending()
        _ = await a.value
        _ = await b.value
    }

    @Test("get returns nil immediately when per-CID waiter list is full")
    func testPerCIDWaiterCap() async throws {
        let node = Ivy(config: cappedConfig(maxPending: 128, maxWaiters: 2))
        let peer = await attachSilentPeer(to: node, key: "caps-silent-peer-2")

        // Two concurrent calls for the same CID; the second coalesces onto
        // the first's waiter list.
        let a = Task { await node.get(cid: "shared-cid", target: peer) }
        try await Task.sleep(for: .milliseconds(20))
        let b = Task { await node.get(cid: "shared-cid", target: peer) }
        try await Task.sleep(for: .milliseconds(30))

        // Third call onto the same CID is over the waiter cap.
        let start = ContinuousClock.now
        let c = await node.get(cid: "shared-cid", target: peer)
        let elapsed = ContinuousClock.now - start

        #expect(c == nil, "third waiter on the same CID should be rejected")
        #expect(elapsed < .milliseconds(100),
                "rejection must be immediate — got \(elapsed)")

        await node.cleanupAllPending()
        _ = await a.value
        _ = await b.value
    }
}
