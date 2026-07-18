import Foundation
import Testing
@testable import Ivy
import Tally

private extension Ivy {
    func waitForNeighborCleanup(nonce: UInt64, peer: PeerID) async -> [PeerEndpoint] {
        await withCheckedContinuation { continuation in
            pendingNeighborResponses[nonce] = PendingNeighborResponse(
                peer: peer,
                continuation: continuation)
        }
    }
}

@Suite("Content teardown")
struct PeerDisconnectTests {
    @Test("teardown resolves every pending targeted content continuation")
    func cleanupResolvesContentFetch() async throws {
        let identity = TransportTestHarness.identity("teardown-node")
        let silentIdentity = TransportTestHarness.identity("teardown-silent-peer")
        let node = Ivy(config: TransportTestHarness.config(identity, port: 0))
        let silentID = TransportTestHarness.key(silentIdentity).peerID
        await node.setContentRequestEnqueueHookForTesting { _ in true }

        let fetch = Task {
            await node.fetchContent(
                ContentRequestKey(rootCID: "pending-root", cids: ["pending-child"]),
                from: [silentID])
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingContentRequests.count == 1
        })

        await node.cleanupAllPending()
        let response = await fetch.value

        #expect(response.entries.isEmpty)
        #expect(response.servedBy == nil)
        #expect(await node.pendingContentRequests.isEmpty)
    }

    @Test("peer retirement resolves session-bound neighbor work")
    func cleanupResolvesNeighborRequest() async throws {
        let node = Ivy(config: IvyConfig(publicKey: "neighbor-retirement", listenPort: 0))
        let peer = PeerID(publicKey: deterministicTestPeerKey("retired-neighbor-peer"))
        let response = BoundedTestTask {
            await node.waitForNeighborCleanup(nonce: 7, peer: peer)
        }
        #expect(try await TransportTestHarness.eventually {
            await node.pendingNeighborResponses[7] != nil
        })

        await node.cleanupPendingForPeer(peer)

        #expect(try await response.value(waitingFor: "retired neighbor request").isEmpty)
        #expect(await node.pendingNeighborResponses[7] == nil)
    }
}
