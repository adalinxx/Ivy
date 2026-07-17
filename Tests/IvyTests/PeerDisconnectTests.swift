import Foundation
import Testing
@testable import Ivy

@Suite("Content teardown")
struct PeerDisconnectTests {
    @Test("teardown resolves every pending targeted content continuation")
    func cleanupResolvesContentFetch() async throws {
        let identity = TransportTestHarness.identity("teardown-node")
        let silentIdentity = TransportTestHarness.identity("teardown-silent-peer")
        let node = Ivy(config: TransportTestHarness.config(identity, port: 0))
        let silentID = TransportTestHarness.key(silentIdentity).peerID

        let fetch = Task {
            await node.fetchContent(
                ContentRequestKey(rootCID: "pending-root", cids: ["pending-child"]),
                from: [silentID])
        }
        await Task.yield()
        try await Task.sleep(for: .milliseconds(20))

        let started = ContinuousClock.now
        await node.cleanupAllPending()
        let response = await fetch.value
        let elapsed = ContinuousClock.now - started

        #expect(response.entries.isEmpty)
        #expect(response.servedBy == nil)
        #expect(elapsed < .milliseconds(500))

    }
}
