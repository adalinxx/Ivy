import Testing
import Foundation
@testable import Ivy
import Tally

@Suite("Peer disconnect cleanup")
struct PeerDisconnectTests {

    @Test("Disconnect removes peer from routing table")
    func disconnectRemovesPeerFromRouter() async {
        let node = Ivy(config: IvyConfig(
            publicKey: "disconnect-router-node",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(999),
                staleTimeout: .seconds(999),
                maxMissedPongs: 99,
                enabled: false
            ),
            enablePEX: false
        ))
        let peer = PeerID(publicKey: "disconnect-router-peer")
        await node.addToRouter(
            peer,
            endpoint: PeerEndpoint(publicKey: peer.publicKey, host: "local", port: 0)
        )

        var routedPeers = await node.allRouterPeers()
        #expect(routedPeers.contains { $0.id == peer })

        await node.disconnect(peer)

        routedPeers = await node.allRouterPeers()
        #expect(!routedPeers.contains { $0.id == peer })
    }

    /// With content-addressed routing, pendingVolumeRequests is keyed by rootCID.
    /// Disconnecting one peer does not cancel the fetch — other peers may still
    /// serve the content. cleanupAllPending() handles full teardown.
    ///
    /// This test verifies that when the ONLY peer is disconnected and
    /// cleanupAllPending() is called, the fetch resolves immediately rather
    /// than waiting for requestTimeout.
    @Test("Pending volume fetch resolves immediately on full teardown")
    func testVolumeRequestResolvesOnDisconnect() async throws {
        // Use a long requestTimeout (10s) to clearly distinguish
        // "resolved immediately on disconnect" from "waited for timeout".
        let nodeA = Ivy(config: IvyConfig(
            publicKey: "disconnect-a",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            requestTimeout: .seconds(10),
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(999),
                staleTimeout: .seconds(999),
                maxMissedPongs: 99,
                enabled: false
            ),
            enablePEX: false
        ))

        // Create a silent peer: LocalPeerConnection without a paired remote end.
        // Messages nodeA sends to silentPeerID are dropped (remoteEnd is nil),
        // so requestVolumeFromPeer will never receive a response.
        let silentPeerID = PeerID(publicKey: "silent-peer-aabbccdd")
        let silentConn = LocalPeerConnection(id: await nodeA.localID)
        await nodeA.registerLocalPeer(silentConn, as: silentPeerID)

        let aID = await nodeA.localID
        await nodeA.addToRouter(silentPeerID, endpoint: PeerEndpoint(publicKey: silentPeerID.publicKey, host: "local", port: 0))
        _ = aID

        try await Task.sleep(for: .milliseconds(30))

        // Start a fetch — nodeA sends want to silentPeerID, which never
        // responds. The continuation is registered in pendingVolumeRequests.
        let fetchTask = Task {
            await nodeA.fetchVolumeFromAllPeers(rootCID: "cid-that-wont-be-served")
        }

        // Let the request register in the want-have phase.
        try await Task.sleep(for: .milliseconds(80))

        // With content-addressed routing, pendingVolumeRequests is keyed by
        // root CID, not peer. Disconnecting one peer doesn't cancel it
        // (other peers might serve the same content). cleanupAllPending()
        // handles full teardown.
        let start = ContinuousClock.now
        await nodeA.disconnect(silentPeerID)
        await nodeA.cleanupAllPending()

        let result = await fetchTask.value
        let elapsed = ContinuousClock.now - start

        #expect(result.isEmpty)
        #expect(
            elapsed < .milliseconds(500),
            "fetch must resolve within 500ms of cleanupAllPending — got \(elapsed)"
        )
    }

    /// Regression: cancellation/teardown resolves the pending request by the
    /// content root, matching pendingVolumeRequests' rootCID-only keying.
    @Test("resolveVolumeRequestsForRoot resolves continuations by rootCID")
    func testResolveByRootCID() async throws {
        let config = IvyConfig(
            publicKey: "root-resolve-a",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            requestTimeout: .seconds(10),
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(999),
                staleTimeout: .seconds(999),
                maxMissedPongs: 99,
                enabled: false
            ),
            enablePEX: false
        )
        let node = Ivy(config: config)
        let silentPeerID = PeerID(publicKey: "silent-keymigrate0")
        let silentConn = LocalPeerConnection(id: await node.localID)
        await node.registerLocalPeer(silentConn, as: silentPeerID)
        await node.addToRouter(silentPeerID, endpoint: PeerEndpoint(publicKey: silentPeerID.publicKey, host: "local", port: 0))

        try await Task.sleep(for: .milliseconds(30))

        // Start a fetch — continuation stored under the root CID.
        let fetchTask = Task {
            await node.fetchVolumeFromAllPeers(rootCID: "test-root-cid")
        }
        try await Task.sleep(for: .milliseconds(80))

        // Simulate what onCancel does: resolve by the content key, independent
        // of which peer was expected to answer.
        let start = ContinuousClock.now
        await node.resolveVolumeRequestsForRoot(rootCID: "test-root-cid")

        let result = await fetchTask.value
        let elapsed = ContinuousClock.now - start

        #expect(result.isEmpty)
        #expect(elapsed < .milliseconds(500),
            "resolveVolumeRequestsForRoot must resolve immediately — got \(elapsed)")
    }

    /// All pending volume requests resolve when cleanupAllPending is called,
    /// ensuring no continuations are leaked on Ivy teardown.
    @Test("cleanupAllPending resolves all pending volume requests")
    func testCleanupAllPendingResolvesVolumes() async throws {
        let nodeA = Ivy(config: IvyConfig(
            publicKey: "cleanup-a",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            requestTimeout: .seconds(10),
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(999),
                staleTimeout: .seconds(999),
                maxMissedPongs: 99,
                enabled: false
            ),
            enablePEX: false
        ))

        let silentPeerID = PeerID(publicKey: "silent-peer-cleanup00")
        let silentConn = LocalPeerConnection(id: await nodeA.localID)
        await nodeA.registerLocalPeer(silentConn, as: silentPeerID)
        await nodeA.addToRouter(silentPeerID, endpoint: PeerEndpoint(publicKey: silentPeerID.publicKey, host: "local", port: 0))

        try await Task.sleep(for: .milliseconds(30))

        let fetchTask = Task {
            await nodeA.fetchVolumeFromAllPeers(rootCID: "cid-cleanup-test")
        }

        try await Task.sleep(for: .milliseconds(80))

        let start = ContinuousClock.now
        await nodeA.cleanupAllPending()

        let result = await fetchTask.value
        let elapsed = ContinuousClock.now - start

        #expect(result.isEmpty)
        #expect(elapsed < .milliseconds(500), "cleanupAllPending must resolve immediately — got \(elapsed)")
    }
}
