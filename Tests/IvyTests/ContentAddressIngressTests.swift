import Testing
import Foundation
@testable import Ivy
@testable import Tally

private final class VolumeAnnouncementCollector: IvyDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var roots: [String] = []

    func ivy(
        _ ivy: Ivy,
        didReceiveVolumeAnnouncement rootCID: String,
        childCIDs: [String],
        totalSize: UInt64,
        from peer: PeerID
    ) {
        lock.withLock { roots.append(rootCID) }
    }

    var receivedRoots: [String] {
        lock.withLock { roots }
    }
}

private final class BlockCollector: IvyDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var blocks: [String] = []

    func ivy(_ ivy: Ivy, didReceiveBlock cid: String, data: Data, from peer: PeerID) {
        lock.withLock { blocks.append(cid) }
    }

    var receivedBlocks: [String] {
        lock.withLock { blocks }
    }
}

@Suite("Content-Addressed Ingress")
struct ContentAddressIngressTests {
    @Test("tampered gossip block is dropped and the peer is penalized")
    func tamperedGossipBlockIsDroppedAndPeerPenalized() async throws {
        let node = Ivy(config: testConfig(publicKey: "gossip-block-verify"))
        let collector = BlockCollector()
        await node.setDelegate(collector)
        let nodeID = await node.localID

        let peer = PeerID(publicKey: "tampered-gossip-block-peer")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        try await Task.sleep(for: .milliseconds(20))

        let honestData = Data("honest gossip block bytes".utf8)
        let cid = testCID(for: honestData)
        let forgedData = Data("forged gossip block bytes".utf8)

        // Drive a blob whose bytes do NOT match the claimed CID through the real
        // gossip ingress (handleMessage -> .block content-address chokepoint).
        remote.send(.block(cid: cid, data: forgedData))
        try await Task.sleep(for: .milliseconds(50))

        // Invalid != unavailable: the tampered content must be dropped, never surfaced.
        #expect(collector.receivedBlocks.isEmpty)
        // Fail-closed: the serving peer is scored down via Tally.
        let tally = await node.tally
        #expect(tally.peerLedger(for: peer)?.failureCount.value == 1)
    }

    @Test("mismatched block response does not resolve a pending fetch")
    func mismatchedBlockDoesNotResolveFetch() async throws {
        let node = Ivy(config: testConfig(publicKey: "requester-block-verify"))
        let nodeID = await node.localID

        let badPeer = PeerID(publicKey: "bad-block-peer")
        let goodPeer = PeerID(publicKey: "good-block-peer")
        let (badLocal, badRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: badPeer)
        let (goodLocal, goodRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: goodPeer)
        await node.registerLocalPeer(badLocal, as: badPeer)
        await node.registerLocalPeer(goodLocal, as: goodPeer)
        await node.addToRouter(badPeer, endpoint: PeerEndpoint(publicKey: badPeer.publicKey, host: "local", port: 0))
        await node.addToRouter(goodPeer, endpoint: PeerEndpoint(publicKey: goodPeer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let goodData = Data("honest block bytes".utf8)
        let cid = testCID(for: goodData)
        let forgedData = Data("forged block bytes".utf8)

        Task {
            for await msg in badRemote.messages {
                if case .dhtForward(let requestedCID, _) = msg, requestedCID == cid {
                    badRemote.send(.block(cid: requestedCID, data: forgedData))
                }
            }
        }
        // The honest peer pushes the block unsolicited (content-addressed
        // responses are verified by CID, not by who was asked).
        Task {
            try? await Task.sleep(for: .milliseconds(60))
            goodRemote.send(.block(cid: cid, data: goodData))
        }

        let result = await node.get(cid: cid, target: badPeer)
        #expect(result == goodData)
    }

    @Test("mismatched blocks response does not poison volume waiters")
    func mismatchedBlocksDoNotPoisonVolumeWaiters() async throws {
        let node = Ivy(config: testConfig(publicKey: "requester-volume-verify"))
        let nodeID = await node.localID

        let badPeer = PeerID(publicKey: "bad-volume-peer")
        let goodPeer = PeerID(publicKey: "good-volume-peer")
        let (badLocal, badRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: badPeer)
        let (goodLocal, goodRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: goodPeer)
        await node.registerLocalPeer(badLocal, as: badPeer)
        await node.registerLocalPeer(goodLocal, as: goodPeer)
        await node.addToRouter(badPeer, endpoint: PeerEndpoint(publicKey: badPeer.publicKey, host: "local", port: 0))
        await node.addToRouter(goodPeer, endpoint: PeerEndpoint(publicKey: goodPeer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let goodData = Data("honest volume root".utf8)
        let rootCID = testCID(for: goodData)
        let forgedData = Data("forged volume root".utf8)

        Task {
            for await msg in badRemote.messages {
                if case .want(let cids) = msg {
                    badRemote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: forgedData)]))
                }
            }
        }
        Task {
            for await msg in goodRemote.messages {
                if case .want(let cids) = msg {
                    try? await Task.sleep(for: .milliseconds(30))
                    goodRemote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: goodData)]))
                }
            }
        }

        let result = await node.fetchVolumeFromAllPeers(rootCID: rootCID)
        #expect(result[rootCID] == goodData)
    }

    @Test("mixed valid and invalid blocks response is rejected atomically")
    func mixedBlocksResponseIsRejectedAtomically() async throws {
        let node = Ivy(config: testConfig(publicKey: "requester-mixed-volume-verify"))
        let nodeID = await node.localID

        let badPeer = PeerID(publicKey: "bad-mixed-volume-peer")
        let goodPeer = PeerID(publicKey: "good-mixed-volume-peer")
        let (badLocal, badRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: badPeer)
        let (goodLocal, goodRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: goodPeer)
        await node.registerLocalPeer(badLocal, as: badPeer)
        await node.registerLocalPeer(goodLocal, as: goodPeer)
        await node.addToRouter(badPeer, endpoint: PeerEndpoint(publicKey: badPeer.publicKey, host: "local", port: 0))
        await node.addToRouter(goodPeer, endpoint: PeerEndpoint(publicKey: goodPeer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let rootData = Data("honest mixed volume root".utf8)
        let rootCID = testCID(for: rootData)
        let childData = Data("honest mixed volume child".utf8)
        let childCID = testCID(for: childData)
        let forgedChildData = Data("forged mixed volume child".utf8)

        Task {
            for await msg in badRemote.messages {
                if case .want(let cids) = msg {
                    badRemote.send(.blocks(
                        rootCID: cids[0],
                        items: [
                            (cid: rootCID, data: rootData),
                            (cid: childCID, data: forgedChildData),
                        ]
                    ))
                }
            }
        }
        Task {
            for await msg in goodRemote.messages {
                if case .want(let cids) = msg {
                    try? await Task.sleep(for: .milliseconds(30))
                    goodRemote.send(.blocks(
                        rootCID: cids[0],
                        items: [
                            (cid: rootCID, data: rootData),
                            (cid: childCID, data: childData),
                        ]
                    ))
                }
            }
        }

        let result = await node.fetchVolumeFromAllPeers(rootCID: rootCID)
        #expect(result[rootCID] == rootData)
        #expect(result[childCID] == childData)
    }

    @Test("invalid pushVolume does not consume the volume dedup key")
    func invalidPushVolumeDoesNotConsumeDedupKey() async throws {
        let node = Ivy(config: testConfig(publicKey: "push-volume-verify"))
        let collector = VolumeAnnouncementCollector()
        await node.setDelegate(collector)
        let nodeID = await node.localID

        let peer = PeerID(publicKey: "push-volume-peer")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        try await Task.sleep(for: .milliseconds(20))

        let goodData = Data("valid pushed volume".utf8)
        let rootCID = testCID(for: goodData)
        let forgedData = Data("invalid pushed volume".utf8)

        remote.send(.pushVolume(rootCID: rootCID, items: [(cid: rootCID, data: forgedData)]))
        try await Task.sleep(for: .milliseconds(30))
        remote.send(.pushVolume(rootCID: rootCID, items: [(cid: rootCID, data: goodData)]))
        try await Task.sleep(for: .milliseconds(150))

        #expect(collector.receivedRoots == [rootCID])
    }

    @Test("pushVolume missing root does not consume the volume dedup key")
    func pushVolumeMissingRootDoesNotConsumeDedupKey() async throws {
        let node = Ivy(config: testConfig(publicKey: "push-volume-missing-root"))
        let collector = VolumeAnnouncementCollector()
        await node.setDelegate(collector)
        let nodeID = await node.localID

        let peer = PeerID(publicKey: "push-volume-missing-root-peer")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        try await Task.sleep(for: .milliseconds(20))

        let rootData = Data("valid pushed missing-root root".utf8)
        let rootCID = testCID(for: rootData)
        let childData = Data("valid pushed missing-root child".utf8)
        let childCID = testCID(for: childData)

        remote.send(.pushVolume(rootCID: rootCID, items: [(cid: childCID, data: childData)]))
        try await Task.sleep(for: .milliseconds(30))
        remote.send(.pushVolume(rootCID: rootCID, items: [(cid: rootCID, data: rootData)]))
        try await Task.sleep(for: .milliseconds(150))

        #expect(collector.receivedRoots == [rootCID])
    }
}
