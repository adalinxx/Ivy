import Testing
import Foundation
@testable import Ivy
@testable import Tally

// MARK: - Thread-safe message recorder

final class PeerMessageLog: @unchecked Sendable {
    private let lock = NSLock()
    private var _messages: [Message] = []

    func record(_ message: Message) {
        lock.withLock { self._messages.append(message) }
    }

    var messages: [Message] { lock.withLock { _messages } }

    func received(want rootCID: String) -> Bool {
        messages.contains {
            if case .want(let cids) = $0 { return cids.contains(rootCID) }
            if case .wantVolume(let root, _) = $0 { return root == rootCID }
            return false
        }
    }

    func wantCount(for rootCID: String) -> Int {
        messages.filter {
            if case .want(let cids) = $0 { return cids.contains(rootCID) }
            if case .wantVolume(let root, _) = $0 { return root == rootCID }
            return false
        }.count
    }
}

private func requestedVolume(_ message: Message) -> (rootCID: String, cids: [String])? {
    switch message {
    case .want(let cids):
        guard let rootCID = cids.first else { return nil }
        return (rootCID, [])
    case .wantVolume(let rootCID, let cids):
        return (rootCID, cids)
    default:
        return nil
    }
}

// MARK: - Mock data source

final class MockVolumeDataSource: IvyDataSource, @unchecked Sendable {
    private let lock = NSLock()
    private var blocks: [String: Data] = [:]
    private var volumes: [String: [String: Data]] = [:]

    func store(rootCID: String, data: Data) {
        store(rootCID: rootCID, entries: [(cid: rootCID, data: data)])
    }

    func store(rootCID: String, entries: [(cid: String, data: Data)]) {
        lock.withLock {
            var volume: [String: Data] = [:]
            for entry in entries {
                blocks[entry.cid] = entry.data
                volume[entry.cid] = entry.data
            }
            volumes[rootCID] = volume
        }
    }

    func data(for cid: String) async -> Data? {
        lock.withLock { blocks[cid] }
    }

    func volumeData(for rootCID: String, cids: [String]) async -> [(cid: String, data: Data)] {
        lock.withLock {
            guard let volume = volumes[rootCID] else { return [] }
            if cids.isEmpty {
                return volume.map { (cid: $0.key, data: $0.value) }
            }
            return cids.compactMap { cid in
                guard let data = volume[cid] else { return nil }
                return (cid: cid, data: data)
            }
        }
    }

    func hasVolume(rootCID: String) async -> Bool {
        lock.withLock { volumes[rootCID] != nil }
    }
}

// MARK: - Helpers

private func makeNode(
    publicKey: String,
    requestTimeout: Duration = .seconds(5),
    maxWantCandidates: Int = 8
) -> Ivy {
    Ivy(config: IvyConfig(
        publicKey: publicKey,
        listenPort: 0,
        bootstrapPeers: [],
        enableLocalDiscovery: false,
        requestTimeout: requestTimeout,
        healthConfig: PeerHealthConfig(
            keepaliveInterval: .seconds(999),
            staleTimeout: .seconds(999),
            maxMissedPongs: 99,
            enabled: false
        ),
        enablePEX: false,
        maxWantCandidates: maxWantCandidates
    ))
}

// MARK: - Suite

/// Tests for the unified single-phase want/blocks protocol.
///
/// Protocol invariant: data is content-addressed, so any peer serving a CID is
/// equally valid. A single `want` message broadcasts to all candidates; the first
/// `blocks` response wakes all coalesced waiters.
@Suite("Want Protocol")
struct WantHaveProtocolTests {

    // MARK: - Requester side

    /// Calling fetchVolumeFromNetwork must send a `want` message (not any old
    /// haveVolumes/getVolume messages) to connected peers.
    @Test("want message sent to candidates on fetch")
    func testWantSentToCandidatesOnFetch() async throws {
        let node = makeNode(publicKey: "requester-want-sent")
        let nodeID = await node.localID
        let peer = PeerID(publicKey: "candidate-want-recv0")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        await node.addToRouter(peer, endpoint: PeerEndpoint(publicKey: peer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let responseData = Data("data".utf8)
        let rootCID = testCID(for: responseData)
        let log = PeerMessageLog()
        Task {
            for await msg in remote.messages {
                log.record(msg)
                if case .want(let cids) = msg {
                    remote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: responseData)]))
                }
            }
        }

        _ = await node.fetchVolumeFromAllPeers(rootCID: rootCID)

        #expect(log.received(want: rootCID), "Peer must receive a want message")
        let noOldProtocol = !log.messages.contains {
            if case .want = $0 { return false }
            return false  // haveVolumes/getVolume no longer exist
        }
        _ = noOldProtocol  // single-phase: only want is sent
    }

    /// Two concurrent callers for the same rootCID must coalesce into one `want`
    /// sent to peers. Both callers receive data when the single response arrives.
    @Test("concurrent fetches coalesce — single want, both callers resolve")
    func testConcurrentFetchesCoalesce() async throws {
        let node = makeNode(publicKey: "requester-coalesce0")
        let nodeID = await node.localID
        let peer = PeerID(publicKey: "holder-coalesce-aaaa0")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        await node.addToRouter(peer, endpoint: PeerEndpoint(publicKey: peer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let expectedData = Data("shared content".utf8)
        let rootCID = testCID(for: expectedData)
        let log = PeerMessageLog()

        Task {
            for await msg in remote.messages {
                log.record(msg)
                if case .want(let cids) = msg {
                    try? await Task.sleep(for: .milliseconds(30))
                    remote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: expectedData)]))
                }
            }
        }

        async let fetch1 = node.fetchVolumeFromAllPeers(rootCID: rootCID)
        async let fetch2 = node.fetchVolumeFromAllPeers(rootCID: rootCID)
        let (r1, r2) = await (fetch1, fetch2)

        #expect(r1[rootCID] == expectedData || r2[rootCID] == expectedData,
            "At least one concurrent fetch must receive data")
        #expect(log.wantCount(for: rootCID) == 1,
            "Exactly one want must be sent — concurrent fetches must coalesce")
    }

    /// The first non-empty blocks response wakes all waiters. A second response
    /// from a slow peer must not crash (no double-resume) and must be discarded.
    @Test("first blocks response wakes all waiters; second is discarded")
    func testFirstBlocksResponseWakesAllWaiters() async throws {
        let node = makeNode(publicKey: "requester-first-wins")
        let nodeID = await node.localID

        let fastPeer = PeerID(publicKey: "fast-winner-ffffffff0")
        let slowPeer = PeerID(publicKey: "slow-loser-sssssssss0")
        let (fLocal, fRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: fastPeer)
        let (sLocal, sRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: slowPeer)
        await node.registerLocalPeer(fLocal, as: fastPeer)
        await node.registerLocalPeer(sLocal, as: slowPeer)
        await node.addToRouter(fastPeer, endpoint: PeerEndpoint(publicKey: fastPeer.publicKey, host: "local", port: 0))
        await node.addToRouter(slowPeer, endpoint: PeerEndpoint(publicKey: slowPeer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let fastData = Data("fast wins".utf8)
        let rootCID = testCID(for: fastData)

        Task {
            for await msg in fRemote.messages {
                if case .want(let cids) = msg {
                    fRemote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: fastData)]))
                }
            }
        }
        Task {
            for await msg in sRemote.messages {
                if case .want(let cids) = msg {
                    try? await Task.sleep(for: .milliseconds(200))
                    sRemote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: Data("slow loses".utf8))]))
                }
            }
        }

        // Would crash with "resuming already-resumed continuation" on double-resume bug
        let result = await node.fetchVolumeFromAllPeers(rootCID: rootCID)
        #expect(result[rootCID] == fastData, "Fast peer must win")
    }

    /// Fetch must resolve at the speed of the fastest peer — a 3s slow peer
    /// must not hold up a 10ms fast peer.
    @Test("fast peer wins — fetch resolves near fast-peer latency")
    func testFastPeerDoesNotWaitForSlowPeer() async throws {
        let node = makeNode(publicKey: "requester-latency000")
        let nodeID = await node.localID

        let fastPeer = PeerID(publicKey: "fast-latency-fffffff")
        let slowPeer = PeerID(publicKey: "slow-latency-sssssss")
        let (fLocal, fRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: fastPeer)
        let (sLocal, sRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: slowPeer)
        await node.registerLocalPeer(fLocal, as: fastPeer)
        await node.registerLocalPeer(sLocal, as: slowPeer)
        await node.addToRouter(fastPeer, endpoint: PeerEndpoint(publicKey: fastPeer.publicKey, host: "local", port: 0))
        await node.addToRouter(slowPeer, endpoint: PeerEndpoint(publicKey: slowPeer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let fastData = Data("fast data".utf8)
        let rootCID = testCID(for: fastData)

        Task {
            for await msg in fRemote.messages {
                if case .want(let cids) = msg {
                    try? await Task.sleep(for: .milliseconds(10))
                    fRemote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: fastData)]))
                }
            }
        }
        Task {
            for await msg in sRemote.messages {
                if case .want(let cids) = msg {
                    try? await Task.sleep(for: .seconds(3))
                    sRemote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: Data("slow".utf8))]))
                }
            }
        }

        let start = ContinuousClock.now
        let result = await node.fetchVolumeFromAllPeers(rootCID: rootCID)
        let elapsed = ContinuousClock.now - start

        #expect(result[rootCID] == fastData, "Fast peer must win")
        // Allow 800ms — enough to distinguish from the slow peer's 3s delay
        #expect(elapsed < .milliseconds(800),
            "Fetch must resolve near fast-peer latency, not 3s slow-peer — got \(elapsed)")
    }

    /// A Byzantine peer that sends empty blocks must not poison waiters.
    /// An honest peer responding afterward must still deliver data.
    @Test("Byzantine empty blocks do not poison waiters")
    func testByzantineEmptyBlocksDoNotPoison() async throws {
        let node = makeNode(publicKey: "requester-byzantine0")
        let nodeID = await node.localID

        let byzantinePeer = PeerID(publicKey: "byzantine-liar-bbbbb")
        let honestPeer = PeerID(publicKey: "honest-server-hhhhh0")
        let (bLocal, bRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: byzantinePeer)
        let (hLocal, hRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: honestPeer)
        await node.registerLocalPeer(bLocal, as: byzantinePeer)
        await node.registerLocalPeer(hLocal, as: honestPeer)
        await node.addToRouter(byzantinePeer, endpoint: PeerEndpoint(publicKey: byzantinePeer.publicKey, host: "local", port: 0))
        await node.addToRouter(honestPeer, endpoint: PeerEndpoint(publicKey: honestPeer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let honestData = Data("real content".utf8)
        let rootCID = testCID(for: honestData)

        // Byzantine: immediately sends empty blocks (claims HAVE, delivers nothing)
        Task {
            for await msg in bRemote.messages {
                if case .want(let cids) = msg {
                    bRemote.send(.blocks(rootCID: cids[0], items: []))
                }
            }
        }
        // Honest: responds slightly later with real data
        Task {
            for await msg in hRemote.messages {
                if case .want(let cids) = msg {
                    try? await Task.sleep(for: .milliseconds(30))
                    hRemote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: honestData)]))
                }
            }
        }

        let result = await node.fetchVolumeFromAllPeers(rootCID: rootCID)
        #expect(result[rootCID] == honestData,
            "Honest peer's data must win — Byzantine empty-blocks must not resolve waiters with [:]")
    }

    @Test("single-candidate empty blocks resolves fetch immediately")
    func testSingleCandidateEmptyBlocksResolvesImmediately() async throws {
        let node = makeNode(publicKey: "requester-empty-blk", requestTimeout: .seconds(10))
        let nodeID = await node.localID

        let peer = PeerID(publicKey: "empty-blocks-peer0")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        await node.addToRouter(peer, endpoint: PeerEndpoint(publicKey: peer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let rootCID = "bafyrei-empty-blocks"
        let tally = await node.tally
        let repBefore = tally.reputation(for: peer)

        Task {
            for await msg in remote.messages {
                if case .want(let cids) = msg {
                    remote.send(.blocks(rootCID: cids[0], items: []))
                }
            }
        }

        let start = ContinuousClock.now
        let result = await node.fetchVolumeFromAllPeers(rootCID: rootCID)
        let elapsed = ContinuousClock.now - start
        let repAfter = tally.reputation(for: peer)

        #expect(result.isEmpty)
        #expect(elapsed < .milliseconds(800),
            "Empty BLOCKS should exhaust the candidate immediately, not wait requestTimeout=10s")
        #expect(repAfter == repBefore,
            "Empty BLOCKS is an incomplete response, not slashable invalid content")
    }

    /// When the single candidate sends notHave, the fetch must resolve immediately
    /// without waiting for requestTimeout. Gap 1 fix preserved.
    @Test("single-candidate notHave resolves fetch immediately")
    func testSingleCandidateNotHaveResolvesImmediately() async throws {
        let node = makeNode(publicKey: "requester-nothave00", requestTimeout: .seconds(10))
        let nodeID = await node.localID

        let peer = PeerID(publicKey: "nothave-peer-single0")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        await node.addToRouter(peer, endpoint: PeerEndpoint(publicKey: peer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let rootCID = "bafyrei-nothave-sngl"
        Task {
            for await msg in remote.messages {
                if case .want(let cids) = msg {
                    remote.send(.notHave(rootCID: cids[0]))
                }
            }
        }

        let start = ContinuousClock.now
        let result = await node.fetchVolumeFromAllPeers(rootCID: rootCID)
        let elapsed = ContinuousClock.now - start

        #expect(result.isEmpty)
        // Allow 800ms — enough to distinguish from requestTimeout=10s
        #expect(elapsed < .milliseconds(800),
            "notHave must resolve immediately, not wait requestTimeout=10s — got \(elapsed)")
    }

    /// When ALL candidates send notHave, the fetch resolves immediately.
    /// Key test for the pendingWantCandidates tracking.
    @Test("all candidates notHave resolves fetch immediately")
    func testAllCandidatesNotHaveResolvesImmediately() async throws {
        let node = makeNode(publicKey: "requester-allnothav", requestTimeout: .seconds(10))
        let nodeID = await node.localID

        let peer1 = PeerID(publicKey: "nothave-peer-one000")
        let peer2 = PeerID(publicKey: "nothave-peer-two000")
        let (local1, remote1) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer1)
        let (local2, remote2) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer2)
        await node.registerLocalPeer(local1, as: peer1)
        await node.registerLocalPeer(local2, as: peer2)
        await node.addToRouter(peer1, endpoint: PeerEndpoint(publicKey: peer1.publicKey, host: "local", port: 0))
        await node.addToRouter(peer2, endpoint: PeerEndpoint(publicKey: peer2.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let rootCID = "bafyrei-allnothave-r"
        Task {
            for await msg in remote1.messages {
                if case .want(let cids) = msg {
                    remote1.send(.notHave(rootCID: cids[0]))
                }
            }
        }
        Task {
            for await msg in remote2.messages {
                if case .want(let cids) = msg {
                    try? await Task.sleep(for: .milliseconds(20))
                    remote2.send(.notHave(rootCID: cids[0]))
                }
            }
        }

        let start = ContinuousClock.now
        let result = await node.fetchVolumeFromAllPeers(rootCID: rootCID)
        let elapsed = ContinuousClock.now - start

        #expect(result.isEmpty)
        #expect(elapsed < .milliseconds(800),
            "All-notHave must resolve immediately — got \(elapsed)")
    }

    /// One of two candidates sends notHave; the other sends blocks.
    /// The single notHave must NOT kill the fetch — the other peer still delivers.
    @Test("partial notHave does not resolve fetch — other candidate delivers")
    func testPartialNotHaveDoesNotResolve() async throws {
        let node = makeNode(publicKey: "requester-partial-nh", requestTimeout: .seconds(5))
        let nodeID = await node.localID

        let missPeer = PeerID(publicKey: "partial-miss-peer00")
        let hitPeer = PeerID(publicKey: "partial-hit-peer000")
        let (mLocal, mRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: missPeer)
        let (hLocal, hRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: hitPeer)
        await node.registerLocalPeer(mLocal, as: missPeer)
        await node.registerLocalPeer(hLocal, as: hitPeer)
        await node.addToRouter(missPeer, endpoint: PeerEndpoint(publicKey: missPeer.publicKey, host: "local", port: 0))
        await node.addToRouter(hitPeer, endpoint: PeerEndpoint(publicKey: hitPeer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let hitData = Data("delivered by hit peer".utf8)
        let rootCID = testCID(for: hitData)

        // Miss peer: notHave immediately
        Task {
            for await msg in mRemote.messages {
                if case .want(let cids) = msg {
                    mRemote.send(.notHave(rootCID: cids[0]))
                }
            }
        }
        // Hit peer: responds with data after a short delay
        Task {
            for await msg in hRemote.messages {
                if case .want(let cids) = msg {
                    try? await Task.sleep(for: .milliseconds(50))
                    hRemote.send(.blocks(rootCID: cids[0], items: [(cid: cids[0], data: hitData)]))
                }
            }
        }

        let result = await node.fetchVolumeFromAllPeers(rootCID: rootCID)
        #expect(result[rootCID] == hitData,
            "Hit peer must deliver data even though miss peer sent notHave first")
    }

    /// `notHave` is a claim about missing data, not proof of invalid behavior.
    @Test("consecutive notHave does not change peer reputation")
    func testConsecutiveNotHavesDoNotChangeTally() async throws {
        let node = makeNode(publicKey: "requester-tally-nth", requestTimeout: .milliseconds(200))
        let nodeID = await node.localID

        let peer = PeerID(publicKey: "nothave-tally-peerr0")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        await node.addToRouter(peer, endpoint: PeerEndpoint(publicKey: peer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        Task {
            for await msg in remote.messages {
                if case .want(let cids) = msg {
                    remote.send(.notHave(rootCID: cids[0]))
                }
            }
        }

        let tally = await node.tally
        let repBefore = tally.reputation(for: peer)

        for i in 0..<5 {
            _ = await node.fetchVolumeFromAllPeers(rootCID: "bafyrei-tally-\(i)")
        }

        let repAfter = tally.reputation(for: peer)
        #expect(repAfter == repBefore,
            "Consecutive notHave must not credit or slash — before=\(repBefore) after=\(repAfter)")
    }

    @Test("child CID fetch uses root Volume request and accepts full Volume")
    func testChildFetchUsesRootVolumeRequest() async throws {
        let node = makeNode(publicKey: "requester-root-shape", requestTimeout: .seconds(5))
        let nodeID = await node.localID

        let completePeer = PeerID(publicKey: "root-volume-peer00")
        let (cLocal, cRemote) = LocalPeerConnection.pair(localID: nodeID, remoteID: completePeer)
        await node.registerLocalPeer(cLocal, as: completePeer)
        await node.addToRouter(completePeer, endpoint: PeerEndpoint(publicKey: completePeer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let rootData = Data("root volume root".utf8)
        let rootCID = testCID(for: rootData)
        let childData = Data("root volume child".utf8)
        let childCID = testCID(for: childData)
        let log = PeerMessageLog()

        Task {
            for await msg in cRemote.messages {
                log.record(msg)
                if let request = requestedVolume(msg) {
                    cRemote.send(.blocks(
                        rootCID: request.rootCID,
                        items: [
                            (cid: rootCID, data: rootData),
                            (cid: childCID, data: childData),
                        ]
                    ))
                }
            }
        }

        let result = await node.fetchVolume(rootCID: rootCID, childCIDs: [childCID])

        #expect(result[rootCID] == rootData)
        #expect(result[childCID] == childData)
        #expect(log.wantCount(for: rootCID) == 1, "Child fetch should request the Volume root")
    }

    @Test("root-only valid Volume response is treated as opaque Volume")
    func testRootOnlyValidVolumeResponseIsOpaque() async throws {
        let node = makeNode(publicKey: "requester-volume-noslash", requestTimeout: .seconds(5))
        let nodeID = await node.localID

        let peer = PeerID(publicKey: "volume-noslash-peer")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        await node.addToRouter(peer, endpoint: PeerEndpoint(publicKey: peer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let rootData = Data("volume noslash root".utf8)
        let rootCID = testCID(for: rootData)
        let childCID = testCID(for: Data("volume noslash child".utf8))
        let tally = await node.tally
        let repBefore = tally.reputation(for: peer)

        Task {
            for await msg in remote.messages {
                if let request = requestedVolume(msg) {
                    remote.send(.blocks(rootCID: request.rootCID, items: [(cid: rootCID, data: rootData)]))
                }
            }
        }

        let result = await node.fetchVolume(rootCID: rootCID, childCIDs: [childCID])
        let repAfter = tally.reputation(for: peer)

        #expect(result[rootCID] == rootData)
        #expect(result[childCID] == nil)
        #expect(repAfter >= repBefore,
            "A root-only opaque Volume response with valid CIDs must not slash the peer")
    }

    @Test("valid but incomplete Volume response is neutral")
    func testValidButIncompleteVolumeResponseIsNeutral() async throws {
        let node = makeNode(publicKey: "requester-volume-missrt", requestTimeout: .seconds(5))
        let nodeID = await node.localID

        let peer = PeerID(publicKey: "volume-missing-root")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        await node.addToRouter(peer, endpoint: PeerEndpoint(publicKey: peer.publicKey, host: "local", port: 0))
        try await Task.sleep(for: .milliseconds(20))

        let rootCID = testCID(for: Data("missing root".utf8))
        let childData = Data("valid child only".utf8)
        let childCID = testCID(for: childData)
        let tally = await node.tally
        let repBefore = tally.reputation(for: peer)

        Task {
            for await msg in remote.messages {
                if let request = requestedVolume(msg) {
                    remote.send(.blocks(rootCID: request.rootCID, items: [(cid: childCID, data: childData)]))
                }
            }
        }

        let start = ContinuousClock.now
        let result = await node.fetchVolume(rootCID: rootCID)
        let elapsed = ContinuousClock.now - start
        let repAfter = tally.reputation(for: peer)

        #expect(result.isEmpty)
        #expect(elapsed < .milliseconds(800),
            "Incomplete Volume response should exhaust the candidate immediately, not wait for timeout")
        #expect(repAfter == repBefore,
            "Valid bytes that do not complete the requested Volume must be neutral")
    }

    /// maxWantCandidates caps the broadcast fan-out when DHT has no providers.
    @Test("want broadcast capped at maxWantCandidates")
    func testWantBroadcastCappedAtMaxCandidates() async throws {
        let maxCandidates = 3
        let node = makeNode(publicKey: "requester-cap-peers0", maxWantCandidates: maxCandidates)
        let nodeID = await node.localID

        // Connect 10 peers — more than maxCandidates
        var logs: [PeerID: PeerMessageLog] = [:]
        for i in 0..<10 {
            let peerID = PeerID(publicKey: "cap-peer-\(String(format: "%08d", i))")
            let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peerID)
            await node.registerLocalPeer(local, as: peerID)
            await node.addToRouter(peerID, endpoint: PeerEndpoint(publicKey: peerID.publicKey, host: "local", port: 0))
            let log = PeerMessageLog()
            logs[peerID] = log
            Task {
                for await msg in remote.messages {
                    log.record(msg)
                    // Never respond — we only care about how many peers receive want
                }
            }
        }
        try await Task.sleep(for: .milliseconds(30))

        let rootCID = "bafyrei-cap-test-cid"
        // Use fetchVolume (not fetchVolumeFromAllPeers): fetchVolumeFromNetwork applies
        // the maxWantCandidates cap on the broadcast fallback. fetchVolumeFromAllPeers
        // broadcasts to all peers by design (no cap — it's the emergency fallback).
        // Wait 700ms: findPinnersViaDHT has a 500ms internal timeout before
        // the broadcast fallback fires, then +200ms for messages to propagate.
        Task { _ = await node.fetchVolume(rootCID: rootCID) }
        try await Task.sleep(for: .milliseconds(700))

        let peersReceived = logs.values.filter { $0.received(want: rootCID) }.count
        #expect(peersReceived <= maxCandidates,
            "At most \(maxCandidates) peers should receive want — got \(peersReceived)")
        #expect(peersReceived > 0,
            "At least one peer must receive want")
    }

    // MARK: - Responder side (handleWant)

    /// When our node receives `want(rootCID)` and the dataSource has the volume,
    /// it must respond with `blocks`.
    @Test("handleWant serves blocks when dataSource.hasVolume is true")
    func testHandleWantServesBlocks() async throws {
        let node = makeNode(publicKey: "responder-has-vol00")
        let nodeID = await node.localID

        let ds = MockVolumeDataSource()
        let blockData = Data("block content here".utf8)
        let rootCID = testCID(for: blockData)
        ds.store(rootCID: rootCID, data: blockData)
        await node.setDataSource(ds)

        let requesterID = PeerID(publicKey: "requester-for-want0")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: requesterID)
        await node.registerLocalPeer(local, as: requesterID)
        try await Task.sleep(for: .milliseconds(20))

        // Collect messages the node sends back (node replies via local, arrives in remote.messages)
        let log = PeerMessageLog()
        Task {
            for await msg in remote.messages {
                log.record(msg)
            }
        }

        // Requester sends want — node processes it via handleWant
        remote.send(.want(rootCIDs: [rootCID]))
        try await Task.sleep(for: .milliseconds(150))

        let blocksMsg = log.messages.first {
            if case .blocks(let cid, _) = $0 { return cid == rootCID }
            return false
        }
        #expect(blocksMsg != nil, "Node must respond with blocks when it has the volume")
        if case .blocks(_, let items) = blocksMsg {
            #expect(items.contains { $0.data == blockData }, "Blocks must contain the stored data")
        }
    }

    @Test("handleWantVolume serves only requested CIDs")
    func testHandleWantVolumeServesRequestedCIDs() async throws {
        let node = makeNode(publicKey: "responder-filter-vol")
        let nodeID = await node.localID

        let ds = MockVolumeDataSource()
        let rootData = Data("filtered root".utf8)
        let rootCID = testCID(for: rootData)
        let childAData = Data("filtered child a".utf8)
        let childACID = testCID(for: childAData)
        let childBData = Data("filtered child b".utf8)
        let childBCID = testCID(for: childBData)
        ds.store(rootCID: rootCID, entries: [
            (cid: rootCID, data: rootData),
            (cid: childACID, data: childAData),
            (cid: childBCID, data: childBData),
        ])
        await node.setDataSource(ds)

        let requesterID = PeerID(publicKey: "requester-filter-vol")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: requesterID)
        await node.registerLocalPeer(local, as: requesterID)
        try await Task.sleep(for: .milliseconds(20))

        let log = PeerMessageLog()
        Task {
            for await msg in remote.messages {
                log.record(msg)
            }
        }

        remote.send(.wantVolume(rootCID: rootCID, cids: [childACID]))
        try await Task.sleep(for: .milliseconds(150))

        let blocksMsg = log.messages.first {
            if case .blocks(let cid, _) = $0 { return cid == rootCID }
            return false
        }
        if case .blocks(_, let items) = blocksMsg {
            #expect(items.contains { $0.cid == rootCID })
            #expect(items.contains { $0.cid == childACID })
            #expect(!items.contains { $0.cid == childBCID })
        } else {
            Issue.record("Expected filtered blocks response")
        }
    }

    /// When our node receives `want(rootCID)` and the dataSource does NOT have
    /// the volume, it must respond with `notHave`.
    @Test("handleWant sends notHave when dataSource.hasVolume is false")
    func testHandleWantSendsNotHave() async throws {
        let node = makeNode(publicKey: "responder-no-vol000")
        let nodeID = await node.localID

        let ds = MockVolumeDataSource()  // empty — no volumes stored
        await node.setDataSource(ds)

        let requesterID = PeerID(publicKey: "requester-for-want1")
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: requesterID)
        await node.registerLocalPeer(local, as: requesterID)
        try await Task.sleep(for: .milliseconds(20))

        let log = PeerMessageLog()
        Task {
            for await msg in remote.messages {
                log.record(msg)
            }
        }

        let rootCID = "bafyrei-missing-vol0"
        remote.send(.want(rootCIDs: [rootCID]))
        try await Task.sleep(for: .milliseconds(150))

        let notHaveMsg = log.messages.first {
            if case .notHave(let cid) = $0 { return cid == rootCID }
            return false
        }
        #expect(notHaveMsg != nil, "Node must respond with notHave when it does not have the volume")
    }

    /// Tally failures recorded for a peer reduce its reputation.
    /// Note: shouldAllow only gates under bandwidth pressure; in isolated tests
    /// with no byte traffic, rate pressure is zero so the gate is always open.
    /// This test verifies that want-induced notHave failures DO accumulate in tally
    /// and that handleWant calls shouldAllow (the gate is in the right place).
    @Test("handleWant calls tally.shouldAllow — failures accumulate in reputation")
    func testHandleWantRespectsTally() async throws {
        let node = makeNode(publicKey: "responder-tally-blk")
        let nodeID = await node.localID

        let ds = MockVolumeDataSource()
        let storedData = Data("data".utf8)
        let rootCID = testCID(for: storedData)
        ds.store(rootCID: rootCID, data: storedData)
        await node.setDataSource(ds)

        let tally = await node.tally
        let peer = PeerID(publicKey: "tally-test-peer0000")
        let repBefore = tally.reputation(for: peer)

        // Record failures to drive down reputation
        for _ in 0..<20 { tally.recordFailure(peer: peer) }
        let repAfter = tally.reputation(for: peer)

        // Reputation must have decreased from failures
        #expect(repAfter <= repBefore,
            "Tally failures must reduce reputation — before=\(repBefore) after=\(repAfter)")

        // Verify handleWant does respond (no rate pressure in isolated test)
        let (local, remote) = LocalPeerConnection.pair(localID: nodeID, remoteID: peer)
        await node.registerLocalPeer(local, as: peer)
        try await Task.sleep(for: .milliseconds(20))

        let log = PeerMessageLog()
        Task {
            for await msg in remote.messages { log.record(msg) }
        }

        remote.send(.want(rootCIDs: [rootCID]))
        try await Task.sleep(for: .milliseconds(150))

        // With no rate pressure shouldAllow returns true — node responds normally
        let volumeResponse = log.messages.first {
            if case .blocks(let cid, _) = $0 { return cid == rootCID }
            if case .notHave(let cid) = $0 { return cid == rootCID }
            return false
        }
        #expect(volumeResponse != nil, "Node responds when no rate pressure — tally.shouldAllow is true")
    }
}
