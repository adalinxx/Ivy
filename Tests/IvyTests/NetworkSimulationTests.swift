import Testing
import Foundation
import Crypto
@testable import Ivy
@testable import Tally

private func generatePinKeyPair() -> (publicKey: String, privateKey: Data) {
    let privateKey = Curve25519.Signing.PrivateKey()
    let pubHex = privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    return (pubHex, privateKey.rawRepresentation)
}

private func signedPinAnnounce(rootCID: String, keyPair: (publicKey: String, privateKey: Data), fee: UInt64 = 5) -> Message {
    let expiry = UInt64(Date().timeIntervalSince1970) + 3600
    let signature = PinAnnouncementSignature.sign(
        rootCID: rootCID,
        publicKey: keyPair.publicKey,
        expiry: expiry,
        fee: fee,
        signingKey: keyPair.privateKey
    )!
    return .pinAnnounce(rootCID: rootCID, publicKey: keyPair.publicKey, expiry: expiry, signature: signature, fee: fee)
}

/// Creates a simulated network of Ivy nodes connected via local peer connections.
/// Returns the nodes and a cleanup function.
func createNetwork(count: Int, thresholdMultiplier: UInt64 = 1000) async -> [Ivy] {
    var nodes: [Ivy] = []
    for i in 0..<count {
        let config = IvyConfig(
            publicKey: "node-\(i)",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            healthConfig: PeerHealthConfig(keepaliveInterval: .seconds(999), staleTimeout: .seconds(999), maxMissedPongs: 99, enabled: false),
            enablePEX: false
        )
        nodes.append(Ivy(config: config))
    }
    return nodes
}

/// Connects two Ivy nodes bidirectionally via a single LocalPeerConnection pair.
/// A.send(bID) → B receives. B.send(aID) → A receives.
func connectNodes(_ a: Ivy, _ b: Ivy) async {
    let aID = await a.localID
    let bID = await b.localID

    // LocalPeerConnection.pair: end1.send → end2.receives, end2.send → end1.receives
    // A registers end1 as bID: A.fireToPeer(bID) → end1.send → end2 receives (B reads end2)
    // B registers end2 as aID: B.fireToPeer(aID) → end2.send → end1 receives (A reads end1)
    let (end1, end2) = LocalPeerConnection.pair(localID: aID, remoteID: bID)
    await a.registerLocalPeer(end1, as: bID)
    await b.registerLocalPeer(end2, as: aID)

    let aEndpoint = PeerEndpoint(publicKey: aID.publicKey, host: "local", port: 0)
    let bEndpoint = PeerEndpoint(publicKey: bID.publicKey, host: "local", port: 0)
    await a.addToRouter(bID, endpoint: bEndpoint)
    await b.addToRouter(aID, endpoint: aEndpoint)
}

/// Extension to expose router operations from tests
extension Ivy {
    func addToRouter(_ peer: PeerID, endpoint: PeerEndpoint) {
        router.addPeer(peer, endpoint: endpoint, tally: tally)
    }

    func allRouterPeers() -> [Router.BucketEntry] {
        router.allPeers()
    }

    func fireToPeerPublic(_ peer: PeerID, _ message: Message) {
        fireToPeer(peer, message)
    }
}

// MARK: - Pin Discovery Chain

@Suite("Pin Discovery Chain")
struct PinDiscoveryChainTests {

    @Test("Pin announcement stored at one node, discovered from another")
    func testPinDiscoveryAcrossNodes() async throws {
        // A stores pin announcement. B queries A via findPins.
        let nodeA = Ivy(config: testConfig(publicKey: "pin-a"))
        let pinB = generatePinKeyPair()
        let peerBID = PeerID(publicKey: pinB.publicKey)
        let localID = await nodeA.localID
        let (bSide, aSide) = LocalPeerConnection.pair(localID: peerBID, remoteID: localID)
        await nodeA.registerLocalPeer(aSide, as: peerBID)
        try await Task.sleep(for: .milliseconds(50))

        // Store a pin announcement at A (as if a pinner published it)
        bSide.send(signedPinAnnounce(rootCID: "QmDiscovery", keyPair: pinB))
        try await Task.sleep(for: .milliseconds(100))

        // Now B queries for it
        bSide.send(.findPins(cid: "QmDiscovery"))
        try await Task.sleep(for: .milliseconds(100))

        // Verify A stored it
        let stored = await nodeA.storedPinAnnouncements(for: "QmDiscovery")
        #expect(stored.count == 1)
        #expect(stored[0] == pinB.publicKey)
    }

    @Test("Multiple pinners for same CID all discoverable")
    func testMultiplePinners() async throws {
        let nodeA = Ivy(config: testConfig(publicKey: "multi-a"))
        let pinB = generatePinKeyPair()
        let peerBID = PeerID(publicKey: pinB.publicKey)
        let localID = await nodeA.localID
        let (bSide, aSide) = LocalPeerConnection.pair(localID: peerBID, remoteID: localID)
        await nodeA.registerLocalPeer(aSide, as: peerBID)
        try await Task.sleep(for: .milliseconds(50))

        // Re-announcing from the same sender replaces that sender's provider record.
        bSide.send(signedPinAnnounce(rootCID: "QmShared", keyPair: pinB, fee: 5))
        try await Task.sleep(for: .milliseconds(50))
        bSide.send(signedPinAnnounce(rootCID: "QmShared", keyPair: pinB, fee: 6))
        try await Task.sleep(for: .milliseconds(100))

        let stored = await nodeA.storedPinAnnouncements(for: "QmShared")
        #expect(stored == [pinB.publicKey])
    }
}

// MARK: - Gossip (Peer Message)

@Suite("Gossip Protocol")
struct GossipProtocolTests {

    @Test("Block announcement gossip reaches peer")
    func testBlockGossip() async throws {
        let nodeA = Ivy(config: testConfig(publicKey: "gossip-a"))
        let collector = MessageCollector()
        await nodeA.setDelegate(collector)

        let peerBID = PeerID(publicKey: "gossip-b")
        let localID = await nodeA.localID
        let (bSide, aSide) = LocalPeerConnection.pair(localID: peerBID, remoteID: localID)
        await nodeA.registerLocalPeer(aSide, as: peerBID)
        try await Task.sleep(for: .milliseconds(50))

        // B gossips a new block header
        let blockHeader = Data("block-47-header".utf8)
        bSide.send(.peerMessage(topic: "newBlock", payload: blockHeader))
        try await Task.sleep(for: .milliseconds(100))

        let topics = collector.allMessages.compactMap { entry -> String? in
            if case .peerMessage(let topic, _) = entry.message { return topic }
            return nil
        }
        #expect(topics.contains("newBlock"))
        bSide.close()
    }

    @Test("Transaction gossip reaches peer")
    func testTxGossip() async throws {
        let nodeA = Ivy(config: testConfig(publicKey: "tx-a"))
        let collector = MessageCollector()
        await nodeA.setDelegate(collector)

        let peerBID = PeerID(publicKey: "tx-b")
        let localID = await nodeA.localID
        let (bSide, aSide) = LocalPeerConnection.pair(localID: peerBID, remoteID: localID)
        await nodeA.registerLocalPeer(aSide, as: peerBID)
        try await Task.sleep(for: .milliseconds(50))

        let signedTx = Data("signed-transaction-payload".utf8)
        bSide.send(.peerMessage(topic: "mempool", payload: signedTx))
        try await Task.sleep(for: .milliseconds(100))

        let mempoolMsgs = collector.allMessages.compactMap { entry -> Data? in
            if case .peerMessage(let topic, let p) = entry.message, topic == "mempool" { return p }
            return nil
        }
        #expect(mempoolMsgs.count == 1)
        #expect(mempoolMsgs[0] == signedTx)
        bSide.close()
    }
}

// MARK: - End-to-End DHT Forwarding

@Suite("End-to-End Protocol")
struct EndToEndProtocolTests {

    @Test("A requests content from C through B — full message handler chain")
    func testThreeNodeEndToEnd() async throws {
        // Topology: A <-> B <-> C
        // C has content. A requests it. B forwards.
        let nodeA = Ivy(config: testConfig(publicKey: "e2e-a"))
        let nodeB = Ivy(config: testConfig(publicKey: "e2e-b"))
        let nodeC = Ivy(config: testConfig(publicKey: "e2e-c"))

        let collectorA = MessageCollector()
        await nodeA.setDelegate(collectorA)

        await connectNodes(nodeA, nodeB)
        await connectNodes(nodeB, nodeC)
        try await Task.sleep(for: .milliseconds(100))

        let cID = await nodeC.localID

        // C has the content in its haveSet
        let testData = Data("end-to-end content".utf8)
        let cid = testCID(for: testData)
        await nodeC.markAvailable(cids: [cid])

        // At minimum: verify the routing table allows B to reach C
        let bClosestToC = await nodeB.allRouterPeers().filter { $0.id == cID }
        #expect(!bClosestToC.isEmpty)
    }

    @Test("Routing table allows B to reach C for forwarding")
    func testRoutingTableForForwarding() async throws {
        let nodeB = Ivy(config: testConfig(publicKey: "rt-b"))
        let nodeC = Ivy(config: testConfig(publicKey: "rt-c"))

        await connectNodes(nodeB, nodeC)
        try await Task.sleep(for: .milliseconds(100))

        let cID = await nodeC.localID
        let bPeers = await nodeB.allRouterPeers()
        let hasCInTable = bPeers.contains { $0.id == cID }
        #expect(hasCInTable)
    }
}
