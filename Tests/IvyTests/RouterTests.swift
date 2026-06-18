import Testing
import Foundation
@testable import Ivy
import Tally

@Suite("Router")
struct RouterTests {
    private func peerKeys(inBucket bucket: Int, localKey: String, count: Int, prefix: String) -> [String] {
        let localHash = Router.hash(localKey)
        var peers: [String] = []
        for i in 0..<10_000 {
            let key = "\(prefix)-\(i)"
            if Router.commonPrefixLength(localHash, Router.hash(key)) == bucket {
                peers.append(key)
            }
            if peers.count == count { break }
        }
        return peers
    }

    @Test("Common prefix length of identical hashes is 256")
    func testCPLIdentical() {
        let h = Router.hash("test")
        #expect(Router.commonPrefixLength(h, h) == 256)
    }

    @Test("Common prefix length of different hashes is less than 256")
    func testCPLDifferent() {
        let a = Router.hash("alice")
        let b = Router.hash("bob")
        let cpl = Router.commonPrefixLength(a, b)
        #expect(cpl < 256)
        #expect(cpl >= 0)
    }

    @Test("XOR distance is zero for identical hashes")
    func testXORDistanceIdentical() {
        let h = Router.hash("same")
        let dist = Router.xorDistance(h, h)
        #expect(dist.allSatisfy { $0 == 0 })
    }

    @Test("XOR distance is symmetric")
    func testXORSymmetric() {
        let a = Router.hash("x")
        let b = Router.hash("y")
        #expect(Router.xorDistance(a, b) == Router.xorDistance(b, a))
    }

    @Test("Add peer to routing table")
    func testAddPeer() {
        let tally = Tally()
        let router = Router(localID: PeerID(publicKey: "local"), k: 20)
        let ep = PeerEndpoint(publicKey: "remote", host: "1.2.3.4", port: 4001)
        router.addPeer(PeerID(publicKey: "remote"), endpoint: ep, tally: tally)
        #expect(router.peerCount() == 1)
    }

    @Test("Duplicate peer updates lastSeen")
    func testDuplicatePeer() {
        let tally = Tally()
        let router = Router(localID: PeerID(publicKey: "local"), k: 20)
        let ep = PeerEndpoint(publicKey: "remote", host: "1.2.3.4", port: 4001)
        router.addPeer(PeerID(publicKey: "remote"), endpoint: ep, tally: tally)
        router.addPeer(PeerID(publicKey: "remote"), endpoint: ep, tally: tally)
        #expect(router.peerCount() == 1)
    }

    @Test("Closest peers returns sorted by distance")
    func testClosestPeers() {
        let tally = Tally()
        let router = Router(localID: PeerID(publicKey: "local"), k: 20)
        for i in 0..<10 {
            let key = "peer-\(i)"
            let ep = PeerEndpoint(publicKey: key, host: "1.2.3.\(i)", port: 4001)
            router.addPeer(PeerID(publicKey: key), endpoint: ep, tally: tally)
        }
        let target = Router.hash("target")
        let closest = router.closestPeers(to: target, count: 3)
        #expect(closest.count == 3)
        let d0 = Router.xorDistance(closest[0].hash, target)
        let d1 = Router.xorDistance(closest[1].hash, target)
        let d2 = Router.xorDistance(closest[2].hash, target)
        #expect(d0 <= d1)
        #expect(d1 <= d2)
    }

    @Test("Full bucket keeps existing peers instead of reputation-evicting")
    func fullBucketKeepsExistingPeers() {
        let tally = Tally()
        let router = Router(localID: PeerID(publicKey: "local"), k: 2)

        var peers: [String] = []
        let localHash = Router.hash("local")
        for i in 0..<100 {
            let key = "candidate-\(i)"
            let cpl = Router.commonPrefixLength(localHash, Router.hash(key))
            if cpl == 0 {
                peers.append(key)
            }
            if peers.count >= 3 { break }
        }
        guard peers.count >= 3 else { return }

        for key in peers.prefix(2) {
            let ep = PeerEndpoint(publicKey: key, host: "1.2.3.4", port: 4001)
            router.addPeer(PeerID(publicKey: key), endpoint: ep, tally: tally)
        }
        #expect(router.peerCount() == 2)

        let goodPeer = peers[2]
        tally.recordReceived(peer: PeerID(publicKey: goodPeer), bytes: 100_000)
        for _ in 0..<10 { tally.recordSuccess(peer: PeerID(publicKey: goodPeer)) }
        tally.recordLatency(peer: PeerID(publicKey: goodPeer), microseconds: 1000)

        let ep = PeerEndpoint(publicKey: goodPeer, host: "5.6.7.8", port: 4001)
        router.addPeer(PeerID(publicKey: goodPeer), endpoint: ep, tally: tally)

        let keys = Set(router.allPeers().map { $0.id.publicKey })
        #expect(keys == Set(peers.prefix(2)))
        #expect(!keys.contains(goodPeer))
    }

    @Test("Removing a peer frees its bucket slot")
    func removePeerFreesBucketSlot() {
        let tally = Tally()
        let router = Router(localID: PeerID(publicKey: "local"), k: 2)

        var peers: [String] = []
        let localHash = Router.hash("local")
        for i in 0..<100 {
            let key = "removable-candidate-\(i)"
            let cpl = Router.commonPrefixLength(localHash, Router.hash(key))
            if cpl == 0 {
                peers.append(key)
            }
            if peers.count >= 3 { break }
        }
        guard peers.count >= 3 else { return }

        for key in peers.prefix(2) {
            router.addPeer(
                PeerID(publicKey: key),
                endpoint: PeerEndpoint(publicKey: key, host: "1.2.3.4", port: 4001),
                tally: tally
            )
        }
        router.removePeer(PeerID(publicKey: peers[0]))
        router.addPeer(
            PeerID(publicKey: peers[2]),
            endpoint: PeerEndpoint(publicKey: peers[2], host: "5.6.7.8", port: 4001),
            tally: tally
        )

        let keys = Set(router.allPeers().map { $0.id.publicKey })
        #expect(keys == Set([peers[1], peers[2]]))
    }

    @Test("All peers returns full list")
    func testAllPeers() {
        let tally = Tally()
        let router = Router(localID: PeerID(publicKey: "local"), k: 20)
        for i in 0..<5 {
            let key = "p\(i)"
            router.addPeer(PeerID(publicKey: key), endpoint: PeerEndpoint(publicKey: key, host: "h", port: 1), tally: tally)
        }
        #expect(router.allPeers().count == 5)
    }

    @Test("Bucket index is CPL with local")
    func testBucketIndex() {
        let router = Router(localID: PeerID(publicKey: "local"), k: 20)
        let idx = router.bucketIndex(for: "remote")
        let cpl = Router.commonPrefixLength(Router.hash("local"), Router.hash("remote"))
        #expect(idx == min(cpl, 255))
    }
}
