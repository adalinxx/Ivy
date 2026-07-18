import Testing
@testable import Ivy
import Tally

@Suite("Router")
struct RouterTests {
    @Test("XOR closeness is lexicographic")
    func xorClosenessIsLexicographic() {
        let target: [UInt8] = [0x55, 0xaa]
        let nearer: [UInt8] = [0x55, 0xab]
        let farther: [UInt8] = [0x54, 0xaa]

        #expect(Router.isCloser(nearer, than: farther, to: target))
        #expect(!Router.isCloser(farther, than: nearer, to: target))
        #expect(!Router.isCloser(nearer, than: nearer, to: target))
    }

    @Test("Closest peers follow XOR distance order")
    func closestPeersFollowDistanceOrder() {
        var router = Router(localID: PeerID(publicKey: "local"), k: 20)
        for index in 0..<8 {
            let key = "peer-\(index)"
            router.addPeer(
                PeerID(publicKey: key),
                endpoint: PeerEndpoint(publicKey: key, host: "127.0.0.1", port: UInt16(index + 1)))
        }

        let target = Router.hash("target")
        let closest = router.closestPeers(to: target, count: 5)

        #expect(closest.count == 5)
        for (left, right) in zip(closest, closest.dropFirst()) {
            #expect(!Router.isCloser(right.hash, than: left.hash, to: target))
        }
    }

    @Test("A full bucket keeps its entries until one is removed")
    func bucketCapacityIsStable() {
        var router = Router(localID: PeerID(publicKey: "local"), k: 2)
        let keys = peerKeys(inSameBucketAs: "local", count: 3)

        for key in keys.prefix(2) {
            router.addPeer(PeerID(publicKey: key), endpoint: endpoint(for: key))
        }
        router.addPeer(PeerID(publicKey: keys[2]), endpoint: endpoint(for: keys[2]))
        #expect(Set(router.allPeers().map(\.id.publicKey)) == Set(keys.prefix(2)))

        router.removePeer(PeerID(publicKey: keys[0]))
        router.addPeer(PeerID(publicKey: keys[2]), endpoint: endpoint(for: keys[2]))
        #expect(Set(router.allPeers().map(\.id.publicKey)) == Set(keys.suffix(2)))
    }

    @Test("Rediscovery refreshes a peer endpoint")
    func rediscoveryRefreshesEndpoint() {
        var router = Router(localID: PeerID(publicKey: "local"), k: 20)
        let peer = PeerID(publicKey: "peer")
        router.addPeer(peer, endpoint: PeerEndpoint(
            publicKey: peer.publicKey, host: "127.0.0.1", port: 4001))
        router.addPeer(peer, endpoint: PeerEndpoint(
            publicKey: peer.publicKey, host: "127.0.0.2", port: 4002))

        #expect(router.allPeers().count == 1)
        #expect(router.allPeers().first?.endpoint.port == 4002)
    }
}

private func endpoint(for key: String) -> PeerEndpoint {
    PeerEndpoint(publicKey: key, host: "127.0.0.1", port: 4001)
}

private func peerKeys(inSameBucketAs localKey: String, count: Int) -> [String] {
    let localHash = Router.hash(localKey)
    var keys: [String] = []
    var bucket: Int?

    for index in 0..<10_000 {
        let key = "bucket-peer-\(index)"
        let candidateBucket = min(Router.commonPrefixLength(localHash, Router.hash(key)), 255)
        if bucket == nil || bucket == candidateBucket {
            bucket = candidateBucket
            keys.append(key)
        }
        if keys.count == count { return keys }
    }

    fatalError("Unable to find enough peers in one bucket")
}
