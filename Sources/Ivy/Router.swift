import Crypto
import Foundation
import Tally

struct Router: Sendable {
    let localHash: [UInt8]
    private let k: Int
    private var buckets: [[BucketEntry]] = Array(repeating: [], count: 256)

    init(localID: PeerID, k: Int = 20) {
        localHash = Self.hash(localID.publicKey)
        self.k = k
    }

    struct BucketEntry: Sendable {
        let id: PeerID
        let hash: [UInt8]
        var endpoint: PeerEndpoint
    }

    mutating func addPeer(_ id: PeerID, endpoint: PeerEndpoint) {
        let peerHash = Self.hash(id.publicKey)
        let index = min(Self.commonPrefixLength(localHash, peerHash), 255)
        if let existing = buckets[index].firstIndex(where: { $0.id == id }) {
            buckets[index][existing].endpoint = endpoint
        } else if buckets[index].count < k {
            buckets[index].append(BucketEntry(id: id, hash: peerHash, endpoint: endpoint))
        }
    }

    mutating func removePeer(_ id: PeerID) {
        let index = min(Self.commonPrefixLength(localHash, Self.hash(id.publicKey)), 255)
        buckets[index].removeAll { $0.id == id }
    }

    func closestPeers(to target: [UInt8], count: Int) -> [BucketEntry] {
        buckets.flatMap { $0 }
            .sorted { Self.isCloser($0.hash, than: $1.hash, to: target) }
            .prefix(count)
            .map { $0 }
    }

    func allPeers() -> [BucketEntry] {
        buckets.flatMap { $0 }
    }

    static func hash(_ key: String) -> [UInt8] {
        Array(SHA256.hash(data: Data(key.utf8)))
    }

    static func commonPrefixLength(_ a: [UInt8], _ b: [UInt8]) -> Int {
        var length = 0
        for (x, y) in zip(a, b) {
            let difference = x ^ y
            if difference == 0 {
                length += 8
            } else {
                return length + difference.leadingZeroBitCount
            }
        }
        return length
    }

    static func isCloser(_ a: [UInt8], than b: [UInt8], to target: [UInt8]) -> Bool {
        for index in 0..<min(a.count, min(b.count, target.count)) {
            let aDistance = a[index] ^ target[index]
            let bDistance = b[index] ^ target[index]
            if aDistance != bDistance { return aDistance < bDistance }
        }
        return false
    }
}
