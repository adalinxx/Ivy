import Testing
import Foundation
@testable import Ivy
import Tally

@Suite("BoundedSet")
struct BoundedSetTests {

    @Test("Respects capacity")
    func testCapacity() {
        var set = BoundedSet<Int>(capacity: 10)
        for i in 0..<20 {
            set.insert(i)
        }
        #expect(set.count <= 10)
    }

    @Test("Contains works after eviction")
    func testContainsAfterEviction() {
        var set = BoundedSet<Int>(capacity: 5)
        for i in 0..<5 { set.insert(i) }
        #expect(set.contains(4))
        for i in 5..<10 { set.insert(i) }
        #expect(set.contains(9))
        #expect(set.count <= 5)
    }

    @Test("Duplicate insert returns false")
    func testDuplicateInsert() {
        var set = BoundedSet<String>(capacity: 10)
        let first = set.insert("hello")
        let second = set.insert("hello")
        #expect(first == true)
        #expect(second == false)
        #expect(set.count == 1)
    }

    @Test("Empty set")
    func testEmpty() {
        let set = BoundedSet<Int>(capacity: 100)
        #expect(set.isEmpty)
        #expect(set.count == 0)
    }

    @Test("RemoveAll clears")
    func testRemoveAll() {
        var set = BoundedSet<Int>(capacity: 10)
        for i in 0..<5 { set.insert(i) }
        set.removeAll()
        #expect(set.isEmpty)
    }

    @Test("Eviction removes oldest entries")
    func testEvictsOldest() {
        var set = BoundedSet<Int>(capacity: 4)
        set.insert(1)
        set.insert(2)
        set.insert(3)
        set.insert(4)
        set.insert(5)
        #expect(set.contains(5))
        #expect(!set.contains(1))
    }

    @Test("Remove drops exact member")
    func testRemove() {
        var set = BoundedSet<String>(capacity: 4)
        set.insert("a")
        set.insert("b")
        let removed = set.remove("a")
        #expect(removed)
        #expect(!set.contains("a"))
        #expect(set.contains("b"))
    }

    @Test("Bulk arbitrary removals and refill stay correct")
    func testBulkRemoveAndRefill() {
        let capacity = 10_000
        var set = BoundedSet<Int>(capacity: capacity)
        for i in 0..<capacity {
            set.insert(i)
        }
        for i in stride(from: 0, to: capacity, by: 2) {
            let removed = set.remove(i)
            #expect(removed)
        }
        for i in capacity..<(capacity + capacity / 2) {
            set.insert(i)
        }

        #expect(set.count == capacity)
        #expect(!set.contains(0))
        #expect(set.contains(1))
        #expect(set.contains(capacity + capacity / 2 - 1))
    }
}

@Suite("BoundedDictionary")
struct BoundedDictionaryTests {

    @Test("Respects capacity")
    func testCapacity() {
        var dict = BoundedDictionary<Int, String>(capacity: 5)
        for i in 0..<10 {
            dict[i] = "value-\(i)"
        }
        #expect(dict.count <= 5)
    }

    @Test("Get and set")
    func testGetSet() {
        var dict = BoundedDictionary<String, Int>(capacity: 10)
        dict["a"] = 1
        dict["b"] = 2
        #expect(dict["a"] == 1)
        #expect(dict["b"] == 2)
        #expect(dict["c"] == nil)
    }

    @Test("Update existing key doesn't count as new")
    func testUpdateExisting() {
        var dict = BoundedDictionary<String, Int>(capacity: 3)
        dict["a"] = 1
        dict["b"] = 2
        dict["c"] = 3
        dict["a"] = 100
        #expect(dict.count == 3)
        #expect(dict["a"] == 100)
    }

    @Test("Remove value")
    func testRemoveValue() {
        var dict = BoundedDictionary<String, Int>(capacity: 10)
        dict["a"] = 1
        let removed = dict.removeValue(forKey: "a")
        #expect(removed == 1)
        #expect(dict["a"] == nil)
    }

    @Test("Set to nil removes")
    func testSetNilRemoves() {
        var dict = BoundedDictionary<String, Int>(capacity: 10)
        dict["a"] = 1
        dict["a"] = nil
        #expect(dict["a"] == nil)
        #expect(dict.count == 0)
    }

    @Test("RemoveAll where predicate")
    func testRemoveAllWhere() {
        var dict = BoundedDictionary<Int, Int>(capacity: 100)
        for i in 0..<10 { dict[i] = i }
        dict.removeAll { key, _ in key % 2 == 0 }
        #expect(dict.count == 5)
        #expect(dict[1] == 1)
        #expect(dict[0] == nil)
    }

    @Test("Max function works")
    func testMax() {
        var dict = BoundedDictionary<String, Int>(capacity: 10)
        dict["a"] = 1
        dict["b"] = 5
        dict["c"] = 3
        let best = dict.max(by: { $0.value < $1.value })
        #expect(best?.key == "b")
        #expect(best?.value == 5)
    }

    @Test("Overflow evicts oldest entries")
    func testOverflowEvictsOldest() {
        var dict = BoundedDictionary<Int, String>(capacity: 4)
        dict[1] = "one"
        dict[2] = "two"
        dict[3] = "three"
        dict[4] = "four"
        dict[5] = "five"

        #expect(dict[1] == nil)
        #expect(dict[5] == "five")
        #expect(dict.count <= 4)
    }

    @Test("Bulk arbitrary removals and refill stay correct")
    func testBulkRemoveAndRefill() {
        let capacity = 10_000
        var dict = BoundedDictionary<Int, Int>(capacity: capacity)
        for i in 0..<capacity {
            dict[i] = i
        }
        for i in stride(from: 0, to: capacity, by: 2) {
            #expect(dict.removeValue(forKey: i) == i)
        }
        for i in capacity..<(capacity + capacity / 2) {
            dict[i] = i
        }

        #expect(dict.count == capacity)
        #expect(dict[0] == nil)
        #expect(dict[1] == 1)
        #expect(dict[capacity + capacity / 2 - 1] == capacity + capacity / 2 - 1)
    }
}

@Suite("InventorySet")
struct InventorySetTests {

    @Test("Contains only exact bounded entries")
    func testExactBoundedMembership() {
        var inventory = InventorySet(capacity: 4)
        for i in 0..<10 {
            inventory.insert("cid-\(i)")
        }

        #expect(inventory.count <= 4)
        #expect(inventory.contains("cid-9"))
        #expect(!inventory.contains("cid-0"))
    }

    @Test("Remove clears advertised availability")
    func testRemove() {
        var inventory = InventorySet(capacity: 4)
        inventory.insert("cid")
        let removed = inventory.remove("cid")
        #expect(removed)
        #expect(!inventory.contains("cid"))
    }

}

@Suite("Message Validation")
struct MessageValidationTests {

    @Test("Oversized string rejected")
    func testOversizedString() {
        var buf = Data()
        buf.appendUInt8(16) // dhtForward tag
        let longString = String(repeating: "x", count: Int(MessageLimits.maxStringLength) + 1)
        let bytes = Data(longString.utf8)
        buf.appendUInt16(UInt16(bytes.count))
        buf.append(bytes)
        let msg = Message.deserialize(buf)
        #expect(msg == nil)
    }

    @Test("Neighbors count capped")
    func testNeighborsCountCapped() {
        var buf = Data()
        buf.appendUInt8(6)
        buf.appendUInt16(UInt16(MessageLimits.maxNeighborCount) + 1)
        let msg = Message.deserialize(buf)
        #expect(msg == nil)
    }

    @Test("Valid neighbors within limit passes")
    func testValidNeighborsPass() {
        let peers = (0..<3).map { PeerEndpoint(publicKey: "k\($0)", host: "1.2.3.4", port: UInt16($0 + 1000)) }
        let msg = Message.neighbors(peers)
        let decoded = Message.deserialize(msg.serialize())
        if case .neighbors(let p, _) = decoded {
            #expect(p.count == 3)
        } else {
            Issue.record("Expected neighbors")
        }
    }

    @Test("CompactBlock txCIDs capped")
    func testCompactBlockCapped() {
        var buf = Data()
        buf.appendUInt8(22)
        buf.appendUInt32(16)
        buf.append(Data(repeating: 0, count: 16))
        let hcid = Data("h".utf8)
        buf.appendUInt16(UInt16(hcid.count))
        buf.append(hcid)
        buf.appendUInt16(UInt16(MessageLimits.maxTxCIDCount) + 1)
        let msg = Message.deserialize(buf)
        #expect(msg == nil)
    }

    @Test("Oversized outbound counts are rejected")
    func testOversizedOutboundCountsRejected() {
        let peer = PeerEndpoint(publicKey: "pk", host: "127.0.0.1", port: 4001)
        let peers = Array(repeating: peer, count: Int(MessageLimits.maxNeighborCount) + 1)
        #expect(Message.neighbors(peers, nonce: 1).serialize().isEmpty)

        let cids = Array(repeating: "cid", count: Int(UInt16.max) + 1)
        #expect(Message.want(rootCIDs: cids).serialize().isEmpty)

        let items = Array(
            repeating: (cid: "cid", data: Data()),
            count: Int(MessageLimits.maxTransactionCount) + 1
        )
        #expect(Message.blocks(rootCID: "root", items: items).serialize().isEmpty)
        #expect(Message.pushVolume(rootCID: "root", items: items).serialize().isEmpty)
    }

    @Test("Oversized outbound fields are rejected")
    func testOversizedOutboundFieldsRejected() {
        let longString = String(repeating: "x", count: Int(MessageLimits.maxStringLength) + 1)
        #expect(Message.dontHave(cid: longString).serialize().isEmpty)

        let largePayload = Data(repeating: 0, count: Int(IvyConfig.defaultMaxFrameSize) + 1)
        #expect(Message.block(cid: "cid", data: largePayload).serialize().isEmpty)
        #expect(Message.frame(.block(cid: "cid", data: largePayload)).isEmpty)
    }

    @Test("Frame size defaults and can be raised per message")
    func testFrameSizeDefaultsAndCanBeRaisedPerMessage() {
        #expect(IvyConfig.defaultMaxFrameSize == 4 * 1024 * 1024)
        let raisedFrameSize = IvyConfig.defaultMaxFrameSize + 8_192
        let payload = Data(repeating: 0xAB, count: Int(IvyConfig.defaultMaxFrameSize) + 512)
        let message = Message.block(cid: "cid", data: payload)

        #expect(message.serialize().isEmpty)
        let encoded = message.serialize(maxFrameSize: raisedFrameSize)
        #expect(!encoded.isEmpty)
        #expect(Message.deserialize(encoded) == nil)

        if case .block(let cid, let data) = Message.deserialize(encoded, maxDataPayload: raisedFrameSize) {
            #expect(cid == "cid")
            #expect(data.count == payload.count)
        } else {
            Issue.record("Expected raised-cap block payload to round-trip")
        }
    }
}

@Suite("Inbound Buffers")
struct InboundBufferTests {

    @Test("Local peer inbound stream is bounded newest")
    func testLocalPeerInboundStreamIsBoundedNewest() async {
        let (sender, receiver) = LocalPeerConnection.pair(
            localID: PeerID(publicKey: "sender"),
            remoteID: PeerID(publicKey: "receiver")
        )

        for i in 0..<(LocalPeerConnection.inboundBufferLimit + 44) {
            sender.send(.ping(nonce: UInt64(i)))
        }
        sender.close()

        var nonces: [UInt64] = []
        for await message in receiver.messages {
            if case .ping(let nonce) = message {
                nonces.append(nonce)
            }
        }

        #expect(nonces.count == LocalPeerConnection.inboundBufferLimit)
        #expect(nonces.first == 44)
        #expect(nonces.last == UInt64(LocalPeerConnection.inboundBufferLimit + 43))
    }
}

@Suite("PeerHealthMonitor")
struct PeerHealthMonitorTests {

    @Test("Track and check peer")
    func testTrackPeer() async {
        let tally = Tally(config: .default)
        let monitor = PeerHealthMonitor(
            config: PeerHealthConfig(keepaliveInterval: .seconds(10), staleTimeout: .seconds(30)),
            tally: tally,
            onStale: { _ in }
        )

        let peer = PeerID(publicKey: "monitor-test-peer")
        await monitor.trackPeer(peer)

        let isStale = await monitor.isStale(peer)
        #expect(!isStale)
    }

    @Test("Untracked peer is stale")
    func testUntrackedIsStale() async {
        let tally = Tally(config: .default)
        let monitor = PeerHealthMonitor(
            config: .default,
            tally: tally,
            onStale: { _ in }
        )

        let peer = PeerID(publicKey: "unknown-peer")
        let isStale = await monitor.isStale(peer)
        #expect(isStale)
    }

    @Test("Record activity refreshes timestamp")
    func testRecordActivity() async {
        let tally = Tally(config: .default)
        let monitor = PeerHealthMonitor(
            config: .default,
            tally: tally,
            onStale: { _ in }
        )

        let peer = PeerID(publicKey: "active-peer")
        await monitor.trackPeer(peer)
        await monitor.recordActivity(from: peer)

        let isStale = await monitor.isStale(peer)
        #expect(!isStale)
    }

    @Test("Remove peer")
    func testRemovePeer() async {
        let tally = Tally(config: .default)
        let monitor = PeerHealthMonitor(
            config: .default,
            tally: tally,
            onStale: { _ in }
        )

        let peer = PeerID(publicKey: "removable-peer")
        await monitor.trackPeer(peer)
        await monitor.removePeer(peer)

        let count = await monitor.trackedPeerCount
        #expect(count == 0)
    }

    @Test("Tracked peer count")
    func testTrackedCount() async {
        let tally = Tally(config: .default)
        let monitor = PeerHealthMonitor(
            config: .default,
            tally: tally,
            onStale: { _ in }
        )

        for i in 0..<5 {
            await monitor.trackPeer(PeerID(publicKey: "p-\(i)"))
        }
        let count = await monitor.trackedPeerCount
        #expect(count == 5)
    }
}

@Suite("IvyLogger")
struct IvyLoggerTests {

    @Test("NullLogger does not crash")
    func testNullLogger() {
        let logger = NullLogger()
        logger.debug("test")
        logger.info("test")
        logger.warning("test")
        logger.error("test")
    }

    @Test("LogLevel ordering")
    func testLogLevelOrdering() {
        #expect(IvyLogLevel.debug < IvyLogLevel.info)
        #expect(IvyLogLevel.info < IvyLogLevel.warning)
        #expect(IvyLogLevel.warning < IvyLogLevel.error)
    }
}
