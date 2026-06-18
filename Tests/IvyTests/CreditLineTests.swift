import Testing
import Foundation
@testable import Ivy
@testable import Tally

@Suite("KeyDifficulty")
struct KeyDifficultyTests {

    @Test("Trailing zero bits computation")
    func testTrailingZeroBits() {
        let bits = KeyDifficulty.trailingZeroBits(of: "test-key")
        #expect(bits >= 0 && bits <= 256)
    }

    @Test("baseTrust returns 0 for low difficulty")
    func testBaseTrustLow() {
        let trust = KeyDifficulty.baseTrust(publicKey: "test-key", minDifficulty: 100, maxDifficulty: 200)
        #expect(trust == 0)
    }

    @Test("baseTrust returns 1.0 for maxDifficulty 0")
    func testBaseTrustMax() {
        let trust = KeyDifficulty.baseTrust(publicKey: "test-key", minDifficulty: 0, maxDifficulty: 1)
        // Any key with >= 1 trailing zero bit gets 1.0
        let bits = KeyDifficulty.trailingZeroBits(of: "test-key")
        if bits >= 1 {
            #expect(trust == 1.0)
        } else {
            #expect(trust == 0.0)
        }
    }

    @Test("baseTrust is monotonic with difficulty")
    func testBaseTrustMonotonic() {
        // Generate many keys and verify higher difficulty → higher baseTrust
        var results: [(String, Int, Double)] = []
        for i in 0..<100 {
            let key = "key-\(i)"
            let bits = KeyDifficulty.trailingZeroBits(of: key)
            let trust = KeyDifficulty.baseTrust(publicKey: key, minDifficulty: 0, maxDifficulty: 32)
            results.append((key, bits, trust))
        }
        let sorted = results.sorted { $0.1 < $1.1 }
        for i in 1..<sorted.count {
            #expect(sorted[i].2 >= sorted[i-1].2)
        }
    }
}

@Suite("CreditLine")
struct CreditLineTests {

    let peerA = PeerID(publicKey: "peer-a")
    let peerB = PeerID(publicKey: "peer-b")

    @Test("New credit line starts at zero balance")
    func testNewCreditLine() {
        let line = CreditLine(peerA: peerA, peerB: peerB, threshold: 50)
        #expect(line.balance == 0)
        #expect(line.sequence == 0)
        #expect(line.threshold == 50)
        #expect(line.successfulSettlements == 0)
        #expect(!line.needsSettlement)
    }

    @Test("Balance adjusts correctly")
    func testBalanceAdjustment() {
        var line = CreditLine(peerA: peerA, peerB: peerB, threshold: 50)
        line.adjustBalance(by: -10)
        #expect(line.balance == -10)
        #expect(line.sequence == 1)

        line.adjustBalance(by: 25)
        #expect(line.balance == 15)
        #expect(line.sequence == 2)
    }

    @Test("Settlement triggers when threshold exceeded")
    func testSettlementTrigger() {
        var line = CreditLine(peerA: peerA, peerB: peerB, threshold: 50)
        line.adjustBalance(by: -49)
        #expect(!line.needsSettlement)

        line.adjustBalance(by: -2)
        #expect(line.needsSettlement)
    }

    @Test("Settlement clears balance and grows threshold")
    func testSettlement() {
        var line = CreditLine(peerA: peerA, peerB: peerB, threshold: 50)
        line.adjustBalance(by: -60)
        #expect(line.needsSettlement)

        line.recordSettlement()
        #expect(line.balance == 0)
        #expect(line.successfulSettlements == 1)
        #expect(line.threshold >= 50)
    }

    @Test("Partial settlement reduces balance")
    func testPartialSettlement() {
        var line = CreditLine(peerA: peerA, peerB: peerB, threshold: 50)
        line.adjustBalance(by: -60)

        line.recordPartialSettlement(workValue: 30)
        #expect(line.balance == -30)
    }

    @Test("Missed settlement halves threshold")
    func testMissedSettlement() {
        var line = CreditLine(peerA: peerA, peerB: peerB, threshold: 100)
        line.recordMissedSettlement()
        #expect(line.threshold == 50)

        line.recordMissedSettlement()
        #expect(line.threshold == 25)
    }

    @Test("Available capacity decreases with balance")
    func testAvailableCapacity() {
        var line = CreditLine(peerA: peerA, peerB: peerB, threshold: 100)
        #expect(line.availableCapacity == 100)

        line.adjustBalance(by: -30)
        #expect(line.availableCapacity == 70)

        line.adjustBalance(by: -70)
        #expect(line.availableCapacity == 0)
    }

    @Test("initialThreshold from baseTrust")
    func testInitialThreshold() {
        let threshold = CreditLine.initialThreshold(baseTrust: 0.5, multiplier: 100)
        #expect(threshold == 50)

        let zero = CreditLine.initialThreshold(baseTrust: 0.0, multiplier: 100)
        #expect(zero == 0)

        let full = CreditLine.initialThreshold(baseTrust: 1.0, multiplier: 100)
        #expect(full == 100)
    }
}

@Suite("CreditLineLedger")
struct CreditLineLedgerTests {

    @Test("Establish credit line on connect")
    func testEstablish() async {
        let local = PeerID(publicKey: "local-peer")
        let remote = PeerID(publicKey: "remote-peer")
        let ledger = CreditLineLedger(localID: local)

        let line = await ledger.establish(with: remote)
        #expect(line.balance == 0)
        #expect(line.threshold >= 1)
    }

    @Test("Charge and earn adjust balance")
    func testChargeAndEarn() async {
        let local = PeerID(publicKey: "local-peer")
        let remote = PeerID(publicKey: "remote-peer")
        let ledger = CreditLineLedger(localID: local)

        _ = await ledger.establish(with: remote)
        let charged = await ledger.chargeForRelay(peer: remote, amount: 5)
        #expect(charged)

        let balance = await ledger.balance(with: remote)
        #expect(balance == -5)

        await ledger.earnFromRelay(peer: remote, amount: 3)
        let newBalance = await ledger.balance(with: remote)
        #expect(newBalance == -2)
    }

    @Test("Settlement clears debt")
    func testSettlement() async {
        let local = PeerID(publicKey: "local-peer")
        let remote = PeerID(publicKey: "remote-peer")
        let ledger = CreditLineLedger(localID: local, baseThresholdMultiplier: 10)

        _ = await ledger.establish(with: remote)
        _ = await ledger.chargeForRelay(peer: remote, amount: 15)

        let needs = await ledger.needsSettlement(peer: remote)
        #expect(needs)

        await ledger.recordSettlement(peer: remote)
        let balance = await ledger.balance(with: remote)
        #expect(balance == 0)
    }
}

@Suite("Economic Message Serialization")
struct EconomicMessageTests {

    @Test("findPins roundtrip")
    func testFindPinsRoundtrip() {
        let msg = Message.findPins(cid: "QmRoot123")
        let decoded = Message.deserialize(msg.serialize())
        if case .findPins(let cid) = decoded {
            #expect(cid == "QmRoot123")
        } else {
            Issue.record("Expected findPins")
        }
    }

    @Test("pins roundtrip")
    func testPinsRoundtrip() {
        let msg = Message.pins(cid: "QmRoot", providers: ["pk1", "pk2"])
        let decoded = Message.deserialize(msg.serialize())
        if case .pins(let cid, let providers) = decoded {
            #expect(cid == "QmRoot")
            #expect(providers.count == 2)
            #expect(providers[0] == "pk1")
            #expect(providers[1] == "pk2")
        } else {
            Issue.record("Expected pins")
        }
    }

    @Test("pinAnnounce roundtrip")
    func testPinAnnounceRoundtrip() {
        let sig = Data([1, 2, 3, 4])
        let msg = Message.pinAnnounce(rootCID: "QmRoot", publicKey: "myKey", expiry: 999999, signature: sig, fee: 50)
        let decoded = Message.deserialize(msg.serialize())
        if case .pinAnnounce(let root, let pk, let exp, let s, let fee) = decoded {
            #expect(root == "QmRoot")
            #expect(pk == "myKey")
            #expect(exp == 999999)
            #expect(s == sig)
            #expect(fee == 50)
        } else {
            Issue.record("Expected pinAnnounce")
        }
    }

    @Test("pinStored roundtrip")
    func testPinStoredRoundtrip() {
        let msg = Message.pinStored(rootCID: "QmStored")
        let decoded = Message.deserialize(msg.serialize())
        if case .pinStored(let root) = decoded {
            #expect(root == "QmStored")
        } else {
            Issue.record("Expected pinStored")
        }
    }

    @Test("deliveryAck roundtrip")
    func testDeliveryAckRoundtrip() {
        let msg = Message.deliveryAck(requestId: 12345)
        let decoded = Message.deserialize(msg.serialize())
        if case .deliveryAck(let rid) = decoded {
            #expect(rid == 12345)
        } else {
            Issue.record("Expected deliveryAck")
        }
    }

    @Test("peerMessage roundtrip")
    func testPeerMessageRoundtrip() {
        let payload = Data("hello world".utf8)
        let msg = Message.peerMessage(topic: "mempool", payload: payload)
        let decoded = Message.deserialize(msg.serialize())
        if case .peerMessage(let topic, let p) = decoded {
            #expect(topic == "mempool")
            #expect(p == payload)
        } else {
            Issue.record("Expected peerMessage")
        }
    }

    @Test("dhtForward roundtrip")
    func testDhtForwardRoundtrip() {
        let msg = Message.dhtForward(cid: "QmOld", ttl: 3)
        let decoded = Message.deserialize(msg.serialize())
        if case .dhtForward(let cid, let ttl) = decoded {
            #expect(cid == "QmOld")
            #expect(ttl == 3)
        } else {
            Issue.record("Expected dhtForward")
        }
    }

    @Test("findNode with fee roundtrip")
    func testFindNodeWithFeeRoundtrip() {
        let target = Data(repeating: 0xBB, count: 32)
        let msg = Message.findNode(target: target, fee: 25)
        let decoded = Message.deserialize(msg.serialize())
        if case .findNode(let t, let fee, _) = decoded {
            #expect(t == target)
            #expect(fee == 25)
        } else {
            Issue.record("Expected findNode with fee")
        }
    }

    @Test("findNode backward compatible (no fee)")
    func testFindNodeBackwardCompat() {
        let target = Data(repeating: 0xCC, count: 32)
        let msg = Message.findNode(target: target)
        let decoded = Message.deserialize(msg.serialize())
        if case .findNode(let t, let fee, _) = decoded {
            #expect(t == target)
            #expect(fee == 0)
        } else {
            Issue.record("Expected findNode")
        }
    }

    @Test("blocks multi-block roundtrip")
    func testBlocksRoundtrip() {
        let items: [(cid: String, data: Data)] = [
            (cid: "Qm-a", data: Data([1, 2, 3])),
            (cid: "Qm-b", data: Data([4, 5, 6])),
            (cid: "Qm-c", data: Data([7, 8, 9]))
        ]
        let msg = Message.blocks(rootCID: "Qm-root", items: items)
        let decoded = Message.deserialize(msg.serialize())
        if case .blocks(let root, let decoded_items) = decoded {
            #expect(root == "Qm-root")
            #expect(decoded_items.count == 3)
            #expect(decoded_items[0].cid == "Qm-a")
            #expect(decoded_items[1].data == Data([4, 5, 6]))
            #expect(decoded_items[2].cid == "Qm-c")
        } else {
            Issue.record("Expected blocks")
        }
    }

}
