import Testing
import Foundation
import Crypto
@testable import Ivy
@testable import Tally

/// Helper to create a minimal IvyConfig for testing
func testConfig(publicKey: String, port: UInt16 = 0) -> IvyConfig {
    IvyConfig(
        publicKey: publicKey,
        listenPort: port,
        bootstrapPeers: [],
        enableLocalDiscovery: false,
        healthConfig: PeerHealthConfig(keepaliveInterval: .seconds(999), staleTimeout: .seconds(999), maxMissedPongs: 99, enabled: false),
        enablePEX: false
    )
}

/// Collects messages received by a delegate
final class MessageCollector: IvyDelegate, @unchecked Sendable {
    private var _messages: [(message: Message, from: PeerID)] = []

    func ivy(_ ivy: Ivy, didReceiveMessage message: Message, from peer: PeerID) {
        _messages.append((message: message, from: peer))
    }

    var allMessages: [(message: Message, from: PeerID)] { _messages }
}

@Suite("Protocol Integration")
struct ProtocolIntegrationTests {
    private func generateKeyPair() -> (publicKey: String, privateKey: Data) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let pubHex = privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        return (pubHex, privateKey.rawRepresentation)
    }

    private func pinSignature(rootCID: String, publicKey: String, expiry: UInt64, fee: UInt64, privateKey: Data) -> Data {
        PinAnnouncementSignature.sign(rootCID: rootCID, publicKey: publicKey, expiry: expiry, fee: fee, signingKey: privateKey)!
    }

    @Test("Pin announcement signature binds all mutable fields")
    func testPinAnnouncementSignatureBindsFields() {
        let (publicKey, privateKey) = generateKeyPair()
        let expiry: UInt64 = 1_700_000_000
        let signature = pinSignature(rootCID: "QmRoot", publicKey: publicKey, expiry: expiry, fee: 5, privateKey: privateKey)

        #expect(PinAnnouncementSignature.verify(rootCID: "QmRoot", publicKey: publicKey, expiry: expiry, fee: 5, signature: signature))
        #expect(!PinAnnouncementSignature.verify(rootCID: "QmOther", publicKey: publicKey, expiry: expiry, fee: 5, signature: signature))
        #expect(!PinAnnouncementSignature.verify(rootCID: "QmRoot", publicKey: String(repeating: "0", count: 64), expiry: expiry, fee: 5, signature: signature))
        #expect(!PinAnnouncementSignature.verify(rootCID: "QmRoot", publicKey: publicKey, expiry: expiry + 1, fee: 5, signature: signature))
        #expect(!PinAnnouncementSignature.verify(rootCID: "QmRoot", publicKey: publicKey, expiry: expiry, fee: 6, signature: signature))

        var tamperedSignature = signature
        tamperedSignature[0] ^= 0x01
        #expect(!PinAnnouncementSignature.verify(rootCID: "QmRoot", publicKey: publicKey, expiry: expiry, fee: 5, signature: tamperedSignature))
    }

    @Test("Pin announcement expiry is bounded")
    func testPinAnnouncementExpiryBounded() {
        let now: UInt64 = 1_700_000_000
        #expect(!PinAnnouncementSignature.isExpiryValid(now, now: now))
        #expect(PinAnnouncementSignature.isExpiryValid(now + 1, now: now))
        #expect(PinAnnouncementSignature.isExpiryValid(now + PinAnnouncementSignature.maxTTLSeconds, now: now))
        #expect(!PinAnnouncementSignature.isExpiryValid(now + PinAnnouncementSignature.maxTTLSeconds + 1, now: now))
        #expect(!PinAnnouncementSignature.isExpiryValid(UInt64.max, now: now))
    }

    @Test("Pin announcement stored and discoverable")
    func testPinAnnouncementStored() async throws {
        let config = testConfig(publicKey: "node-a")
        let nodeA = Ivy(config: config)
        let (pubB, privB) = generateKeyPair()
        let peerBID = PeerID(publicKey: pubB)
        let localID = await nodeA.localID
        let (bSide, aSide) = LocalPeerConnection.pair(localID: peerBID, remoteID: localID)
        await nodeA.registerLocalPeer(aSide, as: peerBID)
        try await Task.sleep(for: .milliseconds(50))

        // B publishes a pin announcement through A
        let expiry = UInt64(Date().timeIntervalSince1970) + 3600
        let fee: UInt64 = 5
        let signature = pinSignature(rootCID: "QmRoot", publicKey: pubB, expiry: expiry, fee: fee, privateKey: privB)
        bSide.send(.pinAnnounce(rootCID: "QmRoot", publicKey: pubB, expiry: expiry, signature: signature, fee: fee))
        try await Task.sleep(for: .milliseconds(100))

        let stored = await nodeA.storedPinAnnouncements(for: "QmRoot")
        #expect(stored.count == 1)
        #expect(stored[0] == pubB)
        bSide.close()
    }

    @Test("Unsigned pin announcement rejected")
    func testUnsignedPinAnnouncementRejected() async throws {
        let nodeA = Ivy(config: testConfig(publicKey: "node-a"))
        let (pubB, _) = generateKeyPair()
        let peerBID = PeerID(publicKey: pubB)
        let localID = await nodeA.localID
        let (bSide, aSide) = LocalPeerConnection.pair(localID: peerBID, remoteID: localID)
        await nodeA.registerLocalPeer(aSide, as: peerBID)
        try await Task.sleep(for: .milliseconds(50))

        bSide.send(.pinAnnounce(rootCID: "QmRoot", publicKey: pubB, expiry: UInt64(Date().timeIntervalSince1970) + 3600, signature: Data(), fee: 5))
        try await Task.sleep(for: .milliseconds(100))

        let stored = await nodeA.storedPinAnnouncements(for: "QmRoot")
        #expect(stored.isEmpty)
        bSide.close()
    }

    @Test("Third-party pin announcement rejected")
    func testThirdPartyPinAnnouncementRejected() async throws {
        let nodeA = Ivy(config: testConfig(publicKey: "node-a"))
        let (pubB, _) = generateKeyPair()
        let (pubVictim, victimPriv) = generateKeyPair()
        let peerBID = PeerID(publicKey: pubB)
        let localID = await nodeA.localID
        let (bSide, aSide) = LocalPeerConnection.pair(localID: peerBID, remoteID: localID)
        await nodeA.registerLocalPeer(aSide, as: peerBID)
        try await Task.sleep(for: .milliseconds(50))

        let expiry = UInt64(Date().timeIntervalSince1970) + 3600
        let fee: UInt64 = 5
        let signature = pinSignature(rootCID: "QmRoot", publicKey: pubVictim, expiry: expiry, fee: fee, privateKey: victimPriv)
        bSide.send(.pinAnnounce(rootCID: "QmRoot", publicKey: pubVictim, expiry: expiry, signature: signature, fee: fee))
        try await Task.sleep(for: .milliseconds(100))

        let stored = await nodeA.storedPinAnnouncements(for: "QmRoot")
        #expect(stored.isEmpty)
        bSide.close()
    }

    @Test("Expired and far-future pin announcements rejected")
    func testOutOfWindowPinAnnouncementsRejected() async throws {
        let nodeA = Ivy(config: testConfig(publicKey: "node-a"))
        let (pubB, privB) = generateKeyPair()
        let peerBID = PeerID(publicKey: pubB)
        let localID = await nodeA.localID
        let (bSide, aSide) = LocalPeerConnection.pair(localID: peerBID, remoteID: localID)
        await nodeA.registerLocalPeer(aSide, as: peerBID)
        try await Task.sleep(for: .milliseconds(50))

        let now = UInt64(Date().timeIntervalSince1970)
        for (rootCID, expiry) in [
            ("QmExpiredPin", now),
            ("QmFarFuturePin", now + PinAnnouncementSignature.maxTTLSeconds + 3600)
        ] {
            let signature = pinSignature(rootCID: rootCID, publicKey: pubB, expiry: expiry, fee: 5, privateKey: privB)
            bSide.send(.pinAnnounce(rootCID: rootCID, publicKey: pubB, expiry: expiry, signature: signature, fee: 5))
        }
        try await Task.sleep(for: .milliseconds(100))

        #expect(await nodeA.storedPinAnnouncements(for: "QmExpiredPin").isEmpty)
        #expect(await nodeA.storedPinAnnouncements(for: "QmFarFuturePin").isEmpty)
        bSide.close()
    }

    @Test("Peer message delivered to delegate")
    func testPeerMessageDelivered() async throws {
        let config = testConfig(publicKey: "node-a")
        let nodeA = Ivy(config: config)
        let collector = MessageCollector()
        await nodeA.setDelegate(collector)

        let peerBID = PeerID(publicKey: "node-b")
        let localID = await nodeA.localID
        let (bSide, aSide) = LocalPeerConnection.pair(localID: peerBID, remoteID: localID)
        await nodeA.registerLocalPeer(aSide, as: peerBID)
        try await Task.sleep(for: .milliseconds(50))

        let payload = Data("new block header".utf8)
        bSide.send(.peerMessage(topic: "newBlock", payload: payload))
        try await Task.sleep(for: .milliseconds(100))

        let peerMsgs = collector.allMessages.compactMap { entry -> String? in
            if case .peerMessage(let topic, _) = entry.message { return topic }
            return nil
        }
        #expect(peerMsgs.contains("newBlock"))
        bSide.close()
    }
}

// Helper extension to set delegate/dataSource from async context
extension Ivy {
    func setDelegate(_ delegate: IvyDelegate?) {
        self.delegate = delegate
    }

    func setDataSource(_ dataSource: IvyDataSource?) {
        self.dataSource = dataSource
    }
}

/// Dict-backed data source for tests
final class DictDataSource: IvyDataSource, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()

    subscript(cid: String) -> Data? {
        get { lock.withLock { storage[cid] } }
        set { lock.withLock { storage[cid] = newValue } }
    }

    func data(for cid: String) async -> Data? {
        lock.withLock { storage[cid] }
    }

    func volumeData(for rootCID: String, cids: [String]) async -> [(cid: String, data: Data)] {
        lock.withLock {
            cids.compactMap { cid in
                if let d = storage[cid] { return (cid: cid, data: d) }
                return nil
            }
        }
    }

    func hasVolume(rootCID: String) async -> Bool {
        lock.withLock { storage[rootCID] != nil }
    }
}
