import Testing
import Foundation
import Crypto
@testable import Ivy
@testable import Tally

private func pinGateKeyPair() -> (publicKey: String, privateKey: Data) {
    let privateKey = Curve25519.Signing.PrivateKey()
    let publicKey = privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    return (publicKey, privateKey.rawRepresentation)
}

private func pinGateSignature(rootCID: String, keyPair: (publicKey: String, privateKey: Data), expiry: UInt64, fee: UInt64) -> Data {
    PinAnnouncementSignature.sign(
        rootCID: rootCID,
        publicKey: keyPair.publicKey,
        expiry: expiry,
        fee: fee,
        signingKey: keyPair.privateKey
    )!
}

private func cidWithBucket(_ bucket: Int, localKey: String, prefix: String) -> String {
    let localHash = Router.hash(localKey)
    for i in 0..<100_000 {
        let cid = "\(prefix)-\(i)"
        if Router.commonPrefixLength(localHash, Router.hash(cid)) == bucket {
            return cid
        }
    }
    fatalError("Unable to find CID in bucket \(bucket)")
}

private func peersCloserThanLocal(
    to targetHash: [UInt8],
    localKey: String,
    count: Int
) -> [String] {
    let localHash = Router.hash(localKey)
    var peers: [String] = []
    for i in 0..<500_000 {
        let key = "pin-gate-peer-\(i)"
        let hash = Router.hash(key)
        guard Router.isCloser(hash, than: localHash, to: targetHash) else { continue }
        peers.append(key)
        if peers.count == count { return peers }
    }
    fatalError("Unable to find closer peers")
}

private func peerInBucket(_ bucket: Int, localKey: String, excluding excluded: Set<String>) -> String {
    let localHash = Router.hash(localKey)
    for i in 0..<100_000 {
        let key = "pin-gate-deep-peer-\(i)"
        guard !excluded.contains(key) else { continue }
        if Router.commonPrefixLength(localHash, Router.hash(key)) == bucket {
            return key
        }
    }
    fatalError("Unable to find peer in bucket \(bucket)")
}

@Suite("Pin announcement closeness gate")
struct PinClosenessGateTests {
    @Test("Far pin announcement is rejected and near announcement is stored")
    func farPinRejectedNearPinAccepted() async {
        let localKey = "pin-gate-local"
        let k = 3
        let node = Ivy(config: IvyConfig(
            publicKey: localKey,
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            kBucketSize: k,
            enablePEX: false
        ))

        let farCID = cidWithBucket(0, localKey: localKey, prefix: "pin-gate-far")
        let farHash = Router.hash(farCID)
        let closerPeers = peersCloserThanLocal(
            to: farHash,
            localKey: localKey,
            count: k
        )
        let deepPeer = peerInBucket(1, localKey: localKey, excluding: Set(closerPeers))
        await node.addToRouter(
            PeerID(publicKey: deepPeer),
            endpoint: PeerEndpoint(publicKey: deepPeer, host: "10.4.0.254", port: 4001)
        )
        for key in closerPeers {
            await node.addToRouter(
                PeerID(publicKey: key),
                endpoint: PeerEndpoint(publicKey: key, host: "10.4.0.1", port: 4001)
            )
        }

        let pinner = pinGateKeyPair()
        let peer = PeerID(publicKey: pinner.publicKey)
        let expiry = UInt64(Date().timeIntervalSince1970) + 3600
        let fee: UInt64 = 5
        let farSignature = pinGateSignature(rootCID: farCID, keyPair: pinner, expiry: expiry, fee: fee)
        await node.handlePinAnnounce(
            rootCID: farCID,
            publicKey: pinner.publicKey,
            expiry: expiry,
            signature: farSignature,
            fee: fee,
            from: peer
        )

        #expect(await node.storedPinAnnouncements(for: farCID).isEmpty)
        let farLedger = await node.tally.peerLedger(for: peer)
        #expect((farLedger?.failureCount.value ?? 0) == 0)

        let nearCID = cidWithBucket(1, localKey: localKey, prefix: "pin-gate-near")
        let nearSignature = pinGateSignature(rootCID: nearCID, keyPair: pinner, expiry: expiry, fee: fee)
        await node.handlePinAnnounce(
            rootCID: nearCID,
            publicKey: pinner.publicKey,
            expiry: expiry,
            signature: nearSignature,
            fee: fee,
            from: peer
        )

        #expect(await node.storedPinAnnouncements(for: nearCID) == [pinner.publicKey])
    }
}
