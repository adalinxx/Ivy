import Testing
import Foundation
import Crypto
@testable import Ivy
@testable import Tally

@Suite("Public address discovery")
struct PublicAddressDiscoveryTests {

    private func generateKeyPair() -> (publicKey: String, privateKey: Data) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let pubHex = privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        return (pubHex, privateKey.rawRepresentation)
    }

    private func makeConfig(publicKey: String) -> IvyConfig {
        IvyConfig(
            publicKey: publicKey,
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(999),
                staleTimeout: .seconds(999),
                maxMissedPongs: 99,
                enabled: false
            ),
            enablePEX: false
        )
    }

    private func signIdentify(publicKey: String, observedHost: String, privateKey: Data) -> Data {
        let material = Data(publicKey.utf8) + Data(observedHost.utf8)
        guard let signingKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateKey),
              let signature = try? signingKey.signature(for: material) else {
            return Data()
        }
        return signature
    }

    @Test("Peer observed-address claims do not publish a public address")
    func peerObservedAddressClaimsDoNotPublishPublicAddress() async throws {
        let (nodePublicKey, _) = generateKeyPair()
        let node = Ivy(config: makeConfig(publicKey: nodePublicKey))
        let localID = await node.localID

        let observedHost = "203.0.113.77"
        let observedPort: UInt16 = 4001

        for _ in 0..<2 {
            let (peerPublicKey, peerPrivateKey) = generateKeyPair()
            let peerID = PeerID(publicKey: peerPublicKey)
            let (peerSide, nodeSide) = LocalPeerConnection.pair(localID: peerID, remoteID: localID)
            await node.registerLocalPeer(nodeSide, as: peerID)
            try await Task.sleep(for: .milliseconds(20))

            peerSide.send(.identify(
                publicKey: peerPublicKey,
                observedHost: observedHost,
                observedPort: observedPort,
                listenAddrs: [],
                chainPorts: [:],
                signature: signIdentify(publicKey: peerPublicKey, observedHost: observedHost, privateKey: peerPrivateKey)
            ))
            try await Task.sleep(for: .milliseconds(50))
            peerSide.close()
        }

        #expect(await node.publicAddress == nil)
    }
}
