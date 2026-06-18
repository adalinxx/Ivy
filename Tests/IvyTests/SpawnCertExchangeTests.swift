import Testing
import Foundation
import Crypto
@testable import Ivy
import Tally

/// step 2a: the `spawnCertPresentation` message transports a peer's
/// spawn-cert chain right after identify. Ivy is transport only — the receiver
/// verifies the chain against its own trustedRoot. These tests cover the wire
/// round-trip, bounds, and that transport preserves verifiability.
@Suite("SpawnCertExchange")
struct SpawnCertExchangeTests {
    private func keyPair(_ seed: UInt8) -> (publicKey: String, privateKey: Data) {
        let priv = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: seed, count: 32))
        let pubHex = priv.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        return (publicKey: pubHex, privateKey: priv.rawRepresentation)
    }

    /// root → a → b, scopes nesting strictly deeper.
    private func depth2Chain() -> (chain: [SpawnCertificate], root: String, leaf: PeerID) {
        let root = keyPair(0x21), a = keyPair(0x22), b = keyPair(0x23)
        let chain = [
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: ["Nexus", "a"], issuerKeyPair: root)!,
            SpawnCertificate.issue(childPublicKey: b.publicKey, chainPath: ["Nexus", "a", "b"], issuerKeyPair: a)!,
        ]
        return (chain, root.publicKey, PeerID(publicKey: b.publicKey))
    }

    @Test("spawnCertPresentation round-trips and preserves verifiability")
    func roundTripPreservesVerification() {
        let (chain, root, leaf) = depth2Chain()
        let wire = Message.spawnCertPresentation(chain: chain).serialize()
        #expect(!wire.isEmpty)
        guard case .spawnCertPresentation(let decoded)? = Message.deserialize(wire) else {
            Issue.record("expected spawnCertPresentation"); return
        }
        #expect(decoded == chain)
        // Transport preserved the chain well enough to still verify + bound scope.
        #expect(SpawnCertificateChain.verify(chain: decoded, leaf: leaf, trustedRoot: root))
        #expect(SpawnCertificateChain.verifiedScope(chain: decoded, leaf: leaf, trustedRoot: root) == ["Nexus", "a", "b"])
    }

    @Test("empty chain round-trips to empty (clears trust)")
    func emptyChainRoundTrips() {
        let wire = Message.spawnCertPresentation(chain: []).serialize()
        #expect(!wire.isEmpty)
        guard case .spawnCertPresentation(let decoded)? = Message.deserialize(wire) else {
            Issue.record("expected spawnCertPresentation"); return
        }
        #expect(decoded.isEmpty)
    }

    @Test("a chain exceeding the wire bound does not serialize (DoS guard)")
    func oversizedChainRejected() {
        let dummy = SpawnCertificate(childPublicKey: "ab", chainPath: ["Nexus"], issuerPublicKey: "cd", signature: Data([0x00]))
        let oversize = Array(repeating: dummy, count: Int(MessageLimits.maxSpawnCertChain) + 1)
        #expect(Message.spawnCertPresentation(chain: oversize).serialize().isEmpty)
    }

    @Test("a chain at the wire bound still serializes")
    func boundaryChainSerializes() {
        let dummy = SpawnCertificate(childPublicKey: "ab", chainPath: ["Nexus"], issuerPublicKey: "cd", signature: Data([0x00]))
        let atBound = Array(repeating: dummy, count: Int(MessageLimits.maxSpawnCertChain))
        let wire = Message.spawnCertPresentation(chain: atBound).serialize()
        #expect(!wire.isEmpty)
        guard case .spawnCertPresentation(let decoded)? = Message.deserialize(wire) else {
            Issue.record("expected spawnCertPresentation"); return
        }
        #expect(decoded.count == Int(MessageLimits.maxSpawnCertChain))
    }

    @Test("adding the new message does not disturb identify round-trip")
    func identifyUnaffected() {
        let msg = Message.identify(publicKey: "deadbeef", observedHost: "1.2.3.4", observedPort: 4001,
                                   listenAddrs: [("1.2.3.4", 4001)], chainPorts: ["Nexus": 4002], signature: Data([0x01, 0x02]))
        guard case .identify(let pk, _, let port, _, let cp, let sig)? = Message.deserialize(msg.serialize()) else {
            Issue.record("expected identify"); return
        }
        #expect(pk == "deadbeef")
        #expect(port == 4001)
        #expect(cp == ["Nexus": 4002])
        #expect(sig == Data([0x01, 0x02]))
    }
}
