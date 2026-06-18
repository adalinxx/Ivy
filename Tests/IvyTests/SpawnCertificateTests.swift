import Testing
import Foundation
import Crypto
@testable import Ivy
@testable import Tally

/// Deterministic Ed25519 key pair derived from a fixed seed byte, in the same
/// (publicKey: raw-hex, privateKey: raw bytes) shape `Ivy.generateKey` returns.
private func fixedKeyPair(_ seed: UInt8) -> (publicKey: String, privateKey: Data) {
    let priv = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: seed, count: 32))
    let pubHex = priv.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    return (publicKey: pubHex, privateKey: priv.rawRepresentation)
}

@Suite("SpawnCertificate")
struct SpawnCertificateTests {

    // Fixed spawn tree: root → a → b → c, plus an unrelated key (mallory)
    // and a second tree root (r2) for cross-tree replay.
    let root = fixedKeyPair(0x01)
    let a = fixedKeyPair(0x02)
    let b = fixedKeyPair(0x03)
    let c = fixedKeyPair(0x04)
    let mallory = fixedKeyPair(0x05)
    let r2 = fixedKeyPair(0x06)

    let pathA = ["Nexus", "a"]
    let pathB = ["Nexus", "a", "b"]
    let pathC = ["Nexus", "a", "b", "c"]

    /// root → a → b → c, scopes nesting strictly deeper at each link.
    func depth3Chain() -> [SpawnCertificate] {
        [
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: pathA, issuerKeyPair: root)!,
            SpawnCertificate.issue(childPublicKey: b.publicKey, chainPath: pathB, issuerKeyPair: a)!,
            SpawnCertificate.issue(childPublicKey: c.publicKey, chainPath: pathC, issuerKeyPair: b)!,
        ]
    }

    // MARK: - Happy paths

    @Test("Depth-1 chain (parent→child) verifies")
    func testDepth1Verifies() {
        let cert = SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: pathA, issuerKeyPair: root)
        #expect(cert != nil)
        #expect(SpawnCertificateChain.verify(
            chain: [cert!], leaf: PeerID(publicKey: a.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Depth-3 chain (root→a→b→c) verifies for leaf c")
    func testDepth3Verifies() {
        #expect(SpawnCertificateChain.verify(
            chain: depth3Chain(), leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey))
        // Prefixes of the chain also prove the intermediate identities.
        #expect(SpawnCertificateChain.verify(
            chain: Array(depth3Chain().prefix(2)), leaf: PeerID(publicKey: b.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Root semantics: empty chain verifies only when leaf IS the trusted root")
    func testEmptyChainRootSemantics() {
        // The root process needs no certificate for itself.
        #expect(SpawnCertificateChain.verify(
            chain: [], leaf: PeerID(publicKey: root.publicKey), trustedRoot: root.publicKey))
        // Attack: anyone else claiming root membership with an empty chain.
        #expect(!SpawnCertificateChain.verify(
            chain: [], leaf: PeerID(publicKey: mallory.publicKey), trustedRoot: root.publicKey))
    }

    @Test("ed01-prefixed spellings of leaf/root collapse to the same identity")
    func testEd01SpellingEquivalence() {
        let chain = depth3Chain()
        #expect(SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: "ed01" + c.publicKey), trustedRoot: "ed01" + root.publicKey))
    }

    @Test("UPPERCASE-hex spelling of an honest key still verifies (no false-federate)")
    func testUppercaseKeySpellingVerifies() {
        // A key presented in uppercase hex is the SAME identity (hex decodes
        // case-insensitively). It must classify trusted, not be wrongly federated.
        let chain = depth3Chain()
        #expect(SpawnCertificateChain.verify(
            chain: chain,
            leaf: PeerID(publicKey: c.publicKey.uppercased()),
            trustedRoot: root.publicKey.uppercased()))
    }

    @Test("Attack: mixed-case self-sign cannot split the issuer != child guard")
    func testMixedCaseSelfSignRejected() {
        // Same key K spelled upper as issuer and lower as child: a string compare
        // would see two identities and pass the self-sign guard, while the
        // signature (case-insensitive decode) verifies under K. Cert-local
        // lowercasing must collapse both to K so the self-sign guard fires.
        let material = SpawnCertificate.signingMaterial(
            childPublicKey: a.publicKey.lowercased(),
            chainPath: pathA,
            issuerPublicKey: a.publicKey.uppercased())
        let priv = try! Curve25519.Signing.PrivateKey(rawRepresentation: a.privateKey)
        let sig = try! priv.signature(for: material)
        let selfSigned = SpawnCertificate(
            childPublicKey: a.publicKey.lowercased(),
            chainPath: pathA,
            issuerPublicKey: a.publicKey.uppercased(),
            signature: sig)
        // Rooting it would need K to be the trusted root; even then the self-sign
        // guard must reject the link.
        #expect(!SpawnCertificateChain.verify(
            chain: [selfSigned], leaf: PeerID(publicKey: a.publicKey), trustedRoot: a.publicKey))
    }

    @Test("verifiedScope returns the leaf's proven scope (callers must enforce it)")
    func testVerifiedScopeReturnsProvenPath() {
        #expect(SpawnCertificateChain.verifiedScope(
            chain: depth3Chain(), leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey) == pathC)
        // Empty-chain root case proves the root's (empty) scope, not nil.
        #expect(SpawnCertificateChain.verifiedScope(
            chain: [], leaf: PeerID(publicKey: root.publicKey), trustedRoot: root.publicKey) == [])
        // Invalid chain → nil (no scope to enforce).
        #expect(SpawnCertificateChain.verifiedScope(
            chain: depth3Chain(), leaf: PeerID(publicKey: mallory.publicKey), trustedRoot: root.publicKey) == nil)
    }

    // MARK: - Forged signatures

    @Test("Attack: bit-flipped signature is rejected")
    func testBitFlippedSignatureRejected() {
        var chain = depth3Chain()
        var sig = chain[1].signature
        sig[sig.count / 2] ^= 0x01
        chain[1] = SpawnCertificate(
            childPublicKey: chain[1].childPublicKey, chainPath: chain[1].chainPath,
            issuerPublicKey: chain[1].issuerPublicKey, signature: sig)
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Attack: signature minted by a different key than the claimed issuer is rejected")
    func testWrongSignerRejected() {
        // Mallory signs a cert that CLAIMS root as issuer — the signature does
        // not verify under root's key.
        let forged = SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: pathA,
                                            issuerKeyPair: (publicKey: root.publicKey, privateKey: mallory.privateKey))!
        #expect(!SpawnCertificateChain.verify(
            chain: [forged], leaf: PeerID(publicKey: a.publicKey), trustedRoot: root.publicKey))
    }

    // MARK: - Chain composition attacks

    @Test("Attack: chain order swapped is rejected")
    func testSwappedOrderRejected() {
        var chain = depth3Chain()
        chain.swapAt(0, 1)
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Attack: broken link (cert[i].child != cert[i+1].issuer) is rejected")
    func testBrokenLinkRejected() {
        // root→a, then a cert issued by an UNRELATED key for c — the chain
        // does not compose through a.
        let chain = [
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: pathA, issuerKeyPair: root)!,
            SpawnCertificate.issue(childPublicKey: c.publicKey, chainPath: pathC, issuerKeyPair: mallory)!,
        ]
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Attack: truncated chain (missing intermediate) is rejected")
    func testTruncatedChainRejected() {
        var chain = depth3Chain()
        chain.remove(at: 1) // drop a→b; root→a no longer composes with b→c
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Attack: valid chain presented for the wrong leaf is rejected")
    func testWrongLeafRejected() {
        // Mallory replays c's perfectly valid chain for her own identity.
        #expect(!SpawnCertificateChain.verify(
            chain: depth3Chain(), leaf: PeerID(publicKey: mallory.publicKey), trustedRoot: root.publicKey))
        // An intermediate identity also cannot present the FULL chain as its own.
        #expect(!SpawnCertificateChain.verify(
            chain: depth3Chain(), leaf: PeerID(publicKey: b.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Attack: chain rooted at an untrusted key is rejected")
    func testWrongRootRejected() {
        // Mallory builds an internally consistent tree under her own root.
        let chain = [
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: pathA, issuerKeyPair: mallory)!,
            SpawnCertificate.issue(childPublicKey: b.publicKey, chainPath: pathB, issuerKeyPair: a)!,
        ]
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: b.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Attack: cross-tree replay — chain valid under root R1 presented to a verifier trusting R2")
    func testCrossTreeReplayRejected() {
        let chain = depth3Chain() // valid under `root` (R1)
        // Sanity: it really is valid under R1…
        #expect(SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey))
        // …and is rejected by a verifier whose tree root is R2.
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: c.publicKey), trustedRoot: r2.publicKey))
    }

    // MARK: - Scope (chainPath) attacks

    @Test("Attack: sideways scope — [Nexus,A] issuing for [Nexus,B,X] is rejected")
    func testSidewaysScopeRejected() {
        let chain = [
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: ["Nexus", "A"], issuerKeyPair: root)!,
            SpawnCertificate.issue(childPublicKey: b.publicKey, chainPath: ["Nexus", "B", "X"], issuerKeyPair: a)!,
        ]
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: b.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Attack: upward scope — [Nexus,A] issuing for [Nexus] is rejected")
    func testUpwardScopeRejected() {
        let chain = [
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: ["Nexus", "A"], issuerKeyPair: root)!,
            SpawnCertificate.issue(childPublicKey: b.publicKey, chainPath: ["Nexus"], issuerKeyPair: a)!,
        ]
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: b.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Attack: equal scope — issuing for the issuer's own path is rejected")
    func testEqualScopeRejected() {
        let chain = [
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: ["Nexus", "A"], issuerKeyPair: root)!,
            SpawnCertificate.issue(childPublicKey: b.publicKey, chainPath: ["Nexus", "A"], issuerKeyPair: a)!,
        ]
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: b.publicKey), trustedRoot: root.publicKey))
    }

    @Test("Attack: empty chainPath scope is rejected (would strict-prefix everything)")
    func testEmptyScopeRejected() {
        let chain = [
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: [], issuerKeyPair: root)!,
            SpawnCertificate.issue(childPublicKey: b.publicKey, chainPath: ["Nexus", "B"], issuerKeyPair: a)!,
        ]
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: b.publicKey), trustedRoot: root.publicKey))
    }

    // MARK: - Self-signed claims

    @Test("Attack: self-signed link (issuer == child) is rejected even when validly signed")
    func testSelfSignedLinkRejected() {
        // Mallory signs her OWN key, claiming to be a spawn-tree root.
        let selfCert = SpawnCertificate.issue(
            childPublicKey: mallory.publicKey, chainPath: ["Nexus"], issuerKeyPair: mallory)!
        #expect(!SpawnCertificateChain.verify(
            chain: [selfCert], leaf: PeerID(publicKey: mallory.publicKey), trustedRoot: mallory.publicKey))
        // Nor does a self-signed link smuggle into a longer chain.
        let chain = [
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: pathA, issuerKeyPair: root)!,
            SpawnCertificate.issue(childPublicKey: a.publicKey, chainPath: pathB, issuerKeyPair: a)!,
        ]
        #expect(!SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: a.publicKey), trustedRoot: root.publicKey))
    }

    // MARK: - Canonical payload

    @Test("Canonical payload: same fields always produce identical signing material")
    func testCanonicalPayloadDeterministic() {
        let m1 = SpawnCertificate.signingMaterial(
            childPublicKey: a.publicKey, chainPath: pathA, issuerPublicKey: root.publicKey)
        let m2 = SpawnCertificate.signingMaterial(
            childPublicKey: a.publicKey, chainPath: pathA, issuerPublicKey: root.publicKey)
        #expect(!m1.isEmpty)
        #expect(m1 == m2)
        // ed01-prefixed key spellings canonicalize to the same material.
        let m3 = SpawnCertificate.signingMaterial(
            childPublicKey: "ed01" + a.publicKey, chainPath: pathA, issuerPublicKey: "ed01" + root.publicKey)
        #expect(m1 == m3)
    }

    @Test("Attack: field-boundary malleability — shifting bytes between chainPath elements must not verify")
    func testFieldBoundaryMalleabilityRejected() {
        // ["Nexus","AB"] and ["Nexus","A","B"] concatenate to the same bytes;
        // length-prefixed encoding must keep their payloads distinct.
        let m1 = SpawnCertificate.signingMaterial(
            childPublicKey: a.publicKey, chainPath: ["Nexus", "AB"], issuerPublicKey: root.publicKey)
        let m2 = SpawnCertificate.signingMaterial(
            childPublicKey: a.publicKey, chainPath: ["Nexus", "A", "B"], issuerPublicKey: root.publicKey)
        let m3 = SpawnCertificate.signingMaterial(
            childPublicKey: a.publicKey, chainPath: ["NexusA", "B"], issuerPublicKey: root.publicKey)
        #expect(m1 != m2)
        #expect(m1 != m3)
        #expect(m2 != m3)

        // Crafted collision attempt: reuse a genuine signature over
        // ["Nexus","AB"] on a cert claiming ["Nexus","A","B"].
        let genuine = SpawnCertificate.issue(
            childPublicKey: a.publicKey, chainPath: ["Nexus", "AB"], issuerKeyPair: root)!
        let crafted = SpawnCertificate(
            childPublicKey: a.publicKey, chainPath: ["Nexus", "A", "B"],
            issuerPublicKey: root.publicKey, signature: genuine.signature)
        #expect(!SpawnCertificateChain.verify(
            chain: [crafted], leaf: PeerID(publicKey: a.publicKey), trustedRoot: root.publicKey))
    }

    // MARK: - Revocation (this pass: verifier-side cert drop)

    @Test("Revocation: dropping a cert degrades the link — remaining chain no longer verifies")
    func testRevocationByDroppingCert() {
        let chain = depth3Chain()
        #expect(SpawnCertificateChain.verify(
            chain: chain, leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey))
        // Parent revokes b by dropping a→b; whatever c can still present no
        // longer proves spawn-tree membership → connection classifies federated.
        let afterRevocation = [chain[0], chain[2]]
        #expect(!SpawnCertificateChain.verify(
            chain: afterRevocation, leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey))
    }

    // MARK: - Codable

    @Test("Certificate survives a Codable roundtrip and still verifies")
    func testCodableRoundtrip() throws {
        let chain = depth3Chain()
        let data = try JSONEncoder().encode(chain)
        let decoded = try JSONDecoder().decode([SpawnCertificate].self, from: data)
        #expect(decoded == chain)
        #expect(SpawnCertificateChain.verify(
            chain: decoded, leaf: PeerID(publicKey: c.publicKey), trustedRoot: root.publicKey))
    }
}
