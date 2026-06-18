import Foundation
import Crypto
import Tally

/// A parent process's attestation that it spawned a child process: a signature
/// by the parent (issuer) over the child's public key and the chain-path scope
/// the child was spawned to serve. Certificates compose along the process tree
/// into a chain rooted at the top process's key, so a grandchild can prove
/// spawn-tree membership to any ancestor (`SpawnCertificateChain.verify`).
///
/// Trust follows provenance: a connection backed by a valid chain to a key the
/// verifier trusts as its tree root classifies as trusted; everything else is
/// federated.
///
/// ## Caller preconditions (handshake wiring — separate PR)
/// - **`leaf` MUST be a possession-proven identity** — the public key of the
///   authenticated connection (bound by the identify-signature handshake), NEVER
///   a field lifted out of the presented chain. The chain is supplied by the
///   connecting (untrusted) peer; verifying it proves spawn-tree membership of
///   the asserted `leaf`, not that the presenter holds `leaf`'s private key.
/// - **Enforce the proven scope.** Use `verifiedScope` (not just the `verify`
///   Bool): a peer proven only for `["Nexus","a"]` must not be trusted to inject
///   consensus data for other chains. The strict-prefix nesting is only
///   meaningful if the caller bounds the peer to `verifiedScope`'s result.
/// - **No temporal validity / revocation in the primitive.** A certificate has
///   no expiry, epoch, or nonce, and the holder assembles its own chain — so a
///   compromised child keeps presenting a still-valid chain. "Revocation" is the
///   VERIFIER ceasing to trust the root (or a specific key), not the holder
///   dropping a cert. On-wire revocation (an expiry/epoch field bound into the
///   signed material + a verifier-side freshness check) is a wiring-PR concern.
///
/// ## Canonical signing payload
/// The signature covers a deterministic, length-prefixed encoding — never JSON —
/// so there is no field-boundary ambiguity (`["Nexus","AB"]` and
/// `["Nexus","A","B"]` encode differently):
///
///     lp(domain) || lp(canonical child key) || lp(canonical issuer key)
///     || count(chainPath) || lp(element)…
///
/// where `lp` is the UInt16-big-endian length prefix used by Ivy's wire format,
/// `count` is a UInt16 element count, and keys are canonicalized to raw hex
/// (`ed01` Multikey prefix stripped) so both spellings of a key sign and verify
/// identically. Keys/signatures are the same Curve25519 (Ed25519) scheme Ivy
/// peers already use for identity.
public struct SpawnCertificate: Codable, Sendable, Equatable {
    public let childPublicKey: String
    public let chainPath: [String]
    public let issuerPublicKey: String
    public let signature: Data

    /// Spawn certificates and identify signatures must never be mutually
    /// replayable, hence a dedicated domain tag.
    private static let domain = "ivy.spawnCert.v1"
    /// Process trees are shallow; bound the scope depth defensively.
    public static let maxChainPathDepth = 255

    /// Cert-local key canonicalization: the shared `KeyDifficulty.canonicalRawHex`
    /// (the PoW/Tally measurement form) strips an `ed01` Multikey prefix but does
    /// NOT lowercase, while hex decoding is case-insensitive — so mixed-case
    /// spellings of one key are the SAME key to the signature check but DIFFERENT
    /// strings to the link/self-sign comparisons. Lowercasing here collapses both
    /// spellings to one identity at EVERY cert site (signing material + all
    /// comparisons), so the self-sign and composition guards can't be split by
    /// case, and an honest uppercase key is no longer wrongly classed federated.
    /// (Pre-testnet: no deployed certs, so changing the signed bytes needs no
    /// migration.)
    static func canonKey(_ presented: String) -> String {
        KeyDifficulty.canonicalRawHex(presented).lowercased()
    }

    public init(childPublicKey: String, chainPath: [String], issuerPublicKey: String, signature: Data) {
        self.childPublicKey = childPublicKey
        self.chainPath = chainPath
        self.issuerPublicKey = issuerPublicKey
        self.signature = signature
    }

    /// Canonical payload the issuer signs. Returns empty Data when any field
    /// exceeds wire limits — callers must treat empty material as invalid
    /// (never sign or verify it), or distinct oversized certs would collide.
    public static func signingMaterial(childPublicKey: String, chainPath: [String], issuerPublicKey: String) -> Data {
        var data = Data()
        guard data.appendLengthPrefixedString(domain),
              data.appendLengthPrefixedString(canonKey(childPublicKey)),
              data.appendLengthPrefixedString(canonKey(issuerPublicKey)),
              data.appendCount(chainPath.count, max: UInt16(maxChainPathDepth)) else { return Data() }
        for element in chainPath {
            guard data.appendLengthPrefixedString(element) else { return Data() }
        }
        return data
    }

    /// Sign a spawn certificate for a child key. `issuerKeyPair` is the
    /// (publicKey: raw-hex, privateKey: raw bytes) shape `Ivy.generateKey`
    /// returns. Returns nil for a malformed key or oversized fields.
    public static func issue(
        childPublicKey: String,
        chainPath: [String],
        issuerKeyPair: (publicKey: String, privateKey: Data)
    ) -> SpawnCertificate? {
        guard issuerKeyPair.privateKey.count == 32,
              let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: issuerKeyPair.privateKey) else {
            return nil
        }
        let material = signingMaterial(
            childPublicKey: childPublicKey, chainPath: chainPath, issuerPublicKey: issuerKeyPair.publicKey)
        guard !material.isEmpty, let signature = try? privateKey.signature(for: material) else { return nil }
        return SpawnCertificate(
            childPublicKey: childPublicKey,
            chainPath: chainPath,
            issuerPublicKey: issuerKeyPair.publicKey,
            signature: signature)
    }

    /// True when `signature` verifies under the claimed issuer key over the
    /// canonical payload. Does NOT judge chain composition or scope nesting —
    /// that is `SpawnCertificateChain.verify`.
    public func hasValidSignature() -> Bool {
        guard !signature.isEmpty,
              let issuerBytes = Data(hexString: Self.canonKey(issuerPublicKey)), issuerBytes.count == 32,
              let verifyKey = try? Curve25519.Signing.PublicKey(rawRepresentation: issuerBytes) else {
            return false
        }
        let material = Self.signingMaterial(
            childPublicKey: childPublicKey, chainPath: chainPath, issuerPublicKey: issuerPublicKey)
        guard !material.isEmpty else { return false }
        return verifyKey.isValidSignature(signature, for: material)
    }
}

public enum SpawnCertificateChain {
    /// Verify that `leaf` is a member of the spawn tree rooted at
    /// `trustedRoot`, proven by `chain` ordered root-first. All keys compare in
    /// canonical raw-hex form. Returns true only when:
    /// - every certificate's signature is valid over the canonical payload;
    /// - the chain composes: cert[i].childPublicKey == cert[i+1].issuerPublicKey;
    /// - chain[0] is issued by `trustedRoot`;
    /// - the last certificate's child is `leaf`;
    /// - scopes nest: each cert's chainPath is a STRICT prefix of the next
    ///   cert's (parents spawn children deeper in the tree, never sideways or
    ///   up), and no chainPath is empty (an empty scope would strict-prefix
    ///   everything);
    /// - no link is self-signed (issuer == child) — only the verifier's own
    ///   `trustedRoot` choice confers root authority, never a self-claim.
    ///
    /// Root semantics: the root process needs no certificate for itself — an
    /// empty chain verifies exactly when `leaf` IS `trustedRoot`.
    public static func verify(chain: [SpawnCertificate], leaf: PeerID, trustedRoot: String) -> Bool {
        verifiedScope(chain: chain, leaf: leaf, trustedRoot: trustedRoot) != nil
    }

    /// Like `verify`, but returns the leaf's PROVEN scope (the deepest cert's
    /// `chainPath`, or `[]` for the empty-chain root case) instead of a bare
    /// Bool, and `nil` when the chain is invalid. Callers MUST bound a trusted
    /// peer to this scope — strict-prefix nesting is only meaningful if the data
    /// a trusted peer may inject is constrained to the scope it actually proved.
    public static func verifiedScope(chain: [SpawnCertificate], leaf: PeerID, trustedRoot: String) -> [String]? {
        let rootKey = canonKey(trustedRoot)
        let leafKey = canonKey(leaf.publicKey)
        guard !chain.isEmpty else { return leafKey == rootKey ? [] : nil }
        // Defense-in-depth: an explicit depth cap. Strict-prefix nesting already
        // forces depth ≤ maxChainPathDepth, but don't rely on a side effect.
        guard chain.count <= SpawnCertificate.maxChainPathDepth else { return nil }

        guard canonKey(chain[0].issuerPublicKey) == rootKey,
              canonKey(chain[chain.count - 1].childPublicKey) == leafKey else { return nil }

        for (index, cert) in chain.enumerated() {
            guard !cert.chainPath.isEmpty,
                  canonKey(cert.issuerPublicKey) != canonKey(cert.childPublicKey),
                  cert.hasValidSignature() else { return nil }
            if index + 1 < chain.count {
                let next = chain[index + 1]
                guard canonKey(cert.childPublicKey) == canonKey(next.issuerPublicKey),
                      isStrictPrefix(cert.chainPath, of: next.chainPath) else { return nil }
            }
        }
        return chain[chain.count - 1].chainPath
    }

    private static func canonKey(_ presented: String) -> String {
        SpawnCertificate.canonKey(presented)
    }

    private static func isStrictPrefix(_ prefix: [String], of path: [String]) -> Bool {
        prefix.count < path.count && Array(path.prefix(prefix.count)) == prefix
    }
}
