import Testing
import Foundation
import Crypto
import NIOCore
import NIOEmbedded
@testable import Ivy
@testable import Tally

private func hygieneConfig(publicKey: String, minPeerKeyBits: Int = 0) -> IvyConfig {
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
        enablePEX: false,
        minPeerKeyBits: minPeerKeyBits
    )
}

/// Grind a real Curve25519 key pair whose RAW hex form meets `minBits` while
/// its ed01-prefixed spelling, hashed VERBATIM, does not — i.e. exactly the
/// key an unnormalized gate would wrongly reject when presented prefixed.
private func grindGateKeyPair(minBits: Int) -> (publicKey: String, privateKey: Data) {
    while true {
        let privateKey = Curve25519.Signing.PrivateKey()
        let hex = privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        if KeyDifficulty.trailingZeroBits(of: hex) >= minBits,
           KeyDifficulty.trailingZeroBits(of: "ed01" + hex) < minBits {
            return (hex, privateKey.rawRepresentation)
        }
    }
}

/// Grind a key pair whose raw AND prefixed spellings both measure below
/// `bits`, so its rejection cannot hinge on which spelling is hashed.
private func grindUngatedKeyPair(below bits: Int) -> (publicKey: String, privateKey: Data) {
    while true {
        let privateKey = Curve25519.Signing.PrivateKey()
        let hex = privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        if KeyDifficulty.trailingZeroBits(of: hex) < bits,
           KeyDifficulty.trailingZeroBits(of: "ed01" + hex) < bits {
            return (hex, privateKey.rawRepresentation)
        }
    }
}

private func signIdentify(publicKey: String, observedHost: String, privateKey: Data) -> Data {
    let material = Data(publicKey.utf8) + Data(observedHost.utf8)
    let key = try! Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
    return try! key.signature(for: material)
}

private func makeInboundConnection(id: PeerID, channel: NIOAsyncTestingChannel) -> PeerConnection {
    PeerConnection(
        id: id,
        endpoint: PeerEndpoint(publicKey: id.publicKey, host: "127.0.0.1", port: 0),
        channel: channel,
        maxFrameSize: IvyConfig.defaultMaxFrameSize
    )
}

@Suite("Identity PoW normalization and Tally ledger hygiene")
struct IdentityPoWAndLedgerHygieneTests {

    @Test("identity canonicalization (Tally) strips ed01 Multikey spelling, passthrough otherwise")
    func canonicalKeyHexSemantics() {
        // Ivy's identify/routing gates measure KeyDifficulty.canonicalRawHex (the
        // single shared form), not a local twin. Guard the semantics the gates rely on.
        let raw = String(repeating: "ab", count: 32)
        #expect(KeyDifficulty.canonicalRawHex("ed01" + raw) == raw)
        #expect(KeyDifficulty.canonicalRawHex(raw) == raw)
        let short = "ed01" + String(repeating: "a", count: 60)
        #expect(KeyDifficulty.canonicalRawHex(short) == short)
        #expect(KeyDifficulty.canonicalRawHex("peer-4587") == "peer-4587")
    }

    @Test("Identify gate admits a key ground on its raw form when presented ed01-prefixed")
    func identifyGateAdmitsPrefixedPresentationOfGroundKey() async throws {
        let requiredBits = 4
        let node = Ivy(config: hygieneConfig(publicKey: "pow-gate-node", minPeerKeyBits: requiredBits))

        let inbound = PeerID(publicKey: "inbound-pow-gate")
        let channel = NIOAsyncTestingChannel()
        await node.registerInboundConnection(makeInboundConnection(id: inbound, channel: channel))

        let (rawKey, privateKey) = grindGateKeyPair(minBits: requiredBits)
        let prefixed = "ed01" + rawKey
        let observedHost = "203.0.113.7"
        await node.handleMessage(
            .identify(
                publicKey: prefixed,
                observedHost: observedHost,
                observedPort: 4001,
                listenAddrs: [],
                chainPorts: [:],
                signature: signIdentify(publicKey: prefixed, observedHost: observedHost, privateKey: privateKey)
            ),
            from: inbound
        )

        let peers = await node.connectionPeersForTesting()
        // Identity derives from the CANONICAL raw form — a prefixed
        // presentation is admitted but collapses onto the raw PeerID.
        #expect(peers.contains(PeerID(publicKey: rawKey)))
        #expect(!peers.contains(PeerID(publicKey: prefixed)))
        #expect(!peers.contains(inbound))

        _ = try? await channel.finish()
    }

    @Test("Both spellings of one ground key collapse to ONE identity (no 2x Sybil amplification)")
    func bothSpellingsCollapseToOneIdentity() async throws {
        let requiredBits = 4
        let node = Ivy(config: hygieneConfig(publicKey: "pow-collapse-node", minPeerKeyBits: requiredBits))

        let (rawKey, privateKey) = grindGateKeyPair(minBits: requiredBits)
        let prefixed = "ed01" + rawKey
        let canonicalID = PeerID(publicKey: rawKey)

        // First connection identifies with the RAW spelling.
        let inboundA = PeerID(publicKey: "inbound-collapse-a")
        let channelA = NIOAsyncTestingChannel()
        await node.registerInboundConnection(makeInboundConnection(id: inboundA, channel: channelA))
        let hostA = "203.0.113.20"
        await node.handleMessage(
            .identify(
                publicKey: rawKey, observedHost: hostA, observedPort: 4001,
                listenAddrs: [], chainPorts: [:],
                signature: signIdentify(publicKey: rawKey, observedHost: hostA, privateKey: privateKey)
            ),
            from: inboundA
        )

        // Second connection identifies with the PREFIXED spelling of the SAME
        // key. Pre-fix this minted a second live identity off one grind; now it
        // must collapse onto the canonical PeerID and be torn down as a
        // duplicate of the live connection.
        let inboundB = PeerID(publicKey: "inbound-collapse-b")
        let channelB = NIOAsyncTestingChannel()
        await node.registerInboundConnection(makeInboundConnection(id: inboundB, channel: channelB))
        let hostB = "203.0.113.21"
        await node.handleMessage(
            .identify(
                publicKey: prefixed, observedHost: hostB, observedPort: 4002,
                listenAddrs: [], chainPorts: [:],
                signature: signIdentify(publicKey: prefixed, observedHost: hostB, privateKey: privateKey)
            ),
            from: inboundB
        )

        let peers = await node.connectionPeersForTesting()
        #expect(peers.contains(canonicalID), "the canonical identity must be live")
        #expect(!peers.contains(PeerID(publicKey: prefixed)), "the prefixed spelling must not be a second identity")
        #expect(!peers.contains(inboundA))
        #expect(!peers.contains(inboundB))
        #expect(peers.count == 1, "one grind must yield exactly ONE admitted identity, got \(peers)")

        _ = try? await channelA.finish()
        _ = try? await channelB.finish()
    }

    @Test("Identify gate still rejects a key below the threshold on its raw form")
    func identifyGateRejectsUngatedKey() async throws {
        let requiredBits = 4
        let node = Ivy(config: hygieneConfig(publicKey: "pow-gate-reject-node", minPeerKeyBits: requiredBits))

        let inbound = PeerID(publicKey: "inbound-pow-reject")
        let channel = NIOAsyncTestingChannel()
        await node.registerInboundConnection(makeInboundConnection(id: inbound, channel: channel))

        let (rawKey, privateKey) = grindUngatedKeyPair(below: requiredBits)
        let prefixed = "ed01" + rawKey
        let observedHost = "203.0.113.8"
        await node.handleMessage(
            .identify(
                publicKey: prefixed,
                observedHost: observedHost,
                observedPort: 4001,
                listenAddrs: [],
                chainPorts: [:],
                signature: signIdentify(publicKey: prefixed, observedHost: observedHost, privateKey: privateKey)
            ),
            from: inbound
        )

        let peers = await node.connectionPeersForTesting()
        #expect(!peers.contains(PeerID(publicKey: prefixed)))
        #expect(!peers.contains(inbound))

        _ = try? await channel.finish()
    }

    @Test("Routing gate measures the canonical raw form of discovered endpoints")
    func routingGateNormalizesPrefixedEndpoints() async {
        let requiredBits = 4
        let node = Ivy(config: hygieneConfig(publicKey: "pow-routing-node", minPeerKeyBits: requiredBits))
        let source = PeerID(publicKey: "pow-routing-source")

        let (groundKey, _) = grindGateKeyPair(minBits: requiredBits)
        let groundPrefixed = PeerEndpoint(publicKey: "ed01" + groundKey, host: "10.0.0.9", port: 4001)
        #expect(await node.isAcceptableDiscoveredEndpoint(groundPrefixed, source: "test", from: source))

        // Raw presentation of the same key is (still) accepted: widening only.
        let groundRaw = PeerEndpoint(publicKey: groundKey, host: "10.0.0.9", port: 4001)
        #expect(await node.isAcceptableDiscoveredEndpoint(groundRaw, source: "test", from: source))

        let (lowKey, _) = grindUngatedKeyPair(below: requiredBits)
        let lowPrefixed = PeerEndpoint(publicKey: "ed01" + lowKey, host: "10.0.0.10", port: 4001)
        #expect(!(await node.isAcceptableDiscoveredEndpoint(lowPrefixed, source: "test", from: source)))
    }

    @Test("Disconnect drops the peer's Tally ledger without delegate help")
    func disconnectResetsTallyLedger() async throws {
        let node = Ivy(config: hygieneConfig(publicKey: "ledger-hygiene-node"))
        let peer = PeerID(publicKey: "ledger-hygiene-peer")
        let channel = NIOAsyncTestingChannel()
        await node.registerConnectionForTesting(makeInboundConnection(id: peer, channel: channel), as: peer)

        let tally = await node.tally
        tally.recordSuccess(peer: peer)
        #expect(tally.peerLedger(for: peer) != nil)

        await node.disconnect(peer)

        #expect(tally.peerLedger(for: peer) == nil)
        #expect(!(await node.connectionPeersForTesting()).contains(peer))

        _ = try? await channel.finish()
    }

    @Test("generateKey is total and meets the target difficulty")
    func generateKeyIsTotal() {
        let key = Ivy.generateKey(targetDifficulty: 2)
        #expect(KeyDifficulty.trailingZeroBits(of: key.publicKey) >= 2)
        #expect(key.privateKey.count == 32)
    }
}
