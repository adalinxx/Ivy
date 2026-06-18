import Testing
import Foundation
import Crypto
import NIOCore
import NIOEmbedded
@testable import Ivy
import Tally

private func postIdentifyConfig(publicKey: String) -> IvyConfig {
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
        minPeerKeyBits: 0
    )
}

private func makeKeyPair() -> (publicKey: String, privateKey: Data) {
    let privateKey = Curve25519.Signing.PrivateKey()
    let hex = privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
    return (hex, privateKey.rawRepresentation)
}

private func signIdentifyFrame(publicKey: String, observedHost: String, privateKey: Data) -> Data {
    let material = Data(publicKey.utf8) + Data(observedHost.utf8)
    let key = try! Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
    return try! key.signature(for: material)
}

private func makeConnection(id: PeerID, channel: NIOAsyncTestingChannel) -> PeerConnection {
    PeerConnection(
        id: id,
        endpoint: PeerEndpoint(publicKey: id.publicKey, host: "127.0.0.1", port: 0),
        channel: channel,
        maxFrameSize: IvyConfig.defaultMaxFrameSize
    )
}

/// Records every didIdentifyPeer callback so the test can assert it fires
/// exactly once with the authenticated real identity.
private final class IdentifyRecorder: IvyDelegate, @unchecked Sendable {
    struct Event: Sendable { let realID: PeerID; let previous: PeerID }
    private let lock = NSLock()
    private var _events: [Event] = []
    private var _spawnCertEvents: [PeerID] = []
    var events: [Event] { lock.withLock { _events } }
    var spawnCertEvents: [PeerID] { lock.withLock { _spawnCertEvents } }

    func ivy(_ ivy: Ivy, didIdentifyPeer realID: PeerID, previous: PeerID) {
        lock.withLock { _events.append(Event(realID: realID, previous: previous)) }
    }

    func ivy(_ ivy: Ivy, didReceiveSpawnCertChain peer: PeerID) {
        lock.withLock { _spawnCertEvents.append(peer) }
    }
}

/// A conformer that does NOT implement didIdentifyPeer — it relies entirely on
/// the protocol-extension default no-op. Its mere existence (compiling +
/// connecting) proves the addition is non-breaking.
private final class DefaultOnlyDelegate: IvyDelegate, @unchecked Sendable {}

@Suite("Post-identify delegate callback (didIdentifyPeer)")
struct PostIdentifyCallbackTests {

    @Test("Fires exactly once with the real identity after an inbound peer identifies")
    func firesOnceOnInboundRekey() async throws {
        let node = Ivy(config: postIdentifyConfig(publicKey: "post-identify-node"))
        let recorder = IdentifyRecorder()
        await node.setDelegate(recorder)

        let inbound = PeerID(publicKey: "inbound-post-identify")
        let channel = NIOAsyncTestingChannel()
        await node.registerInboundConnection(makeConnection(id: inbound, channel: channel))

        let (rawKey, privateKey) = makeKeyPair()
        let realID = PeerID(publicKey: rawKey)
        let observedHost = "203.0.113.50"
        await node.handleMessage(
            .identify(
                publicKey: rawKey,
                observedHost: observedHost,
                observedPort: 4001,
                listenAddrs: [],
                chainPorts: [:],
                signature: signIdentifyFrame(publicKey: rawKey, observedHost: observedHost, privateKey: privateKey)
            ),
            from: inbound
        )

        // The connection must now be keyed to the real identity ...
        let peers = await node.connectionPeersForTesting()
        #expect(peers.contains(realID))
        #expect(!peers.contains(inbound))

        // ... and the callback must have fired exactly once carrying that real
        // identity plus the temporary inbound id it replaced.
        let events = recorder.events
        #expect(events.count == 1)
        #expect(events.first?.realID == realID)
        #expect(events.first?.previous == inbound)

        _ = try? await channel.finish()
    }

    @Test("Does not fire when identify is rejected (bad signature)")
    func doesNotFireOnRejectedIdentify() async throws {
        let node = Ivy(config: postIdentifyConfig(publicKey: "post-identify-reject-node"))
        let recorder = IdentifyRecorder()
        await node.setDelegate(recorder)

        let inbound = PeerID(publicKey: "inbound-post-identify-reject")
        let channel = NIOAsyncTestingChannel()
        await node.registerInboundConnection(makeConnection(id: inbound, channel: channel))

        let (rawKey, _) = makeKeyPair()
        await node.handleMessage(
            .identify(
                publicKey: rawKey,
                observedHost: "203.0.113.51",
                observedPort: 4001,
                listenAddrs: [],
                chainPorts: [:],
                signature: Data() // empty signature -> rejected, disconnected
            ),
            from: inbound
        )

        #expect(recorder.events.isEmpty)
        _ = try? await channel.finish()
    }

    @Test("A conformer relying on the default no-op still compiles and connects")
    func defaultImplementationStillConnects() async throws {
        let node = Ivy(config: postIdentifyConfig(publicKey: "post-identify-default-node"))
        let delegate = DefaultOnlyDelegate()
        await node.setDelegate(delegate)

        let inbound = PeerID(publicKey: "inbound-post-identify-default")
        let channel = NIOAsyncTestingChannel()
        await node.registerInboundConnection(makeConnection(id: inbound, channel: channel))

        let (rawKey, privateKey) = makeKeyPair()
        let realID = PeerID(publicKey: rawKey)
        let observedHost = "203.0.113.52"
        await node.handleMessage(
            .identify(
                publicKey: rawKey,
                observedHost: observedHost,
                observedPort: 4001,
                listenAddrs: [],
                chainPorts: [:],
                signature: signIdentifyFrame(publicKey: rawKey, observedHost: observedHost, privateKey: privateKey)
            ),
            from: inbound
        )

        // Identity behavior is unchanged: the peer is still admitted under its
        // real id even though the delegate does not implement the new callback.
        let peers = await node.connectionPeersForTesting()
        #expect(peers.contains(realID))
        #expect(!peers.contains(inbound))

        _ = try? await channel.finish()
    }

    @Test("didReceiveSpawnCertChain fires after a presentation; chain is queryable 2c)")
    func spawnCertPresentationFiresCallback() async throws {
        let node = Ivy(config: postIdentifyConfig(publicKey: "spawn-cert-node"))
        let recorder = IdentifyRecorder()
        await node.setDelegate(recorder)

        let inbound = PeerID(publicKey: "inbound-spawn-cert")
        let channel = NIOAsyncTestingChannel()
        await node.registerInboundConnection(makeConnection(id: inbound, channel: channel))

        let (rawKey, privateKey) = makeKeyPair()
        let realID = PeerID(publicKey: rawKey)
        let observedHost = "203.0.113.60"
        await node.handleMessage(
            .identify(publicKey: rawKey, observedHost: observedHost, observedPort: 4001,
                      listenAddrs: [], chainPorts: [:],
                      signature: signIdentifyFrame(publicKey: rawKey, observedHost: observedHost, privateKey: privateKey)),
            from: inbound)

        // A real chain whose leaf is THIS connection's authenticated key.
        let rootKP = makeKeyPair()
        let chain = [SpawnCertificate.issue(childPublicKey: rawKey, chainPath: ["Nexus", "x"], issuerKeyPair: rootKP)!]
        await node.handleMessage(.spawnCertPresentation(chain: chain), from: realID)

        #expect(recorder.spawnCertEvents == [realID])
        let stored = await node.spawnCertChain(for: realID)
        #expect(stored == chain)
    }

    @Test("a presentation under a still-unauthenticated inbound id is ignored (no callback, not stored)")
    func spawnCertPresentationIgnoredPreIdentify() async throws {
        let node = Ivy(config: postIdentifyConfig(publicKey: "spawn-cert-preid-node"))
        let recorder = IdentifyRecorder()
        await node.setDelegate(recorder)

        let inbound = PeerID(publicKey: "inbound-preid")
        let channel = NIOAsyncTestingChannel()
        await node.registerInboundConnection(makeConnection(id: inbound, channel: channel))

        let rootKP = makeKeyPair(), leaf = makeKeyPair()
        let chain = [SpawnCertificate.issue(childPublicKey: leaf.publicKey, chainPath: ["Nexus", "x"], issuerKeyPair: rootKP)!]
        await node.handleMessage(.spawnCertPresentation(chain: chain), from: inbound) // temp inbound- id

        #expect(recorder.spawnCertEvents.isEmpty)
        let stored = await node.spawnCertChain(for: inbound)
        #expect(stored.isEmpty)
    }
}
