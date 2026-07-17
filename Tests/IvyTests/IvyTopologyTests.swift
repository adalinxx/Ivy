import Crypto
import Foundation
import Testing
@testable import Ivy

@Suite("Ivy mode and carrier isolation")
struct IvyTopologyTests {
    private func identity(_ byte: UInt8) -> Curve25519.Signing.PrivateKey {
        try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
    }

    private func key(_ identity: Curve25519.Signing.PrivateKey) -> String {
        try! PeerKey(rawRepresentation: identity.publicKey.rawRepresentation).hex
    }

    @Test("pinned identity canonicalizes raw and ed01 spellings")
    func pinnedCanonicalization() throws {
        let remote = key(identity(2))
        let mode = IvyMode.pinned(peer: "ed01" + remote.uppercased())
        #expect(mode.allowsEndpoint(try PeerKey(remote)))
        #expect(!mode.allowsEndpoint(try PeerKey(key(identity(3)))))
        #expect(!mode.participatesInPublicDiscovery)
    }

    @Test("pinned mode keeps public discovery off and listener configuration intact")
    func pinnedConfiguration() throws {
        let local = identity(1)
        let remote = key(identity(2))
        let endpoint = PeerEndpoint(publicKey: remote, host: "127.0.0.1", port: 4001)
        let config = IvyConfig(
            signingKey: local,
            listenPort: 4100,
            bootstrapPeers: [endpoint],
            stunServers: [("stun.example", 3478)],
            mode: .pinned(peer: remote))

        try config.validate()
        #expect(config.listenPort == 4100)
        #expect(config.stunServers.isEmpty)
    }

    @Test("pinned endpoint and configured carrier identities are disjoint")
    func carrierIdentityDisjointness() {
        let local = identity(1)
        let remote = key(identity(2))
        let carrier = PeerEndpoint(publicKey: remote, host: "127.0.0.1", port: 5001)
        let config = IvyConfig(
            signingKey: local,
            carriers: [carrier],
            mode: .pinned(peer: remote))

        #expect(throws: IvyModeError.identityRoleCollision(remote)) {
            try config.validate()
        }
    }

    @Test("pinned mode rejects substitute bootstrap identities")
    func substituteBootstrapRejected() {
        let local = identity(1)
        let expected = key(identity(2))
        let substitute = key(identity(3))
        let config = IvyConfig(
            signingKey: local,
            bootstrapPeers: [PeerEndpoint(publicKey: substitute, host: "127.0.0.1", port: 4002)],
            mode: .pinned(peer: expected))

        #expect(throws: IvyModeError.peerOutsidePinnedMode(expected: expected, actual: substitute)) {
            try config.validate()
        }
    }

    @Test("pinned mode rejects malformed identities")
    func malformedPinnedIdentityRejected() {
        let config = IvyConfig(
            signingKey: identity(1),
            mode: .pinned(peer: "not-a-peer-key"))

        #expect(throws: IvyModeError.invalidPinnedIdentity("not-a-peer-key")) {
            try config.validate()
        }
    }

    @Test("ordinary connect cannot bypass pinned identity")
    func ordinaryConnectHonorsPinnedIdentity() async {
        let local = identity(1)
        let expected = key(identity(2))
        let substitute = key(identity(3))
        let node = Ivy(config: IvyConfig(
            signingKey: local,
            mode: .pinned(peer: expected)))

        await #expect(throws: IvyError.peerOutsideMode) {
            try await node.connect(to: PeerEndpoint(
                publicKey: substitute,
                host: "127.0.0.1",
                port: 4001))
        }
        await #expect(throws: IvyError.peerOutsideMode) {
            try await node.connect(to: PeerEndpoint(
                publicKey: key(local),
                host: "127.0.0.1",
                port: 4001))
        }
    }

    @Test("configured carrier cannot be used as an application endpoint")
    func carrierCannotBecomeEndpoint() async {
        let local = identity(1)
        let carrierKey = key(identity(4))
        let carrier = PeerEndpoint(publicKey: carrierKey, host: "127.0.0.1", port: 5001)
        let node = Ivy(config: IvyConfig(signingKey: local, carriers: [carrier]))

        await #expect(throws: IvyError.peerOutsideMode) {
            try await node.connect(to: carrier)
        }
        #expect(await node.connectedPeers.isEmpty)
    }

    @Test("invalid transport capacities fail before the listener starts")
    func invalidCapacityRejected() {
        let config = IvyConfig(signingKey: identity(1), maxConnections: 0)

        #expect(throws: IvyModeError.invalidConfiguration("capacity limits must be positive")) {
            try config.validate()
        }

        let oversizedFrames = IvyConfig(signingKey: identity(1), maxFrameSize: .max)
        #expect(throws: IvyModeError.invalidConfiguration("maxFrameSize is outside the supported range")) {
            try oversizedFrames.validate()
        }

        let invalidHealth = IvyConfig(
            signingKey: identity(1),
            healthConfig: PeerHealthConfig(keepaliveInterval: .zero))
        #expect(throws: IvyModeError.invalidConfiguration("peer health limits are invalid")) {
            try invalidHealth.validate()
        }
    }

}
