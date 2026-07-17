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

    @Test("the protocol frame fits maximum canonical metadata through relay")
    func protocolFrameFitsMaximumMetadata() throws {
        let initiatorIdentity = identity(2)
        let responderIdentity = identity(3)
        let carrierIdentity = identity(4)
        let initiator = try PeerKey(rawRepresentation: initiatorIdentity.publicKey.rawRepresentation)
        let responder = try PeerKey(rawRepresentation: responderIdentity.publicKey.rawRepresentation)
        let carrier = try PeerKey(rawRepresentation: carrierIdentity.publicKey.rawRepresentation)
        let addresses = (0..<8).map { index in
            let length = index < 6 ? 8_186 : 8_185
            let suffix = "\(index)"
            return ListenAddress(
                host: String(repeating: "a", count: length - suffix.count) + suffix,
                port: UInt16(index + 1))
        }
        let metadata = try #require(PeerMetadata(listenAddresses: addresses).encode())
        #expect(metadata.count == PeerMetadata.maxEncodedSize)
        let initiatorHello = SessionHelloInitiator(
            routeBinding: Data(repeating: 0x11, count: 32),
            initiator: initiator,
            responder: responder,
            nonce: Data(repeating: 0x22, count: 32),
            metadata: metadata)
        let signedInitiator = try SignedSessionHelloInitiator.sign(
            initiatorHello,
            with: initiatorIdentity)
        let initiatorRecord = SessionWireRecord.helloInitiator(signedInitiator).serialize()
        #expect(try SessionWireRecord.deserialize(initiatorRecord) == .helloInitiator(signedInitiator))

        let hello = SessionHelloResponder(
            routeBinding: Data(repeating: 0x11, count: 32),
            responder: responder,
            initiator: initiator,
            initiatorNonce: Data(repeating: 0x22, count: 32),
            responderNonce: Data(repeating: 0x33, count: 32),
            metadata: metadata)
        let signedHello = try SignedSessionHelloResponder.sign(hello, with: responderIdentity)
        let endpointRecord = SessionWireRecord.helloResponder(signedHello).serialize()
        #expect(try SessionWireRecord.deserialize(endpointRecord) == .helloResponder(signedHello))
        let relayPacket = Message.relayPacket(
            routeID: Data(repeating: 0x44, count: 32),
            opaqueEndpointRecord: endpointRecord
        ).serialize()
        let carrierRecord = try SessionDataRecord.sign(
            sessionID: SessionID(bytes: Data(repeating: 0x55, count: 32)),
            sender: carrier,
            receiver: responder,
            sequence: 1,
            payload: relayPacket,
            with: carrierIdentity)
        let wireRecord = SessionWireRecord.data(carrierRecord)

        let serialized = wireRecord.serialize()
        #expect(!serialized.isEmpty)
        #expect(serialized.count <= Int(IvyConfig.protocolMaxFrameSize))
        guard case .data(let decodedCarrier) = try SessionWireRecord.deserialize(serialized),
              case .relayPacket(_, let opaqueRecord) = Message.deserialize(decodedCarrier.payload) else {
            Issue.record("Expected a nested responder record")
            return
        }
        #expect(try SessionWireRecord.deserialize(opaqueRecord) == .helloResponder(signedHello))
    }

    @Test("invalid transport capacities fail before the listener starts")
    func invalidCapacityRejected() {
        let config = IvyConfig(signingKey: identity(1), maxConnections: 0)

        #expect(throws: IvyModeError.invalidConfiguration("capacity limits must be positive")) {
            try config.validate()
        }

        let invalidHealth = IvyConfig(
            signingKey: identity(1),
            healthConfig: PeerHealthConfig(keepaliveInterval: .zero))
        #expect(throws: IvyModeError.invalidConfiguration("peer health limits are invalid")) {
            try invalidHealth.validate()
        }
    }

}
