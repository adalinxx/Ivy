import Crypto
import Foundation
import Testing
@testable import Ivy

@Suite("Ivy v8 session protocol")
struct SessionProtocolTests {
    private func identity(_ byte: UInt8) -> Curve25519.Signing.PrivateKey {
        try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: byte, count: 32))
    }

    private func peerKey(_ identity: Curve25519.Signing.PrivateKey) -> PeerKey {
        try! PeerKey(rawRepresentation: identity.publicKey.rawRepresentation)
    }

    private func transcript() throws -> (
        SignedSessionHelloInitiator,
        SignedSessionHelloResponder,
        SessionID,
        Curve25519.Signing.PrivateKey,
        Curve25519.Signing.PrivateKey
    ) {
        let initiator = identity(1)
        let responder = identity(2)
        let helloI = SessionHelloInitiator(
            routeBinding: Data(repeating: 0x33, count: 32),
            initiator: peerKey(initiator),
            responder: peerKey(responder),
            nonce: Data(repeating: 0x11, count: 32),
            metadata: PeerMetadata(listenAddresses: [
                ListenAddress(host: "a.example", port: 4001),
            ]).encode()!)
        let signedI = try SignedSessionHelloInitiator.sign(helloI, with: initiator)
        let helloR = SessionHelloResponder(
            routeBinding: helloI.routeBinding,
            responder: helloI.responder,
            initiator: helloI.initiator,
            initiatorNonce: helloI.nonce,
            responderNonce: Data(repeating: 0x22, count: 32),
            metadata: PeerMetadata(listenAddresses: [
                ListenAddress(host: "r.example", port: 5001),
            ]).encode()!)
        let signedR = try SignedSessionHelloResponder.sign(helloR, with: responder)
        return (signedI, signedR, try SessionID(initiator: signedI, responder: signedR), initiator, responder)
    }

    @Test("metadata contains only canonical listen addresses")
    func canonicalMetadata() throws {
        let a = ListenAddress(host: "a.example", port: 4001)
        let z = ListenAddress(host: "z.example", port: 4002)
        let metadata = PeerMetadata(listenAddresses: [z, a, z])
        let encoded = try #require(metadata.encode())

        #expect(metadata.listenAddresses == [a, z])
        #expect(try PeerMetadata.decodeCanonical(encoded) == metadata)
    }

    @Test("signed responder hello and initiator finish authenticate one transcript")
    func handshake() throws {
        let (helloI, helloR, sessionID, initiatorIdentity, responderIdentity) = try transcript()
        let initiator = peerKey(initiatorIdentity)
        let responder = peerKey(responderIdentity)
        let finish = try SessionFinish.sign(
            sessionID: sessionID,
            sender: initiator,
            receiver: responder,
            with: initiatorIdentity)

        #expect(helloI.isValid())
        #expect(helloR.isValid())
        #expect(finish.isValid())
        #expect(try SessionID(initiator: helloI, responder: helloR) == sessionID)

        let otherSession = try SessionID(bytes: Data(repeating: 0xaa, count: 32))
        #expect(!SessionFinish(
            sessionID: otherSession,
            sender: finish.sender,
            receiver: finish.receiver,
            signature: finish.signature).isValid())
        #expect(!SessionFinish(
            sessionID: finish.sessionID,
            sender: responder,
            receiver: initiator,
            signature: finish.signature).isValid())

        let records: [SessionWireRecord] = [
            .helloInitiator(helloI),
            .helloResponder(helloR),
            .finish(finish),
        ]
        for record in records {
            #expect(try SessionWireRecord.deserialize(record.serialize()) == record)
        }
    }

    @Test("hello signatures bind identity and metadata")
    func helloTampering() throws {
        let (signed, _, _, _, wrongIdentity) = try transcript()
        var signature = signed.signature
        signature[0] ^= 1
        #expect(!SignedSessionHelloInitiator(hello: signed.hello, signature: signature).isValid())
        let signedByWrongIdentity = try SignedSessionHelloInitiator.sign(signed.hello, with: wrongIdentity)
        #expect(!signedByWrongIdentity.isValid())

        var metadata = signed.hello.metadata
        metadata[metadata.startIndex] ^= 1
        let changed = SessionHelloInitiator(
            routeBinding: signed.hello.routeBinding,
            initiator: signed.hello.initiator,
            responder: signed.hello.responder,
            nonce: signed.hello.nonce,
            metadata: metadata)
        #expect(!SignedSessionHelloInitiator(hello: changed, signature: signed.signature).isValid())
    }

    @Test("signed data is transcript-bound and strictly sequenced")
    func signedData() throws {
        let (_, _, sessionID, initiatorIdentity, responderIdentity) = try transcript()
        let initiator = peerKey(initiatorIdentity)
        let responder = peerKey(responderIdentity)
        let record = try SessionDataRecord.sign(
            sessionID: sessionID,
            sender: initiator,
            receiver: responder,
            sequence: 9,
            payload: Data("payload".utf8),
            with: initiatorIdentity)

        #expect(record.isValid(sender: initiator, receiver: responder))
        #expect(!record.isValid(sender: responder, receiver: initiator))
        #expect(
            try SessionWireRecord.deserialize(SessionWireRecord.data(record).serialize())
                == SessionWireRecord.data(record))

        var receive = SessionSequenceState()
        let first = receive.acceptIncoming(1)
        let gap = receive.acceptIncoming(9)
        let replay = receive.acceptIncoming(9)
        let earlier = receive.acceptIncoming(2)
        #expect(first)
        #expect(gap)
        #expect(!replay)
        #expect(!earlier)

        var send = SessionSequenceState(nextToSend: UInt64.max)
        let last = send.takeNextOutgoing()
        let exhausted = send.takeNextOutgoing()
        #expect(last == UInt64.max)
        #expect(exhausted == nil)
    }

    @Test("application frames are not session records")
    func rejectsApplicationFrame() {
        #expect(throws: (any Error).self) {
            try SessionWireRecord.deserialize(Message.ping(nonce: 1).serialize())
        }
    }
}
