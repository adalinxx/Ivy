import Crypto
import Foundation
import NIOEmbedded
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

    @Test("frozen v8 session vectors")
    func frozenV8Vectors() throws {
        let route = Data(repeating: 0x11, count: 32)
        let initiator = try PeerKey(rawRepresentation: Data(repeating: 0x22, count: 32))
        let responder = try PeerKey(rawRepresentation: Data(repeating: 0x33, count: 32))
        let metadata = Data([0, 0])
        let helloI = SessionHelloInitiator(
            routeBinding: route,
            initiator: initiator,
            responder: responder,
            nonce: Data(repeating: 0x44, count: 32),
            metadata: metadata)
        let helloIHex = "0008"
            + String(repeating: "11", count: 32)
            + String(repeating: "22", count: 32)
            + String(repeating: "33", count: 32)
            + String(repeating: "44", count: 32)
            + "000000020000"
        let expectedHelloI = try #require(Data(hexString: helloIHex))
        #expect(helloI.encode() == expectedHelloI)
        #expect(try SessionHelloInitiator.decode(expectedHelloI) == helloI)

        let signedI = SignedSessionHelloInitiator(
            hello: helloI,
            signature: Data(repeating: 0x55, count: 64))
        let expectedWireI = try #require(Data(hexString:
            "495659080100000088" + helloIHex + String(repeating: "55", count: 64)))
        #expect(SessionWireRecord.helloInitiator(signedI).serialize() == expectedWireI)
        #expect(try SessionWireRecord.deserialize(expectedWireI) == .helloInitiator(signedI))
        var legacyWireI = expectedWireI
        legacyWireI[legacyWireI.startIndex + 3] = 0x07
        #expect(throws: (any Error).self) {
            try SessionWireRecord.deserialize(legacyWireI)
        }

        let helloR = SessionHelloResponder(
            routeBinding: route,
            responder: responder,
            initiator: initiator,
            initiatorNonce: Data(repeating: 0x44, count: 32),
            responderNonce: Data(repeating: 0x66, count: 32),
            metadata: metadata)
        let helloRHex = "0008"
            + String(repeating: "11", count: 32)
            + String(repeating: "33", count: 32)
            + String(repeating: "22", count: 32)
            + String(repeating: "44", count: 32)
            + String(repeating: "66", count: 32)
            + "000000020000"
        let signedR = SignedSessionHelloResponder(
            hello: helloR,
            signature: Data(repeating: 0x77, count: 64))
        let expectedWireR = try #require(Data(hexString:
            "4956590802000000a8" + helloRHex + String(repeating: "77", count: 64)))
        #expect(SessionWireRecord.helloResponder(signedR).serialize() == expectedWireR)
        #expect(try SessionWireRecord.deserialize(expectedWireR) == .helloResponder(signedR))

        let sessionID = try SessionID(bytes: Data(repeating: 0x88, count: 32))
        let finish = SessionFinish(
            sessionID: sessionID,
            sender: initiator,
            receiver: responder,
            signature: Data(repeating: 0x99, count: 64))
        let expectedFinish = try #require(Data(hexString:
            "4956590803"
                + String(repeating: "88", count: 32)
                + String(repeating: "22", count: 32)
                + String(repeating: "33", count: 32)
                + String(repeating: "99", count: 64)))
        #expect(SessionWireRecord.finish(finish).serialize() == expectedFinish)
        #expect(try SessionWireRecord.deserialize(expectedFinish) == .finish(finish))

        let dataRecord = SessionDataRecord(
            sessionID: sessionID,
            sequence: 1,
            payload: Data([0xaa, 0xbb]),
            signature: Data(repeating: 0xcc, count: 64))
        let expectedData = try #require(Data(hexString:
            "4956590804"
                + String(repeating: "88", count: 32)
                + "000000000000000100000002aabb"
                + String(repeating: "cc", count: 64)))
        #expect(SessionWireRecord.data(dataRecord).serialize() == expectedData)
        #expect(try SessionWireRecord.deserialize(expectedData) == .data(dataRecord))
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
        #expect(!receive.canAcceptIncoming(9))
        #expect(receive.canAcceptIncoming(10))

        var send = SessionSequenceState(nextToSend: UInt64.max)
        let last = send.takeNextOutgoing()
        let exhausted = send.takeNextOutgoing()
        #expect(last == UInt64.max)
        #expect(exhausted == nil)
    }

    @Test("direct handshake rejects a mismatched route binding")
    func directRouteBindingMismatch() async throws {
        let localIdentity = identity(1)
        let remoteIdentity = identity(2)
        let local = peerKey(localIdentity)
        let remote = peerKey(remoteIdentity)
        let ivy = Ivy(config: IvyConfig(signingKey: localIdentity, stunServers: []))
        let channel = EmbeddedChannel()
        defer { _ = try? channel.finish() }
        let connection = PeerConnection(
            endpoint: PeerEndpoint(publicKey: remote.hex, host: "127.0.0.1", port: 4001),
            channel: channel,
            inboundByteBudget: InboundByteBudget(limit: IvyConfig.defaultMaxInboundBufferedBytes))
        let metadata = try #require(PeerMetadata().encode())
        let matching = SessionHelloInitiator(
            routeBinding: Ivy.directRouteBinding,
            initiator: remote,
            responder: local,
            nonce: Data(repeating: 1, count: 32),
            metadata: metadata)
        let mismatched = SessionHelloInitiator(
            routeBinding: Data(repeating: 1, count: 32),
            initiator: remote,
            responder: local,
            nonce: matching.nonce,
            metadata: metadata)

        let acceptsMatching = await ivy.acceptsInboundHello(matching, on: connection)
        let acceptsMismatched = await ivy.acceptsInboundHello(mismatched, on: connection)
        #expect(acceptsMatching)
        #expect(!acceptsMismatched)
    }

    @Test("duplicate sessions prefer the smaller session ID")
    func preferredSessionID() throws {
        let smaller = try SessionID(bytes: Data(repeating: 1, count: 32))
        let larger = try SessionID(bytes: Data(repeating: 2, count: 32))

        #expect(Ivy.preferredSessionID(larger, smaller) == smaller)
        #expect(Ivy.preferredSessionID(smaller, larger) == smaller)
    }

    @Test("application frames are not session records")
    func rejectsApplicationFrame() {
        #expect(throws: (any Error).self) {
            try SessionWireRecord.deserialize(Message.ping(nonce: 1).serialize())
        }
    }

    @Test("protocol violations require endpoint-authenticated evidence")
    func violationAttribution() {
        let peer = peerKey(identity(3))

        #expect(Ivy.attributedPeer(peer, direct: true, evidence: .unverified) == nil)
        #expect(Ivy.attributedPeer(peer, direct: false, evidence: .unverified) == nil)
        #expect(Ivy.attributedPeer(peer, direct: true, evidence: .signedTransport) == peer)
        #expect(Ivy.attributedPeer(peer, direct: false, evidence: .signedTransport) == nil)
        #expect(Ivy.attributedPeer(peer, direct: true, evidence: .signedPayload) == peer)
        #expect(Ivy.attributedPeer(peer, direct: false, evidence: .signedPayload) == peer)
    }
}
