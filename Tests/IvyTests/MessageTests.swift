import Crypto
import Foundation
import Testing
@testable import Ivy

@Suite("Message")
struct MessageTests {
    private func signedDataRecord(_ payload: Data, keyByte: UInt8) throws -> SessionWireRecord {
        let signingKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: keyByte, count: 32))
        let receiverKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: keyByte + 1, count: 32))
        let sender = try PeerKey(rawRepresentation: signingKey.publicKey.rawRepresentation)
        let receiver = try PeerKey(rawRepresentation: receiverKey.publicKey.rawRepresentation)
        let record = try SessionDataRecord.sign(
            sessionID: SessionID(bytes: Data(repeating: keyByte, count: 32)),
            sender: sender,
            receiver: receiver,
            sequence: 1,
            payload: payload,
            with: signingKey)
        return .data(record)
    }

    @Test("every v8 message roundtrips canonically")
    func roundtrip() throws {
        let endpoint = PeerEndpoint(publicKey: "peer", host: "192.0.2.1", port: 4001)
        let peerKey = try PeerKey(rawRepresentation: Data(repeating: 0x44, count: 32))
        let routeID = Data(repeating: 0x22, count: 32)
        let entries = [ContentEntry(cid: "root", data: Data([1, 2, 3]))]
        let messages: [Message] = [
            .ping(nonce: 1),
            .pong(nonce: 1),
            .findNode(target: Data(repeating: 0xab, count: 32), nonce: 2),
            .neighbors([endpoint], nonce: 2),
            .contentRequest(requestID: 3, rootCID: "root", cids: ["child"]),
            .contentResponse(requestID: 3, entries: entries),
            .contentUnavailable(requestID: 3),
            .findProviders(rootCID: "root", requestID: 4),
            .providers(
                rootCID: "root",
                requestID: 4,
                records: [ProviderRecord(endpoint: endpoint, expiresAt: 123)]),
            .announceProvider(rootCID: "root", expiresAt: 123),
            .relayOpen(routeID: routeID, targetKey: peerKey),
            .relayOffer(routeID: routeID, sourceKey: peerKey),
            .relayAccept(routeID: routeID, status: 1),
            .relayReady(routeID: routeID, status: 0),
            .relayPacket(routeID: routeID, opaqueEndpointRecord: Data([4, 5, 6])),
            .relayClose(routeID: routeID),
            .peerMessage(topic: "topic", payload: Data("hello".utf8)),
        ]

        for message in messages {
            let encoded = message.serialize()
            #expect(!encoded.isEmpty)
            #expect(Message.deserialize(encoded)?.serialize() == encoded)
        }
    }

    @Test("targeted content preserves selection and bytes")
    func targetedContent() {
        let request = Message.contentRequest(
            requestID: 11,
            rootCID: "root",
            cids: ["child-a", "child-b"])
        guard case .contentRequest(let requestID, let root, let cids) = Message.deserialize(request.serialize()) else {
            Issue.record("Expected content request")
            return
        }
        #expect(requestID == 11)
        #expect(root == "root")
        #expect(cids == ["child-a", "child-b"])

        let entries = [
            ContentEntry(cid: "root", data: Data([1])),
            ContentEntry(cid: "child-a", data: Data([2, 3])),
        ]
        guard case .contentResponse(let responseID, let decoded) = Message.deserialize(
            Message.contentResponse(requestID: 11, entries: entries).serialize()
        ) else {
            Issue.record("Expected content response")
            return
        }
        #expect(responseID == 11)
        #expect(decoded == entries)
    }

    @Test("content response budgets exactly include direct and relayed framing")
    func contentResponseBudgets() throws {
        let frameSize: UInt32 = 512
        let cids = ["root", "child"]
        let directBudget = try #require(Message.contentResponseDataBudget(
            for: cids,
            maxFrameSize: frameSize,
            relayed: false))
        let relayedBudget = try #require(Message.contentResponseDataBudget(
            for: cids,
            maxFrameSize: frameSize,
            relayed: true))
        #expect(directBudget == 367)
        #expect(relayedBudget == 217)

        func response(_ dataBytes: Int) -> Data {
            Message.contentResponse(requestID: 1, entries: [
                ContentEntry(cid: "root", data: Data(repeating: 0xaa, count: dataBytes)),
                ContentEntry(cid: "child", data: Data()),
            ]).serialize(maxFrameSize: frameSize)
        }

        #expect(try signedDataRecord(response(directBudget), keyByte: 1)
            .serialize(maxPayload: frameSize).count == Int(frameSize))
        #expect(try signedDataRecord(response(directBudget + 1), keyByte: 1)
            .serialize(maxPayload: frameSize).isEmpty)

        let routeID = Data(repeating: 0x44, count: 32)
        let endpointRecord = try signedDataRecord(response(relayedBudget), keyByte: 1)
            .serialize(maxPayload: frameSize)
        let relayPacket = Message.relayPacket(
            routeID: routeID,
            opaqueEndpointRecord: endpointRecord
        ).serialize(maxFrameSize: frameSize)
        #expect(try signedDataRecord(relayPacket, keyByte: 3)
            .serialize(maxPayload: frameSize).count == Int(frameSize))

        let oversizedEndpointRecord = try signedDataRecord(response(relayedBudget + 1), keyByte: 1)
            .serialize(maxPayload: frameSize)
        let oversizedRelayPacket = Message.relayPacket(
            routeID: routeID,
            opaqueEndpointRecord: oversizedEndpointRecord
        ).serialize(maxFrameSize: frameSize)
        #expect(try signedDataRecord(oversizedRelayPacket, keyByte: 3)
            .serialize(maxPayload: frameSize).isEmpty)
    }

    @Test("content response serialization preflights its exact aggregate size")
    func contentResponsePreflight() {
        let exact = Message.contentResponse(
            requestID: 1,
            entries: [ContentEntry(cid: "root", data: Data(repeating: 0xaa, count: 11))])
        let oversized = Message.contentResponse(
            requestID: 1,
            entries: [ContentEntry(cid: "root", data: Data(repeating: 0xaa, count: 12))])

        #expect(exact.serialize(maxFrameSize: 32).count == 32)
        #expect(oversized.serialize(maxFrameSize: 32).isEmpty)
    }

    @Test("malformed messages and invalid identifiers are rejected")
    func malformed() {
        #expect(Message.deserialize(Data()) == nil)
        #expect(Message.deserialize(Data([255])) == nil)

        var trailing = Message.ping(nonce: 1).serialize()
        trailing.append(0)
        #expect(Message.deserialize(trailing) == nil)

        #expect(Message.deserialize(
            Message.contentRequest(requestID: 0, rootCID: "root", cids: []).serialize()) == nil)
        #expect(Message.deserialize(Message.contentResponse(requestID: 0, entries: []).serialize()) == nil)
        #expect(Message.deserialize(Message.contentUnavailable(requestID: 0).serialize()) == nil)
        #expect(Message.relayReady(routeID: Data([1]), status: 0).serialize().isEmpty)
    }

}
