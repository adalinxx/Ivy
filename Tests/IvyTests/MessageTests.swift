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

    @Test("frozen v9 message vectors")
    func frozenV9Vectors() throws {
        let route = String(repeating: "11", count: 32)
        let keyBytes = String(repeating: "44", count: 32)
        let key = try PeerKey(rawRepresentation: Data(repeating: 0x44, count: 32))
        let target = String(repeating: "ab", count: 32)
        let endpoint = PeerEndpoint(publicKey: "pk", host: "h", port: 0x1234)
        let vectors: [(Message, String)] = [
            (.ping(nonce: 0x0102_0304_0506_0708), "000102030405060708"),
            (.pong(nonce: 0x0102_0304_0506_0708), "010102030405060708"),
            (.findNode(target: Data(repeating: 0xab, count: 32), nonce: 2),
             "0500000020\(target)0000000000000002"),
            (.neighbors([], nonce: 2), "0600000000000000000002"),
            (.neighbors([endpoint], nonce: 2),
             "0600010002706b00016812340000000000000002"),
            (.contentRequest(requestID: 3, rootCID: "r", cids: []),
             "1a00000000000000030001720000"),
            (.contentRequest(requestID: 3, rootCID: "r", cids: ["a", "bc"]),
             "1a0000000000000003000172000200016100026263"),
            (.contentResponse(requestID: 3, entries: []), "3200000000000000030000"),
            (.contentResponse(requestID: 3, entries: [
                ContentEntry(cid: "r", data: Data([1, 2])),
                ContentEntry(cid: "x", data: Data()),
            ]), "320000000000000003000200017200000002010200017800000000"),
            (.contentUnavailable(requestID: 3), "3a0000000000000003"),
            (.volumeRequest(requestID: 3, rootCID: "r"),
             "1b0000000000000003000172"),
            (.volumeChunk(
                requestID: 3,
                rootCID: "r",
                index: 0,
                count: 1,
                totalEntries: 1,
                totalBytes: 2,
                payload: Data([0xaa, 0xbb])
             ), "1c0000000000000003000172000000010001000000000000000200000002aabb"),
            (.findProviders(rootCID: "r", requestID: 4), "280001720000000000000004"),
            (.providers(rootCID: "r", requestID: 4, records: []),
             "2900017200000000000000000004"),
            (.providers(
                rootCID: "r",
                requestID: 4,
                records: [ProviderRecord(endpoint: endpoint, expiresAt: 0x0102_0304_0506_0708)]),
             "2900017200010002706b000168123401020304050607080000000000000004"),
            (.announceProvider(rootCID: "r", expiresAt: 5), "2a0001720000000000000005"),
            (.relayOpen(routeID: Data(repeating: 0x11, count: 32), targetKey: key),
             "3c\(route)\(keyBytes)"),
            (.relayOffer(routeID: Data(repeating: 0x11, count: 32), sourceKey: key),
             "3d\(route)\(keyBytes)"),
            (.relayAccept(routeID: Data(repeating: 0x11, count: 32), status: 1),
             "3e\(route)01"),
            (.relayReady(routeID: Data(repeating: 0x11, count: 32), status: 0),
             "3f\(route)00"),
            (.relayPacket(
                routeID: Data(repeating: 0x11, count: 32),
                opaqueEndpointRecord: Data([4, 5, 6])),
             "40\(route)00000003040506"),
            (.relayClose(routeID: Data(repeating: 0x11, count: 32)), "41\(route)"),
            (.peerMessage(topic: "t", payload: Data([0xaa])), "3100017400000001aa"),
        ]

        for (message, hex) in vectors {
            let expected = try #require(Data(hexString: hex))
            #expect(message.serialize() == expected)
            #expect(Message.deserialize(expected)?.serialize() == expected)
        }
    }

    @Test("every v9 message roundtrips canonically")
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
            .volumeRequest(requestID: 3, rootCID: "root"),
            .volumeChunk(
                requestID: 3,
                rootCID: "root",
                index: 0,
                count: 1,
                totalEntries: 1,
                totalBytes: 3,
                payload: Data([1, 2, 3])
            ),
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

    @Test("Volume chunks exactly include direct and relayed framing")
    func volumeChunkBudgets() throws {
        let frameSize: UInt32 = 512
        let directBudget = try #require(Message.volumeChunkDataBudget(
            rootCID: "root",
            maxFrameSize: frameSize,
            relayed: false
        ))
        let relayedBudget = try #require(Message.volumeChunkDataBudget(
            rootCID: "root",
            maxFrameSize: frameSize,
            relayed: true
        ))
        #expect(directBudget == 366)
        #expect(relayedBudget == 216)

        func chunk(_ payloadBytes: Int) -> Data {
            Message.volumeChunk(
                requestID: 1,
                rootCID: "root",
                index: 0,
                count: 1,
                totalEntries: 1,
                totalBytes: UInt64(payloadBytes),
                payload: Data(repeating: 0xaa, count: payloadBytes)
            ).serialize(maxFrameSize: frameSize)
        }

        #expect(try signedDataRecord(chunk(directBudget), keyByte: 1)
            .serialize(maxPayload: frameSize).count == Int(frameSize))
        #expect(try signedDataRecord(chunk(directBudget + 1), keyByte: 1)
            .serialize(maxPayload: frameSize).isEmpty)

        let routeID = Data(repeating: 0x44, count: 32)
        let endpointRecord = try signedDataRecord(chunk(relayedBudget), keyByte: 1)
            .serialize(maxPayload: frameSize)
        let relayPacket = Message.relayPacket(
            routeID: routeID,
            opaqueEndpointRecord: endpointRecord
        ).serialize(maxFrameSize: frameSize)
        #expect(try signedDataRecord(relayPacket, keyByte: 3)
            .serialize(maxPayload: frameSize).count == Int(frameSize))

        let oversizedEndpointRecord = try signedDataRecord(
            chunk(relayedBudget + 1),
            keyByte: 1
        ).serialize(maxPayload: frameSize)
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

        var zeroContentRequest = Message.contentRequest(
            requestID: 1,
            rootCID: "root",
            cids: []).serialize()
        zeroContentRequest.replaceSubrange(1..<9, with: repeatElement(0, count: 8))
        #expect(Message.deserialize(zeroContentRequest) == nil)

        var zeroContentResponse = Message.contentResponse(
            requestID: 1,
            entries: []).serialize()
        zeroContentResponse.replaceSubrange(1..<9, with: repeatElement(0, count: 8))
        #expect(Message.deserialize(zeroContentResponse) == nil)

        var zeroUnavailable = Message.contentUnavailable(requestID: 1).serialize()
        zeroUnavailable.replaceSubrange(1..<9, with: repeatElement(0, count: 8))
        #expect(Message.deserialize(zeroUnavailable) == nil)

        var zeroFindProviders = Message.findProviders(
            rootCID: "root",
            requestID: 1).serialize()
        zeroFindProviders.replaceSubrange(
            (zeroFindProviders.count - 8)..<zeroFindProviders.count,
            with: repeatElement(0, count: 8))
        #expect(Message.deserialize(zeroFindProviders) == nil)

        var zeroProviders = Message.providers(
            rootCID: "root",
            requestID: 1,
            records: []).serialize()
        zeroProviders.replaceSubrange(
            (zeroProviders.count - 8)..<zeroProviders.count,
            with: repeatElement(0, count: 8))
        #expect(Message.deserialize(zeroProviders) == nil)
        #expect(Message.relayReady(routeID: Data([1]), status: 0).serialize().isEmpty)

        let unicodeEquivalent = ["\u{00e9}", "e\u{0301}"]
        #expect(unicodeEquivalent[0] == unicodeEquivalent[1])
        for identifier in unicodeEquivalent {
            #expect(Message.contentRequest(
                requestID: 1,
                rootCID: identifier,
                cids: []).serialize().isEmpty)
            #expect(Message.findProviders(
                rootCID: identifier,
                requestID: 1).serialize().isEmpty)
            #expect(Message.announceProvider(
                rootCID: identifier,
                expiresAt: 1).serialize().isEmpty)
        }
    }

}
