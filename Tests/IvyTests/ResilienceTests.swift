import Foundation
import NIOEmbedded
import Testing
@testable import Ivy
import Tally

@Suite("Live transport bounds")
struct ResilienceTests {
    @Test("application records obey the negotiated frame cap")
    func frameCap() {
        let message = Message.peerMessage(
            topic: "state",
            payload: Data(repeating: 0xAB, count: 128))

        #expect(message.serialize(maxFrameSize: 64).isEmpty)

        let encoded = message.serialize(maxFrameSize: 256)
        guard case .peerMessage(let topic, let payload)? =
                Message.deserialize(encoded, maxDataPayload: 256) else {
            Issue.record("bounded peer message did not round-trip")
            return
        }
        #expect(topic == "state")
        #expect(payload == Data(repeating: 0xAB, count: 128))
    }

    @Test("message parser rejects oversized bounded fields")
    func parserBounds() {
        let longTopic = String(
            repeating: "x",
            count: Int(MessageLimits.maxStringLength) + 1)
        #expect(Message.peerMessage(topic: longTopic, payload: Data()).serialize().isEmpty)

        var malformed = Data()
        malformed.appendUInt8(26)
        malformed.appendUInt64(1)
        malformed.appendUInt16(4)
        malformed.append(Data("root".utf8))
        malformed.appendUInt16(MessageLimits.maxContentCIDCount + 1)
        #expect(Message.deserialize(malformed) == nil)
    }

    @Test("inbound queue overflow preserves order and closes the connection")
    func inboundQueue() async {
        let channel = EmbeddedChannel()
        let connection = PeerConnection(
            endpoint: PeerEndpoint(publicKey: "", host: "127.0.0.1", port: 1),
            channel: channel)

        for value in 0..<connection.inboundBufferLimit {
            #expect(connection.feedRecord(Data([UInt8(value)])))
        }
        #expect(!connection.feedRecord(Data([0xff])))
        #expect(!connection.isLive)

        var received: [UInt8] = []
        for await record in connection.records {
            if let byte = record.first { received.append(byte) }
        }

        #expect(received.count == connection.inboundBufferLimit)
        #expect(received.first == 0)
        #expect(received.last == UInt8(connection.inboundBufferLimit - 1))
        #expect(connection.inboundBufferLimit * Int(IvyConfig.defaultMaxFrameSize)
            <= PeerConnection.inboundBufferByteBudget)
    }
}
