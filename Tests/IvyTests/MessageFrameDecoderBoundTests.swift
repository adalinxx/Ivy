import Testing
import Foundation
import NIOCore
import NIOEmbedded
@testable import Ivy

/// Records every `Message` the decoder fires downstream so tests can assert
/// whether a frame body was consumed and delivered.
private final class FrameTailCollector: ChannelInboundHandler {
    typealias InboundIn = Message

    private(set) var messages: [Message] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        messages.append(unwrapInboundIn(data))
    }
}

/// Regression coverage for: the inbound `MessageFrameDecoder` must reject
/// a frame whose declared `[UInt32 length]` prefix exceeds `maxFrameSize` BEFORE
/// it reads/allocates the body. These tests drive the real decoder through an
/// `EmbeddedChannel` so they fail if the bound is ever moved after `readData`.
@Suite("MessageFrameDecoder frame bound")
struct MessageFrameDecoderBoundTests {

    // A small, explicit cap (well under IvyConfig.defaultMaxFrameSize) passed to
    // the real decoder via the same `init(maxFrameSize:)` the production dial path
    // uses, so the oversized-length test never has to materialize a large body.
    private static let testMaxFrameSize: UInt32 = 1024

    private func makeChannel() throws -> (EmbeddedChannel, FrameTailCollector) {
        let collector = FrameTailCollector()
        let channel = EmbeddedChannel()
        try channel.pipeline.addHandler(
            MessageFrameDecoder(maxFrameSize: Self.testMaxFrameSize)
        ).wait()
        try channel.pipeline.addHandler(collector).wait()
        // Activate the channel so `isActive` is meaningful: it must read `true`
        // before the oversized read and flip to `false` only because the decoder
        // closed it (not merely because it was never connected).
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 4001)).wait()
        #expect(channel.isActive == true)
        return (channel, collector)
    }

    @Test("Oversized declared length closes the channel before reading the body")
    func oversizedLengthClosesBeforeBodyRead() throws {
        let (channel, collector) = try makeChannel()

        // Declared length exceeds maxFrameSize. We deliberately send NO body
        // bytes: if the bound were checked AFTER readData, the decoder would
        // either block awaiting bytes (no close) or attempt to allocate the
        // declared length. The production ordering closes immediately.
        let declared = Self.testMaxFrameSize + 1
        var header = channel.allocator.buffer(capacity: 4)
        header.writeInteger(declared, endianness: .big, as: UInt32.self)

        // writeInbound throws if a downstream handler (the close) rejects, so we
        // tolerate either outcome and assert on channel state below.
        _ = try? channel.writeInbound(header)

        #expect(channel.isActive == false)
        #expect(collector.messages.isEmpty)

        // No decoded Message should have been delivered downstream.
        let delivered: Message? = try? channel.readInbound()
        #expect(delivered == nil)
    }

    @Test("Within-bound frame decodes and is delivered intact")
    func withinBoundFrameDelivered() throws {
        let (channel, collector) = try makeChannel()

        let message = Message.ping(nonce: 0xABCD)
        let payload = message.serialize(maxFrameSize: Self.testMaxFrameSize)
        #expect(!payload.isEmpty)
        #expect(payload.count <= Int(Self.testMaxFrameSize))

        var frame = channel.allocator.buffer(capacity: 4 + payload.count)
        frame.writeInteger(UInt32(payload.count), endianness: .big, as: UInt32.self)
        frame.writeBytes(payload)

        try channel.writeInbound(frame)

        #expect(channel.isActive == true)
        #expect(collector.messages.count == 1)
        if case .ping(let nonce) = collector.messages.first {
            #expect(nonce == 0xABCD)
        } else {
            Issue.record("Expected a decoded ping frame to be delivered intact")
        }

        _ = try channel.finish()
    }

    @Test("Zero-length frame is skipped and subsequent frame is processed")
    func zeroLengthFrameDoesNotCloseConnection() throws {
        let (channel, collector) = try makeChannel()

        let message = Message.ping(nonce: 0xF00D)
        let payload = message.serialize(maxFrameSize: Self.testMaxFrameSize)
        #expect(!payload.isEmpty)

        var frame = channel.allocator.buffer(capacity: 8 + payload.count)
        frame.writeInteger(UInt32(0), endianness: .big, as: UInt32.self)
        frame.writeInteger(UInt32(payload.count), endianness: .big, as: UInt32.self)
        frame.writeBytes(payload)

        try channel.writeInbound(frame)

        #expect(channel.isActive == true)
        #expect(collector.messages.count == 1)
        if case .ping(let nonce) = collector.messages.first {
            #expect(nonce == 0xF00D)
        } else {
            Issue.record("Expected ping after zero-length frame")
        }

        _ = try channel.finish()
    }
}
