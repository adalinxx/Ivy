import Foundation
import NIOCore
import NIOEmbedded
import Testing
@testable import Ivy

private final class SessionFrameCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = InboundFrame
    private(set) var records: [Data] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        records.append(unwrapInboundIn(data).bytes)
    }
}

@Suite("Session frame bounds")
struct MessageFrameDecoderBoundTests {
    private static let limit: UInt32 = 1024

    private func channel(
        budget: InboundByteBudget = InboundByteBudget(limit: Int(Self.limit) + 4)
    ) throws -> (EmbeddedChannel, SessionFrameCollector) {
        let collector = SessionFrameCollector()
        let channel = EmbeddedChannel()
        try channel.pipeline.addHandler(SessionFrameDecoder(
            maxFrameSize: Self.limit,
            budget: budget)).wait()
        try channel.pipeline.addHandler(collector).wait()
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 4001)).wait()
        return (channel, collector)
    }

    @Test("oversized declared record closes before body allocation")
    func oversizedLength() throws {
        let (channel, collector) = try channel()
        var header = channel.allocator.buffer(capacity: 4)
        header.writeInteger(Self.limit + 1, endianness: .big, as: UInt32.self)
        _ = try? channel.writeInbound(header)
        #expect(!channel.isActive)
        #expect(collector.records.isEmpty)
    }

    @Test("bounded records are delivered unchanged")
    func boundedRecord() throws {
        let (channel, collector) = try channel()
        let record = Data([0x49, 0x56, 0x59, 0x08, 0x01])
        var frame = channel.allocator.buffer(capacity: 4 + record.count)
        frame.writeInteger(UInt32(record.count), endianness: .big, as: UInt32.self)
        frame.writeBytes(record)
        try channel.writeInbound(frame)
        #expect(collector.records == [record])
        _ = try channel.finish()
    }

    @Test("zero-length records close as malformed wire")
    func zeroLength() throws {
        let (channel, collector) = try channel()
        var frame = channel.allocator.buffer(capacity: 4)
        frame.writeInteger(UInt32(0), endianness: .big, as: UInt32.self)
        _ = try? channel.writeInbound(frame)
        #expect(!channel.isActive)
        #expect(collector.records.isEmpty)
    }

    @Test("partial headers and bodies hold the shared byte budget")
    func partialFramesShareBudget() throws {
        let budget = InboundByteBudget(limit: Int(Self.limit) + 4)
        let (bodyChannel, _) = try channel(budget: budget)
        var partialBody = bodyChannel.allocator.buffer(capacity: 5)
        partialBody.writeInteger(Self.limit, endianness: .big, as: UInt32.self)
        partialBody.writeInteger(UInt8(1))
        try bodyChannel.writeInbound(partialBody)
        #expect(budget.currentUsage == Int(Self.limit))

        let (competingChannel, _) = try channel(budget: budget)
        var competing = competingChannel.allocator.buffer(capacity: 4)
        competing.writeInteger(UInt32(1), endianness: .big, as: UInt32.self)
        _ = try? competingChannel.writeInbound(competing)
        #expect(!competingChannel.isActive)
        #expect(budget.currentUsage == Int(Self.limit))

        _ = try bodyChannel.finish()
        #expect(budget.currentUsage == 0)
    }

    @Test("closing a partial header releases its reservation")
    func partialHeaderClose() throws {
        let budget = InboundByteBudget(limit: 4)
        let (channel, _) = try channel(budget: budget)
        var byte = channel.allocator.buffer(capacity: 1)
        byte.writeInteger(UInt8(0))
        try channel.writeInbound(byte)
        #expect(budget.currentUsage == 4)
        _ = try channel.finish()
        #expect(budget.currentUsage == 0)
    }
}
