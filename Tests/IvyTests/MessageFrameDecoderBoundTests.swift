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

    private func framed(_ records: [Data]) -> [UInt8] {
        records.flatMap { record in
            let count = UInt32(record.count)
            return [
                UInt8(truncatingIfNeeded: count >> 24),
                UInt8(truncatingIfNeeded: count >> 16),
                UInt8(truncatingIfNeeded: count >> 8),
                UInt8(truncatingIfNeeded: count),
            ] + record
        }
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

    @Test("every stream split delivers the same records")
    func everySplit() throws {
        let records = [
            Data([0x49, 0x56, 0x59, 0x08, 0x01]),
            Data([0xaa, 0xbb, 0xcc]),
        ]
        let stream = framed(records)

        for split in 0...stream.count {
            let budget = InboundByteBudget(limit: Int(Self.limit) + 4)
            let (channel, collector) = try channel(budget: budget)
            if split > 0 {
                var first = channel.allocator.buffer(capacity: split)
                first.writeBytes(stream[..<split])
                try channel.writeInbound(first)
            }
            if split < stream.count {
                var second = channel.allocator.buffer(capacity: stream.count - split)
                second.writeBytes(stream[split...])
                try channel.writeInbound(second)
            }
            #expect(collector.records == records, "split \(split)")
            _ = try channel.finish()
            #expect(budget.currentUsage == 0, "split \(split)")
        }
    }

    @Test("coalesced frames preserve record boundaries")
    func coalescedFrames() throws {
        let records = [Data([1]), Data([2, 3]), Data([4, 5, 6])]
        let (channel, collector) = try channel()
        var stream = channel.allocator.buffer(capacity: 18)
        stream.writeBytes(framed(records))

        try channel.writeInbound(stream)

        #expect(collector.records == records)
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

    @Test("byte-at-a-time slowloris input releases its reservation on close")
    func slowlorisClose() throws {
        let budget = InboundByteBudget(limit: Int(Self.limit) + 4)
        let (channel, collector) = try channel(budget: budget)
        let partial = framed([Data(repeating: 0xaa, count: Int(Self.limit))]).prefix(12)

        for byte in partial {
            var input = channel.allocator.buffer(capacity: 1)
            input.writeInteger(byte)
            try channel.writeInbound(input)
        }
        #expect(collector.records.isEmpty)
        #expect(budget.currentUsage == Int(Self.limit))

        _ = try channel.finish()
        #expect(budget.currentUsage == 0)
    }

    @Test("seeded hostile mutations never leak frame budget")
    func seededHostileMutations() throws {
        var generator = TestSeededGenerator(seed: 0x4956_5908)
        let corpus = [
            Message.ping(nonce: 1).serialize(),
            Message.contentRequest(requestID: 1, rootCID: "root", cids: ["child"]).serialize(),
            Message.peerMessage(topic: "state", payload: Data([1, 2, 3])).serialize(),
        ]

        for iteration in 0..<256 {
            var body = corpus[Int(generator.next() % UInt64(corpus.count))]
            switch generator.next() % 4 {
            case 0 where !body.isEmpty:
                body[Int(generator.next() % UInt64(body.count))] ^= UInt8(1 << (generator.next() % 8))
            case 1 where !body.isEmpty:
                body.removeLast(Int(generator.next() % UInt64(body.count)) + 1)
            case 2:
                body.append(UInt8(truncatingIfNeeded: generator.next()))
            default:
                body = Data((0..<Int(generator.next() % 32)).map { _ in
                    UInt8(truncatingIfNeeded: generator.next())
                })
            }

            if let accepted = Message.deserialize(body) {
                #expect(accepted.serialize() == body, "iteration \(iteration)")
            }

            let budget = InboundByteBudget(limit: Int(Self.limit) + 4)
            let (channel, collector) = try channel(budget: budget)
            var bytes = framed([body.isEmpty ? Data([0]) : body])
            if generator.next() & 1 == 1, !bytes.isEmpty {
                bytes[Int(generator.next() % UInt64(bytes.count))] ^= 1
            }
            var input = channel.allocator.buffer(capacity: bytes.count)
            input.writeBytes(bytes)
            _ = try? channel.writeInbound(input)
            for record in collector.records {
                if let accepted = Message.deserialize(record) {
                    #expect(accepted.serialize() == record, "iteration \(iteration)")
                }
            }
            _ = try? channel.finish()
            #expect(budget.currentUsage == 0, "iteration \(iteration)")
        }
    }
}
