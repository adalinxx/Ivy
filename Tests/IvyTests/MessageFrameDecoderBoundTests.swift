import Foundation
import NIOCore
import NIOEmbedded
import Testing
@testable import Ivy

private final class SessionFrameCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = Data
    private(set) var records: [Data] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        records.append(unwrapInboundIn(data))
    }
}

@Suite("Session frame bounds")
struct MessageFrameDecoderBoundTests {
    private static let limit: UInt32 = 1024

    private func channel() throws -> (EmbeddedChannel, SessionFrameCollector) {
        let collector = SessionFrameCollector()
        let channel = EmbeddedChannel()
        try channel.pipeline.addHandler(SessionFrameDecoder(maxFrameSize: Self.limit)).wait()
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
}
