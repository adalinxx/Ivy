import Foundation
import NIOCore
import NIOEmbedded
import Testing
@testable import Ivy

@Suite("Session frame bounds")
struct MessageFrameDecoderBoundTests {
    private static let limit: UInt32 = 1024

    private func accumulator(
        budget: InboundByteBudget = InboundByteBudget(limit: Int(Self.limit) + 4),
        connectionBudget: InboundByteBudget? = nil
    ) -> SessionFrameAccumulator {
        SessionFrameAccumulator(
            maxFrameSize: Self.limit,
            budget: budget,
            connectionBudget: connectionBudget
                ?? InboundByteBudget(limit: 2 * Int(Self.limit) + 4))
    }

    @discardableResult
    private func decode(
        _ bytes: [UInt8],
        with accumulator: SessionFrameAccumulator,
        into records: inout [Data]
    ) -> Bool {
        var input = ByteBufferAllocator().buffer(capacity: bytes.count)
        input.writeBytes(bytes)
        while input.readableBytes > 0 {
            switch accumulator.nextFrame(from: &input) {
            case .frame(let frame):
                records.append(frame.bytes)
            case .incomplete:
                return true
            case .invalid:
                return false
            }
        }
        return true
    }

    private func lengthPrefix(_ length: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: length >> 24),
            UInt8(truncatingIfNeeded: length >> 16),
            UInt8(truncatingIfNeeded: length >> 8),
            UInt8(truncatingIfNeeded: length),
        ]
    }

    private func framed(_ records: [Data]) -> [UInt8] {
        records.flatMap { record in
            lengthPrefix(UInt32(record.count)) + record
        }
    }

    @Test("inbound async bridge receives independently owned bytes")
    func inboundBridgeOwnership() throws {
        let channel = EmbeddedChannel(handlers: [InboundBufferCopyHandler()])
        defer { _ = try? channel.finish() }
        var source = ByteBuffer(bytes: [0, 1, 2, 3, 4])
        source.moveReaderIndex(forwardBy: 1)

        try channel.writeInbound(source)
        let inbound = try channel.readInbound(as: ByteBuffer.self)
        let owned = try #require(inbound)
        let sourceAddress = source.withUnsafeReadableBytes {
            UInt(bitPattern: $0.baseAddress!)
        }
        let ownedAddress = owned.withUnsafeReadableBytes {
            UInt(bitPattern: $0.baseAddress!)
        }

        #expect(owned.getBytes(at: owned.readerIndex, length: owned.readableBytes) == [1, 2, 3, 4])
        #expect(ownedAddress != sourceAddress)
    }

    @Test("oversized declared record closes before body allocation")
    func oversizedLength() {
        let accumulator = accumulator()
        var records: [Data] = []
        #expect(!decode(
            lengthPrefix(Self.limit + 1),
            with: accumulator,
            into: &records
        ))
        #expect(records.isEmpty)
    }

    @Test("bounded records are delivered unchanged")
    func boundedRecord() {
        let accumulator = accumulator()
        let record = Data([0x49, 0x56, 0x59, 0x08, 0x01])
        var records: [Data] = []
        #expect(decode(framed([record]), with: accumulator, into: &records))
        #expect(records == [record])
        accumulator.reset()
    }

    @Test("every stream split delivers the same records")
    func everySplit() {
        let records = [
            Data([0x49, 0x56, 0x59, 0x08, 0x01]),
            Data([0xaa, 0xbb, 0xcc]),
        ]
        let stream = framed(records)

        for split in 0...stream.count {
            let budget = InboundByteBudget(limit: Int(Self.limit) + 4)
            let accumulator = accumulator(budget: budget)
            var decoded: [Data] = []
            if split > 0 {
                #expect(decode(
                    Array(stream[..<split]),
                    with: accumulator,
                    into: &decoded
                ))
            }
            if split < stream.count {
                #expect(decode(
                    Array(stream[split...]),
                    with: accumulator,
                    into: &decoded
                ))
            }
            #expect(decoded == records, "split \(split)")
            accumulator.reset()
            #expect(budget.currentUsage == 0, "split \(split)")
        }
    }

    @Test("coalesced frames preserve record boundaries")
    func coalescedFrames() {
        let records = [Data([1]), Data([2, 3]), Data([4, 5, 6])]
        let accumulator = accumulator()
        var decoded: [Data] = []
        #expect(decode(framed(records), with: accumulator, into: &decoded))
        #expect(decoded == records)
        accumulator.reset()
    }

    @Test("raw accumulator drains coalesced frames one at a time")
    func rawAccumulatorCoalescedFrames() {
        let records = [Data([1]), Data([2, 3]), Data([4, 5, 6])]
        let budget = InboundByteBudget(limit: 64)
        let accumulator = SessionFrameAccumulator(
            maxFrameSize: Self.limit,
            budget: budget,
            connectionBudget: InboundByteBudget(limit: 64))
        var stream = ByteBufferAllocator().buffer(capacity: 18)
        stream.writeBytes(framed(records))

        for expected in records {
            switch accumulator.nextFrame(from: &stream) {
            case .frame(let frame):
                #expect(frame.bytes == expected)
            case .incomplete:
                Issue.record("coalesced frame was not available")
                return
            case .invalid:
                Issue.record("valid coalesced frame was rejected")
                return
            }
        }

        #expect(stream.readableBytes == 0)
        accumulator.reset()
    }

    @Test("raw accumulator releases partial frame reservations on reset")
    func rawAccumulatorResetReleasesReservations() {
        let budget = InboundByteBudget(limit: 64)
        let accumulator = SessionFrameAccumulator(
            maxFrameSize: Self.limit,
            budget: budget,
            connectionBudget: InboundByteBudget(limit: 64))
        var partial = ByteBufferAllocator().buffer(capacity: 1)
        partial.writeInteger(UInt8(0))

        switch accumulator.nextFrame(from: &partial) {
        case .incomplete:
            break
        case .frame, .invalid:
            Issue.record("partial header did not wait for more bytes")
            return
        }
        #expect(budget.currentUsage == 4)
        accumulator.reset()
        #expect(budget.currentUsage == 0)
    }

    @Test("zero-length records close as malformed wire")
    func zeroLength() {
        let accumulator = accumulator()
        var records: [Data] = []
        #expect(!decode(
            lengthPrefix(0),
            with: accumulator,
            into: &records
        ))
        #expect(records.isEmpty)
    }

    @Test("declared lengths do not reserve unseen bytes or evict another connection")
    func slowlorisIsolation() {
        let budget = InboundByteBudget(limit: 16)
        let bodyAccumulator = accumulator(budget: budget)
        var bodyRecords: [Data] = []
        #expect(decode(
            lengthPrefix(Self.limit) + [1],
            with: bodyAccumulator,
            into: &bodyRecords
        ))
        #expect(budget.currentUsage == 1)

        let competingAccumulator = accumulator(budget: budget)
        var competingRecords: [Data] = []
        #expect(decode(
            framed([Data([2])]),
            with: competingAccumulator,
            into: &competingRecords
        ))
        #expect(competingRecords == [Data([2])])
        #expect(budget.currentUsage == 1)

        competingAccumulator.reset()
        bodyAccumulator.reset()
        #expect(budget.currentUsage == 0)
    }

    @Test("one connection cannot exceed its byte reservation")
    func perConnectionBudget() {
        let budget = InboundByteBudget(limit: 64)
        let connectionBudget = InboundByteBudget(limit: 8)
        let accumulator = accumulator(
            budget: budget,
            connectionBudget: connectionBudget)
        var records: [Data] = []
        #expect(decode(
            lengthPrefix(9) + Array(repeating: UInt8(0xaa), count: 8),
            with: accumulator,
            into: &records
        ))
        #expect(budget.currentUsage == 8)
        #expect(connectionBudget.currentUsage == 8)

        #expect(!decode([0xaa], with: accumulator, into: &records))
        #expect(records.isEmpty)
        #expect(budget.currentUsage == 0)
        #expect(connectionBudget.currentUsage == 0)
    }

    @Test("closing a partial header releases its reservation")
    func partialHeaderClose() {
        let budget = InboundByteBudget(limit: 4)
        let accumulator = accumulator(budget: budget)
        var records: [Data] = []
        #expect(decode([0], with: accumulator, into: &records))
        #expect(budget.currentUsage == 4)
        accumulator.reset()
        #expect(budget.currentUsage == 0)
    }

    @Test("byte-at-a-time slowloris input releases its reservation on close")
    func slowlorisClose() {
        let budget = InboundByteBudget(limit: Int(Self.limit) + 4)
        let accumulator = accumulator(budget: budget)
        var records: [Data] = []
        let partial = framed([Data(repeating: 0xaa, count: Int(Self.limit))]).prefix(12)

        for byte in partial {
            #expect(decode([byte], with: accumulator, into: &records))
        }
        #expect(records.isEmpty)
        #expect(budget.currentUsage == partial.count - 4)

        accumulator.reset()
        #expect(budget.currentUsage == 0)
    }

    @Test("seeded hostile mutations never leak frame budget")
    func seededHostileMutations() {
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
            let accumulator = accumulator(budget: budget)
            var bytes = framed([body.isEmpty ? Data([0]) : body])
            if generator.next() & 1 == 1, !bytes.isEmpty {
                bytes[Int(generator.next() % UInt64(bytes.count))] ^= 1
            }
            var records: [Data] = []
            _ = decode(bytes, with: accumulator, into: &records)
            for record in records {
                if let accepted = Message.deserialize(record) {
                    #expect(accepted.serialize() == record, "iteration \(iteration)")
                }
            }
            accumulator.reset()
            #expect(budget.currentUsage == 0, "iteration \(iteration)")
        }
    }
}
