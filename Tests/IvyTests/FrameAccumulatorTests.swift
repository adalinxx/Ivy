import Foundation
import Testing
@testable import Ivy

@Suite("Frame accumulator")
struct FrameAccumulatorTests {
    private func framed(_ body: Data) -> Data {
        var out = Data()
        let length = UInt32(body.count)
        out.append(UInt8(truncatingIfNeeded: length >> 24))
        out.append(UInt8(truncatingIfNeeded: length >> 16))
        out.append(UInt8(truncatingIfNeeded: length >> 8))
        out.append(UInt8(truncatingIfNeeded: length))
        out.append(body)
        return out
    }

    private func accumulator(
        limit: Int = 1 << 20,
        maxFrameSize: UInt32 = 64
    ) -> (FrameAccumulator, InboundByteBudget) {
        let budget = InboundByteBudget(limit: limit)
        return (FrameAccumulator(maxFrameSize: maxFrameSize, budgets: [budget]), budget)
    }

    @Test("a frame split across arbitrary byte boundaries reassembles once")
    func reassemblesAcrossSplits() {
        let body = Data((0..<40).map { UInt8($0) })
        let wire = framed(body)
        for split in 1..<wire.count {
            var (acc, _) = accumulator()
            var frames: [Data] = []
            let first = acc.consume(wire.prefix(split)) { frames.append($0.bytes) }
            let second = acc.consume(wire.suffix(from: split)) { frames.append($0.bytes) }
            #expect(first == .incomplete)
            #expect(second == .incomplete)
            #expect(frames == [body])
        }
    }

    @Test("several frames in one delivery all arrive, in order")
    func deliversBackToBackFrames() {
        var (acc, _) = accumulator()
        let bodies = [Data([1]), Data([2, 2]), Data([3, 3, 3])]
        var wire = Data()
        for body in bodies { wire.append(framed(body)) }
        var frames: [Data] = []
        #expect(acc.consume(wire) { frames.append($0.bytes) } == .incomplete)
        #expect(frames == bodies)
    }

    @Test("an oversized or empty frame fails the stream")
    func rejectsUnusableLengths() {
        var (tooBig, _) = accumulator(maxFrameSize: 8)
        #expect(tooBig.consume(framed(Data(repeating: 0, count: 9))) { _ in } == .failed)

        var (empty, _) = accumulator()
        #expect(empty.consume(framed(Data())) { _ in } == .failed)
    }

    @Test("a partial frame charges the budget and releases it on reset")
    func partialFramesAreChargedAndReleased() {
        var (acc, budget) = accumulator(limit: 4096)
        let wire = framed(Data(repeating: 0xab, count: 40))
        // Header plus a few body bytes, so the frame stays incomplete.
        #expect(acc.consume(wire.prefix(10)) { _ in } == .incomplete)
        #expect(budget.currentUsage > 0)
        acc.reset()
        #expect(budget.currentUsage == 0)
    }

    @Test("a stream that would exceed the budget fails instead of buffering")
    func refusesToExceedTheBudget() {
        // Enough for the header but not the body it announces.
        var (acc, _) = accumulator(limit: 8)
        #expect(acc.consume(framed(Data(repeating: 0, count: 32))) { _ in } == .failed)
    }
}
