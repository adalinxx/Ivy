import Foundation

/// Reassembles length-prefixed frames from an arbitrary byte stream, charging
/// every buffered byte to the supplied budgets.
///
/// This is deliberately free of any transport type: TCP drives it from a NIO
/// handler and QUIC from an async byte sequence, so both get the same frame cap
/// and the same accounting for partial frames (IVY-008, IVY-009). A transport
/// cannot loosen those bounds by bringing its own framing.
struct FrameAccumulator {
    enum Outcome: Equatable {
        /// Bytes consumed; nothing complete yet.
        case incomplete
        /// The stream broke its contract and the connection must close.
        case failed
    }

    static let headerByteCount = 4

    private let maxFrameSize: UInt32
    private let budgets: [InboundByteBudget]
    private var header: [UInt8] = []
    private var headerReservation: InboundByteReservation?
    private var expectedBodyLength: Int?
    private var body = Data()
    private var bodyReservation: InboundByteReservation?

    init(maxFrameSize: UInt32, budgets: [InboundByteBudget]) {
        self.maxFrameSize = maxFrameSize
        self.budgets = budgets
        header.reserveCapacity(Self.headerByteCount)
    }

    /// Consumes `bytes`, handing each completed frame to `deliver`.
    mutating func consume(
        _ bytes: Data,
        deliver: (InboundFrame) -> Void
    ) -> Outcome {
        var offset = bytes.startIndex
        while offset < bytes.endIndex {
            if expectedBodyLength == nil {
                if header.isEmpty {
                    let reservation = InboundByteReservation(budgets: budgets)
                    guard reservation.acquire(Self.headerByteCount) else { return fail() }
                    headerReservation = reservation
                }
                let wanted = min(Self.headerByteCount - header.count, bytes.endIndex - offset)
                header.append(contentsOf: bytes[offset..<offset + wanted])
                offset += wanted
                guard header.count == Self.headerByteCount else { return .incomplete }

                let length = UInt32(header[0]) << 24
                    | UInt32(header[1]) << 16
                    | UInt32(header[2]) << 8
                    | UInt32(header[3])
                guard length > 0, length <= maxFrameSize else { return fail() }
                expectedBodyLength = Int(length)
                bodyReservation = InboundByteReservation(budgets: budgets)
                header.removeAll(keepingCapacity: true)
                headerReservation = nil
            }

            guard let expected = expectedBodyLength, let reservation = bodyReservation else {
                continue
            }
            let wanted = min(expected - body.count, bytes.endIndex - offset)
            guard reservation.acquire(wanted) else { return fail() }
            body.append(bytes[offset..<offset + wanted])
            offset += wanted
            guard body.count == expected else { return .incomplete }

            deliver(InboundFrame(bytes: body, reservation: reservation))
            body = Data()
            bodyReservation = nil
            expectedBodyLength = nil
        }
        return .incomplete
    }

    /// Releases every buffered byte. Called when the stream ends, so a dead
    /// connection stops charging the node-wide budget.
    mutating func reset() {
        header.removeAll(keepingCapacity: true)
        headerReservation = nil
        expectedBodyLength = nil
        body = Data()
        bodyReservation = nil
    }

    private mutating func fail() -> Outcome {
        reset()
        return .failed
    }
}
