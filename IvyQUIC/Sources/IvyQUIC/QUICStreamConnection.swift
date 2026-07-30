import Foundation
import Ivy
import NIOCore
import QUIC

/// A `TransportConnection` carried by one QUIC bidirectional stream.
///
/// Ivy's framing, byte budgets, and admission all live above this, so the only
/// job here is to honour the seam's two contracts: deliver bytes no faster than
/// `requestBytes()` asks for them, and report writability so a slow peer
/// backpressures the session instead of queueing without bound.
final class QUICStreamConnection: TransportConnection, @unchecked Sendable {
    /// Matches NIO's channel watermark defaults, so QUIC and TCP backpressure
    /// at the same offered load.
    private static let highWaterMark = 64 * 1024
    private static let lowWaterMark = 32 * 1024

    private let connection: QUICConnection
    private let stream: QUICStream

    private let lock = NSLock()
    private var sink: (any TransportConnectionSink)?
    private var closed = false
    private var closeDelivered = false
    private var pumpsStarted = false
    private var writable = true
    private var queuedBytes = 0
    private var pumps: [Task<Void, Never>] = []

    // Captured up front: the addresses are unreadable once the connection closes.
    private let remoteHost: String?
    private let boundHost: String?
    private let boundPort: UInt16?

    private let demand: AsyncStream<Void>
    private let demandContinuation: AsyncStream<Void>.Continuation
    private let outbound: AsyncStream<Data>
    private let outboundContinuation: AsyncStream<Data>.Continuation

    init(connection: QUICConnection, stream: QUICStream) {
        self.connection = connection
        self.stream = stream
        self.remoteHost = connection.remoteAddress?.ipAddress
        self.boundHost = connection.localAddress?.ipAddress
        self.boundPort = connection.localAddress?.port.map(UInt16.init)
        (self.demand, self.demandContinuation) = AsyncStream<Void>.makeStream(
            bufferingPolicy: .unbounded)
        (self.outbound, self.outboundContinuation) = AsyncStream<Data>.makeStream(
            bufferingPolicy: .unbounded)
    }

    var observedHost: String? { remoteHost }
    var localHost: String? { boundHost }
    var localPort: UInt16? { boundPort }

    var isActive: Bool { lock.withLock { !closed } }
    var isWritable: Bool { lock.withLock { writable } }

    func attach(_ sink: any TransportConnectionSink) {
        // The stream can die between being handed over and the sink arriving; a
        // close that already happened must still reach it.
        enum Outcome { case alreadyClosed, start, alreadyAttached }
        let outcome = lock.withLock { () -> Outcome in
            guard !closeDelivered else { return .alreadyClosed }
            guard !pumpsStarted else { return .alreadyAttached }
            self.sink = sink
            pumpsStarted = true
            return .start
        }
        switch outcome {
        case .alreadyClosed:
            sink.transportDidClose()
        case .start:
            startPumps()
        case .alreadyAttached:
            // A second sink would orphan the first and leave two readers
            // competing for the same demand tokens.
            break
        }
    }

    /// One delivery per request. `inbound` is a backpressured producer, so not
    /// calling `next()` is what holds the peer off — the same contract NIO's
    /// `read()` gives the TCP transport.
    func requestBytes() {
        demandContinuation.yield(())
    }

    func send(_ payload: Data) {
        let outcome = lock.withLock { () -> (queued: Bool, becameUnwritable: Bool) in
            guard !closed else { return (false, false) }
            let wasWritable = writable
            queuedBytes += payload.count
            let crossed = wasWritable && queuedBytes >= Self.highWaterMark
            if crossed { writable = false }
            return (true, crossed)
        }
        // Nothing is queued once closed, so a late send cannot retain a payload
        // on a connection whose pump has already gone.
        guard outcome.queued else { return }
        outboundContinuation.yield(payload)
        if outcome.becameUnwritable {
            currentSink?.transportWritabilityChanged(isWritable: false)
        }
    }

    func close() {
        guard beginClose() else { return }
        let connection = self.connection
        Task { await connection.close() }
        deliverClose()
    }

    private func startPumps() {
        let stream = self.stream
        let demand = self.demand
        let outbound = self.outbound

        let readPump = Task { [weak self] in
            var iterator = stream.inbound.makeAsyncIterator()
            for await _ in demand {
                let chunk: ByteBuffer?
                do {
                    chunk = try await iterator.next()
                } catch {
                    break
                }
                guard let chunk, let self else { break }
                self.currentSink?.transportDidReceive(Data(chunk.readableBytesView))
            }
            self?.streamEnded()
        }

        let writePump = Task { [weak self] in
            for await payload in outbound {
                do {
                    try await stream.send(ByteBuffer(bytes: payload))
                } catch {
                    // A stream that will not take writes cannot carry the
                    // session. Failing the connection is what releases the
                    // peer's slot and frees anyone waiting on writability;
                    // returning quietly would leave both stuck for good.
                    self?.streamEnded()
                    return
                }
                guard let self else { return }
                self.didSend(payload.count)
            }
        }

        // Death has to be observable without being asked for. The read pump
        // only looks at the stream while it holds demand, so a peer that dies
        // while the session is busy would otherwise go unnoticed.
        let connection = self.connection
        let deathPump = Task { [weak self] in
            await connection.waitUntilClosed()
            self?.streamEnded()
        }

        let started = lock.withLock { () -> Bool in
            guard !closed else { return false }
            pumps = [readPump, writePump, deathPump]
            return true
        }
        if !started {
            readPump.cancel()
            writePump.cancel()
            deathPump.cancel()
        }
    }

    private func didSend(_ byteCount: Int) {
        let becameWritable = lock.withLock { () -> Bool in
            queuedBytes -= byteCount
            guard !closed, !writable, queuedBytes <= Self.lowWaterMark else { return false }
            writable = true
            return true
        }
        if becameWritable { currentSink?.transportWritabilityChanged(isWritable: true) }
    }

    /// The peer finished or reset the stream, which ends the session riding it.
    private func streamEnded() {
        guard beginClose() else { return }
        let connection = self.connection
        Task { await connection.close() }
        deliverClose()
    }

    /// Marks the connection closed, returning whether this call was the one that
    /// did it. Cancelling the pumps here is what stops them holding the stream.
    private func beginClose() -> Bool {
        let pumps = lock.withLock { () -> [Task<Void, Never>]? in
            guard !closed else { return nil }
            closed = true
            writable = false
            queuedBytes = 0
            defer { self.pumps = [] }
            return self.pumps
        }
        guard let pumps else { return false }
        demandContinuation.finish()
        outboundContinuation.finish()
        for pump in pumps { pump.cancel() }
        return true
    }

    private func deliverClose() {
        let sink = lock.withLock { () -> (any TransportConnectionSink)? in
            closeDelivered = true
            defer { self.sink = nil }
            return self.sink
        }
        sink?.transportDidClose()
    }

    private var currentSink: (any TransportConnectionSink)? {
        lock.withLock { sink }
    }
}
