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
        let alreadyClosed = lock.withLock { () -> Bool in
            guard !closeDelivered else { return true }
            self.sink = sink
            return false
        }
        guard !alreadyClosed else {
            sink.transportDidClose()
            return
        }
        startPumps()
    }

    /// One delivery per request. `inbound` is a backpressured producer, so not
    /// calling `next()` is what holds the peer off — the same contract NIO's
    /// `read()` gives the TCP transport.
    func requestBytes() {
        demandContinuation.yield(())
    }

    func send(_ payload: Data) {
        let becameUnwritable = lock.withLock { () -> Bool in
            guard !closed else { return false }
            let wasWritable = writable
            queuedBytes += payload.count
            if wasWritable, queuedBytes >= Self.highWaterMark {
                writable = false
                return true
            }
            return false
        }
        outboundContinuation.yield(payload)
        if becameUnwritable { currentSink?.transportWritabilityChanged(isWritable: false) }
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
                    break
                }
                guard let self else { break }
                self.didSend(payload.count)
            }
        }

        let started = lock.withLock { () -> Bool in
            guard !closed else { return false }
            pumps = [readPump, writePump]
            return true
        }
        if !started {
            readPump.cancel()
            writePump.cancel()
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
