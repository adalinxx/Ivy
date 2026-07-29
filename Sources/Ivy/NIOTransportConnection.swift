import Foundation
import NIOCore

/// A `TransportConnection` backed by a NIO channel.
///
/// `autoRead` stays off for the channel's whole life, so `requestBytes()` maps
/// onto NIO's own demand signal: the socket is read exactly as far as the layer
/// above has asked for.
///
/// Public so that out-of-package transports carried by a NIO channel (QUIC
/// stream channels, for one) reuse the same adapter instead of re-deriving the
/// delivery and demand rules.
public final class NIOTransportConnection: TransportConnection, @unchecked Sendable {
    private let channel: Channel
    private let lock = NSLock()
    private var sink: (any TransportConnectionSink)?
    private var closeDelivered = false

    public init(channel: Channel) {
        self.channel = channel
    }

    public var observedHost: String? { channel.remoteAddress?.ipAddress }
    public var localHost: String? { channel.localAddress?.ipAddress }
    public var localPort: UInt16? { channel.localAddress?.port.map(UInt16.init) }
    public var isActive: Bool { channel.isActive }
    public var isWritable: Bool { channel.isWritable }

    public func attach(_ sink: any TransportConnectionSink) {
        // The channel can die between the dial returning and the sink arriving;
        // a close that already happened must still reach the sink.
        let alreadyClosed = lock.withLock { () -> Bool in
            guard !closeDelivered else { return true }
            self.sink = sink
            return false
        }
        if alreadyClosed { sink.transportDidClose() }
    }

    public func requestBytes() {
        channel.read()
    }

    public func send(_ payload: Data) {
        var buffer = channel.allocator.buffer(capacity: payload.count)
        buffer.writeBytes(payload)
        channel.writeAndFlush(buffer, promise: nil)
    }

    public func close() {
        channel.close(promise: nil)
    }

    fileprivate func deliver(_ bytes: Data) {
        currentSink?.transportDidReceive(bytes)
    }

    fileprivate func deliverWritability(_ isWritable: Bool) {
        currentSink?.transportWritabilityChanged(isWritable: isWritable)
    }

    fileprivate func deliverClose() {
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

/// Forwards a channel's bytes and lifecycle to its `NIOTransportConnection`.
public final class NIOTransportHandler: ChannelInboundHandler, @unchecked Sendable {
    public typealias InboundIn = ByteBuffer

    private let connection: NIOTransportConnection
    private var onActive: (@Sendable (NIOTransportConnection) -> Void)?

    /// `onActive` runs exactly once, when the channel is live. An accepted
    /// connection must only be surfaced then: registration checks liveness, and
    /// a connection surfaced from the child channel initializer is not active
    /// yet and would be refused as dead.
    public init(
        connection: NIOTransportConnection,
        onActive: (@Sendable (NIOTransportConnection) -> Void)? = nil
    ) {
        self.connection = connection
        self.onActive = onActive
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        // A stream channel can already be active by the time this handler is
        // installed, in which case `channelActive` will never fire for it.
        guard context.channel.isActive else { return }
        fireActive()
    }

    public func channelActive(context: ChannelHandlerContext) {
        fireActive()
        context.fireChannelActive()
    }

    private func fireActive() {
        guard let onActive else { return }
        self.onActive = nil
        onActive(connection)
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        guard let bytes = buffer.readData(length: buffer.readableBytes) else { return }
        connection.deliver(bytes)
    }

    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        connection.deliverWritability(context.channel.isWritable)
        context.fireChannelWritabilityChanged()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        connection.deliverClose()
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

/// Resumes once its connection closes, so a caller can wait on a peer's close
/// without depending on any particular transport's future type.
final class TransportCloseWaiter: TransportConnectionSink, @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    private var closed = false

    func transportDidReceive(_ bytes: Data) {}
    func transportWritabilityChanged(isWritable: Bool) {}

    func transportDidClose() {
        let continuation = lock.withLock { () -> CheckedContinuation<Void, Never>? in
            guard !closed else { return nil }
            closed = true
            defer { self.continuation = nil }
            return self.continuation
        }
        continuation?.resume()
    }

    func wait() async {
        await withCheckedContinuation { continuation in
            let alreadyClosed = lock.withLock { () -> Bool in
                guard !closed else { return true }
                self.continuation = continuation
                return false
            }
            if alreadyClosed { continuation.resume() }
        }
    }
}
