import Foundation
import NIOCore

/// A `TransportConnection` backed by a NIO channel.
///
/// `autoRead` stays off for the channel's whole life, so `requestBytes()` maps
/// onto NIO's own demand signal: the socket is read exactly as far as the layer
/// above has asked for.
final class NIOTransportConnection: TransportConnection, @unchecked Sendable {
    private let channel: Channel
    private let lock = NSLock()
    private var sink: (any TransportConnectionSink)?

    init(channel: Channel) {
        self.channel = channel
    }

    var observedHost: String? { channel.remoteAddress?.ipAddress }
    var localHost: String? { channel.localAddress?.ipAddress }
    var localPort: UInt16? { channel.localAddress?.port.map(UInt16.init) }
    var isActive: Bool { channel.isActive }
    var isWritable: Bool { channel.isWritable }

    func attach(_ sink: any TransportConnectionSink) {
        lock.withLock { self.sink = sink }
    }

    func requestBytes() {
        channel.read()
    }

    func send(_ payload: Data) {
        var buffer = channel.allocator.buffer(capacity: payload.count)
        buffer.writeBytes(payload)
        channel.writeAndFlush(buffer, promise: nil)
    }

    func close() {
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
final class NIOTransportHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let connection: NIOTransportConnection

    init(connection: NIOTransportConnection) {
        self.connection = connection
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        guard let bytes = buffer.readData(length: buffer.readableBytes) else { return }
        connection.deliver(bytes)
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        connection.deliverWritability(context.channel.isWritable)
        context.fireChannelWritabilityChanged()
    }

    func channelInactive(context: ChannelHandlerContext) {
        connection.deliverClose()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
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
