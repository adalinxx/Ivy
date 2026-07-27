import NIOCore

/// Wire identifier for a transport. Encoded in advertised addresses.
public enum TransportKind: UInt8, Sendable, Hashable, CaseIterable {
    case tcp = 1
    case quic = 2
}

/// A bound listener owned by a transport.
public protocol TransportListenerHandle: Sendable {
    /// Port the listener actually bound to, once known.
    var localPort: UInt16? { get }
    /// Stops accepting and releases the bound socket.
    func close() async
    /// Fire-and-forget close for contexts that cannot await (`deinit`).
    func closeImmediately()
}

/// Produces ordered, reliable byte-stream channels for the session layer.
///
/// Conformances must guarantee:
/// - `initializer`/`streamInitializer` run on the channel's event loop before any
///   inbound read is delivered, and a channel whose initializer fails is closed.
/// - Accepted channels are delivered with `autoRead` disabled and no reads issued;
///   the acceptor enables reads once admission is granted (IVY-001).
/// - Delivered channels report `remoteAddress` and `localAddress`.
/// - Closing a delivered channel tears down the underlying transport connection,
///   and a transport-level teardown fires `channelInactive` on the delivered channel.
public protocol IvyTransport: Sendable {
    var kind: TransportKind { get }

    func dial(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        initializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> Channel

    func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        streamInitializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> any TransportListenerHandle
}

enum TransportError: Error, Equatable {
    /// A transport completed a dial without running the supplied initializer.
    case channelNotInitialized
}
