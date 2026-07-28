import NIOCore

/// Wire identifier for a transport. Encoded in advertised addresses.
public enum TransportKind: UInt8, Sendable, Hashable, CaseIterable {
    case tcp = 1
    case quic = 2
    /// Reached through a carrier rather than dialed directly. Only valid in
    /// provider records: it names where to find a peer, not a socket to open,
    /// and never enters the routing table.
    case relay = 3

    /// Whether a node can open a connection of this kind itself.
    var isDirectlyDialable: Bool { self != .relay }
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

    /// - Parameter boundToPort: Local port to dial from, so the NAT mapping the
    ///   peer sees matches the address this node advertises. Ignored by
    ///   transports that cannot reuse their listening port; a conforming type
    ///   may fall back to an ephemeral port when the bind fails.
    func dial(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        boundToPort: UInt16?,
        initializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> Channel

    func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        streamInitializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> any TransportListenerHandle
}

extension IvyTransport {
    func dial(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        initializer: @Sendable @escaping (Channel) -> EventLoopFuture<Void>
    ) async throws -> Channel {
        try await dial(
            host: host,
            port: port,
            group: group,
            boundToPort: nil,
            initializer: initializer)
    }
}

enum TransportError: Error, Equatable {
    /// A transport completed a dial without running the supplied initializer.
    case channelNotInitialized
}
