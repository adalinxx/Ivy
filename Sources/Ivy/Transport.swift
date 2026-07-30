import Foundation
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

/// Receives everything a transport connection produces.
public protocol TransportConnectionSink: AnyObject, Sendable {
    /// Bytes that were asked for, in order. Never more than was requested.
    func transportDidReceive(_ bytes: Data)
    func transportWritabilityChanged(isWritable: Bool)
    func transportDidClose()
}

/// A live ordered byte stream to one peer.
///
/// Deliberately not a NIO channel: a transport may reach a peer over something
/// else entirely, and everything that bounds a connection — framing, byte
/// budgets, admission, the session state machine — lives above this and is the
/// same for all of them.
public protocol TransportConnection: Sendable {
    /// Address the peer was observed at, which netgroup accounting keys on.
    var observedHost: String? { get }
    var localHost: String? { get }
    var localPort: UInt16? { get }
    var isActive: Bool { get }
    var isWritable: Bool { get }

    /// Installs the sink. Nothing is delivered before this, and a transport must
    /// not deliver anything until `requestBytes()` asks for it.
    func attach(_ sink: any TransportConnectionSink)

    /// Asks for the next delivery. This is the whole flow-control contract: a
    /// transport reads no further ahead than it has been asked to, so a slow
    /// consumer stops the peer rather than buffering without bound.
    func requestBytes()

    /// Sends one already-framed payload.
    func send(_ payload: Data)
    func close()
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
        boundToPort: UInt16?
    ) async throws -> any TransportConnection

    /// `onConnection` runs for each accepted connection. Admission decides
    /// whether to keep it, and nothing is read until it calls `requestBytes()`.
    func listen(
        host: String,
        port: UInt16,
        group: any EventLoopGroup,
        onConnection: @Sendable @escaping (any TransportConnection) -> Void
    ) async throws -> any TransportListenerHandle
}

extension IvyTransport {
    func dial(
        host: String,
        port: UInt16,
        group: any EventLoopGroup
    ) async throws -> any TransportConnection {
        try await dial(host: host, port: port, group: group, boundToPort: nil)
    }
}

enum TransportError: Error, Equatable {
    case dialFailed
}
