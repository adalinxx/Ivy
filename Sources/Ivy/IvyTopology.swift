import Foundation
import Tally

/// Declares whether an Ivy instance participates in the public peer overlay or is
/// a direct, identity-pinned session to one operational counterparty.
///
/// A pinned session is useful for relationships such as a child process's configured
/// parent evidence channel. It may transport verifiable bytes, but it must not discover
/// substitute peers or silently widen the authority boundary through PEX or relays.
public enum IvyTopology: Sendable, Equatable {
    case publicOverlay
    case pinnedPeer(publicKey: String)

    public var participatesInPublicDiscovery: Bool {
        if case .publicOverlay = self { return true }
        return false
    }

    public var acceptsInboundConnections: Bool {
        if case .publicOverlay = self { return true }
        return false
    }

    public var allowsRelayFallback: Bool {
        if case .publicOverlay = self { return true }
        return false
    }

    /// Whether an authenticated peer identity is in scope for this Ivy instance.
    /// Key spellings are canonicalized so raw and `ed01`-prefixed forms cannot
    /// bypass a pinned identity boundary.
    public func allowsPeer(publicKey: String) -> Bool {
        switch self {
        case .publicOverlay:
            return true
        case .pinnedPeer(let expected):
            return Self.canonicalKey(expected) == Self.canonicalKey(publicKey)
        }
    }

    private static func canonicalKey(_ key: String) -> String {
        KeyDifficulty.canonicalRawHex(key).lowercased()
    }
}
