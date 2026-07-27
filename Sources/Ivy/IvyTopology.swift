import Foundation

public enum IvyModeError: Error, Sendable, Equatable {
    case invalidPinnedIdentity(String)
    case invalidEndpointIdentity(String)
    case invalidCarrierIdentity(String)
    case duplicateCarrierIdentity(String)
    case identityRoleCollision(String)
    case peerOutsidePinnedMode(expected: String, actual: String)
    case invalidConfiguration(String)
}

public enum IvyMode: Sendable, Equatable {
    case overlay
    case privateNetwork
    case pinned(peer: String)

    public var participatesInPublicDiscovery: Bool {
        if case .overlay = self { return true }
        return false
    }

    var usesOverlayServices: Bool {
        if case .privateNetwork = self { return false }
        return true
    }

    func pinnedKey() throws -> PeerKey? {
        guard case .pinned(let peer) = self else { return nil }
        guard let key = try? PeerKey(peer) else { throw IvyModeError.invalidPinnedIdentity(peer) }
        return key
    }

    func allowsEndpoint(_ key: PeerKey) -> Bool {
        switch self {
        case .overlay, .privateNetwork:
            return true
        case .pinned(let expected):
            return (try? PeerKey(expected)) == key
        }
    }
}
