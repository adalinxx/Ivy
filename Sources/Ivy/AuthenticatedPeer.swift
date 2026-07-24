import Foundation
import Tally

public enum AuthenticatedPeerRole: Sendable, Equatable {
    case endpoint
    case carrier
}

public enum AuthenticatedRoute: Sendable, Equatable {
    case direct
    case relayed(carrier: PeerKey, routeID: Data)
}

public struct AuthenticatedPeer: Sendable, Equatable {
    public let key: PeerKey
    public let role: AuthenticatedPeerRole
    public let route: AuthenticatedRoute
    public let metadata: PeerMetadata
    /// Opaque identity of this authenticated transport session. A replacement
    /// connection for the same key has a different value.
    public let sessionID: Data

    public init(
        key: PeerKey,
        role: AuthenticatedPeerRole,
        route: AuthenticatedRoute,
        metadata: PeerMetadata,
        sessionID: Data = Data()
    ) {
        self.key = key
        self.role = role
        self.route = route
        self.metadata = metadata
        self.sessionID = sessionID
    }

    public var id: PeerID { key.peerID }
}

public struct PeerMessage: Sendable, Equatable {
    public let topic: String
    public let payload: Data

    public init(topic: String, payload: Data) {
        self.topic = topic
        self.payload = payload
    }
}

public enum SendMessageResult: Sendable, Equatable {
    case enqueued(endpoint: PeerID, route: AuthenticatedRoute)
    /// The authenticated session is live, but its transport has reached its
    /// outbound high-water mark. Retry after `Ivy.waitUntilWritable(to:)`.
    case backpressured
    case notConnected
    case locallyRejected
}
