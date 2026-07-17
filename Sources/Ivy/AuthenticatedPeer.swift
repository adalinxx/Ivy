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

    public init(key: PeerKey, role: AuthenticatedPeerRole, route: AuthenticatedRoute, metadata: PeerMetadata) {
        self.key = key
        self.role = role
        self.route = route
        self.metadata = metadata
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
    case notConnected
    case locallyRejected
}
