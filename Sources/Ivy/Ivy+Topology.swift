import Foundation

public enum IvyTopologyError: Error, Sendable, Equatable {
    case peerOutsidePinnedTopology(expected: String, actual: String)
}

public extension Ivy {
    /// Connect using this instance's configured topology boundary.
    ///
    /// Public overlays retain ordinary connection behavior. A pinned session may
    /// connect only to its configured identity, so operational authority cannot be
    /// widened by a discovered or caller-supplied substitute endpoint.
    func connectInConfiguredTopology(to endpoint: PeerEndpoint) async throws {
        guard config.topology.allowsPeer(publicKey: endpoint.publicKey) else {
            let expected: String
            if case .pinnedPeer(let publicKey) = config.topology {
                expected = publicKey
            } else {
                expected = "public-overlay"
            }
            throw IvyTopologyError.peerOutsidePinnedTopology(
                expected: expected,
                actual: endpoint.publicKey
            )
        }
        try await connect(to: endpoint)
    }
}
