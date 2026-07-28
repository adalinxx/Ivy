import Foundation

/// A hole punch in progress with one peer.
///
/// The coordinator is the responder of the relayed session — the side that
/// accepted the relayed connection, and so the side more likely to be the one
/// behind a NAT, matching how DCUtR assigns the role.
struct PendingHolePunch: Sendable {
    enum Phase: Sendable, Equatable {
        /// Coordinator: offered our addresses, waiting for theirs.
        case awaitingCandidates
        /// Responder: sent ours, waiting for the sync that fires the dial.
        case awaitingSync
        case dialing
    }

    let punchID: UInt64
    let peer: PeerKey
    let generation: UInt64
    let isCoordinator: Bool
    let startedAt: ContinuousClock.Instant
    var phase: Phase
    var attempt: Int
    var remoteCandidates: [PunchCandidate] = []
    var timeoutTask: IvyTimer?
    var dialTask: Task<Void, Never>?

    /// Half the round trip measured over the relay, so a dial sent now lands at
    /// roughly the moment the peer's own dial does.
    func syncDelay(now: ContinuousClock.Instant) -> Duration {
        let roundTrip = now - startedAt
        return roundTrip / 2
    }
}

/// Which addresses this node offers, and which offered ones it will dial.
enum HolePunchCandidates {
    /// Rejects anything that is not a plausible public socket. A peer names its
    /// own addresses, so without this it could aim our dials at a host inside
    /// our network or at a service on our own machine.
    static func acceptable(
        _ candidates: [PunchCandidate],
        allowingPrivateHosts: Bool,
        isRoutable: (String) -> Bool,
        hasTransport: (TransportKind) -> Bool
    ) -> [PunchCandidate] {
        candidates.filter { candidate in
            guard candidate.transport.isDirectlyDialable,
                  hasTransport(candidate.transport),
                  candidate.port != 0 else { return false }
            return allowingPrivateHosts || isRoutable(candidate.host)
        }
    }
}
