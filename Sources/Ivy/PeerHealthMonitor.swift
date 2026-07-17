import Foundation
import Tally

public struct PeerHealthConfig: Sendable {
    public let keepaliveInterval: Duration
    public let staleTimeout: Duration
    public let maxMissedPongs: Int
    public let enabled: Bool

    public init(
        keepaliveInterval: Duration = .seconds(60),
        staleTimeout: Duration = .seconds(180),
        maxMissedPongs: Int = 3,
        enabled: Bool = true
    ) {
        self.keepaliveInterval = keepaliveInterval
        self.staleTimeout = staleTimeout
        self.maxMissedPongs = maxMissedPongs
        self.enabled = enabled
    }

    public static let `default` = PeerHealthConfig()
}

actor PeerHealthMonitor {
    struct PeerHealth: Sendable {
        let sessionID: SessionID
        var lastActivity: ContinuousClock.Instant
        var pendingPingNonce: UInt64?
        var missedPongs: Int = 0
    }

    private var peers: [PeerID: PeerHealth] = [:]
    private let config: PeerHealthConfig
    private var monitorTask: Task<Void, Never>?
    private let onStale: @Sendable (PeerID, SessionID) -> Void
    private let now: @Sendable () -> ContinuousClock.Instant
    private let nextNonce: @Sendable () -> UInt64

    init(
        config: PeerHealthConfig,
        onStale: @escaping @Sendable (PeerID, SessionID) -> Void,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        nextNonce: @escaping @Sendable () -> UInt64 = { UInt64.random(in: .min ... .max) }
    ) {
        self.config = config
        self.onStale = onStale
        self.now = now
        self.nextNonce = nextNonce
    }

    func startMonitoring(
        sendPing: @escaping @Sendable (PeerID, SessionID, UInt64) async -> Void
    ) {
        guard config.enabled else { return }
        monitorTask?.cancel()
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: self?.config.keepaliveInterval ?? .seconds(60))
                } catch {
                    return
                }
                guard let self else { return }
                let staleList = await self.checkAndPing(sendPing: sendPing)
                for (peer, sessionID) in staleList {
                    self.onStale(peer, sessionID)
                }
            }
        }
    }

    func stopMonitoring() {
        monitorTask?.cancel()
        monitorTask = nil
    }

    func trackPeer(_ peer: PeerID, sessionID: SessionID) {
        guard peers[peer]?.sessionID != sessionID else { return }
        peers[peer] = PeerHealth(sessionID: sessionID, lastActivity: now())
    }

    func removePeer(_ peer: PeerID, sessionID: SessionID) {
        guard peers[peer]?.sessionID == sessionID else { return }
        peers.removeValue(forKey: peer)
    }

    func recordActivity(from peer: PeerID, sessionID: SessionID) {
        guard peers[peer]?.sessionID == sessionID else { return }
        peers[peer]?.lastActivity = now()
        peers[peer]?.pendingPingNonce = nil
        peers[peer]?.missedPongs = 0
    }

    func recordPong(from peer: PeerID, sessionID: SessionID, nonce: UInt64) {
        guard let health = peers[peer], health.sessionID == sessionID else { return }
        if health.pendingPingNonce == nonce {
            peers[peer]?.pendingPingNonce = nil
            peers[peer]?.missedPongs = 0
            peers[peer]?.lastActivity = now()
        }
    }

    func checkAndPing(
        sendPing: @Sendable (PeerID, SessionID, UInt64) async -> Void
    ) async -> [(PeerID, SessionID)] {
        var stale: [(PeerID, SessionID)] = []
        var pendingPings: [(PeerID, SessionID, UInt64)] = []
        let current = now()

        for (peer, var health) in peers {
            let sinceActivity = health.lastActivity.duration(to: current)

            if sinceActivity >= config.staleTimeout {
                stale.append((peer, health.sessionID))
                continue
            }

            if sinceActivity >= config.keepaliveInterval {
                if health.pendingPingNonce != nil {
                    health.missedPongs += 1
                    if health.missedPongs >= config.maxMissedPongs {
                        stale.append((peer, health.sessionID))
                        continue
                    }
                }

                let nonce = nextNonce()
                health.pendingPingNonce = nonce
                peers[peer] = health
                pendingPings.append((peer, health.sessionID, nonce))
            }
        }

        for (peer, sessionID) in stale where peers[peer]?.sessionID == sessionID {
            peers.removeValue(forKey: peer)
        }

        for (peer, sessionID, nonce) in pendingPings {
            guard let health = peers[peer],
                  health.sessionID == sessionID,
                  health.pendingPingNonce == nonce
            else { continue }
            await sendPing(peer, sessionID, nonce)
        }

        return stale
    }

    func health(for peer: PeerID) -> PeerHealth? { peers[peer] }
}
