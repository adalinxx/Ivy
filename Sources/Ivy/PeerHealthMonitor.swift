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
        var lastActivity: ContinuousClock.Instant
        var pendingPingNonce: UInt64?
        var missedPongs: Int = 0
    }

    private var peers: [PeerID: PeerHealth] = [:]
    private let config: PeerHealthConfig
    private var monitorTask: Task<Void, Never>?
    private let onStale: @Sendable (PeerID) -> Void

    init(config: PeerHealthConfig, onStale: @escaping @Sendable (PeerID) -> Void) {
        self.config = config
        self.onStale = onStale
    }

    func startMonitoring(sendPing: @escaping @Sendable (PeerID, UInt64) async -> Void) {
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
                for peer in staleList {
                    self.onStale(peer)
                }
            }
        }
    }

    func stopMonitoring() {
        monitorTask?.cancel()
        monitorTask = nil
    }

    func trackPeer(_ peer: PeerID) {
        if peers[peer] == nil {
            peers[peer] = PeerHealth(lastActivity: .now)
        }
    }

    func removePeer(_ peer: PeerID) {
        peers.removeValue(forKey: peer)
    }

    func recordActivity(from peer: PeerID) {
        peers[peer]?.lastActivity = .now
        peers[peer]?.missedPongs = 0
    }

    func recordPong(from peer: PeerID, nonce: UInt64) {
        guard let health = peers[peer] else { return }
        if health.pendingPingNonce == nonce {
            peers[peer]?.pendingPingNonce = nil
            peers[peer]?.missedPongs = 0
            peers[peer]?.lastActivity = .now
        }
    }

    private func checkAndPing(sendPing: @Sendable (PeerID, UInt64) async -> Void) async -> [PeerID] {
        var stale: [PeerID] = []

        for (peer, var health) in peers {
            let sinceActivity = health.lastActivity.duration(to: .now)

            if sinceActivity > config.staleTimeout || health.missedPongs >= config.maxMissedPongs {
                stale.append(peer)
                continue
            }

            if sinceActivity > config.keepaliveInterval {
                if health.pendingPingNonce != nil {
                    health.missedPongs += 1
                    peers[peer] = health
                }

                let nonce = UInt64.random(in: 0...UInt64.max)
                peers[peer]?.pendingPingNonce = nonce
                await sendPing(peer, nonce)
            }
        }

        for peer in stale {
            peers.removeValue(forKey: peer)
        }

        return stale
    }
}
