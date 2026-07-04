import Foundation

/// Circuit-relay accounting for NAT traversal (Phase 1). Tracks active relayed
/// circuits with per-peer / total caps and per-circuit byte+duration budgets, so
/// a public node can forward traffic for unreachable peers without becoming an
/// open amplifier. Restored from the removed `ba45d07` implementation.
///
/// Keyed on peer public keys (the relay forwards `relayData` frames between two
/// endpoints it is each directly connected to). Netgroup/per-IP admission is
/// enforced at the call site (which has the connection's observed host); this
/// actor bounds count + lifetime.
actor RelayService {
    struct Circuit: Sendable {
        let peerA: String
        let peerB: String
        let created: ContinuousClock.Instant          // hard-lifetime backstop
        var lastActivity: ContinuousClock.Instant      // sliding idle timeout — renewed on relayed traffic
        var windowStart: ContinuousClock.Instant       // start of the current byte-rate window
        var bytesInWindow: Int = 0

        // An IDLE circuit (no relayed traffic within this) is torn down; an ACTIVELY-used
        // circuit is renewed on every frame and lives on. This replaces the old hard 120s
        // lifetime, which black-holed long-lived legitimate gossip/sync circuits mid-stream
        // (a relay-only follower's chain gossip is continuous and far exceeds 120s).
        static let idleTimeout: Duration = .seconds(120)
        // Absolute backstop: no circuit outlives this regardless of activity, bounding the
        // worst case a single circuit can cost the relay.
        static let maxLifetime: Duration = .seconds(3600)
        // Byte-RATE cap (not a total): at most `maxBytesPerWindow` per `rateWindow`, reset each
        // window. Bounds sustained throughput abuse while permitting arbitrarily long legitimate
        // transfers (chain sync, ongoing gossip) at a sane rate. Tunable defaults, not protocol constants.
        static let rateWindow: Duration = .seconds(60)
        static let maxBytesPerWindow = 8 * 1024 * 1024  // 8 MB/min

        var isExpired: Bool {
            lastActivity.duration(to: .now) > Self.idleTimeout
                || created.duration(to: .now) > Self.maxLifetime
        }
    }

    private var circuits: [String: Circuit] = [:]
    private let maxCircuitsPerPeer = 4
    private let maxTotalCircuits = 128

    private func circuitKey(_ a: String, _ b: String) -> String {
        a < b ? "\(a):\(b)" : "\(b):\(a)"
    }

    /// Open a circuit between `initiator` and `target` if within caps. Idempotent.
    func createCircuit(initiator: String, target: String) -> Bool {
        pruneExpired()
        let key = circuitKey(initiator, target)
        guard circuits[key] == nil else { return true }  // already open
        guard circuits.count < maxTotalCircuits else { return false }

        let peerCircuits = circuits.values.filter {
            $0.peerA == initiator || $0.peerB == initiator
        }.count
        guard peerCircuits < maxCircuitsPerPeer else { return false }

        let now: ContinuousClock.Instant = .now
        circuits[key] = Circuit(peerA: initiator, peerB: target, created: now, lastActivity: now, windowStart: now)
        return true
    }

    /// Account `bytes` against the circuit; returns false if absent/expired
    /// (caller must then drop the frame and may tear the circuit down).
    func relay(from src: String, to dst: String, bytes: Int) -> Bool {
        let key = circuitKey(src, dst)
        guard var circuit = circuits[key] else { return false }
        if circuit.isExpired {
            circuits.removeValue(forKey: key)
            return false
        }
        let now: ContinuousClock.Instant = .now
        // Roll the byte-rate window if it has elapsed.
        if circuit.windowStart.duration(to: now) > Circuit.rateWindow {
            circuit.windowStart = now
            circuit.bytesInWindow = 0
        }
        circuit.bytesInWindow += bytes
        // Over the per-window rate cap: DROP this frame but KEEP the circuit — a rate limit
        // throttles, it does not destroy a legitimate stream mid-burst. Tearing down here
        // would (a) re-introduce the black-holing this change fixes (a sync backlog bursts
        // past the cap) and (b) trip the pre-existing relay/endpoint role-confusion in
        // handleRelayData (a torn circuit makes the next relayData look like endpoint traffic).
        // Persist the counter (the window keeps accounting) and do NOT renew the idle timeout,
        // so a circuit that only ever floods still idles out.
        if circuit.bytesInWindow > Circuit.maxBytesPerWindow {
            circuits[key] = circuit
            return false
        }
        // Renew the idle timeout on a SUCCESSFUL relay — an actively-relaying circuit lives past 120s.
        circuit.lastActivity = now
        circuits[key] = circuit
        return true
    }

    func hasCircuit(between a: String, and b: String) -> Bool {
        let key = circuitKey(a, b)
        guard let circuit = circuits[key] else { return false }
        return !circuit.isExpired
    }

    func removeCircuit(between a: String, and b: String) {
        circuits.removeValue(forKey: circuitKey(a, b))
    }

    func removeAllCircuits(forPeer peerKey: String) {
        circuits = circuits.filter { $0.value.peerA != peerKey && $0.value.peerB != peerKey }
    }

    func activeCircuitCount() -> Int {
        pruneExpired()
        return circuits.count
    }

    private func pruneExpired() {
        circuits = circuits.filter { !$0.value.isExpired }
    }
}
