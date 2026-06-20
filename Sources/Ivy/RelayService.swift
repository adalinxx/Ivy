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
        let created: ContinuousClock.Instant
        var bytesRelayed: Int = 0

        static let maxDuration: Duration = .seconds(120)
        static let maxBytes = 128 * 1024  // tunable default, not a protocol constant

        var isExpired: Bool {
            created.duration(to: .now) > Self.maxDuration || bytesRelayed >= Self.maxBytes
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

        circuits[key] = Circuit(peerA: initiator, peerB: target, created: .now)
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
        circuit.bytesRelayed += bytes
        // Reject (and close) the frame that pushes the circuit over its budget,
        // rather than forwarding it and only refusing the next one.
        if circuit.isExpired {
            circuits.removeValue(forKey: key)
            return false
        }
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
