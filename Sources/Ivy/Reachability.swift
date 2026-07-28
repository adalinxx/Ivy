import Foundation

/// Whether this node believes peers can dial it directly on a transport.
public enum Reachability: Sendable, Equatable {
    case unknown
    case publiclyReachable
    case unreachable
}

/// The dial-back a probe responder sends: the only frame on a fresh connection,
/// carrying back the nonce it was asked to echo. It is smaller than the request
/// that triggers it, so the exchange cannot amplify traffic.
enum ReachabilityProbe {
    static let nonceByteCount = 32
    static let magic = Data([0x49, 0x56, 0x59, 0x44])  // "IVYD"
    static let version: UInt8 = 1
    static let frameByteCount = magic.count + 1 + nonceByteCount

    static func encode(nonce: Data) -> Data? {
        guard nonce.count == nonceByteCount else { return nil }
        var bytes = magic
        bytes.append(version)
        bytes.append(nonce)
        return bytes
    }

    /// Returns the nonce if `data` is a dial-back frame, else nil. Callers use a
    /// nil result to fall through to ordinary session decoding.
    static func decode(_ data: Data) -> Data? {
        guard data.count == frameByteCount,
              data.prefix(magic.count) == magic else { return nil }
        let versionIndex = data.index(data.startIndex, offsetBy: magic.count)
        guard data[versionIndex] == version else { return nil }
        return Data(data.suffix(nonceByteCount))
    }
}

/// A dial-back this node asked a peer to perform, awaiting the nonce inbound.
struct PendingReachabilityProbe: Sendable {
    let requestID: UInt64
    let peer: PeerKey
    let transport: TransportKind
    let nonce: Data
    let generation: UInt64
}

/// Tracks per-transport reachability and decides when to probe again.
///
/// A peer that lies in its response can only withhold a confirmation, never
/// manufacture one: confirmation requires the nonce arriving on an inbound
/// connection, which a NAT would have dropped.
struct ReachabilityState: Sendable {
    private(set) var status: Reachability = .unknown
    private(set) var confirmations = 0
    private(set) var failures = 0
    private(set) var outstanding = 0
    private var backoffMultiplier = 1

    var isProbing: Bool { outstanding > 0 }

    mutating func beginRound(probeCount: Int) {
        confirmations = 0
        failures = 0
        outstanding = probeCount
    }

    /// Records a nonce that arrived inbound, which is the only proof of reachability.
    mutating func recordConfirmation(required: Int) {
        confirmations += 1
        if outstanding > 0 { outstanding -= 1 }
        if confirmations >= required {
            status = .publiclyReachable
            backoffMultiplier = 1
            outstanding = 0
        }
    }

    mutating func recordFailure() {
        failures += 1
        if outstanding > 0 { outstanding -= 1 }
    }

    /// Called once a round has no probes left outstanding.
    mutating func finishRound(requiredFailures: Int) {
        guard outstanding == 0, status != .publiclyReachable else { return }
        if confirmations == 0, failures >= requiredFailures {
            status = .unreachable
        }
        backoffMultiplier = min(backoffMultiplier * 2, 4)
    }

    mutating func declareReachable() {
        status = .publiclyReachable
        outstanding = 0
        backoffMultiplier = 1
    }

    func nextInterval(base: Duration) -> Duration {
        base * backoffMultiplier
    }
}
