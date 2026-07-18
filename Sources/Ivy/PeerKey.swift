import Crypto
import Foundation
import Tally

public enum PeerKeyError: Error, Equatable {
    case invalidEncoding
}

/// Ivy's canonical Ed25519 identity. Text encodings are accepted only at API
/// boundaries; protocol and session state always carry the validated 32 bytes.
public struct PeerKey: Hashable, Sendable, Comparable, CustomStringConvertible {
    public static let byteCount = 32

    public let rawRepresentation: Data

    public init(rawRepresentation: Data) throws {
        guard rawRepresentation.count == Self.byteCount,
              (try? Curve25519.Signing.PublicKey(rawRepresentation: rawRepresentation)) != nil else {
            throw PeerKeyError.invalidEncoding
        }
        self.rawRepresentation = rawRepresentation
    }

    public init(_ encoded: String) throws {
        let rawHex: Substring
        if encoded.count == 68, encoded.prefix(4).lowercased() == "ed01" {
            rawHex = encoded.dropFirst(4)
        } else {
            rawHex = encoded[encoded.startIndex...]
        }
        guard rawHex.count == Self.byteCount * 2,
              let bytes = Data(hexString: String(rawHex)) else {
            throw PeerKeyError.invalidEncoding
        }
        try self.init(rawRepresentation: bytes)
    }

    public var hex: String {
        rawRepresentation.map { String(format: "%02x", $0) }.joined()
    }

    public var description: String { hex }

    public static func < (lhs: PeerKey, rhs: PeerKey) -> Bool {
        lhs.rawRepresentation.lexicographicallyPrecedes(rhs.rawRepresentation)
    }

    var peerID: PeerID { PeerID(publicKey: hex) }
}
