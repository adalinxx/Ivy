import Foundation
import CID
import Multihash

public enum ContentAddressVerifier {
    public static func data(_ data: Data, matches rawCID: String) -> Bool {
        guard let expectedCID = try? CID(rawCID),
              let hashAlgorithm = expectedCID.multihash.algorithm,
              let actualMultihash = try? Multihash(raw: data, hashedWith: hashAlgorithm),
              let actualCID = try? CID(
                  version: expectedCID.version,
                  codec: expectedCID.codec,
                  multihash: actualMultihash
              ) else {
            return false
        }
        return actualCID == expectedCID
    }
}
