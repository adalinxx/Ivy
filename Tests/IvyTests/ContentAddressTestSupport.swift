import Foundation
import CID
import Multihash

/// The CID of `data` in the network's content-address format — CIDv1 / dag-json /
/// sha2-256 (matching cashew). Previously delegated to Acorn's `ContentIdentifier`;
/// inlined here over `CID` + `Multihash` (Ivy's own dependencies) so the Ivy package
/// no longer depends on Acorn. `try!` is safe: hashing in-memory test `Data` cannot fail.
func testCID(for data: Data) -> String {
    let multihash = try! Multihash(raw: data, hashedWith: .sha2_256)
    return try! CID(version: .v1, codec: .dag_json, multihash: multihash).toBaseEncodedString
}
