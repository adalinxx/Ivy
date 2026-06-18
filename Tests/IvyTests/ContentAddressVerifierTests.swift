import Testing
import Foundation
import Ivy
import CID
import Multihash

@Suite("Content Address Verification")
struct ContentAddressVerifierTests {
    @Test("accepts bytes matching their CID")
    func acceptsMatchingCID() {
        let data = Data("verified payload".utf8)
        #expect(ContentAddressVerifier.data(data, matches: testCID(for: data)))
    }

    @Test("rejects bytes that do not match their CID")
    func rejectsMismatchedCID() {
        let data = Data("original payload".utf8)
        let forged = Data("forged payload".utf8)
        #expect(!ContentAddressVerifier.data(forged, matches: testCID(for: data)))
    }

    @Test("uses the CID's multihash algorithm")
    func usesCIDMultihashAlgorithm() throws {
        let data = Data("sha512 addressed payload".utf8)
        let multihash = try Multihash(raw: data, hashedWith: .sha2_512)
        let cid = try CID(version: .v1, codec: .dag_json, multihash: multihash)

        #expect(ContentAddressVerifier.data(data, matches: cid.toBaseEncodedString))
        #expect(!ContentAddressVerifier.data(Data("wrong".utf8), matches: cid.toBaseEncodedString))
    }
}
