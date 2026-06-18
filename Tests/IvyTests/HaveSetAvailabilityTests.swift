import Testing
import Foundation
@testable import Ivy
@testable import Tally

extension Ivy {
    func haveSetContainsForTesting(_ cid: String) -> Bool {
        haveSet.contains(cid)
    }
}

@Suite("haveSet availability")
struct HaveSetAvailabilityTests {
    @Test("Transient local block miss during DHT forward does not evict haveSet")
    func transientMissDoesNotEvictHaveSet() async {
        let node = Ivy(config: IvyConfig(
            publicKey: "haveset-node",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            enablePEX: false
        ))
        let cid = "haveset-transient-miss"
        let requester = PeerID(publicKey: "haveset-requester")

        await node.markAvailable(cids: [cid])
        #expect(await node.haveSetContainsForTesting(cid))

        await node.handleDHTForward(cid: cid, ttl: 0, from: requester)

        #expect(await node.haveSetContainsForTesting(cid))
    }
}
