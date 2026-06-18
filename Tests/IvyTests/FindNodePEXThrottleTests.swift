import Testing
import Foundation
@testable import Ivy
@testable import Tally

private func throttleConfig(
    publicKey: String,
    findNodeBurst: Double = 40,
    findNodeRefillPerSec: Double = 10,
    pexMaxAcceptedPerRound: Int? = nil,
    pexMinResponderScore: Double = 0
) -> IvyConfig {
    IvyConfig(
        publicKey: publicKey,
        listenPort: 0,
        bootstrapPeers: [],
        enableLocalDiscovery: false,
        healthConfig: PeerHealthConfig(
            keepaliveInterval: .seconds(999),
            staleTimeout: .seconds(999),
            maxMissedPongs: 99,
            enabled: false
        ),
        enablePEX: false,
        findNodeBurst: findNodeBurst,
        findNodeRefillPerSec: findNodeRefillPerSec,
        pexMaxAcceptedPerRound: pexMaxAcceptedPerRound,
        pexMinResponderScore: pexMinResponderScore
    )
}

@Suite("findNode + PEX throttling")
struct FindNodePEXThrottleTests {

    @Test("findNode from an unidentified (temp) peer is not served")
    func findNodeFromTempPeerRejected() async throws {
        // A still-temporary inbound-<uuid> id must not be served findNode, so an
        // attacker cannot reset its per-peer rate bucket by churning connection
        // ids before identifying.
        let node = Ivy(config: throttleConfig(
            publicKey: "tempgate-node",
            findNodeBurst: 10,
            findNodeRefillPerSec: 0
        ))
        let localID = await node.localID
        let tempID = PeerID(publicKey: "inbound-\(UUID().uuidString)")
        let (peerSide, nodeSide) = LocalPeerConnection.pair(localID: tempID, remoteID: localID)
        await node.registerLocalPeer(nodeSide, as: tempID)
        await node.addToRouter(
            PeerID(publicKey: "tempgate-entry"),
            endpoint: PeerEndpoint(publicKey: "tempgate-entry", host: "10.3.0.1", port: 4001)
        )

        let collector = Task<Int, Never> {
            var n = 0
            var iterator = peerSide.messages.makeAsyncIterator()
            while let msg = await iterator.next() {
                if case .neighbors = msg { n += 1 }
            }
            return n
        }

        for i in 0..<5 {
            peerSide.send(.findNode(target: Data("t\(i)".utf8), fee: 0, nonce: UInt64(i)))
        }
        try await Task.sleep(for: .milliseconds(200))
        collector.cancel()
        let neighborsCount = await collector.value

        #expect(neighborsCount == 0)
        peerSide.close()
    }

    @Test("findNode flood is throttled — requests past the burst are dropped")
    func findNodeFloodThrottled() async throws {
        // Small burst, no refill within the test window.
        let node = Ivy(config: throttleConfig(
            publicKey: "throttle-findnode-node",
            findNodeBurst: 3,
            findNodeRefillPerSec: 0
        ))
        let localID = await node.localID
        let peerID = PeerID(publicKey: "throttle-findnode-sender")
        let (peerSide, nodeSide) = LocalPeerConnection.pair(localID: peerID, remoteID: localID)
        await node.registerLocalPeer(nodeSide, as: peerID)
        await node.addToRouter(
            PeerID(publicKey: "throttle-table-entry"),
            endpoint: PeerEndpoint(publicKey: "throttle-table-entry", host: "10.2.0.1", port: 4001)
        )

        var neighborsCount = 0
        let collector = Task<Int, Never> {
            var n = 0
            var iterator = peerSide.messages.makeAsyncIterator()
            while let msg = await iterator.next() {
                if case .neighbors = msg { n += 1 }
            }
            return n
        }

        // Fire many findNode requests rapidly; only the burst (3) should reply.
        for i in 0..<10 {
            peerSide.send(.findNode(target: Data("t\(i)".utf8), fee: 0, nonce: UInt64(i)))
        }
        try await Task.sleep(for: .milliseconds(200))
        collector.cancel()
        neighborsCount = await collector.value

        #expect(neighborsCount == 3)

        peerSide.close()
    }

    @Test("PEX response with more than the cap accepts only the cap")
    func pexResponseCapped() async throws {
        let cap = 4
        let node = Ivy(config: throttleConfig(
            publicKey: "throttle-pexcap-node",
            pexMaxAcceptedPerRound: cap
        ))
        let peerID = PeerID(publicKey: "throttle-pexcap-sender")

        // 10 valid, distinct endpoints (minPeerKeyBits is 0 → all pass validation).
        let entries = (0..<10).map {
            PeerEndpoint(publicKey: "pex-cand-\($0)", host: "10.5.\($0).1", port: 4001)
        }

        let accepted = await node.receivePEXResponseForTesting(
            nonce: 0xca90,
            peers: entries,
            from: peerID
        )
        #expect(accepted.count == cap)
    }

    @Test("Low-reputation responder's PEX entries are not accepted")
    func lowReputationResponderRejected() async throws {
        // Floor above zero; an unknown peer scores 0 → its feed is dropped.
        let node = Ivy(config: throttleConfig(
            publicKey: "throttle-pexrep-node",
            pexMinResponderScore: 0.01
        ))
        let peerID = PeerID(publicKey: "throttle-pexrep-sender")
        let entries = [PeerEndpoint(publicKey: "pex-rep-cand", host: "10.6.0.1", port: 4001)]

        let accepted = await node.receivePEXResponseForTesting(
            nonce: 0x9009,
            peers: entries,
            from: peerID
        )
        #expect(accepted.isEmpty)

        // With the default permissive floor (0), the same feed is accepted.
        let permissive = Ivy(config: throttleConfig(publicKey: "throttle-pexrep-ok-node"))
        let acceptedPermissive = await permissive.receivePEXResponseForTesting(
            nonce: 0x9009,
            peers: entries,
            from: peerID
        )
        #expect(acceptedPermissive.count == 1)
    }
}
