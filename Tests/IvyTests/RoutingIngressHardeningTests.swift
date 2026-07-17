import Foundation
import Testing
@testable import Ivy
import Tally

private extension Ivy {
    func addTestRoute(_ peer: PeerID, port: UInt16) {
        router.addPeer(
            peer,
            endpoint: PeerEndpoint(
                publicKey: peer.publicKey,
                host: "127.0.0.1",
                port: port))
    }

    func awaitTestNeighbors(nonce: UInt64, from peer: PeerID) async -> [PeerEndpoint] {
        await withCheckedContinuation { continuation in
            pendingNeighborResponses[nonce] = PendingNeighborResponse(
                peer: peer,
                continuation: continuation)
        }
    }

    func hasPendingTestNeighbors(nonce: UInt64) -> Bool {
        pendingNeighborResponses[nonce] != nil
    }
}

@Suite("Routing ingress hardening", .serialized)
struct RoutingIngressHardeningTests {
    @Test("Solicited neighbors obey identity, address, and key-work policy")
    func solicitedNeighborsAreValidated() async throws {
        let requiredBits = 2
        let node = routingNode("routing-policy", minPeerKeyBits: requiredBits)
        let peerID = PeerID(publicKey: deterministicTestPeerKey("routing-policy-peer"))
        await node.addTestRoute(peerID, port: 1)
        let nonce: UInt64 = 1
        let waiter = Task { await node.awaitTestNeighbors(nonce: nonce, from: peerID) }
        #expect(try await TransportTestHarness.eventually {
            await node.hasPendingTestNeighbors(nonce: nonce)
        })

        let lowWork = keyWithWork(lessThan: requiredBits)
        let valid = keyWithWork(atLeast: requiredBits)
        let unusable = keyWithWork(atLeast: requiredBits, seed: "unusable")
        await node.handleMessage(.neighbors([
            PeerEndpoint(publicKey: "not-a-peer-key", host: "10.0.0.1", port: 4001),
            PeerEndpoint(publicKey: lowWork, host: "10.0.0.2", port: 4001),
            PeerEndpoint(publicKey: unusable, host: "10.0.0.3", port: 0),
            PeerEndpoint(publicKey: valid, host: "10.0.0.4", port: 4001),
        ], nonce: nonce), from: peerID)
        _ = await waiter.value

        let routed = Set(await node.knownPeerEndpoints.map(\.publicKey))
        #expect(routed == Set([peerID.publicKey, valid]))
    }

    @Test("Unsolicited and wrong-peer neighbors cannot mutate routing")
    func neighborsRequireTheExpectedPeerAndNonce() async throws {
        let node = routingNode("routing-correlation")
        let wrongID = PeerID(publicKey: deterministicTestPeerKey("routing-wrong-peer"))
        let queriedID = PeerID(publicKey: deterministicTestPeerKey("routing-queried-peer"))
        let advertised = testRoutingEndpoint("routing-advertised", port: 4001)

        await node.handleMessage(.neighbors([advertised], nonce: 0xfeed), from: wrongID)
        #expect(!(await node.knownPeerEndpoints.map(\.publicKey).contains(advertised.publicKey)))

        let nonce: UInt64 = 2
        let waiter = Task { await node.awaitTestNeighbors(nonce: nonce, from: queriedID) }
        #expect(try await TransportTestHarness.eventually {
            await node.hasPendingTestNeighbors(nonce: nonce)
        })
        await node.handleMessage(.neighbors([advertised], nonce: nonce), from: wrongID)
        #expect(!(await node.knownPeerEndpoints.map(\.publicKey).contains(advertised.publicKey)))

        await node.handleMessage(.neighbors([advertised], nonce: nonce), from: queriedID)
        _ = await waiter.value
        #expect(await node.knownPeerEndpoints.map(\.publicKey).contains(advertised.publicKey))
    }

    @Test("Public discovery rejects SSRF destinations")
    func publicDiscoveryRejectsNonGlobalHosts() async {
        let node = routingNode(
            "routing-public",
            externalAddress: (host: "8.8.8.8", port: 4001))
        let source = PeerID(publicKey: deterministicTestPeerKey("routing-source"))
        let endpointKey = deterministicTestPeerKey("routing-endpoint")

        for host in [
            "127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.1",
            "::1", "fc00::1", "64:ff9b::0a00:0001", "example.com",
        ] {
            let endpoint = PeerEndpoint(publicKey: endpointKey, host: host, port: 4001)
            #expect(!(await node.isAcceptableDiscoveredEndpoint(endpoint, source: "test", from: source)))
        }

        for host in ["1.1.1.1", "2606:4700:4700::1111", "64:ff9b::0808:0808"] {
            let endpoint = PeerEndpoint(publicKey: endpointKey, host: host, port: 4001)
            #expect(await node.isAcceptableDiscoveredEndpoint(endpoint, source: "test", from: source))
        }

        let localNode = routingNode("routing-local")
        let privateEndpoint = PeerEndpoint(publicKey: endpointKey, host: "10.0.0.1", port: 4001)
        #expect(await localNode.isAcceptableDiscoveredEndpoint(
            privateEndpoint,
            source: "test",
            from: source))

        let domainNode = routingNode(
            "routing-domain",
            externalAddress: (host: "node.example", port: 4001))
        #expect(!(await domainNode.isAcceptableDiscoveredEndpoint(
            privateEndpoint,
            source: "test",
            from: source)))
    }
}

private func routingNode(
    _ label: String,
    minPeerKeyBits: Int = 0,
    externalAddress: (host: String, port: UInt16)? = nil
) -> Ivy {
    Ivy(config: IvyConfig(
        publicKey: label,
        listenPort: 0,
        bootstrapPeers: [],
        minPeerKeyBits: minPeerKeyBits,
        externalAddress: externalAddress))
}

private func testRoutingEndpoint(_ label: String, port: UInt16) -> PeerEndpoint {
    PeerEndpoint(publicKey: deterministicTestPeerKey(label), host: "10.0.0.1", port: port)
}

private func keyWithWork(atLeast target: Int, seed: String = "valid") -> String {
    for index in 0..<10_000 {
        let key = deterministicTestPeerKey("routing-\(seed)-\(index)")
        if KeyDifficulty.keyWorkBits(key) >= target { return key }
    }
    fatalError("Unable to find key with requested work")
}

private func keyWithWork(lessThan target: Int) -> String {
    for index in 0..<10_000 {
        let key = deterministicTestPeerKey("routing-low-work-\(index)")
        if KeyDifficulty.keyWorkBits(key) < target { return key }
    }
    fatalError("Unable to find key below requested work")
}
