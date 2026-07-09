import Testing
import Foundation
@testable import Ivy
@testable import Tally

private func routingConfig(
    publicKey: String,
    minPeerKeyBits: Int = 0,
    tallyConfig: TallyConfig = .default
) -> IvyConfig {
    IvyConfig(
        publicKey: publicKey,
        listenPort: 0,
        bootstrapPeers: [],
        enableLocalDiscovery: false,
        tallyConfig: tallyConfig,
        healthConfig: PeerHealthConfig(
            keepaliveInterval: .seconds(999),
            staleTimeout: .seconds(999),
            maxMissedPongs: 99,
            enabled: false
        ),
        enablePEX: false,
        minPeerKeyBits: minPeerKeyBits
    )
}

private func keyWithDifficulty(atLeast target: Int) -> String {
    for i in 0..<10_000 {
        let key = "routing-valid-\(target)-\(i)"
        if KeyDifficulty.trailingZeroBits(of: key) >= target {
            return key
        }
    }
    fatalError("Unable to find key with target difficulty \(target)")
}

private func keyWithDifficulty(lessThan target: Int) -> String {
    for i in 0..<10_000 {
        let key = "routing-invalid-\(target)-\(i)"
        if KeyDifficulty.trailingZeroBits(of: key) < target {
            return key
        }
    }
    fatalError("Unable to find key below target difficulty \(target)")
}

private func nextMessage(
    from conn: LocalPeerConnection,
    after send: () -> Void,
    wait: Duration = .milliseconds(150)
) async throws -> Message? {
    let task = Task<Message?, Never> {
        var iterator = conn.messages.makeAsyncIterator()
        return await iterator.next()
    }
    send()
    try await Task.sleep(for: wait)
    task.cancel()
    return await task.value
}

@Suite("Routing ingress hardening")
struct RoutingIngressHardeningTests {

    @Test("Solicited neighbors only inserts endpoints that pass routing identity and address validation")
    func neighborsRejectInvalidDiscoveredEndpoints() async throws {
        let requiredBits = 2
        let node = Ivy(config: routingConfig(publicKey: "routing-node", minPeerKeyBits: requiredBits))
        let localID = await node.localID
        let peerID = PeerID(publicKey: "routing-neighbor-sender")
        let (peerSide, nodeSide) = LocalPeerConnection.pair(localID: peerID, remoteID: localID)
        await node.registerLocalPeer(nodeSide, as: peerID)
        await node.addToRouter(peerID, endpoint: PeerEndpoint(publicKey: peerID.publicKey, host: "local", port: 1))

        let badKey = keyWithDifficulty(lessThan: requiredBits)
        let goodKey = keyWithDifficulty(atLeast: requiredBits)

        var lookup: Task<[PeerEndpoint], Never>!
        let request = try await nextMessage(from: peerSide) {
            lookup = Task { await node.findNode(target: goodKey) }
        }
        guard case .findNode(_, _, let nonce) = request else {
            Issue.record("Expected findNode")
            return
        }

        peerSide.send(.neighbors([
            PeerEndpoint(publicKey: badKey, host: "10.0.0.1", port: 4001),
            PeerEndpoint(publicKey: goodKey, host: "10.0.0.2", port: 4001),
            PeerEndpoint(publicKey: keyWithDifficulty(atLeast: requiredBits), host: "0.0.0.0", port: 4001),
            PeerEndpoint(publicKey: keyWithDifficulty(atLeast: requiredBits), host: "10.0.0.3", port: 0)
        ], nonce: nonce))
        _ = await lookup.value

        let routedKeys = await Set(node.allRouterPeers().map { $0.id.publicKey })
        #expect(!routedKeys.contains(badKey))
        #expect(routedKeys.contains(goodKey))
        #expect(routedKeys.count == 2)

        peerSide.close()
    }

    @Test("Unsolicited neighbors responses do not mutate routing table")
    func unsolicitedNeighborsResponseIsIgnored() async throws {
        let node = Ivy(config: routingConfig(publicKey: "routing-unsolicited-neighbors-node"))
        let localID = await node.localID
        let peerID = PeerID(publicKey: "routing-unsolicited-neighbors-sender")
        let (peerSide, nodeSide) = LocalPeerConnection.pair(localID: peerID, remoteID: localID)
        await node.registerLocalPeer(nodeSide, as: peerID)

        let advertised = PeerEndpoint(publicKey: "routing-unsolicited-neighbor", host: "10.0.0.1", port: 4001)
        peerSide.send(.neighbors([advertised], nonce: 0xfeed))
        try await Task.sleep(for: .milliseconds(100))

        let routedKeys = await Set(node.allRouterPeers().map { $0.id.publicKey })
        #expect(!routedKeys.contains(advertised.publicKey))

        peerSide.close()
    }

    @Test("Neighbors response with wrong nonce does not mutate routing table")
    func wrongNonceNeighborsResponseIsIgnored() async throws {
        let node = Ivy(config: routingConfig(publicKey: "routing-wrong-nonce-node"))
        let localID = await node.localID
        let peerID = PeerID(publicKey: "routing-wrong-nonce-sender")
        let (peerSide, nodeSide) = LocalPeerConnection.pair(localID: peerID, remoteID: localID)
        await node.registerLocalPeer(nodeSide, as: peerID)
        await node.addToRouter(peerID, endpoint: PeerEndpoint(publicKey: peerID.publicKey, host: "local", port: 1))

        let advertised = PeerEndpoint(publicKey: "routing-wrong-nonce-neighbor", host: "10.0.0.1", port: 4001)
        var lookup: Task<[PeerEndpoint], Never>!
        let request = try await nextMessage(from: peerSide) {
            lookup = Task { await node.findNode(target: advertised.publicKey) }
        }
        guard case .findNode(_, _, let nonce) = request else {
            Issue.record("Expected findNode")
            return
        }

        peerSide.send(.neighbors([advertised], nonce: nonce &+ 1))
        try await Task.sleep(for: .milliseconds(100))
        #expect(!(await Set(node.allRouterPeers().map { $0.id.publicKey })).contains(advertised.publicKey))

        peerSide.send(.neighbors([advertised], nonce: nonce))
        _ = await lookup.value
        #expect((await Set(node.allRouterPeers().map { $0.id.publicKey })).contains(advertised.publicKey))

        peerSide.close()
    }

    @Test("Neighbors response from wrong peer does not satisfy stolen nonce")
    func wrongPeerNeighborsResponseIsIgnored() async throws {
        let node = Ivy(config: routingConfig(publicKey: "routing-wrong-peer-node"))
        let localID = await node.localID
        let queriedID = PeerID(publicKey: "routing-queried-peer")
        let wrongID = PeerID(publicKey: "routing-wrong-peer")
        let (queriedSide, queriedNodeSide) = LocalPeerConnection.pair(localID: queriedID, remoteID: localID)
        let (wrongSide, wrongNodeSide) = LocalPeerConnection.pair(localID: wrongID, remoteID: localID)
        await node.registerLocalPeer(queriedNodeSide, as: queriedID)
        await node.registerLocalPeer(wrongNodeSide, as: wrongID)
        await node.addToRouter(queriedID, endpoint: PeerEndpoint(publicKey: queriedID.publicKey, host: "local", port: 1))

        let advertised = PeerEndpoint(publicKey: "routing-stolen-nonce-neighbor", host: "10.0.0.1", port: 4001)
        var lookup: Task<[PeerEndpoint], Never>!
        let request = try await nextMessage(from: queriedSide) {
            lookup = Task { await node.findNode(target: advertised.publicKey) }
        }
        guard case .findNode(_, _, let nonce) = request else {
            Issue.record("Expected findNode")
            return
        }

        wrongSide.send(.neighbors([advertised], nonce: nonce))
        try await Task.sleep(for: .milliseconds(100))
        #expect(!(await Set(node.allRouterPeers().map { $0.id.publicKey })).contains(advertised.publicKey))

        queriedSide.send(.neighbors([advertised], nonce: nonce))
        _ = await lookup.value
        #expect((await Set(node.allRouterPeers().map { $0.id.publicKey })).contains(advertised.publicKey))

        queriedSide.close()
        wrongSide.close()
    }

    @Test("Unsolicited PEX responses do not mutate routing table or earn success")
    func unsolicitedPEXResponseIsIgnored() async throws {
        let node = Ivy(config: routingConfig(publicKey: "routing-pex-node"))
        let localID = await node.localID
        let peerID = PeerID(publicKey: "routing-pex-sender")
        let (peerSide, nodeSide) = LocalPeerConnection.pair(localID: peerID, remoteID: localID)
        await node.registerLocalPeer(nodeSide, as: peerID)

        let tally = await node.tally
        tally.recordReceived(peer: peerID, bytes: 1)
        let advertised = PeerEndpoint(publicKey: "routing-pex-poison", host: "10.1.0.1", port: 4001)

        peerSide.send(.pexResponse(nonce: 0xfeed, peers: [advertised]))
        try await Task.sleep(for: .milliseconds(100))

        let routedKeys = await Set(node.allRouterPeers().map { $0.id.publicKey })
        #expect(!routedKeys.contains(advertised.publicKey))
        #expect((tally.peerLedger(for: peerID)?.successCount.value ?? 0) == 0)

        peerSide.close()
    }

    @Test("Solicited PEX with invalid endpoints is not rewarded")
    func solicitedInvalidPEXResponseIsNotRewarded() async throws {
        let requiredBits = 2
        let node = Ivy(config: routingConfig(publicKey: "routing-pex-invalid-node", minPeerKeyBits: requiredBits))
        let localID = await node.localID
        let peerID = PeerID(publicKey: "routing-pex-invalid-sender")
        let (peerSide, nodeSide) = LocalPeerConnection.pair(localID: peerID, remoteID: localID)
        await node.registerLocalPeer(nodeSide, as: peerID)

        let tally = await node.tally
        tally.recordReceived(peer: peerID, bytes: 1)
        let invalid = PeerEndpoint(
            publicKey: keyWithDifficulty(lessThan: requiredBits),
            host: "10.1.0.2",
            port: 4001
        )

        let discovered = await node.receivePEXResponseForTesting(
            nonce: 0xbeef,
            peers: [invalid],
            from: peerID
        )

        #expect(discovered.isEmpty)
        let ledger = tally.peerLedger(for: peerID)
        #expect((ledger?.successCount.value ?? 0) == 0)
        #expect(ledger?.failureCount.value == 1)

        peerSide.close()
    }

    @Test("A public node rejects discovered endpoints in non-routable address space")
    func publicNodeRejectsNonRoutableDiscoveredEndpoints() async {
        // A node with a declared, GENUINELY globally-routable externalAddress is
        // public-facing (8.8.8.8 is real global unicast, not a special-use range).
        let publicNode = Ivy(config: IvyConfig(
            publicKey: "routing-public-node",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            healthConfig: PeerHealthConfig(keepaliveInterval: .seconds(999), staleTimeout: .seconds(999), maxMissedPongs: 99, enabled: false),
            enablePEX: false,
            externalAddress: (host: "8.8.8.8", port: 4001)
        ))
        let source = PeerID(publicKey: "routing-public-source")
        func ep(_ host: String) -> PeerEndpoint {
            PeerEndpoint(publicKey: "disc-\(host)", host: host, port: 4001)
        }

        // Non-routable / special-use / internal / non-IP: all rejected (no SSRF
        // steering into private hosts OR into special-use/documentation ranges).
        for host in ["127.0.0.1", "10.0.0.1", "172.16.5.5", "192.168.1.1",
                     "169.254.1.1", "100.64.0.1", "240.0.0.1", "255.255.255.255",
                     // Newly-classified special-use ranges (multicast / benchmarking /
                     // RFC 5737 TEST-NET-1/2/3 / IPv6 multicast / RFC 3849 docs).
                     "224.0.0.1", "239.0.0.1", "198.18.0.1", "192.0.2.1",
                     "198.51.100.7", "203.0.113.5", "ff02::1", "2001:db8::1",
                     "::1", "fe80::1", "fc00::1",
                     // IPv6 transition forms wrapping an INTERNAL IPv4 must be
                     // classified by the embedded v4 (SSRF via NAT64/6to4/Teredo
                     // translation host), not passed through as routable IPv6.
                     "64:ff9b::a9fe:a9fe",   // NAT64 (RFC 6052) → 169.254.169.254 metadata
                     "64:ff9b::0a00:0001",   // NAT64 (RFC 6052) → 10.0.0.1 private
                     "2002:0a00:0001::1",    // 6to4 (RFC 3964) → 10.0.0.1 private
                     "2001::f5ff:fffe",      // Teredo (RFC 4380) → 10.0.0.1 private
                     "not-an-ip", "example.com"] {
            #expect(!(await publicNode.isAcceptableDiscoveredEndpoint(ep(host), source: "test", from: source)),
                    "public node must reject non-routable/special-use host \(host)")
        }
        // Genuinely globally-routable addresses still pass.
        #expect(await publicNode.isAcceptableDiscoveredEndpoint(ep("1.1.1.1"), source: "test", from: source))
        #expect(await publicNode.isAcceptableDiscoveredEndpoint(ep("2606:4700:4700::1111"), source: "test", from: source))
        // Transition forms wrapping a PUBLIC IPv4 embed a routable address, so
        // they must stay ACCEPTED — proves we extract-and-classify the embedded
        // v4 rather than blanket-rejecting the transition prefix.
        #expect(await publicNode.isAcceptableDiscoveredEndpoint(ep("64:ff9b::0808:0808"), source: "test", from: source))  // NAT64 of 8.8.8.8
        #expect(await publicNode.isAcceptableDiscoveredEndpoint(ep("2002:0808:0808::1"), source: "test", from: source))   // 6to4 of 8.8.8.8

        // A node WITHOUT a public externalAddress (local/test mode) still accepts
        // loopback/private peers — the filter must not break local operation.
        let localNode = Ivy(config: routingConfig(publicKey: "routing-local-node"))
        #expect(await localNode.isAcceptableDiscoveredEndpoint(ep("127.0.0.1"), source: "test", from: source))
        #expect(await localNode.isAcceptableDiscoveredEndpoint(ep("10.0.0.1"), source: "test", from: source))
    }

    @Test("A STUN-reflexive-public node (no externalAddress) rejects non-routable discovered endpoints")
    func stunPublicNodeRejectsNonRoutableDiscoveredEndpoints() async {
        // No declared externalAddress, but the node became publicly reachable via
        // STUN: start() stores a reflexive publicAddress and sendIdentify advertises
        // it. Such a node is effectively public, so the SSRF non-routable filter
        // must apply — even though config.externalAddress is nil.
        let stunNode = Ivy(config: routingConfig(publicKey: "routing-stun-public-node"))
        await stunNode.setPublicAddressForTesting(ObservedAddress(host: "8.8.8.8", port: 4001))
        let source = PeerID(publicKey: "routing-stun-public-source")
        func ep(_ host: String) -> PeerEndpoint {
            PeerEndpoint(publicKey: "stun-disc-\(host)", host: host, port: 4001)
        }

        for host in ["10.0.0.1", "169.254.169.254", "127.0.0.1", "192.168.1.1"] {
            #expect(!(await stunNode.isAcceptableDiscoveredEndpoint(ep(host), source: "test", from: source)),
                    "STUN-public node must reject non-routable host \(host)")
        }
        // Genuinely routable endpoints still pass.
        #expect(await stunNode.isAcceptableDiscoveredEndpoint(ep("1.1.1.1"), source: "test", from: source))
    }

    @Test("findNode handler is gated by Tally before enumerating routing table")
    func findNodeIsGatedBeforeReplyingWithNeighbors() async throws {
        let tallyConfig = TallyConfig(rateLimitBytesPerSecond: 1)
        let node = Ivy(config: routingConfig(publicKey: "routing-find-node", tallyConfig: tallyConfig))
        let localID = await node.localID
        let peerID = PeerID(publicKey: "routing-find-node-sender")
        let (peerSide, nodeSide) = LocalPeerConnection.pair(localID: peerID, remoteID: localID)
        await node.registerLocalPeer(nodeSide, as: peerID)
        await node.addToRouter(
            PeerID(publicKey: "routing-table-entry"),
            endpoint: PeerEndpoint(publicKey: "routing-table-entry", host: "10.2.0.1", port: 4001)
        )

        let tally = await node.tally
        tally.recordSent(peer: PeerID(publicKey: "pressure-source"), bytes: 1_000)

        let response = try await nextMessage(from: peerSide) {
            peerSide.send(.findNode(target: Data("target".utf8)))
        }

        #expect(response == nil)

        peerSide.close()
    }
}
