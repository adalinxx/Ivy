import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import Testing
@testable import Ivy
import Tally

/// Closes a connection as soon as the dialer sends its first handshake record.
private final class CloseOnFirstRead: ChannelInboundHandler, Sendable {
    typealias InboundIn = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.close(promise: nil)
    }
}

@Suite("Outbound netgroup cap")
struct OutboundNetgroupCapTests {
    /// A proxy-fronted node raises its inbound per-netgroup cap because every
    /// inbound peer arrives from the proxy's one address. Identities are free,
    /// so one attacker host can offer many of them; that raised inbound cap
    /// must not let the attacker's single netgroup take every outbound slot.
    @Test("one netgroup cannot occupy more than the outbound per-netgroup cap")
    func singleNetgroupCannotFillOutbound() async throws {
        var attackerNodes: [Ivy] = []
        var attackerEndpoints: [PeerEndpoint] = []
        for index in 0..<6 {
            let identity = TransportTestHarness.identity("outbound-cap-attacker-\(index)")
            let port = TransportTestHarness.nextPort()
            let node = Ivy(config: TransportTestHarness.config(identity, port: port))
            try await node.start()
            attackerNodes.append(node)
            attackerEndpoints.append(TransportTestHarness.endpoint(identity, port: port))
        }

        func connectedCount(maxOutboundConnectionsPerNetgroup: Int) async throws -> Int {
            let port = TransportTestHarness.nextPort()
            let victim = Ivy(config: IvyConfig(
                signingKey: TransportTestHarness.identity(
                    "outbound-cap-victim-\(maxOutboundConnectionsPerNetgroup)"),
                listenPort: port,
                stunServers: [],
                healthConfig: PeerHealthConfig(enabled: false),
                maxInboundConnectionsPerNetgroup: IvyConfig.defaultMaxConnections,
                maxOutboundConnectionsPerNetgroup: maxOutboundConnectionsPerNetgroup,
                externalAddress: ("127.0.0.1", port)))
            try await victim.start()
            for endpoint in attackerEndpoints {
                try? await victim.connect(to: endpoint)
            }
            let connected = await victim.connectedPeers.count
            await victim.stop()
            return connected
        }

        let capped = try await connectedCount(
            maxOutboundConnectionsPerNetgroup: IvyConfig.defaultMaxOutboundConnectionsPerNetgroup)
        #expect(IvyConfig.defaultMaxOutboundConnectionsPerNetgroup < attackerEndpoints.count)
        #expect(capped == IvyConfig.defaultMaxOutboundConnectionsPerNetgroup,
                "outbound sessions to one netgroup: \(capped)")

        // Control: every attacker is reachable, so the refusals above are the cap.
        let uncapped = try await connectedCount(
            maxOutboundConnectionsPerNetgroup: attackerEndpoints.count)
        #expect(uncapped == attackerEndpoints.count)

        for node in attackerNodes { await node.stop() }
    }

    @Test("distinct netgroups still fill outbound capacity past a saturated one")
    func distinctNetgroupsFillOutbound() async {
        let node = Ivy(config: IvyConfig(
            publicKey: "outbound-cap-diverse-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 8,
            maxInboundConnectionsPerNetgroup: IvyConfig.defaultMaxConnections))
        func endpoint(_ label: String, _ host: String) -> PeerEndpoint {
            PeerEndpoint(publicKey: deterministicTestPeerKey(label), host: host, port: 4001)
        }

        var reserved: [PeerEndpoint] = []
        for index in 0..<IvyConfig.defaultMaxOutboundConnectionsPerNetgroup {
            let attacker = endpoint("outbound-cap-diverse-attacker-\(index)", "10.1.0.\(index + 1)")
            #expect(await node.reserveOutgoingDial(to: attacker))
            reserved.append(attacker)
        }
        #expect(!(await node.reserveOutgoingDial(
            to: endpoint("outbound-cap-diverse-attacker-extra", "10.1.9.9"))))

        let remaining = 8 - IvyConfig.defaultMaxOutboundConnectionsPerNetgroup
        for index in 0..<remaining {
            let honest = endpoint("outbound-cap-diverse-honest-\(index)", "10.\(index + 2).0.1")
            #expect(await node.reserveOutgoingDial(to: honest))
            reserved.append(honest)
        }
        #expect(await node.outgoingDialCountForTesting == 8)

        let generation = await node.runGeneration
        for endpoint in reserved {
            await node.finishOutgoingDial(
                to: PeerID(publicKey: endpoint.publicKey),
                generation: generation)
        }
        await node.stop()
    }

    @Test("configured dials are exempt from the outbound cap but still count against it")
    func configuredPeersExemptButCounted() async throws {
        // Three operator-chosen peers in one /16, as fly.dev backbones are.
        let configured = (0..<3).map { index in
            PeerEndpoint(
                publicKey: deterministicTestPeerKey("outbound-cap-configured-\(index)"),
                host: "137.66.\(index).1",
                port: 4001)
        }
        let node = Ivy(config: IvyConfig(
            publicKey: "outbound-cap-configured-node",
            listenPort: 0,
            bootstrapPeers: configured,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxInboundConnectionsPerNetgroup: IvyConfig.defaultMaxConnections))
        for endpoint in configured {
            #expect(await node.reserveOutgoingDial(to: endpoint, configured: true))
        }
        let discovered = PeerEndpoint(
            publicKey: deterministicTestPeerKey("outbound-cap-configured-discovered"),
            host: "137.66.200.1",
            port: 4001)
        #expect(!(await node.reserveOutgoingDial(to: discovered)))

        let generation = await node.runGeneration
        for endpoint in configured {
            await node.finishOutgoingDial(
                to: PeerID(publicKey: endpoint.publicKey),
                generation: generation)
        }

        // Promotion applies the same rule once sessions exist.
        var channels: [EmbeddedChannel] = []
        for (index, endpoint) in configured.prefix(2).enumerated() {
            let channel = EmbeddedChannel()
            try await channel.connect(to: SocketAddress(ipAddress: endpoint.host, port: 4001)).get()
            let connection = PeerConnection(endpoint: endpoint, channel: channel)
            connection.observedHost = endpoint.host
            try await node.seedConnectedEndpointForTesting(
                endpoint,
                connection: connection,
                marker: UInt8(index + 1))
            channels.append(channel)
        }
        func candidate(_ endpoint: PeerEndpoint) async throws -> PeerConnection {
            let channel = EmbeddedChannel()
            try await channel.connect(to: SocketAddress(ipAddress: endpoint.host, port: 4001)).get()
            channels.append(channel)
            let connection = PeerConnection(endpoint: endpoint, channel: channel)
            connection.observedHost = endpoint.host
            return connection
        }
        let configuredConnection = try await candidate(configured[2])
        let discoveredConnection = try await candidate(discovered)
        #expect(await node.canPromoteForTesting(
            configuredConnection,
            peerKey: try PeerKey(configured[2].publicKey)))
        #expect(!(await node.canPromoteForTesting(
            discoveredConnection,
            peerKey: try PeerKey(discovered.publicKey))))
        // An inbound peer from the same netgroup is judged by the inbound cap.
        #expect(await node.canPromoteForTesting(
            discoveredConnection,
            peerKey: try PeerKey(discovered.publicKey),
            isInbound: true))

        for endpoint in configured.prefix(2) {
            await node.disconnect(PeerID(publicKey: endpoint.publicKey))
        }
        configuredConnection.cancel()
        discoveredConnection.cancel()
        for channel in channels { _ = try? channel.finish() }
        await node.stop()
    }

    /// The key is unauthenticated when a dial is reserved, so a referral naming
    /// a configured key at an attacker's address must not skip the cap.
    @Test("a configured key offered at another address is capped like any dial")
    func configuredKeyAtOtherAddressIsCapped() async {
        let configured = PeerEndpoint(
            publicKey: deterministicTestPeerKey("outbound-referral-configured"),
            host: "137.66.0.1",
            port: 4001)
        let node = Ivy(config: IvyConfig(
            publicKey: "outbound-referral-node",
            listenPort: 0,
            bootstrapPeers: [configured],
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxInboundConnectionsPerNetgroup: IvyConfig.defaultMaxConnections))
        var reserved: [PeerEndpoint] = []
        for index in 0..<IvyConfig.defaultMaxOutboundConnectionsPerNetgroup {
            let discovered = PeerEndpoint(
                publicKey: deterministicTestPeerKey("outbound-referral-discovered-\(index)"),
                host: "137.66.\(index + 1).1",
                port: 4001)
            #expect(await node.reserveOutgoingDial(to: discovered))
            reserved.append(discovered)
        }

        let referral = PeerEndpoint(
            publicKey: configured.publicKey,
            host: "137.66.9.9",
            port: 4001)
        #expect(!(await node.reserveOutgoingDial(to: referral)))
        #expect(await node.reserveOutgoingDial(to: configured, configured: true))
        reserved.append(configured)

        let generation = await node.runGeneration
        for endpoint in reserved {
            await node.finishOutgoingDial(
                to: PeerID(publicKey: endpoint.publicKey),
                generation: generation)
        }
        await node.stop()
    }

    /// Our dial to X is in flight when X's own connection to us completes first,
    /// so the surviving session is a responder. It answers our dial and must
    /// keep holding the outbound slot it was reserved under.
    @Test("a dialed peer that completes inbound still holds its outbound slot")
    func dialedPeerCompletingInboundStaysOutbound() async throws {
        let nodeIdentity = TransportTestHarness.identity("outbound-flip-node")
        let xIdentity = TransportTestHarness.identity("outbound-flip-x")
        let yIdentity = TransportTestHarness.identity("outbound-flip-y")
        let nodePort = TransportTestHarness.nextPort()
        let xPort = TransportTestHarness.nextPort()
        let yPort = TransportTestHarness.nextPort()
        let node = Ivy(config: IvyConfig(
            signingKey: nodeIdentity,
            listenPort: nodePort,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxInboundConnectionsPerNetgroup: IvyConfig.defaultMaxConnections,
            maxOutboundConnectionsPerNetgroup: 1,
            externalAddress: ("127.0.0.1", nodePort)))
        let x = Ivy(config: TransportTestHarness.config(xIdentity, port: xPort))
        let y = Ivy(config: TransportTestHarness.config(yIdentity, port: yPort))
        try await x.start()
        try await y.start()
        try await node.start()
        let generation = await node.runGeneration
        let xID = TransportTestHarness.key(xIdentity).peerID
        let yID = TransportTestHarness.key(yIdentity).peerID

        #expect(await node.reserveOutgoingDial(
            to: TransportTestHarness.endpoint(xIdentity, port: xPort)))
        try await x.connect(to: TransportTestHarness.endpoint(nodeIdentity, port: nodePort))
        #expect(try await TransportTestHarness.eventually {
            await node.hasEndpointSession(xID)
        })
        await node.finishOutgoingDial(to: xID, generation: generation)

        // X holds the only outbound slot for 127.0/16, so Y there is refused.
        try? await node.connect(to: TransportTestHarness.endpoint(yIdentity, port: yPort))
        #expect(await node.hasEndpointSession(xID))
        #expect(!(await node.hasEndpointSession(yID)))
        #expect(await node.connectedPeers == [xID])

        await node.stop()
        await x.stop()
        await y.stop()
    }

    @Test("an inbound session replacing an outbound one keeps the outbound slot")
    func inboundReplacementKeepsOutboundSlot() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "outbound-replace-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 8,
            maxInboundConnectionsPerNetgroup: IvyConfig.defaultMaxConnections,
            maxOutboundConnectionsPerNetgroup: 1))
        let x = PeerEndpoint(
            publicKey: deterministicTestPeerKey("outbound-replace-x"),
            host: "10.1.0.1",
            port: 4001)
        var channels: [EmbeddedChannel] = []
        func direct(_ host: String, port: Int) async throws -> PeerConnection {
            let channel = EmbeddedChannel()
            try await channel.connect(to: SocketAddress(ipAddress: host, port: port)).get()
            channels.append(channel)
            let connection = PeerConnection(endpoint: x, channel: channel)
            connection.observedHost = host
            return connection
        }

        try await node.seedConnectedEndpointForTesting(
            x,
            connection: try await direct("10.1.0.1", port: 4001),
            marker: 0x90)
        let pendingID = try await node.seedResponderAwaitingFinishForTesting(
            x,
            connection: try await direct("10.1.0.2", port: 4002),
            marker: 0x10)
        await node.promotePendingResponderForTesting(pendingID)

        // The lower session ID wins, so the inbound session replaced the outbound one.
        #expect(await node.selectedSessionIDForTesting(PeerID(publicKey: x.publicKey))
                == Data(repeating: 0x10, count: 32))
        #expect(!(await node.reserveOutgoingDial(to: PeerEndpoint(
            publicKey: deterministicTestPeerKey("outbound-replace-y"),
            host: "10.1.9.9",
            port: 4001))))

        await node.disconnect(PeerID(publicKey: x.publicKey))
        for channel in channels { _ = try? channel.finish() }
        await node.stop()
    }

    /// Dials A, then a same-netgroup dial that fails, then B. With an outbound
    /// cap of 2, B connects only if the failed dial released its slot.
    private func assertFailedDialReleasesSlot(
        label: String,
        failingEndpoint: PeerEndpoint
    ) async throws {
        let nodePort = TransportTestHarness.nextPort()
        let node = Ivy(config: IvyConfig(
            signingKey: TransportTestHarness.identity("\(label)-node"),
            listenPort: nodePort,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxInboundConnectionsPerNetgroup: IvyConfig.defaultMaxConnections,
            maxOutboundConnectionsPerNetgroup: 2,
            externalAddress: ("127.0.0.1", nodePort)))
        let aIdentity = TransportTestHarness.identity("\(label)-a")
        let bIdentity = TransportTestHarness.identity("\(label)-b")
        let aPort = TransportTestHarness.nextPort()
        let bPort = TransportTestHarness.nextPort()
        let a = Ivy(config: TransportTestHarness.config(aIdentity, port: aPort))
        let b = Ivy(config: TransportTestHarness.config(bIdentity, port: bPort))
        try await a.start()
        try await b.start()
        try await node.start()

        try await node.connect(to: TransportTestHarness.endpoint(aIdentity, port: aPort))
        do {
            try await node.connect(to: failingEndpoint)
            Issue.record("the failing dial unexpectedly connected")
        } catch {}
        #expect(try await TransportTestHarness.eventually(attempts: 250) {
            let dials = await node.outgoingDialCountForTesting
            let pending = await node.pendingSessionCountForTesting
            return dials == 0 && pending == 0
        })

        try await node.connect(to: TransportTestHarness.endpoint(bIdentity, port: bPort))
        #expect(Set(await node.connectedPeers) == Set([
            TransportTestHarness.key(aIdentity).peerID,
            TransportTestHarness.key(bIdentity).peerID,
        ]))

        await node.stop()
        await a.stop()
        await b.stop()
    }

    @Test("a same-netgroup dial answered by the wrong identity releases its outbound slot")
    func wrongIdentityDialReleasesSlot() async throws {
        let impostorPort = TransportTestHarness.nextPort()
        let impostor = Ivy(config: TransportTestHarness.config(
            TransportTestHarness.identity("outbound-release-wrong-key-impostor"),
            port: impostorPort))
        try await impostor.start()
        try await assertFailedDialReleasesSlot(
            label: "outbound-release-wrong-key",
            failingEndpoint: PeerEndpoint(
                publicKey: TransportTestHarness.key(
                    TransportTestHarness.identity("outbound-release-wrong-key-expected")).hex,
                host: "127.0.0.1",
                port: impostorPort))
        await impostor.stop()
    }

    @Test("a same-netgroup dial closed mid-handshake releases its outbound slot")
    func closedMidHandshakeDialReleasesSlot() async throws {
        let listener = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(CloseOnFirstRead())
            }
            .bind(host: "127.0.0.1", port: 0).get()
        let port = try #require(listener.localAddress?.port.flatMap { UInt16(exactly: $0) })
        try await assertFailedDialReleasesSlot(
            label: "outbound-release-closed",
            failingEndpoint: PeerEndpoint(
                publicKey: TransportTestHarness.key(
                    TransportTestHarness.identity("outbound-release-closed-target")).hex,
                host: "127.0.0.1",
                port: port))
        try? await listener.close().get()
    }

    @Test("configured peers in one netgroup all connect while a discovered peer there is refused")
    func configuredPeersConnectOverTCP() async throws {
        var configuredNodes: [Ivy] = []
        var configuredEndpoints: [PeerEndpoint] = []
        for index in 0..<3 {
            let identity = TransportTestHarness.identity("outbound-configured-tcp-\(index)")
            let port = TransportTestHarness.nextPort()
            let peer = Ivy(config: TransportTestHarness.config(identity, port: port))
            try await peer.start()
            configuredNodes.append(peer)
            configuredEndpoints.append(TransportTestHarness.endpoint(identity, port: port))
        }
        let discoveredIdentity = TransportTestHarness.identity("outbound-configured-tcp-discovered")
        let discoveredPort = TransportTestHarness.nextPort()
        let discovered = Ivy(config: TransportTestHarness.config(
            discoveredIdentity,
            port: discoveredPort))
        try await discovered.start()

        let nodePort = TransportTestHarness.nextPort()
        let node = Ivy(config: IvyConfig(
            signingKey: TransportTestHarness.identity("outbound-configured-tcp-node"),
            listenPort: nodePort,
            bootstrapPeers: configuredEndpoints,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxInboundConnectionsPerNetgroup: IvyConfig.defaultMaxConnections,
            externalAddress: ("127.0.0.1", nodePort)))
        #expect(IvyConfig.defaultMaxOutboundConnectionsPerNetgroup < configuredEndpoints.count)
        try await node.start()

        let configuredIDs = Set(configuredEndpoints.map { PeerID(publicKey: $0.publicKey) })
        #expect(try await TransportTestHarness.eventually(attempts: 250) {
            Set(await node.connectedPeers) == configuredIDs
        })
        try? await node.connect(to: TransportTestHarness.endpoint(
            discoveredIdentity,
            port: discoveredPort))
        #expect(Set(await node.connectedPeers) == configuredIDs)

        await node.stop()
        await discovered.stop()
        for peer in configuredNodes { await peer.stop() }
    }
}
