import Foundation
import NIOCore
import NIOEmbedded
import Testing
@testable import Ivy
import Tally

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

    @Test("configured peers are exempt from the outbound cap but still count against it")
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
            #expect(await node.reserveOutgoingDial(to: endpoint))
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
}
