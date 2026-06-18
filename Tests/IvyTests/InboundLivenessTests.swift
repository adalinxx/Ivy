import Testing
import Foundation
import Crypto
import NIOCore
import NIOEmbedded
@testable import Ivy
@testable import Tally

extension Ivy {
    func connectionEndpointForTesting(_ peer: PeerID) -> PeerEndpoint? {
        connections[peer]?.endpoint
    }
}

private func inboundLivenessConfig(publicKey: String) -> IvyConfig {
    IvyConfig(
        publicKey: publicKey,
        listenPort: 0,
        bootstrapPeers: [],
        enableLocalDiscovery: false,
        healthConfig: PeerHealthConfig(
            keepaliveInterval: .seconds(999),
            staleTimeout: .seconds(999),
            maxMissedPongs: 99,
            enabled: true
        ),
        enablePEX: false
    )
}

@Suite("Inbound liveness monitoring")
struct InboundLivenessTests {

    @Test("Inbound peers can be tracked by the health monitor")
    func inboundPeerIsTracked() async {
        let node = Ivy(config: inboundLivenessConfig(publicKey: "inbound-health-node"))
        await node.installHealthMonitorForTesting()

        let inbound = PeerID(publicKey: "inbound-temp")
        await node.trackHealthPeerForTesting(inbound)

        #expect(await node.healthMonitorTracksPeerForTesting(inbound))
        #expect(await node.trackedHealthPeerCountForTesting() == 1)
    }

    @Test("Identify re-key moves health tracking from temporary inbound ID to real peer")
    func identifyRekeyMovesHealthTracking() async {
        let node = Ivy(config: inboundLivenessConfig(publicKey: "inbound-rekey-node"))
        await node.installHealthMonitorForTesting()

        let temporary = PeerID(publicKey: "inbound-temp")
        let real = PeerID(publicKey: "real-peer")
        await node.trackHealthPeerForTesting(temporary)
        await node.moveHealthPeerForTesting(from: temporary, to: real)

        #expect(!(await node.healthMonitorTracksPeerForTesting(temporary)))
        #expect(await node.healthMonitorTracksPeerForTesting(real))
        #expect(await node.trackedHealthPeerCountForTesting() == 1)
    }

    // MARK: - Real ingress paths
    //
    // The two tests above poke trackPeer/movePeer directly. The two below drive
    // the ACTUAL code paths: the inbound-accept ingress and a real signed
    // identify re-key over the live connection's message stream.

    private func generateKeyPair() -> (publicKey: String, privateKey: Data) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let pubHex = privateKey.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        return (pubHex, privateKey.rawRepresentation)
    }

    private func signIdentify(publicKey: String, observedHost: String, privateKey: Data) -> Data {
        let material = Data(publicKey.utf8) + Data(observedHost.utf8)
        let key = try! Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        return try! key.signature(for: material)
    }

    private func makeInboundConnection(
        id: PeerID,
        channel: NIOAsyncTestingChannel
    ) -> PeerConnection {
        PeerConnection(
            id: id,
            endpoint: PeerEndpoint(publicKey: id.publicKey, host: "127.0.0.1", port: 0),
            channel: channel,
            maxFrameSize: IvyConfig.defaultMaxFrameSize
        )
    }

    @Test("Inbound accept ingress health-tracks the new peer")
    func inboundAcceptIngressTracksPeer() async throws {
        let node = Ivy(config: inboundLivenessConfig(publicKey: "inbound-accept-node"))
        await node.installHealthMonitorForTesting()

        // Drive the actor registration path used by the inbound acceptor after
        // it installs the message handler on the accepted socket.
        let inbound = PeerID(publicKey: "inbound-test-accept")
        let channel = NIOAsyncTestingChannel()
        let conn = makeInboundConnection(id: inbound, channel: channel)
        await node.registerInboundConnection(conn)

        // The registration path records the temporary inbound connection and
        // schedules health tracking on it asynchronously.
        try await Task.sleep(for: .milliseconds(50))

        #expect(await node.connectionPeersForTesting().contains(inbound))
        #expect(await node.healthMonitorTracksPeerForTesting(inbound))
        #expect(await node.trackedHealthPeerCountForTesting() == 1)

        _ = try? await channel.finish()
    }

    @Test("Inbound identify without a listen address does not route the peer")
    func inboundIdentifyWithoutListenAddrDoesNotRoutePeer() async throws {
        let node = Ivy(config: inboundLivenessConfig(publicKey: "inbound-no-listen-node"))

        let inbound = PeerID(publicKey: "inbound-no-listen")
        let channel = NIOAsyncTestingChannel()
        let conn = PeerConnection(
            id: inbound,
            endpoint: PeerEndpoint(publicKey: inbound.publicKey, host: "127.0.0.1", port: 49152),
            channel: channel,
            maxFrameSize: IvyConfig.defaultMaxFrameSize
        )
        await node.registerInboundConnection(conn)

        let (realKey, realPriv) = generateKeyPair()
        let observedHost = "203.0.113.210"
        let signature = signIdentify(publicKey: realKey, observedHost: observedHost, privateKey: realPriv)
        await node.handleMessage(
            .identify(
                publicKey: realKey,
                observedHost: observedHost,
                observedPort: 4001,
                listenAddrs: [],
                chainPorts: [:],
                signature: signature
            ),
            from: inbound
        )

        let routed = await node.allRouterPeers()
        #expect(!routed.contains { $0.id.publicKey == realKey })
        #expect(!routed.contains { $0.id.publicKey == inbound.publicKey })

        _ = try? await channel.finish()
    }

    @Test("Inbound identify routes by advertised listen address, not source port")
    func inboundIdentifyRoutesAdvertisedListenAddress() async throws {
        let node = Ivy(config: inboundLivenessConfig(publicKey: "inbound-advertised-node"))

        let inbound = PeerID(publicKey: "inbound-advertised")
        let sourceEndpoint = PeerEndpoint(publicKey: inbound.publicKey, host: "127.0.0.1", port: 49153)
        let channel = NIOAsyncTestingChannel()
        let conn = PeerConnection(
            id: inbound,
            endpoint: sourceEndpoint,
            channel: channel,
            maxFrameSize: IvyConfig.defaultMaxFrameSize
        )
        await node.registerInboundConnection(conn)

        let (realKey, realPriv) = generateKeyPair()
        let observedHost = "203.0.113.211"
        let advertised = ("198.51.100.44", UInt16(4100))
        let signature = signIdentify(publicKey: realKey, observedHost: observedHost, privateKey: realPriv)
        await node.handleMessage(
            .identify(
                publicKey: realKey,
                observedHost: observedHost,
                observedPort: 4001,
                listenAddrs: [advertised],
                chainPorts: [:],
                signature: signature
            ),
            from: inbound
        )

        let entries = await node.allRouterPeers().filter { $0.id.publicKey == realKey }
        #expect(entries.count == 1)
        #expect(entries.first?.endpoint.host == advertised.0)
        #expect(entries.first?.endpoint.port == advertised.1)
        #expect(entries.first?.endpoint.port != sourceEndpoint.port)

        _ = try? await channel.finish()
    }

    @Test("Default inbound cap is enforced when Tally maxPeers is nil")
    func defaultInboundCapIsEnforcedWhenMaxPeersNil() async throws {
        let node = Ivy(config: inboundLivenessConfig(publicKey: "inbound-default-cap-node"))
        var channels: [NIOAsyncTestingChannel] = []

        for i in 0...IvyConfig.defaultMaxInboundConnections {
            let peer = PeerID(publicKey: "inbound-cap-\(i)")
            let channel = NIOAsyncTestingChannel()
            channels.append(channel)
            let conn = makeInboundConnection(id: peer, channel: channel)
            await node.registerInboundConnection(conn)
        }

        let peers = await node.connectionPeersForTesting()
        #expect(peers.count <= IvyConfig.defaultMaxInboundConnections)
        #expect(!peers.contains(PeerID(publicKey: "inbound-cap-0")))

        for channel in channels {
            _ = try? await channel.finish()
        }
    }

    @Test("Identify remap keeps an existing live real-ID connection")
    func identifyRemapKeepsExistingLiveConnection() async throws {
        let node = Ivy(config: inboundLivenessConfig(publicKey: "inbound-duplicate-node"))

        let (realKey, realPriv) = generateKeyPair()
        let realID = PeerID(publicKey: realKey)
        let existingEndpoint = PeerEndpoint(publicKey: realKey, host: "198.51.100.10", port: 7000)
        let existingChannel = NIOAsyncTestingChannel()
        let existingConn = PeerConnection(
            id: realID,
            endpoint: existingEndpoint,
            channel: existingChannel,
            maxFrameSize: IvyConfig.defaultMaxFrameSize
        )
        await node.registerConnectionForTesting(existingConn, as: realID)

        let inbound = PeerID(publicKey: "inbound-duplicate")
        let freshEndpoint = PeerEndpoint(publicKey: inbound.publicKey, host: "127.0.0.1", port: 49154)
        let freshChannel = NIOAsyncTestingChannel()
        let freshConn = PeerConnection(
            id: inbound,
            endpoint: freshEndpoint,
            channel: freshChannel,
            maxFrameSize: IvyConfig.defaultMaxFrameSize
        )
        await node.registerInboundConnection(freshConn)

        let observedHost = "203.0.113.212"
        let signature = signIdentify(publicKey: realKey, observedHost: observedHost, privateKey: realPriv)
        await node.handleMessage(
            .identify(
                publicKey: realKey,
                observedHost: observedHost,
                observedPort: 4001,
                listenAddrs: [("203.0.113.77", 9000)],
                chainPorts: [:],
                signature: signature
            ),
            from: inbound
        )

        let peers = await node.connectionPeersForTesting()
        #expect(peers.contains(realID))
        #expect(!peers.contains(inbound))
        #expect(await node.connectionEndpointForTesting(realID) == existingEndpoint)

        _ = try? await existingChannel.finish()
        _ = try? await freshChannel.finish()
    }

    @Test("Real identify re-key over the live connection moves health tracking")
    func realIdentifyRekeyMovesTracking() async throws {
        let node = Ivy(config: inboundLivenessConfig(publicKey: "inbound-real-rekey-node"))
        await node.installHealthMonitorForTesting()

        // Register an inbound peer through the same actor path used by the real
        // accept ingress after the pipeline-level handler has been installed.
        let inbound = PeerID(publicKey: "inbound-test-rekey")
        let channel = NIOAsyncTestingChannel()
        let conn = makeInboundConnection(id: inbound, channel: channel)
        await node.registerInboundConnection(conn)
        try await Task.sleep(for: .milliseconds(50))

        guard await node.connectionPeersForTesting().contains(inbound) else {
            Issue.record("inbound peer was not registered")
            return
        }
        #expect(await node.healthMonitorTracksPeerForTesting(inbound))

        // Deliver a real, signature-valid identify over the connection's message
        // pipeline (handleMessage is what handleInbound calls per inbound frame).
        // This drives handleIdentify → the re-key branch → movePeerHealthTracking.
        let (realKey, realPriv) = generateKeyPair()
        let observedHost = "203.0.113.200"
        let signature = signIdentify(publicKey: realKey, observedHost: observedHost, privateKey: realPriv)
        await node.handleMessage(
            .identify(
                publicKey: realKey,
                observedHost: observedHost,
                observedPort: 4001,
                listenAddrs: [],
                chainPorts: [:],
                signature: signature
            ),
            from: inbound
        )

        let realPeer = PeerID(publicKey: realKey)
        #expect(!(await node.healthMonitorTracksPeerForTesting(inbound)),
                "tracking must move off the temporary inbound ID")
        #expect(await node.healthMonitorTracksPeerForTesting(realPeer),
                "the real peer must become health-tracked")
        #expect(await node.trackedHealthPeerCountForTesting() == 1)

        _ = try? await channel.finish()
    }
}
