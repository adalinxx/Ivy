import Foundation
import NIOCore
import NIOEmbedded
import Testing
@testable import Ivy

@Suite("Configured carrier relay", .serialized)
struct RelayIntegrationTests {
    @Test("unconfigured overlay peers cannot inject unrelated relay state")
    func unrelatedRelayControlIsRejected() async throws {
        let senderIdentity = TransportTestHarness.identity("relay-unrelated-sender")
        let targetIdentity = TransportTestHarness.identity("relay-unrelated-target")
        let sender = Ivy(config: TransportTestHarness.config(
            senderIdentity,
            port: TransportTestHarness.nextPort()))
        let targetPort = TransportTestHarness.nextPort()
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort))
        let targetRecorder = TransportTestRecorder()
        await target.setTestDelegate(targetRecorder)

        try await sender.start()
        try await target.start()
        try await sender.connect(to: TransportTestHarness.endpoint(targetIdentity, port: targetPort))
        let senderID = TransportTestHarness.key(senderIdentity).peerID
        try await targetRecorder.waitForConnect(senderID)

        #expect(await sender.sendAuthenticatedMessageForTesting(
            .relayReady(routeID: Data(repeating: 1, count: 32), status: 0),
            to: TransportTestHarness.key(targetIdentity).peerID))
        try await targetRecorder.waitForDisconnect(senderID)
        #expect(await target.peerConnectionCount == 0)

        await sender.stop()
        await target.stop()
    }

    @Test("inbound offers from one authenticated carrier remain bounded")
    func inboundOfferCap() async throws {
        let targetIdentity = TransportTestHarness.identity("relay-offer-cap-target")
        let carrierIdentity = TransportTestHarness.identity("relay-offer-cap-carrier")
        let sourceIdentity = TransportTestHarness.identity("relay-offer-cap-source")
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: TransportTestHarness.nextPort()))
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: 4001)
        let carrierKey = TransportTestHarness.key(carrierIdentity)
        let channel = EmbeddedChannel()
        try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 4001)).get()
        let connection = PeerConnection(endpoint: carrierEndpoint, channel: channel)
        try await target.seedConnectedEndpointForTesting(
            carrierEndpoint,
            connection: connection,
            marker: 1)

        for marker in 1...(Ivy.maxRelayRoutesPerPeer + 1) {
            await target.handleRelayControlForTesting(
                .relayOffer(
                    routeID: Data(repeating: UInt8(marker), count: 32),
                    sourceKey: TransportTestHarness.key(sourceIdentity)),
                from: carrierKey)
        }

        #expect(await target.installedRouteCountForTesting == Ivy.maxRelayRoutesPerPeer)
        await target.disconnect(carrierKey.peerID)
        _ = try? channel.finish()
    }

    @Test("A configured carrier authenticates one route ID and forwards peer messages")
    func configuredCarrierRelay() async throws {
        let carrierIdentity = TransportTestHarness.identity("relay-carrier")
        let sourceIdentity = TransportTestHarness.identity("relay-source")
        let targetIdentity = TransportTestHarness.identity("relay-target")
        let carrierPort = TransportTestHarness.nextPort()
        let sourcePort = TransportTestHarness.nextPort()
        let targetPort = TransportTestHarness.nextPort()
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: carrierPort)
        let targetID = TransportTestHarness.key(targetIdentity).peerID
        let sourceID = TransportTestHarness.key(sourceIdentity).peerID
        let carrierKey = TransportTestHarness.key(carrierIdentity)
        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity,
            port: carrierPort,
            relayEnabled: true))
        let source = Ivy(config: TransportTestHarness.config(
            sourceIdentity,
            port: sourcePort,
            carriers: [carrierEndpoint],
            mode: .pinned(peer: targetID.publicKey)))
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort))
        let sourceRecorder = TransportTestRecorder()
        let targetRecorder = TransportTestRecorder()
        await source.setTestDelegate(sourceRecorder)
        await target.setTestDelegate(targetRecorder)

        try await carrier.start()
        try await target.start()
        try await source.start()
        try await target.connect(to: carrierEndpoint)
        #expect(try await TransportTestHarness.eventually {
            let carrierCount = await carrier.peerConnectionCount
            return carrierCount == 2 && sourceRecorder.authenticatedPeers.contains {
                $0.key == carrierKey && $0.role == .carrier
            } && targetRecorder.authenticatedPeers.contains {
                $0.key == carrierKey && $0.role == .endpoint
            }
        })
        #expect(await source.peerConnectionCount == 0)

        try await source.connectViaRelay(to: PeerEndpoint(
            publicKey: targetID.publicKey,
            host: "relay",
            port: 0))

        let payload = Data("relayed node state".utf8)
        let result = await source.sendMessage(
            to: targetID,
            topic: "node.state",
            payload: payload)
        guard case .enqueued(let endpoint, let route) = result,
              case .relayed(let authenticatedCarrier, let routeID) = route else {
            Issue.record("expected an enqueued relayed message")
            await source.stop()
            await target.stop()
            await carrier.stop()
            return
        }

        #expect(endpoint == targetID)
        #expect(authenticatedCarrier == carrierKey)
        #expect(try await TransportTestHarness.eventually {
            targetRecorder.authenticatedPeers.contains { $0.key.peerID == sourceID }
                && targetRecorder.receivedMessage(
                    topic: "node.state",
                    payload: payload,
                    from: sourceID)
        })
        guard case .relayed(let targetCarrier, let targetRouteID)? =
                targetRecorder.authenticatedPeers.first(where: { $0.key.peerID == sourceID })?.route else {
            Issue.record("target did not authenticate the relayed source")
            await source.stop()
            await target.stop()
            await carrier.stop()
            return
        }
        #expect(targetCarrier == carrierKey)
        #expect(targetRouteID == routeID)

        await target.stop()
        #expect(try await TransportTestHarness.eventually {
            await source.peerConnectionCount == 0
        })

        await source.stop()
        await carrier.stop()
    }

    @Test("relay admission failure closes the route promptly")
    func relayAdmissionFailureClosesRoute() async throws {
        let carrierIdentity = TransportTestHarness.identity("relay-full-carrier")
        let sourceIdentity = TransportTestHarness.identity("relay-full-source")
        let targetIdentity = TransportTestHarness.identity("relay-full-target")
        let carrierPort = TransportTestHarness.nextPort()
        let sourcePort = TransportTestHarness.nextPort()
        let targetPort = TransportTestHarness.nextPort()
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: carrierPort)
        let targetEndpoint = TransportTestHarness.endpoint(targetIdentity, port: targetPort)
        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity,
            port: carrierPort,
            relayEnabled: true))
        let source = Ivy(config: TransportTestHarness.config(
            sourceIdentity,
            port: sourcePort,
            carriers: [carrierEndpoint],
            mode: .pinned(peer: targetEndpoint.publicKey)))
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort,
            maxConnections: 1))

        try await carrier.start()
        try await target.start()
        try await source.start()
        try await target.connect(to: carrierEndpoint)
        #expect(try await TransportTestHarness.eventually {
            await carrier.peerConnectionCount == 2
        })

        let completedPromptly = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                do {
                    try await source.connectViaRelay(to: targetEndpoint)
                } catch {
                    return true
                }
                return false
            }
            group.addTask {
                try? await Task.sleep(for: .seconds(2))
                await source.stop()
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        #expect(completedPromptly)
        #expect(await target.peerConnectionCount == 1)

        await source.stop()
        await target.stop()
        await carrier.stop()
    }
}
