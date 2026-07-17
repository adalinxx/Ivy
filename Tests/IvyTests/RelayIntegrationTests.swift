import Foundation
import Testing
@testable import Ivy

@Suite("Configured carrier relay", .serialized)
struct RelayIntegrationTests {
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
            sourceRecorder.authenticatedPeers.contains {
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
}
