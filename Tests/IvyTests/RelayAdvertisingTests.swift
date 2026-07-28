import Crypto
import Foundation
import Tally
import Testing
@testable import Ivy

@Suite("Relay advertising")
struct RelayAdvertisingTests {
    @Test("a relay endpoint keeps its carrier through provider records")
    func relayEndpointRoundtrips() throws {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("nat-peer"),
            host: "1.1.1.1",
            port: 4001,
            transport: .relay,
            carrierKey: deterministicTestPeerKey("carrier"))
        let record = ProviderRecord(endpoint: endpoint, expiresAt: 99)
        let wire = Message.providers(rootCID: "r", requestID: 1, records: [record]).serialize()
        let decoded = try #require(Message.deserialize(wire))
        guard case .providers(_, _, let records) = decoded else {
            Issue.record("expected providers")
            return
        }
        #expect(records.map(\.endpoint) == [endpoint])
        #expect(records.first?.endpoint.carrierKey == endpoint.carrierKey)
    }

    @Test("a carrier is dropped from any endpoint that is not a relay hint")
    func carrierOnlyAppliesToRelayEndpoints() {
        let direct = PeerEndpoint(
            publicKey: deterministicTestPeerKey("peer"),
            host: "1.1.1.1",
            port: 4001,
            carrierKey: deterministicTestPeerKey("carrier"))
        #expect(direct.carrierKey == nil)
    }

    @Test("a relay hint is not a listen address")
    func relayHintIsRejectedInMetadata() throws {
        let encoded = try #require(PeerMetadata(listenAddresses: [
            ListenAddress(host: "1.1.1.1", port: 4001),
        ]).encode())
        var corrupted = encoded
        corrupted[corrupted.index(before: corrupted.endIndex)] = TransportKind.relay.rawValue
        #expect(throws: SessionProtocolError.malformed) {
            try PeerMetadata.decodeCanonical(corrupted)
        }
    }

    @Test("relay hints are accepted only from provider records, and must name a third party")
    func relayHintValidation() async throws {
        let ivy = Ivy(config: IvyConfig(publicKey: deterministicTestPeerKey("seeker")))
        let localKey = await ivy.localID.publicKey
        let targetKey = deterministicTestPeerKey("nat-peer")
        let source = PeerID(publicKey: deterministicTestPeerKey("responder"))
        func hint(carrier: String) -> PeerEndpoint {
            PeerEndpoint(
                publicKey: targetKey,
                host: "1.1.1.1",
                port: 4001,
                transport: .relay,
                carrierKey: carrier)
        }

        let valid = hint(carrier: deterministicTestPeerKey("carrier"))
        #expect(await ivy.isAcceptableDiscoveredEndpoint(
            valid, provenance: .referral("provider"), from: source))
        // Kademlia routing stays direct-only, so neighbour referrals may not carry one.
        #expect(await !ivy.isAcceptableDiscoveredEndpoint(
            valid, provenance: .referral("neighbors"), from: source))
        #expect(await !ivy.isAcceptableDiscoveredEndpoint(
            valid, provenance: .selfAdvertisement, from: source))
        // A peer cannot name itself, or us, as its own carrier.
        #expect(await !ivy.isAcceptableDiscoveredEndpoint(
            hint(carrier: targetKey), provenance: .referral("provider"), from: source))
        #expect(await !ivy.isAcceptableDiscoveredEndpoint(
            hint(carrier: localKey),
            provenance: .referral("provider"),
            from: source))
    }

    @Test("relayed inbound sessions are capped overall and per carrier")
    func relayedInboundIsCapped() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: deterministicTestPeerKey("carrier-host"),
            maxRelayedInboundConnections: 2,
            maxRelayedInboundPerCarrier: 1))
        let carrierA = try PeerKey(deterministicTestPeerKey("carrier-a"))
        let carrierB = try PeerKey(deterministicTestPeerKey("carrier-b"))
        let carrierC = try PeerKey(deterministicTestPeerKey("carrier-c"))

        #expect(await ivy.relayedInboundHasCapacity(carrier: carrierA))
        await ivy.seedRelayedInboundForTesting(carrier: carrierA)
        // The per-carrier cap of one is now spent, but other carriers still fit.
        #expect(await !ivy.relayedInboundHasCapacity(carrier: carrierA))
        #expect(await ivy.relayedInboundHasCapacity(carrier: carrierB))

        await ivy.seedRelayedInboundForTesting(carrier: carrierB)
        // Two relayed sessions exhaust the overall cap regardless of carrier.
        #expect(await !ivy.relayedInboundHasCapacity(carrier: carrierC))
    }

    @Test("a stranger reaches a relayed provider through the carrier it advertised")
    func strangerReachesProviderThroughAdvertisedCarrier() async throws {
        let carrierIdentity = TransportTestHarness.identity("advert-carrier")
        let providerIdentity = TransportTestHarness.identity("advert-provider")
        let strangerIdentity = TransportTestHarness.identity("advert-stranger")
        let carrierPort = TransportTestHarness.nextPort()
        let providerPort = TransportTestHarness.nextPort()
        let strangerPort = TransportTestHarness.nextPort()
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: carrierPort)
        let carrierKey = TransportTestHarness.key(carrierIdentity)
        let providerKey = TransportTestHarness.key(providerIdentity)

        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity, port: carrierPort, relayEnabled: true))
        // The provider knows the carrier; the stranger does not.
        let provider = Ivy(config: TransportTestHarness.config(
            providerIdentity, port: providerPort, carriers: [carrierEndpoint]))
        let stranger = Ivy(config: TransportTestHarness.config(
            strangerIdentity, port: strangerPort, requestTimeout: .seconds(5)))

        try await carrier.start()
        try await provider.start()
        try await stranger.start()
        defer {
            Task {
                await stranger.stop()
                await provider.stop()
                await carrier.stop()
            }
        }

        #expect(try await TransportTestHarness.eventually {
            await provider.liveCarrierKeys.contains(carrierKey)
        })

        // A provider record names a globally routable carrier, since a referral
        // to a loopback address is never acceptable. The dial is redirected to
        // the carrier actually running on loopback.
        await stranger.setDialEndpointRewriteForTesting { endpoint in
            guard endpoint.host == "1.1.1.1" else { return endpoint }
            return PeerEndpoint(
                publicKey: endpoint.publicKey,
                host: "127.0.0.1",
                port: carrierPort,
                transport: endpoint.transport)
        }
        let hint = PeerEndpoint(
            publicKey: providerKey.hex,
            host: "1.1.1.1",
            port: carrierPort,
            transport: .relay,
            carrierKey: carrierKey.hex)

        try await stranger.connect(to: hint)
        #expect(await stranger.connectedPeers.contains { $0 == providerKey.peerID })
        // The stranger reached it without the carrier ever being configured.
        #expect(await stranger.config.carriers.isEmpty)
    }
}
