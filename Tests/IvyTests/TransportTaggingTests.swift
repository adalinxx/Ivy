import Foundation
import Tally
import Testing
@testable import Ivy

@Suite("Transport-tagged addresses")
struct TransportTaggingTests {
    @Test("listen addresses carry their transport through canonical metadata")
    func metadataCarriesTransport() throws {
        let addresses = [
            ListenAddress(host: "192.0.2.1", port: 4001, transport: .tcp),
            ListenAddress(host: "192.0.2.1", port: 4001, transport: .quic),
        ]
        let metadata = PeerMetadata(listenAddresses: addresses)
        let encoded = try #require(metadata.encode())
        let decoded = try PeerMetadata.decodeCanonical(encoded)
        #expect(decoded.listenAddresses == metadata.listenAddresses)
        #expect(decoded.listenAddresses.map(\.transport) == [.tcp, .quic])
    }

    @Test("an unknown transport tag makes metadata malformed")
    func metadataRejectsUnknownTransportTag() throws {
        let encoded = try #require(PeerMetadata(listenAddresses: [
            ListenAddress(host: "192.0.2.1", port: 4001),
        ]).encode())
        var corrupted = encoded
        corrupted[corrupted.index(before: corrupted.endIndex)] = 0x7f
        #expect(throws: SessionProtocolError.malformed) {
            try PeerMetadata.decodeCanonical(corrupted)
        }
    }

    @Test("endpoints keep their transport across neighbors and provider records")
    func endpointsRoundtripTransport() throws {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("quic-peer"),
            host: "192.0.2.7",
            port: 4001,
            transport: .quic)

        let neighbors = try #require(
            Message.deserialize(Message.neighbors([endpoint], nonce: 9).serialize()))
        guard case .neighbors(let decoded, _) = neighbors else {
            Issue.record("expected neighbors")
            return
        }
        #expect(decoded == [endpoint])

        let record = ProviderRecord(endpoint: endpoint, expiresAt: 5)
        let providers = try #require(Message.deserialize(
            Message.providers(rootCID: "r", requestID: 1, records: [record]).serialize()))
        guard case .providers(_, _, let decodedRecords) = providers else {
            Issue.record("expected providers")
            return
        }
        #expect(decodedRecords.map(\.endpoint) == [endpoint])
    }

    @Test("a message carrying an unknown transport tag fails to decode")
    func messageRejectsUnknownTransportTag() throws {
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("tagged-peer"),
            host: "192.0.2.7",
            port: 4001)
        var wire = Message.neighbors([endpoint], nonce: 9).serialize()
        // The tag trails host and port, ahead of the 8-byte nonce.
        let tagIndex = wire.index(wire.endIndex, offsetBy: -9)
        #expect(wire[tagIndex] == TransportKind.tcp.rawValue)
        wire[tagIndex] = 0x7f
        #expect(Message.deserialize(wire) == nil)
    }

    @Test("a node advertises only the transports it has bound")
    func advertisesInstalledTransportsOnly() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: deterministicTestPeerKey("advertiser"),
            listenPort: 4001))
        let addresses = await ivy.advertisedListenAddresses(observedLocalHost: "192.0.2.9")
        #expect(!addresses.isEmpty)
        #expect(addresses.allSatisfy { $0.transport == .tcp })
    }

    @Test("an endpoint for an uninstalled transport is not routable")
    func rejectsEndpointsForUninstalledTransports() async throws {
        let ivy = Ivy(config: IvyConfig(publicKey: deterministicTestPeerKey("dialer")))
        let peerKey = deterministicTestPeerKey("remote")
        let peer = PeerID(publicKey: peerKey)
        let quic = PeerEndpoint(
            publicKey: peerKey,
            host: "1.1.1.1",
            port: 4001,
            transport: .quic)
        let tcp = PeerEndpoint(
            publicKey: peerKey,
            host: "1.1.1.1",
            port: 4001,
            transport: .tcp)

        #expect(await !ivy.isAcceptableDiscoveredEndpoint(
            quic, provenance: .selfAdvertisement, from: peer))
        #expect(await ivy.isAcceptableDiscoveredEndpoint(
            tcp, provenance: .selfAdvertisement, from: peer))
    }
}
