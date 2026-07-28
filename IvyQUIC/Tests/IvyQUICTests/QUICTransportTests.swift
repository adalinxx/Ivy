import Crypto
import Foundation
import Ivy
import NIOCore
import Testing
@testable import IvyQUIC

@Suite("QUIC transport")
struct QUICTransportTests {
    private func identity(_ label: String) -> Curve25519.Signing.PrivateKey {
        try! Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(SHA256.hash(data: Data(label.utf8))))
    }

    private func config(
        _ identity: Curve25519.Signing.PrivateKey,
        port: UInt16
    ) -> IvyConfig {
        IvyConfig(
            signingKey: identity,
            listenPort: 0,
            quicListenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            externalAddress: port == 0 ? nil : ("127.0.0.1", port))
    }

    @Test("two nodes complete an authenticated session over QUIC")
    func authenticatedSessionOverQUIC() async throws {
        let listenerIdentity = identity("quic-listener")
        let dialerIdentity = identity("quic-dialer")

        let listener = Ivy(
            config: config(listenerIdentity, port: 0),
            transports: [try QUICTransport()])
        let dialer = Ivy(
            config: config(dialerIdentity, port: 0),
            transports: [try QUICTransport()])

        try await listener.start()
        try await dialer.start()

        let port = try #require(await listener.boundPort(for: .quic))
        let listenerKey = try PeerKey(
            rawRepresentation: listenerIdentity.publicKey.rawRepresentation)
        try await dialer.connect(to: PeerEndpoint(
            publicKey: listenerKey.hex,
            host: "127.0.0.1",
            port: port,
            transport: .quic))

        #expect(await dialer.connectedPeers.count == 1)
        #expect(await listener.connectedPeers.count == 1)

        await dialer.stop()
        await listener.stop()
    }
}
