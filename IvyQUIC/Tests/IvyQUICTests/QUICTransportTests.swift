import Crypto
import Foundation
import Ivy
import NIOCore
import NIOPosix
import Testing
@testable import IvyQUIC

/// Records what arrived, so a test can wait for delivery rather than sleep.
final class MessageRecorder: IvyDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var messages: [PeerMessage] = []

    func ivy(_ ivy: Ivy, didReceiveMessage message: PeerMessage, from peer: AuthenticatedPeer) async {
        lock.withLock { messages.append(message) }
    }

    var received: [PeerMessage] { lock.withLock { messages } }
}

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
        // The dial returns once the initiator is satisfied; the responder
        // promotes its own session an actor hop later, so converge rather than
        // assume the two happen together.
        try await eventually { await listener.connectedPeers.count == 1 }

        await dialer.stop()
        await listener.stop()
    }

    /// Drives the read pump hard: payloads far larger than one QUIC delivery, so
    /// every frame is reassembled across many chunks, and enough of them that
    /// the demand loop has to re-arm repeatedly.
    @Test("records spanning many QUIC deliveries are reassembled in order")
    func multiFrameExchangeOverQUIC() async throws {
        let listenerIdentity = identity("quic-bulk-listener")
        let dialerIdentity = identity("quic-bulk-dialer")

        let listener = Ivy(
            config: config(listenerIdentity, port: 0),
            transports: [try QUICTransport()])
        let dialer = Ivy(
            config: config(dialerIdentity, port: 0),
            transports: [try QUICTransport()])
        let recorder = MessageRecorder()
        await listener.setDelegate(recorder)

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

        let listenerID = try #require(await dialer.connectedPeers.first)
        let sent = (0..<8).map { index in
            PeerMessage(
                topic: "bulk-\(index)",
                payload: Data(repeating: UInt8(index), count: 128 * 1024))
        }
        for message in sent {
            var result = await dialer.sendMessage(
                to: listenerID,
                topic: message.topic,
                payload: message.payload)
            // The watermark stops the writer rather than queueing without bound.
            while case .backpressured = result {
                #expect(await dialer.waitUntilWritable(to: listenerID))
                result = await dialer.sendMessage(
                    to: listenerID,
                    topic: message.topic,
                    payload: message.payload)
            }
            if case .enqueued = result {} else {
                Issue.record("send was refused: \(result)")
            }
        }

        try await eventually { recorder.received.count == sent.count }
        #expect(recorder.received == sent)

        await dialer.stop()
        await listener.stop()
    }

    /// The mapping the peer sees has to be the one this node advertises, or a
    /// punch lands on a port nothing is listening on. This works because the
    /// dialing socket is connected to the remote, so its 4-tuple wins demux
    /// against the listener sharing the port.
    @Test("a hole-punch dial leaves from the port this node advertises")
    func holePunchDialUsesAdvertisedPort() async throws {
        let group = MultiThreadedEventLoopGroup.singleton
        let transport = try QUICTransport(reusePort: true)

        let listener = try await transport.listen(
            host: "127.0.0.1",
            port: 0,
            group: group,
            onConnection: { _ in })
        let listenPort = try #require(listener.localPort)

        // Somewhere to dial that is not ourselves.
        let peer = try await transport.listen(
            host: "127.0.0.1",
            port: 0,
            group: group,
            onConnection: { _ in })
        let peerPort = try #require(peer.localPort)

        let dialed = try await transport.dial(
            host: "127.0.0.1",
            port: peerPort,
            group: group,
            boundToPort: listenPort)
        #expect(dialed.isActive)
        #expect(dialed.localPort == listenPort)

        dialed.close()
        await listener.close()
        await peer.close()
    }

    /// Tearing down while records are still in flight is where a close race
    /// shows up: the read pump, the write pump, and the session teardown all
    /// run at once. The surviving end must settle rather than hang or trap.
    ///
    /// The idle timeout is deliberately short here because it is what bounds
    /// this: a QUIC peer that stops answering sends no FIN, so the stream ends
    /// only when the idle timer fires, and the session — with its admission
    /// slot — is held until then. On TCP the same teardown is immediate.
    @Test("a QUIC session torn down mid-transfer settles on both ends")
    func teardownDuringTransfer() async throws {
        let listenerIdentity = identity("quic-teardown-listener")
        let dialerIdentity = identity("quic-teardown-dialer")

        let listener = Ivy(
            config: config(listenerIdentity, port: 0),
            transports: [try QUICTransport(idleTimeout: .seconds(2))])
        let dialer = Ivy(
            config: config(dialerIdentity, port: 0),
            transports: [try QUICTransport(idleTimeout: .seconds(2))])

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
        let listenerID = try #require(await dialer.connectedPeers.first)

        // Keep records moving, then pull the listener out from under them.
        for index in 0..<16 {
            _ = await dialer.sendMessage(
                to: listenerID,
                topic: "teardown-\(index)",
                payload: Data(repeating: 0xAB, count: 64 * 1024))
        }
        await listener.stop()

        try await eventually { await dialer.connectedPeers.isEmpty }
        await dialer.stop()
        #expect(await dialer.connectedPeers.isEmpty)
    }

    private func eventually(
        timeout: Duration = .seconds(5),
        _ condition: @Sendable () async -> Bool
    ) async throws {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            if await condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("condition never became true within \(timeout)")
    }
}
