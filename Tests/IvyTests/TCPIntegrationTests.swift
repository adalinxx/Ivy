import Crypto
import Foundation
import Testing
@testable import Ivy
import Tally

enum TransportTestHarness {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var port =
        UInt16(ProcessInfo.processInfo.processIdentifier % 10_000) + 30_000

    static func nextPort() -> UInt16 {
        lock.withLock {
            port += 1
            return port
        }
    }

    static func identity(_ label: String) -> Curve25519.Signing.PrivateKey {
        try! Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(SHA256.hash(data: Data(label.utf8))))
    }

    static func key(_ identity: Curve25519.Signing.PrivateKey) -> PeerKey {
        try! PeerKey(rawRepresentation: identity.publicKey.rawRepresentation)
    }

    static func endpoint(
        _ identity: Curve25519.Signing.PrivateKey,
        port: UInt16
    ) -> PeerEndpoint {
        PeerEndpoint(publicKey: key(identity).hex, host: "127.0.0.1", port: port)
    }

    static func config(
        _ identity: Curve25519.Signing.PrivateKey,
        port: UInt16,
        bootstrapPeers: [PeerEndpoint] = [],
        carriers: [PeerEndpoint] = [],
        mode: IvyMode = .overlay,
        relayEnabled: Bool = false,
        maxConnections: Int = IvyConfig.defaultMaxConnections,
        maxContentCandidates: Int = 8
    ) -> IvyConfig {
        IvyConfig(
            signingKey: identity,
            listenPort: port,
            bootstrapPeers: bootstrapPeers,
            requestTimeout: .seconds(1),
            relayTimeout: .seconds(1),
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: maxConnections,
            maxConnectionsPerNetgroup: min(16, maxConnections),
            maxContentCandidates: maxContentCandidates,
            externalAddress: ("127.0.0.1", port),
            relayEnabled: relayEnabled,
            carriers: carriers,
            mode: mode)
    }

    static func eventually(
        attempts: Int = 100,
        _ condition: () async -> Bool
    ) async throws -> Bool {
        for _ in 0..<attempts {
            if await condition() { return true }
            try await Task.sleep(for: .milliseconds(20))
        }
        return await condition()
    }
}

final class TransportTestRecorder: IvyDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var connected: [AuthenticatedPeer] = []
    private var received: [(PeerMessage, PeerID)] = []

    func ivy(_ ivy: Ivy, didConnect peer: AuthenticatedPeer) {
        lock.withLock { connected.append(peer) }
    }

    func ivy(_ ivy: Ivy, didReceiveMessage message: PeerMessage, from peer: PeerID) {
        lock.withLock { received.append((message, peer)) }
    }

    var authenticatedPeers: [AuthenticatedPeer] {
        lock.withLock { connected }
    }

    func receivedMessage(topic: String, payload: Data, from peer: PeerID) -> Bool {
        lock.withLock {
            received.contains { message, sender in
                message.topic == topic && message.payload == payload && sender == peer
            }
        }
    }
}

final class TransportTestContentSource: IvyContentSource, Sendable {
    private let entries: [String: Data]

    init(_ entries: [String: Data]) {
        self.entries = entries
    }

    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry] {
        cids.compactMap { cid in
            entries[cid].map { ContentEntry(cid: cid, data: $0) }
        }
    }
}

final class TransportRawContentSource: IvyContentSource, Sendable {
    private let selections: [String: [ContentEntry]]

    init(_ selections: [String: [ContentEntry]]) {
        self.selections = selections
    }

    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry] {
        selections[rootCID] ?? []
    }
}

extension Ivy {
    func setTestDelegate(_ delegate: IvyDelegate?) {
        self.delegate = delegate
    }
}

@Suite("TCP transport", .serialized)
struct TCPIntegrationTests {
    @Test("SessionFinish authenticates both ends of a TCP connection")
    func authenticatedConnect() async throws {
        let serverIdentity = TransportTestHarness.identity("tcp-connect-server")
        let clientIdentity = TransportTestHarness.identity("tcp-connect-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        let serverRecorder = TransportTestRecorder()
        let clientRecorder = TransportTestRecorder()
        await server.setTestDelegate(serverRecorder)
        await client.setTestDelegate(clientRecorder)

        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(serverIdentity, port: serverPort))

        #expect(try await TransportTestHarness.eventually {
            let serverCount = await server.peerConnectionCount
            let clientCount = await client.peerConnectionCount
            return serverCount == 1
                && clientCount == 1
                && serverRecorder.authenticatedPeers.count == 1
                && clientRecorder.authenticatedPeers.count == 1
        })
        #expect(serverRecorder.authenticatedPeers.map(\.key) == [
            TransportTestHarness.key(clientIdentity),
        ])
        #expect(clientRecorder.authenticatedPeers.map(\.key) == [
            TransportTestHarness.key(serverIdentity),
        ])

        await client.stop()
        await server.stop()
    }

    @Test("Outbound authentication rejects an unexpected identity")
    func identityMismatch() async throws {
        let serverIdentity = TransportTestHarness.identity("tcp-actual-server")
        let expectedIdentity = TransportTestHarness.identity("tcp-expected-server")
        let clientIdentity = TransportTestHarness.identity("tcp-mismatch-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))

        try await server.start()
        try await client.start()
        await #expect(throws: (any Error).self) {
            try await client.connect(to: TransportTestHarness.endpoint(
                expectedIdentity,
                port: serverPort))
        }
        try await Task.sleep(for: .milliseconds(100))
        #expect(await client.peerConnectionCount == 0)
        #expect(await server.peerConnectionCount == 0)

        await client.stop()
        await server.stop()
    }

    @Test("Pinned listener rejects a substitute identity")
    func pinnedSubstitute() async throws {
        let expectedIdentity = TransportTestHarness.identity("tcp-pinned-expected")
        let listenerIdentity = TransportTestHarness.identity("tcp-pinned-listener")
        let substituteIdentity = TransportTestHarness.identity("tcp-pinned-substitute")
        let listenerPort = TransportTestHarness.nextPort()
        let substitutePort = TransportTestHarness.nextPort()
        let listener = Ivy(config: TransportTestHarness.config(
            listenerIdentity,
            port: listenerPort,
            mode: .pinned(peer: TransportTestHarness.key(expectedIdentity).hex)))
        let substitute = Ivy(config: TransportTestHarness.config(
            substituteIdentity,
            port: substitutePort))

        try await listener.start()
        try await substitute.start()
        await #expect(throws: (any Error).self) {
            try await substitute.connect(to: TransportTestHarness.endpoint(
                listenerIdentity,
                port: listenerPort))
        }
        try await Task.sleep(for: .milliseconds(100))
        #expect(await listener.peerConnectionCount == 0)

        await substitute.stop()
        await listener.stop()
    }

    @Test("Authenticated TCP carries generic peer messages")
    func peerMessageDelivery() async throws {
        let serverIdentity = TransportTestHarness.identity("tcp-message-server")
        let clientIdentity = TransportTestHarness.identity("tcp-message-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        let recorder = TransportTestRecorder()
        await server.setTestDelegate(recorder)

        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(serverIdentity, port: serverPort))
        #expect(try await TransportTestHarness.eventually {
            await server.peerConnectionCount == 1
        })

        let serverID = TransportTestHarness.key(serverIdentity).peerID
        let clientID = TransportTestHarness.key(clientIdentity).peerID
        let payload = Data("opaque node state".utf8)
        #expect(await client.sendMessage(
            to: serverID,
            topic: "node.state",
            payload: payload) == .enqueued(endpoint: serverID, route: .direct))
        #expect(try await TransportTestHarness.eventually {
            recorder.receivedMessage(topic: "node.state", payload: payload, from: clientID)
        })

        await client.stop()
        await server.stop()
    }

    @Test("Targeted partial content crosses authenticated TCP")
    func targetedContent() async throws {
        let serverIdentity = TransportTestHarness.identity("tcp-content-server")
        let clientIdentity = TransportTestHarness.identity("tcp-content-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let root = "opaque-root"
        let child = "opaque-child"
        let source = TransportTestContentSource([
            root: Data("root bytes".utf8),
            child: Data("child bytes".utf8),
        ])
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        await server.setContentSource(source)

        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(serverIdentity, port: serverPort))
        let serverID = TransportTestHarness.key(serverIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await server.peerConnectionCount == 1
        })

        let response = await client.fetchContent(
            ContentRequestKey(rootCID: root, cids: [child]),
            from: [serverID])
        #expect(response.entries == [
            root: Data("root bytes".utf8),
            child: Data("child bytes".utf8),
        ])
        #expect(response.servedBy == serverID)

        await client.stop()
        await server.stop()
    }

    @Test("storage cannot exceed the aggregate content budget")
    func oversizedContentSource() async throws {
        let serverIdentity = TransportTestHarness.identity("tcp-oversized-content-server")
        let clientIdentity = TransportTestHarness.identity("tcp-oversized-content-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let budget = try #require(Message.contentResponseDataBudget(
            for: ["root"],
            maxFrameSize: IvyConfig.protocolMaxFrameSize,
            relayed: false))
        let source = TransportTestContentSource([
            "root": Data(repeating: 0xaa, count: budget + 1),
        ])
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        await server.setContentSource(source)

        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(serverIdentity, port: serverPort))
        let serverID = TransportTestHarness.key(serverIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await server.peerConnectionCount == 1
        })

        let response = await client.fetchContent(
            ContentRequestKey(rootCID: "root", cids: []),
            from: [serverID])
        #expect(response == .empty)

        await client.stop()
        await server.stop()
    }

    @Test("remote source output must exactly match the requested selection")
    func malformedContentSource() async throws {
        let serverIdentity = TransportTestHarness.identity("tcp-malformed-content-server")
        let clientIdentity = TransportTestHarness.identity("tcp-malformed-content-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let duplicateRoot = ContentEntry(cid: "duplicate", data: Data())
        let extraRoot = ContentEntry(cid: "extra-root", data: Data())
        let missingRoot = ContentEntry(cid: "missing-child", data: Data())
        let source = TransportRawContentSource([
            "duplicate": [duplicateRoot, duplicateRoot],
            "extra-root": [extraRoot, ContentEntry(cid: "unrequested", data: Data())],
            "missing-child": [missingRoot],
        ])
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        await server.setContentSource(source)

        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(serverIdentity, port: serverPort))
        let serverID = TransportTestHarness.key(serverIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await server.peerConnectionCount == 1
        })

        for root in ["duplicate", "extra-root", "missing-child"] {
            let response = await client.fetchContent(
                ContentRequestKey(rootCID: root, cids: ["child"]),
                from: [serverID])
            #expect(response == .empty)
        }

        await client.stop()
        await server.stop()
    }

    @Test("simultaneous cross-dial converges to one usable session")
    func duplicateSessionConvergence() async throws {
        let leftIdentity = TransportTestHarness.identity("cross-dial-left")
        let rightIdentity = TransportTestHarness.identity("cross-dial-right")
        let leftPort = TransportTestHarness.nextPort()
        let rightPort = TransportTestHarness.nextPort()
        let left = Ivy(config: TransportTestHarness.config(leftIdentity, port: leftPort))
        let right = Ivy(config: TransportTestHarness.config(rightIdentity, port: rightPort))
        let recorder = TransportTestRecorder()
        await right.setTestDelegate(recorder)

        try await left.start()
        try await right.start()
        async let leftDial: Void = left.connect(to: TransportTestHarness.endpoint(
            rightIdentity,
            port: rightPort))
        async let rightDial: Void = right.connect(to: TransportTestHarness.endpoint(
            leftIdentity,
            port: leftPort))
        _ = try await (leftDial, rightDial)

        let rightID = TransportTestHarness.key(rightIdentity).peerID
        let leftID = TransportTestHarness.key(leftIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            let leftCount = await left.peerConnectionCount
            let rightCount = await right.peerConnectionCount
            let leftSession = await left.selectedSessionIDForTesting(rightID)
            let rightSession = await right.selectedSessionIDForTesting(leftID)
            let leftPending = await left.pendingSessionCountForTesting
            let rightPending = await right.pendingSessionCountForTesting
            return leftCount == 1
                && rightCount == 1
                && leftSession != nil
                && leftSession == rightSession
                && leftPending == 0
                && rightPending == 0
        })
        let result = await left.sendMessage(
            to: rightID,
            topic: "cross-dial",
            payload: Data("still live".utf8))
        guard case .enqueued = result else {
            Issue.record("converged session rejected the first application message: \(result)")
            await right.stop()
            await left.stop()
            return
        }
        #expect(try await TransportTestHarness.eventually {
            recorder.receivedMessage(
                topic: "cross-dial",
                payload: Data("still live".utf8),
                from: leftID)
        })

        await right.stop()
        await left.stop()
    }

    @Test("configured peers retry after an initial startup failure")
    func startupRetry() async throws {
        let serverIdentity = TransportTestHarness.identity("retry-server")
        let clientIdentity = TransportTestHarness.identity("retry-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let serverEndpoint = TransportTestHarness.endpoint(serverIdentity, port: serverPort)
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(
            clientIdentity,
            port: clientPort,
            bootstrapPeers: [serverEndpoint],
            mode: .pinned(peer: serverEndpoint.publicKey)))

        try await client.start()
        try await Task.sleep(for: .milliseconds(100))
        try await server.start()

        #expect(try await TransportTestHarness.eventually(attempts: 200) {
            await client.peerConnectionCount == 1
        })

        await client.stop()
        await server.stop()
    }

    @Test("the authenticated connection cap rejects excess peers")
    func authenticatedConnectionCap() async throws {
        let serverIdentity = TransportTestHarness.identity("capacity-server")
        let firstIdentity = TransportTestHarness.identity("capacity-first")
        let secondIdentity = TransportTestHarness.identity("capacity-second")
        let serverPort = TransportTestHarness.nextPort()
        let firstPort = TransportTestHarness.nextPort()
        let secondPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(
            serverIdentity,
            port: serverPort,
            maxConnections: 1))
        let first = Ivy(config: TransportTestHarness.config(firstIdentity, port: firstPort))
        let second = Ivy(config: TransportTestHarness.config(secondIdentity, port: secondPort))
        let endpoint = TransportTestHarness.endpoint(serverIdentity, port: serverPort)

        try await server.start()
        try await first.start()
        try await second.start()
        try await first.connect(to: endpoint)
        await #expect(throws: (any Error).self) {
            try await second.connect(to: endpoint)
        }
        #expect(await server.peerConnectionCount == 1)

        await second.stop()
        await first.stop()
        await server.stop()
    }
}
