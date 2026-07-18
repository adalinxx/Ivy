import Crypto
import Foundation
import NIOPosix
import Testing
@testable import Ivy
import Tally

private struct TransportTestTimeout: Error {
    let event: String
}

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
        advertisedHost: String = "127.0.0.1",
        bootstrapPeers: [PeerEndpoint] = [],
        carriers: [PeerEndpoint] = [],
        mode: IvyMode = .overlay,
        relayEnabled: Bool = false,
        relayTimeout: Duration = .seconds(1),
        maxConnections: Int = IvyConfig.defaultMaxConnections,
        maxContentCandidates: Int = 8
    ) -> IvyConfig {
        IvyConfig(
            signingKey: identity,
            listenPort: port,
            bootstrapPeers: bootstrapPeers,
            requestTimeout: .seconds(1),
            relayTimeout: relayTimeout,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: maxConnections,
            maxConnectionsPerNetgroup: min(16, maxConnections),
            maxContentCandidates: maxContentCandidates,
            externalAddress: port == 0 ? nil : (advertisedHost, port),
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
    private var currentConnections: Set<String> = []
    private var disconnected: [PeerID] = []
    private var received: [(PeerMessage, PeerID)] = []

    func ivy(_ ivy: Ivy, didConnect peer: AuthenticatedPeer) {
        lock.withLock {
            connected.append(peer)
            currentConnections.insert(peer.key.hex)
        }
    }

    func ivy(_ ivy: Ivy, didDisconnect peer: PeerID) {
        lock.withLock {
            disconnected.append(peer)
            currentConnections.remove(peer.publicKey)
        }
    }

    func ivy(_ ivy: Ivy, didReceiveMessage message: PeerMessage, from peer: PeerID) {
        lock.withLock { received.append((message, peer)) }
    }

    var authenticatedPeers: [AuthenticatedPeer] {
        lock.withLock { connected }
    }

    func isConnected(_ peer: PeerID) -> Bool {
        lock.withLock { currentConnections.contains(peer.publicKey) }
    }

    func waitForConnect(_ peer: PeerID) async throws {
        guard try await TransportTestHarness.eventually({
            self.lock.withLock { self.currentConnections.contains(peer.publicKey) }
        }) else {
            throw TransportTestTimeout(event: "connect \(peer.publicKey)")
        }
    }

    func waitForDisconnect(_ peer: PeerID) async throws {
        guard try await TransportTestHarness.eventually({
            self.lock.withLock { self.disconnected.contains(peer) }
        }) else {
            throw TransportTestTimeout(event: "disconnect \(peer.publicKey)")
        }
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

private actor CancellationAwareContentSource: IvyContentSource {
    private var started = false
    private var cancelled = false

    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry] {
        started = true
        do {
            try await Task.sleep(for: .seconds(60))
        } catch {
            cancelled = true
        }
        return []
    }

    func didStart() -> Bool { started }
    func wasCancelled() -> Bool { cancelled }
}

private actor NonCooperativeContentSource: IvyContentSource {
    private var started = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry] {
        started = true
        await withCheckedContinuation { waiters.append($0) }
        return []
    }

    func didStart() -> Bool { started }

    func release() {
        let current = waiters
        waiters.removeAll()
        for waiter in current { waiter.resume() }
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

    @Test("connections accepted before discovery completes are health-tracked")
    func connectionDuringDiscoveryIsHealthTracked() async throws {
        let serverIdentity = TransportTestHarness.identity("health-before-discovery-server")
        let clientIdentity = TransportTestHarness.identity("health-before-discovery-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let server = Ivy(config: IvyConfig(
            signingKey: serverIdentity,
            listenPort: serverPort,
            stunServers: [],
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(60),
                staleTimeout: .seconds(180)),
            externalAddress: ("127.0.0.1", serverPort)))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        let discovery = TestBarrier("listener ready before discovery")
        await server.setListenerReadyHookForTesting {
            do {
                try await discovery.arriveAndWait()
            } catch {
                Issue.record("\(error)")
            }
        }

        let starting = Task { try await server.start() }
        try await discovery.waitForArrivals()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(
            serverIdentity,
            port: serverPort))
        let clientID = TransportTestHarness.key(clientIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await server.isHealthTrackedForTesting(clientID)
        })

        await discovery.release()
        try await starting.value
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

    @Test("Authenticated TCP carries directed sync and broadcast gossip")
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

        let gossip = Data("new block".utf8)
        await client.broadcastMessage(topic: "blocks.gossip", payload: gossip)
        #expect(try await TransportTestHarness.eventually {
            recorder.receivedMessage(topic: "blocks.gossip", payload: gossip, from: clientID)
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
        let recorder = TransportTestRecorder()
        await server.setTestDelegate(recorder)
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

        await client.reportDeficientContent(rootCID: root, servedBy: serverID)
        #expect(await client.peerConnectionCount == 1)
        let sync = Data("next range".utf8)
        #expect(await client.sendMessage(
            to: serverID,
            topic: "sync.request",
            payload: sync) == .enqueued(endpoint: serverID, route: .direct))
        let clientID = TransportTestHarness.key(clientIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            recorder.receivedMessage(topic: "sync.request", payload: sync, from: clientID)
        })

        await client.stop()
        await server.stop()
    }

    @Test("closing a connection cancels its active content callback")
    func connectionCloseCancelsContentCallback() async throws {
        let serverIdentity = TransportTestHarness.identity("cancel-content-server")
        let clientIdentity = TransportTestHarness.identity("cancel-content-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        let source = CancellationAwareContentSource()
        await server.setContentSource(source)

        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(
            serverIdentity,
            port: serverPort))
        let serverID = TransportTestHarness.key(serverIdentity).peerID
        let request = BoundedTestTask {
            await client.fetchContent(
                ContentRequestKey(rootCID: "root", cids: []),
                from: [serverID])
        }
        #expect(try await TransportTestHarness.eventually { await source.didStart() })

        await server.stop()
        #expect(try await TransportTestHarness.eventually { await source.wasCancelled() })
        #expect(try await request.value(waitingFor: "cancelled content callback") == .empty)
        await client.stop()
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

    @Test("transport close retires a session even if storage ignores cancellation")
    func connectionCloseDoesNotWaitForStorage() async throws {
        let serverIdentity = TransportTestHarness.identity("stuck-content-server")
        let clientIdentity = TransportTestHarness.identity("stuck-content-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        let source = NonCooperativeContentSource()
        await server.setContentSource(source)

        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(
            serverIdentity,
            port: serverPort))
        let serverID = TransportTestHarness.key(serverIdentity).peerID
        let request = BoundedTestTask {
            await client.fetchContent(
                ContentRequestKey(rootCID: "root", cids: []),
                from: [serverID])
        }
        #expect(try await TransportTestHarness.eventually { await source.didStart() })

        await client.disconnect(serverID)
        #expect(try await TransportTestHarness.eventually {
            await server.peerConnectionCount == 0
        })

        await source.release()
        #expect(try await request.value(waitingFor: "closed stuck content request") == .empty)
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
        let rightEndpoint = TransportTestHarness.endpoint(rightIdentity, port: rightPort)
        let leftEndpoint = TransportTestHarness.endpoint(leftIdentity, port: leftPort)
        let rightID = TransportTestHarness.key(rightIdentity).peerID
        let leftID = TransportTestHarness.key(leftIdentity).peerID
        async let leftDial: Void = left.connect(to: rightEndpoint)
        async let rightDial: Void = right.connect(to: leftEndpoint)
        _ = try await (leftDial, rightDial)

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

    @Test("configured identities fail over across all declared routes")
    func configuredRouteFailover() async throws {
        let serverIdentity = TransportTestHarness.identity("route-failover-server")
        let clientIdentity = TransportTestHarness.identity("route-failover-client")
        let deadPort = TransportTestHarness.nextPort()
        let livePort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let dead = TransportTestHarness.endpoint(serverIdentity, port: deadPort)
        let live = TransportTestHarness.endpoint(serverIdentity, port: livePort)
        let serverID = TransportTestHarness.key(serverIdentity).peerID
        let recorder = TransportTestRecorder()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: livePort))
        let client = Ivy(config: TransportTestHarness.config(
            clientIdentity,
            port: clientPort,
            bootstrapPeers: [dead, live],
            mode: .pinned(peer: serverID.publicKey)))
        await client.setTestDelegate(recorder)

        try await server.start()
        try await client.start()
        try await recorder.waitForConnect(serverID)

        await server.stop()
        try await recorder.waitForDisconnect(serverID)
        try await server.start()
        await client.runPendingReconnectForTesting(serverID)
        try await recorder.waitForConnect(serverID)

        #expect(await client.peerConnectionCount == 1)
        await client.stop()
        await server.stop()
    }

    @Test("an established configured peer reconnects after transport loss")
    func establishedReconnect() async throws {
        let serverIdentity = TransportTestHarness.identity("reconnect-established-server")
        let clientIdentity = TransportTestHarness.identity("reconnect-established-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let serverEndpoint = TransportTestHarness.endpoint(serverIdentity, port: serverPort)
        let serverID = TransportTestHarness.key(serverIdentity).peerID
        let clientID = TransportTestHarness.key(clientIdentity).peerID
        let recorder = TransportTestRecorder()
        let restartedServerRecorder = TransportTestRecorder()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(
            clientIdentity,
            port: clientPort,
            bootstrapPeers: [serverEndpoint],
            mode: .pinned(peer: serverID.publicKey)))
        await client.setTestDelegate(recorder)

        try await server.start()
        try await client.start()
        try await recorder.waitForConnect(serverID)

        await server.stop()
        try await recorder.waitForDisconnect(serverID)
        await server.setTestDelegate(restartedServerRecorder)
        try await server.start()
        await client.runPendingReconnectForTesting(serverID)
        try await recorder.waitForConnect(serverID)
        try await restartedServerRecorder.waitForConnect(clientID)

        #expect(await client.peerConnectionCount == 1)
        #expect(await server.peerConnectionCount == 1)
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

    @Test("an old session cannot deliver after replacement during an actor hop")
    func staleSessionMessageIsDropped() async throws {
        let node = Ivy(config: IvyConfig(
            publicKey: "stale-message-node",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        let peerIdentity = TransportTestHarness.identity("stale-message-peer")
        let endpoint = TransportTestHarness.endpoint(peerIdentity, port: 4001)
        let peer = TransportTestHarness.key(peerIdentity).peerID
        let recorder = TransportTestRecorder()
        let activity = TestBarrier("message activity actor hop")
        await node.setTestDelegate(recorder)
        try await node.seedConnectedEndpointForTesting(endpoint, marker: 1)
        await node.setMessageActivityHookForTesting {
            do {
                try await activity.arriveAndWait()
            } catch {
                Issue.record("\(error)")
            }
        }

        let stale = BoundedTestTask {
            await node.handleCurrentMessageForTesting(
                .peerMessage(topic: "stale", payload: Data("old".utf8)),
                from: peer)
            return true
        }
        try await activity.waitForArrivals()
        try await node.seedConnectedEndpointForTesting(endpoint, marker: 2)
        await activity.release()

        #expect(try await stale.value(waitingFor: "stale session message"))
        #expect(!recorder.receivedMessage(
            topic: "stale",
            payload: Data("old".utf8),
            from: peer))
        await node.stop()
    }

    @Test("a transport closed during promotion cannot make connect succeed")
    func closedPromotionFailsAuthentication() async throws {
        let serverIdentity = TransportTestHarness.identity("closed-promotion-server")
        let clientIdentity = TransportTestHarness.identity("closed-promotion-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        await client.setPromotionHookForTesting { $0.cancel() }

        try await server.start()
        try await client.start()
        await #expect(throws: (any Error).self) {
            try await client.connect(to: TransportTestHarness.endpoint(
                serverIdentity,
                port: serverPort))
        }
        #expect(try await TransportTestHarness.eventually {
            let clientCount = await client.peerConnectionCount
            let serverCount = await server.peerConnectionCount
            return clientCount == 0 && serverCount == 0
        })

        await client.stop()
        await server.stop()
    }

    @Test("cancelling authentication immediately releases its socket")
    func authenticationCancellationReleasesCapacity() async throws {
        let stalledIdentity = TransportTestHarness.identity("cancel-auth-stalled")
        let clientIdentity = TransportTestHarness.identity("cancel-auth-client")
        let accepted = TestChannelRecorder()
        let listener = try await ServerBootstrap(
            group: MultiThreadedEventLoopGroup.singleton
        ).childChannelInitializer { channel in
            accepted.store(channel)
            return channel.eventLoop.makeSucceededVoidFuture()
        }.bind(host: "127.0.0.1", port: 0).get()
        let rawPort = try #require(listener.localAddress?.port)
        let port = try #require(UInt16(exactly: rawPort))
        let client = Ivy(config: IvyConfig(
            signingKey: clientIdentity,
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        try await client.start()

        let connecting = Task { () -> Bool in
            do {
                try await client.connect(to: TransportTestHarness.endpoint(
                    stalledIdentity,
                    port: port))
                return true
            } catch {
                return false
            }
        }
        #expect(try await TransportTestHarness.eventually {
            await client.pendingSessionCountForTesting == 1
        })
        #expect(accepted.isActive)

        connecting.cancel()
        let completion = BoundedTestTask { await connecting.value }
        #expect(!(try await completion.value(waitingFor: "cancelled authentication")))
        #expect(try await TransportTestHarness.eventually {
            let pending = await client.pendingSessionCountForTesting
            let outgoing = await client.outgoingDialCountForTesting
            return pending == 0 && outgoing == 0
        })
        #expect(try await TransportTestHarness.eventually { !accepted.isActive })

        await client.stop()
        try await listener.close().get()
    }

    @Test("configured maintenance survives a transport closing during promotion")
    func closedPromotionRearmsConfiguredReconnect() async throws {
        let serverIdentity = TransportTestHarness.identity("promotion-reconnect-server")
        let clientIdentity = TransportTestHarness.identity("promotion-reconnect-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let endpoint = TransportTestHarness.endpoint(serverIdentity, port: serverPort)
        let serverID = TransportTestHarness.key(serverIdentity).peerID
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(
            clientIdentity,
            port: clientPort,
            bootstrapPeers: [endpoint],
            mode: .pinned(peer: serverID.publicKey)))
        await client.setPromotionHookForTesting { $0.cancel() }

        try await server.start()
        try await client.start()
        #expect(try await TransportTestHarness.eventually {
            let reconnecting = await client.reconnectTasks[serverID] != nil
            let connected = await client.peerConnectionCount
            return reconnecting && connected == 0
        })

        await client.setPromotionHookForTesting(nil)
        await client.runPendingReconnectForTesting(serverID)
        #expect(try await TransportTestHarness.eventually {
            await client.peerConnectionCount == 1
        })

        await client.stop()
        await server.stop()
    }

    @Test("a pinned reconnect cannot substitute another endpoint identity")
    func pinnedReconnectRejectsSubstituteIdentity() async throws {
        let expectedIdentity = TransportTestHarness.identity("reconnect-expected")
        let substituteIdentity = TransportTestHarness.identity("reconnect-substitute")
        let clientIdentity = TransportTestHarness.identity("reconnect-pinned-client")
        let expectedPort = TransportTestHarness.nextPort()
        let substitutePort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let expectedEndpoint = TransportTestHarness.endpoint(expectedIdentity, port: expectedPort)
        let expectedID = TransportTestHarness.key(expectedIdentity).peerID
        let recorder = TransportTestRecorder()
        let expected = Ivy(config: TransportTestHarness.config(expectedIdentity, port: expectedPort))
        let substitute = Ivy(config: TransportTestHarness.config(
            substituteIdentity,
            port: substitutePort))
        let client = Ivy(config: TransportTestHarness.config(
            clientIdentity,
            port: clientPort,
            bootstrapPeers: [expectedEndpoint],
            mode: .pinned(peer: expectedID.publicKey)))
        await client.setTestDelegate(recorder)

        try await expected.start()
        try await substitute.start()
        try await client.start()
        try await recorder.waitForConnect(expectedID)

        await expected.stop()
        try await recorder.waitForDisconnect(expectedID)
        await client.setDialEndpointRewriteForTesting { endpoint in
            PeerEndpoint(
                publicKey: endpoint.publicKey,
                host: "127.0.0.1",
                port: substitutePort)
        }
        await client.runPendingReconnectForTesting(expectedID)

        #expect(await client.peerConnectionCount == 0)
        #expect(await substitute.peerConnectionCount == 0)
        await client.stop()
        await substitute.stop()
    }

    @Test("releasing a connected node closes its transports")
    func releasingNodeClosesConnections() async throws {
        let serverIdentity = TransportTestHarness.identity("release-server")
        let clientIdentity = TransportTestHarness.identity("release-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let clientID = TransportTestHarness.key(clientIdentity).peerID
        let server = Ivy(config: TransportTestHarness.config(
            serverIdentity,
            port: serverPort))
        var client: Ivy? = Ivy(config: TransportTestHarness.config(
            clientIdentity,
            port: clientPort))
        weak let releasedClient = client

        try await server.start()
        try await client?.start()
        try await client?.connect(to: TransportTestHarness.endpoint(
            serverIdentity,
            port: serverPort))
        #expect(try await TransportTestHarness.eventually {
            await server.connectedPeers.contains(clientID)
        })

        client = nil

        #expect(try await TransportTestHarness.eventually { releasedClient == nil })
        #expect(try await TransportTestHarness.eventually {
            await !server.connectedPeers.contains(clientID)
        })
        await server.stop()
    }
}
