import Foundation
import Testing
@testable import Ivy
import Tally

/// Serves a fixed set of Volumes, each keyed by its root.
private struct MapVolumeSource: IvyContentSource {
    let volumes: [String: [ContentEntry]]
    var bundles: [String: [String]] = [:]

    func volumeBundle(rootCID: String) -> [String] {
        bundles[rootCID] ?? []
    }

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] {
        []
    }

    func volume(rootCID: String, maxDataBytes: Int) -> [ContentEntry] {
        volumes[rootCID] ?? []
    }
}

/// Holds every read until `open()`; reads after that return at once.
private actor GatedVolumeSource: IvyContentSource {
    private let volumes: [String: [ContentEntry]]
    private let bundles: [String: [String]]
    private var isOpen = false
    private var startedReads = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(volumes: [String: [ContentEntry]], bundles: [String: [String]] = [:]) {
        self.volumes = volumes
        self.bundles = bundles
    }

    func volumeBundle(rootCID: String) -> [String] {
        bundles[rootCID] ?? []
    }

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] {
        []
    }

    func volume(rootCID: String, maxDataBytes: Int) async -> [ContentEntry] {
        startedReads += 1
        readOrder.append(rootCID)
        if !isOpen { await withCheckedContinuation { waiters.append($0) } }
        return volumes[rootCID] ?? []
    }

    func readsStarted() -> Int { startedReads }
    private var readOrder: [String] = []
    func reads() -> [String] { readOrder }

    func open() {
        isOpen = true
        let current = waiters
        waiters.removeAll()
        for waiter in current { waiter.resume() }
    }
}

private func smallVolume(_ root: String) -> [ContentEntry] {
    [
        ContentEntry(cid: root, data: Data("\(root) bytes".utf8)),
        ContentEntry(cid: "\(root)-child", data: Data("\(root) child".utf8)),
    ]
}

private func expectedResponse(
    _ root: String,
    servedBy peer: PeerID
) -> AttributedVolumeResponse {
    AttributedVolumeResponse(
        rootCID: root,
        entries: Dictionary(uniqueKeysWithValues: smallVolume(root).map { ($0.cid, $0.data) }),
        servedBy: peer
    )
}

/// Two started, connected nodes: `client` dials `server`.
private struct ConnectedPair {
    let server: Ivy
    let client: Ivy
    let serverPeer: AuthenticatedPeer
    let clientPeer: AuthenticatedPeer
    let serverEndpoint: PeerEndpoint

    static func make(
        _ name: String,
        serverSource: (any IvyContentSource)?,
        serverInFlightVolumeBytes: Int = IvyConfig.defaultMaxInFlightVolumeBytes,
        serverConcurrentContentRequests: Int = 64,
        serverRequestTimeout: Duration? = nil,
        requestTimeout: Duration = .seconds(5)
    ) async throws -> ConnectedPair {
        let serverIdentity = TransportTestHarness.identity("\(name)-server")
        let clientIdentity = TransportTestHarness.identity("\(name)-client")
        let serverPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(
            serverIdentity,
            port: serverPort,
            requestTimeout: serverRequestTimeout ?? requestTimeout,
            maxInFlightVolumeBytes: serverInFlightVolumeBytes,
            maxConcurrentContentRequests: serverConcurrentContentRequests
        ))
        let client = Ivy(config: TransportTestHarness.config(
            clientIdentity,
            port: TransportTestHarness.nextPort(),
            requestTimeout: requestTimeout
        ))
        let serverRecorder = TransportTestRecorder()
        let clientRecorder = TransportTestRecorder()
        await server.setTestDelegate(serverRecorder)
        await client.setTestDelegate(clientRecorder)
        if let serverSource { await server.setContentSource(serverSource) }
        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(serverIdentity, port: serverPort))
        #expect(try await TransportTestHarness.eventually {
            serverRecorder.authenticatedPeers.count == 1
                && clientRecorder.authenticatedPeers.count == 1
        })
        return ConnectedPair(
            server: server,
            client: client,
            serverPeer: try #require(clientRecorder.authenticatedPeers.first),
            clientPeer: try #require(serverRecorder.authenticatedPeers.first),
            serverEndpoint: TransportTestHarness.endpoint(serverIdentity, port: serverPort)
        )
    }

    func stop() async {
        await client.stop()
        await server.stop()
    }
}

@Suite("Volume serving capacity and fetch order", .serialized)
struct VolumeServingTests {
    @Test("small Volumes being sent hold their own size, so many share the budget")
    func sendingVolumesHoldActualSize() async throws {
        let roots = (0..<8).map { "small-\($0)" }
        let pair = try await ConnectedPair.make(
            "serving-actual-size",
            serverSource: MapVolumeSource(volumes: Dictionary(
                uniqueKeysWithValues: roots.map { ($0, smallVolume($0)) }
            ))
        )
        // Stall every send so all eight are in flight at once. The old
        // worst-case reservation (64 MiB each, 128 MiB budget) admitted two
        // and refused the other six.
        await pair.server.setEndpointWritabilityForTesting(pair.clientPeer.id, writable: false)
        let fetches = roots.map { root in
            Task { await pair.client.fetchVolume(rootCID: root, from: pair.serverPeer) }
        }
        let archiveBytes = roots.reduce(0) { total, root in
            total + (VolumeArchive.encode(entries: smallVolume(root), rootCID: root)?.data.count ?? 0)
        }
        #expect(archiveBytes > 0 && archiveBytes < MessageLimits.maxVolumeArchiveBytes)
        #expect(try await TransportTestHarness.eventually {
            await pair.server.reservedServingVolumeBytesForTesting == archiveBytes
        })
        await pair.server.setEndpointWritabilityForTesting(pair.clientPeer.id, writable: true)
        for (root, fetch) in zip(roots, fetches) {
            #expect(await fetch.value == expectedResponse(root, servedBy: pair.serverPeer.id))
        }
        #expect(try await TransportTestHarness.eventually {
            await pair.server.reservedServingVolumeBytesForTesting == 0
        })
        await pair.stop()
    }

    @Test("a read beyond capacity waits its turn instead of being refused")
    func burstWaitsForReadCapacity() async throws {
        let source = GatedVolumeSource(volumes: ["first": smallVolume("first"), "second": smallVolume("second")])
        // Room for exactly one worst-case read.
        let pair = try await ConnectedPair.make(
            "serving-burst-waits",
            serverSource: source,
            serverInFlightVolumeBytes: MessageLimits.maxVolumeArchiveBytes
        )
        let first = Task { await pair.client.fetchVolume(rootCID: "first", from: pair.serverPeer) }
        #expect(try await TransportTestHarness.eventually { await source.readsStarted() == 1 })
        let second = Task { await pair.client.fetchVolume(rootCID: "second", from: pair.serverPeer) }
        #expect(try await TransportTestHarness.eventually {
            await pair.server.servingVolumeReadWaiterCountForTesting == 1
        })
        #expect(await source.readsStarted() == 1)

        await source.open()
        #expect(await first.value == expectedResponse("first", servedBy: pair.serverPeer.id))
        #expect(await second.value == expectedResponse("second", servedBy: pair.serverPeer.id))
        #expect(try await TransportTestHarness.eventually {
            let reserved = await pair.server.reservedServingVolumeBytesForTesting
            let waiting = await pair.server.servingVolumeReadWaiterCountForTesting
            return reserved == 0 && waiting == 0
        })
        await pair.stop()
    }

    @Test("a request that waits for a slot longer than requestTimeout is still served")
    func waitingForSlotOutlivesRequestTimeout() async throws {
        let source = GatedVolumeSource(volumes: ["first": smallVolume("first"), "second": smallVolume("second")])
        let pair = try await ConnectedPair.make(
            "serving-wait-outlives-timeout",
            serverSource: source,
            serverConcurrentContentRequests: 1,
            serverRequestTimeout: .seconds(1)
        )
        let first = Task { await pair.client.fetchVolume(rootCID: "first", from: pair.serverPeer) }
        #expect(try await TransportTestHarness.eventually { await source.readsStarted() == 1 })
        let second = Task { await pair.client.fetchVolume(rootCID: "second", from: pair.serverPeer) }
        #expect(try await TransportTestHarness.eventually {
            await pair.server.waitingServingTicketCountForTesting == 1
        })
        try await Task.sleep(for: .milliseconds(2_500))
        #expect(await pair.server.waitingServingTicketCountForTesting == 1)

        await source.open()
        #expect(await second.value == expectedResponse("second", servedBy: pair.serverPeer.id))
        first.cancel()
        await pair.stop()
    }

    @Test("waiting reads are admitted oldest first as capacity frees")
    func waitersAreAdmittedInOrder() async throws {
        let roots = ["a", "b", "c", "d"]
        let source = GatedVolumeSource(volumes: Dictionary(
            uniqueKeysWithValues: roots.map { ($0, smallVolume($0)) }
        ))
        let pair = try await ConnectedPair.make(
            "serving-fifo",
            serverSource: source,
            serverInFlightVolumeBytes: MessageLimits.maxVolumeArchiveBytes
        )
        var fetches: [Task<AttributedVolumeResponse, Never>] = []
        for (index, root) in roots.enumerated() {
            fetches.append(Task { await pair.client.fetchVolume(rootCID: root, from: pair.serverPeer) })
            #expect(try await TransportTestHarness.eventually {
                await pair.server.servingVolumeReadWaiterCountForTesting == index
            })
        }
        await source.open()
        for (root, fetch) in zip(roots, fetches) {
            #expect(await fetch.value == expectedResponse(root, servedBy: pair.serverPeer.id))
        }
        #expect(await source.readsStarted() == roots.count)
        #expect(try await TransportTestHarness.eventually {
            await pair.server.reservedServingVolumeBytesForTesting == 0
        })
        await pair.stop()
    }

    @Test("a waiting read is withdrawn when its requester disconnects")
    func waiterReleasedOnDisconnect() async throws {
        let source = GatedVolumeSource(volumes: ["held": smallVolume("held"), "queued": smallVolume("queued")])
        let pair = try await ConnectedPair.make(
            "serving-waiter-disconnect",
            serverSource: source,
            serverInFlightVolumeBytes: MessageLimits.maxVolumeArchiveBytes
        )
        let held = Task { await pair.client.fetchVolume(rootCID: "held", from: pair.serverPeer) }
        #expect(try await TransportTestHarness.eventually { await source.readsStarted() == 1 })
        let queued = Task { await pair.client.fetchVolume(rootCID: "queued", from: pair.serverPeer) }
        #expect(try await TransportTestHarness.eventually {
            await pair.server.servingVolumeReadWaiterCountForTesting == 1
        })

        await pair.client.stop()
        #expect(try await TransportTestHarness.eventually {
            await pair.server.servingVolumeReadWaiterCountForTesting == 0
        })
        await source.open()
        #expect(try await TransportTestHarness.eventually {
            await pair.server.reservedServingVolumeBytesForTesting == 0
        })
        // The queued read never reached storage.
        #expect(await source.readsStarted() == 1)
        _ = await held.value
        _ = await queued.value
        await pair.server.stop()
    }

    @Test("stopping the server releases waiting reads without hanging")
    func stopReleasesWaiters() async throws {
        let source = GatedVolumeSource(volumes: ["held": smallVolume("held"), "queued": smallVolume("queued")])
        let pair = try await ConnectedPair.make(
            "serving-waiter-stop",
            serverSource: source,
            serverInFlightVolumeBytes: MessageLimits.maxVolumeArchiveBytes
        )
        let held = Task { await pair.client.fetchVolume(rootCID: "held", from: pair.serverPeer) }
        #expect(try await TransportTestHarness.eventually { await source.readsStarted() == 1 })
        let queued = Task { await pair.client.fetchVolume(rootCID: "queued", from: pair.serverPeer) }
        #expect(try await TransportTestHarness.eventually {
            await pair.server.servingVolumeReadWaiterCountForTesting == 1
        })

        await pair.server.stop()
        #expect(try await TransportTestHarness.eventually {
            await pair.server.servingVolumeReadWaiterCountForTesting == 0
        })
        await source.open()
        #expect(try await TransportTestHarness.eventually {
            await pair.server.reservedServingVolumeBytesForTesting == 0
        })
        #expect(await held.value == .empty)
        #expect(await queued.value == .empty)
        await pair.client.stop()
    }

    @Test("a budget smaller than one worst-case Volume still serves, one read at a time")
    func smallBudgetServesAlone() async throws {
        let pair = try await ConnectedPair.make(
            "serving-small-budget",
            serverSource: MapVolumeSource(volumes: ["root": smallVolume("root")]),
            serverInFlightVolumeBytes: 1024 * 1024,
            requestTimeout: .seconds(10)
        )
        #expect(!(await pair.client.fetchVolume(rootCID: "root", from: pair.serverPeer)).entries.isEmpty)
        #expect(await pair.server.servingVolumeReadWaiterCountForTesting == 0)
        #expect(await pair.server.reservedServingVolumeBytesForTesting == 0)
        await pair.stop()
    }

    @Test("a connected peer holding the Volume is asked before any DHT lookup")
    func connectedPeerBeforeDHT() async throws {
        let pair = try await ConnectedPair.make(
            "fetch-connected-first",
            serverSource: MapVolumeSource(volumes: ["root": smallVolume("root")])
        )
        let response = await pair.client.fetchVolume(rootCID: "root")
        #expect(response == expectedResponse("root", servedBy: pair.serverPeer.id))
        #expect(await pair.client.providerQueryCountForTesting == 0)
        await pair.stop()
    }

    @Test("when connected peers miss, the DHT still finds a provider")
    func dhtFallbackAfterConnectedMiss() async throws {
        let providerIdentity = TransportTestHarness.identity("fetch-dht-provider")
        let relayIdentity = TransportTestHarness.identity("fetch-dht-relay")
        let clientIdentity = TransportTestHarness.identity("fetch-dht-client")
        let providerPort = TransportTestHarness.nextPort()
        let relayPort = TransportTestHarness.nextPort()
        // Ivy refuses loopback provider referrals (SSRF hardening), so the
        // provider advertises a public address that the client's dialer maps
        // back to this machine.
        let advertisedHost = "9.9.9.9"
        let provider = Ivy(config: TransportTestHarness.config(
            providerIdentity,
            port: providerPort,
            advertisedHost: advertisedHost
        ))
        let relay = Ivy(config: TransportTestHarness.config(relayIdentity, port: relayPort))
        let client = Ivy(config: TransportTestHarness.config(
            clientIdentity,
            port: TransportTestHarness.nextPort()
        ))
        await client.setDialEndpointRewriteForTesting { endpoint in
            endpoint.host == advertisedHost
                ? PeerEndpoint(publicKey: endpoint.publicKey, host: "127.0.0.1", port: endpoint.port)
                : endpoint
        }
        await provider.setContentSource(MapVolumeSource(volumes: ["root": smallVolume("root")]))
        try await provider.start()
        try await relay.start()
        try await client.start()
        try await provider.connect(to: TransportTestHarness.endpoint(relayIdentity, port: relayPort))
        try await client.connect(to: TransportTestHarness.endpoint(relayIdentity, port: relayPort))
        let providerID = TransportTestHarness.key(providerIdentity).peerID
        #expect(try await TransportTestHarness.eventually {
            await relay.peerConnectionCount == 2
        })
        await provider.announceProvider(
            rootCID: "root",
            expiresAt: UInt64(Date().timeIntervalSince1970) + 600
        )
        #expect(try await TransportTestHarness.eventually {
            await relay.providers(for: "root").contains(providerID)
        })

        let response = await client.fetchVolume(rootCID: "root")
        #expect(response.entries == Dictionary(
            uniqueKeysWithValues: smallVolume("root").map { ($0.cid, $0.data) }
        ))
        #expect(response.servedBy == providerID)
        #expect(await client.providerQueryCountForTesting == 1)
        await client.stop()
        await relay.stop()
        await provider.stop()
    }
}

@Suite("Volume bundles", .serialized)
struct VolumeBundleTests {
    private static let roots = ["root", "member-a", "member-b"]
    private static let volumes = Dictionary(uniqueKeysWithValues: roots.map { ($0, smallVolume($0)) })

    @Test("one request returns the bundle's Volumes in order, leaving out one the server cannot send")
    func bundleRoundTrip() async throws {
        let pair = try await ConnectedPair.make(
            "bundle-round-trip",
            serverSource: MapVolumeSource(
                volumes: Self.volumes,
                bundles: ["root": ["root", "member-a", "absent", "member-b"]]
            )
        )
        let response = await pair.client.fetchVolumeBundle(rootCID: "root", from: [pair.serverPeer])
        #expect(response == AttributedVolumeBundleResponse(
            volumes: Self.roots.map { expectedResponse($0, servedBy: pair.serverPeer.id) },
            ended: true
        ))
        #expect(try await TransportTestHarness.eventually {
            let reserved = await pair.server.reservedServingVolumeBytesForTesting
            let tickets = await pair.server.servingTicketCountForTesting
            return reserved == 0 && tickets == 0
        })
        await pair.stop()
    }

    @Test("a peer whose source bundles nothing says so at once, and still serves the Volume")
    func noBundleIsAnsweredNotTimedOut() async throws {
        // The source holds the Volume and implements no bundle hook.
        let pair = try await ConnectedPair.make(
            "bundle-none",
            serverSource: MapVolumeSource(volumes: Self.volumes),
            requestTimeout: .seconds(30)
        )
        let clock = ContinuousClock()
        let started = clock.now
        let bundle = await pair.client.fetchVolumeBundle(rootCID: "root", from: [pair.serverPeer])
        #expect(bundle == AttributedVolumeBundleResponse(volumes: [], noBundle: true, ended: true))
        // A Volume the peer does not hold is refused, not answered "no bundle".
        let absent = await pair.client.fetchVolume(rootCID: "absent", from: pair.serverPeer)
        #expect(absent == .empty)
        #expect(clock.now - started < .seconds(10))
        let single = await pair.client.fetchVolume(rootCID: "root", from: pair.serverPeer)
        #expect(single == expectedResponse("root", servedBy: pair.serverPeer.id))
        await pair.stop()
    }

    @Test("a requester that disconnects mid-bundle releases the serving slot and its bytes")
    func disconnectReleasesServing() async throws {
        let source = GatedVolumeSource(volumes: Self.volumes, bundles: ["root": Self.roots])
        let pair = try await ConnectedPair.make("bundle-disconnect", serverSource: source)
        let fetch = Task { await pair.client.fetchVolumeBundle(rootCID: "root", from: [pair.serverPeer]) }
        #expect(try await TransportTestHarness.eventually { await source.readsStarted() == 1 })
        #expect(await pair.server.reservedServingVolumeBytesForTesting == MessageLimits.maxVolumeArchiveBytes)

        await pair.client.stop()
        #expect(try await TransportTestHarness.eventually {
            await !pair.server.connectedPeers.contains(pair.clientPeer.id)
        })
        await source.open()
        #expect(try await TransportTestHarness.eventually {
            let reserved = await pair.server.reservedServingVolumeBytesForTesting
            let tickets = await pair.server.servingTicketCountForTesting
            return reserved == 0 && tickets == 0
        })
        // The Volumes after the interrupted one were never read.
        #expect(await source.readsStarted() == 1)
        // Nothing arrived, and the answer did not end.
        #expect(await fetch.value == .empty)
        await pair.server.stop()
    }

    @Test("another peer's waiting request is served between a bundle's Volumes")
    func bundleYieldsItsSlotBetweenVolumes() async throws {
        var volumes = Self.volumes
        volumes["other"] = smallVolume("other")
        let source = GatedVolumeSource(volumes: volumes, bundles: ["root": Self.roots])
        let pair = try await ConnectedPair.make(
            "bundle-yields", serverSource: source, serverConcurrentContentRequests: 1
        )
        let second = Ivy(config: TransportTestHarness.config(
            TransportTestHarness.identity("bundle-yields-second"),
            port: TransportTestHarness.nextPort(),
            requestTimeout: .seconds(5)
        ))
        try await second.start()
        try await second.connect(to: pair.serverEndpoint)
        #expect(try await TransportTestHarness.eventually {
            await second.connectedPeers.contains(pair.serverPeer.id)
        })
        let bundle = Task { await pair.client.fetchVolumeBundle(rootCID: "root", from: [pair.serverPeer]) }
        #expect(try await TransportTestHarness.eventually { await source.readsStarted() == 1 })
        let other = Task { await second.fetchVolume(rootCID: "other") }
        #expect(try await TransportTestHarness.eventually {
            await pair.server.waitingServingTicketCountForTesting == 1
        })
        await source.open()
        #expect(await other.value == expectedResponse("other", servedBy: pair.serverPeer.id))
        await second.stop()
        #expect(await bundle.value.volumes.map(\.rootCID) == Self.roots)
        #expect(await source.reads() == ["root", "other", "member-a", "member-b"])
        await pair.stop()
    }

    @Test("no peer named, no request: a bundle is never asked of a peer on Ivy's initiative")
    func asksOnlyNamedPeers() async throws {
        let source = GatedVolumeSource(volumes: Self.volumes, bundles: ["root": Self.roots])
        let pair = try await ConnectedPair.make("bundle-unnamed", serverSource: source)
        #expect(await pair.client.fetchVolumeBundle(rootCID: "root", from: []) == .empty)
        // A session the peer has since replaced is not asked either.
        let stale = AuthenticatedPeer(
            key: pair.serverPeer.key,
            role: pair.serverPeer.role,
            route: pair.serverPeer.route,
            metadata: pair.serverPeer.metadata,
            sessionID: Data(repeating: 0xEE, count: 32)
        )
        #expect(await pair.client.fetchVolumeBundle(rootCID: "root", from: [stale]) == .empty)
        #expect(await source.readsStarted() == 0)
        await pair.stop()
    }
}

@Suite("Messages a later version added", .serialized)
struct UnknownMessageTests {
    @Test("a message with an unknown tag is ignored and the session stays usable")
    func unknownTagIsIgnored() async throws {
        let pair = try await ConnectedPair.make(
            "unknown-tag",
            serverSource: MapVolumeSource(volumes: ["root": smallVolume("root")])
        )
        // 0xC8 is no message of this version.
        #expect(Message.deserialize(Data([0xC8, 1, 2, 3])) == nil)
        guard case .enqueued = await pair.client.sendRawPayloadForTesting(
            Data([0xC8, 1, 2, 3]), to: pair.serverPeer
        ) else {
            Issue.record("the unknown message was not sent")
            return
        }
        // Records are processed in order: this answer follows the ignored one.
        let response = await pair.client.fetchVolume(rootCID: "root", from: pair.serverPeer)
        #expect(response == expectedResponse("root", servedBy: pair.serverPeer.id))
        #expect(await pair.server.connectedPeers.contains(pair.clientPeer.id))
        await pair.stop()
    }

    @Test("a known message that does not decode still ends the session")
    func malformedKnownTagEndsTheSession() async throws {
        let pair = try await ConnectedPair.make("malformed-known-tag", serverSource: nil)
        // A ping (tag 0) cut short of its nonce.
        guard case .enqueued = await pair.client.sendRawPayloadForTesting(
            Data([0x00, 1, 2, 3]), to: pair.serverPeer
        ) else {
            Issue.record("the malformed message was not sent")
            return
        }
        #expect(try await TransportTestHarness.eventually {
            await !pair.server.connectedPeers.contains(pair.clientPeer.id)
        })
        await pair.stop()
    }
}
