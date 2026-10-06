import Foundation
import Testing
@testable import Ivy
import Tally

/// Records each Volume read; reads wait until released when `gated`.
private actor RecordingSource: IvyContentSource {
    private let volumes: [String: [ContentEntry]]
    private var gated: Bool
    private(set) var reads: [String] = []
    private var active = 0
    private(set) var maximumActive = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(volumes: [String: [ContentEntry]], gated: Bool = false) {
        self.volumes = volumes
        self.gated = gated
    }

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] { [] }

    func volume(rootCID: String, maxDataBytes: Int) async -> [ContentEntry] {
        guard let volume = volumes[rootCID] else { return [] }
        reads.append(rootCID)
        active += 1
        maximumActive = max(maximumActive, active)
        if gated { await withCheckedContinuation { waiters.append($0) } }
        active -= 1
        return volume
    }

    func readCount() -> Int { reads.count }

    /// Stops gating and releases every waiting read.
    func open() {
        gated = false
        releaseAll()
    }

    func releaseAll() {
        let current = waiters
        waiters.removeAll()
        for waiter in current { waiter.resume() }
    }
}

private func volume(_ root: String) -> [ContentEntry] {
    [ContentEntry(cid: root, data: Data("\(root) bytes".utf8))]
}

/// One client connected to several servers.
private struct ClientFixture {
    let client: Ivy
    let servers: [Ivy]
    let serverIDs: [PeerID]

    static func make(
        _ name: String,
        sources: [any IvyContentSource],
        maxOutstandingVolumeRequestsPerPeer: Int = 16
    ) async throws -> ClientFixture {
        let clientIdentity = TransportTestHarness.identity("\(name)-client")
        let client = Ivy(config: TransportTestHarness.config(
            clientIdentity,
            port: TransportTestHarness.nextPort(),
            requestTimeout: .seconds(10),
            maxOutstandingVolumeRequestsPerPeer: maxOutstandingVolumeRequestsPerPeer
        ))
        let recorder = TransportTestRecorder()
        await client.setTestDelegate(recorder)
        try await client.start()
        var servers: [Ivy] = []
        var serverIDs: [PeerID] = []
        for (index, source) in sources.enumerated() {
            let identity = TransportTestHarness.identity("\(name)-server-\(index)")
            let port = TransportTestHarness.nextPort()
            let server = Ivy(config: TransportTestHarness.config(identity, port: port, requestTimeout: .seconds(10)))
            await server.setContentSource(source)
            try await server.start()
            try await client.connect(to: TransportTestHarness.endpoint(identity, port: port))
            servers.append(server)
            serverIDs.append(TransportTestHarness.key(identity).peerID)
        }
        #expect(try await TransportTestHarness.eventually { recorder.authenticatedPeers.count == sources.count })
        return ClientFixture(client: client, servers: servers, serverIDs: serverIDs)
    }

    func stop() async {
        await client.stop()
        for server in servers { await server.stop() }
    }
}

@Suite("Client Volume scheduling", .serialized)
struct ClientVolumeSchedulingTests {
    @Test("a fetch asks one peer at a time, not every connected peer")
    func asksOnePeerAtATime() async throws {
        let first = RecordingSource(volumes: ["root": volume("root")])
        let second = RecordingSource(volumes: ["root": volume("root")])
        let fixture = try await ClientFixture.make("client-one-peer", sources: [first, second])
        let response = await fixture.client.fetchVolume(rootCID: "root")
        #expect(response.entries == ["root": Data("root bytes".utf8)])
        // Exactly one server read it.
        let reads = await first.readCount() + second.readCount()
        #expect(reads == 1)
        await fixture.stop()
    }

    @Test("a miss moves on to the next peer")
    func missRotatesToNextPeer() async throws {
        let missing = RecordingSource(volumes: [:])
        let holder = RecordingSource(volumes: ["root": volume("root")])
        let fixture = try await ClientFixture.make("client-rotate", sources: [missing, holder])
        // Whichever is asked first, the fetch ends at the holder.
        let response = await fixture.client.fetchVolume(rootCID: "root")
        #expect(response.entries == ["root": Data("root bytes".utf8)])
        #expect(response.servedBy == fixture.serverIDs[1])
        #expect(await fixture.client.providerQueryCountForTesting == 0)
        await fixture.stop()
    }

    @Test("requests in flight to one peer stay within the limit, and the rest wait")
    func perPeerLimitHolds() async throws {
        let source = RecordingSource(
            volumes: Dictionary(uniqueKeysWithValues: (0..<5).map { ("root-\($0)", volume("root-\($0)")) }),
            gated: true
        )
        let fixture = try await ClientFixture.make(
            "client-limit", sources: [source], maxOutstandingVolumeRequestsPerPeer: 2
        )
        let peer = fixture.serverIDs[0]
        let fetches = (0..<5).map { index in
            Task { await fixture.client.fetchVolume(rootCID: "root-\(index)") }
        }
        #expect(try await TransportTestHarness.eventually { await source.readCount() == 2 })
        #expect(await fixture.client.outstandingVolumeRequests[peer] == 2)
        // The other three wait on the client rather than reaching the server.
        try await Task.sleep(for: .milliseconds(200))
        #expect(await source.readCount() == 2)
        await source.open()
        for (index, fetch) in fetches.enumerated() {
            #expect(await fetch.value.entries == ["root-\(index)": Data("root-\(index) bytes".utf8)])
        }
        #expect(await source.maximumActive <= 2)
        #expect(await fixture.client.outstandingVolumeRequests[peer] == nil)
        await fixture.stop()
    }

    @Test("requests spread across peers that both hold the content")
    func requestsSpreadAcrossPeers() async throws {
        let roots = (0..<6).map { "root-\($0)" }
        let volumes = Dictionary(uniqueKeysWithValues: roots.map { ($0, volume($0)) })
        let first = RecordingSource(volumes: volumes, gated: true)
        let second = RecordingSource(volumes: volumes, gated: true)
        let fixture = try await ClientFixture.make(
            "client-spread", sources: [first, second], maxOutstandingVolumeRequestsPerPeer: 10
        )
        let fetches = roots.map { root in Task { await fixture.client.fetchVolume(rootCID: root) } }
        // Least loaded first: three in flight to each peer, though either
        // peer's limit would take all six.
        // (Each server reads two at a time; its third waits server-side.)
        let (a, b) = (fixture.serverIDs[0], fixture.serverIDs[1])
        #expect(try await TransportTestHarness.eventually {
            let outstanding = await fixture.client.outstandingVolumeRequests
            return outstanding[a] == 3 && outstanding[b] == 3
        })
        await first.open()
        await second.open()
        for (root, fetch) in zip(roots, fetches) {
            #expect(await fetch.value.entries == [root: Data("\(root) bytes".utf8)])
        }
        await fixture.stop()
    }

    @Test("stopping releases requests waiting for a slot")
    func stopReleasesWaiters() async throws {
        let source = RecordingSource(volumes: ["a": volume("a"), "b": volume("b")], gated: true)
        let fixture = try await ClientFixture.make(
            "client-stop", sources: [source], maxOutstandingVolumeRequestsPerPeer: 1
        )
        let first = Task { await fixture.client.fetchVolume(rootCID: "a") }
        #expect(try await TransportTestHarness.eventually { await source.readCount() == 1 })
        let waiting = Task { await fixture.client.fetchVolume(rootCID: "b") }
        #expect(try await TransportTestHarness.eventually {
            await fixture.client.outstandingVolumeSlotWaiters.count == 1
        })
        await fixture.client.stop()
        #expect(await waiting.value == .empty)
        #expect(await fixture.client.outstandingVolumeSlotWaiters.isEmpty)
        await source.releaseAll()
        _ = await first.value
        for server in fixture.servers { await server.stop() }
    }

    @Test("a peer that let a request time out is tried after peers that answer")
    func timedOutPeerGoesLast() async throws {
        let silentIdentity = TransportTestHarness.identity("client-silent-server")
        let holderIdentity = TransportTestHarness.identity("client-holder-server")
        let clientIdentity = TransportTestHarness.identity("client-silent-client")
        let (silentPort, holderPort) = (TransportTestHarness.nextPort(), TransportTestHarness.nextPort())
        let silent = Ivy(config: TransportTestHarness.config(silentIdentity, port: silentPort))
        let holder = Ivy(config: TransportTestHarness.config(holderIdentity, port: holderPort))
        let client = Ivy(config: TransportTestHarness.config(
            clientIdentity, port: TransportTestHarness.nextPort(), requestTimeout: .seconds(1)
        ))
        await silent.setContentSource(RecordingSource(volumes: ["root": volume("root")]))
        await holder.setContentSource(RecordingSource(volumes: ["root": volume("root")]))
        let silentRecorder = TransportTestRecorder()
        let clientRecorder = TransportTestRecorder()
        await silent.setTestDelegate(silentRecorder)
        await client.setTestDelegate(clientRecorder)
        try await silent.start()
        try await holder.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(silentIdentity, port: silentPort))
        #expect(try await TransportTestHarness.eventually {
            silentRecorder.authenticatedPeers.count == 1 && clientRecorder.authenticatedPeers.count == 1
        })
        // The only peer never replies: the fetch times out and records it.
        let silentID = TransportTestHarness.key(silentIdentity).peerID
        await silent.setEndpointWritabilityForTesting(try #require(silentRecorder.authenticatedPeers.first).id, writable: false)
        #expect(await client.fetchVolume(rootCID: "root").entries.isEmpty)
        #expect(await client.volumeTimeoutStreaks[silentID] == 1)

        // With a peer that answers connected, it is asked first: no timeout.
        // (Without the streak, a random tie would pick the silent peer about
        // half the time; eight fetches make that near certain to show.)
        try await client.connect(to: TransportTestHarness.endpoint(holderIdentity, port: holderPort))
        #expect(try await TransportTestHarness.eventually { clientRecorder.authenticatedPeers.count == 2 })
        for _ in 0..<8 {
            let started = ContinuousClock.now
            let response = await client.fetchVolume(rootCID: "root")
            #expect(response.servedBy == TransportTestHarness.key(holderIdentity).peerID)
            #expect(ContinuousClock.now - started < .milliseconds(800))
        }
        await client.stop()
        await holder.stop()
        await silent.stop()
    }

    @Test("cancelling a fetch waiting for a slot withdraws it and leaks nothing")
    func cancelWhileWaitingForSlot() async throws {
        let source = RecordingSource(volumes: ["a": volume("a"), "b": volume("b")], gated: true)
        let fixture = try await ClientFixture.make(
            "client-cancel-waiting", sources: [source], maxOutstandingVolumeRequestsPerPeer: 1
        )
        let peer = fixture.serverIDs[0]
        let first = Task { await fixture.client.fetchVolume(rootCID: "a") }
        #expect(try await TransportTestHarness.eventually { await source.readCount() == 1 })
        let waiting = Task { await fixture.client.fetchVolume(rootCID: "b") }
        #expect(try await TransportTestHarness.eventually {
            await fixture.client.outstandingVolumeSlotWaiters.count == 1
        })
        waiting.cancel()
        #expect(await waiting.value == .empty)
        #expect(try await TransportTestHarness.eventually {
            await fixture.client.outstandingVolumeSlotWaiters.isEmpty
        })
        #expect(await fixture.client.outstandingVolumeRequests[peer] == 1)
        await source.open()
        #expect(await first.value.entries == ["a": Data("a bytes".utf8)])
        #expect(await fixture.client.outstandingVolumeRequests[peer] == nil)
        #expect(await source.readCount() == 1)
        await fixture.stop()
    }

    @Test("cancelling a fetch mid-request releases its slot")
    func cancelMidRequestReleasesSlot() async throws {
        let source = RecordingSource(volumes: ["a": volume("a")], gated: true)
        let fixture = try await ClientFixture.make("client-cancel-inflight", sources: [source])
        let peer = fixture.serverIDs[0]
        let fetch = Task { await fixture.client.fetchVolume(rootCID: "a") }
        #expect(try await TransportTestHarness.eventually { await source.readCount() == 1 })
        #expect(await fixture.client.outstandingVolumeRequests[peer] == 1)
        fetch.cancel()
        #expect(await fetch.value == .empty)
        #expect(try await TransportTestHarness.eventually {
            await fixture.client.outstandingVolumeRequests[peer] == nil
        })
        await source.open()
        await fixture.stop()
    }

    @Test("the per-peer limit is validated")
    func limitValidated() throws {
        let key = TransportTestHarness.identity("client-limit-config")
        #expect(throws: (any Error).self) {
            try IvyConfig(signingKey: key, listenPort: 0, maxOutstandingVolumeRequestsPerPeer: 0).validate()
        }
        #expect(IvyConfig(signingKey: key, listenPort: 0).maxOutstandingVolumeRequestsPerPeer == 16)
    }
}
