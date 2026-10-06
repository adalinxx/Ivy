import Foundation
import Testing
@testable import Ivy
import Tally

/// Each read waits until released, oldest first; `started` records the
/// order in which reads began, which is the order requests were granted.
private actor OrderedGateSource: IvyContentSource {
    private(set) var started: [String] = []
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var isOpen = false

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] { [] }

    func volume(rootCID: String, maxDataBytes: Int) async -> [ContentEntry] {
        started.append(rootCID)
        if !isOpen { await withCheckedContinuation { waiters.append($0) } }
        return [ContentEntry(cid: rootCID, data: Data("\(rootCID) bytes".utf8))]
    }

    func startedRoots() -> [String] { started }

    func releaseNext() {
        guard !waiters.isEmpty else { return }
        waiters.removeFirst().resume()
    }

    func open() {
        isOpen = true
        let current = waiters
        waiters.removeAll()
        for waiter in current { waiter.resume() }
    }
}

/// One server and several clients, each its own identity.
private struct ServingFixture {
    let server: Ivy
    let clients: [Ivy]
    /// The server as each client sees it.
    let serverPeers: [AuthenticatedPeer]
    /// Each client as the server knows it.
    let clientIDs: [PeerID]

    static func make(
        _ name: String,
        clients count: Int,
        source: any IvyContentSource,
        maxConcurrentContentRequests: Int = 64,
        maxConcurrentContentRequestsPerPeer: Int? = nil,
        maxQueuedContentRequestsPerPeer: Int = 64,
        maxQueuedContentRequests: Int = 1_024,
        maxInFlightVolumeBytes: Int = IvyConfig.defaultMaxInFlightVolumeBytes
    ) async throws -> ServingFixture {
        let serverIdentity = TransportTestHarness.identity("\(name)-server")
        let serverPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(
            serverIdentity,
            port: serverPort,
            requestTimeout: .seconds(10),
            maxInFlightVolumeBytes: maxInFlightVolumeBytes,
            maxConcurrentContentRequests: maxConcurrentContentRequests,
            maxConcurrentContentRequestsPerPeer: maxConcurrentContentRequestsPerPeer,
            maxQueuedContentRequestsPerPeer: maxQueuedContentRequestsPerPeer,
            maxQueuedContentRequests: maxQueuedContentRequests
        ))
        await server.setContentSource(source)
        try await server.start()
        var clients: [Ivy] = []
        var serverPeers: [AuthenticatedPeer] = []
        var clientIDs: [PeerID] = []
        for index in 0..<count {
            let identity = TransportTestHarness.identity("\(name)-client-\(index)")
            let client = Ivy(config: TransportTestHarness.config(
                identity,
                port: TransportTestHarness.nextPort(),
                requestTimeout: .seconds(10)
            ))
            let recorder = TransportTestRecorder()
            await client.setTestDelegate(recorder)
            try await client.start()
            try await client.connect(to: TransportTestHarness.endpoint(serverIdentity, port: serverPort))
            #expect(try await TransportTestHarness.eventually { recorder.authenticatedPeers.count == 1 })
            clients.append(client)
            serverPeers.append(try #require(recorder.authenticatedPeers.first))
            clientIDs.append(TransportTestHarness.key(identity).peerID)
        }
        #expect(try await TransportTestHarness.eventually { await server.peerConnectionCount == count })
        return ServingFixture(server: server, clients: clients, serverPeers: serverPeers, clientIDs: clientIDs)
    }

    func fetch(_ client: Int, _ root: String) -> Task<AttributedVolumeResponse, Never> {
        let (ivy, peer) = (clients[client], serverPeers[client])
        return Task { await ivy.fetchVolume(rootCID: root, from: peer) }
    }

    func waiting(_ count: Int) async throws {
        let server = server
        #expect(try await TransportTestHarness.eventually {
            await server.waitingServingTicketCountForTesting == count
        })
    }

    func stop() async {
        for client in clients { await client.stop() }
        await server.stop()
    }
}

private func served(_ response: AttributedVolumeResponse, _ root: String) -> Bool {
    response.entries == [root: Data("\(root) bytes".utf8)]
}

@Suite("Ranked serving queue", .serialized)
struct ServingQueueTests {
    @Test("without pressure, requests are served at once and never queue")
    func noPressureNoQueue() async throws {
        let source = OrderedGateSource()
        await source.open()
        let fixture = try await ServingFixture.make("queue-no-pressure", clients: 2, source: source)
        let fetches = (0..<4).map { fixture.fetch($0 % 2, "root-\($0)") }
        for (index, fetch) in fetches.enumerated() {
            #expect(served(await fetch.value, "root-\(index)"))
        }
        #expect(await fixture.server.servingTicketCountForTesting == 0)
        await fixture.stop()
    }

    @Test("a peer over its slot limit waits instead of being refused")
    func perPeerOverflowWaits() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-per-peer-waits", clients: 1, source: source,
            maxConcurrentContentRequestsPerPeer: 1
        )
        let first = fixture.fetch(0, "first")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["first"] })
        let second = fixture.fetch(0, "second")
        try await fixture.waiting(1)
        await source.open()
        #expect(served(await first.value, "first"))
        #expect(served(await second.value, "second"))
        #expect(await fixture.server.servingTicketCountForTesting == 0)
        await fixture.stop()
    }

    @Test("under pressure, the peer that served us the most verified content goes first")
    func helpfulPeerFirst() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-priority", clients: 3, source: source,
            maxConcurrentContentRequests: 1
        )
        // Client 2 has served this node verified content; client 1 has not.
        await fixture.server.tally.recordUsefulReceived(peer: fixture.clientIDs[2], bytes: 10_000)
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let stranger = fixture.fetch(1, "stranger")
        try await fixture.waiting(1)
        let helpful = fixture.fetch(2, "helpful")
        try await fixture.waiting(2)

        await source.releaseNext()
        #expect(try await TransportTestHarness.eventually {
            await source.startedRoots() == ["holder", "helpful"]
        })
        await source.releaseNext()
        #expect(try await TransportTestHarness.eventually {
            await source.startedRoots() == ["holder", "helpful", "stranger"]
        })
        await source.open()
        #expect(served(await holder.value, "holder"))
        #expect(served(await helpful.value, "helpful"))
        #expect(served(await stranger.value, "stranger"))
        await fixture.stop()
    }

    @Test("among equally helpful peers, the oldest waiter goes first")
    func equalPriorityIsFIFO() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-fifo", clients: 3, source: source,
            maxConcurrentContentRequests: 1
        )
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let older = fixture.fetch(1, "older")
        try await fixture.waiting(1)
        let newer = fixture.fetch(2, "newer")
        try await fixture.waiting(2)
        await source.releaseNext()
        #expect(try await TransportTestHarness.eventually {
            await source.startedRoots() == ["holder", "older"]
        })
        await source.open()
        _ = await holder.value
        #expect(served(await older.value, "older"))
        #expect(served(await newer.value, "newer"))
        #expect(await source.startedRoots() == ["holder", "older", "newer"])
        await fixture.stop()
    }

    @Test("a free slot serves a newcomer even while another peer waits at its own limit")
    func freeSlotIsNotIdledByIneligibleWaiters() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-no-idle-slots", clients: 2, source: source,
            maxConcurrentContentRequests: 4,
            maxConcurrentContentRequestsPerPeer: 1
        )
        let active = fixture.fetch(0, "a-active")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["a-active"] })
        let queued = fixture.fetch(0, "a-queued")
        try await fixture.waiting(1)
        // Three slots are free; peer 1 must not wait behind peer 0's queue.
        let other = fixture.fetch(1, "b")
        #expect(try await TransportTestHarness.eventually {
            await source.startedRoots() == ["a-active", "b"]
        })
        try await fixture.waiting(1)
        await source.open()
        #expect(served(await active.value, "a-active"))
        #expect(served(await queued.value, "a-queued"))
        #expect(served(await other.value, "b"))
        await fixture.stop()
    }

    @Test("a peer whose queue is full is refused at once")
    func perPeerQueueFullRefuses() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-per-peer-full", clients: 1, source: source,
            maxConcurrentContentRequestsPerPeer: 1,
            maxQueuedContentRequestsPerPeer: 1
        )
        let active = fixture.fetch(0, "active")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["active"] })
        let queued = fixture.fetch(0, "queued")
        try await fixture.waiting(1)
        let started = ContinuousClock.now
        #expect(await fixture.fetch(0, "overflow").value == .empty)
        #expect(ContinuousClock.now - started < .seconds(5))
        await source.open()
        #expect(served(await active.value, "active"))
        #expect(served(await queued.value, "queued"))
        await fixture.stop()
    }

    @Test("a full queue drops its least helpful waiter for a more helpful peer")
    func fullQueueDisplacesLeastHelpful() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-displace", clients: 3, source: source,
            maxConcurrentContentRequests: 1,
            maxQueuedContentRequests: 1
        )
        await fixture.server.tally.recordUsefulReceived(peer: fixture.clientIDs[2], bytes: 10_000)
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let stranger = fixture.fetch(1, "stranger")
        try await fixture.waiting(1)
        let helpful = fixture.fetch(2, "helpful")
        // The stranger is displaced and refused; the helpful peer takes its place.
        #expect(await stranger.value == .empty)
        try await fixture.waiting(1)
        await source.open()
        #expect(served(await holder.value, "holder"))
        #expect(served(await helpful.value, "helpful"))
        #expect(await source.startedRoots() == ["holder", "helpful"])
        await fixture.stop()
    }

    @Test("in a full queue, a peer with nothing waiting still gets a place")
    func fullQueueAdmitsPeerWithNothingWaiting() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-place-for-all", clients: 3, source: source,
            maxConcurrentContentRequests: 1,
            maxQueuedContentRequests: 1
        )
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let first = fixture.fetch(1, "first")
        try await fixture.waiting(1)
        // Equal weights: the single place rotates to the peer that had none.
        let second = fixture.fetch(2, "second")
        #expect(await first.value == .empty)
        try await fixture.waiting(1)
        await source.open()
        _ = await holder.value
        #expect(served(await second.value, "second"))
        await fixture.stop()
    }

    @Test("in a full queue, a peer already waiting is refused unless under its weighted share")
    func fullQueueRefusesPeerAlreadyWaiting() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-refuse-repeat", clients: 3, source: source,
            maxConcurrentContentRequests: 1,
            maxQueuedContentRequests: 2
        )
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let first = fixture.fetch(1, "first")
        try await fixture.waiting(1)
        let second = fixture.fetch(2, "second")
        try await fixture.waiting(2)
        // Peer 2 already waits and holds its equal share: refused, nothing displaced.
        #expect(await fixture.fetch(2, "again").value == .empty)
        try await fixture.waiting(2)
        await source.open()
        _ = await holder.value
        #expect(served(await first.value, "first"))
        #expect(served(await second.value, "second"))
        await fixture.stop()
    }

    @Test("a waiting request is withdrawn when its requester disconnects")
    func waiterWithdrawnOnDisconnect() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-disconnect", clients: 2, source: source,
            maxConcurrentContentRequests: 1
        )
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let leaver = fixture.fetch(1, "leaver")
        try await fixture.waiting(1)
        await fixture.clients[1].stop()
        try await fixture.waiting(0)
        await source.open()
        #expect(served(await holder.value, "holder"))
        _ = await leaver.value
        #expect(await source.startedRoots() == ["holder"])
        #expect(try await TransportTestHarness.eventually {
            await fixture.server.servingTicketCountForTesting == 0
        })
        await fixture.stop()
    }

    @Test("stopping the server refuses every waiting request")
    func stopRefusesWaiters() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-stop", clients: 2, source: source,
            maxConcurrentContentRequests: 1
        )
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let waiter = fixture.fetch(1, "waiter")
        try await fixture.waiting(1)
        await fixture.server.stop()
        #expect(try await TransportTestHarness.eventually {
            await fixture.server.servingTicketCountForTesting == 0
        })
        await source.open()
        #expect(await waiter.value == .empty)
        _ = await holder.value
        for client in fixture.clients { await client.stop() }
    }

    @Test("Volume reads waiting for capacity go first come, first served, whatever the credit")
    func readQueueIsFIFO() async throws {
        let source = OrderedGateSource()
        // Slots to spare; room for exactly one worst-case read at a time.
        let fixture = try await ServingFixture.make(
            "read-fifo", clients: 3, source: source,
            maxInFlightVolumeBytes: MessageLimits.maxVolumeArchiveBytes
        )
        await fixture.server.tally.recordUsefulReceived(peer: fixture.clientIDs[2], bytes: 1_000_000)
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let stranger = fixture.fetch(1, "stranger")
        #expect(try await TransportTestHarness.eventually {
            await fixture.server.servingVolumeReadWaiterCountForTesting == 1
        })
        let helpful = fixture.fetch(2, "helpful")
        #expect(try await TransportTestHarness.eventually {
            await fixture.server.servingVolumeReadWaiterCountForTesting == 2
        })
        await source.open()
        #expect(served(await holder.value, "holder"))
        #expect(served(await stranger.value, "stranger"))
        #expect(served(await helpful.value, "helpful"))
        #expect(await source.startedRoots() == ["holder", "stranger", "helpful"])
        await fixture.stop()
    }

    @Test("under sustained pressure a newcomer with no credit keeps being served, at its weighted share")
    func newcomerSyncsUnderSustainedPressure() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-newcomer-syncs", clients: 3, source: source,
            maxConcurrentContentRequests: 1
        )
        // 1 MiB of credit: weight 1 + log2(1 + 1024) ≈ 11 against the newcomer's 1.
        await fixture.server.tally.recordUsefulReceived(peer: fixture.clientIDs[1], bytes: 1_048_576)
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        var fetches: [Task<AttributedVolumeResponse, Never>] = []
        for index in 0..<30 {
            fetches.append(fixture.fetch(1, "credited-\(index)"))
            try await fixture.waiting(index + 1)
        }
        for index in 0..<3 {
            fetches.append(fixture.fetch(2, "newcomer-\(index)"))
            try await fixture.waiting(31 + index)
        }
        // Grant one slot at a time and record who was served.
        for grant in 1...33 {
            await source.releaseNext()
            #expect(try await TransportTestHarness.eventually { await source.startedRoots().count == grant + 1 })
        }
        await source.open()
        for fetch in fetches { #expect(!(await fetch.value).entries.isEmpty) }
        _ = await holder.value

        let order = Array(await source.startedRoots().dropFirst())
        let newcomerPositions = order.indices.filter { order[$0].hasPrefix("newcomer") }
        #expect(newcomerPositions.count == 3)
        // The newcomer is reached within one stride of the credited peer
        // (about 11 grants) and then about every 12.
        #expect(newcomerPositions.first! <= 14)
        for (earlier, later) in zip(newcomerPositions, newcomerPositions.dropFirst()) {
            #expect((8...14).contains(later - earlier - 1))
        }
        await fixture.stop()
    }

    @Test("credited peers re-requesting one at a time cannot starve a newcomer")
    func sequentialCreditedPeersCannotStarveNewcomer() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-sequential-credited", clients: 3, source: source,
            maxConcurrentContentRequests: 1
        )
        for credited in [0, 1] {
            await fixture.server.tally.recordUsefulReceived(peer: fixture.clientIDs[credited], bytes: 1_048_576)
        }
        // Each credited peer syncs sequentially: the next request only after a reply.
        let loops = [0, 1].map { credited in
            let (ivy, peer) = (fixture.clients[credited], fixture.serverPeers[credited])
            return Task {
                for index in 0..<40 {
                    _ = await ivy.fetchVolume(rootCID: "c\(credited)-\(index)", from: peer)
                }
            }
        }
        #expect(try await TransportTestHarness.eventually { await source.startedRoots().count == 1 })
        try await fixture.waiting(1)
        let newcomer = fixture.fetch(2, "newcomer")
        try await fixture.waiting(2)

        var grants = 0
        while !(await source.startedRoots().contains("newcomer")), grants < 40 {
            let before = await source.startedRoots().count
            await source.releaseNext()
            #expect(try await TransportTestHarness.eventually { await source.startedRoots().count > before })
            grants += 1
        }
        // Two credited peers at weight ~11 each against 1: the newcomer is
        // reached within about two of their strides.
        #expect(await source.startedRoots().contains("newcomer"))
        #expect(grants <= 30)
        await source.open()
        #expect(served(await newcomer.value, "newcomer"))
        for loop in loops { loop.cancel() }
        await fixture.stop()
    }

    @Test("once queued, a newcomer keeps its place as credited peers keep arriving")
    func newcomerKeepsPlaceAgainstLaterArrivals() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-newcomer-keeps-place", clients: 5, source: source,
            maxConcurrentContentRequests: 1,
            maxQueuedContentRequests: 2
        )
        for credited in [2, 3, 4] {
            await fixture.server.tally.recordUsefulReceived(peer: fixture.clientIDs[credited], bytes: 1_048_576)
        }
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let newcomer = fixture.fetch(1, "newcomer")
        try await fixture.waiting(1)
        let first = fixture.fetch(2, "credited-a")
        try await fixture.waiting(2)
        // Each later arrival displaces the newest waiter, never the newcomer.
        let second = fixture.fetch(3, "credited-b")
        #expect(await first.value == .empty)
        let third = fixture.fetch(4, "credited-c")
        #expect(await second.value == .empty)
        try await fixture.waiting(2)
        await source.open()
        _ = await holder.value
        #expect(served(await newcomer.value, "newcomer"))
        #expect(served(await third.value, "credited-c"))
        await fixture.stop()
    }

    @Test("a newcomer gets a place even when a heavily credited peer fills the queue")
    func newcomerGetsPlaceInFullQueue() async throws {
        let source = OrderedGateSource()
        let fixture = try await ServingFixture.make(
            "queue-newcomer-place", clients: 3, source: source,
            maxConcurrentContentRequests: 1,
            maxQueuedContentRequests: 4
        )
        await fixture.server.tally.recordUsefulReceived(peer: fixture.clientIDs[1], bytes: 1_048_576)
        let holder = fixture.fetch(0, "holder")
        #expect(try await TransportTestHarness.eventually { await source.startedRoots() == ["holder"] })
        let credited = (0..<4).map { fixture.fetch(1, "credited-\($0)") }
        try await fixture.waiting(4)
        let newcomer = fixture.fetch(2, "newcomer")
        // The credited peer's newest request makes room.
        #expect(await credited[3].value == .empty)
        try await fixture.waiting(4)
        await source.open()
        #expect(served(await newcomer.value, "newcomer"))
        for fetch in credited.prefix(3) { #expect(!(await fetch.value).entries.isEmpty) }
        _ = await holder.value
        await fixture.stop()
    }

    @Test("serving limits are validated and the per-peer default is derived")
    func configurationValidation() throws {
        let key = TransportTestHarness.identity("queue-config")
        func config(
            concurrent: Int = 64,
            perPeer: Int? = nil,
            queuedPerPeer: Int = 64,
            queued: Int = 1_024
        ) -> IvyConfig {
            IvyConfig(
                signingKey: key,
                listenPort: 0,
                maxConcurrentContentRequests: concurrent,
                maxConcurrentContentRequestsPerPeer: perPeer,
                maxQueuedContentRequestsPerPeer: queuedPerPeer,
                maxQueuedContentRequests: queued
            )
        }
        #expect(config().maxConcurrentContentRequestsPerPeer == 8)
        #expect(config(concurrent: 12).maxConcurrentContentRequestsPerPeer == 3)
        #expect(config(concurrent: 2).maxConcurrentContentRequestsPerPeer == 1)
        #expect(throws: (any Error).self) { try config(concurrent: 4, perPeer: 5).validate() }
        #expect(throws: (any Error).self) { try config(perPeer: 0).validate() }
        #expect(throws: (any Error).self) { try config(queuedPerPeer: -1).validate() }
        #expect(throws: (any Error).self) { try config(queued: -1).validate() }
        try config(concurrent: 4, perPeer: 4, queuedPerPeer: 0, queued: 0).validate()
    }
}
