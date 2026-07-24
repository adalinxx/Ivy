import Foundation
import Testing
@testable import Ivy
import Tally

private extension Ivy {
    func pendingContentState() -> (requestID: UInt64?, candidates: Set<PeerID>) {
        guard let request = pendingContentRequests.first else { return (nil, []) }
        return (request.key, request.value.candidates)
    }

    func servingContentCount() -> Int {
        servingContentRequests.count
    }

    func pendingVolumeState() -> (requestID: UInt64?, candidates: Set<PeerID>) {
        guard let request = pendingVolumeRequests.first else { return (nil, []) }
        return (request.key, Set(request.value.candidateSessions.keys))
    }

    func inFlightVolumeByteCount() -> Int {
        inFlightVolumeBytes
    }

    func volumeReservations() -> (receiving: Int, serving: Int) {
        (reservedVolumeBytes, reservedServingVolumeBytes)
    }

    func awaitSeededVolume(
        requestID: UInt64,
        rootCID: String,
        candidateSessions: [PeerID: Data]
    ) async -> AttributedVolumeResponse {
        await withCheckedContinuation { continuation in
            pendingVolumeRequests[requestID] = PendingVolumeRequest(
                rootCID: rootCID,
                generation: runGeneration,
                maximumArchiveBytes: MessageLimits.maxVolumeArchiveBytes,
                maximumEntries: Int(MessageLimits.maxVolumeEntryCount),
                continuation: continuation,
                candidateSessions: candidateSessions
            )
        }
    }

    func networkFetchWaiterCount(for key: ContentRequestKey) -> Int {
        max(0, (pendingFetches[key]?.continuations.count ?? 0) - 1)
    }
}

private actor BlockingContentSource: IvyContentSource {
    private var starts = 0
    private var active = 0
    private var maximumActive = 0
    private var waiters: [Int: CheckedContinuation<Void, Never>] = [:]

    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry] {
        let index = starts
        starts += 1
        active += 1
        maximumActive = max(maximumActive, active)
        await withCheckedContinuation { waiters[index] = $0 }
        active -= 1
        return []
    }

    func startedCount() -> Int { starts }
    func maxActiveCount() -> Int { maximumActive }

    func release(_ index: Int) {
        waiters.removeValue(forKey: index)?.resume()
    }

    func releaseAll() {
        let current = Array(waiters.values)
        waiters.removeAll()
        for waiter in current { waiter.resume() }
    }
}

private actor BlockingAuthorizationContentSource: IvyContentSource {
    private var authorizationStarts = 0
    private var contentRequests = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func authorizesContentRequest(
        from peer: AuthenticatedPeer,
        rootCID: String,
        cids: [String]
    ) async -> Bool {
        authorizationStarts += 1
        await withCheckedContinuation { waiters.append($0) }
        return true
    }

    func content(
        rootCID: String,
        cids: [String],
        maxDataBytes: Int
    ) -> [ContentEntry] {
        contentRequests += 1
        return []
    }

    func counts() -> (authorizationStarts: Int, contentRequests: Int) {
        (authorizationStarts, contentRequests)
    }

    func releaseAll() {
        let current = waiters
        waiters.removeAll()
        for waiter in current { waiter.resume() }
    }
}

private actor ControlledNetworkFetch {
    private var invocationCount = 0
    private var completions: [Int: AttributedContentResponse] = [:]

    func run() async -> AttributedContentResponse {
        let invocation = invocationCount
        invocationCount += 1
        do {
            try await TestSynchronization.wait(
                for: "network fetch invocation \(invocation) completion"
            ) {
                await self.hasCompletion(invocation)
            }
        } catch TestSynchronizationError.cancelled {
            completions.removeValue(forKey: invocation)
            return .empty
        } catch {
            completions.removeValue(forKey: invocation)
            Issue.record("\(error)")
            return .empty
        }
        return completions.removeValue(forKey: invocation) ?? .empty
    }

    func waitForInvocations(_ count: Int) async throws {
        try await TestSynchronization.wait(for: "\(count) network fetch invocation(s)") {
            await self.hasInvocations(count)
        }
    }

    func complete(_ invocation: Int, with response: AttributedContentResponse) {
        completions[invocation] = response
    }

    func count() -> Int { invocationCount }

    private func hasCompletion(_ invocation: Int) -> Bool { completions[invocation] != nil }
    private func hasInvocations(_ count: Int) -> Bool { invocationCount >= count }
}

private actor TestContentSource: IvyContentSource {
    let entries: [String: Data]
    private var receivedRequests: [(rootCID: String, cids: [String], maxDataBytes: Int)] = []

    init(entries: [String: Data]) {
        self.entries = entries
    }

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] {
        receivedRequests.append((rootCID, cids, maxDataBytes))
        return cids.compactMap { cid in
            entries[cid].map { ContentEntry(cid: cid, data: $0) }
        }
    }

    func requests() -> [(rootCID: String, cids: [String], maxDataBytes: Int)] {
        receivedRequests
    }
}

private actor DenyingContentSource: IvyContentSource {
    private var authorizationChecks = 0
    private var contentRequests = 0

    func authorizesContentRequest(
        from peer: AuthenticatedPeer,
        rootCID: String,
        cids: [String]
    ) -> Bool {
        authorizationChecks += 1
        return false
    }

    func content(
        rootCID: String,
        cids: [String],
        maxDataBytes: Int
    ) -> [ContentEntry] {
        contentRequests += 1
        return []
    }

    func counts() -> (authorizationChecks: Int, contentRequests: Int) {
        (authorizationChecks, contentRequests)
    }
}

private struct RawContentSource: IvyContentSource {
    let entries: [ContentEntry]

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] {
        entries
    }
}

private struct TestVolumeSource: IvyContentSource {
    let entries: [ContentEntry]

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] {
        []
    }

    func volume(rootCID: String, maxDataBytes: Int) -> [ContentEntry] {
        entries
    }
}

private actor BlockingConcurrentVolumeSource: IvyContentSource {
    private var starts = 0
    private var waiters: [Int: CheckedContinuation<Void, Never>] = [:]

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] {
        []
    }

    func volume(rootCID: String, maxDataBytes: Int) async -> [ContentEntry] {
        let index = starts
        starts += 1
        await withCheckedContinuation { waiters[index] = $0 }
        return [ContentEntry(cid: rootCID, data: Data())]
    }

    func startedCount() -> Int { starts }

    func release(_ index: Int) {
        waiters.removeValue(forKey: index)?.resume()
    }

    func releaseAll() {
        let current = Array(waiters.values)
        waiters.removeAll()
        for waiter in current { waiter.resume() }
    }
}

@Suite("Targeted content exchange")
struct ContentExchangeTests {
    private func node(_ key: String) -> Ivy {
        Ivy(config: IvyConfig(
            publicKey: key,
            listenPort: 0,
            requestTimeout: .seconds(1)))
    }

    private func volumeMessage(
        requestID: UInt64,
        rootCID: String,
        entries: [ContentEntry]
    ) -> Message? {
        guard let archive = VolumeArchive.encode(entries: entries, rootCID: rootCID) else {
            return nil
        }
        return .volumeChunk(
            requestID: requestID,
            rootCID: rootCID,
            index: 0,
            count: 1,
            totalEntries: UInt16(archive.entries.count),
            totalBytes: UInt64(archive.data.count),
            payload: archive.data
        )
    }

    @Test("a complete Volume is fetched as one boundary")
    func completeLocalVolume() async {
        let ivy = node("local-volume")
        let source = TestVolumeSource(entries: [
            ContentEntry(cid: "child", data: Data("child".utf8)),
            ContentEntry(cid: "root", data: Data("root".utf8)),
        ])
        await ivy.setContentSource(source)

        #expect(await ivy.fetchVolume(rootCID: "root") == AttributedVolumeResponse(
            rootCID: "root",
            entries: [
                "root": Data("root".utf8),
                "child": Data("child".utf8),
            ],
            servedBy: nil
        ))
    }

    @Test("an advertised Volume is fenced to the exact authenticated session")
    func exactVolumeSessionIsFenced() async throws {
        let ivy = node("exact-volume-session-requester")
        let identity = deterministicTestPeerKey("exact-volume-session-peer")
        let endpoint = PeerEndpoint(
            publicKey: identity,
            host: "127.0.0.1",
            port: 4101
        )
        let key = try PeerKey(identity)
        let oldSessionID = Data(repeating: 1, count: 32)
        let currentSessionID = Data(repeating: 2, count: 32)
        let currentPeer = AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata(),
            sessionID: currentSessionID
        )
        try await ivy.seedConnectedEndpointForTesting(endpoint, marker: 2)
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }

        let fetch = Task { await ivy.fetchVolume(rootCID: "root", from: currentPeer) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let requestID = try #require(await ivy.pendingVolumeState().requestID)
        let entries = [
            ContentEntry(cid: "root", data: Data("root".utf8)),
            ContentEntry(cid: "child", data: Data("child".utf8)),
        ]

        guard case let .volumeChunk(_, root, index, count, totalEntries, totalBytes, payload) =
                try #require(volumeMessage(
                    requestID: requestID,
                    rootCID: "root",
                    entries: entries
                )) else {
            Issue.record("Expected Volume chunk")
            return
        }
        await ivy.handleVolumeChunk(
            requestID: requestID,
            rootCID: root,
            index: index,
            count: count,
            totalEntries: totalEntries,
            totalBytes: totalBytes,
            payload: payload,
            from: key.peerID,
            sessionID: oldSessionID
        )
        #expect(await ivy.pendingVolumeState().requestID == requestID)

        await ivy.handleVolumeChunk(
            requestID: requestID,
            rootCID: root,
            index: index,
            count: count,
            totalEntries: totalEntries,
            totalBytes: totalBytes,
            payload: payload,
            from: key.peerID,
            sessionID: currentSessionID
        )
        #expect(await fetch.value == AttributedVolumeResponse(
            rootCID: "root",
            entries: [
                "root": Data("root".utf8),
                "child": Data("child".utf8),
            ],
            servedBy: key.peerID
        ))
    }

    @Test("caller Volume limits reject advertised excess before allocation")
    func callerVolumeLimitsRejectBeforeAllocation() async throws {
        let ivy = node("bounded-volume-requester")
        let identity = deterministicTestPeerKey("bounded-volume-peer")
        let endpoint = PeerEndpoint(
            publicKey: identity,
            host: "127.0.0.1",
            port: 4102
        )
        let key = try PeerKey(identity)
        let sessionID = Data(repeating: 3, count: 32)
        let peer = AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata(),
            sessionID: sessionID
        )
        try await ivy.seedConnectedEndpointForTesting(endpoint, marker: 3)
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }

        let memberLimited = Task {
            await ivy.fetchVolume(
                rootCID: "root",
                from: peer,
                maximumArchiveBytes: 1_024,
                maximumEntries: 1
            )
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let memberRequestID = try #require(
            await ivy.pendingVolumeState().requestID
        )
        guard case let .volumeChunk(_, root, index, count, totalEntries, totalBytes, payload) =
                try #require(volumeMessage(
                    requestID: memberRequestID,
                    rootCID: "root",
                    entries: [
                        ContentEntry(cid: "root", data: Data("root".utf8)),
                        ContentEntry(cid: "padding", data: Data("padding".utf8)),
                    ]
                )) else {
            Issue.record("Expected Volume chunk")
            return
        }
        await ivy.handleVolumeChunk(
            requestID: memberRequestID,
            rootCID: root,
            index: index,
            count: count,
            totalEntries: totalEntries,
            totalBytes: totalBytes,
            payload: payload,
            from: key.peerID,
            sessionID: sessionID
        )
        #expect(await memberLimited.value.failure == .callerBoundaryExceeded)
        #expect(await ivy.volumeReservations().receiving == 0)
        #expect(await ivy.inFlightVolumeByteCount() == 0)
        #expect(await ivy.tally.peerCount == 0)

        let entry = ContentEntry(
            cid: "root",
            data: Data(repeating: 0xaa, count: 128)
        )
        let archive = try #require(VolumeArchive.encode(
            entries: [entry],
            rootCID: "root"
        ))
        let byteLimited = Task {
            await ivy.fetchVolume(
                rootCID: "root",
                from: peer,
                maximumArchiveBytes: archive.data.count - 1,
                maximumEntries: 1
            )
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let byteRequestID = try #require(
            await ivy.pendingVolumeState().requestID
        )
        await ivy.handleVolumeChunk(
            requestID: byteRequestID,
            rootCID: "root",
            index: 0,
            count: 1,
            totalEntries: 1,
            totalBytes: UInt64(archive.data.count),
            payload: archive.data,
            from: key.peerID,
            sessionID: sessionID
        )
        #expect(await byteLimited.value.failure == .callerBoundaryExceeded)
        #expect(await ivy.volumeReservations().receiving == 0)
        #expect(await ivy.inFlightVolumeByteCount() == 0)
        #expect(await ivy.tally.peerCount == 0)

        let exactBound = Task {
            await ivy.fetchVolume(
                rootCID: "root",
                from: peer,
                maximumArchiveBytes: archive.data.count,
                maximumEntries: 1
            )
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let exactRequestID = try #require(
            await ivy.pendingVolumeState().requestID
        )
        await ivy.handleVolumeChunk(
            requestID: exactRequestID,
            rootCID: "root",
            index: 0,
            count: 1,
            totalEntries: 1,
            totalBytes: UInt64(archive.data.count),
            payload: archive.data,
            from: key.peerID,
            sessionID: sessionID
        )
        #expect(await exactBound.value == AttributedVolumeResponse(
            rootCID: "root",
            entries: ["root": entry.data],
            servedBy: key.peerID
        ))

        let inconsistent = Task {
            await ivy.fetchVolume(
                rootCID: "root",
                from: peer,
                maximumArchiveBytes: archive.data.count,
                maximumEntries: 1
            )
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let inconsistentRequestID = try #require(
            await ivy.pendingVolumeState().requestID
        )
        let split = archive.data.count / 2
        await ivy.handleVolumeChunk(
            requestID: inconsistentRequestID,
            rootCID: "root",
            index: 0,
            count: 2,
            totalEntries: 1,
            totalBytes: UInt64(archive.data.count),
            payload: Data(archive.data[..<split]),
            from: key.peerID,
            sessionID: sessionID
        )
        await ivy.handleVolumeChunk(
            requestID: inconsistentRequestID,
            rootCID: "root",
            index: 1,
            count: 2,
            totalEntries: 1,
            totalBytes: UInt64(archive.data.count + 1),
            payload: Data(archive.data[split...]),
            from: key.peerID,
            sessionID: sessionID
        )
        #expect(await inconsistent.value == .empty)
        #expect(await ivy.volumeReservations().receiving == 0)
        #expect(await ivy.inFlightVolumeByteCount() == 0)
        #expect(await ivy.tally.peerCount == 1)
    }

    @Test("Volume archive accepts the hard byte cap and rejects one byte over")
    func volumeArchiveByteCap() {
        let rootCID = "root"
        let archiveOverhead = 2 + 2 + rootCID.utf8.count + 4
        let exact = ContentEntry(
            cid: rootCID,
            data: Data(
                repeating: 0xaa,
                count: MessageLimits.maxVolumeArchiveBytes - archiveOverhead
            )
        )
        let archive = VolumeArchive.encode(entries: [exact], rootCID: rootCID)
        #expect(archive?.data.count == MessageLimits.maxVolumeArchiveBytes)

        let oversized = ContentEntry(cid: rootCID, data: exact.data + Data([0xbb]))
        #expect(VolumeArchive.encode(entries: [oversized], rootCID: rootCID) == nil)
    }

    @Test("concurrent Volume sources share one aggregate materialization cap")
    func servingVolumeReservationCap() async throws {
        let ivy = node("volume-serving-reservations")
        let source = BlockingConcurrentVolumeSource()
        await ivy.setContentSource(source)
        let peers = try (0..<3).map {
            try PeerKey(deterministicTestPeerKey("volume-serving-peer-\($0)")).peerID
        }
        for (offset, peer) in peers.enumerated() {
            await ivy.scheduleVolumeRequest(
                requestID: UInt64(offset + 1),
                rootCID: "root-\(offset)",
                from: peer
            )
        }
        #expect(try await TransportTestHarness.eventually {
            await source.startedCount() == 2
        })
        #expect(await source.startedCount() == 2)
        #expect(await ivy.volumeReservations().serving
            == MessageLimits.maxInFlightVolumeBytes)

        await source.releaseAll()
        #expect(try await TransportTestHarness.eventually {
            await ivy.volumeReservations().serving == 0
        })
    }

    @Test("Volume chunks reject gaps and duplicates without leaking bytes")
    func volumeChunkSequenceIsStrict() async throws {
        let ivy = node("volume-sequence-requester")
        let identity = deterministicTestPeerKey("volume-sequence-peer")
        let endpoint = PeerEndpoint(publicKey: identity, host: "127.0.0.1", port: 4103)
        let key = try PeerKey(identity)
        let sessionID = Data(repeating: 3, count: 32)
        let peer = AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata(),
            sessionID: sessionID
        )
        try await ivy.seedConnectedEndpointForTesting(endpoint, marker: 3)
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }
        let archive = try #require(VolumeArchive.encode(entries: [
            ContentEntry(cid: "root", data: Data(repeating: 0xaa, count: 128)),
        ], rootCID: "root"))
        let split = archive.data.count / 2

        let outOfOrder = Task { await ivy.fetchVolume(rootCID: "root", from: peer) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let outOfOrderID = try #require(await ivy.pendingVolumeState().requestID)
        await ivy.handleVolumeChunk(
            requestID: outOfOrderID,
            rootCID: "root",
            index: 1,
            count: 2,
            totalEntries: 1,
            totalBytes: UInt64(archive.data.count),
            payload: Data(archive.data[split...]),
            from: key.peerID,
            sessionID: sessionID
        )
        #expect(await outOfOrder.value == .empty)
        #expect(await ivy.inFlightVolumeByteCount() == 0)

        let duplicate = Task { await ivy.fetchVolume(rootCID: "root", from: peer) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let duplicateID = try #require(await ivy.pendingVolumeState().requestID)
        let first = Data(archive.data[..<split])
        await ivy.handleVolumeChunk(
            requestID: duplicateID,
            rootCID: "root",
            index: 0,
            count: 2,
            totalEntries: 1,
            totalBytes: UInt64(archive.data.count),
            payload: first,
            from: key.peerID,
            sessionID: sessionID
        )
        #expect(await ivy.inFlightVolumeByteCount() == first.count)
        #expect(await ivy.volumeReservations().receiving == archive.data.count)
        await ivy.handleVolumeChunk(
            requestID: duplicateID,
            rootCID: "root",
            index: 0,
            count: 2,
            totalEntries: 1,
            totalBytes: UInt64(archive.data.count),
            payload: first,
            from: key.peerID,
            sessionID: sessionID
        )
        #expect(await duplicate.value == .empty)
        #expect(await ivy.inFlightVolumeByteCount() == 0)
        #expect(await ivy.volumeReservations().receiving == 0)
    }

    @Test("cancelling a partial Volume releases its assembly immediately")
    func partialVolumeCancellation() async throws {
        let ivy = node("volume-cancel-requester")
        let identity = deterministicTestPeerKey("volume-cancel-peer")
        let endpoint = PeerEndpoint(publicKey: identity, host: "127.0.0.1", port: 4104)
        let key = try PeerKey(identity)
        let sessionID = Data(repeating: 4, count: 32)
        let peer = AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata(),
            sessionID: sessionID
        )
        try await ivy.seedConnectedEndpointForTesting(endpoint, marker: 4)
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }
        let archive = try #require(VolumeArchive.encode(entries: [
            ContentEntry(cid: "root", data: Data(repeating: 0xaa, count: 128)),
        ], rootCID: "root"))
        let split = archive.data.count / 2

        let fetch = Task { await ivy.fetchVolume(rootCID: "root", from: peer) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let requestID = try #require(await ivy.pendingVolumeState().requestID)
        await ivy.handleVolumeChunk(
            requestID: requestID,
            rootCID: "root",
            index: 0,
            count: 2,
            totalEntries: 1,
            totalBytes: UInt64(archive.data.count),
            payload: Data(archive.data[..<split]),
            from: key.peerID,
            sessionID: sessionID
        )
        #expect(await ivy.inFlightVolumeByteCount() == split)
        #expect(await ivy.volumeReservations().receiving == archive.data.count)
        fetch.cancel()
        #expect(try await TransportTestHarness.eventually {
            let pending = await ivy.pendingVolumeState().requestID
            let bytes = await ivy.inFlightVolumeByteCount()
            let reserved = await ivy.volumeReservations().receiving
            return pending == nil && bytes == 0 && reserved == 0
        })
        #expect(await fetch.value == .empty)
    }

    @Test("cancelling before Volume request insertion leaves no pending request")
    func volumeCancellationBeforeInsertion() async throws {
        let ivy = node("volume-pre-insertion-cancel")
        let identity = deterministicTestPeerKey("volume-pre-insertion-peer")
        let endpoint = PeerEndpoint(
            publicKey: identity,
            host: "127.0.0.1",
            port: 4106
        )
        let key = try PeerKey(identity)
        let peer = AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata(),
            sessionID: Data(repeating: 6, count: 32)
        )
        try await ivy.seedConnectedEndpointForTesting(endpoint, marker: 6)
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }

        for _ in 0..<32 {
            let fetch = Task {
                await ivy.fetchVolume(rootCID: "root", from: peer)
            }
            fetch.cancel()
            #expect(await fetch.value == .empty)
        }
        #expect(await ivy.pendingVolumeState().requestID == nil)
    }

    @Test("partial Volume timeout and stop release reservations")
    func partialVolumeTimeoutAndStop() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "volume-timeout-requester",
            listenPort: 0,
            requestTimeout: .seconds(1)
        ))
        let identity = deterministicTestPeerKey("volume-timeout-peer")
        let endpoint = PeerEndpoint(publicKey: identity, host: "127.0.0.1", port: 4105)
        let key = try PeerKey(identity)
        let sessionID = Data(repeating: 5, count: 32)
        let peer = AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata(),
            sessionID: sessionID
        )
        try await ivy.seedConnectedEndpointForTesting(endpoint, marker: 5)
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }
        let archive = try #require(VolumeArchive.encode(entries: [
            ContentEntry(cid: "root", data: Data(repeating: 0xaa, count: 128)),
        ], rootCID: "root"))
        let split = archive.data.count / 2

        func beginPartialFetch() async throws -> (
            Task<AttributedVolumeResponse, Never>,
            UInt64
        ) {
            let fetch = Task { await ivy.fetchVolume(rootCID: "root", from: peer) }
            #expect(try await TransportTestHarness.eventually {
                await ivy.pendingVolumeState().requestID != nil
            })
            let requestID = try #require(await ivy.pendingVolumeState().requestID)
            await ivy.handleVolumeChunk(
                requestID: requestID,
                rootCID: "root",
                index: 0,
                count: 2,
                totalEntries: 1,
                totalBytes: UInt64(archive.data.count),
                payload: Data(archive.data[..<split]),
                from: key.peerID,
                sessionID: sessionID
            )
            return (fetch, requestID)
        }

        let (timedOut, _) = try await beginPartialFetch()
        #expect(await timedOut.value == .empty)
        #expect(await ivy.inFlightVolumeByteCount() == 0)
        #expect(await ivy.volumeReservations().receiving == 0)

        let (stopped, requestID) = try await beginPartialFetch()
        await ivy.stop()
        #expect(await stopped.value == .empty)
        #expect(await ivy.inFlightVolumeByteCount() == 0)
        #expect(await ivy.volumeReservations().receiving == 0)
        await ivy.handleVolumeChunk(
            requestID: requestID,
            rootCID: "root",
            index: 1,
            count: 2,
            totalEntries: 1,
            totalBytes: UInt64(archive.data.count),
            payload: Data(archive.data[split...]),
            from: key.peerID,
            sessionID: sessionID
        )
        #expect(await ivy.inFlightVolumeByteCount() == 0)
    }

    @Test("competing providers assemble independently and resolve atomically")
    func competingVolumeProvidersAreIsolated() async throws {
        let ivy = node("volume-provider-isolation")
        let firstKey = try PeerKey(deterministicTestPeerKey("volume-provider-first"))
        let secondKey = try PeerKey(deterministicTestPeerKey("volume-provider-second"))
        let firstSession = Data(repeating: 1, count: 32)
        let secondSession = Data(repeating: 2, count: 32)
        let firstArchive = try #require(VolumeArchive.encode(entries: [
            ContentEntry(cid: "root", data: Data("first".utf8)),
        ], rootCID: "root"))
        let secondArchive = try #require(VolumeArchive.encode(entries: [
            ContentEntry(cid: "root", data: Data("second".utf8)),
        ], rootCID: "root"))
        let firstSplit = firstArchive.data.count / 2
        let requestID: UInt64 = 99
        let fetch = Task {
            await ivy.awaitSeededVolume(
                requestID: requestID,
                rootCID: "root",
                candidateSessions: [
                    firstKey.peerID: firstSession,
                    secondKey.peerID: secondSession,
                ]
            )
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID == requestID
        })
        await ivy.handleVolumeChunk(
            requestID: requestID,
            rootCID: "root",
            index: 0,
            count: 2,
            totalEntries: 1,
            totalBytes: UInt64(firstArchive.data.count),
            payload: Data(firstArchive.data[..<firstSplit]),
            from: firstKey.peerID,
            sessionID: firstSession
        )
        await ivy.handleVolumeChunk(
            requestID: requestID,
            rootCID: "root",
            index: 0,
            count: 1,
            totalEntries: 1,
            totalBytes: UInt64(secondArchive.data.count),
            payload: secondArchive.data,
            from: secondKey.peerID,
            sessionID: secondSession
        )
        #expect(await fetch.value == AttributedVolumeResponse(
            rootCID: "root",
            entries: ["root": Data("second".utf8)],
            servedBy: secondKey.peerID
        ))
        #expect(await ivy.inFlightVolumeByteCount() == 0)
        #expect(await ivy.volumeReservations().receiving == 0)
    }

    @Test("promised Volume sizes share one aggregate receive reservation")
    func receivingVolumeReservationCap() async throws {
        let ivy = node("volume-receive-reservations")
        let keys = try (0..<3).map {
            try PeerKey(deterministicTestPeerKey("volume-receive-peer-\($0)"))
        }
        let sessions = Dictionary(uniqueKeysWithValues: keys.enumerated().map {
            ($0.element.peerID, Data(repeating: UInt8($0.offset + 1), count: 32))
        })
        let requestID: UInt64 = 100
        let fetch = Task {
            await ivy.awaitSeededVolume(
                requestID: requestID,
                rootCID: "root",
                candidateSessions: sessions
            )
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID == requestID
        })
        for key in keys {
            await ivy.handleVolumeChunk(
                requestID: requestID,
                rootCID: "root",
                index: 0,
                count: 2,
                totalEntries: 1,
                totalBytes: UInt64(MessageLimits.maxVolumeArchiveBytes),
                payload: Data([0]),
                from: key.peerID,
                sessionID: sessions[key.peerID]
            )
        }
        #expect(await ivy.volumeReservations().receiving
            == MessageLimits.maxInFlightVolumeBytes)
        #expect(await ivy.inFlightVolumeByteCount() == 2)
        #expect(await ivy.pendingVolumeState().candidates.count == 2)
        let tally = await ivy.tally
        #expect(tally.peerCount == 0)

        for key in keys {
            await ivy.markVolumeCandidateDone(requestID: requestID, peer: key.peerID)
        }
        #expect(await fetch.value.failure == .localCapacityUnavailable)
        #expect(await ivy.volumeReservations().receiving == 0)
        #expect(await ivy.inFlightVolumeByteCount() == 0)
    }

    @Test("solicited content replies survive admission exhaustion on the exact session")
    func solicitedRepliesBypassAdmissionOnExactSession() async throws {
        let tally = Tally(config: TallyConfig(
            perPeerRequestCapacity: 1,
            perPeerRequestRefillPerSecond: 0
        ))
        let ivy = Ivy(
            config: IvyConfig(
                publicKey: "solicited-reply-requester",
                listenPort: 0,
                requestTimeout: .seconds(1)
            ),
            tally: tally
        )
        let identity = deterministicTestPeerKey("solicited-reply-peer")
        let endpoint = PeerEndpoint(publicKey: identity, host: "127.0.0.1", port: 4102)
        let key = try PeerKey(identity)
        let sessionID = Data(repeating: 2, count: 32)
        let peer = AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata(),
            sessionID: sessionID
        )
        try await ivy.seedConnectedEndpointForTesting(endpoint, marker: 2)
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }

        let entries = [ContentEntry(cid: "root", data: Data("root".utf8))]
        let volumeFetch = Task { await ivy.fetchVolume(rootCID: "root", from: peer) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let volumeRequestID = try #require(await ivy.pendingVolumeState().requestID)

        #expect(tally.shouldAllow(peer: key.peerID))
        #expect(!tally.shouldAllow(peer: key.peerID))
        let volumeResponse = try #require(volumeMessage(
            requestID: volumeRequestID,
            rootCID: "root",
            entries: entries
        ))
        await ivy.handleMessage(
            volumeResponse,
            from: key.peerID
        )
        #expect(await ivy.pendingVolumeState().requestID == volumeRequestID)
        let deniedAfterWrongSession = tally.metrics.denied

        await ivy.handleCurrentMessageForTesting(
            volumeResponse,
            from: key.peerID
        )
        #expect(await volumeFetch.value == AttributedVolumeResponse(
            rootCID: "root",
            entries: ["root": Data("root".utf8)],
            servedBy: key.peerID
        ))
        #expect(tally.metrics.denied == deniedAfterWrongSession)

        await ivy.handleCurrentMessageForTesting(
            try #require(volumeMessage(
                requestID: .max,
                rootCID: "root",
                entries: entries
            )),
            from: key.peerID
        )
        #expect(tally.metrics.denied == deniedAfterWrongSession + 1)

        let unavailableFetch = Task { await ivy.fetchVolume(rootCID: "missing", from: peer) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let unavailableRequestID = try #require(await ivy.pendingVolumeState().requestID)
        await ivy.handleCurrentMessageForTesting(
            .contentUnavailable(requestID: unavailableRequestID),
            from: key.peerID
        )
        #expect(await unavailableFetch.value == .empty)

        let contentFetch = Task { await ivy.fetchContent(rootCID: "root", from: peer) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingContentState().requestID != nil
        })
        let contentRequestID = try #require(await ivy.pendingContentState().requestID)
        await ivy.handleCurrentMessageForTesting(
            .contentResponse(requestID: contentRequestID, entries: entries),
            from: key.peerID
        )
        #expect(await contentFetch.value == AttributedContentResponse(
            entries: ["root": Data("root".utf8)],
            servedBy: key.peerID
        ))

        let malformedFetch = Task { await ivy.fetchVolume(rootCID: "malformed", from: peer) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let malformedRequestID = try #require(await ivy.pendingVolumeState().requestID)
        await ivy.handleCurrentMessageForTesting(
            .volumeChunk(
                requestID: malformedRequestID,
                rootCID: "wrong-root",
                index: 0,
                count: 1,
                totalEntries: 1,
                totalBytes: 1,
                payload: Data([0])
            ),
            from: key.peerID
        )
        #expect(await malformedFetch.value == .empty)

        let oversizedFetch = Task { await ivy.fetchVolume(rootCID: "oversized", from: peer) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingVolumeState().requestID != nil
        })
        let oversizedRequestID = try #require(await ivy.pendingVolumeState().requestID)
        await ivy.handleCurrentMessageForTesting(
            .volumeChunk(
                requestID: oversizedRequestID,
                rootCID: "oversized",
                index: 0,
                count: 1,
                totalEntries: 1,
                totalBytes: UInt64(MessageLimits.maxVolumeArchiveBytes + 1),
                payload: Data([0])
            ),
            from: key.peerID
        )
        #expect(await oversizedFetch.value == .empty)
        await ivy.stop()
    }

    @Test("public network fetch leaders stop at the pending-request cap")
    func publicNetworkFetchCap() async throws {
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            publicKey: "content-network-cap",
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxPendingRequests: 2,
            externalAddress: ("127.0.0.1", port)))
        let controlled = ControlledNetworkFetch()
        await ivy.setNetworkFetchHookForTesting { _, _, _ in await controlled.run() }

        try await ivy.start()
        let first = BoundedTestTask { await ivy.fetchContent(rootCID: "root-a") }
        let second = BoundedTestTask { await ivy.fetchContent(rootCID: "root-b") }
        try await controlled.waitForInvocations(2)

        let rejected = BoundedTestTask { await ivy.fetchContent(rootCID: "root-c") }
        #expect(try await rejected.value(waitingFor: "capped network fetch") == .empty)
        #expect(await controlled.count() == 2)

        await controlled.complete(0, with: .empty)
        await controlled.complete(1, with: .empty)
        #expect(try await first.value(waitingFor: "first capped fetch") == .empty)
        #expect(try await second.value(waitingFor: "second capped fetch") == .empty)
        await ivy.stop()
    }

    @Test("cancelling coalesced waiters releases only their owned work")
    func coalescedFetchCancellation() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "content-cancellation",
            listenPort: 0,
            requestTimeout: .seconds(5),
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxPendingRequests: 1))
        let controlled = ControlledNetworkFetch()
        await ivy.setNetworkFetchHookForTesting { _, _, _ in
            await controlled.run()
        }
        try await ivy.start()

        let leader = BoundedTestTask { await ivy.fetchContent(rootCID: "root") }
        try await controlled.waitForInvocations(1)
        let follower = BoundedTestTask { await ivy.fetchContent(rootCID: "root") }
        let key = ContentRequestKey(rootCID: "root", cids: [])
        try await TestSynchronization.wait(for: "coalesced cancellation follower") {
            await ivy.networkFetchWaiterCount(for: key) == 1
        }

        follower.cancel()
        #expect(try await follower.value(waitingFor: "cancelled follower") == .empty)
        #expect(await ivy.networkFetchWaiterCount(for: key) == 0)
        #expect(await ivy.activeFetchCountForTesting == 1)

        leader.cancel()
        #expect(try await leader.value(waitingFor: "cancelled leader") == .empty)
        try await TestSynchronization.wait(for: "cancelled leader slot release") {
            await ivy.activeFetchCountForTesting == 0
        }

        let replacement = BoundedTestTask {
            await ivy.fetchContent(rootCID: "replacement")
        }
        try await controlled.waitForInvocations(2)
        await controlled.complete(1, with: .empty)
        #expect(try await replacement.value(waitingFor: "replacement fetch") == .empty)
        await ivy.stop()
    }

    @Test("cancelling a wire fetch removes its pending request immediately")
    func wireFetchCancellation() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "wire-content-cancellation",
            listenPort: 0,
            requestTimeout: .seconds(5),
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxPendingRequests: 1))
        let peer = PeerID(publicKey: deterministicTestPeerKey("silent-content-peer"))
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }

        let request = BoundedTestTask {
            await ivy.fetchContent(
                ContentRequestKey(rootCID: "root", cids: []),
                from: [peer]
            )
        }
        try await TestSynchronization.wait(for: "pending wire content request") {
            await ivy.pendingContentState().requestID != nil
        }
        request.cancel()
        #expect(try await request.value(waitingFor: "cancelled wire fetch") == .empty)
        #expect(await ivy.pendingContentState().requestID == nil)

        let replacement = BoundedTestTask {
            await ivy.fetchContent(
                ContentRequestKey(rootCID: "replacement", cids: []),
                from: [peer]
            )
        }
        try await TestSynchronization.wait(for: "replacement wire content request") {
            await ivy.pendingContentState().requestID != nil
        }
        await ivy.cleanupAllPending()
        #expect(try await replacement.value(waitingFor: "replacement wire cleanup") == .empty)
    }

    @Test("remote content authorization runs before storage")
    func contentAuthorizationPrecedesStorage() async {
        let ivy = node("content-authorization")
        let source = DenyingContentSource()
        await ivy.setContentSource(source)

        await ivy.handleContentRequest(
            requestID: 1,
            rootCID: "root",
            cids: [],
            from: PeerID(publicKey: deterministicTestPeerKey("unauthorized-content-peer"))
        )

        let counts = await source.counts()
        #expect(counts.authorizationChecks == 1)
        #expect(counts.contentRequests == 0)
    }

    @Test("authorization and storage use one captured source")
    func authorizationCannotSwapStorageSource() async throws {
        let ivy = node("content-source-swap")
        let original = BlockingAuthorizationContentSource()
        let replacement = TestContentSource(entries: [:])
        await ivy.setContentSource(original)
        let peer = PeerID(publicKey: deterministicTestPeerKey("content-source-swap-peer"))

        let request = Task {
            await ivy.handleContentRequest(
                requestID: 1,
                rootCID: "root",
                cids: [],
                from: peer
            )
        }
        try await TestSynchronization.wait(for: "blocked content authorization") {
            await original.counts().authorizationStarts == 1
        }
        await ivy.setContentSource(replacement)
        await original.releaseAll()
        await request.value

        #expect(await original.counts().contentRequests == 1)
        #expect(await replacement.requests().isEmpty)
    }

    @Test("authorization work obeys the inbound content cap")
    func authorizationObeysContentCap() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "content-authorization-cap",
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConcurrentContentRequests: 1
        ))
        let source = BlockingAuthorizationContentSource()
        await ivy.setContentSource(source)
        let peer = PeerID(publicKey: deterministicTestPeerKey("content-authorization-cap-peer"))

        let first = Task {
            await ivy.handleContentRequest(
                requestID: 1,
                rootCID: "one",
                cids: [],
                from: peer
            )
        }
        try await TestSynchronization.wait(for: "first content authorization") {
            await source.counts().authorizationStarts == 1
        }
        await ivy.handleContentRequest(
            requestID: 2,
            rootCID: "two",
            cids: [],
            from: peer
        )
        #expect(await source.counts().authorizationStarts == 1)
        await source.releaseAll()
        await first.value
    }

    @Test("private content exchange requires explicit opt-in")
    func privateContentExchangeRequiresOptIn() async throws {
        let peer = PeerID(publicKey: deterministicTestPeerKey("private-content-peer"))
        let disabledSource = DenyingContentSource()
        let disabled = Ivy(config: IvyConfig(
            publicKey: "private-content-disabled",
            listenPort: 0,
            mode: .privateNetwork
        ))
        await disabled.setContentSource(disabledSource)
        await disabled.handleMessage(
            .contentRequest(requestID: 1, rootCID: "root", cids: []),
            from: peer
        )
        let disabledCounts = await disabledSource.counts()
        #expect(disabledCounts.authorizationChecks == 0)
        #expect(disabledCounts.contentRequests == 0)

        let enabledSource = DenyingContentSource()
        let enabled = Ivy(config: IvyConfig(
            publicKey: "private-content-enabled",
            listenPort: 0,
            privateContentExchangeEnabled: true,
            mode: .privateNetwork
        ))
        await enabled.setContentSource(enabledSource)
        await enabled.handleMessage(
            .contentRequest(requestID: 2, rootCID: "root", cids: []),
            from: peer
        )
        try await TestSynchronization.wait(for: "private content authorization") {
            await enabledSource.counts().authorizationChecks == 1
        }
        let enabledCounts = await enabledSource.counts()
        #expect(enabledCounts.authorizationChecks == 1)
        #expect(enabledCounts.contentRequests == 0)
    }

    @Test("local fetches coalesce and retain their concurrency slots across restart")
    func localFetchWorkRemainsBoundedAcrossRestart() async throws {
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            publicKey: "content-local-cap",
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConcurrentContentRequests: 2,
            externalAddress: ("127.0.0.1", port)))
        let source = BlockingContentSource()
        await ivy.setContentSource(source)
        try await ivy.start()

        let first = BoundedTestTask { await ivy.fetchContent(rootCID: "root-a") }
        try await TestSynchronization.wait(for: "first local fetch") {
            await source.startedCount() == 1
        }
        let follower = BoundedTestTask { await ivy.fetchContent(rootCID: "root-a") }
        let key = ContentRequestKey(rootCID: "root-a", cids: [])
        try await TestSynchronization.wait(for: "coalesced local fetch") {
            await ivy.networkFetchWaiterCount(for: key) == 1
        }
        let second = BoundedTestTask { await ivy.fetchContent(rootCID: "root-b") }
        try await TestSynchronization.wait(for: "second local fetch") {
            await source.startedCount() == 2
        }

        await ivy.stop()
        #expect(try await follower.value(waitingFor: "stopped local follower") == .empty)
        try await ivy.start()
        #expect(await ivy.fetchContent(rootCID: "root-c") == .empty)
        #expect(await source.startedCount() == 2)

        await source.releaseAll()
        #expect(try await first.value(waitingFor: "old first local fetch") == .empty)
        #expect(try await second.value(waitingFor: "old second local fetch") == .empty)
        #expect(await source.maxActiveCount() == 2)
        await ivy.stop()
    }

    @Test("the fetch deadline returns while stalled work retains its bounded slot")
    func fetchDeadlineKeepsStalledWorkBounded() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "content-deadline",
            listenPort: 0,
            requestTimeout: .milliseconds(50),
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxPendingRequests: 1,
            maxConcurrentContentRequests: 1))
        let source = BlockingContentSource()
        await ivy.setContentSource(source)

        let first = BoundedTestTask { await ivy.fetchContent(rootCID: "root-a") }
        #expect(try await first.value(waitingFor: "timed-out local fetch") == .empty)
        #expect(await ivy.activeFetchCountForTesting == 1)

        let second = BoundedTestTask { await ivy.fetchContent(rootCID: "root-b") }
        #expect(try await second.value(waitingFor: "capacity-rejected local fetch") == .empty)
        #expect(await source.startedCount() == 1)

        await source.releaseAll()
        #expect(try await TransportTestHarness.eventually {
            await ivy.activeFetchCountForTesting == 0
        })
    }

    @Test("stop drains a local fetch before the first network start")
    func stopDrainsOfflineFetch() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "offline-content-stop",
            listenPort: 0,
            requestTimeout: .seconds(5),
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))
        let blocked = BlockingContentSource()
        await ivy.setContentSource(blocked)

        let stale = BoundedTestTask { await ivy.fetchContent(rootCID: "root") }
        try await TestSynchronization.wait(for: "offline local fetch") {
            await blocked.startedCount() == 1
        }

        await ivy.stop()
        #expect(try await stale.value(waitingFor: "stopped offline fetch") == .empty)

        let expected = Data("new".utf8)
        await ivy.setContentSource(TestContentSource(entries: ["root": expected]))
        try await ivy.start()
        #expect(await ivy.fetchContent(rootCID: "root").entries == ["root": expected])

        await blocked.releaseAll()
        await ivy.stop()
    }

    @Test("coalesced public fetches are isolated across stop and restart")
    func publicFetchIsRunScoped() async throws {
        let identity = TransportTestHarness.identity("content-public-run")
        let ivy = Ivy(config: TransportTestHarness.config(
            identity,
            port: TransportTestHarness.nextPort()))
        let controlled = ControlledNetworkFetch()
        let key = ContentRequestKey(rootCID: "root", cids: [])
        let oldResponse = AttributedContentResponse(
            entries: ["root": Data("old".utf8)],
            servedBy: nil)
        let newResponse = AttributedContentResponse(
            entries: ["root": Data("new".utf8)],
            servedBy: nil)
        await ivy.setNetworkFetchHookForTesting { _, _, _ in
            await controlled.run()
        }

        try await ivy.start()
        let oldLeader = BoundedTestTask { await ivy.fetchContent(rootCID: "root") }
        try await controlled.waitForInvocations(1)
        let oldFollower = BoundedTestTask { await ivy.fetchContent(rootCID: "root") }
        let oldJoined = try await TransportTestHarness.eventually {
            await ivy.networkFetchWaiterCount(for: key) == 1
        }
        #expect(oldJoined)
        guard oldJoined else {
            await controlled.complete(0, with: .empty)
            await ivy.stop()
            _ = try? await oldLeader.value(waitingFor: "old content leader cleanup")
            _ = try? await oldFollower.value(waitingFor: "old content follower cleanup")
            return
        }

        await ivy.stop()
        #expect(try await oldFollower.value(waitingFor: "old content follower drain") == .empty)

        try await ivy.start()
        let newLeader = BoundedTestTask { await ivy.fetchContent(rootCID: "root") }
        try await controlled.waitForInvocations(2)
        let newFollower = BoundedTestTask { await ivy.fetchContent(rootCID: "root") }
        let newJoined = try await TransportTestHarness.eventually {
            await ivy.networkFetchWaiterCount(for: key) == 1
        }
        #expect(newJoined)
        guard newJoined else {
            await controlled.complete(0, with: oldResponse)
            await controlled.complete(1, with: .empty)
            await ivy.stop()
            _ = try? await oldLeader.value(waitingFor: "old content leader cleanup")
            _ = try? await newLeader.value(waitingFor: "new content leader cleanup")
            _ = try? await newFollower.value(waitingFor: "new content follower cleanup")
            return
        }

        await controlled.complete(0, with: oldResponse)
        #expect(try await oldLeader.value(waitingFor: "old content leader completion") == .empty)
        #expect(await ivy.networkFetchWaiterCount(for: key) == 1)

        await controlled.complete(1, with: newResponse)
        #expect(try await newLeader.value(waitingFor: "new content leader completion") == newResponse)
        #expect(try await newFollower.value(waitingFor: "new content follower completion") == newResponse)
        #expect(await ivy.networkFetchWaiterCount(for: key) == 0)

        await ivy.stop()
    }

    @Test("local fetch uses the same exact opaque selection contract")
    func exactPartialSelection() async {
        let ivy = node("content-requester")
        let source = TestContentSource(entries: [
            "root": Data([0x00, 0xff, 0x7f]),
            "child-a": Data("bytes unrelated to the name".utf8),
            "child-b": Data([0x01, 0x02]),
            "unselected": Data([0x03]),
        ])
        await ivy.setContentSource(source)

        let response = await ivy.fetchContent(
            rootCID: "root",
            cids: ["child-b", "root", "child-a", "child-b"])

        #expect(response.entries == [
            "root": Data([0x00, 0xff, 0x7f]),
            "child-a": Data("bytes unrelated to the name".utf8),
            "child-b": Data([0x01, 0x02]),
        ])
        #expect(response.servedBy == nil)
        let requests = await source.requests()
        #expect(requests.count == 1)
        #expect(requests.first?.rootCID == "root")
        #expect(requests.first?.cids == ["root", "child-a", "child-b"])
        #expect(requests.first?.maxDataBytes == Message.contentResponseDataBudget(
            for: ["root", "child-a", "child-b"],
            maxFrameSize: IvyConfig.protocolMaxFrameSize,
            relayed: false))
    }

    @Test("remote selection receives the exact direct aggregate data budget")
    func remoteSelectionBudget() async {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "budgeted-content-server",
            listenPort: 0))
        let source = TestContentSource(entries: ["root": Data()])
        await ivy.setContentSource(source)

        await ivy.handleContentRequest(
            requestID: 1,
            rootCID: "root",
            cids: [],
            from: PeerID(publicKey: deterministicTestPeerKey("budgeted-content-client")))

        let request = await source.requests().first
        #expect(request?.cids == ["root"])
        #expect(request?.maxDataBytes == Message.contentResponseDataBudget(
            for: ["root"],
            maxFrameSize: IvyConfig.protocolMaxFrameSize,
            relayed: false))
        #expect(request?.maxDataBytes != .max)
    }

    @Test("structurally impossible exact selection does not invoke storage")
    func impossibleSelection() async {
        let ivy = node("impossible-content-server")
        let source = TestContentSource(entries: [:])
        await ivy.setContentSource(source)
        let cids = (0..<Int(MessageLimits.maxContentCIDCount)).map { "child-\($0)" }

        await ivy.handleContentRequest(
            requestID: 1,
            rootCID: "root",
            cids: cids,
            from: PeerID(publicKey: deterministicTestPeerKey("impossible-content-client")))

        #expect(await source.requests().isEmpty)
    }

    @Test("an empty selected identifier rejects the request")
    func emptySelectedIdentifier() async {
        let ivy = node("invalid-content-requester")
        let source = TestContentSource(entries: ["root": Data("root".utf8)])
        await ivy.setContentSource(source)

        let response = await ivy.fetchContent(rootCID: "root", cids: [""])

        #expect(response == .empty)
        #expect((await source.requests()).isEmpty)
    }

    @Test("non-ASCII identifiers are rejected before storage")
    func nonASCIIIdentifier() async {
        let ivy = node("non-ascii-content-requester")
        let source = TestContentSource(entries: [:])
        await ivy.setContentSource(source)

        #expect(await ivy.fetchContent(rootCID: "\u{00e9}") == .empty)
        #expect(await ivy.fetchContent(rootCID: "e\u{0301}") == .empty)
        #expect((await source.requests()).isEmpty)
    }

    @Test("an incomplete selection is reported as unavailable")
    func incompleteSelection() async {
        let ivy = node("incomplete-requester")
        let source = TestContentSource(entries: ["root": Data("root-only".utf8)])
        await ivy.setContentSource(source)

        let response = await ivy.fetchContent(rootCID: "root", cids: ["missing-child"])

        #expect(response == .empty)
        #expect((await source.requests()).first?.cids == ["root", "missing-child"])
    }

    @Test("source output must exactly match the requested selection")
    func exactSourceShape() async {
        let ivy = node("exact-source-shape")
        let root = ContentEntry(cid: "root", data: Data("root".utf8))
        let child = ContentEntry(cid: "child", data: Data("child".utf8))

        await ivy.setContentSource(RawContentSource(entries: [child, root]))
        #expect(await ivy.fetchContent(rootCID: "root", cids: ["child"]).entries == [
            "root": root.data,
            "child": child.data,
        ])

        for invalid in [
            [root, root],
            [root, ContentEntry(cid: "extra", data: Data())],
            [root],
        ] {
            await ivy.setContentSource(RawContentSource(entries: invalid))
            #expect(await ivy.fetchContent(rootCID: "root", cids: ["child"]) == .empty)
        }
    }

    @Test("only a complete response from an expected candidate resolves a fetch")
    func adversarialResponseCorrelation() async throws {
        let ivy = node("correlation-requester")
        let candidateA = PeerID(publicKey: deterministicTestPeerKey("candidate-a"))
        let candidateB = PeerID(publicKey: deterministicTestPeerKey("candidate-b"))
        let stranger = PeerID(publicKey: deterministicTestPeerKey("stranger"))
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }
        let key = ContentRequestKey(rootCID: "root", cids: ["child"])
        let fetch = Task { await ivy.fetchContent(key, from: [candidateA, candidateB]) }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingContentState().requestID != nil
        })
        guard let requestID = await ivy.pendingContentState().requestID else {
            Issue.record("Expected a pending content request")
            return
        }

        await ivy.handleContentResponse(
            requestID: requestID,
            entries: [ContentEntry(cid: "root", data: Data())],
            from: stranger)
        #expect(await ivy.pendingContentState().candidates == Set([candidateA, candidateB]))

        await ivy.handleContentResponse(
            requestID: requestID,
            entries: [
                ContentEntry(cid: "root", data: Data("root".utf8)),
                ContentEntry(cid: "extra", data: Data()),
            ],
            from: candidateA)
        #expect(await ivy.pendingContentState().candidates == Set([candidateB]))

        await ivy.handleContentResponse(
            requestID: requestID,
            entries: [
                ContentEntry(cid: "root", data: Data("root".utf8)),
                ContentEntry(cid: "child", data: Data("child".utf8)),
            ],
            from: candidateB)

        #expect(await fetch.value == AttributedContentResponse(
            entries: [
                "root": Data("root".utf8),
                "child": Data("child".utf8),
            ],
            servedBy: candidateB))
        #expect(await ivy.pendingContentState().requestID == nil)
    }

    @Test("an exact content fetch is fenced to one authenticated session")
    func exactSessionFetchIsFenced() async throws {
        let ivy = node("exact-session-requester")
        let identity = deterministicTestPeerKey("exact-session-peer")
        let endpoint = PeerEndpoint(
            publicKey: identity,
            host: "127.0.0.1",
            port: 4100
        )
        let key = try PeerKey(identity)
        let oldSessionID = Data(repeating: 1, count: 32)
        let currentSessionID = Data(repeating: 2, count: 32)
        let oldPeer = AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata(),
            sessionID: oldSessionID
        )
        let currentPeer = AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata(),
            sessionID: currentSessionID
        )
        try await ivy.seedConnectedEndpointForTesting(endpoint, marker: 2)
        await ivy.setContentRequestEnqueueHookForTesting { _ in true }

        #expect(await ivy.fetchContent(rootCID: "root", from: oldPeer) == .empty)
        #expect(await ivy.pendingContentState().requestID == nil)

        let fetch = Task {
            await ivy.fetchContent(
                rootCID: "root",
                cids: ["child"],
                from: currentPeer
            )
        }
        #expect(try await TransportTestHarness.eventually {
            await ivy.pendingContentState().requestID != nil
        })
        let requestID = try #require(await ivy.pendingContentState().requestID)
        let entries = [
            ContentEntry(cid: "root", data: Data("root".utf8)),
            ContentEntry(cid: "child", data: Data("child".utf8)),
        ]

        await ivy.handleContentResponse(
            requestID: requestID,
            entries: entries,
            from: key.peerID,
            sessionID: oldSessionID
        )
        #expect(await ivy.pendingContentState().requestID == requestID)

        await ivy.handleContentResponse(
            requestID: requestID,
            entries: entries,
            from: key.peerID,
            sessionID: currentSessionID
        )
        #expect(await fetch.value == AttributedContentResponse(
            entries: [
                "root": Data("root".utf8),
                "child": Data("child".utf8),
            ],
            servedBy: key.peerID
        ))
    }

    @Test("a request rejected before enqueue does not wait for its network timeout")
    func locallyRejectedRequestCompletesImmediately() async {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "content-local-rejection",
            listenPort: 0,
            requestTimeout: .seconds(5)))
        let peer = PeerID(publicKey: deterministicTestPeerKey("missing-content-peer"))

        let started = ContinuousClock.now
        let response = await ivy.fetchContent(
            ContentRequestKey(rootCID: "root", cids: []),
            from: [peer])

        #expect(response == .empty)
        #expect(ContinuousClock.now - started < .milliseconds(200))
        #expect(await ivy.pendingContentState().requestID == nil)
    }

    @Test("last-resort content fallback rotates across connected peers")
    func connectedFallbackIsFair() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "content-fallback-fairness",
            listenPort: 0,
            maxContentCandidates: 2))
        let peers = (0..<3).map {
            PeerID(publicKey: deterministicTestPeerKey("fallback-peer-\($0)"))
        }
        for (index, peer) in peers.enumerated() {
            let endpoint = PeerEndpoint(
                publicKey: peer.publicKey,
                host: "127.0.0.1",
                port: UInt16(4100 + index))
            try await ivy.seedConnectedEndpointForTesting(
                endpoint,
                marker: UInt8(index + 1))
        }

        let first = await ivy.connectedFallbackCandidates(rootCID: "root", excluding: [:])
        let second = await ivy.connectedFallbackCandidates(rootCID: "root", excluding: [:])

        #expect(first.count == 2)
        #expect(second.count == 2)
        #expect(Set(first + second) == Set(peers))
        await ivy.stop()
    }

    @Test("inbound storage callbacks obey the global concurrency bound")
    func inboundContentConcurrency() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "bounded-content-server",
            listenPort: 0,
            maxConcurrentContentRequests: 2))
        let source = BlockingContentSource()
        await ivy.setContentSource(source)
        let peers = (0..<3).map {
            PeerID(publicKey: deterministicTestPeerKey("content-caller-\($0)"))
        }

        let first = Task {
            await ivy.handleContentRequest(requestID: 1, rootCID: "root", cids: [], from: peers[0])
        }
        let second = Task {
            await ivy.handleContentRequest(requestID: 2, rootCID: "root", cids: [], from: peers[1])
        }
        #expect(try await TransportTestHarness.eventually {
            let started = await source.startedCount()
            let serving = await ivy.servingContentCount()
            return started == 2 && serving == 2
        })

        await ivy.handleContentRequest(requestID: 3, rootCID: "root", cids: [], from: peers[2])
        #expect(await source.startedCount() == 2)
        #expect(await ivy.servingContentCount() == 2)

        await source.releaseAll()
        _ = await first.value
        _ = await second.value
        #expect(await ivy.servingContentCount() == 0)
    }

    @Test("a disconnected peer retains its serving slot until storage exits")
    func disconnectedPeerRetainsServingSlot() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: "disconnected-content-slot",
            listenPort: 0,
            maxConcurrentContentRequests: 8
        ))
        let source = BlockingContentSource()
        await ivy.setContentSource(source)
        let peerKey = try PeerKey(deterministicTestPeerKey(
            "disconnected-content-client"
        ))
        let oldConnection = try connection(peerKey: peerKey, marker: 1)
        let replacementConnection = try connection(peerKey: peerKey, marker: 2)

        let oldRequest = Task {
            await ivy.handleContentRequestForTesting(
                connection: oldConnection,
                peerKey: peerKey,
                sessionMarker: 1,
                requestID: 7
            )
        }
        #expect(try await TransportTestHarness.eventually {
            let started = await source.startedCount()
            let serving = await ivy.servingContentCount()
            return started == 1 && serving == 1
        })

        await ivy.cleanupPendingForPeer(peerKey.peerID)
        let replacementRequest = Task {
            await ivy.handleContentRequestForTesting(
                connection: replacementConnection,
                peerKey: peerKey,
                sessionMarker: 2,
                requestID: 7
            )
        }
        #expect(try await TransportTestHarness.eventually {
            let started = await source.startedCount()
            let serving = await ivy.servingContentCount()
            return started == 2 && serving == 2
        })

        await source.release(0)
        _ = await oldRequest.value
        #expect(await ivy.servingContentCount() == 1)

        await source.release(1)
        _ = await replacementRequest.value
        #expect(await ivy.servingContentCount() == 0)
        await ivy.stop()
    }

    @Test("restart retains stalled Volume slots and byte reservations")
    func restartRetainsServingVolumeReservations() async throws {
        let identity = TransportTestHarness.identity(
            "restart-volume-reservation"
        )
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: port,
            requestTimeout: .seconds(5),
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConcurrentContentRequests: 2,
            externalAddress: ("127.0.0.1", port)
        ))
        let source = BlockingConcurrentVolumeSource()
        await ivy.setContentSource(source)
        try await ivy.start()
        let peers = (0..<4).map {
            PeerID(publicKey: deterministicTestPeerKey(
                "restart-volume-client-\($0)"
            ))
        }

        await ivy.scheduleVolumeRequest(
            requestID: 1,
            rootCID: "root-a",
            from: peers[0]
        )
        await ivy.scheduleVolumeRequest(
            requestID: 2,
            rootCID: "root-b",
            from: peers[1]
        )
        #expect(try await TransportTestHarness.eventually {
            let started = await source.startedCount()
            let serving = await ivy.servingContentCount()
            let reservation = await ivy.volumeReservations().serving
            return started == 2
                && serving == 2
                && reservation == MessageLimits.maxInFlightVolumeBytes
        })

        await ivy.stop()
        #expect(await ivy.servingContentCount() == 2)
        #expect(
            await ivy.volumeReservations().serving
                == MessageLimits.maxInFlightVolumeBytes
        )
        try await ivy.start()
        await ivy.scheduleVolumeRequest(
            requestID: 3,
            rootCID: "root-c",
            from: peers[2]
        )
        #expect(await source.startedCount() == 2)
        #expect(await ivy.servingContentCount() == 2)

        await source.release(0)
        #expect(try await TransportTestHarness.eventually {
            let serving = await ivy.servingContentCount()
            let reservation = await ivy.volumeReservations().serving
            return serving == 1
                && reservation == MessageLimits.maxVolumeArchiveBytes
        })
        await ivy.scheduleVolumeRequest(
            requestID: 4,
            rootCID: "root-d",
            from: peers[3]
        )
        #expect(try await TransportTestHarness.eventually {
            let started = await source.startedCount()
            let serving = await ivy.servingContentCount()
            let reservation = await ivy.volumeReservations().serving
            return started == 3
                && serving == 2
                && reservation == MessageLimits.maxInFlightVolumeBytes
        })

        await source.release(1)
        await source.release(2)
        #expect(try await TransportTestHarness.eventually {
            let serving = await ivy.servingContentCount()
            let reservation = await ivy.volumeReservations().serving
            return serving == 0 && reservation == 0
        })
        await ivy.stop()
    }

    @Test("a replaced session cannot deliver a stale content reply")
    func staleSessionReply() async throws {
        let ivy = node("stale-content-server")
        let source = BlockingContentSource()
        await ivy.setContentSource(source)
        let peerKey = try PeerKey(deterministicTestPeerKey("stale-content-client"))
        let oldConnection = try connection(peerKey: peerKey, marker: 1)
        let newConnection = try connection(peerKey: peerKey, marker: 2)

        let oldRequest = Task {
            await ivy.handleContentRequestForTesting(
                connection: oldConnection,
                peerKey: peerKey,
                sessionMarker: 1,
                requestID: 7)
        }
        #expect(try await TransportTestHarness.eventually {
            await source.startedCount() == 1
        })

        let newRequest = Task {
            await ivy.handleContentRequestForTesting(
                connection: newConnection,
                peerKey: peerKey,
                sessionMarker: 2,
                requestID: 7)
        }
        #expect(try await TransportTestHarness.eventually {
            await source.startedCount() == 2
        })

        await source.releaseAll()
        _ = await oldRequest.value
        _ = await newRequest.value

        #expect(await ivy.sentContentRepliesForTesting == [newConnection.connectionID])
        await ivy.stop()
    }

    private func connection(
        peerKey: PeerKey,
        marker: UInt8
    ) throws -> PeerConnection {
        PeerConnection(
            endpoint: PeerEndpoint(publicKey: peerKey.hex, host: "relay", port: 0),
            routeID: Data(repeating: marker, count: 32),
            carrier: try PeerKey(deterministicTestPeerKey("stale-content-carrier")))
    }
}
