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

    func networkFetchWaiterCount(for key: ContentRequestKey) -> Int {
        pendingNetworkFetches[key]?.waiters.count ?? 0
    }
}

private actor BlockingContentSource: IvyContentSource {
    private var starts = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry] {
        starts += 1
        await withCheckedContinuation { waiters.append($0) }
        return []
    }

    func startedCount() -> Int { starts }

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

private struct RawContentSource: IvyContentSource {
    let entries: [ContentEntry]

    func content(rootCID: String, cids: [String], maxDataBytes: Int) -> [ContentEntry] {
        entries
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
