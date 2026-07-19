import Foundation
import Tally

public protocol IvyContentSource: Sendable {
    /// Return every requested entry exactly once within `maxDataBytes`, or `[]`.
    /// `cids` is canonical and includes `rootCID`. Ivy treats identifiers and
    /// bytes as opaque.
    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry]
}

public struct AttributedContentResponse: Sendable, Equatable {
    public let entries: [String: Data]
    /// The authenticated remote server, or `nil` for a local-source result.
    public let servedBy: PeerID?

    public static let empty = AttributedContentResponse(entries: [:], servedBy: nil)

    public init(entries: [String: Data], servedBy: PeerID?) {
        self.entries = entries
        self.servedBy = servedBy
    }
}

struct ContentRequestKey: Hashable, Sendable {
    let rootCID: String
    let cids: [String]

    init(rootCID: String, cids: [String]) {
        self.rootCID = rootCID
        self.cids = Array(Set(cids.filter { $0 != rootCID })).sorted()
    }

    var requestedCIDs: [String] { [rootCID] + cids }
    var requestedSet: Set<String> { Set(requestedCIDs) }
}

struct PendingContentRequest {
    let key: ContentRequestKey
    let continuation: CheckedContinuation<AttributedContentResponse, Never>
    var candidates: Set<PeerID>
    var timeoutTask: IvyTimer? = nil
}

struct PendingFetch {
    let token: UInt64
    let generation: UInt64
    var continuations: [CheckedContinuation<AttributedContentResponse, Never>]
    var operationTask: Task<Void, Never>? = nil
    var timeoutTask: IvyTimer? = nil
}

struct InboundContentRequest: Hashable {
    let peer: PeerID
    let connectionID: UUID?
    let requestID: UInt64
}

extension Ivy {
    func handleContentRequest(
        requestID: UInt64,
        rootCID: String,
        cids: [String],
        from peer: PeerID,
        session: AuthenticatedSession? = nil
    ) async {
        guard MessageLimits.accepts(rootCID),
              cids.count <= Int(MessageLimits.maxContentCIDCount),
              cids.allSatisfy(MessageLimits.accepts) else { return }
        let key = ContentRequestKey(rootCID: rootCID, cids: cids)
        guard let maxDataBytes = Message.contentResponseDataBudget(
            for: key.requestedCIDs,
            maxFrameSize: IvyConfig.protocolMaxFrameSize,
            relayed: session.map { !$0.connection.isDirect }
                ?? (endpointConnection(for: peer)?.isDirect == false)
        ) else {
            sendContentReply(
                .contentUnavailable(requestID: requestID),
                to: peer,
                session: session,
                bypassAdmission: true)
            return
        }
        let inbound = InboundContentRequest(
            peer: peer,
            connectionID: session?.connection.connectionID,
            requestID: requestID)
        guard beginServingContent(inbound) else {
            sendContentReply(
                .contentUnavailable(requestID: requestID),
                to: peer,
                session: session,
                bypassAdmission: true)
            return
        }
        defer { endServingContent(inbound) }

        let available = await contentSource?.content(
            rootCID: rootCID,
            cids: key.requestedCIDs,
            maxDataBytes: maxDataBytes
        ) ?? []
        guard session.map(isCurrent) ?? true else { return }

        guard let byCID = validatedContent(
            available,
            for: key,
            maxDataBytes: maxDataBytes
        ) else {
            sendContentReply(
                .contentUnavailable(requestID: requestID),
                to: peer,
                session: session,
                bypassAdmission: true)
            return
        }

        let entries = key.requestedCIDs.compactMap { cid in
            byCID[cid].map { ContentEntry(cid: cid, data: $0) }
        }
        let response = Message.contentResponse(requestID: requestID, entries: entries)
        guard case .enqueued = sendContentReply(response, to: peer, session: session) else {
            sendContentReply(
                .contentUnavailable(requestID: requestID),
                to: peer,
                session: session,
                bypassAdmission: true)
            return
        }
    }

    @discardableResult
    private func sendContentReply(
        _ message: Message,
        to peer: PeerID,
        session: AuthenticatedSession?,
        bypassAdmission: Bool = false
    ) -> SendMessageResult {
        if let session {
#if DEBUG || IVY_TESTING
            contentReplyConnectionsForTesting.append(session.connection.connectionID)
#endif
            return enqueueIfCurrent(message, on: session, bypassAdmission: bypassAdmission)
        }
        return fireToPeer(peer, message, bypassAdmission: bypassAdmission)
    }

    private func beginServingContent(_ request: InboundContentRequest) -> Bool {
        let perPeerLimit = max(1, min(8, config.maxConcurrentContentRequests / 4))
        guard servingContentRequests.count + activeLocalContentRequestCount
                < config.maxConcurrentContentRequests,
              !servingContentRequests.contains(request),
              servingContentRequests.lazy.filter({ $0.peer == request.peer }).count
                < perPeerLimit else { return false }
        servingContentRequests.insert(request)
        return true
    }

    private func endServingContent(_ request: InboundContentRequest) {
        servingContentRequests.remove(request)
    }

    func handleContentResponse(
        requestID: UInt64,
        entries: [ContentEntry],
        from peer: PeerID
    ) {
        guard let pending = pendingContentRequests[requestID],
              pending.candidates.contains(peer) else { return }
        let key = pending.key

        var result: [String: Data] = [:]
        for entry in entries {
            guard key.requestedSet.contains(entry.cid), result[entry.cid] == nil else {
                tally.recordProtocolViolation(peer: peer)
                markContentCandidateDone(requestID: requestID, peer: peer)
                return
            }
            result[entry.cid] = entry.data
        }
        guard key.requestedCIDs.allSatisfy({ result[$0] != nil }) else {
            markContentCandidateDone(requestID: requestID, peer: peer)
            return
        }

        rememberProvider(rootCID: key.rootCID, peer: peer)
        resolveContentRequest(requestID: requestID, entries: result, servedBy: peer)
    }

    func handleContentUnavailable(requestID: UInt64, from peer: PeerID) {
        markContentCandidateDone(requestID: requestID, peer: peer)
    }

    /// Fetches an exact content selection. The root is always included; `cids`
    /// names any additional entries. The response is attributed but unvalidated.
    public func fetchContent(
        rootCID: String,
        cids: [String] = []
    ) async -> AttributedContentResponse {
        let generation = runGeneration
        guard MessageLimits.accepts(rootCID),
              cids.count <= Int(MessageLimits.maxContentCIDCount),
              cids.allSatisfy(MessageLimits.accepts) else { return .empty }
        let key = ContentRequestKey(rootCID: rootCID, cids: cids)
        guard Message.contentResponseDataBudget(
            for: key.requestedCIDs,
            maxFrameSize: IvyConfig.protocolMaxFrameSize,
            relayed: false
        ) != nil else { return .empty }
        return await fetchContentCoalesced(key, generation: generation)
    }

    private func localContent(for key: ContentRequestKey) async -> [String: Data]? {
        guard let source = contentSource else { return nil }
        guard let maxDataBytes = Message.contentResponseDataBudget(
            for: key.requestedCIDs,
            maxFrameSize: IvyConfig.protocolMaxFrameSize,
            relayed: false
        ) else { return nil }
        guard servingContentRequests.count + activeLocalContentRequestCount
                < config.maxConcurrentContentRequests else { return nil }
        activeLocalContentRequestCount += 1
        defer { activeLocalContentRequestCount -= 1 }
        let entries = await source.content(
            rootCID: key.rootCID,
            cids: key.requestedCIDs,
            maxDataBytes: maxDataBytes
        )
        return validatedContent(entries, for: key, maxDataBytes: maxDataBytes)
    }

    private func validatedContent(
        _ entries: [ContentEntry],
        for key: ContentRequestKey,
        maxDataBytes: Int
    ) -> [String: Data]? {
        guard entries.count == key.requestedCIDs.count else { return nil }
        var missing = key.requestedSet
        var remaining = maxDataBytes
        var result: [String: Data] = [:]
        for entry in entries {
            guard missing.remove(entry.cid) != nil,
                  entry.data.count <= remaining else { return nil }
            remaining -= entry.data.count
            result[entry.cid] = entry.data
        }
        return missing.isEmpty ? result : nil
    }

    private func fetchContentCoalesced(
        _ key: ContentRequestKey,
        generation: UInt64
    ) async -> AttributedContentResponse {
        await withCheckedContinuation { continuation in
            if var pending = pendingFetches[key] {
                guard pending.generation == generation,
                      pending.continuations.count < config.maxWaitersPerRequest else {
                    continuation.resume(returning: .empty)
                    return
                }
                pending.continuations.append(continuation)
                pendingFetches[key] = pending
                return
            }
            guard activeFetchCount < config.maxPendingRequests else {
                continuation.resume(returning: .empty)
                return
            }
            nextFetchToken &+= 1
            let token = nextFetchToken
            var pending = PendingFetch(
                token: token,
                generation: generation,
                continuations: [continuation])
            activeFetchCount += 1
            pendingFetches[key] = pending
            pending.operationTask = Task { [weak self] in
                await self?.runFetch(key, generation: generation, token: token)
            }
            let timeout = config.requestTimeout
            pending.timeoutTask = delayedTask(after: timeout) { [weak self] in
                await self?.timeoutFetch(key, token: token)
            }
            pendingFetches[key] = pending
        }
    }

    private func runFetch(
        _ key: ContentRequestKey,
        generation: UInt64,
        token: UInt64
    ) async {
        defer { activeFetchCount -= 1 }
        let response: AttributedContentResponse
        if !Task.isCancelled, let local = await localContent(for: key) {
            response = AttributedContentResponse(entries: local, servedBy: nil)
        } else if config.mode.usesOverlayServices,
                  !Task.isCancelled,
                  isCurrentRun(generation) {
#if DEBUG || IVY_TESTING
            if let hook = networkFetchHookForTesting {
                response = await hook(key, generation, token)
            } else {
                response = await performNetworkFetch(key, generation: generation)
            }
#else
            response = await performNetworkFetch(key, generation: generation)
#endif
        } else {
            response = .empty
        }
        guard pendingFetches[key]?.token == token,
              let pending = pendingFetches.removeValue(forKey: key) else { return }
        pending.timeoutTask?.cancel()
        let result = generation == runGeneration ? response : .empty
        for continuation in pending.continuations { continuation.resume(returning: result) }
    }

    private func timeoutFetch(_ key: ContentRequestKey, token: UInt64) {
        guard pendingFetches[key]?.token == token,
              let pending = pendingFetches.removeValue(forKey: key) else { return }
        pending.operationTask?.cancel()
        for continuation in pending.continuations { continuation.resume(returning: .empty) }
    }

    private func performNetworkFetch(
        _ key: ContentRequestKey,
        generation: UInt64
    ) async -> AttributedContentResponse {
        guard isCurrentRun(generation) else { return .empty }
        var attemptedSessions: [PeerID: UUID] = [:]
        let cached = cachedProviderEndpoints(rootCID: key.rootCID)
        await connectToProviderEndpoints(cached, generation: generation)
        guard isCurrentRun(generation) else { return .empty }

        var candidates = Array(connectedProviderIDs(for: key.rootCID)
            .prefix(config.maxContentCandidates))
        if !candidates.isEmpty {
            let sessions = liveConnectionIDs(for: candidates)
            let response = await fetchContent(key, from: candidates, generation: generation)
            guard isCurrentRun(generation) else { return .empty }
            if !response.entries.isEmpty { return response }
            attemptedSessions.merge(sessions) { _, latest in latest }
        }

        let fresh = await queryFreshProviderEndpoints(
            rootCID: key.rootCID,
            generation: generation)
        guard isCurrentRun(generation) else { return .empty }
        await connectToProviderEndpoints(fresh + cached, generation: generation)
        guard isCurrentRun(generation) else { return .empty }
        candidates = Array(connectedProviderIDs(for: key.rootCID)
            .filter {
                attemptedSessions[$0] != endpointConnection(for: $0)?.connectionID
            }
            .prefix(config.maxContentCandidates))
        if !candidates.isEmpty {
            let sessions = liveConnectionIDs(for: candidates)
            let response = await fetchContent(key, from: candidates, generation: generation)
            guard isCurrentRun(generation) else { return .empty }
            if !response.entries.isEmpty { return response }
            attemptedSessions.merge(sessions) { _, latest in latest }
        }

        candidates = connectedFallbackCandidates(
            rootCID: key.rootCID,
            excluding: attemptedSessions)
        guard !candidates.isEmpty else { return .empty }
        let response = await fetchContent(key, from: candidates, generation: generation)
        return isCurrentRun(generation) ? response : .empty
    }

    private func liveConnectionIDs(for peers: [PeerID]) -> [PeerID: UUID] {
        Dictionary(uniqueKeysWithValues: peers.compactMap { peer in
            guard let connection = endpointConnection(for: peer), connection.isLive else {
                return nil
            }
            return (peer, connection.connectionID)
        })
    }

    func fetchContent(
        _ key: ContentRequestKey,
        from candidates: [PeerID],
        generation: UInt64? = nil
    ) async -> AttributedContentResponse {
        if let generation, !isCurrentRun(generation) { return .empty }
        let response: AttributedContentResponse = await withCheckedContinuation { continuation in
            guard pendingContentRequests.count < config.maxPendingRequests else {
                continuation.resume(returning: .empty)
                return
            }

            let requestID = makeContentRequestID()
            let message = Message.contentRequest(
                requestID: requestID,
                rootCID: key.rootCID,
                cids: key.cids
            )
            var enqueued: Set<PeerID> = []
            for peer in candidates {
                if enqueueContentRequest(message, to: peer) {
                    enqueued.insert(peer)
                }
            }
            guard !enqueued.isEmpty else {
                continuation.resume(returning: .empty)
                return
            }
            pendingContentRequests[requestID] = PendingContentRequest(
                key: key,
                continuation: continuation,
                candidates: enqueued)

            let timeout = config.requestTimeout
            let timeoutTask = delayedTask(after: timeout) { [weak self] in
                await self?.resolveContentRequest(requestID: requestID)
            }
            pendingContentRequests[requestID]?.timeoutTask = timeoutTask
        }
        if let generation, !isCurrentRun(generation) { return .empty }
        return response
    }

    private func makeContentRequestID() -> UInt64 {
        makeWireOperationID(avoiding: Set(pendingContentRequests.keys))
    }

    private func enqueueContentRequest(_ message: Message, to peer: PeerID) -> Bool {
#if DEBUG || IVY_TESTING
        if let hook = contentRequestEnqueueHookForTesting { return hook(peer) }
#endif
        if case .enqueued = fireToPeer(peer, message) { return true }
        return false
    }

    func markContentCandidateDone(requestID: UInt64, peer: PeerID) {
        guard var pending = pendingContentRequests[requestID],
              pending.candidates.remove(peer) != nil else { return }
        if pending.candidates.isEmpty {
            resolveContentRequest(requestID: requestID)
        } else {
            pendingContentRequests[requestID] = pending
        }
    }

    func resolveContentRequest(
        requestID: UInt64,
        entries: [String: Data] = [:],
        servedBy: PeerID? = nil
    ) {
        guard let pending = pendingContentRequests.removeValue(forKey: requestID) else { return }
        pending.timeoutTask?.cancel()
        let response = AttributedContentResponse(entries: entries, servedBy: servedBy)
        pending.continuation.resume(returning: response)
    }

    public func reportDeficientContent(rootCID: String, servedBy peer: PeerID) {
        guard MessageLimits.accepts(rootCID) else { return }
        forgetProvider(rootCID: rootCID, peer: peer)
        if deficientPeerSuppression[rootCID] == nil,
           deficientPeerSuppression.count >= Self.maxProviderRoots,
           let evicted = deficientPeerSuppression.min(by: { left, right in
               let leftExpiry = left.value.values.max()
               let rightExpiry = right.value.values.max()
               if leftExpiry == rightExpiry { return left.key < right.key }
               return leftExpiry.map { expiry in
                   rightExpiry.map { expiry < $0 } ?? false
               } ?? true
           })?.key {
            deficientPeerSuppression.removeValue(forKey: evicted)
        }
        var peers = deficientPeerSuppression[rootCID] ?? [:]
        if peers[peer.publicKey] == nil,
           peers.count >= config.kBucketSize,
           let evicted = peers.min(by: { left, right in
               left.value == right.value ? left.key < right.key : left.value < right.value
           })?.key {
            peers.removeValue(forKey: evicted)
        }
        peers[peer.publicKey] = ContinuousClock.Instant.now + Self.deficiencySuppressionWindow
        deficientPeerSuppression[rootCID] = peers
    }

    func isDeficiencySuppressed(rootCID: String, peer: PeerID) -> Bool {
        guard var byPeer = deficientPeerSuppression[rootCID] else { return false }
        let now = ContinuousClock.Instant.now
        if let until = byPeer[peer.publicKey], now < until { return true }
        byPeer = byPeer.filter { now < $0.value }
        if byPeer.isEmpty {
            deficientPeerSuppression.removeValue(forKey: rootCID)
        } else {
            deficientPeerSuppression[rootCID] = byPeer
        }
        return false
    }

    func connectedFallbackCandidates(
        rootCID: String,
        excluding attempted: [PeerID: UUID]
    ) -> [PeerID] {
        let eligible = connectedEndpointPeers
            .filter { attempted[$0] != endpointConnection(for: $0)?.connectionID }
            .filter { !isDeficiencySuppressed(rootCID: rootCID, peer: $0) }
            .sorted { $0.publicKey < $1.publicKey }
        guard !eligible.isEmpty else { return [] }

        let start = nextConnectedFallbackOffset % eligible.count
        let rotated = Array(eligible[start...] + eligible[..<start])
        let selected = Array(rotated.prefix(config.maxContentCandidates))
        nextConnectedFallbackOffset = (start + selected.count) % eligible.count
        return selected
    }
}
