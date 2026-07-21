import Foundation
import Tally

public protocol IvyContentSource: Sendable {
    /// Return every requested entry exactly once within `maxDataBytes`, or `[]`.
    /// `cids` is canonical and includes `rootCID`. Ivy treats identifiers and
    /// bytes as opaque.
    func content(rootCID: String, cids: [String], maxDataBytes: Int) async -> [ContentEntry]

    /// Admission hook for authenticated remote requests. Public content
    /// sources accept every peer by default; private users can narrow access
    /// without changing the opaque content contract.
    func authorizesContentRequest(
        from peer: AuthenticatedPeer,
        rootCID: String,
        cids: [String]
    ) async -> Bool
}

public extension IvyContentSource {
    func authorizesContentRequest(
        from peer: AuthenticatedPeer,
        rootCID: String,
        cids: [String]
    ) async -> Bool {
        true
    }
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
    let exactSessionID: Data?
    var timeoutTask: IvyTimer? = nil
}

struct PendingFetch {
    let token: UInt64
    let generation: UInt64
    var continuations: [UUID: CheckedContinuation<AttributedContentResponse, Never>]
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

        let source = contentSource
        if let source {
            guard let requester = authenticatedPeer(for: peer, session: session),
                  await source.authorizesContentRequest(
                    from: requester,
                    rootCID: rootCID,
                    cids: key.requestedCIDs
                  ) else {
                sendContentReply(
                    .contentUnavailable(requestID: requestID),
                    to: peer,
                    session: session,
                    bypassAdmission: true)
                return
            }
        }
        guard !Task.isCancelled, session.map(isCurrent) ?? true else { return }
        let available = await source?.content(
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

    private func authenticatedPeer(
        for peer: PeerID,
        session: AuthenticatedSession?
    ) -> AuthenticatedPeer? {
        if let session {
            return AuthenticatedPeer(
                key: session.peerKey,
                role: session.role,
                route: session.connection.route,
                metadata: session.metadata,
                sessionID: session.sessionID.bytes)
        }
        guard let key = try? PeerKey(peer.publicKey) else { return nil }
        return AuthenticatedPeer(
            key: key,
            role: .endpoint,
            route: .direct,
            metadata: PeerMetadata())
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
        from peer: PeerID,
        sessionID: Data? = nil
    ) {
        guard let pending = pendingContentRequests[requestID],
              pending.candidates.contains(peer),
              pending.exactSessionID.map({ $0 == sessionID }) ?? true else { return }
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

    func handleContentUnavailable(
        requestID: UInt64,
        from peer: PeerID,
        sessionID: Data? = nil
    ) {
        guard let pending = pendingContentRequests[requestID],
              pending.exactSessionID.map({ $0 == sessionID }) ?? true else { return }
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

    /// Fetches one exact selection from the specified authenticated endpoint
    /// session. A replacement connection for the same key cannot receive or
    /// satisfy the request.
    public func fetchContent(
        rootCID: String,
        cids: [String] = [],
        from peer: AuthenticatedPeer
    ) async -> AttributedContentResponse {
        let generation = runGeneration
        guard MessageLimits.accepts(rootCID),
              cids.count <= Int(MessageLimits.maxContentCIDCount),
              cids.allSatisfy(MessageLimits.accepts) else { return .empty }
        let key = ContentRequestKey(rootCID: rootCID, cids: cids)
        guard Message.contentResponseDataBudget(
            for: key.requestedCIDs,
            maxFrameSize: IvyConfig.protocolMaxFrameSize,
            relayed: peer.route != .direct
        ) != nil else { return .empty }
        return await fetchContent(
            key,
            from: [peer.id],
            generation: generation,
            exactPeer: peer
        )
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
        let waiterID = UUID()
        let response: AttributedContentResponse = await withTaskCancellationHandler {
            guard !Task.isCancelled else { return AttributedContentResponse.empty }
            return await withCheckedContinuation { continuation in
                guard !Task.isCancelled else {
                    continuation.resume(returning: .empty)
                    return
                }
                if var pending = pendingFetches[key] {
                    guard pending.generation == generation,
                          pending.continuations.count < config.maxWaitersPerRequest else {
                        continuation.resume(returning: .empty)
                        return
                    }
                    pending.continuations[waiterID] = continuation
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
                    continuations: [waiterID: continuation])
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
        } onCancel: {
            Task { await self.cancelFetchWaiter(key, waiterID: waiterID) }
        }
        return Task.isCancelled ? .empty : response
    }

    private func cancelFetchWaiter(_ key: ContentRequestKey, waiterID: UUID) {
        guard var pending = pendingFetches[key],
              let continuation = pending.continuations.removeValue(forKey: waiterID)
        else { return }
        continuation.resume(returning: .empty)
        guard pending.continuations.isEmpty else {
            pendingFetches[key] = pending
            return
        }
        pendingFetches.removeValue(forKey: key)
        pending.timeoutTask?.cancel()
        pending.operationTask?.cancel()
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
        } else if !Task.isCancelled,
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
        for continuation in pending.continuations.values {
            continuation.resume(returning: result)
        }
    }

    private func timeoutFetch(_ key: ContentRequestKey, token: UInt64) {
        guard pendingFetches[key]?.token == token,
              let pending = pendingFetches.removeValue(forKey: key) else { return }
        pending.operationTask?.cancel()
        for continuation in pending.continuations.values {
            continuation.resume(returning: .empty)
        }
    }

    private func performNetworkFetch(
        _ key: ContentRequestKey,
        generation: UInt64
    ) async -> AttributedContentResponse {
        guard isCurrentRun(generation), !Task.isCancelled,
              config.mode.usesOverlayServices || config.privateContentExchangeEnabled
        else { return .empty }
        var attemptedSessions: [PeerID: UUID] = [:]
        let cached = cachedProviderEndpoints(rootCID: key.rootCID)
        await connectToProviderEndpoints(cached, generation: generation)
        guard isCurrentRun(generation), !Task.isCancelled else { return .empty }

        var candidates = Array(connectedProviderIDs(for: key.rootCID)
            .prefix(config.maxContentCandidates))
        if !candidates.isEmpty {
            let sessions = liveConnectionIDs(for: candidates)
            let response = await fetchContent(key, from: candidates, generation: generation)
            guard isCurrentRun(generation), !Task.isCancelled else { return .empty }
            if !response.entries.isEmpty { return response }
            attemptedSessions.merge(sessions) { _, latest in latest }
        }

        let fresh = await queryFreshProviderEndpoints(
            rootCID: key.rootCID,
            generation: generation)
        guard isCurrentRun(generation), !Task.isCancelled else { return .empty }
        await connectToProviderEndpoints(fresh + cached, generation: generation)
        guard isCurrentRun(generation), !Task.isCancelled else { return .empty }
        candidates = Array(connectedProviderIDs(for: key.rootCID)
            .filter {
                attemptedSessions[$0] != endpointConnection(for: $0)?.connectionID
            }
            .prefix(config.maxContentCandidates))
        if !candidates.isEmpty {
            let sessions = liveConnectionIDs(for: candidates)
            let response = await fetchContent(key, from: candidates, generation: generation)
            guard isCurrentRun(generation), !Task.isCancelled else { return .empty }
            if !response.entries.isEmpty { return response }
            attemptedSessions.merge(sessions) { _, latest in latest }
        }

        candidates = connectedFallbackCandidates(
            rootCID: key.rootCID,
            excluding: attemptedSessions)
        guard !Task.isCancelled, !candidates.isEmpty else { return .empty }
        let response = await fetchContent(key, from: candidates, generation: generation)
        return isCurrentRun(generation) && !Task.isCancelled ? response : .empty
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
        generation: UInt64? = nil,
        exactPeer: AuthenticatedPeer? = nil
    ) async -> AttributedContentResponse {
        if let generation, !isCurrentRun(generation) { return .empty }
        let requestID = makeContentRequestID()
        let response: AttributedContentResponse = await withTaskCancellationHandler {
            guard !Task.isCancelled else { return .empty }
            return await withCheckedContinuation { continuation in
                guard !Task.isCancelled,
                      pendingContentRequests.count < config.maxPendingRequests else {
                    continuation.resume(returning: .empty)
                    return
                }

                let message = Message.contentRequest(
                    requestID: requestID,
                    rootCID: key.rootCID,
                    cids: key.cids
                )
                var enqueued: Set<PeerID> = []
                if let exactPeer {
                    guard candidates == [exactPeer.id],
                          enqueueContentRequestOnCurrentSession(
                            message,
                            to: exactPeer
                          ) else {
                        continuation.resume(returning: .empty)
                        return
                    }
                    enqueued.insert(exactPeer.id)
                } else {
                    for peer in candidates {
                        if enqueueContentRequest(message, to: peer) {
                            enqueued.insert(peer)
                        }
                    }
                }
                guard !enqueued.isEmpty else {
                    continuation.resume(returning: .empty)
                    return
                }
                pendingContentRequests[requestID] = PendingContentRequest(
                    key: key,
                    continuation: continuation,
                    candidates: enqueued,
                    exactSessionID: exactPeer?.sessionID)

                let timeout = config.requestTimeout
                let timeoutTask = delayedTask(after: timeout) { [weak self] in
                    await self?.resolveContentRequest(requestID: requestID)
                }
                pendingContentRequests[requestID]?.timeoutTask = timeoutTask
            }
        } onCancel: {
            Task { await self.resolveContentRequest(requestID: requestID) }
        }
        if Task.isCancelled || generation.map({ !isCurrentRun($0) }) == true {
            return .empty
        }
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
