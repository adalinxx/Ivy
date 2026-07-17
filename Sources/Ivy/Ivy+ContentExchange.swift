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
    var continuations: [CheckedContinuation<AttributedContentResponse, Never>]
    var candidates: Set<PeerID>
}

struct PendingNetworkFetch {
    let token: UInt64
    var waiters: [CheckedContinuation<AttributedContentResponse, Never>]
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
                ?? (connections[peer]?.isDirect == false)
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
#if DEBUG
            contentReplyConnectionsForTesting.append(session.connection.connectionID)
#endif
            return enqueueIfCurrent(message, on: session, bypassAdmission: bypassAdmission)
        }
        return fireToPeer(peer, message, bypassAdmission: bypassAdmission)
    }

    private func beginServingContent(_ request: InboundContentRequest) -> Bool {
        let perPeerLimit = max(1, min(8, config.maxConcurrentContentRequests / 4))
        guard servingContentRequests.count < config.maxConcurrentContentRequests,
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

        var result: [String: Data] = [:]
        for entry in entries {
            guard pending.key.requestedSet.contains(entry.cid), result[entry.cid] == nil else {
                tally.recordProtocolViolation(peer: peer)
                markContentCandidateDone(requestID: requestID, peer: peer)
                return
            }
            result[entry.cid] = entry.data
        }
        guard pending.key.requestedCIDs.allSatisfy({ result[$0] != nil }) else {
            markContentCandidateDone(requestID: requestID, peer: peer)
            return
        }

        rememberProvider(rootCID: pending.key.rootCID, peer: peer)
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
        guard MessageLimits.accepts(rootCID),
              cids.count <= Int(MessageLimits.maxContentCIDCount),
              cids.allSatisfy(MessageLimits.accepts) else { return .empty }
        let key = ContentRequestKey(rootCID: rootCID, cids: cids)
        if let local = await localContent(for: key) {
            return AttributedContentResponse(entries: local, servedBy: nil)
        }
        return await fetchContentFromNetwork(key)
    }

    private func localContent(for key: ContentRequestKey) async -> [String: Data]? {
        guard let maxDataBytes = Message.contentResponseDataBudget(
            for: key.requestedCIDs,
            maxFrameSize: IvyConfig.protocolMaxFrameSize,
            relayed: false
        ) else { return nil }
        guard let entries = await contentSource?.content(
            rootCID: key.rootCID,
            cids: key.requestedCIDs,
            maxDataBytes: maxDataBytes
        ) else { return nil }
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

    private func fetchContentFromNetwork(_ key: ContentRequestKey) async -> AttributedContentResponse {
        if var pending = pendingNetworkFetches[key] {
            guard pending.waiters.count + 1 < config.maxWaitersPerRequest else { return .empty }
            return await withCheckedContinuation { continuation in
                pending.waiters.append(continuation)
                pendingNetworkFetches[key] = pending
            }
        }
        nextNetworkFetchToken &+= 1
        let token = nextNetworkFetchToken
        pendingNetworkFetches[key] = PendingNetworkFetch(token: token, waiters: [])
        let response = await performNetworkFetch(key)
        guard pendingNetworkFetches[key]?.token == token,
              let pending = pendingNetworkFetches.removeValue(forKey: key) else { return response }
        for waiter in pending.waiters { waiter.resume(returning: response) }
        return response
    }

    private func performNetworkFetch(_ key: ContentRequestKey) async -> AttributedContentResponse {
        var attemptedPeers: Set<PeerID> = []
        let cached = cachedProviderEndpoints(rootCID: key.rootCID)
        let attemptedEndpoints = await connectToProviderEndpoints(cached)

        var candidates = Array(connectedProviderIDs(for: key.rootCID)
            .prefix(config.maxContentCandidates))
        if !candidates.isEmpty {
            attemptedPeers.formUnion(candidates)
            let response = await fetchContent(key, from: candidates)
            if !response.entries.isEmpty { return response }
        }

        let fresh = await queryFreshProviderEndpoints(rootCID: key.rootCID)
            .filter { !attemptedEndpoints.contains($0) }
        _ = await connectToProviderEndpoints(fresh)
        candidates = Array(connectedProviderIDs(for: key.rootCID)
            .filter { !attemptedPeers.contains($0) }
            .prefix(config.maxContentCandidates))
        if !candidates.isEmpty {
            attemptedPeers.formUnion(candidates)
            let response = await fetchContent(key, from: candidates)
            if !response.entries.isEmpty { return response }
        }

        candidates = Array(connectedEndpointIDs()
            .filter { !attemptedPeers.contains($0) }
            .prefix(config.maxContentCandidates))
        guard !candidates.isEmpty else { return .empty }
        return await fetchContent(key, from: candidates)
    }

    func fetchContent(
        _ key: ContentRequestKey,
        from candidates: [PeerID]
    ) async -> AttributedContentResponse {
        if let requestID = contentRequestIDs[key],
           let pending = pendingContentRequests[requestID] {
            guard pending.continuations.count < config.maxWaitersPerRequest else { return .empty }
            return await withCheckedContinuation { continuation in
                pendingContentRequests[requestID]?.continuations.append(continuation)
            }
        }
        guard pendingContentRequests.count < config.maxPendingRequests else { return .empty }

        return await withCheckedContinuation { continuation in
            if let requestID = contentRequestIDs[key] {
                guard var pending = pendingContentRequests[requestID],
                      pending.continuations.count < config.maxWaitersPerRequest else {
                    continuation.resume(returning: .empty)
                    return
                }
                pending.continuations.append(continuation)
                pendingContentRequests[requestID] = pending
                return
            }

            let requestID = makeContentRequestID()
            pendingContentRequests[requestID] = PendingContentRequest(
                key: key,
                continuations: [continuation],
                candidates: Set(candidates)
            )
            contentRequestIDs[key] = requestID

            let message = Message.contentRequest(
                requestID: requestID,
                rootCID: key.rootCID,
                cids: key.cids
            )
            for peer in candidates {
                fireToPeer(peer, message)
            }
            let timeout = config.requestTimeout
            Task { [weak self] in
                do {
                    try await Task.sleep(for: timeout)
                } catch {
                    return
                }
                await self?.resolveContentRequest(requestID: requestID)
            }
        }
    }

    private func makeContentRequestID() -> UInt64 {
        var requestID = UInt64.random(in: 1 ... .max)
        while pendingContentRequests[requestID] != nil {
            requestID = UInt64.random(in: 1 ... .max)
        }
        return requestID
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
        contentRequestIDs.removeValue(forKey: pending.key)
        let response = AttributedContentResponse(entries: entries, servedBy: servedBy)
        for continuation in pending.continuations {
            continuation.resume(returning: response)
        }
    }

    public func reportDeficientContent(rootCID: String, servedBy peer: PeerID) {
        guard MessageLimits.accepts(rootCID) else { return }
        forgetProvider(rootCID: rootCID, peer: peer)
        if deficientPeerSuppression[rootCID] == nil,
           deficientPeerSuppression.count >= Self.maxProviderRoots,
           let evicted = deficientPeerSuppression.keys.first {
            deficientPeerSuppression.removeValue(forKey: evicted)
        }
        var peers = deficientPeerSuppression[rootCID] ?? [:]
        if peers[peer.publicKey] == nil,
           peers.count >= config.kBucketSize,
           let evicted = peers.keys.first {
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

    func connectedEndpointIDs() -> [PeerID] {
        Array(connections.keys)
    }
}
