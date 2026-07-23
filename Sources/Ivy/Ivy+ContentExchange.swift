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

    /// Return every entry in the complete local Volume rooted at `rootCID`, or
    /// `[]`. Ivy transports the boundary opaquely; the application validates
    /// the content-addressed bytes before publishing it.
    func volume(rootCID: String, maxDataBytes: Int) async -> [ContentEntry]

    func authorizesVolumeRequest(
        from peer: AuthenticatedPeer,
        rootCID: String
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

    func volume(rootCID: String, maxDataBytes: Int) async -> [ContentEntry] {
        []
    }

    func authorizesVolumeRequest(
        from peer: AuthenticatedPeer,
        rootCID: String
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

public enum VolumeFetchFailure: Sendable, Equatable {
    case callerBoundaryExceeded
    case localCapacityUnavailable
}

public struct AttributedVolumeResponse: Sendable, Equatable {
    public let rootCID: String
    public let entries: [String: Data]
    public let servedBy: PeerID?
    public let failure: VolumeFetchFailure?

    public static let empty = AttributedVolumeResponse(
        rootCID: "",
        entries: [:],
        servedBy: nil
    )
    public static let localCapacityUnavailable = AttributedVolumeResponse(
        rootCID: "",
        entries: [:],
        servedBy: nil,
        failure: .localCapacityUnavailable
    )

    public init(
        rootCID: String,
        entries: [String: Data],
        servedBy: PeerID?,
        failure: VolumeFetchFailure? = nil
    ) {
        self.rootCID = rootCID
        self.entries = entries
        self.servedBy = servedBy
        self.failure = failure
    }
}

struct VolumeArchive {
    let entries: [ContentEntry]
    let data: Data

    static func encode(
        entries: [ContentEntry],
        rootCID: String
    ) -> VolumeArchive? {
        guard !entries.isEmpty,
              entries.count <= Int(MessageLimits.maxVolumeEntryCount) else {
            return nil
        }
        var remainingBytes = MessageLimits.maxVolumeArchiveBytes - 2
        for entry in entries {
            guard MessageLimits.accepts(entry.cid) else {
                return nil
            }
            let metadataBytes = 2 + entry.cid.utf8.count + 4
            guard metadataBytes <= remainingBytes,
                  entry.data.count <= remainingBytes - metadataBytes else {
                return nil
            }
            remainingBytes -= metadataBytes + entry.data.count
        }
        let encodedBytes = MessageLimits.maxVolumeArchiveBytes - remainingBytes
        let entries = entries.sorted { $0.cid < $1.cid }
        guard entries.contains(where: { $0.cid == rootCID }) else { return nil }
        var previous: String?
        var data = Data(capacity: encodedBytes)
        guard data.appendCount(
            entries.count,
            max: MessageLimits.maxVolumeEntryCount
        ) else { return nil }
        for entry in entries {
            guard previous.map({ $0 < entry.cid }) ?? true,
                  data.appendLengthPrefixedString(entry.cid),
                  data.appendLengthPrefixedData(
                    entry.data,
                    maxDataPayload: UInt32(MessageLimits.maxVolumeArchiveBytes)
                  ) else {
                return nil
            }
            previous = entry.cid
        }
        return VolumeArchive(entries: entries, data: data)
    }

    static func decode(
        _ data: Data,
        rootCID: String,
        expectedEntries: UInt16
    ) -> [ContentEntry]? {
        guard !data.isEmpty,
              data.count <= MessageLimits.maxVolumeArchiveBytes else { return nil }
        var reader = DataReader(
            data,
            maxDataPayload: UInt32(MessageLimits.maxVolumeArchiveBytes)
        )
        guard let count = reader.readUInt16(),
              count == expectedEntries,
              count > 0 else { return nil }
        var entries: [ContentEntry] = []
        entries.reserveCapacity(Int(count))
        var previous: String?
        var containsRoot = false
        for _ in 0..<count {
            guard let cid = reader.readString(),
                  let bytes = reader.readData(),
                  MessageLimits.accepts(cid),
                  previous.map({ $0 < cid }) ?? true else { return nil }
            containsRoot = containsRoot || cid == rootCID
            entries.append(ContentEntry(cid: cid, data: bytes))
            previous = cid
        }
        return containsRoot && reader.remaining == 0 ? entries : nil
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

    func matches(peer: PeerID, sessionID: Data?) -> Bool {
        candidates.contains(peer)
            && (exactSessionID.map { $0 == sessionID } ?? true)
    }
}

struct PendingVolumeRequest {
    let rootCID: String
    let generation: UInt64
    let maximumArchiveBytes: Int
    let maximumEntries: Int
    let continuation: CheckedContinuation<AttributedVolumeResponse, Never>
    var candidateSessions: [PeerID: Data]
    var assemblies: [PeerID: VolumeAssembly] = [:]
    var failure: VolumeFetchFailure? = nil
    var timeoutTask: IvyTimer? = nil

    func matches(peer: PeerID, sessionID: Data?) -> Bool {
        candidateSessions[peer] == sessionID
    }
}

struct VolumeAssembly {
    let chunkCount: UInt16
    let totalEntries: UInt16
    let totalBytes: Int
    var nextIndex: UInt16 = 0
    var archive = Data()
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
    func scheduleContentRequest(
        requestID: UInt64,
        rootCID: String,
        cids: [String],
        from peer: PeerID,
        session: AuthenticatedSession? = nil
    ) {
        guard let request = beginContentRequest(
            requestID: requestID,
            rootCID: rootCID,
            cids: cids,
            from: peer,
            session: session
        ) else { return }
        servingContentTasks[request.inbound] = Task { [weak self] in
            await self?.serveContentRequest(
                request,
                from: peer,
                session: session
            )
        }
    }

    func handleContentRequest(
        requestID: UInt64,
        rootCID: String,
        cids: [String],
        from peer: PeerID,
        session: AuthenticatedSession? = nil
    ) async {
        guard let request = beginContentRequest(
            requestID: requestID,
            rootCID: rootCID,
            cids: cids,
            from: peer,
            session: session
        ) else { return }
        await serveContentRequest(request, from: peer, session: session)
    }

    private func beginContentRequest(
        requestID: UInt64,
        rootCID: String,
        cids: [String],
        from peer: PeerID,
        session: AuthenticatedSession?
    ) -> (
        inbound: InboundContentRequest,
        requestID: UInt64,
        rootCID: String,
        key: ContentRequestKey,
        maxDataBytes: Int
    )? {
        guard MessageLimits.accepts(rootCID),
              cids.count <= Int(MessageLimits.maxContentCIDCount),
              cids.allSatisfy(MessageLimits.accepts) else { return nil }
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
            return nil
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
            return nil
        }
        return (inbound, requestID, rootCID, key, maxDataBytes)
    }

    private func serveContentRequest(
        _ request: (
            inbound: InboundContentRequest,
            requestID: UInt64,
            rootCID: String,
            key: ContentRequestKey,
            maxDataBytes: Int
        ),
        from peer: PeerID,
        session: AuthenticatedSession?
    ) async {
        let (inbound, requestID, rootCID, key, maxDataBytes) = request
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
        guard case .enqueued = sendContentReply(
            response,
            to: peer,
            session: session,
            bypassAdmission: true
        ) else {
            sendContentReply(
                .contentUnavailable(requestID: requestID),
                to: peer,
                session: session,
                bypassAdmission: true)
            return
        }
    }

    func scheduleVolumeRequest(
        requestID: UInt64,
        rootCID: String,
        from peer: PeerID,
        session: AuthenticatedSession? = nil
    ) {
        guard let inbound = beginVolumeRequest(
            requestID: requestID,
            rootCID: rootCID,
            from: peer,
            session: session
        ) else { return }
        let timeout = delayedTask(after: config.requestTimeout) { [weak self] in
            await self?.cancelServingVolume(inbound)
        }
        servingContentTasks[inbound] = Task { [weak self] in
            defer { timeout.cancel() }
            await self?.serveVolumeRequest(
                inbound: inbound,
                requestID: requestID,
                rootCID: rootCID,
                from: peer,
                session: session
            )
        }
    }

    private func cancelServingVolume(_ request: InboundContentRequest) {
        servingContentTasks[request]?.cancel()
    }

    func handleVolumeRequest(
        requestID: UInt64,
        rootCID: String,
        from peer: PeerID,
        session: AuthenticatedSession? = nil
    ) async {
        guard let inbound = beginVolumeRequest(
            requestID: requestID,
            rootCID: rootCID,
            from: peer,
            session: session
        ) else { return }
        await serveVolumeRequest(
            inbound: inbound,
            requestID: requestID,
            rootCID: rootCID,
            from: peer,
            session: session
        )
    }

    private func beginVolumeRequest(
        requestID: UInt64,
        rootCID: String,
        from peer: PeerID,
        session: AuthenticatedSession?
    ) -> InboundContentRequest? {
        guard MessageLimits.accepts(rootCID) else { return nil }
        let inbound = InboundContentRequest(
            peer: peer,
            connectionID: session?.connection.connectionID,
            requestID: requestID
        )
        guard beginServingContent(inbound) else {
            sendContentReply(
                .contentUnavailable(requestID: requestID),
                to: peer,
                session: session,
                bypassAdmission: true
            )
            return nil
        }
        return inbound
    }

    private func serveVolumeRequest(
        inbound: InboundContentRequest,
        requestID: UInt64,
        rootCID: String,
        from peer: PeerID,
        session: AuthenticatedSession?
    ) async {
        defer { endServingContent(inbound) }
        let source = contentSource
        if let source {
            guard let requester = authenticatedPeer(for: peer, session: session),
                  await source.authorizesVolumeRequest(
                    from: requester,
                    rootCID: rootCID
                  ) else {
                sendContentReply(
                    .contentUnavailable(requestID: requestID),
                    to: peer,
                    session: session,
                    bypassAdmission: true
                )
                return
            }
        }
        guard !Task.isCancelled, session.map(isCurrent) ?? true else { return }
        guard let source, reserveServingVolumeCapacity() else {
            sendContentReply(
                .contentUnavailable(requestID: requestID),
                to: peer,
                session: session,
                bypassAdmission: true
            )
            return
        }
        defer { releaseServingVolumeCapacity() }
        let entries = await source.volume(
            rootCID: rootCID,
            maxDataBytes: MessageLimits.maxVolumeArchiveBytes
        )
        guard session.map(isCurrent) ?? true,
              let archive = VolumeArchive.encode(
                entries: entries,
                rootCID: rootCID
              ),
              let payloadBytes = Message.volumeChunkDataBudget(
                rootCID: rootCID,
                maxFrameSize: IvyConfig.protocolMaxFrameSize,
                relayed: session.map { !$0.connection.isDirect }
                    ?? (endpointConnection(for: peer)?.isDirect == false)
              ),
              payloadBytes > 0 else {
            sendContentReply(
                .contentUnavailable(requestID: requestID),
                to: peer,
                session: session,
                bypassAdmission: true
            )
            return
        }
        let chunkCount = (archive.data.count + payloadBytes - 1) / payloadBytes
        guard chunkCount > 0,
              chunkCount <= Int(MessageLimits.maxVolumeChunkCount) else {
            sendContentReply(
                .contentUnavailable(requestID: requestID),
                to: peer,
                session: session,
                bypassAdmission: true
            )
            return
        }
        for index in 0..<chunkCount {
            guard !Task.isCancelled, session.map(isCurrent) ?? true else { return }
            let start = index * payloadBytes
            let end = min(start + payloadBytes, archive.data.count)
            let response = Message.volumeChunk(
                requestID: requestID,
                rootCID: rootCID,
                index: UInt16(index),
                count: UInt16(chunkCount),
                totalEntries: UInt16(archive.entries.count),
                totalBytes: UInt64(archive.data.count),
                payload: Data(archive.data[start..<end])
            )
            guard await sendVolumeChunk(
                response,
                to: peer,
                session: session
            ) else {
                sendContentReply(
                    .contentUnavailable(requestID: requestID),
                    to: peer,
                    session: session,
                    bypassAdmission: true
                )
                return
            }
        }
    }

    private func reserveServingVolumeCapacity() -> Bool {
        guard MessageLimits.maxVolumeArchiveBytes
                <= MessageLimits.maxInFlightVolumeBytes - reservedServingVolumeBytes else {
            return false
        }
        reservedServingVolumeBytes += MessageLimits.maxVolumeArchiveBytes
        return true
    }

    private func releaseServingVolumeCapacity() {
        precondition(reservedServingVolumeBytes >= MessageLimits.maxVolumeArchiveBytes)
        reservedServingVolumeBytes -= MessageLimits.maxVolumeArchiveBytes
    }

    private func sendVolumeChunk(
        _ message: Message,
        to peer: PeerID,
        session: AuthenticatedSession?
    ) async -> Bool {
        while !Task.isCancelled, session.map(isCurrent) ?? true {
            switch sendContentReply(
                message,
                to: peer,
                session: session,
                bypassAdmission: true
            ) {
            case .enqueued:
                return true
            case .backpressured:
                let writable: Bool
                if let session {
                    guard let authenticated = authenticatedPeer(
                        for: peer,
                        session: session
                    ) else { return false }
                    writable = await waitUntilWritable(to: authenticated)
                } else {
                    writable = await waitUntilWritable(to: peer)
                }
                guard writable else { return false }
            case .notConnected, .locallyRejected:
                return false
            }
        }
        return false
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
        servingContentTasks.removeValue(forKey: request)
        servingContentRequests.remove(request)
    }

    func handleContentResponse(
        requestID: UInt64,
        entries: [ContentEntry],
        from peer: PeerID,
        sessionID: Data? = nil
    ) {
        guard let pending = pendingContentRequests[requestID],
              pending.matches(peer: peer, sessionID: sessionID) else { return }
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
        if let pending = pendingVolumeRequests[requestID] {
            guard pending.matches(peer: peer, sessionID: sessionID) else { return }
            markVolumeCandidateDone(requestID: requestID, peer: peer)
            return
        }
        guard let pending = pendingContentRequests[requestID],
              pending.matches(peer: peer, sessionID: sessionID) else { return }
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

    /// Fetches one complete Volume. Provider selection may use any connected
    /// endpoint advertising the root.
    public func fetchVolume(rootCID: String) async -> AttributedVolumeResponse {
        let generation = runGeneration
        guard MessageLimits.accepts(rootCID) else { return .empty }
        if let local = await localVolume(rootCID: rootCID) { return local }
        guard isCurrentRun(generation), !Task.isCancelled,
              config.mode.usesOverlayServices || config.privateContentExchangeEnabled else {
            return .empty
        }

        let cached = cachedProviderEndpoints(rootCID: rootCID)
        await connectToProviderEndpoints(cached, generation: generation)
        guard isCurrentRun(generation), !Task.isCancelled else { return .empty }
        var candidates = Array(
            connectedProviderIDs(for: rootCID).prefix(config.maxContentCandidates)
        )
        if !candidates.isEmpty {
            let response = await fetchVolume(
                rootCID: rootCID,
                from: candidates,
                generation: generation,
                maximumArchiveBytes: MessageLimits.maxVolumeArchiveBytes,
                maximumEntries: Int(MessageLimits.maxVolumeEntryCount)
            )
            if !response.entries.isEmpty { return response }
        }

        let fresh = await queryFreshProviderEndpoints(
            rootCID: rootCID,
            generation: generation
        )
        await connectToProviderEndpoints(fresh + cached, generation: generation)
        guard isCurrentRun(generation), !Task.isCancelled else { return .empty }
        candidates = Array(
            connectedProviderIDs(for: rootCID).prefix(config.maxContentCandidates)
        )
        if !candidates.isEmpty {
            let response = await fetchVolume(
                rootCID: rootCID,
                from: candidates,
                generation: generation,
                maximumArchiveBytes: MessageLimits.maxVolumeArchiveBytes,
                maximumEntries: Int(MessageLimits.maxVolumeEntryCount)
            )
            if !response.entries.isEmpty { return response }
        }
        candidates = connectedFallbackCandidates(rootCID: rootCID, excluding: [:])
        guard !candidates.isEmpty else { return .empty }
        return await fetchVolume(
            rootCID: rootCID,
            from: candidates,
            generation: generation,
            maximumArchiveBytes: MessageLimits.maxVolumeArchiveBytes,
            maximumEntries: Int(MessageLimits.maxVolumeEntryCount)
        )
    }

    /// Fetches one complete Volume from the exact authenticated endpoint
    /// session that advertised it.
    public func fetchVolume(
        rootCID: String,
        from peer: AuthenticatedPeer
    ) async -> AttributedVolumeResponse {
        await fetchVolume(
            rootCID: rootCID,
            from: peer,
            maximumArchiveBytes: MessageLimits.maxVolumeArchiveBytes,
            maximumEntries: Int(MessageLimits.maxVolumeEntryCount)
        )
    }

    /// Fetches one complete Volume from an exact session while rejecting a
    /// response whose advertised boundary exceeds the caller's needs before
    /// allocating its archive.
    public func fetchVolume(
        rootCID: String,
        from peer: AuthenticatedPeer,
        maximumArchiveBytes: Int,
        maximumEntries: Int
    ) async -> AttributedVolumeResponse {
        guard MessageLimits.accepts(rootCID) else { return .empty }
        guard maximumArchiveBytes > 0,
              maximumArchiveBytes <= MessageLimits.maxVolumeArchiveBytes,
              maximumEntries > 0,
              maximumEntries <= Int(MessageLimits.maxVolumeEntryCount) else {
            return .empty
        }
        return await fetchVolume(
            rootCID: rootCID,
            from: [peer.id],
            generation: runGeneration,
            maximumArchiveBytes: maximumArchiveBytes,
            maximumEntries: maximumEntries,
            exactPeer: peer
        )
    }

    private func localVolume(rootCID: String) async -> AttributedVolumeResponse? {
        guard let source = contentSource else { return nil }
        guard servingContentRequests.count + activeLocalContentRequestCount
                < config.maxConcurrentContentRequests,
              reserveServingVolumeCapacity() else { return nil }
        activeLocalContentRequestCount += 1
        defer {
            activeLocalContentRequestCount -= 1
            releaseServingVolumeCapacity()
        }
        let entries = await source.volume(
            rootCID: rootCID,
            maxDataBytes: MessageLimits.maxVolumeArchiveBytes
        )
        guard let archive = VolumeArchive.encode(
            entries: entries,
            rootCID: rootCID
        ) else { return nil }
        return AttributedVolumeResponse(
            rootCID: rootCID,
            entries: Dictionary(
                uniqueKeysWithValues: archive.entries.map { ($0.cid, $0.data) }
            ),
            servedBy: nil
        )
    }

    private func fetchVolume(
        rootCID: String,
        from candidates: [PeerID],
        generation: UInt64,
        maximumArchiveBytes: Int,
        maximumEntries: Int,
        exactPeer: AuthenticatedPeer? = nil
    ) async -> AttributedVolumeResponse {
        guard isCurrentRun(generation), !Task.isCancelled else { return .empty }
        let requestID = makeWireOperationID(
            avoiding: Set(pendingContentRequests.keys).union(pendingVolumeRequests.keys)
        )
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard !Task.isCancelled, isCurrentRun(generation) else {
                    continuation.resume(returning: .empty)
                    return
                }
                guard pendingContentRequests.count + pendingVolumeRequests.count
                        < config.maxPendingRequests else {
                    continuation.resume(returning: .localCapacityUnavailable)
                    return
                }
                let message = Message.volumeRequest(
                    requestID: requestID,
                    rootCID: rootCID
                )
                var enqueued: [PeerID: Data] = [:]
                if let exactPeer {
                    if candidates == [exactPeer.id],
                       enqueueContentRequestOnCurrentSession(message, to: exactPeer) {
                        enqueued[exactPeer.id] = exactPeer.sessionID
                    }
                } else {
                    for peer in candidates {
                        if let sessionID = enqueueContentRequestOnCurrentSession(
                            message,
                            to: peer
                        ) {
                            enqueued[peer] = sessionID
                        }
                    }
                }
                guard !enqueued.isEmpty else {
                    continuation.resume(returning: .empty)
                    return
                }
                pendingVolumeRequests[requestID] = PendingVolumeRequest(
                    rootCID: rootCID,
                    generation: generation,
                    maximumArchiveBytes: maximumArchiveBytes,
                    maximumEntries: maximumEntries,
                    continuation: continuation,
                    candidateSessions: enqueued
                )
                pendingVolumeRequests[requestID]?.timeoutTask = delayedTask(
                    after: config.requestTimeout
                ) { [weak self] in
                    await self?.resolveVolumeRequest(requestID: requestID)
                }
            }
        } onCancel: {
            Task { await self.resolveVolumeRequest(requestID: requestID) }
        }
    }

    func handleVolumeChunk(
        requestID: UInt64,
        rootCID: String,
        index: UInt16,
        count: UInt16,
        totalEntries: UInt16,
        totalBytes: UInt64,
        payload: Data,
        from peer: PeerID,
        sessionID: Data?,
        relayed: Bool = false
    ) {
        guard var pending = pendingVolumeRequests[requestID],
              pending.generation == runGeneration,
              pending.matches(peer: peer, sessionID: sessionID) else {
            return
        }
        guard rootCID == pending.rootCID,
              count > 0,
              count <= MessageLimits.maxVolumeChunkCount,
              index < count,
              totalEntries > 0,
              totalBytes > 0,
              totalBytes <= UInt64(MessageLimits.maxVolumeArchiveBytes),
              !payload.isEmpty,
              let maxChunkBytes = Message.volumeChunkDataBudget(
                rootCID: rootCID,
                maxFrameSize: IvyConfig.protocolMaxFrameSize,
                relayed: relayed
              ),
              payload.count <= maxChunkBytes else {
            rejectVolumeCandidate(requestID: requestID, peer: peer)
            return
        }
        let byteCount = Int(totalBytes)
        var assembly: VolumeAssembly
        if let existing = pending.assemblies[peer] {
            assembly = existing
            guard assembly.chunkCount == count,
                  assembly.totalEntries == totalEntries,
                  assembly.totalBytes == byteCount,
                  assembly.nextIndex == index else {
                rejectVolumeCandidate(requestID: requestID, peer: peer)
                return
            }
        } else {
            guard index == 0 else {
                rejectVolumeCandidate(requestID: requestID, peer: peer)
                return
            }
            // Caller-local capacity is not part of the wire request. A
            // provider serving a globally valid complete Volume has not
            // violated protocol merely because this consumer needs less.
            guard totalEntries <= UInt16(pending.maximumEntries),
                  totalBytes <= UInt64(pending.maximumArchiveBytes) else {
                markVolumeCandidateDone(
                    requestID: requestID,
                    peer: peer,
                    failure: .callerBoundaryExceeded
                )
                return
            }
            guard byteCount <= MessageLimits.maxInFlightVolumeBytes
                    - reservedVolumeBytes else {
                markVolumeCandidateDone(
                    requestID: requestID,
                    peer: peer,
                    failure: .localCapacityUnavailable
                )
                return
            }
            assembly = VolumeAssembly(
                chunkCount: count,
                totalEntries: totalEntries,
                totalBytes: byteCount
            )
            reservedVolumeBytes += byteCount
            pending.assemblies[peer] = assembly
            pendingVolumeRequests[requestID] = pending
        }
        guard payload.count <= assembly.totalBytes - assembly.archive.count else {
            rejectVolumeCandidate(requestID: requestID, peer: peer)
            return
        }
        guard payload.count <= MessageLimits.maxInFlightVolumeBytes
                - inFlightVolumeBytes else {
            markVolumeCandidateDone(
                requestID: requestID,
                peer: peer,
                failure: .localCapacityUnavailable
            )
            return
        }
        assembly.archive.append(payload)
        assembly.nextIndex += 1
        inFlightVolumeBytes += payload.count

        if assembly.nextIndex < assembly.chunkCount {
            guard assembly.archive.count < assembly.totalBytes else {
                rejectVolumeCandidate(requestID: requestID, peer: peer)
                return
            }
            pending.assemblies[peer] = assembly
            pendingVolumeRequests[requestID] = pending
            return
        }

        guard assembly.archive.count == assembly.totalBytes,
              let entries = VolumeArchive.decode(
                assembly.archive,
                rootCID: rootCID,
                expectedEntries: totalEntries
              ) else {
            pending.assemblies[peer] = assembly
            pendingVolumeRequests[requestID] = pending
            rejectVolumeCandidate(requestID: requestID, peer: peer)
            return
        }
        pending.assemblies[peer] = assembly
        pendingVolumeRequests[requestID] = pending
        rememberProvider(rootCID: rootCID, peer: peer)
        resolveVolumeRequest(requestID: requestID, entries: entries, servedBy: peer)
    }

    func markVolumeCandidateDone(
        requestID: UInt64,
        peer: PeerID,
        failure: VolumeFetchFailure? = nil
    ) {
        guard var pending = pendingVolumeRequests[requestID],
              pending.candidateSessions.removeValue(forKey: peer) != nil else { return }
        if failure == .localCapacityUnavailable || pending.failure == nil {
            pending.failure = failure
        }
        releaseVolumeAssembly(pending.assemblies.removeValue(forKey: peer))
        pendingVolumeRequests[requestID] = pending
        if pending.candidateSessions.isEmpty {
            resolveVolumeRequest(requestID: requestID)
        }
    }

    private func rejectVolumeCandidate(requestID: UInt64, peer: PeerID) {
        tally.recordProtocolViolation(peer: peer)
        markVolumeCandidateDone(requestID: requestID, peer: peer)
    }

    private func releaseVolumeAssembly(_ assembly: VolumeAssembly?) {
        guard let assembly else { return }
        precondition(assembly.archive.count <= inFlightVolumeBytes)
        precondition(assembly.totalBytes <= reservedVolumeBytes)
        inFlightVolumeBytes -= assembly.archive.count
        reservedVolumeBytes -= assembly.totalBytes
    }

    func resolveVolumeRequest(
        requestID: UInt64,
        entries: [ContentEntry] = [],
        servedBy: PeerID? = nil
    ) {
        guard let pending = pendingVolumeRequests.removeValue(forKey: requestID) else {
            return
        }
        for assembly in pending.assemblies.values {
            releaseVolumeAssembly(assembly)
        }
        pending.timeoutTask?.cancel()
        pending.continuation.resume(returning: AttributedVolumeResponse(
            rootCID: entries.isEmpty ? "" : pending.rootCID,
            entries: Dictionary(uniqueKeysWithValues: entries.map { ($0.cid, $0.data) }),
            servedBy: servedBy,
            failure: entries.isEmpty ? pending.failure : nil
        ))
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

    func isExpectedContentReply(
        _ message: Message,
        from peer: PeerID,
        sessionID: Data?
    ) -> Bool {
        switch message {
        case .contentResponse(let requestID, _):
            return pendingContentRequests[requestID]?.matches(
                peer: peer,
                sessionID: sessionID
            ) ?? false
        case .volumeChunk(let requestID, _, _, _, _, _, _):
            return pendingVolumeRequests[requestID]?.matches(
                peer: peer,
                sessionID: sessionID
            ) ?? false
        case .contentUnavailable(let requestID):
            if let pending = pendingContentRequests[requestID],
               pending.matches(peer: peer, sessionID: sessionID) {
                return true
            }
            return pendingVolumeRequests[requestID]?.matches(
                peer: peer,
                sessionID: sessionID
            ) ?? false
        default:
            return false
        }
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
