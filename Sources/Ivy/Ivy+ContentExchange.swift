import Foundation
import NIOCore
import Tally
import Crypto

/// A volume fetch result carrying WHO served it. Volumes are locality bundles,
/// not completeness claims: their completeness/correctness is verified lazily
/// by the consumer's resolution (JIT). When resolution finds the bundle
/// deficient or falsified, the consumer reports the serving peer back via
/// `reportDeficientVolume(rootCID:peer:)` — trust is local.
public struct AttributedVolumeResponse: Sendable {
    public let entries: [String: Data]
    public let servedBy: PeerID?

    public static let empty = AttributedVolumeResponse(entries: [:], servedBy: nil)

    public init(entries: [String: Data], servedBy: PeerID?) {
        self.entries = entries
        self.servedBy = servedBy
    }
}

extension Ivy {
    // MARK: - DHT Forwarding

    func handleDHTForward(cid: String, ttl: UInt8, from peer: PeerID) async {
        guard tally.shouldAllow(peer: peer), await hasCreditCapacity(peer: peer) else {
            fireToPeer(peer, .dontHave(cid: cid), bypassBudget: true)
            return
        }

        let advertisedAvailable = haveSet.contains(cid)
        var data: Data?
        if advertisedAvailable {
            data = await getLocalBlock(cid: cid)
        }

        if let data {
            fireToPeer(peer, .block(cid: cid, data: data), bypassBudget: true)
            let cpl = Router.commonPrefixLength(router.localHash, Router.hash(cid))
            tally.recordSent(peer: peer, bytes: data.count, cpl: cpl)
            await meterSent(peer: peer, bytes: data.count)
        } else if ttl > 0 {
            guard addPendingForward(cid: cid, requester: peer) else { return }
            let cidHash = Router.hash(cid)
            let closest = router.closestPeers(to: cidHash, count: 3)
            for entry in closest {
                guard entry.id != peer, entry.id != localID else { continue }
                let reachable = connections[entry.id] != nil
                guard reachable else { continue }
                fireToPeer(entry.id, .dhtForward(cid: cid, ttl: ttl - 1))
            }
        }
        // ttl == 0 and not found: silently fail (requester has its own timeout)
    }

    func resolveForwards(cid: String, data: Data, from peer: PeerID) {
        guard let requesters = removePendingForwards(for: cid) else { return }
        let payload = Message.block(cid: cid, data: data).serialize(maxFrameSize: config.maxFrameSize)
        let cpl = Router.commonPrefixLength(router.localHash, Router.hash(cid))
        for requester in requesters.keys {
            firePayloadToPeer(requester, payload)
            tally.recordSent(peer: requester, bytes: data.count, cpl: cpl)
        }
    }

    func addPendingForward(cid: String, requester: PeerID) -> Bool {
        if pendingForwards[cid]?[requester] != nil { return true }
        guard pendingForwardCount < Self.maxPendingForwards else { return false }
        guard (pendingForwardCountsByPeer[requester] ?? 0) < Self.maxPendingForwardsPerPeer else { return false }

        nextPendingForwardGeneration &+= 1
        let generation = nextPendingForwardGeneration
        pendingForwards[cid, default: [:]][requester] = generation
        pendingForwardCountsByPeer[requester, default: 0] += 1
        pendingForwardCount += 1

        Task {
            try? await Task.sleep(for: config.requestTimeout)
            self.expirePendingForward(cid: cid, requester: requester, generation: generation)
        }
        return true
    }

    func expirePendingForward(cid: String, requester: PeerID, generation: UInt64) {
        guard pendingForwards[cid]?[requester] == generation else { return }
        removePendingForward(cid: cid, requester: requester)
    }

    func removePendingForward(cid: String, requester: PeerID) {
        guard pendingForwards[cid]?.removeValue(forKey: requester) != nil else { return }
        if pendingForwards[cid]?.isEmpty == true {
            pendingForwards.removeValue(forKey: cid)
        }
        if let count = pendingForwardCountsByPeer[requester], count > 1 {
            pendingForwardCountsByPeer[requester] = count - 1
        } else {
            pendingForwardCountsByPeer.removeValue(forKey: requester)
        }
        pendingForwardCount = max(pendingForwardCount - 1, 0)
    }

    func removePendingForwards(for cid: String) -> [PeerID: UInt64]? {
        guard let requesters = pendingForwards.removeValue(forKey: cid) else { return nil }
        for requester in requesters.keys {
            if let count = pendingForwardCountsByPeer[requester], count > 1 {
                pendingForwardCountsByPeer[requester] = count - 1
            } else {
                pendingForwardCountsByPeer.removeValue(forKey: requester)
            }
            pendingForwardCount = max(pendingForwardCount - 1, 0)
        }
        return requesters
    }

    // MARK: - want (passive responder)

    func handleWant(rootCIDs: [String], from peer: PeerID) async {
        for rootCID in rootCIDs {
            await handleWant(rootCID: rootCID, requestedCIDs: [], from: peer)
        }
    }

    func handleWant(rootCID: String, requestedCIDs: [String], from peer: PeerID) async {
        guard tally.shouldAllow(peer: peer) else { return }
        let requested = orderedRequestedCIDs(rootCID: rootCID, requestedCIDs: requestedCIDs)
        var items = await dataSource?.volumeData(for: rootCID, cids: requested) ?? []
        guard !items.isEmpty, items.contains(where: { $0.cid == rootCID }) else {
            fireToPeer(peer, .notHave(rootCID: rootCID), bypassBudget: true)
            return
        }

        items = budgetedWantItems(rootCID: rootCID, items: items)
        guard !items.isEmpty, items.contains(where: { $0.cid == rootCID }) else {
            fireToPeer(peer, .notHave(rootCID: rootCID), bypassBudget: true)
            return
        }

        fireToPeer(peer, .blocks(rootCID: rootCID, items: items))
        let totalBytes = items.reduce(0) { $0 + $1.data.count }
        if totalBytes > 0 {
            let cpl = Router.commonPrefixLength(router.localHash, Router.hash(rootCID))
            tally.recordSent(peer: peer, bytes: totalBytes, cpl: cpl)
            await meterSent(peer: peer, bytes: totalBytes)
        }
    }

    func orderedRequestedCIDs(rootCID: String, requestedCIDs: [String]) -> [String] {
        guard !requestedCIDs.isEmpty else { return [] }
        var seen: Set<String> = []
        var ordered: [String] = []
        for cid in [rootCID] + requestedCIDs where seen.insert(cid).inserted {
            ordered.append(cid)
        }
        return ordered
    }

    func budgetedWantItems(rootCID: String, items: [(cid: String, data: Data)]) -> [(cid: String, data: Data)] {
        let maxBytes = Int(config.maxFrameSize) - 1024
        let ordered = items.sorted { lhs, rhs in
            if lhs.cid == rootCID { return true }
            if rhs.cid == rootCID { return false }
            return lhs.cid < rhs.cid
        }
        var total = 0
        var result: [(cid: String, data: Data)] = []
        for item in ordered {
            let itemCost = item.cid.utf8.count + item.data.count + 8
            guard total + itemCost <= maxBytes else { continue }
            result.append(item)
            total += itemCost
        }
        return result
    }

    func handleBlocks(rootCID: String, items: [(cid: String, data: Data)], from peer: PeerID) async {
        guard pendingVolumeRequests[rootCID] != nil else { return }
        guard !items.isEmpty else {
            markVolumeCandidateDone(rootCID: rootCID, peer: peer)
            return
        }

        var result: [String: Data] = [:]
        for item in items {
            guard ContentAddressVerifier.data(item.data, matches: item.cid) else {
                tally.recordFailure(peer: peer)
                markVolumeCandidateDone(rootCID: rootCID, peer: peer)
                return
            }
            result[item.cid] = item.data
        }

        guard result[rootCID] != nil else {
            markVolumeCandidateDone(rootCID: rootCID, peer: peer)
            return
        }

        for cid in result.keys {
            haveSet.insert(cid)
        }

        var totalReceived = 0
        for item in items {
            let cpl = Router.commonPrefixLength(router.localHash, Router.hash(item.cid))
            tally.recordReceived(peer: peer, bytes: item.data.count, cpl: cpl)
            totalReceived += item.data.count
        }
        if totalReceived > 0 { await meterReceived(peer: peer, bytes: totalReceived) }
        tally.recordSuccess(peer: peer)
        recordVolumeProvider(rootCID: rootCID, peer: peer)
        resolveVolumeRequest(key: rootCID, result: result, servedBy: peer)
    }

    // MARK: - Volume-Aware Fetching

    /// Handle announceVolume: record provider, gossip to other peers.
    func handleAnnounceVolume(rootCID: String, childCIDs: [String], totalSize: UInt64, from peer: PeerID) async {
        guard tally.shouldAllow(peer: peer), admitGossipRelay(from: peer) else { return }

        // Dedup: don't process the same volume announcement twice
        let dedupKey = "vol-\(rootCID)"
        guard !haveSet.contains(dedupKey) else { return }
        haveSet.insert(dedupKey)

        recordVolumeProvider(rootCID: rootCID, peer: peer)

        // Gossip relay to other connected peers (like announceBlock)
        let payload = Message.announceVolume(rootCID: rootCID, childCIDs: childCIDs, totalSize: totalSize)
            .serialize(maxFrameSize: config.maxFrameSize)
        broadcastPayload(payload, excluding: peer)

        delegate?.ivy(self, didReceiveVolumeAnnouncement: rootCID, childCIDs: childCIDs, totalSize: totalSize, from: peer)
    }

    func handlePushVolume(rootCID: String, items: [(cid: String, data: Data)], from peer: PeerID) async {
        guard tally.shouldAllow(peer: peer), admitGossipRelay(from: peer) else { return }

        let dedupKey = "vol-\(rootCID)"
        guard !haveSet.contains(dedupKey) else { return }

        let childCIDs = items.map(\.cid)
        var totalSize: UInt64 = 0
        var verifiedCIDs: [String] = []

        guard items.contains(where: { $0.cid == rootCID }) else {
            tally.recordFailure(peer: peer)
            return
        }
        for (cid, data) in items {
            guard ContentAddressVerifier.data(data, matches: cid) else {
                tally.recordFailure(peer: peer)
                return
            }
            verifiedCIDs.append(cid)
            totalSize += UInt64(data.count)
        }
        for cid in verifiedCIDs {
            haveSet.insert(cid)
        }
        haveSet.insert(dedupKey)
        recordVolumeProvider(rootCID: rootCID, peer: peer)

        let totalBytes = items.reduce(0) { $0 + $1.data.count }
        let cpl = Router.commonPrefixLength(router.localHash, Router.hash(rootCID))
        tally.recordReceived(peer: peer, bytes: totalBytes, cpl: cpl)
        tally.recordSuccess(peer: peer)

        let announcePayload = Message.announceVolume(rootCID: rootCID, childCIDs: childCIDs, totalSize: totalSize)
            .serialize(maxFrameSize: config.maxFrameSize)
        broadcastPayload(announcePayload, excluding: peer)

        delegate?.ivy(self, didReceiveVolumeAnnouncement: rootCID, childCIDs: childCIDs, totalSize: totalSize, from: peer)
    }

    /// Record that a peer served content belonging to a volume (provider memory).
    func recordVolumeProvider(rootCID: String, peer: PeerID) {
        var providers = providerRecords[rootCID] ?? []
        if !providers.contains(peer) {
            providers.append(peer)
            if providers.count > 8 { providers = Array(providers.suffix(8)) }
            providerRecords[rootCID] = providers
        }
    }

    /// Fetch from all directly connected peers — no DHT lookup.
    /// Registers the continuation before any async work so cleanupAllPending
    /// can cancel it immediately without waiting for a DHT timeout.
    public func fetchVolumeFromAllPeers(rootCID: String) async -> [String: Data] {
        await fetchVolumeFromAllPeersAttributed(rootCID: rootCID).entries
    }

    /// Attributed variant: returns WHO served the bundle so the consumer's
    /// resolution can report a deficient/falsified volume back to its server
    /// (`reportDeficientVolume`). A retry routes around recently-deficient peers
    /// automatically — candidate selection skips suppressed peers for this root.
    /// Advisory: if suppression would empty the candidate set (single-peer
    /// topologies), fall back to all peers — a deficiency may have been transient
    /// and retrying the only peer beats guaranteed failure.
    public func fetchVolumeFromAllPeersAttributed(
        rootCID: String
    ) async -> AttributedVolumeResponse {
        let all = Array(connections.keys) + Array(localPeers.keys)
        var candidates = all.filter { !isDeficiencySuppressed(rootCID: rootCID, peer: $0) }
        if candidates.isEmpty { candidates = all }
        guard !candidates.isEmpty else { return .empty }
        return await fetchWithCandidates(rootCID: rootCID, candidates: candidates)
    }

    public func fetchVolume(rootCID: String) async -> [String: Data] {
        if let entries = await dataSource?.volumeData(for: rootCID, cids: []), !entries.isEmpty {
            var result: [String: Data] = [:]
            for item in entries { result[item.cid] = item.data }
            return result
        }
        return await fetchVolumeFromNetwork(rootCID: rootCID).entries
    }

    /// Single-phase content fetch. Sends `want([rootCID])` to candidates and
    /// waits for the first `blocks` response. Candidates are selected in order:
    /// 1. Locally-known providers (provider records + pin announcements + DHT)
    /// 2. All direct peers capped at maxWantCandidates
    ///
    /// Coalescing: if a waiter for this rootCID already exists, joins it without
    /// sending new messages. First responder wakes all coalesced waiters.
    func fetchVolumeFromNetwork(rootCID: String, requestedCIDs: [String] = []) async -> AttributedVolumeResponse {
        // Coalesce: join an existing in-flight request for the same content.
        if let existing = pendingVolumeRequests[rootCID] {
            guard existing.continuations.count < config.maxWaitersPerPendingCID else { return .empty }
            return await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in
                    guard !Task.isCancelled else { continuation.resume(returning: .empty); return }
                    pendingVolumeRequests[rootCID]?.continuations.append(continuation)
                }
            } onCancel: {
                Task { await self.resolveVolumeRequestsForRoot(rootCID: rootCID) }
            }
        }

        // Build candidate list: known providers first, then broadcast fallback.
        var candidates: [PeerID] = []
        var seen: Set<String> = []

        for p in providerRecords[rootCID] ?? [] {
            guard connections[p] != nil || localPeers[p] != nil else { continue }
            guard tally.shouldAllow(peer: p) else { continue }
            guard !isDeficiencySuppressed(rootCID: rootCID, peer: p) else { continue }
            if seen.insert(p.publicKey).inserted { candidates.append(p) }
        }
        for pk in storedPinAnnouncements(for: rootCID) {
            let pid = PeerID(publicKey: pk)
            guard connections[pid] != nil || localPeers[pid] != nil else { continue }
            guard tally.shouldAllow(peer: pid) else { continue }
            guard !isDeficiencySuppressed(rootCID: rootCID, peer: pid) else { continue }
            if seen.insert(pid.publicKey).inserted { candidates.append(pid) }
        }
        if candidates.count < 2 {
            let discovered = await findPinnersViaDHT(rootCID: rootCID)
            for pid in discovered {
                guard connections[pid] != nil || localPeers[pid] != nil else { continue }
                guard tally.shouldAllow(peer: pid) else { continue }
                guard !isDeficiencySuppressed(rootCID: rootCID, peer: pid) else { continue }
                if seen.insert(pid.publicKey).inserted { candidates.append(pid) }
            }
        }
        // Broadcast fallback: direct peers capped at maxWantCandidates
        if candidates.isEmpty {
            let allPeers = Array(connections.keys) + Array(localPeers.keys)
            for p in allPeers {
                guard tally.shouldAllow(peer: p) else { continue }
                guard !isDeficiencySuppressed(rootCID: rootCID, peer: p) else { continue }
                if seen.insert(p.publicKey).inserted { candidates.append(p) }
                if candidates.count >= config.maxWantCandidates { break }
            }
        }
        // Advisory last resort: suppression emptied the candidate set (every
        // holder is recently-deficient for this root). Don't strand — retry the
        // suppressed peers; a deficiency may have been transient, and this beats
        // guaranteed failure. Tally demotion still compounds for repeat liars.
        if candidates.isEmpty {
            let allPeers = Array(connections.keys) + Array(localPeers.keys)
            for p in allPeers {
                guard tally.shouldAllow(peer: p) else { continue }
                if seen.insert(p.publicKey).inserted { candidates.append(p) }
                if candidates.count >= config.maxWantCandidates { break }
            }
        }

        guard !candidates.isEmpty else { return .empty }
        return await fetchWithCandidates(rootCID: rootCID, candidates: candidates, requestedCIDs: requestedCIDs)
    }

    /// Core send-and-wait: register continuation, send `want` to candidates,
    /// first `blocks` response wins. Re-checks coalescing inside the continuation
    /// to handle races where a concurrent fetch registered while we were in async
    /// candidate discovery (e.g., the DHT lookup in fetchVolumeFromNetwork).
    func fetchWithCandidates(rootCID: String, candidates: [PeerID], requestedCIDs: [String] = []) async -> AttributedVolumeResponse {
        // Coalesce: join an existing in-flight request for this content.
        if let existing = pendingVolumeRequests[rootCID] {
            guard existing.continuations.count < config.maxWaitersPerPendingCID else { return .empty }
            return await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in
                    guard !Task.isCancelled else { continuation.resume(returning: .empty); return }
                    pendingVolumeRequests[rootCID]?.continuations.append(continuation)
                }
            } onCancel: {
                Task { await self.resolveVolumeRequestsForRoot(rootCID: rootCID) }
            }
        }

        guard pendingVolumeRequests.count < config.maxPendingRequests else { return .empty }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard !Task.isCancelled else { continuation.resume(returning: .empty); return }
                // Re-check: a concurrent fetch may have registered while we were in async work.
                if pendingVolumeRequests[rootCID] != nil {
                    pendingVolumeRequests[rootCID]?.continuations.append(continuation)
                    return
                }
                pendingVolumeRequests[rootCID] = PendingVolumeRequest(
                    continuations: [continuation],
                    candidates: Set(candidates)
                )
                let message: Message
                if requestedCIDs.isEmpty {
                    message = .want(rootCIDs: [rootCID])
                } else {
                    message = .wantVolume(rootCID: rootCID, cids: requestedCIDs)
                }
                let payload = message.serialize(maxFrameSize: config.maxFrameSize)
                for peer in candidates {
                    if let conn = connections[peer] {
                        conn.fireAndForget(payload)
                    } else if let local = localPeers[peer] {
                        local.send(message)
                    }
                }
                Task {
                    try? await Task.sleep(for: self.config.requestTimeout)
                    self.resolveVolumeRequest(key: rootCID, result: [:])
                }
            }
        } onCancel: {
            Task { await self.resolveVolumeRequestsForRoot(rootCID: rootCID) }
        }
    }

    func handleNotHave(rootCID: String, from peer: PeerID) {
        markVolumeCandidateDone(rootCID: rootCID, peer: peer)
    }

    public func recordProvider(rootCID: String, peer: PeerID) {
        recordVolumeProvider(rootCID: rootCID, peer: peer)
    }

    /// P-1003: batch variant — record one peer as provider for multiple CIDs in
    /// a single actor hop instead of N sequential `recordProvider` calls.
    public func recordProviders(rootCIDs: [String], peer: PeerID) {
        for cid in rootCIDs where !cid.isEmpty {
            recordVolumeProvider(rootCID: cid, peer: peer)
        }
    }

    public func fetchVolume(rootCID: String, childCIDs: [String]) async -> [String: Data] {
        var result: [String: Data] = [:]
        var missing: [String] = []
        for cid in childCIDs {
            if let data = await getLocalBlock(cid: cid) {
                result[cid] = data
            } else {
                missing.append(cid)
            }
        }
        guard !missing.isEmpty else { return result }
        let requested = orderedRequestedCIDs(rootCID: rootCID, requestedCIDs: missing)
        let networkResult = await fetchVolumeFromNetwork(rootCID: rootCID, requestedCIDs: requested).entries
        if let data = networkResult[rootCID] {
            result[rootCID] = data
        }
        for cid in missing {
            if let data = networkResult[cid] { result[cid] = data }
        }
        return result
    }

    /// Resolves the pending volume request for a given rootCID. Volume requests
    /// are keyed by content, not by the peer that may serve it.
    func resolveVolumeRequestsForRoot(rootCID: String) {
        resolveVolumeRequest(key: rootCID, result: [:])
    }

    /// Returns true if a new continuation can be appended to `pendingRequests[cid]`.
    /// Rejects when either the per-CID waiter list or the global pending-map
    /// capacity would be exceeded.
    func canRegisterPending(cid: String) -> Bool {
        if let existing = pendingRequests[cid] {
            return existing.count < config.maxWaitersPerPendingCID
        }
        return pendingRequests.count < config.maxPendingRequests
    }

    func markVolumeCandidateDone(rootCID: String, peer: PeerID) {
        guard var request = pendingVolumeRequests[rootCID] else { return }
        request.candidates.remove(peer)
        if request.candidates.isEmpty {
            resolveVolumeRequest(key: rootCID, result: [:])
        } else {
            pendingVolumeRequests[rootCID] = request
        }
    }

    func resolveVolumeRequest(key: String, result: [String: Data], servedBy: PeerID? = nil) {
        guard let request = pendingVolumeRequests.removeValue(forKey: key) else { return }
        let response = AttributedVolumeResponse(entries: result, servedBy: servedBy)
        for cont in request.continuations {
            cont.resume(returning: response)
        }
    }

    /// JIT resolution verdict from the consumer: the volume `peer` served for
    /// `rootCID` did not resolve — entries the closure needed were missing, or
    /// content was falsified at a level only typed resolution can see. Demote
    /// the peer in Tally and forget it as a provider for this root, so future
    /// fetches prefer peers whose bundles actually resolve. Trust is local:
    /// nothing is stored about the volume itself — only about the peer.
    public func reportDeficientVolume(rootCID: String, peer: PeerID) {
        tally.recordFailure(peer: peer)
        if var providers = providerRecords[rootCID] {
            providers.removeAll { $0 == peer }
            if providers.isEmpty {
                providerRecords.removeValue(forKey: rootCID)
            } else {
                providerRecords[rootCID] = providers
            }
        }
        // Short-lived per-root suppression: the next fetch for this root routes
        // around `peer` without any per-call exclusion parameter. Self-healing
        // via the window so a transient miss doesn't permanently strand a peer.
        deficientPeerSuppression[rootCID, default: [:]][peer.publicKey] =
            ContinuousClock.Instant.now + Self.deficiencySuppressionWindow
    }

    /// True iff `peer` is within its deficiency-suppression window for `rootCID`.
    /// Lazily prunes expired entries so the map can't grow unbounded.
    func isDeficiencySuppressed(rootCID: String, peer: PeerID) -> Bool {
        guard var byPeer = deficientPeerSuppression[rootCID] else { return false }
        let now = ContinuousClock.Instant.now
        if let until = byPeer[peer.publicKey], now < until { return true }
        byPeer = byPeer.filter { _, until in now < until }
        if byPeer.isEmpty {
            deficientPeerSuppression.removeValue(forKey: rootCID)
        } else {
            deficientPeerSuppression[rootCID] = byPeer
        }
        return false
    }

    /// Get known providers for a volume.
    public func providers(for rootCID: String) -> [PeerID] {
        providerRecords[rootCID] ?? []
    }
}
