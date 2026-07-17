import Foundation
import Tally

struct ProviderHint: Sendable, Equatable {
    let peer: PeerID
    let endpoint: PeerEndpoint?
    let expiresAt: UInt64
}

struct PendingProviderQuery {
    let requestID: UInt64
    var continuations: [CheckedContinuation<[PeerEndpoint], Never>]
    var expectedPeers: Set<String>
    var endpoints: Set<PeerEndpoint>
}

extension Ivy {
    static let providerObservationTTL: UInt64 = 20 * 60
    static let maxProviderTTL: UInt64 = 24 * 60 * 60

    func handleFindProviders(rootCID: String, requestID: UInt64, from peer: PeerID) {
        evictExpiredProviders(rootCID: rootCID)
        let records = (providerHints[rootCID] ?? []).compactMap { hint -> ProviderRecord? in
            guard let endpoint = hint.endpoint else { return nil }
            return ProviderRecord(endpoint: endpoint, expiresAt: hint.expiresAt)
        }
        fireToPeer(
            peer,
            .providers(rootCID: rootCID, requestID: requestID, records: records))
    }

    func handleProvidersResponse(
        rootCID: String,
        requestID: UInt64,
        records: [ProviderRecord],
        from peer: PeerID
    ) {
        guard var pending = pendingProviderQueries[rootCID],
              pending.requestID == requestID,
              pending.expectedPeers.remove(peer.publicKey) != nil else { return }

        for record in records.prefix(Int(MessageLimits.maxNeighborCount)) {
            let endpoint = record.endpoint
            guard providerExpiryIsValid(record.expiresAt),
                  isAcceptableDiscoveredEndpoint(
                    endpoint,
                    provenance: .referral("provider"),
                    from: peer),
                  let key = try? PeerKey(endpoint.publicKey) else { continue }
            let canonical = PeerEndpoint(
                publicKey: key.hex,
                host: endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines),
                port: endpoint.port)
            pending.endpoints.insert(canonical)
            storeProviderHint(
                rootCID: rootCID,
                peer: key.peerID,
                endpoint: canonical,
                expiresAt: record.expiresAt)
        }

        pendingProviderQueries[rootCID] = pending
        if pending.expectedPeers.isEmpty {
            resolveProviderQuery(rootCID: rootCID, requestID: requestID)
        }
    }

    func handleAnnounceProvider(rootCID: String, expiresAt: UInt64, from peer: PeerID) {
        guard providerExpiryIsValid(expiresAt),
              shouldStoreProviderHint(rootCID: rootCID) else { return }
        storeProviderHint(
            rootCID: rootCID,
            peer: peer,
            endpoint: providerEndpoint(for: peer),
            expiresAt: expiresAt)
    }

    public func announceProvider(rootCID: String, expiresAt: UInt64) {
        guard MessageLimits.accepts(rootCID), providerExpiryIsValid(expiresAt) else { return }
        if let endpoint = localProviderEndpoint() {
            storeProviderHint(
                rootCID: rootCID,
                peer: localID,
                endpoint: endpoint,
                expiresAt: expiresAt)
        }
        let message = Message.announceProvider(rootCID: rootCID, expiresAt: expiresAt)
        for entry in router.closestPeers(to: Router.hash(rootCID), count: config.kBucketSize)
            where hasEndpointSession(entry.id) {
            fireToPeer(entry.id, message)
        }
    }

    public func discoverProviders(rootCID: String) async -> [PeerEndpoint] {
        let generation = runGeneration
        guard MessageLimits.accepts(rootCID) else { return [] }
        let cached = cachedProviderEndpoints(rootCID: rootCID)
        return cached.isEmpty
            ? uniqueProviderEndpoints(await queryFreshProviderEndpoints(
                rootCID: rootCID,
                generation: generation))
            : cached
    }

    func cachedProviderEndpoints(rootCID: String) -> [PeerEndpoint] {
        evictExpiredProviders(rootCID: rootCID)
        return uniqueProviderEndpoints((providerHints[rootCID] ?? []).compactMap(\.endpoint))
    }

    func queryFreshProviderEndpoints(
        rootCID: String,
        generation: UInt64
    ) async -> [PeerEndpoint] {
        guard isCurrentRun(generation), MessageLimits.accepts(rootCID) else { return [] }
        var targets = providerLookupTargets(rootCID: rootCID)
        if targets.isEmpty {
            _ = await findNode(target: rootCID, generation: generation)
            guard isCurrentRun(generation) else { return [] }
            targets = providerLookupTargets(rootCID: rootCID)
        }
        return await queryProviders(
            rootCID: rootCID,
            targets: targets,
            generation: generation)
    }

    private func uniqueProviderEndpoints(_ endpoints: [PeerEndpoint]) -> [PeerEndpoint] {
        var seen: Set<String> = []
        return endpoints.filter { seen.insert($0.publicKey).inserted }
    }

    func queryProviders(
        rootCID: String,
        targets: [Router.BucketEntry],
        generation: UInt64? = nil
    ) async -> [PeerEndpoint] {
        if let generation, !isCurrentRun(generation) { return [] }
        guard !targets.isEmpty,
              pendingProviderQueries[rootCID] != nil
                || pendingProviderQueries.count < config.maxPendingRequests else { return [] }
        if let pending = pendingProviderQueries[rootCID],
           pending.continuations.count >= config.maxWaitersPerRequest {
            return []
        }

        let endpoints = await withCheckedContinuation { continuation in
            if var pending = pendingProviderQueries[rootCID] {
                let newTargets = targets.filter {
                    !pending.expectedPeers.contains($0.id.publicKey)
                }
                pending.continuations.append(continuation)
                pending.expectedPeers.formUnion(newTargets.map { $0.id.publicKey })
                pendingProviderQueries[rootCID] = pending
                for target in newTargets {
                    fireToPeer(
                        target.id,
                        .findProviders(rootCID: rootCID, requestID: pending.requestID))
                }
                return
            }

            let requestID = makeProviderRequestID()
            pendingProviderQueries[rootCID] = PendingProviderQuery(
                requestID: requestID,
                continuations: [continuation],
                expectedPeers: Set(targets.map { $0.id.publicKey }),
                endpoints: [])
            for target in targets {
                fireToPeer(
                    target.id,
                    .findProviders(rootCID: rootCID, requestID: requestID))
            }
            Task { [weak self] in
                do {
                    try await Task.sleep(for: .milliseconds(500))
                } catch {
                    return
                }
                await self?.resolveProviderQuery(rootCID: rootCID, requestID: requestID)
            }
        }
        if let generation, !isCurrentRun(generation) { return [] }
        return endpoints
    }

    private func makeProviderRequestID() -> UInt64 {
        var requestID = UInt64.random(in: 1 ... .max)
        while pendingProviderQueries.values.contains(where: { $0.requestID == requestID }) {
            requestID = UInt64.random(in: 1 ... .max)
        }
        return requestID
    }

    func resolveProviderQuery(rootCID: String, requestID: UInt64) {
        guard let pending = pendingProviderQueries[rootCID],
              pending.requestID == requestID else { return }
        pendingProviderQueries.removeValue(forKey: rootCID)
        let endpoints = pending.endpoints.sorted {
            ($0.publicKey, $0.host, $0.port) < ($1.publicKey, $1.host, $1.port)
        }
        for continuation in pending.continuations {
            continuation.resume(returning: endpoints)
        }
    }

    func providerLookupTargets(rootCID: String) -> [Router.BucketEntry] {
        let count = min(6, max(1, config.kBucketSize))
        return router.closestPeers(to: Router.hash(rootCID), count: count).filter {
            hasEndpointSession($0.id)
        }
    }

    func connectToProviderEndpoints(
        _ endpoints: [PeerEndpoint],
        generation: UInt64
    ) async -> Set<PeerEndpoint> {
        guard isCurrentRun(generation) else { return [] }
        let candidates = uniqueProviderEndpoints(endpoints).filter {
            !hasEndpointSession(PeerID(publicKey: $0.publicKey))
        }.prefix(config.maxContentCandidates)
        await withTaskGroup(of: Void.self) { group in
            for endpoint in candidates {
                group.addTask { [weak self] in
                    guard let self,
                          await self.isCurrentRun(generation) else { return }
                    _ = try? await self.connectEndpointIfAdmitted(
                        to: endpoint,
                        allowRelayFallback: true,
                        requiredGeneration: generation)
                }
            }
        }
        return isCurrentRun(generation) ? Set(candidates) : []
    }

    public func rememberProvider(rootCID: String, peer: PeerID) {
        guard MessageLimits.accepts(rootCID), hasEndpointSession(peer) else { return }
        storeProviderHint(
            rootCID: rootCID,
            peer: peer,
            endpoint: providerEndpoint(for: peer),
            expiresAt: nowUnix() + Self.providerObservationTTL)
    }

    func storeProviderHint(
        rootCID: String,
        peer: PeerID,
        endpoint: PeerEndpoint?,
        expiresAt: UInt64
    ) {
        if providerHints[rootCID] == nil,
           providerHints.count >= Self.maxProviderRoots,
           let evicted = providerHints.keys.first {
            providerHints.removeValue(forKey: evicted)
        }
        var hints = providerHints[rootCID] ?? []
        hints.removeAll { $0.peer == peer }
        hints.append(ProviderHint(peer: peer, endpoint: endpoint, expiresAt: expiresAt))
        if hints.count > config.kBucketSize {
            hints = Array(hints.suffix(config.kBucketSize))
        }
        providerHints[rootCID] = hints
    }

    func forgetProvider(rootCID: String, peer: PeerID) {
        guard var hints = providerHints[rootCID] else { return }
        hints.removeAll { $0.peer == peer }
        if hints.isEmpty {
            providerHints.removeValue(forKey: rootCID)
        } else {
            providerHints[rootCID] = hints
        }
    }

    func connectedProviderIDs(for rootCID: String) -> [PeerID] {
        evictExpiredProviders(rootCID: rootCID)
        return (providerHints[rootCID] ?? []).compactMap { hint in
            guard hasEndpointSession(hint.peer),
                  !isDeficiencySuppressed(rootCID: rootCID, peer: hint.peer) else { return nil }
            return hint.peer
        }
    }

    public func providers(for rootCID: String) -> [PeerID] {
        evictExpiredProviders(rootCID: rootCID)
        return (providerHints[rootCID] ?? []).map(\.peer)
    }

    func evictExpiredProviders(rootCID: String) {
        guard var hints = providerHints[rootCID] else { return }
        let now = nowUnix()
        hints.removeAll { $0.expiresAt <= now }
        if hints.isEmpty {
            providerHints.removeValue(forKey: rootCID)
        } else {
            providerHints[rootCID] = hints
        }
    }

    func shouldStoreProviderHint(rootCID: String) -> Bool {
        let keyHash = Router.hash(rootCID)
        let peers = router.allPeers()
        guard peers.count >= config.kBucketSize,
              let farthest = router.closestPeers(to: keyHash, count: config.kBucketSize).last else {
            return true
        }
        return Router.isCloser(router.localHash, than: farthest.hash, to: keyHash)
    }

    func providerExpiryIsValid(_ expiresAt: UInt64) -> Bool {
        let now = nowUnix()
        return expiresAt > now && expiresAt <= now + Self.maxProviderTTL
    }

    func localProviderEndpoint() -> PeerEndpoint? {
        if let external = config.externalAddress {
            return PeerEndpoint(publicKey: localKey.hex, host: external.host, port: external.port)
        }
        if let publicAddress {
            return PeerEndpoint(publicKey: localKey.hex, host: publicAddress.host, port: publicAddress.port)
        }
        return nil
    }

    func providerEndpoint(for peer: PeerID) -> PeerEndpoint? {
        guard let endpoint = connections[peer]?.endpoint,
              !endpoint.host.isEmpty,
              endpoint.host != "unknown",
              endpoint.port != 0 else { return nil }
        return endpoint
    }

    func nowUnix() -> UInt64 {
        UInt64(Date().timeIntervalSince1970)
    }
}
