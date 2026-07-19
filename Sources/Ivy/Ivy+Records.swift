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
    var responsesByPeer: [String: [ProviderHint]]
    var timeoutTask: IvyTimer? = nil
}

extension Ivy {
    static let providerObservationTTL: UInt64 = 20 * 60
    static let maxProviderTTL: UInt64 = 24 * 60 * 60

    func handleFindProviders(rootCID: String, requestID: UInt64, from peer: PeerID) {
        guard config.mode.usesOverlayServices else { return }
        evictExpiredProviders(rootCID: rootCID)
        let records = providerRecordsForWire(providerHints[rootCID] ?? [])
        fireToPeer(
            peer,
            .providers(rootCID: rootCID, requestID: requestID, records: records))
    }

    func providerRecordsForWire(_ hints: [ProviderHint]) -> [ProviderRecord] {
        let records = hints.compactMap { hint -> ProviderRecord? in
            guard let endpoint = hint.endpoint else { return nil }
            return ProviderRecord(endpoint: endpoint, expiresAt: hint.expiresAt)
        }.sorted {
            ($0.endpoint.publicKey, $0.endpoint.host, $0.endpoint.port)
                < ($1.endpoint.publicKey, $1.endpoint.host, $1.endpoint.port)
        }
        let byIdentity = Dictionary(grouping: records, by: \.endpoint.publicKey)
        var selected: [ProviderRecord] = []
        for index in 0..<Self.maxRoutesPerIdentity {
            for identity in byIdentity.keys.sorted()
                where selected.count < Int(MessageLimits.maxNeighborCount) {
                let routes = byIdentity[identity] ?? []
                if routes.indices.contains(index) { selected.append(routes[index]) }
            }
        }
        return selected
    }

    func handleProvidersResponse(
        rootCID: String,
        requestID: UInt64,
        records: [ProviderRecord],
        from peer: PeerID
    ) {
        guard config.mode.usesOverlayServices,
              var pending = pendingProviderQueries[rootCID],
              pending.requestID == requestID,
              pending.expectedPeers.remove(peer.publicKey) != nil else { return }

        var accepted: [ProviderHint] = []
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
            accepted.append(ProviderHint(
                peer: key.peerID,
                endpoint: canonical,
                expiresAt: record.expiresAt))
        }

        pending.responsesByPeer[peer.publicKey] = boundedProviderHints(accepted)
        pendingProviderQueries[rootCID] = pending
        if pending.expectedPeers.isEmpty {
            resolveProviderQuery(rootCID: rootCID, requestID: requestID)
        }
    }

    func handleAnnounceProvider(rootCID: String, expiresAt: UInt64, from peer: PeerID) {
        guard config.mode.usesOverlayServices,
              providerExpiryIsValid(expiresAt),
              shouldStoreProviderHint(rootCID: rootCID) else { return }
        storeProviderHint(
            rootCID: rootCID,
            peer: peer,
            endpoint: providerEndpoint(for: peer),
            expiresAt: expiresAt)
    }

    public func announceProvider(rootCID: String, expiresAt: UInt64) {
        guard config.mode.usesOverlayServices,
              MessageLimits.accepts(rootCID),
              providerExpiryIsValid(expiresAt) else { return }
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
        guard config.mode.usesOverlayServices, MessageLimits.accepts(rootCID) else { return [] }
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
        guard config.mode.usesOverlayServices,
              isCurrentRun(generation),
              MessageLimits.accepts(rootCID) else { return [] }
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
        var seen: Set<PeerEndpoint> = []
        return endpoints.filter { seen.insert($0).inserted }
    }

    func queryProviders(
        rootCID: String,
        targets: [Router.BucketEntry],
        generation: UInt64? = nil
    ) async -> [PeerEndpoint] {
        if let generation, !isCurrentRun(generation) { return [] }
        var seenTargets: Set<String> = []
        let boundedTargets = targets.filter {
            seenTargets.insert($0.id.publicKey).inserted
        }.prefix(min(6, max(1, config.kBucketSize)))
        guard !boundedTargets.isEmpty,
              pendingProviderQueries[rootCID] != nil
                || pendingProviderQueries.count < config.maxPendingRequests else { return [] }
        if let pending = pendingProviderQueries[rootCID],
           pending.continuations.count >= config.maxWaitersPerRequest {
            return []
        }

        let endpoints = await withCheckedContinuation { continuation in
            if var pending = pendingProviderQueries[rootCID] {
                pending.continuations.append(continuation)
                pendingProviderQueries[rootCID] = pending
                return
            }

            let requestID = makeProviderRequestID()
            var pending = PendingProviderQuery(
                requestID: requestID,
                continuations: [continuation],
                expectedPeers: [],
                responsesByPeer: [:])
            for target in boundedTargets {
                if case .enqueued = fireToPeer(
                    target.id,
                    .findProviders(rootCID: rootCID, requestID: requestID)) {
                    pending.expectedPeers.insert(target.id.publicKey)
                }
            }
            guard !pending.expectedPeers.isEmpty else {
                continuation.resume(returning: [])
                return
            }
            pendingProviderQueries[rootCID] = pending
            let timeoutTask = delayedTask(after: .milliseconds(500)) { [weak self] in
                await self?.resolveProviderQuery(rootCID: rootCID, requestID: requestID)
            }
            pendingProviderQueries[rootCID]?.timeoutTask = timeoutTask
        }
        if let generation, !isCurrentRun(generation) { return [] }
        return endpoints
    }

    private func makeProviderRequestID() -> UInt64 {
        makeWireOperationID { requestID in
            pendingProviderQueries.values.contains { $0.requestID == requestID }
        }
    }

    func resolveProviderQuery(rootCID: String, requestID: UInt64) {
        guard let pending = pendingProviderQueries[rootCID],
              pending.requestID == requestID else { return }
        pendingProviderQueries.removeValue(forKey: rootCID)
        pending.timeoutTask?.cancel()
        let hints = diversifiedProviderHints(pending.responsesByPeer)
        for hint in hints {
            storeProviderHint(
                rootCID: rootCID,
                peer: hint.peer,
                endpoint: hint.endpoint,
                expiresAt: hint.expiresAt)
        }
        let endpoints = hints.compactMap(\.endpoint)
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
    ) async {
        guard isCurrentRun(generation) else { return }
        var alternativesByPeer: [String: [PeerEndpoint]] = [:]
        var peerOrder: [String] = []
        for endpoint in uniqueProviderEndpoints(endpoints) {
            if alternativesByPeer[endpoint.publicKey] == nil {
                peerOrder.append(endpoint.publicKey)
            }
            alternativesByPeer[endpoint.publicKey, default: []].append(endpoint)
        }
        let candidates = Array(peerOrder.compactMap { key -> [PeerEndpoint]? in
            guard !hasEndpointSession(PeerID(publicKey: key)) else { return nil }
            return alternativesByPeer[key].map {
                Array($0.prefix(Self.maxRoutesPerIdentity))
            }
        }.prefix(config.maxContentCandidates))

        await withTaskGroup(of: Void.self) { group in
            for alternatives in candidates {
                group.addTask { [weak self] in
                    guard let self else { return }
                    _ = try? await self.connectEndpointIfAdmitted(
                        to: alternatives,
                        requiredGeneration: generation)
                }
            }
        }
    }

    public func rememberProvider(rootCID: String, peer: PeerID) {
        guard config.mode.usesOverlayServices,
              MessageLimits.accepts(rootCID),
              hasEndpointSession(peer) else { return }
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
           let evicted = providerHints.min(by: { left, right in
               let leftExpiry = left.value.map(\.expiresAt).max() ?? 0
               let rightExpiry = right.value.map(\.expiresAt).max() ?? 0
               return leftExpiry == rightExpiry
                   ? left.key < right.key
                   : leftExpiry < rightExpiry
           })?.key {
            providerHints.removeValue(forKey: evicted)
        }
        providerHints[rootCID] = boundedProviderHints(
            (providerHints[rootCID] ?? []) + [ProviderHint(
                peer: peer,
                endpoint: endpoint,
                expiresAt: expiresAt)])
    }

    private func boundedProviderHints(_ input: [ProviderHint]) -> [ProviderHint] {
        var peerOrder: [PeerID] = []
        var routesByPeer: [PeerID: [ProviderHint]] = [:]
        for hint in input {
            peerOrder.removeAll { $0 == hint.peer }
            peerOrder.append(hint.peer)
            var routes = routesByPeer[hint.peer] ?? []
            routes.removeAll { $0.endpoint == hint.endpoint }
            routes.append(hint)
            routesByPeer[hint.peer] = Array(routes.suffix(Self.maxRoutesPerIdentity))
        }
        return peerOrder.suffix(config.kBucketSize).flatMap { routesByPeer[$0] ?? [] }
    }

    private func diversifiedProviderHints(
        _ responses: [String: [ProviderHint]]
    ) -> [ProviderHint] {
        let sources = responses.keys.sorted()
        var indices = Dictionary(uniqueKeysWithValues: sources.map { ($0, 0) })
        var selectedPeers: Set<PeerID> = []
        var peers: [PeerID] = []

        while selectedPeers.count < config.kBucketSize {
            var madeProgress = false
            for source in sources {
                let hints = responses[source] ?? []
                var index = indices[source] ?? 0
                while index < hints.count {
                    let hint = hints[index]
                    index += 1
                    if selectedPeers.insert(hint.peer).inserted {
                        peers.append(hint.peer)
                        madeProgress = true
                        break
                    }
                }
                indices[source] = index
                if selectedPeers.count == config.kBucketSize { break }
            }
            if !madeProgress { break }
        }

        var selected: [ProviderHint] = []
        var seenEndpoints: Set<PeerEndpoint> = []
        for routeIndex in 0..<Self.maxRoutesPerIdentity {
            for peer in peers {
                for source in sources {
                    let routes = (responses[source] ?? []).filter { $0.peer == peer }
                    guard routes.indices.contains(routeIndex),
                          selected.lazy.filter({ $0.peer == peer }).count
                            < Self.maxRoutesPerIdentity else { continue }
                    let hint = routes[routeIndex]
                    guard let endpoint = hint.endpoint,
                          seenEndpoints.insert(endpoint).inserted else { continue }
                    selected.append(hint)
                }
            }
        }
        return selected
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
        var seen: Set<PeerID> = []
        return (providerHints[rootCID] ?? []).compactMap { hint in
            guard hasEndpointSession(hint.peer),
                  !isDeficiencySuppressed(rootCID: rootCID, peer: hint.peer),
                  seen.insert(hint.peer).inserted else { return nil }
            return hint.peer
        }
    }

    public func providers(for rootCID: String) -> [PeerID] {
        guard config.mode.usesOverlayServices else { return [] }
        evictExpiredProviders(rootCID: rootCID)
        var seen: Set<PeerID> = []
        return (providerHints[rootCID] ?? []).compactMap { hint in
            seen.insert(hint.peer).inserted ? hint.peer : nil
        }
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
        guard let address = advertisedListenAddresses(observedLocalHost: nil).first else { return nil }
        return PeerEndpoint(publicKey: localKey.hex, host: address.host, port: address.port)
    }

    func providerEndpoint(for peer: PeerID) -> PeerEndpoint? {
        guard let endpoint = endpointConnection(for: peer)?.endpoint,
              !endpoint.host.isEmpty,
              endpoint.host != "unknown",
              endpoint.port != 0 else { return nil }
        return endpoint
    }

    func nowUnix() -> UInt64 {
        UInt64(Date().timeIntervalSince1970)
    }
}
