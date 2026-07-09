import Foundation
import NIOCore
import Tally
import Crypto

extension Ivy {
    // MARK: - DHT

    public func findNode(target: String) async -> [PeerEndpoint] {
        let targetHash = Router.hash(target)
        let lookupParallelism = min(Self.kademliaLookupParallelism, max(1, config.kBucketSize))
        // Convergence normally stops the lookup; k rounds is only a safety guard.
        let maxLookupRounds = max(1, config.kBucketSize)
        var candidatesByKey: [String: Router.BucketEntry] = [:]
        var queried: Set<String> = []
        var previousCandidateKeys: [String] = []

        for _ in 0..<maxLookupRounds {
            for entry in router.closestPeers(to: targetHash, count: config.kBucketSize) {
                candidatesByKey[entry.id.publicKey] = entry
            }

            let candidates = closestCandidateEntries(candidatesByKey.values, to: targetHash)
            let candidateKeys = candidates.map { $0.id.publicKey }
            let toQuery = candidates
                .filter {
                    !queried.contains($0.id.publicKey) &&
                    (connections[$0.id] != nil || localPeers[$0.id] != nil)
                }
                .prefix(lookupParallelism)

            if toQuery.isEmpty { break }

            var nonces: [UInt64] = []
            nonces.reserveCapacity(toQuery.count)
            for entry in toQuery {
                queried.insert(entry.id.publicKey)
                let nonce = makeFindNodeNonce()
                nonces.append(nonce)
                requestNeighbors(from: entry.id, targetHash: targetHash, nonce: nonce, timeout: .milliseconds(500))
            }

            let responses = await collectNeighborResponses(nonces: nonces)
            for endpoint in responses.flatMap({ $0 }) {
                let id = PeerID(publicKey: endpoint.publicKey)
                candidatesByKey[id.publicKey] = Router.BucketEntry(
                    id: id,
                    hash: Router.hash(id.publicKey),
                    endpoint: endpoint,
                    lastSeen: .now
                )
            }

            let stabilized = candidateKeys == previousCandidateKeys
            previousCandidateKeys = candidateKeys
            if stabilized && !candidates.contains(where: { !queried.contains($0.id.publicKey) }) {
                break
            }
        }

        for entry in router.closestPeers(to: targetHash, count: config.kBucketSize) {
            candidatesByKey[entry.id.publicKey] = entry
        }
        return closestCandidateEntries(candidatesByKey.values, to: targetHash).map { $0.endpoint }
    }

    // MARK: - Peer Exchange (PEX)

    func startPEX() {
        pexTask = Task { [weak self] in
            guard let self else { return }
            try? await Task.sleep(for: .seconds(30))
            while !Task.isCancelled {
                await self.runPEXRound()
                try? await Task.sleep(for: self.config.pexInterval)
            }
        }
    }

    func runPEXRound() async {
        let peerList = Array(connections.keys)
        guard !peerList.isEmpty else { return }

        let target = peerList.randomElement()!
        let nonce = UInt64.random(in: 0...UInt64.max)

        let discovered: [PeerEndpoint] = await withTaskCancellationHandler {
            await withCheckedContinuation { cont in
                guard !Task.isCancelled else { cont.resume(returning: []); return }
                pendingPEX[nonce] = cont
                fireToPeer(target, .pexRequest(nonce: nonce))
                Task {
                    try? await Task.sleep(for: .seconds(10))
                    if let pending = self.pendingPEX.removeValue(forKey: nonce) {
                        pending.resume(returning: [])
                    }
                }
            }
        } onCancel: {
            Task { await self.resolvePendingPEX(nonce: nonce) }
        }

        for ep in discovered {
            if addDiscoveredPeer(ep, source: "pex", from: target) != nil {
                Task { try? await connect(to: ep) }
            }
        }
    }

    func handlePEXRequest(nonce: UInt64, from peer: PeerID) {
        guard tally.shouldAllow(peer: peer) else { return }

        let peerHash = router.cachedHash(peer.publicKey)
        let maxPeers = config.pexMaxPeers

        let allPeers = router.closestPeers(to: peerHash, count: maxPeers * 2)

        var selected = [PeerEndpoint]()
        selected.reserveCapacity(maxPeers)
        for entry in allPeers {
            if entry.id == peer || entry.id == localID { continue }
            if entry.endpoint.host == "0.0.0.0" || entry.endpoint.host == "unknown" { continue }
            selected.append(entry.endpoint)
            if selected.count >= maxPeers { break }
        }

        fireToPeer(peer, .pexResponse(nonce: nonce, peers: selected))
    }

    func handlePEXResponse(nonce: UInt64, peers: [PeerEndpoint], from peer: PeerID) {
        guard let cont = pendingPEX.removeValue(forKey: nonce) else {
            config.logger.warning("Ignoring unsolicited PEX response from \(peer.publicKey.prefix(16))…")
            return
        }

        // Ignore candidate feeds from peers below the responder-score floor.
        // Default floor is 0 (permissive), so fresh/unknown peers (rep 0) still
        // bootstrap; operators can raise it to reject low-reputation feeders.
        guard tally.reputation(for: peer) >= config.pexMinResponderScore else {
            config.logger.warning("Ignoring PEX response from low-reputation \(peer.publicKey.prefix(16))…")
            tally.recordFailure(peer: peer)
            cont.resume(returning: [])
            return
        }

        let validated = peers.filter { isAcceptableDiscoveredEndpoint($0, source: "pex", from: peer) }
        // Cap accepted entries per round so one peer can't inject an unbounded
        // candidate set in a single exchange.
        let accepted = Array(validated.prefix(config.pexMaxAcceptedPerRound))
        if validated.count == peers.count {
            tally.recordSuccess(peer: peer)
        } else {
            tally.recordFailure(peer: peer)
        }
        cont.resume(returning: accepted)
    }

#if DEBUG
    func receivePEXResponseForTesting(nonce: UInt64, peers: [PeerEndpoint], from peer: PeerID) async -> [PeerEndpoint] {
        await withCheckedContinuation { cont in
            pendingPEX[nonce] = cont
            handlePEXResponse(nonce: nonce, peers: peers, from: peer)
        }
    }
#endif

    @discardableResult
    func addDiscoveredPeer(_ endpoint: PeerEndpoint, source: String, from peer: PeerID) -> PeerID? {
        guard isAcceptableDiscoveredEndpoint(endpoint, source: source, from: peer) else {
            return nil
        }

        let discovered = PeerID(publicKey: endpoint.publicKey)
        guard connections[discovered] == nil else { return nil }
        router.addPeer(discovered, endpoint: endpoint, tally: tally)
        return discovered
    }

    func isAcceptableDiscoveredEndpoint(_ endpoint: PeerEndpoint, source: String, from peer: PeerID) -> Bool {
        guard !endpoint.publicKey.isEmpty else {
            config.logger.warning("Rejecting \(source) endpoint from \(peer.publicKey.prefix(16))…: empty public key")
            return false
        }

        let discovered = PeerID(publicKey: endpoint.publicKey)
        guard discovered != localID else { return false }

        let host = endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty,
              host != "0.0.0.0",
              host != "::",
              host != "unknown",
              endpoint.port != 0 else {
            config.logger.warning("Rejecting \(source) endpoint \(endpoint.publicKey.prefix(16))… from \(peer.publicKey.prefix(16))…: unusable address")
            return false
        }

        // A publicly-reachable node rejects discovered endpoints that point at
        // non-routable address space (RFC1918, loopback, link-local, IPv6
        // unique-local, unspecified) or a non-IP string — a peer must not be able
        // to steer it into dialing an internal host (SSRF). Gated to public nodes
        // (a declared, routable externalAddress): a node configured for local/test
        // operation legitimately talks to loopback/private peers, so the filter
        // must not apply to it.
        if let ext = config.externalAddress, !isNonRoutableDiscoveredHost(ext.host),
           isNonRoutableDiscoveredHost(host) {
            config.logger.warning("Rejecting \(source) endpoint \(endpoint.publicKey.prefix(16))… from \(peer.publicKey.prefix(16))…: non-routable address \(host)")
            return false
        }

        // Measure the canonical raw key form (ed01 Multikey prefix stripped)
        // so a key ground to the threshold passes regardless of which
        // spelling the endpoint record carries.
        if config.minPeerKeyBits > 0 {
            let bits = KeyDifficulty.keyWorkBits(endpoint.publicKey)
            guard bits >= config.minPeerKeyBits else {
                config.logger.warning("Rejecting \(source) endpoint \(endpoint.publicKey.prefix(16))… from \(peer.publicKey.prefix(16))…: \(bits) key PoW bits, need \(config.minPeerKeyBits)")
                return false
            }
        }

        return true
    }

    /// True if `host` is NOT a globally-routable IP literal: a non-IP string, or
    /// an address in loopback / RFC1918-private / link-local / IPv6 unique-local
    /// / unspecified space. Reuses `NetGroup.group` for parsing (v4:/v6:/raw:
    /// tagging) so a single canonical parser decides both bucketing and routability.
    func isNonRoutableDiscoveredHost(_ host: String) -> Bool {
        let group = NetGroup.group(host)
        if group.hasPrefix("v4:") {
            let parts = group.dropFirst(3).split(separator: ".")
            guard parts.count == 2, let a = Int(parts[0]), let b = Int(parts[1]) else { return true }
            switch a {
            case 0, 10, 127: return true                   // unspecified/this-net, private, loopback
            case 169: return b == 254                       // link-local 169.254/16
            case 172: return (16...31).contains(b)          // private 172.16/12
            case 192: return b == 168                       // private 192.168/16
            case 100: return (64...127).contains(b)         // CGNAT/shared 100.64/10 (RFC 6598)
            case 240...255: return true                     // reserved 240/4 (incl. broadcast)
            default: return false
            }
        }
        if group.hasPrefix("v6:") {
            let parts = group.dropFirst(3).split(separator: ".")
            guard let first = parts.first, let h = UInt16(first, radix: 16) else { return true }
            if h == 0 { return true }                       // ::/16 (::, ::1, docs) — non-global
            if (0xfe80...0xfebf).contains(h) { return true } // link-local fe80::/10
            if (0xfc00...0xfdff).contains(h) { return true } // unique-local fc00::/7
            return false
        }
        return true   // raw: — not an IP literal
    }
}
