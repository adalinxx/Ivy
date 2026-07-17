import Foundation
import Tally

extension Ivy {
    // MARK: - DHT

    public func findNode(target: String) async -> [PeerEndpoint] {
        let targetHash = Router.hash(target)
        let lookupParallelism = min(Self.kademliaLookupParallelism, max(1, config.kBucketSize))
        let maxLookupRounds = max(1, config.kBucketSize)
        var candidatesByKey: [String: Router.BucketEntry] = [:]
        var queried: Set<String> = []

        for _ in 0..<maxLookupRounds {
            for entry in router.closestPeers(to: targetHash, count: config.kBucketSize) {
                candidatesByKey[entry.id.publicKey] = entry
            }

            let candidates = closestCandidateEntries(candidatesByKey.values, to: targetHash)
            let batch = candidates
                .filter { !queried.contains($0.id.publicKey) }
                .prefix(lookupParallelism)
            guard !batch.isEmpty else { break }

            for entry in batch {
                queried.insert(entry.id.publicKey)
            }

            await withTaskGroup(of: Void.self) { group in
                for entry in batch where !hasEndpointSession(entry.id) {
                    group.addTask { [weak self] in
                        guard let self else { return }
                        do {
                            try await self.connect(to: entry.endpoint)
                        } catch {
                            await self.removeFailedRoutingPeer(entry.id)
                        }
                    }
                }
            }

            let retained = Set(router.allPeers().map { $0.id.publicKey })
            for entry in batch where !hasEndpointSession(entry.id)
                && !retained.contains(entry.id.publicKey) {
                candidatesByKey.removeValue(forKey: entry.id.publicKey)
            }

            let queryable = batch.filter { hasEndpointSession($0.id) }
            let responses = await withTaskGroup(
                of: [PeerEndpoint].self,
                returning: [[PeerEndpoint]].self
            ) { group in
                for entry in queryable {
                    group.addTask { [weak self] in
                        guard let self else { return [] }
                        return await self.requestNeighbors(
                            from: entry.id,
                            targetHash: targetHash,
                            timeout: .milliseconds(500))
                    }
                }
                var result: [[PeerEndpoint]] = []
                for await response in group where !response.isEmpty {
                    result.append(response)
                }
                return result
            }
            for endpoint in responses.flatMap({ $0 }) {
                let id = PeerID(publicKey: endpoint.publicKey)
                candidatesByKey[id.publicKey] = Router.BucketEntry(
                    id: id,
                    hash: Router.hash(id.publicKey),
                    endpoint: endpoint
                )
            }

        }

        for entry in router.closestPeers(to: targetHash, count: config.kBucketSize) {
            candidatesByKey[entry.id.publicKey] = entry
        }
        return closestCandidateEntries(candidatesByKey.values, to: targetHash).map { $0.endpoint }
    }

    func startRoutingRefresh() {
        routingRefreshTask = Task { [weak self] in
            do {
                try await Task.sleep(for: .seconds(30))
            } catch {
                return
            }
            while !Task.isCancelled {
                let interval: Duration
                if let self {
                    await self.refreshRoutingTable()
                    interval = self.config.routingRefreshInterval
                } else {
                    return
                }
                do {
                    try await Task.sleep(for: interval)
                } catch {
                    return
                }
            }
        }
    }

    func refreshRoutingTable() async {
        guard case .overlay = config.mode else { return }
        let target = secureRandom32().map { String(format: "%02x", $0) }.joined()
        _ = await findNode(target: target)
    }

    private func removeFailedRoutingPeer(_ peer: PeerID) {
        guard running, !hasEndpointSession(peer) else { return }
        router.removePeer(peer)
    }

    @discardableResult
    func addDiscoveredPeer(_ endpoint: PeerEndpoint, source: String, from peer: PeerID) -> PeerID? {
        guard isAcceptableDiscoveredEndpoint(endpoint, source: source, from: peer) else {
            return nil
        }

        guard let key = try? PeerKey(endpoint.publicKey) else { return nil }
        let discovered = key.peerID
        guard !hasEndpointSession(discovered) else { return nil }
        router.addPeer(
            discovered,
            endpoint: PeerEndpoint(publicKey: key.hex, host: endpoint.host, port: endpoint.port)
        )
        return discovered
    }

    func isAcceptableDiscoveredEndpoint(_ endpoint: PeerEndpoint, source: String, from peer: PeerID) -> Bool {
        if source != "session metadata", !config.mode.participatesInPublicDiscovery {
            return false
        }
        guard let key = try? PeerKey(endpoint.publicKey), config.allowsEndpoint(key) else {
            config.logger.warning("Rejecting \(source) endpoint from \(peer.publicKey.prefix(16))…: empty public key")
            return false
        }

        let discovered = key.peerID
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

        // Unknown/public reachability must not let discovered records steer the
        // node into internal addresses. An explicit private IP opts into LAN use.
        let allowsPrivateDiscovery = config.externalAddress.map { address in
            isIPAddressLiteral(address.host) && isNonRoutableDiscoveredHost(address.host)
        } ?? false
        if !allowsPrivateDiscovery,
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
    /// an address in any non-global / special-use range. Parses the FULL address
    /// (all four IPv4 octets / all eight IPv6 hextets) via the canonical
    /// `NetGroup` parser, NOT the coarse /16-/32 group grain — so a /24 or /32
    /// special range (e.g. an RFC 5737 TEST-NET) is classified precisely without
    /// over-rejecting the real-public space surrounding it.
    func isNonRoutableDiscoveredHost(_ host: String) -> Bool {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if let octets = NetGroup.ipv4Octets(trimmed) {
            return Self.isNonRoutableIPv4(octets)
        }
        // IPv4-mapped ("::ffff:a.b.c.d") / -compatible ("::a.b.c.d") IPv6: the
        // meaningful network is the embedded IPv4, so classify by that.
        if trimmed.contains(":"), let mapped = NetGroup.embeddedMappedIPv4(trimmed),
           let octets = NetGroup.ipv4Octets(mapped) {
            return Self.isNonRoutableIPv4(octets)
        }
        if trimmed.contains(":"), let hextets = NetGroup.ipv6Hextets(trimmed) {
            return Self.isNonRoutableIPv6(hextets)
        }
        return true   // not an IP literal
    }

    private func isIPAddressLiteral(_ host: String) -> Bool {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        return NetGroup.ipv4Octets(trimmed) != nil || NetGroup.ipv6Hextets(trimmed) != nil
    }

    /// Precise IPv4 special-use classification over the full dotted-quad.
    static func isNonRoutableIPv4(_ o: [Int]) -> Bool {
        let (a, b, c) = (o[0], o[1], o[2])
        switch a {
        case 0: return true                              // "this network" 0.0.0.0/8 (RFC 1122)
        case 10: return true                             // private 10.0.0.0/8 (RFC 1918)
        case 127: return true                            // loopback 127.0.0.0/8 (RFC 1122)
        case 100: return (64...127).contains(b)          // CGNAT/shared 100.64.0.0/10 (RFC 6598)
        case 169: return b == 254                        // link-local 169.254.0.0/16 (RFC 3927)
        case 172: return (16...31).contains(b)           // private 172.16.0.0/12 (RFC 1918)
        case 192:
            if b == 168 { return true }                  // private 192.168.0.0/16 (RFC 1918)
            if b == 0 && c == 2 { return true }          // TEST-NET-1 192.0.2.0/24 (RFC 5737)
            return false
        case 198:
            if b == 18 || b == 19 { return true }        // benchmarking 198.18.0.0/15 (RFC 2544)
            if b == 51 && c == 100 { return true }       // TEST-NET-2 198.51.100.0/24 (RFC 5737)
            return false
        case 203:
            if b == 0 && c == 113 { return true }        // TEST-NET-3 203.0.113.0/24 (RFC 5737)
            return false
        case 224...239: return true                      // multicast 224.0.0.0/4 (RFC 5771)
        case 240...255: return true                      // reserved 240.0.0.0/4, incl. broadcast (RFC 1112)
        default: return false
        }
    }

    /// If `h` is an IPv6 transition form that embeds an IPv4 address, returns the
    /// four embedded octets so they can be run through the v4 special-use
    /// classifier; nil otherwise. Covers NAT64 (RFC 6052), 6to4 (RFC 3964) and
    /// Teredo (RFC 4380) — mirrors Bitcoin Core's IsRFC6052/3964/4380 handling.
    static func embeddedTransitionIPv4(_ h: [UInt16]) -> [Int]? {
        func octets(_ hi: UInt16, _ lo: UInt16) -> [Int] {
            [Int(hi >> 8), Int(hi & 0xff), Int(lo >> 8), Int(lo & 0xff)]
        }
        // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): 0064:ff9b then 64 zero
        // bits; the embedded IPv4 is the last two hextets.
        if h[0] == 0x0064, h[1] == 0xff9b, h[2] == 0, h[3] == 0, h[4] == 0, h[5] == 0 {
            return octets(h[6], h[7])
        }
        // 6to4 2002::/16 (RFC 3964): the embedded IPv4 is hextets[1..2].
        if h[0] == 0x2002 {
            return octets(h[1], h[2])
        }
        // Teredo 2001:0000::/32 (RFC 4380): the client IPv4 is the last two
        // hextets XOR 0xffff. Precisely 2001:0000: (second hextet 0) — distinct
        // from documentation 2001:db8::/32 and from plain global 2001::/16.
        if h[0] == 0x2001, h[1] == 0x0000 {
            return octets(h[6] ^ 0xffff, h[7] ^ 0xffff)
        }
        return nil
    }

    /// Precise IPv6 special-use classification over the full eight hextets.
    static func isNonRoutableIPv6(_ h: [UInt16]) -> Bool {
        let first = h[0]
        // Transition forms embedding an IPv4 (NAT64/6to4/Teredo): classify by the
        // embedded v4, so an internal/special-use v4 wrapped in a transition
        // prefix can't slip past as "routable IPv6" (SSRF on a translation host).
        // A wrapped globally-routable v4 stays routable.
        if let v4 = embeddedTransitionIPv4(h) { return isNonRoutableIPv4(v4) }
        if first == 0 { return true }                    // ::, ::1, IPv4-compat/mapped, discard — non-global (RFC 4291)
        if (0xfe80...0xfebf).contains(first) { return true } // link-local fe80::/10 (RFC 4291)
        if (0xfc00...0xfdff).contains(first) { return true } // unique-local fc00::/7 (RFC 4193)
        if (0xff00...0xffff).contains(first) { return true } // multicast ff00::/8 (RFC 4291)
        if first == 0x2001 && h[1] == 0x0db8 { return true } // documentation 2001:db8::/32 (RFC 3849)
        return false
    }
}
