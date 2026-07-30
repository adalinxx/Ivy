import Foundation
import Tally

extension Ivy {
    // MARK: - Starting a punch

    /// Offers our addresses to a peer we currently reach only through a carrier,
    /// so the two of us can try to replace the relay with a direct connection.
    func startHolePunch(with peer: PeerKey, generation: UInt64) {
        guard config.holePunchEnabled,
              isCurrentRun(generation),
              holePunches[peer] == nil,
              holePunches.count < config.maxConcurrentHolePunches,
              !isCoolingDown(peer),
              let session = liveSession(for: peer),
              session.role == .endpoint,
              // Only worth doing for a peer we cannot already reach directly.
              !session.connection.isDirect else { return }

        let candidates = localPunchCandidates(for: session)
        guard !candidates.isEmpty else { return }

        let punchID = nextHolePunchID()
        holePunches[peer] = PendingHolePunch(
            punchID: punchID,
            peer: peer,
            generation: generation,
            isCoordinator: true,
            startedAt: .now,
            phase: .awaitingCandidates,
            attempt: 1)
        sendHolePunch(.holePunchConnect(punchID: punchID, candidates: candidates), to: session)
        scheduleHolePunchTimeout(for: peer, generation: generation)
    }

    // MARK: - Handling the exchange

    func handleHolePunchConnect(
        punchID: UInt64,
        candidates: [PunchCandidate],
        session: AuthenticatedSession
    ) {
        let peer = session.peerKey
        guard config.holePunchEnabled, session.role == .endpoint, !session.connection.isDirect else {
            sendHolePunch(
                .holePunchAbort(punchID: punchID, reason: .disabled),
                to: session)
            return
        }
        let accepted = acceptablePunchCandidates(candidates)
        guard !accepted.isEmpty else {
            sendHolePunch(
                .holePunchAbort(punchID: punchID, reason: .noCandidates),
                to: session)
            return
        }

        if var punch = holePunches[peer] {
            // Our own offer is being answered: measure the round trip and fire.
            guard punch.isCoordinator,
                  punch.punchID == punchID,
                  punch.phase == .awaitingCandidates else { return }
            punch.remoteCandidates = accepted
            punch.phase = .dialing
            holePunches[peer] = punch
            sendHolePunch(.holePunchSync(punchID: punchID), to: session)
            let delay = punch.syncDelay(now: .now)
            beginPunchDial(with: peer, after: delay, generation: punch.generation)
            return
        }

        // A peer is offering first, so we answer and wait for its sync.
        guard holePunches.count < config.maxConcurrentHolePunches, !isCoolingDown(peer) else {
            sendHolePunch(
                .holePunchAbort(
                    punchID: punchID,
                    reason: isCoolingDown(peer) ? .cooldown : .busy),
                to: session)
            return
        }
        let ours = localPunchCandidates(for: session)
        guard !ours.isEmpty else {
            sendHolePunch(
                .holePunchAbort(punchID: punchID, reason: .noCandidates),
                to: session)
            return
        }
        let generation = runGeneration
        holePunches[peer] = PendingHolePunch(
            punchID: punchID,
            peer: peer,
            generation: generation,
            isCoordinator: false,
            startedAt: .now,
            phase: .awaitingSync,
            attempt: 1,
            remoteCandidates: accepted)
        sendHolePunch(.holePunchConnect(punchID: punchID, candidates: ours), to: session)
        scheduleHolePunchTimeout(for: peer, generation: generation)
    }

    func handleHolePunchSync(punchID: UInt64, session: AuthenticatedSession) {
        let peer = session.peerKey
        guard var punch = holePunches[peer],
              !punch.isCoordinator,
              punch.punchID == punchID,
              punch.phase == .awaitingSync else { return }
        punch.phase = .dialing
        holePunches[peer] = punch
        // The coordinator waits half a round trip before dialing; we are already
        // that half-trip behind, so we dial now.
        beginPunchDial(with: peer, after: .zero, generation: punch.generation)
    }

    func handleHolePunchAbort(punchID: UInt64, reason: HolePunchAbortReason, from peer: PeerKey) {
        guard let punch = holePunches[peer], punch.punchID == punchID else { return }
        config.logger.info("Hole punch with \(peer.hex.prefix(16))… aborted: \(reason)")
        finishHolePunch(with: peer, retry: false)
    }

    // MARK: - Dialing

    private func beginPunchDial(with peer: PeerKey, after delay: Duration, generation: UInt64) {
        guard var punch = holePunches[peer] else { return }
        punch.dialTask?.cancel()
        punch.dialTask = Task { [weak self] in
            if delay > .zero { try? await Task.sleep(for: delay) }
            await self?.dialPunchCandidates(with: peer, generation: generation)
        }
        holePunches[peer] = punch
    }

    private func dialPunchCandidates(with peer: PeerKey, generation: UInt64) async {
        guard isCurrentRun(generation),
              let punch = holePunches[peer],
              punch.generation == generation else { return }

        // QUIC first: a UDP punch survives more NATs than a TCP simultaneous open.
        let candidates = punch.remoteCandidates.sorted {
            $0.transport.rawValue > $1.transport.rawValue
        }
        for candidate in candidates {
            guard isCurrentRun(generation), holePunches[peer]?.generation == generation else {
                return
            }
            let endpoint = PeerEndpoint(
                publicKey: peer.hex,
                host: candidate.host,
                port: candidate.port,
                transport: candidate.transport)
            // The punched connection takes the ordinary inbound path on the other
            // side and the ordinary handshake on this one: coordinating timing
            // never grants a peer admission it would not otherwise get.
            if await attemptPunchDial(to: endpoint, peer: peer, generation: generation) {
                completeHolePunch(with: peer)
                return
            }
            if candidate.transport == .tcp {
                // Stagger so a TCP simultaneous open has a moment to land before
                // the next attempt disturbs it.
                try? await Task.sleep(for: .milliseconds(200))
            }
        }
        finishHolePunch(with: peer, retry: true)
    }

    private func attemptPunchDial(
        to endpoint: PeerEndpoint,
        peer: PeerKey,
        generation: UInt64
    ) async -> Bool {
        guard hasTransport(endpoint.transport), punchDialIsPermitted(to: endpoint) else {
            return false
        }
        // The ordinary dial path, so a punched connection converges with a
        // crossing dial exactly as any other pair of simultaneous dials does.
        let connected = try? await connectDirect(
            to: endpoint,
            key: peer,
            role: .endpoint,
            generation: generation,
            punchingFromPort: config.listenPort(for: endpoint.transport))
        guard connected == true, isCurrentRun(generation) else { return false }
        return liveSession(for: peer)?.connection.isDirect == true
    }

    /// A punch dial reuses the peer's live relayed session slot, since replacing
    /// it is the point. Every other limit a referral dial faces still applies,
    /// because the address came from the peer itself.
    private func punchDialIsPermitted(to endpoint: PeerEndpoint) -> Bool {
        // The host itself was already screened for routability by
        // `acceptablePunchCandidates`, which is where the private-address policy
        // lives; a candidate is still only ever an address the peer chose, so the
        // rest of the endpoint policy applies unchanged.
        guard let key = try? PeerKey(endpoint.publicKey),
              config.allowsEndpoint(key),
              peerMeetsDifficulty(key),
              !reconnectSuppressed.contains(key.peerID),
              connectionCapacityUsed < config.maxConnections else { return false }
        let group = NetGroup.group(endpoint.host)
        guard directConnectionCount(inNetgroup: group)
                < config.maxConnectionsPerNetgroup else { return false }
        // Charged last, so a refusal never spends budget an honest dial could use.
        // Candidates are addresses the peer chose, and the per-peer cooldown alone
        // would still let many peers sum into a scan.
        return recordPunchDialAllowance()
    }

    // MARK: - Candidates

    private func localPunchCandidates(for session: AuthenticatedSession) -> [PunchCandidate] {
        var candidates: [PunchCandidate] = []
        for kind in installedTransportKinds {
            let port = config.listenPort(for: kind)
            guard port != 0 else { continue }
            if let external = config.externalAddress {
                candidates.append(PunchCandidate(
                    transport: kind,
                    host: external.host,
                    port: kind == .tcp ? external.port : port))
            } else if let publicAddress {
                candidates.append(PunchCandidate(
                    transport: kind,
                    host: publicAddress.host,
                    port: port))
            }
            if config.allowPrivateHolePunchCandidates,
               let localHost = carrierLocalHost(for: session) {
                candidates.append(PunchCandidate(transport: kind, host: localHost, port: port))
            }
        }
        return PunchCandidate.canonical(candidates) ?? []
    }

    /// The address our carrier connection leaves from, which is the closest thing
    /// we have to a local address on a relayed session.
    private func carrierLocalHost(for session: AuthenticatedSession) -> String? {
        guard case .relayed(_, let carrier) = session.connection.transport,
              let carrierSession = liveSession(for: carrier) else { return nil }
        let host = carrierSession.connection.localHost
        guard let host, host != "0.0.0.0", host != "::" else { return nil }
        return host
    }

    func acceptablePunchCandidates(_ candidates: [PunchCandidate]) -> [PunchCandidate] {
        HolePunchCandidates.acceptable(
            candidates,
            allowingPrivateHosts: config.allowPrivateHolePunchCandidates,
            isRoutable: { !isNonRoutableDiscoveredHost($0) },
            hasTransport: { hasTransport($0) })
    }

    // MARK: - Lifecycle

    private func scheduleHolePunchTimeout(for peer: PeerKey, generation: UInt64) {
        guard var punch = holePunches[peer] else { return }
        punch.timeoutTask?.cancel()
        punch.timeoutTask = delayedTask(after: config.holePunchTimeout) { [weak self] in
            await self?.expireHolePunch(with: peer, generation: generation)
        }
        holePunches[peer] = punch
    }

    private func expireHolePunch(with peer: PeerKey, generation: UInt64) {
        guard isCurrentRun(generation), holePunches[peer]?.generation == generation else { return }
        finishHolePunch(with: peer, retry: true)
    }

    /// Ends the current attempt, retrying while attempts remain. Failure keeps
    /// the relayed session and is never held against the peer or the carrier.
    func finishHolePunch(with peer: PeerKey, retry: Bool) {
        guard let punch = holePunches.removeValue(forKey: peer) else { return }
        punch.timeoutTask?.cancel()
        punch.dialTask?.cancel()

        guard retry, punch.isCoordinator, punch.attempt < config.holePunchAttempts,
              isCurrentRun(punch.generation),
              liveSession(for: peer)?.connection.isDirect == false else {
            if retry { holePunchCooldowns[peer] = .now }
            return
        }
        let attempt = punch.attempt + 1
        let generation = punch.generation
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            await self?.retryHolePunch(with: peer, attempt: attempt, generation: generation)
        }
    }

    private func retryHolePunch(with peer: PeerKey, attempt: Int, generation: UInt64) {
        guard isCurrentRun(generation),
              holePunches[peer] == nil,
              let session = liveSession(for: peer),
              !session.connection.isDirect else { return }
        startHolePunch(with: peer, generation: generation)
        holePunches[peer]?.attempt = attempt
    }

    /// Retires punch state once a direct session exists, without disturbing a
    /// dial that is still in flight: cancelling one mid-handshake would tear down
    /// the very session that just succeeded.
    func completeHolePunch(with peer: PeerKey) {
        holePunchStartTasks.removeValue(forKey: peer)?.cancel()
        guard let punch = holePunches.removeValue(forKey: peer) else { return }
        punch.timeoutTask?.cancel()
    }

    func cancelHolePunch(with peer: PeerKey) {
        holePunchStartTasks.removeValue(forKey: peer)?.cancel()
        guard let punch = holePunches.removeValue(forKey: peer) else { return }
        punch.timeoutTask?.cancel()
        punch.dialTask?.cancel()
    }

    /// Consumes one slot from the node-wide punch-dial budget.
    private func recordPunchDialAllowance() -> Bool {
        let now = ContinuousClock.now
        recentPunchDials.removeAll { now - $0 >= Self.punchDialRateWindow }
        guard recentPunchDials.count < config.maxPunchDialsPerWindow else {
            config.logger.info("Refusing a hole-punch dial: at the node-wide rate limit")
            return false
        }
        recentPunchDials.append(now)
        return true
    }

    private func isCoolingDown(_ peer: PeerKey) -> Bool {
        guard let last = holePunchCooldowns[peer] else { return false }
        return ContinuousClock.now - last < config.holePunchPerPeerCooldown
    }

    private func sendHolePunch(_ message: Message, to session: AuthenticatedSession) {
        enqueueHolePunchMessage(message, on: session)
    }
}
