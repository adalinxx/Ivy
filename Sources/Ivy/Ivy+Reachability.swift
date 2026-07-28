import Crypto
import Foundation
import Tally

extension Ivy {
    // MARK: - Asking peers whether we are reachable

    /// Starts a probe round for each installed transport.
    func startReachabilityProbes(generation: UInt64) {
        guard config.reachabilityEnabled, isCurrentRun(generation) else { return }
        // An operator who declares an external address has asserted reachability;
        // probing cannot improve on that and the declared port may not be ours.
        if config.externalAddress != nil {
            for kind in installedTransportKinds {
                reachability[kind, default: ReachabilityState()].declareReachable()
            }
            return
        }
        for kind in installedTransportKinds {
            probeReachability(for: kind, generation: generation)
        }
    }

    private func probeReachability(for kind: TransportKind, generation: UInt64) {
        guard config.reachabilityEnabled, isCurrentRun(generation) else { return }
        var state = reachability[kind, default: ReachabilityState()]
        guard !state.isProbing else { return }
        let port = config.listenPort(for: kind)
        guard port != 0 else { return }

        let peers = reachabilityProbeSample()
        state.beginRound(probeCount: peers.count)
        reachability[kind] = state

        for session in peers {
            let requestID = nextReachabilityRequestID()
            let nonce = Data(SystemRandomNumberGenerator.randomBytes(
                count: ReachabilityProbe.nonceByteCount))
            pendingReachabilityProbes[nonce] = PendingReachabilityProbe(
                requestID: requestID,
                peer: session.peerKey,
                transport: kind,
                nonce: nonce,
                generation: generation)
            let sent = enqueueReachabilityRequest(
                requestID: requestID,
                transport: kind,
                port: port,
                nonce: nonce,
                on: session)
            if case .enqueued = sent {} else {
                failReachabilityProbe(nonce: nonce, generation: generation)
            }
        }

        scheduleReachabilityProbeDeadline(for: kind, generation: generation)
        scheduleNextReachabilityRound(for: kind, generation: generation)
    }

    /// Picks authenticated direct endpoint sessions in distinct netgroups, so one
    /// operator cannot supply every confirmation.
    ///
    /// The order is random rather than by peer key: a deterministic order is
    /// grindable, and an attacker holding the first few keys could capture every
    /// probe slot round after round.
    private func reachabilityProbeSample() -> [AuthenticatedSession] {
        var seenGroups: Set<String> = []
        var sample: [AuthenticatedSession] = []
        var generator = SystemRandomNumberGenerator()
        let candidates: [AuthenticatedSession] = directEndpointSessions
            .shuffled(using: &generator)
        for session in candidates {
            let group = connectionNetgroup(session.connection)
            guard seenGroups.insert(group).inserted else { continue }
            sample.append(session)
            if sample.count == config.reachabilityProbeSampleSize { break }
        }
        return sample
    }

    private func scheduleReachabilityProbeDeadline(
        for kind: TransportKind,
        generation: UInt64
    ) {
        reachabilityDeadlines[kind]?.cancel()
        reachabilityDeadlines[kind] = delayedTask(after: config.requestTimeout) { [weak self] in
            await self?.finishReachabilityRound(for: kind, generation: generation)
        }
    }

    private func scheduleNextReachabilityRound(for kind: TransportKind, generation: UInt64) {
        let interval = reachability[kind, default: ReachabilityState()]
            .nextInterval(base: config.reachabilityProbeInterval)
        reachabilityTimers[kind]?.cancel()
        reachabilityTimers[kind] = delayedTask(after: interval) { [weak self] in
            await self?.probeReachability(for: kind, generation: generation)
        }
    }

    private func finishReachabilityRound(for kind: TransportKind, generation: UInt64) {
        guard isCurrentRun(generation) else { return }
        for (nonce, probe) in pendingReachabilityProbes where probe.transport == kind {
            pendingReachabilityProbes.removeValue(forKey: nonce)
            reachability[kind, default: ReachabilityState()].recordFailure()
        }
        var state = reachability[kind, default: ReachabilityState()]
        let previous = state.status
        state.finishRound(requiredFailures: config.reachabilityConfirmations)
        reachability[kind] = state
        if state.status != previous {
            config.logger.info("Reachability for \(kind) is now \(state.status)")
        }
    }

    /// A dial-back landed: this node is reachable on that transport. Only an
    /// inbound nonce counts, so a peer cannot talk us into a false positive.
    func confirmReachability(nonce: Data, arrivingOn transport: TransportKind) -> Bool {
        guard let probe = pendingReachabilityProbes[nonce],
              // The dial-back must arrive on the transport it was asked for, or it
              // says nothing about that transport's reachability.
              probe.transport == transport,
              isCurrentRun(probe.generation) else { return false }
        pendingReachabilityProbes.removeValue(forKey: nonce)
        var state = reachability[probe.transport, default: ReachabilityState()]
        let previous = state.status
        state.recordConfirmation(required: config.reachabilityConfirmations)
        reachability[probe.transport] = state
        if state.status != previous {
            config.logger.info("Reachability for \(probe.transport) is now \(state.status)")
        }
        return true
    }

    private func failReachabilityProbe(nonce: Data, generation: UInt64) {
        guard let probe = pendingReachabilityProbes.removeValue(forKey: nonce),
              isCurrentRun(generation) else { return }
        reachability[probe.transport, default: ReachabilityState()].recordFailure()
    }

    func handleReachabilityResponse(
        requestID: UInt64,
        status: ReachabilityStatus,
        from peer: PeerID
    ) {
        // Responses are bookkeeping: a peer reporting failure can only cost us a
        // confirmation, never grant one.
        guard status != .dialed else { return }
        guard let entry = pendingReachabilityProbes.first(where: {
            $0.value.requestID == requestID && $0.value.peer.peerID == peer
        }) else { return }
        pendingReachabilityProbes.removeValue(forKey: entry.key)
        reachability[entry.value.transport, default: ReachabilityState()].recordFailure()
    }

    // MARK: - Dialing peers back for them

    /// Dials the requester back at the address we already observe for it. The
    /// request carries no host, so this can never be aimed at a third party.
    func handleReachabilityRequest(
        requestID: UInt64,
        transport kind: TransportKind,
        port: UInt16,
        nonce: Data,
        session: AuthenticatedSession
    ) async {
        let generation = runGeneration
        guard config.reachabilityEnabled,
              let observedHost = Self.dialBackHost(
                  role: session.role,
                  isDirect: session.connection.isDirect,
                  observedHost: session.connection.observedHost),
              hasTransport(kind),
              tally.shouldAllow(peer: session.peerKey.peerID) else {
            respondToReachabilityRequest(requestID, status: .refused, session: session)
            return
        }
        guard activeDialBacks < config.maxConcurrentDialBacks,
              dialBackAllowed(for: session.peerKey) else {
            respondToReachabilityRequest(requestID, status: .refused, session: session)
            return
        }

        lastDialBack[session.peerKey] = ContinuousClock.now
        activeDialBacks += 1
        defer { activeDialBacks -= 1 }

        let status = await performDialBack(
            host: observedHost,
            port: port,
            transport: kind,
            nonce: nonce)
        guard isCurrentRun(generation),
              let current = liveSession(for: session.peerKey),
              current.sessionID == session.sessionID else { return }
        respondToReachabilityRequest(requestID, status: status, session: current)
    }

    /// The only address a dial-back may target: the one already observed for a
    /// direct endpoint session. A relayed session has none, and a carrier is not
    /// owed this service, so both refuse.
    static func dialBackHost(
        role: AuthenticatedPeerRole,
        isDirect: Bool,
        observedHost: String?
    ) -> String? {
        guard role == .endpoint,
              isDirect,
              let host = observedHost,
              !host.isEmpty else { return nil }
        return host
    }

    private func dialBackAllowed(for peer: PeerKey) -> Bool {
        guard let last = lastDialBack[peer] else { return true }
        return ContinuousClock.now - last >= config.dialBackPerPeerInterval
    }

    private func performDialBack(
        host: String,
        port: UInt16,
        transport kind: TransportKind,
        nonce: Data
    ) async -> ReachabilityStatus {
        guard let frame = ReachabilityProbe.encode(nonce: nonce),
              let transport = try? transport(for: kind) else { return .refused }
        do {
            let channel = try await transport.dial(
                host: host,
                port: port,
                group: group
            ) { channel in channel.eventLoop.makeSucceededVoidFuture() }
            var buffer = channel.allocator.buffer(capacity: 4 + frame.count)
            buffer.writeInteger(UInt32(frame.count), endianness: .big)
            buffer.writeBytes(frame)
            try await channel.writeAndFlush(buffer).get()
            try? await channel.close().get()
            return .dialed
        } catch {
            return .dialFailed
        }
    }

    private func respondToReachabilityRequest(
        _ requestID: UInt64,
        status: ReachabilityStatus,
        session: AuthenticatedSession
    ) {
        sendReachabilityResponse(requestID: requestID, status: status, on: session)
    }
}

extension SystemRandomNumberGenerator {
    static func randomBytes(count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }
}
