import Crypto
import Foundation
import Testing
@testable import Ivy

@Suite("Hole punching")
struct HolePunchTests {
    private func candidate(
        _ host: String,
        _ port: UInt16,
        _ transport: TransportKind = .tcp
    ) -> PunchCandidate {
        PunchCandidate(transport: transport, host: host, port: port)
    }

    @Test("candidate lists are canonical, deduplicated, and capped")
    func candidateCanonicalisation() {
        let duplicated = [candidate("1.1.1.1", 1), candidate("1.1.1.1", 1)]
        #expect(PunchCandidate.canonical(duplicated)?.count == 1)

        let unsorted = [candidate("2.2.2.2", 2), candidate("1.1.1.1", 1)]
        #expect(PunchCandidate.canonical(unsorted) == [candidate("1.1.1.1", 1), candidate("2.2.2.2", 2)])

        // At most two per transport, and never more than four in total.
        let tooManyTCP = (1...3).map { candidate("1.1.1.\($0)", 1) }
        #expect(PunchCandidate.canonical(tooManyTCP) == nil)
        #expect(PunchCandidate.canonical([]) == nil)
        // A relay hint names a carrier, not something to punch towards.
        #expect(PunchCandidate.canonical([candidate("1.1.1.1", 1, .relay)]) == nil)
        #expect(PunchCandidate.canonical([candidate("1.1.1.1", 0)]) == nil)
    }

    @Test("hole punch messages roundtrip and reject non-canonical candidates")
    func messageCodec() throws {
        let message = Message.holePunchConnect(
            punchID: 5,
            candidates: [candidate("1.1.1.1", 1), candidate("2.2.2.2", 2, .quic)])
        let decoded = try #require(Message.deserialize(message.serialize()))
        guard case .holePunchConnect(let punchID, let candidates) = decoded else {
            Issue.record("expected holePunchConnect")
            return
        }
        #expect(punchID == 5)
        #expect(candidates.count == 2)

        #expect(Message.deserialize(Message.holePunchSync(punchID: 5).serialize()) != nil)
        #expect(Message.deserialize(
            Message.holePunchAbort(punchID: 5, reason: .busy).serialize()) != nil)

        // A punch with no identity, or an unsorted list, is not encodable.
        #expect(Message.holePunchSync(punchID: 0).serialize().isEmpty)
        #expect(Message.holePunchConnect(
            punchID: 5,
            candidates: [candidate("2.2.2.2", 2), candidate("1.1.1.1", 1)]).serialize().isEmpty)
    }

    @Test("private and loopback candidates are refused unless explicitly allowed")
    func privateCandidatesAreRefusedByDefault() async throws {
        let strict = Ivy(config: IvyConfig(publicKey: deterministicTestPeerKey("strict")))
        let offered = [
            candidate("127.0.0.1", 4001),
            candidate("192.168.1.1", 4001),
            candidate("1.1.1.1", 4001),
        ]
        // Otherwise a peer could aim our dials at our own machine or LAN.
        #expect(await strict.acceptablePunchCandidates(offered) == [candidate("1.1.1.1", 4001)])

        let permissive = Ivy(config: IvyConfig(
            publicKey: deterministicTestPeerKey("permissive"),
            allowPrivateHolePunchCandidates: true))
        #expect(await permissive.acceptablePunchCandidates(offered).count == 3)
    }

    @Test("candidates for transports this node lacks are refused")
    func candidatesForUninstalledTransportsAreRefused() async throws {
        let ivy = Ivy(config: IvyConfig(publicKey: deterministicTestPeerKey("tcp-only")))
        let offered = [candidate("1.1.1.1", 4001), candidate("1.1.1.1", 4002, .quic)]
        #expect(await ivy.acceptablePunchCandidates(offered) == [candidate("1.1.1.1", 4001)])
    }

    @Test("the sync delay is half the measured round trip")
    func syncDelayIsHalfTheRoundTrip() {
        let start = ContinuousClock.now
        let punch = PendingHolePunch(
            punchID: 1,
            peer: try! PeerKey(deterministicTestPeerKey("peer")),
            generation: 1,
            isCoordinator: true,
            startedAt: start,
            phase: .awaitingCandidates,
            attempt: 1)
        #expect(punch.syncDelay(now: start + .milliseconds(100)) == .milliseconds(50))
    }

    @Test("a relayed session is upgraded to a direct one by punching")
    func relayedSessionIsUpgradedToDirect() async throws {
        let carrierIdentity = TransportTestHarness.identity("punch-carrier")
        let sourceIdentity = TransportTestHarness.identity("punch-source")
        let targetIdentity = TransportTestHarness.identity("punch-target")
        let carrierPort = TransportTestHarness.nextPort()
        let sourcePort = TransportTestHarness.nextPort()
        let targetPort = TransportTestHarness.nextPort()
        let carrierEndpoint = TransportTestHarness.endpoint(carrierIdentity, port: carrierPort)
        let sourceKey = TransportTestHarness.key(sourceIdentity)
        let targetKey = TransportTestHarness.key(targetIdentity)

        let carrier = Ivy(config: TransportTestHarness.config(
            carrierIdentity, port: carrierPort, relayEnabled: true))
        // Both sides sit on loopback, so they must be willing to punch to it.
        let source = Ivy(config: TransportTestHarness.config(
            sourceIdentity,
            port: sourcePort,
            carriers: [carrierEndpoint],
            allowPrivateHolePunchCandidates: true))
        let target = Ivy(config: TransportTestHarness.config(
            targetIdentity,
            port: targetPort,
            allowPrivateHolePunchCandidates: true))

        try await carrier.start()
        try await target.start()
        try await source.start()
        defer {
            Task {
                await source.stop()
                await target.stop()
                await carrier.stop()
            }
        }

        try await target.connect(to: carrierEndpoint)
        #expect(try await TransportTestHarness.eventually {
            let hasCarrier = await source.liveCarrierKeys
                .contains(TransportTestHarness.key(carrierIdentity))
            let carrierPeers = await carrier.peerConnectionCount
            return hasCarrier && carrierPeers == 2
        })

        // Reachable only through the carrier to begin with.
        try await source.connectViaRelay(to: TransportTestHarness.endpoint(
            targetIdentity, port: targetPort))
        #expect(await source.routeForTesting(to: targetKey) == .some(false))

        // The target accepted the relayed session, so it coordinates the upgrade.
        #expect(try await TransportTestHarness.eventually {
            let sourceRoute = await source.routeForTesting(to: targetKey)
            let targetRoute = await target.routeForTesting(to: sourceKey)
            return sourceRoute == true && targetRoute == true
        })
    }
}
