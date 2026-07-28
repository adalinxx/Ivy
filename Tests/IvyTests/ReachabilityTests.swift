import Foundation
import Testing
@testable import Ivy

@Suite("Reachability")
struct ReachabilityTests {
    @Test("a dial-back frame roundtrips and rejects malformed input")
    func probeFrameCodec() throws {
        let nonce = Data(repeating: 0x5a, count: ReachabilityProbe.nonceByteCount)
        let frame = try #require(ReachabilityProbe.encode(nonce: nonce))
        #expect(frame.count == ReachabilityProbe.frameByteCount)
        #expect(ReachabilityProbe.decode(frame) == nonce)

        #expect(ReachabilityProbe.encode(nonce: Data([1, 2, 3])) == nil)
        #expect(ReachabilityProbe.decode(Data(frame.dropLast())) == nil)

        var wrongVersion = frame
        wrongVersion[wrongVersion.index(wrongVersion.startIndex, offsetBy: 4)] = 9
        #expect(ReachabilityProbe.decode(wrongVersion) == nil)

        var wrongMagic = frame
        wrongMagic[wrongMagic.startIndex] = 0x00
        #expect(ReachabilityProbe.decode(wrongMagic) == nil)
    }

    @Test("reachability messages roundtrip and reject invalid fields")
    func messageCodec() throws {
        let nonce = Data(repeating: 0x11, count: ReachabilityProbe.nonceByteCount)
        let request = Message.reachabilityRequest(
            requestID: 7, transport: .tcp, port: 4001, nonce: nonce)
        #expect(Message.deserialize(request.serialize()) != nil)

        let response = Message.reachabilityResponse(requestID: 7, status: .dialFailed)
        #expect(Message.deserialize(response.serialize()) != nil)

        // A zero request ID, a zero port, and a short nonce are all unusable.
        #expect(Message.reachabilityRequest(
            requestID: 0, transport: .tcp, port: 4001, nonce: nonce).serialize().isEmpty)
        #expect(Message.reachabilityRequest(
            requestID: 7, transport: .tcp, port: 0, nonce: nonce).serialize().isEmpty)
        #expect(Message.reachabilityRequest(
            requestID: 7, transport: .tcp, port: 4001, nonce: Data([1])).serialize().isEmpty)
    }

    @Test("confirmation needs the configured number of inbound nonces")
    func confirmationRequiresInboundNonce() {
        var reachability = ReachabilityState()
        reachability.beginRound(probeCount: 2)
        #expect(reachability.status == .unknown)

        reachability.recordConfirmation(required: 2)
        #expect(reachability.status == .unknown)
        reachability.recordConfirmation(required: 2)
        #expect(reachability.status == .publiclyReachable)
    }

    @Test("a round with only failures reports the node unreachable")
    func failuresMakeNodeUnreachable() {
        var reachability = ReachabilityState()
        reachability.beginRound(probeCount: 2)
        reachability.recordFailure()
        reachability.recordFailure()
        reachability.finishRound(requiredFailures: 2)
        #expect(reachability.status == .unreachable)
    }

    @Test("a declared external address asserts reachability without probing")
    func externalAddressDeclaresReachability() async throws {
        let ivy = Ivy(config: IvyConfig(
            signingKey: deterministicTestSigningKey("declared"),
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            externalAddress: (host: "1.1.1.1", port: 4001)))
        try await ivy.start()
        #expect(await ivy.reachabilityStatus(for: .tcp) == .publiclyReachable)
        await ivy.stop()
    }

    @Test("a peer dials back the address it observes, proving reachability")
    func dialBackConfirmsReachabilityOverLoopback() async throws {
        let proverKey = deterministicTestSigningKey("prover")
        let helperKey = deterministicTestSigningKey("helper")

        let prover = Ivy(config: IvyConfig(
            signingKey: proverKey,
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            reachabilityProbeSampleSize: 1,
            reachabilityConfirmations: 1))
        let helper = Ivy(config: IvyConfig(
            signingKey: helperKey,
            listenPort: 0,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false)))

        try await prover.start()
        try await helper.start()

        let helperPort = try #require(await helper.boundPort(for: .tcp))
        try await prover.connect(to: PeerEndpoint(
            publicKey: try PeerKey(rawRepresentation: helperKey.publicKey.rawRepresentation).hex,
            host: "127.0.0.1",
            port: helperPort))

        // The prover's own listener port is what the helper is asked to dial; the
        // helper learns the host from the socket, not from the request.
        let proverPort = try #require(await prover.boundPort(for: .tcp))
        let session = try #require(await prover.directEndpointSessions.first)
        let requestID = await prover.nextReachabilityRequestID()
        let nonce = Data(repeating: 0x33, count: ReachabilityProbe.nonceByteCount)
        await prover.registerReachabilityProbeForTesting(
            requestID: requestID,
            peer: session.peerKey,
            transport: .tcp,
            nonce: nonce)
        _ = await prover.enqueueReachabilityRequest(
            requestID: requestID,
            transport: .tcp,
            port: proverPort,
            nonce: nonce,
            on: session)

        // A real dial-back round trip is slower than an in-process assertion, and
        // slower still with the rest of the suite running alongside it.
        let confirmed = try await TransportTestHarness.eventually(attempts: 200) {
            await prover.reachabilityStatus(for: .tcp) == .publiclyReachable
        }
        if !confirmed {
            let proverState = await prover.reachabilityStateForTesting
            let pending = await prover.pendingReachabilityProbeCountForTesting
            let proverPeers = await prover.connectedPeers.count
            let proverPendingSessions = await prover.pendingSessionCountForTesting
            let helperAttempts = await helper.dialBackAttemptCountForTesting
            let helperPeers = await helper.connectedPeers.count
            Issue.record("""
                dial-back never confirmed
                prover: \(proverState) pendingProbes=\(pending) peers=\(proverPeers) \
                pendingSessions=\(proverPendingSessions) port=\(proverPort)
                helper: dialBackAttempts=\(helperAttempts) peers=\(helperPeers)
                """)
        }
        #expect(confirmed)

        await prover.stop()
        await helper.stop()
    }

    @Test("a nonce arriving on a connection we dialed proves nothing")
    func dialBackMustArriveOnAnAcceptedConnection() async throws {
        let ivy = Ivy(config: IvyConfig(
            publicKey: deterministicTestPeerKey("prover-2"),
            listenPort: 0,
            stunServers: []))
        let nonce = Data(repeating: 0x44, count: ReachabilityProbe.nonceByteCount)
        await ivy.registerReachabilityProbeForTesting(
            requestID: 1,
            peer: try PeerKey(deterministicTestPeerKey("helper-2")),
            transport: .tcp,
            nonce: nonce)

        // The transport must match the one probed, or the nonce says nothing
        // about that transport.
        #expect(await !ivy.confirmReachability(nonce: nonce, arrivingOn: .quic))
        #expect(await ivy.reachabilityStatus(for: .tcp) == .unknown)
        // An unknown nonce is never a confirmation.
        #expect(await !ivy.confirmReachability(
            nonce: Data(repeating: 0x99, count: ReachabilityProbe.nonceByteCount),
            arrivingOn: .tcp))
    }

    @Test("a dial-back only ever targets a direct endpoint's observed address")
    func dialBackTargetsObservedAddressOnly() {
        #expect(Ivy.dialBackHost(
            role: .endpoint, isDirect: true, observedHost: "1.1.1.1") == "1.1.1.1")
        // A relayed session has no observed address, a carrier is not owed the
        // service, and an empty host is not dialable.
        #expect(Ivy.dialBackHost(role: .endpoint, isDirect: false, observedHost: "1.1.1.1") == nil)
        #expect(Ivy.dialBackHost(role: .carrier, isDirect: true, observedHost: "1.1.1.1") == nil)
        #expect(Ivy.dialBackHost(role: .endpoint, isDirect: true, observedHost: "") == nil)
        #expect(Ivy.dialBackHost(role: .endpoint, isDirect: true, observedHost: nil) == nil)
    }
}
