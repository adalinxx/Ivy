import Foundation
import NIOCore
import NIOPosix
import Tally

public enum IvyError: Error, Sendable {
    case notRunning
    case invalidPeerKey
    case peerOutsideMode
    case identityVerificationFailed
    case noRelayAvailable
}

struct PendingNeighborResponse: Sendable {
    let peer: PeerID
    let continuation: CheckedContinuation<[PeerEndpoint], Never>
}

private enum PendingSessionDirection {
    case initiator(expected: PeerKey, routeBinding: Data)
    case responder
}

private struct PendingSession {
    let connection: PeerConnection
    let direction: PendingSessionDirection
    let generation: UInt64
    var helloInitiator: SignedSessionHelloInitiator?
    var helloResponder: SignedSessionHelloResponder?
    var sessionID: SessionID?
    var remoteKey: PeerKey?
    var remoteMetadata: PeerMetadata?
}

final class AuthenticatedSession {
    let connection: PeerConnection
    let peerKey: PeerKey
    let role: AuthenticatedPeerRole
    let sessionID: SessionID
    let metadata: PeerMetadata
    var sequenceState = SessionSequenceState()
    var didNotifyConnect = false

    init(
        connection: PeerConnection,
        peerKey: PeerKey,
        role: AuthenticatedPeerRole,
        sessionID: SessionID,
        metadata: PeerMetadata
    ) {
        self.connection = connection
        self.peerKey = peerKey
        self.role = role
        self.sessionID = sessionID
        self.metadata = metadata
    }
}

private struct RelayRoute {
    let source: PeerKey
    let target: PeerKey
    var ready: Bool
    var lastActivity: ContinuousClock.Instant
}

private struct InstalledRoute {
    let carrier: PeerKey
    let remote: PeerKey
}

private struct PendingRelayOpen {
    let carrier: PeerKey
    let target: PeerKey
    let continuation: CheckedContinuation<Data?, Never>
}

private struct PendingOutgoingDial {
    let endpoint: PeerEndpoint
    let generation: UInt64
}

struct PendingReconnect {
    let generation: UInt64
    let token: UInt64
    let task: Task<Void, Never>
}

enum ProtocolViolationEvidence {
    case unverified
    case signedTransport
    case signedPayload
}

public actor Ivy {
    public let config: IvyConfig
    public let tally: Tally
    var router: Router
    public let localID: PeerID
    let localKey: PeerKey
    let group: EventLoopGroup
    let inboundByteBudget: InboundByteBudget

    public weak var delegate: IvyDelegate?
    var contentSource: (any IvyContentSource)?
    public func setContentSource(_ source: IvyContentSource?) { contentSource = source }

    private var pendingSessions: [UUID: PendingSession] = [:]
    private var authenticationWaiters: [UUID: CheckedContinuation<Bool, Never>] = [:]
    private var endpointSessions: [PeerKey: AuthenticatedSession] = [:]
    private var carrierSessions: [PeerKey: AuthenticatedSession] = [:]
    private var authenticatedConnections: [UUID: (PeerKey, AuthenticatedPeerRole)] = [:]
    private var relayRoutes: [Data: RelayRoute] = [:]
    private var installedRoutes: [Data: InstalledRoute] = [:]
    private var routeConnections: [Data: PeerConnection] = [:]
    private var pendingRelayOpens: [Data: PendingRelayOpen] = [:]
    static let directRouteBinding = Data(repeating: 0, count: 32)
    static let maxRelayRoutes = 64
    static let maxRelayRoutesPerPeer = 8
    static let relayIdleTimeout: Duration = .seconds(300)

    func endpointConnection(for peer: PeerID) -> PeerConnection? {
        guard let key = try? PeerKey(peer.publicKey) else { return nil }
        return endpointSessions[key]?.connection
    }

    var connectedEndpointPeers: [PeerID] { endpointSessions.keys.map(\.peerID) }
    var serverChannel: Channel?
    var running = false
    private var lifecycleTail: Task<Void, Never>?
    var runGeneration: UInt64 = 0
    private var inboundAdmissionGate: InboundAdmissionGate?

    let stunClient: STUNClient
    private(set) public var publicAddress: ObservedAddress?
    var routingRefreshTask: Task<Void, Never>?
    var pendingNeighborResponses: [UInt64: PendingNeighborResponse] = [:]
    var healthMonitor: PeerHealthMonitor?
    private var outgoingDials: [PeerID: PendingOutgoingDial] = [:]
    var reconnectAttempts: [PeerID: Int] = [:]
    var reconnectTasks: [PeerID: PendingReconnect] = [:]
    private var nextReconnectToken: UInt64 = 0
    static let reconnectBaseDelayMs: UInt64 = 500
    static let reconnectMaxDelayMs: UInt64 = 30_000
    static let reconnectJitterMs: UInt64 = 250
    static let kademliaLookupParallelism = 3

    var providerHints: [String: [ProviderHint]] = [:]
    static let maxProviderRoots = 10_000
    var deficientPeerSuppression: [String: [String: ContinuousClock.Instant]] = [:]
    static let deficiencySuppressionWindow: Duration = .seconds(30)

    var pendingContentRequests: [UInt64: PendingContentRequest] = [:]
    var contentRequestIDs: [ContentRequestKey: UInt64] = [:]
    var pendingNetworkFetches: [ContentRequestKey: PendingNetworkFetch] = [:]
    var nextNetworkFetchToken: UInt64 = 0
    var servingContentRequests: Set<InboundContentRequest> = []
    var pendingProviderQueries: [String: PendingProviderQuery] = [:]

    public init(config: IvyConfig, group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton, tally: Tally? = nil) {
        self.config = config
        self.localID = PeerID(publicKey: config.publicKey)
        self.localKey = config.peerKey
        self.tally = tally ?? Tally(config: config.tallyConfig)
        self.router = Router(localID: PeerID(publicKey: config.publicKey), k: config.kBucketSize)
        self.group = group
        self.inboundByteBudget = InboundByteBudget(limit: config.maxInboundBufferedBytes)
        self.stunClient = STUNClient(group: group, servers: config.stunServers)
    }

    // MARK: - Lifecycle

    public func start() async throws {
#if DEBUG || IVY_TESTING
        lifecycleRequestCountForTesting += 1
#endif
        let previous = lifecycleTail
        let operation = Task { [weak self] in
            await previous?.value
            guard let self else { throw CancellationError() }
            try await self.startNow()
        }
        lifecycleTail = Task { _ = try? await operation.value }
#if DEBUG || IVY_TESTING
        await lifecycleRequestHookForTesting?(lifecycleRequestCountForTesting)
#endif
        try await operation.value
    }

    private func startNow() async throws {
        guard !running, serverChannel == nil else { return }
        try config.validate()
        runGeneration &+= 1
        let generation = runGeneration
#if DEBUG || IVY_TESTING
        await lifecycleStartHookForTesting?()
#endif
        let listener = try await startListener(generation: generation)
        serverChannel = listener.channel
        inboundAdmissionGate = listener.gate
        running = true

        if let externalAddress = config.externalAddress {
            let address = ObservedAddress(host: externalAddress.host, port: externalAddress.port)
            publicAddress = address
            delegate?.ivy(self, didDiscoverPublicAddress: address)
        } else if let address = await stunClient.discoverPublicAddress() {
            guard isCurrentRun(generation) else { return }
            publicAddress = address
            delegate?.ivy(self, didDiscoverPublicAddress: address)
        }
        guard isCurrentRun(generation) else { return }

        for endpoint in config.bootstrapPeers {
            Task {
                await self.maintainConfiguredConnection(
                    to: endpoint,
                    role: .endpoint,
                    generation: generation)
            }
        }
        for carrier in config.carriers {
            Task {
                await self.maintainConfiguredConnection(
                    to: carrier,
                    role: .carrier,
                    generation: generation)
            }
        }

        let monitor = PeerHealthMonitor(
            config: config.healthConfig,
            onStale: { [weak self] peer, sessionID in
                guard let self else { return }
                Task {
                    await self.disconnectStale(
                        peer,
                        sessionID: sessionID,
                        generation: generation)
                }
            })
        healthMonitor = monitor
        await monitor.startMonitoring { [weak self] peer, sessionID, nonce in
            guard let self else { return }
            await self.sendHealthPing(
                peer,
                sessionID: sessionID,
                nonce: nonce,
                generation: generation)
        }
        guard isCurrentRun(generation) else { return }

        if config.mode.participatesInPublicDiscovery {
            startRoutingRefresh(generation: generation)
        }
    }

    public func stop() async {
#if DEBUG || IVY_TESTING
        lifecycleRequestCountForTesting += 1
#endif
        let previous = lifecycleTail
        let operation = Task { [weak self] in
            await previous?.value
            await self?.stopNow()
        }
        lifecycleTail = operation
#if DEBUG || IVY_TESTING
        await lifecycleRequestHookForTesting?(lifecycleRequestCountForTesting)
#endif
        await operation.value
    }

    private func stopNow() async {
        guard running || serverChannel != nil else { return }
        runGeneration &+= 1
        running = false
        inboundAdmissionGate?.invalidate()
        inboundAdmissionGate = nil
        routingRefreshTask?.cancel()
        routingRefreshTask = nil
        await healthMonitor?.stopMonitoring()
        cleanupAllPending()

        try? await serverChannel?.close().get()
        serverChannel = nil
        let pendingConnections = pendingSessions.values.map(\.connection)
        let endpointConnections = endpointSessions.values.map(\.connection)
        let carrierConnections = carrierSessions.values.map(\.connection)
        pendingSessions.removeAll()
        endpointSessions.removeAll()
        carrierSessions.removeAll()
        authenticatedConnections.removeAll()
        for connection in pendingConnections + endpointConnections + carrierConnections {
            connection.cancel()
        }
        relayRoutes.removeAll()
        installedRoutes.removeAll()
        routeConnections.removeAll()

        outgoingDials.removeAll()
        for reconnect in reconnectTasks.values {
            reconnect.task.cancel()
        }
        reconnectTasks.removeAll()
        reconnectAttempts.removeAll()
    }

    func isCurrentRun(_ generation: UInt64) -> Bool {
        running && generation == runGeneration
    }

    private func sendHealthPing(
        _ peer: PeerID,
        sessionID: SessionID,
        nonce: UInt64,
        generation: UInt64
    ) {
        guard isCurrentRun(generation),
              let key = try? PeerKey(peer.publicKey),
              authenticatedSession(for: key)?.sessionID == sessionID else { return }
        fireToPeer(peer, .ping(nonce: nonce))
    }

    static func attributedPeer(
        _ peer: PeerKey,
        direct: Bool,
        evidence: ProtocolViolationEvidence
    ) -> PeerKey? {
        switch evidence {
        case .unverified:
            return nil
        case .signedTransport:
            return direct ? peer : nil
        case .signedPayload:
            return peer
        }
    }

    // MARK: - Authenticated Connections

    private func authenticatedSession(for key: PeerKey) -> AuthenticatedSession? {
        endpointSessions[key] ?? carrierSessions[key]
    }

    func isCurrent(_ session: AuthenticatedSession) -> Bool {
        running && sessionForAuthority((session.peerKey, session.role)) === session
    }

    func hasEndpointSession(_ peer: PeerID) -> Bool {
        guard let key = try? PeerKey(peer.publicKey) else { return false }
        return endpointSessions[key] != nil
    }

    func connectionCount(inNetgroup group: String, excluding peer: PeerID?) -> Int {
        let excluded = peer.flatMap { try? PeerKey($0.publicKey) }
        return (Array(endpointSessions.values) + Array(carrierSessions.values)).filter { session in
            session.peerKey != excluded
                && session.connection.isDirect
                && connectionNetgroup(session.connection) == group
        }.count
    }

    func connectionNetgroup(_ connection: PeerConnection) -> String {
        guard let host = connection.observedHost, !host.isEmpty else {
            return "raw:connection:" + connection.connectionID.uuidString
        }
        return NetGroup.group(host)
    }

    public var connectedPeers: [PeerID] {
        endpointSessions.keys.map(\.peerID)
    }

    public var connectedPeerEndpoints: [PeerEndpoint] {
        endpointSessions.values.map(\.connection.endpoint)
    }

    public var knownPeerEndpoints: [PeerEndpoint] {
        router.allPeers().map(\.endpoint)
    }

    public var peerConnectionCount: Int { endpointSessions.count }

    // MARK: - Connection Management

    public func connect(to endpoint: PeerEndpoint) async throws {
        guard try await connectEndpointIfAdmitted(to: endpoint, allowRelayFallback: true) else {
            throw IvyError.identityVerificationFailed
        }
    }

    func connectEndpointIfAdmitted(
        to endpoint: PeerEndpoint,
        allowRelayFallback: Bool,
        requiredGeneration: UInt64? = nil
    ) async throws -> Bool {
        guard let key = try? PeerKey(endpoint.publicKey) else { throw IvyError.invalidPeerKey }
        guard config.allowsEndpoint(key) else { throw IvyError.peerOutsideMode }
        guard running else { throw IvyError.notRunning }
        let generation = runGeneration
        if let requiredGeneration, requiredGeneration != generation {
            throw IvyError.notRunning
        }
        if endpointSessions[key] != nil { return true }
        guard reserveOutgoingDial(to: endpoint) else {
            return endpointSessions[key] != nil
        }

        let connection: PeerConnection
        do {
            let canonical = PeerEndpoint(
                publicKey: key.hex,
                host: endpoint.host,
                port: endpoint.port)
#if DEBUG || IVY_TESTING
            let rewritten = dialEndpointRewriteForTesting?(canonical) ?? canonical
            let dialEndpoint = PeerEndpoint(
                publicKey: key.hex,
                host: rewritten.host,
                port: rewritten.port)
#else
            let dialEndpoint = canonical
#endif
            connection = try await PeerConnection.dial(
                endpoint: dialEndpoint,
                group: group,
                inboundByteBudget: inboundByteBudget)
        } catch {
            finishOutgoingDial(to: key.peerID, generation: generation, connected: false)
            guard isCurrentRun(generation) else { throw IvyError.notRunning }
            if allowRelayFallback {
                try await connectViaRelay(to: endpoint, requiredGeneration: generation)
                return true
            }
            throw error
        }
        guard isCurrentRun(generation) else {
            finishOutgoingDial(to: key.peerID, generation: generation, connected: false)
            connection.cancel()
            throw IvyError.notRunning
        }

        Task { await self.handleInbound(connection) }
        let authenticated = await authenticateInitiator(
            connection,
            expected: key,
            routeBinding: Self.directRouteBinding)
        finishOutgoingDial(to: key.peerID, generation: generation, connected: authenticated)
        guard isCurrentRun(generation) else {
            connection.cancel()
            throw IvyError.notRunning
        }
        guard authenticated else {
            connection.cancel()
            if allowRelayFallback {
                try await connectViaRelay(to: endpoint, requiredGeneration: generation)
                return true
            }
            throw IvyError.identityVerificationFailed
        }
        return true
    }

    private func connectCarrier(to endpoint: PeerEndpoint) async throws {
        guard let key = try? PeerKey(endpoint.publicKey), config.isConfiguredCarrier(key) else {
            throw IvyError.peerOutsideMode
        }
        guard running else { throw IvyError.notRunning }
        let generation = runGeneration
        if carrierSessions[key] != nil { return }
        guard reserveOutgoingDial(to: endpoint) else {
            if carrierSessions[key] != nil { return }
            throw IvyError.identityVerificationFailed
        }

        let connection: PeerConnection
        do {
            connection = try await PeerConnection.dial(
                endpoint: PeerEndpoint(publicKey: key.hex, host: endpoint.host, port: endpoint.port),
                group: group,
                inboundByteBudget: inboundByteBudget)
        } catch {
            finishOutgoingDial(to: key.peerID, generation: generation, connected: false)
            throw error
        }
        guard isCurrentRun(generation) else {
            finishOutgoingDial(to: key.peerID, generation: generation, connected: false)
            connection.cancel()
            throw IvyError.notRunning
        }

        Task { await self.handleInbound(connection) }
        let authenticated = await authenticateInitiator(
            connection,
            expected: key,
            routeBinding: Self.directRouteBinding)
        finishOutgoingDial(to: key.peerID, generation: generation, connected: authenticated)
        guard authenticated else {
            connection.cancel()
            throw IvyError.identityVerificationFailed
        }
    }

    func reserveOutgoingDial(to endpoint: PeerEndpoint) -> Bool {
        guard let key = try? PeerKey(endpoint.publicKey),
              authenticatedSession(for: key) == nil,
              outgoingDials[key.peerID] == nil,
              connectionCapacityUsed < config.maxConnections else { return false }

        let targetGroup = NetGroup.group(endpoint.host)
        let pendingInGroup = outgoingDials.values.filter {
            NetGroup.group($0.endpoint.host) == targetGroup
        }.count
        guard connectionCount(inNetgroup: targetGroup, excluding: key.peerID) + pendingInGroup
                < config.maxConnectionsPerNetgroup else {
            return false
        }

        outgoingDials[key.peerID] = PendingOutgoingDial(
            endpoint: PeerEndpoint(publicKey: key.hex, host: endpoint.host, port: endpoint.port),
            generation: runGeneration)
        return true
    }

    func finishOutgoingDial(to peer: PeerID, generation: UInt64, connected: Bool) {
        guard outgoingDials[peer]?.generation == generation else { return }
        outgoingDials.removeValue(forKey: peer)
        if connected {
            reconnectAttempts.removeValue(forKey: peer)
            reconnectTasks.removeValue(forKey: peer)?.task.cancel()
        }
    }

    public func disconnect(_ peer: PeerID) {
        guard let key = try? PeerKey(peer.publicKey) else { return }
        reconnectTasks.removeValue(forKey: key.peerID)?.task.cancel()
        reconnectAttempts.removeValue(forKey: key.peerID)
        guard let session = authenticatedSession(for: key) else { return }
        teardownAuthenticatedSession(session, reconnect: false)
        session.connection.cancel()
    }

    private func disconnectStale(
        _ peer: PeerID,
        sessionID: SessionID,
        generation: UInt64
    ) {
        guard isCurrentRun(generation),
              let key = try? PeerKey(peer.publicKey),
              let session = authenticatedSession(for: key),
              session.sessionID == sessionID else { return }
        teardownAuthenticatedSession(session, reconnect: true)
        session.connection.cancel()
    }

    private func scheduleReconnect(
        to endpoint: PeerEndpoint,
        peer: PeerID,
        role: AuthenticatedPeerRole,
        generation: UInt64
    ) {
        guard let key = try? PeerKey(peer.publicKey),
              isCurrentRun(generation),
              authenticatedSession(for: key) == nil,
              outgoingDials[peer] == nil,
              reconnectTasks[peer] == nil else { return }

        let delay = reconnectDelay(for: peer)
        nextReconnectToken &+= 1
        let token = nextReconnectToken
        let task = Task { [weak self] in
            do {
                try await Task.sleep(for: delay)
            } catch {
                return
            }
            guard let self else { return }
            await self.runScheduledReconnect(
                to: endpoint,
                peer: peer,
                role: role,
                generation: generation,
                token: token)
        }
        reconnectTasks[peer] = PendingReconnect(
            generation: generation,
            token: token,
            task: task)
    }

    func reconnectDelay(for peer: PeerID) -> Duration {
        let attempt = min((reconnectAttempts[peer] ?? 0) + 1, 16)
        reconnectAttempts[peer] = attempt
        let shift = min(attempt - 1, 10)
        let exponential = Self.reconnectBaseDelayMs * (UInt64(1) << UInt64(shift))
        let capped = min(exponential, Self.reconnectMaxDelayMs)
        return .milliseconds(capped + UInt64.random(in: 0 ... Self.reconnectJitterMs))
    }

    func runScheduledReconnect(
        to endpoint: PeerEndpoint,
        peer: PeerID,
        role: AuthenticatedPeerRole,
        generation: UInt64,
        token: UInt64
    ) async {
        guard reconnectTasks[peer]?.generation == generation,
              reconnectTasks[peer]?.token == token else { return }
        reconnectTasks.removeValue(forKey: peer)
        guard isCurrentRun(generation) else { return }
        await maintainConfiguredConnection(to: endpoint, role: role, generation: generation)
    }

    private func maintainConfiguredConnection(
        to endpoint: PeerEndpoint,
        role: AuthenticatedPeerRole,
        generation: UInt64
    ) async {
        guard isCurrentRun(generation), let key = try? PeerKey(endpoint.publicKey) else { return }
        do {
            if role == .carrier {
                try await connectCarrier(to: endpoint)
            } else {
                try await connect(to: endpoint)
            }
        } catch {
            scheduleReconnect(
                to: endpoint,
                peer: key.peerID,
                role: role,
                generation: generation)
        }
    }

    // MARK: - Session Authentication

    private var connectionCapacityUsed: Int {
        var representedDials = Set(authenticatedConnections.values.map { $0.0.peerID })
        for pending in pendingSessions.values {
            if case .initiator(let expected, _) = pending.direction {
                representedDials.insert(expected.peerID)
            }
        }
        let reservedOnly = outgoingDials.keys.lazy.filter { !representedDials.contains($0) }.count
        return authenticatedConnections.count + pendingSessions.count + reservedOnly
    }

    @discardableResult
    func registerInboundConnection(_ connection: PeerConnection, generation: UInt64) -> Bool {
        let netgroup = connectionNetgroup(connection)
        let pendingInNetgroup = pendingSessions.values.lazy.filter {
            $0.connection.isDirect && self.connectionNetgroup($0.connection) == netgroup
        }.count
        guard isCurrentRun(generation),
              connection.isLive,
              connectionCapacityUsed < config.maxConnections,
              connectionCount(inNetgroup: netgroup, excluding: nil) + pendingInNetgroup
                < config.maxConnectionsPerNetgroup else {
            connection.cancel()
            return false
        }

        pendingSessions[connection.connectionID] = PendingSession(
            connection: connection,
            direction: .responder,
            generation: generation)
        Task { await self.handleInbound(connection) }
        schedulePendingTimeout(connection.connectionID, generation: generation)
        return true
    }

    private func authenticateInitiator(
        _ connection: PeerConnection,
        expected: PeerKey,
        routeBinding: Data
    ) async -> Bool {
        guard let metadata = localMetadata(for: connection).encode() else { return false }
        let hello = SessionHelloInitiator(
            routeBinding: routeBinding,
            initiator: localKey,
            responder: expected,
            nonce: secureRandom32(),
            metadata: metadata)
        guard let signed = try? SignedSessionHelloInitiator.sign(hello, with: config.signingKey) else {
            return false
        }

        pendingSessions[connection.connectionID] = PendingSession(
            connection: connection,
            direction: .initiator(expected: expected, routeBinding: routeBinding),
            generation: runGeneration,
            helloInitiator: signed)

        return await withCheckedContinuation { continuation in
            authenticationWaiters[connection.connectionID] = continuation
            guard sendSessionRecord(.helloInitiator(signed), on: connection) else {
                failPendingSession(connection.connectionID)
                return
            }
            schedulePendingTimeout(connection.connectionID, generation: runGeneration)
        }
    }

    private func schedulePendingTimeout(_ connectionID: UUID, generation: UInt64) {
        Task { [weak self] in
            do {
                try await Task.sleep(for: .seconds(30))
            } catch {
                return
            }
            await self?.timeoutPendingSession(connectionID, generation: generation)
        }
    }

    private func timeoutPendingSession(_ connectionID: UUID, generation: UInt64) {
        guard isCurrentRun(generation),
              pendingSessions[connectionID]?.generation == generation else { return }
        failPendingSession(connectionID)
    }

    private func failPendingSession(_ connectionID: UUID) {
        guard let pending = pendingSessions.removeValue(forKey: connectionID) else { return }
        authenticationWaiters.removeValue(forKey: connectionID)?.resume(returning: false)
        removeRouteConnection(pending.connection)
        pending.connection.cancel()
    }

    private func handleInbound(_ connection: PeerConnection) async {
        for await frame in connection.records {
            await handleSessionRecord(frame.bytes, on: connection)
            withExtendedLifetime(frame) {}
        }
        connectionEnded(connection)
    }

    private func handleSessionRecord(_ bytes: Data, on connection: PeerConnection) async {
        let record: SessionWireRecord
        do {
            record = try SessionWireRecord.deserialize(bytes)
        } catch {
            rejectRecord(on: connection)
            return
        }

        if let authority = authenticatedConnections[connection.connectionID],
           let session = sessionForAuthority(authority),
           session.connection === connection {
            guard case .data(let dataRecord) = record else {
                rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                    session.peerKey,
                    direct: session.connection.isDirect,
                    evidence: .unverified))
                return
            }
            await handleAuthenticatedData(dataRecord, session: session)
            return
        }

        guard pendingSessions[connection.connectionID] != nil else {
            connection.cancel()
            return
        }
        await handlePendingRecord(record, on: connection)
    }

    private func sessionForAuthority(_ authority: (PeerKey, AuthenticatedPeerRole)) -> AuthenticatedSession? {
        authority.1 == .endpoint ? endpointSessions[authority.0] : carrierSessions[authority.0]
    }

    private func handlePendingRecord(_ record: SessionWireRecord, on connection: PeerConnection) async {
        guard var pending = pendingSessions[connection.connectionID] else { return }

        switch record {
        case .helloInitiator(let signed):
            guard case .responder = pending.direction,
                  pending.helloInitiator == nil,
                  signed.isValid(),
                  acceptsInboundHello(signed.hello, on: connection),
                  peerMeetsDifficulty(signed.hello.initiator),
                  let remoteMetadata = try? PeerMetadata.decodeCanonical(signed.hello.metadata),
                  let localMetadata = localMetadata(for: connection).encode() else {
                rejectRecord(on: connection)
                return
            }

            let helloResponder = SessionHelloResponder(
                routeBinding: signed.hello.routeBinding,
                responder: localKey,
                initiator: signed.hello.initiator,
                initiatorNonce: signed.hello.nonce,
                responderNonce: secureRandom32(),
                metadata: localMetadata)
            guard let signedResponder = try? SignedSessionHelloResponder.sign(
                    helloResponder,
                    with: config.signingKey),
                  let sessionID = try? SessionID(initiator: signed, responder: signedResponder) else {
                rejectRecord(on: connection)
                return
            }

            pending.helloInitiator = signed
            pending.helloResponder = signedResponder
            pending.sessionID = sessionID
            pending.remoteKey = signed.hello.initiator
            pending.remoteMetadata = remoteMetadata
            pendingSessions[connection.connectionID] = pending
            guard sendSessionRecord(.helloResponder(signedResponder), on: connection) else {
                failPendingSession(connection.connectionID)
                return
            }

        case .helloResponder(let signed):
            guard case .initiator(let expected, let routeBinding) = pending.direction,
                  let helloInitiator = pending.helloInitiator,
                  pending.helloResponder == nil,
                  signed.isValid(),
                  signed.hello.routeBinding == routeBinding,
                  signed.hello.responder == expected,
                  signed.hello.initiator == localKey,
                  signed.hello.initiatorNonce == helloInitiator.hello.nonce,
                  peerMeetsDifficulty(expected),
                  let remoteMetadata = try? PeerMetadata.decodeCanonical(signed.hello.metadata),
                  let sessionID = try? SessionID(initiator: helloInitiator, responder: signed),
                  let finish = try? SessionFinish.sign(
                    sessionID: sessionID,
                    sender: localKey,
                    receiver: expected,
                    with: config.signingKey) else {
                rejectRecord(on: connection)
                return
            }

            pending.helloResponder = signed
            pending.sessionID = sessionID
            pending.remoteKey = expected
            pending.remoteMetadata = remoteMetadata
            pendingSessions[connection.connectionID] = pending
            guard sendSessionRecord(.finish(finish), on: connection) else {
                failPendingSession(connection.connectionID)
                return
            }
            await promotePendingSession(pending)

        case .finish(let finish):
            guard case .responder = pending.direction,
                  let sessionID = pending.sessionID,
                  let remoteKey = pending.remoteKey,
                  finish.sessionID == sessionID,
                  finish.sender == remoteKey,
                  finish.receiver == localKey,
                  finish.isValid() else {
                rejectRecord(on: connection)
                return
            }
            await promotePendingSession(pending)

        case .data:
            rejectRecord(on: connection)
        }
    }

    func acceptsInboundHello(_ hello: SessionHelloInitiator, on connection: PeerConnection) -> Bool {
        guard hello.responder == localKey, hello.initiator != localKey else { return false }
        switch connection.transport {
        case .direct:
            guard hello.routeBinding == Self.directRouteBinding else { return false }
            return config.allowsEndpoint(hello.initiator)
                || config.isConfiguredCarrier(hello.initiator)
        case .relayed(let routeID, let carrier):
            guard hello.routeBinding == routeID,
                  let installed = installedRoutes[routeID],
                  installed.carrier == carrier,
                  installed.remote == hello.initiator else { return false }
            return config.allowsEndpoint(hello.initiator)
        }
    }

    private func peerMeetsDifficulty(_ key: PeerKey) -> Bool {
        config.minPeerKeyBits == 0
            || KeyDifficulty.trailingZeroBits(of: key.hex) >= config.minPeerKeyBits
    }

    private func localMetadata(for connection: PeerConnection) -> PeerMetadata {
        var addresses: [ListenAddress] = []
        if let external = config.externalAddress {
            addresses.append(ListenAddress(host: external.host, port: external.port))
        } else {
            if let publicAddress {
                addresses.append(ListenAddress(host: publicAddress.host, port: publicAddress.port))
            }
            if let localHost = connection.channel?.localAddress?.ipAddress,
               localHost != "0.0.0.0", localHost != "::" {
                addresses.append(ListenAddress(host: localHost, port: config.listenPort))
            }
        }
        return PeerMetadata(listenAddresses: addresses)
    }

    private func promotePendingSession(_ pending: PendingSession) async {
        let connectionID = pending.connection.connectionID
        guard isCurrentRun(pending.generation),
              pendingSessions[connectionID]?.generation == pending.generation,
              let peerKey = pending.remoteKey,
              let metadata = pending.remoteMetadata,
              let sessionID = pending.sessionID,
              pending.helloInitiator != nil else {
            failPendingSession(connectionID)
            return
        }
        pendingSessions.removeValue(forKey: connectionID)

        // Role is local policy: configured carrier identities stay carrier-only.
        let role: AuthenticatedPeerRole = config.isConfiguredCarrier(peerKey) ? .carrier : .endpoint

        let session = AuthenticatedSession(
            connection: pending.connection,
            peerKey: peerKey,
            role: role,
            sessionID: sessionID,
            metadata: metadata)
        let existing = role == .endpoint ? endpointSessions[peerKey] : carrierSessions[peerKey]

        if let existing,
           existing.connection.isLive,
           existing.sessionID == Self.preferredSessionID(existing.sessionID, sessionID) {
            authenticationWaiters.removeValue(forKey: connectionID)?.resume(returning: true)
            removeRouteConnection(pending.connection)
            pending.connection.cancel()
            return
        }

        if existing == nil,
           (authenticatedConnections.count >= config.maxConnections
            || (pending.connection.isDirect
                && connectionCount(
                    inNetgroup: connectionNetgroup(pending.connection),
                    excluding: peerKey.peerID) >= config.maxConnectionsPerNetgroup)) {
            authenticationWaiters.removeValue(forKey: connectionID)?.resume(returning: false)
            removeRouteConnection(pending.connection)
            pending.connection.cancel()
            return
        }

        if let existing {
            session.didNotifyConnect = existing.didNotifyConnect
            authenticatedConnections.removeValue(forKey: existing.connection.connectionID)
            existing.connection.cancel()
        }

        authenticatedConnections[connectionID] = (peerKey, role)
        if role == .endpoint {
            endpointSessions[peerKey] = session
            let route: PeerEndpoint?
            if let endpoint = firstAdvertisedListenEndpoint(
                key: peerKey,
                addresses: metadata.listenAddresses,
                from: peerKey.peerID) {
                route = endpoint
            } else if case .initiator = pending.direction,
                      !pending.connection.endpoint.host.isEmpty,
                      pending.connection.endpoint.host != "unknown",
                      pending.connection.endpoint.port != 0 {
                route = PeerEndpoint(
                    publicKey: peerKey.hex,
                    host: pending.connection.endpoint.host,
                    port: pending.connection.endpoint.port)
            } else {
                route = nil
            }
            if let route {
                pending.connection.endpoint = route
                router.addPeer(peerKey.peerID, endpoint: route)
            }
        } else {
            carrierSessions[peerKey] = session
        }
        pending.connection.releaseInboundAdmission()

        await healthMonitor?.trackPeer(peerKey.peerID, sessionID: session.sessionID)
        if isCurrent(session),
           session.connection.isLive,
           !session.didNotifyConnect {
            session.didNotifyConnect = true
            delegate?.ivy(self, didConnect: AuthenticatedPeer(
                key: peerKey,
                role: role,
                route: pending.connection.route,
                metadata: metadata))
        }
        authenticationWaiters.removeValue(forKey: connectionID)?.resume(returning: true)
    }

    private func firstAdvertisedListenEndpoint(
        key: PeerKey,
        addresses: [ListenAddress],
        from peer: PeerID
    ) -> PeerEndpoint? {
        for address in addresses {
            let endpoint = PeerEndpoint(publicKey: key.hex, host: address.host, port: address.port)
            if isAcceptableDiscoveredEndpoint(
                endpoint,
                provenance: .selfAdvertisement,
                from: peer
            ) {
                return endpoint
            }
        }
        return nil
    }

    private func rejectRecord(on connection: PeerConnection) {
        if let authority = authenticatedConnections[connection.connectionID],
           let session = sessionForAuthority(authority) {
            rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                session.peerKey,
                direct: session.connection.isDirect,
                evidence: .unverified))
            return
        }
        failPendingSession(connection.connectionID)
    }

    private func rejectAuthenticatedSession(
        _ session: AuthenticatedSession,
        attributedTo peer: PeerKey?
    ) {
        if let peer {
            tally.recordProtocolViolation(peer: peer.peerID)
        }
        teardownAuthenticatedSession(session, reconnect: false)
        session.connection.cancel()
    }

    private func connectionEnded(_ connection: PeerConnection) {
        if pendingSessions[connection.connectionID] != nil {
            failPendingSession(connection.connectionID)
            return
        }
        guard let authority = authenticatedConnections[connection.connectionID],
              let session = sessionForAuthority(authority),
              session.connection === connection else {
            removeRouteConnection(connection)
            return
        }
        teardownAuthenticatedSession(session, reconnect: true)
    }

    private func teardownAuthenticatedSession(
        _ session: AuthenticatedSession,
        reconnect: Bool
    ) {
        let key = session.peerKey
        if session.role == .endpoint {
            guard endpointSessions[key] === session else { return }
            endpointSessions.removeValue(forKey: key)
            router.removePeer(key.peerID)
            cleanupPendingForPeer(key.peerID)
        } else {
            guard carrierSessions[key] === session else { return }
            carrierSessions.removeValue(forKey: key)
        }

        authenticatedConnections.removeValue(forKey: session.connection.connectionID)
        removeRoutes(involving: key)
        if let monitor = healthMonitor {
            let peer = key.peerID
            let sessionID = session.sessionID
            Task {
                await monitor.removePeer(peer, sessionID: sessionID)
            }
        }
        if session.didNotifyConnect {
            delegate?.ivy(self, didDisconnect: key.peerID)
        }

        guard reconnect,
              running,
              let endpoint = configuredReconnectEndpoint(for: key, role: session.role) else { return }
        scheduleReconnect(
            to: endpoint,
            peer: key.peerID,
            role: session.role,
            generation: runGeneration)
    }

    private func configuredReconnectEndpoint(
        for key: PeerKey,
        role: AuthenticatedPeerRole
    ) -> PeerEndpoint? {
        let endpoints = role == .carrier ? config.carriers : config.bootstrapPeers
        return endpoints.first { (try? PeerKey($0.publicKey)) == key }
    }

    private func removeRoutes(involving key: PeerKey) {
        let serviceRouteIDs = relayRoutes.compactMap { routeID, route in
            route.source == key || route.target == key ? routeID : nil
        }
        for routeID in serviceRouteIDs {
            closeRelayRoute(routeID, excluding: key)
        }

        let installedRouteIDs = installedRoutes.compactMap { routeID, route in
            route.carrier == key || route.remote == key ? routeID : nil
        }
        for routeID in installedRouteIDs {
            guard let route = installedRoutes[routeID] else { continue }
            closeInstalledRoute(routeID, notifyCarrier: route.carrier != key)
        }

        let requestIDs = pendingRelayOpens.compactMap { requestID, request in
            request.carrier == key || request.target == key ? requestID : nil
        }
        for requestID in requestIDs {
            pendingRelayOpens.removeValue(forKey: requestID)?.continuation.resume(returning: nil)
        }
    }

    private func removeRouteConnection(_ connection: PeerConnection) {
        guard case .relayed(let routeID, _) = connection.transport,
              routeConnections[routeID] === connection else { return }
        closeInstalledRoute(routeID, notifyCarrier: true)
    }

    private func closeRelayRoute(_ routeID: Data, excluding excluded: PeerKey? = nil) {
        guard let route = relayRoutes[routeID] else { return }
        for participant in [route.source, route.target] where participant != excluded {
            _ = sendRelayControl(.relayClose(routeID: routeID), to: participant)
        }
        relayRoutes.removeValue(forKey: routeID)
    }

    private func closeInstalledRoute(_ routeID: Data, notifyCarrier: Bool) {
        guard let route = installedRoutes[routeID] else { return }
        if notifyCarrier {
            _ = sendRelayControl(.relayClose(routeID: routeID), to: route.carrier)
        }
        installedRoutes.removeValue(forKey: routeID)
        let connection = routeConnections.removeValue(forKey: routeID)
        connection?.cancel()
    }

    // MARK: - Signed Sending

    public func sendMessage(to peer: PeerID, topic: String, payload: Data) -> SendMessageResult {
        enqueueEndpoint(.peerMessage(topic: topic, payload: payload), to: peer)
    }

    public func broadcastMessage(topic: String, payload: Data) {
        let message = Message.peerMessage(topic: topic, payload: payload)
        for key in endpointSessions.keys {
            _ = enqueueEndpoint(message, to: key.peerID)
        }
    }

    @discardableResult
    func fireToPeer(
        _ peer: PeerID,
        _ message: Message,
        bypassAdmission: Bool = false
    ) -> SendMessageResult {
        guard let key = try? PeerKey(peer.publicKey) else { return .notConnected }
        if let session = endpointSessions[key] {
            return enqueue(message, on: session, bypassAdmission: bypassAdmission)
        } else if message.isKeepalive, let session = carrierSessions[key] {
            return enqueue(message, on: session, bypassAdmission: true)
        }
        return .notConnected
    }

    private func enqueueEndpoint(_ message: Message, to peer: PeerID) -> SendMessageResult {
        guard let key = try? PeerKey(peer.publicKey), let session = endpointSessions[key] else {
            return .notConnected
        }
        return enqueue(message, on: session, bypassAdmission: false)
    }

    @discardableResult
    private func enqueue(
        _ message: Message,
        on session: AuthenticatedSession,
        bypassAdmission: Bool
    ) -> SendMessageResult {
        let payload = message.serialize()
        guard !payload.isEmpty else { return .locallyRejected }
        return enqueuePayload(
            payload,
            on: session,
            bypassAdmission: bypassAdmission || message.isKeepalive)
    }

    private func enqueuePayload(
        _ payload: Data,
        on session: AuthenticatedSession,
        bypassAdmission: Bool
    ) -> SendMessageResult {
        guard bypassAdmission || tally.shouldAllow(peer: session.peerKey.peerID) else {
            return .locallyRejected
        }
        guard let sequence = session.sequenceState.takeNextOutgoing() else { return .locallyRejected }
        guard let record = try? SessionDataRecord.sign(
            sessionID: session.sessionID,
            sender: localKey,
            receiver: session.peerKey,
            sequence: sequence,
            payload: payload,
            with: config.signingKey),
              !SessionWireRecord.data(record).serialize().isEmpty else {
            return .locallyRejected
        }
        guard sendSessionRecord(.data(record), on: session.connection) else {
            return .notConnected
        }

        tally.recordSent(peer: session.peerKey.peerID, bytes: payload.count)

        return .enqueued(endpoint: session.peerKey.peerID, route: session.connection.route)
    }

    func enqueueIfCurrent(
        _ message: Message,
        on session: AuthenticatedSession,
        bypassAdmission: Bool = false
    ) -> SendMessageResult {
        guard isCurrent(session) else { return .notConnected }
        return enqueue(message, on: session, bypassAdmission: bypassAdmission)
    }

    private func sendRelayControl(_ message: Message, to key: PeerKey) -> Bool {
        let session: AuthenticatedSession?
        if let carrier = carrierSessions[key] {
            session = carrier
        } else if let endpoint = endpointSessions[key],
                  endpoint.connection.isDirect,
                  endpointMayReceiveRelayControl(message, peer: key) {
            session = endpoint
        } else {
            session = nil
        }
        guard let session else { return false }
        if case .enqueued = enqueue(message, on: session, bypassAdmission: true) {
            return true
        }
        return false
    }

    private func sendSessionRecord(_ record: SessionWireRecord, on connection: PeerConnection) -> Bool {
        switch connection.transport {
        case .direct:
            return connection.sendRecord(record)
        case .relayed(let routeID, let carrier):
            guard connection.isLive,
                  installedRoutes[routeID]?.carrier == carrier else { return false }
            let payload = record.serialize()
            guard !payload.isEmpty else { return false }
            return sendRelayControl(
                .relayPacket(routeID: routeID, opaqueEndpointRecord: payload),
                to: carrier)
        }
    }

    // MARK: - Signed Receiving

    private func handleAuthenticatedData(
        _ record: SessionDataRecord,
        session: AuthenticatedSession
    ) async {
        guard isCurrent(session) else { return }
        guard record.sessionID == session.sessionID,
              session.sequenceState.canAcceptIncoming(record.sequence) else {
            rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                session.peerKey,
                direct: session.connection.isDirect,
                evidence: .unverified))
            return
        }
        guard record.isValid(sender: session.peerKey, receiver: localKey) else {
            rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                session.peerKey,
                direct: session.connection.isDirect,
                evidence: .unverified))
            return
        }
        let transportAttribution = Self.attributedPeer(
            session.peerKey,
            direct: session.connection.isDirect,
            evidence: .signedTransport)
        guard session.sequenceState.acceptIncoming(record.sequence) else {
            rejectAuthenticatedSession(session, attributedTo: transportAttribution)
            return
        }
        tally.recordReceived(peer: session.peerKey.peerID, bytes: record.payload.count)

        guard let message = Message.deserialize(record.payload) else {
            rejectAuthenticatedSession(session, attributedTo: Self.attributedPeer(
                session.peerKey,
                direct: session.connection.isDirect,
                evidence: .signedPayload))
            return
        }

        if isRelayControl(message) {
            if case .relayClose(let routeID) = message,
               relayCloseMatches(routeID, sender: session.peerKey) {
                // A valid close releases bounded state and must remain available under load.
            } else if !tally.shouldAllow(peer: session.peerKey.peerID) {
                return
            }
            guard sessionMayCarryRelayControl(message, session: session) else {
                rejectAuthenticatedSession(session, attributedTo: session.peerKey)
                return
            }
            handleRelayControl(message, from: session.peerKey)
            return
        }

        if session.role == .carrier {
            switch message {
            case .ping, .pong:
                break
            default:
                rejectAuthenticatedSession(session, attributedTo: session.peerKey)
                return
            }
        }
        await handleMessage(message, from: session.peerKey.peerID, session: session)
    }

    private func isRelayControl(_ message: Message) -> Bool {
        switch message {
        case .relayOpen, .relayOffer, .relayAccept, .relayReady, .relayPacket, .relayClose:
            return true
        default:
            return false
        }
    }

    private func sessionMayCarryRelayControl(
        _ message: Message,
        session: AuthenticatedSession
    ) -> Bool {
        guard session.connection.isDirect else { return false }
        if session.role == .carrier {
            return config.isConfiguredCarrier(session.peerKey)
        }

        switch message {
        case .relayOpen:
            return config.relayEnabled
        case .relayOffer:
            // Inbound route offers do not grant endpoint authority. The
            // relayed handshake still authenticates both endpoint keys.
            return true
        case .relayAccept(let routeID, _):
            return relayRoutes[routeID]?.target == session.peerKey
        case .relayReady(let routeID, _):
            return pendingRelayOpens[routeID]?.carrier == session.peerKey
        case .relayPacket(let routeID, _):
            return relayParticipant(routeID, peer: session.peerKey)
        case .relayClose(let routeID):
            return relayCloseMatches(routeID, sender: session.peerKey)
        default:
            return false
        }
    }

    private func endpointMayReceiveRelayControl(_ message: Message, peer: PeerKey) -> Bool {
        switch message {
        case .relayOffer(let routeID, _):
            return config.relayEnabled && relayRoutes[routeID]?.target == peer
        case .relayReady(let routeID, _):
            return config.relayEnabled && relayRoutes[routeID]?.source == peer
        case .relayAccept(let routeID, _), .relayPacket(let routeID, _), .relayClose(let routeID):
            return relayParticipant(routeID, peer: peer)
        default:
            return false
        }
    }

    private func relayParticipant(_ routeID: Data, peer: PeerKey) -> Bool {
        if let route = relayRoutes[routeID] {
            return route.source == peer || route.target == peer
        }
        return installedRoutes[routeID]?.carrier == peer
            || pendingRelayOpens[routeID]?.carrier == peer
    }

    private func relayCloseMatches(_ routeID: Data, sender: PeerKey) -> Bool {
        if let route = relayRoutes[routeID] {
            return route.source == sender || route.target == sender
        }
        return installedRoutes[routeID]?.carrier == sender
            || pendingRelayOpens[routeID]?.carrier == sender
    }

    // MARK: - Relay Routes

    public func connectViaRelay(to endpoint: PeerEndpoint) async throws {
        try await connectViaRelay(to: endpoint, requiredGeneration: runGeneration)
    }

    private func connectViaRelay(
        to endpoint: PeerEndpoint,
        requiredGeneration generation: UInt64
    ) async throws {
        guard let target = try? PeerKey(endpoint.publicKey) else { throw IvyError.invalidPeerKey }
        guard config.allowsEndpoint(target) else { throw IvyError.peerOutsideMode }
        guard isCurrentRun(generation) else { throw IvyError.notRunning }
        if endpointSessions[target] != nil { return }
        guard installedRoutes.count + pendingRelayOpens.count < Self.maxRelayRoutes else {
            throw IvyError.noRelayAvailable
        }

        let candidates = carrierSessions.values
            .filter { $0.connection.isDirect }
            .map(\.peerKey)

        for carrier in candidates.sorted() {
            guard isCurrentRun(generation) else { throw IvyError.notRunning }
            guard let routeID = await requestRelayRoute(
                target: target,
                via: carrier,
                generation: generation) else {
                continue
            }
            guard isCurrentRun(generation) else { throw IvyError.notRunning }
            let connection = makeRelayedConnection(
                endpoint: PeerEndpoint(publicKey: target.hex, host: endpoint.host, port: endpoint.port),
                routeID: routeID,
                carrier: carrier)
            routeConnections[routeID] = connection
            Task { await self.handleInbound(connection) }
            let authenticated = await authenticateInitiator(
                connection,
                expected: target,
                routeBinding: routeID)
            guard isCurrentRun(generation) else {
                connection.cancel()
                throw IvyError.notRunning
            }
            if authenticated { return }
            closeInstalledRoute(routeID, notifyCarrier: true)
        }
        throw IvyError.noRelayAvailable
    }

    private func requestRelayRoute(
        target: PeerKey,
        via carrier: PeerKey,
        generation: UInt64
    ) async -> Data? {
        guard isCurrentRun(generation) else { return nil }
        let routeID = freshRouteID()

        return await withCheckedContinuation { continuation in
            pendingRelayOpens[routeID] = PendingRelayOpen(
                carrier: carrier,
                target: target,
                continuation: continuation)
            guard sendRelayControl(.relayOpen(routeID: routeID, targetKey: target), to: carrier) else {
                pendingRelayOpens.removeValue(forKey: routeID)
                continuation.resume(returning: nil)
                return
            }
            Task { [weak self] in
                guard let self else { return }
                do {
                    try await Task.sleep(for: self.config.relayTimeout)
                } catch {
                    return
                }
                await self.timeoutRelayOpen(routeID)
            }
        }
    }

    private func timeoutRelayOpen(_ routeID: Data) {
        guard let pending = pendingRelayOpens.removeValue(forKey: routeID) else { return }
        _ = sendRelayControl(.relayClose(routeID: routeID), to: pending.carrier)
        pending.continuation.resume(returning: nil)
    }

    private func handleRelayControl(_ message: Message, from sender: PeerKey) {
        switch message {
        case .relayOpen(let routeID, let target):
            guard routeID.count == 32,
                  routeID != Self.directRouteBinding,
                  relayRoutes[routeID] == nil,
                  installedRoutes[routeID] == nil else {
                tally.recordProtocolViolation(peer: sender.peerID)
                return
            }
            guard relayRoutes.count < Self.maxRelayRoutes else {
                _ = sendRelayControl(.relayReady(routeID: routeID, status: 1), to: sender)
                return
            }
            guard relayRoutes.values.lazy.filter({ $0.source == sender }).count
                    < Self.maxRelayRoutesPerPeer else {
                _ = sendRelayControl(.relayReady(routeID: routeID, status: 1), to: sender)
                return
            }
            guard config.relayEnabled,
                  sender != target,
                  let targetSession = endpointSessions[target],
                  targetSession.connection.isDirect else {
                _ = sendRelayControl(
                    .relayReady(
                        routeID: routeID,
                        status: 1),
                    to: sender)
                return
            }

            relayRoutes[routeID] = RelayRoute(
                source: sender,
                target: target,
                ready: false,
                lastActivity: .now)
            scheduleUnreadyRelayExpiry(routeID)
            guard sendRelayControl(.relayOffer(routeID: routeID, sourceKey: sender), to: target) else {
                relayRoutes.removeValue(forKey: routeID)
                _ = sendRelayControl(
                    .relayReady(routeID: routeID, status: 1),
                    to: sender)
                return
            }

        case .relayOffer(let routeID, let source):
            guard routeID.count == 32,
                  source != localKey,
                  config.allowsEndpoint(source),
                  relayRoutes[routeID] == nil,
                  installedRoutes[routeID] == nil else {
                _ = sendRelayControl(.relayAccept(routeID: routeID, status: 1), to: sender)
                return
            }
            guard installedRoutes.count < Self.maxRelayRoutes else {
                _ = sendRelayControl(.relayAccept(routeID: routeID, status: 1), to: sender)
                return
            }
            guard installedRoutes.values.lazy.filter({ $0.carrier == sender }).count
                    < Self.maxRelayRoutesPerPeer else {
                _ = sendRelayControl(.relayAccept(routeID: routeID, status: 1), to: sender)
                return
            }
            installedRoutes[routeID] = InstalledRoute(carrier: sender, remote: source)
            scheduleIdleInstalledRouteExpiry(routeID, carrier: sender)
            guard sendRelayControl(.relayAccept(routeID: routeID, status: 0), to: sender) else {
                installedRoutes.removeValue(forKey: routeID)
                return
            }

        case .relayAccept(let routeID, let status):
            guard var route = relayRoutes[routeID], route.target == sender else {
                tally.recordProtocolViolation(peer: sender.peerID)
                return
            }
            guard status == 0 else {
                relayRoutes.removeValue(forKey: routeID)
                _ = sendRelayControl(
                    .relayReady(routeID: routeID, status: status),
                    to: route.source)
                return
            }
            route.ready = true
            route.lastActivity = .now
            relayRoutes[routeID] = route
            scheduleRelayIdleExpiry(routeID)
            guard sendRelayControl(
                    .relayReady(routeID: routeID, status: 0),
                    to: route.source) else {
                closeRelayRoute(routeID)
                return
            }

        case .relayReady(let routeID, let status):
            guard let pending = pendingRelayOpens.removeValue(forKey: routeID),
                  pending.carrier == sender else {
                tally.recordProtocolViolation(peer: sender.peerID)
                return
            }
            guard status == 0,
                  routeID.count == 32,
                  routeID != Self.directRouteBinding,
                  installedRoutes.count < Self.maxRelayRoutes,
                  installedRoutes[routeID] == nil,
                  relayRoutes[routeID] == nil else {
                pending.continuation.resume(returning: nil)
                return
            }
            installedRoutes[routeID] = InstalledRoute(
                carrier: sender,
                remote: pending.target)
            scheduleIdleInstalledRouteExpiry(routeID, carrier: sender)
            pending.continuation.resume(returning: routeID)

        case .relayClose(let routeID):
            if let route = relayRoutes[routeID] {
                guard route.source == sender || route.target == sender else { return }
                closeRelayRoute(routeID, excluding: sender)
                return
            }
            if let pending = pendingRelayOpens[routeID], pending.carrier == sender {
                pendingRelayOpens.removeValue(forKey: routeID)?.continuation.resume(returning: nil)
                return
            }
            guard installedRoutes[routeID]?.carrier == sender else { return }
            closeInstalledRoute(routeID, notifyCarrier: false)

        case .relayPacket(let routeID, let opaqueRecord):
            if var route = relayRoutes[routeID] {
                guard route.ready else { return }
                let destination: PeerKey
                if route.source == sender {
                    destination = route.target
                } else if route.target == sender {
                    destination = route.source
                } else {
                    tally.recordProtocolViolation(peer: sender.peerID)
                    return
                }
                route.lastActivity = .now
                relayRoutes[routeID] = route
                guard let destinationSession = endpointSessions[destination],
                      destinationSession.connection.isDirect else {
                    closeRelayRoute(routeID)
                    return
                }
                guard sendRelayControl(
                        .relayPacket(routeID: routeID, opaqueEndpointRecord: opaqueRecord),
                        to: destination) else {
                    closeRelayRoute(routeID)
                    return
                }
                return
            }

            guard let installed = installedRoutes[routeID],
                  installed.carrier == sender else {
                return
            }
            if let connection = routeConnections[routeID] {
                guard connection.feedRecord(opaqueRecord) else {
                    closeInstalledRoute(routeID, notifyCarrier: true)
                    return
                }
                return
            }

            guard let firstRecord = try? SessionWireRecord.deserialize(
                    opaqueRecord),
                  case .helloInitiator(let hello) = firstRecord,
                  hello.isValid(),
                  hello.hello.initiator == installed.remote,
                  hello.hello.responder == localKey,
                  hello.hello.routeBinding == routeID else {
                closeInstalledRoute(routeID, notifyCarrier: true)
                return
            }

            let endpoint = PeerEndpoint(
                publicKey: installed.remote.hex,
                host: "relay",
                port: 0)
            let connection = makeRelayedConnection(
                endpoint: endpoint,
                routeID: routeID,
                carrier: sender)
            guard registerInboundConnection(connection, generation: runGeneration) else {
                closeInstalledRoute(routeID, notifyCarrier: true)
                return
            }
            routeConnections[routeID] = connection
            guard connection.feedRecord(opaqueRecord) else {
                failPendingSession(connection.connectionID)
                closeInstalledRoute(routeID, notifyCarrier: true)
                return
            }

        default:
            return
        }
    }

    private func scheduleUnreadyRelayExpiry(_ routeID: Data) {
        Task { [weak self] in
            guard let self else { return }
            do {
                try await Task.sleep(for: self.config.relayTimeout)
            } catch {
                return
            }
            await self.expireUnreadyRelayRoute(routeID)
        }
    }

    private func expireUnreadyRelayRoute(_ routeID: Data) {
        guard relayRoutes[routeID]?.ready == false else { return }
        closeRelayRoute(routeID)
    }

    private func scheduleRelayIdleExpiry(_ routeID: Data, after delay: Duration? = nil) {
        Task { [weak self] in
            guard let self else { return }
            do {
                try await Task.sleep(for: delay ?? Self.relayIdleTimeout)
            } catch {
                return
            }
            await self.expireIdleRelayRoute(routeID)
        }
    }

    private func expireIdleRelayRoute(_ routeID: Data) {
        guard let route = relayRoutes[routeID], route.ready else { return }
        let idle = route.lastActivity.duration(to: .now)
        if idle >= Self.relayIdleTimeout {
            closeRelayRoute(routeID)
        } else {
            scheduleRelayIdleExpiry(routeID, after: Self.relayIdleTimeout - idle)
        }
    }

    private func scheduleIdleInstalledRouteExpiry(_ routeID: Data, carrier: PeerKey) {
        Task { [weak self] in
            guard let self else { return }
            do {
                try await Task.sleep(for: self.config.relayTimeout)
            } catch {
                return
            }
            await self.expireIdleInstalledRoute(routeID, carrier: carrier)
        }
    }

    private func expireIdleInstalledRoute(_ routeID: Data, carrier: PeerKey) {
        guard routeConnections[routeID] == nil,
              installedRoutes[routeID]?.carrier == carrier else { return }
        closeInstalledRoute(routeID, notifyCarrier: true)
    }

    private func freshRouteID() -> Data {
        var routeID = secureRandom32()
        while routeID == Self.directRouteBinding
            || relayRoutes[routeID] != nil
            || installedRoutes[routeID] != nil {
            routeID = secureRandom32()
        }
        return routeID
    }

    private func makeRelayedConnection(
        endpoint: PeerEndpoint,
        routeID: Data,
        carrier: PeerKey
    ) -> PeerConnection {
        PeerConnection(
            endpoint: endpoint,
            routeID: routeID,
            carrier: carrier,
            inboundByteBudget: inboundByteBudget)
    }

    // MARK: - Message Handling

    func handleMessage(
        _ message: Message,
        from peer: PeerID,
        session: AuthenticatedSession? = nil
    ) async {
        if let session {
            guard isCurrent(session) else { return }
            if let monitor = healthMonitor {
                await monitor.recordActivity(from: peer, sessionID: session.sessionID)
            }
        }
        if case .pong = message {
            // Pongs discharge a ping already admitted by this node.
        } else if !tally.shouldAllow(peer: peer) {
            return
        }
        switch message {
        case .ping(let nonce):
            fireToPeer(peer, .pong(nonce: nonce))

        case .pong(let nonce):
            if let monitor = healthMonitor, let session {
                await monitor.recordPong(
                    from: peer,
                    sessionID: session.sessionID,
                    nonce: nonce)
            }

        case .relayOpen, .relayOffer, .relayAccept, .relayReady, .relayPacket, .relayClose:
            return

        case .findNode(let target, let nonce):
            let closest = router.closestPeers(to: Array(target), count: config.kBucketSize)
            let endpoints = closest.map { $0.endpoint }
            fireToPeer(peer, .neighbors(endpoints, nonce: nonce))

        case .neighbors(let endpoints, let nonce):
            guard isExpectedNeighborResponse(nonce: nonce, from: peer) else { return }
            var accepted: [PeerEndpoint] = []
            for ep in endpoints {
                guard isAcceptableDiscoveredEndpoint(
                        ep,
                        provenance: .referral("neighbors"),
                        from: peer),
                      let key = try? PeerKey(ep.publicKey) else { continue }
                let canonical = PeerEndpoint(
                    publicKey: key.hex,
                    host: ep.host.trimmingCharacters(in: .whitespacesAndNewlines),
                    port: ep.port)
                accepted.append(canonical)
            }
            receiveNeighborResponse(nonce: nonce, endpoints: accepted, from: peer)

        case .contentRequest(let requestID, let rootCID, let cids):
            await handleContentRequest(
                requestID: requestID,
                rootCID: rootCID,
                cids: cids,
                from: peer,
                session: session
            )

        case .contentResponse(let requestID, let entries):
            handleContentResponse(requestID: requestID, entries: entries, from: peer)

        case .contentUnavailable(let requestID):
            handleContentUnavailable(requestID: requestID, from: peer)

        case .findProviders(let rootCID, let requestID):
            handleFindProviders(rootCID: rootCID, requestID: requestID, from: peer)

        case .providers(let rootCID, let requestID, let records):
            handleProvidersResponse(
                rootCID: rootCID,
                requestID: requestID,
                records: records,
                from: peer)

        case .announceProvider(let rootCID, let expiresAt):
            handleAnnounceProvider(rootCID: rootCID, expiresAt: expiresAt, from: peer)

        case .peerMessage(let topic, let payload):
            delegate?.ivy(
                self,
                didReceiveMessage: PeerMessage(topic: topic, payload: payload),
                from: peer)
        }
    }

    func requestNeighbors(
        from peer: PeerID,
        targetHash: [UInt8],
        generation: UInt64,
        timeout: Duration
    ) async -> [PeerEndpoint] {
        guard isCurrentRun(generation) else { return [] }
#if DEBUG || IVY_TESTING
        if let hook = neighborRequestHookForTesting {
            let endpoints = await hook(peer, targetHash)
            return isCurrentRun(generation) ? endpoints : []
        }
#endif
        guard hasEndpointSession(peer),
              pendingNeighborResponses.count < config.maxPendingRequests else { return [] }
        let nonce = makeFindNodeNonce()
        let endpoints = await withCheckedContinuation { cont in
            pendingNeighborResponses[nonce] = PendingNeighborResponse(
                peer: peer,
                continuation: cont)
            guard case .enqueued = fireToPeer(
                peer,
                .findNode(target: Data(targetHash), nonce: nonce)) else {
                resolveNeighborResponse(nonce: nonce, endpoints: [])
                return
            }
            Task { [weak self] in
                do {
                    try await Task.sleep(for: timeout)
                } catch {
                    return
                }
                await self?.resolveNeighborResponse(nonce: nonce, endpoints: [])
            }
        }
        return isCurrentRun(generation) ? endpoints : []
    }

    func receiveNeighborResponse(nonce: UInt64, endpoints: [PeerEndpoint], from peer: PeerID) {
        guard isExpectedNeighborResponse(nonce: nonce, from: peer) else { return }
        resolveNeighborResponse(nonce: nonce, endpoints: endpoints)
    }

    func resolveNeighborResponse(nonce: UInt64, endpoints: [PeerEndpoint]) {
        guard let pending = pendingNeighborResponses.removeValue(forKey: nonce) else { return }
        pending.continuation.resume(returning: endpoints)
    }

    func isExpectedNeighborResponse(nonce: UInt64, from peer: PeerID) -> Bool {
        pendingNeighborResponses[nonce]?.peer == peer
    }

    func makeFindNodeNonce() -> UInt64 {
        var nonce = UInt64.random(in: 1...UInt64.max)
        while pendingNeighborResponses[nonce] != nil {
            nonce = UInt64.random(in: 1...UInt64.max)
        }
        return nonce
    }

    // MARK: - Cleanup

    func cleanupPendingForPeer(_ peer: PeerID) {
        let requestIDs = pendingContentRequests.compactMap { requestID, request in
            request.candidates.contains(peer) ? requestID : nil
        }
        for requestID in requestIDs {
            markContentCandidateDone(requestID: requestID, peer: peer)
        }

        let peerKey = peer.publicKey
        let providerRoots = pendingProviderQueries.compactMap { rootCID, pending in
            pending.expectedPeers.contains(peerKey) ? rootCID : nil
        }
        for rootCID in providerRoots {
            guard var pending = pendingProviderQueries[rootCID] else { continue }
            pending.expectedPeers.remove(peerKey)
            if pending.expectedPeers.isEmpty {
                resolveProviderQuery(rootCID: rootCID, requestID: pending.requestID)
            } else {
                pendingProviderQueries[rootCID] = pending
            }
        }
    }

    /// Resume every in-flight continuation with an empty result. Shared by
    /// `cleanupAllPending` (stop/reset) and `deinit` (teardown safety net).
    private static func drainAllPending(
        pendingContentRequests: [UInt64: PendingContentRequest],
        pendingNeighborResponses: [UInt64: PendingNeighborResponse],
        pendingProviderQueries: [String: PendingProviderQuery],
        authenticationWaiters: [UUID: CheckedContinuation<Bool, Never>],
        pendingRelayOpens: [Data: PendingRelayOpen]
    ) {
        for (_, request) in pendingContentRequests {
            for cont in request.continuations { cont.resume(returning: .empty) }
        }
        for (_, pending) in pendingNeighborResponses {
            pending.continuation.resume(returning: [])
        }
        for (_, pending) in pendingProviderQueries {
            for cont in pending.continuations { cont.resume(returning: []) }
        }
        for (_, continuation) in authenticationWaiters {
            continuation.resume(returning: false)
        }
        for (_, request) in pendingRelayOpens {
            request.continuation.resume(returning: nil)
        }
    }

    /// Safety net for an instance released with requests still in flight.
    deinit {
        Self.drainAllPending(
            pendingContentRequests: pendingContentRequests,
            pendingNeighborResponses: pendingNeighborResponses,
            pendingProviderQueries: pendingProviderQueries,
            authenticationWaiters: authenticationWaiters,
            pendingRelayOpens: pendingRelayOpens
        )
    }

    func cleanupAllPending() {
        Self.drainAllPending(
            pendingContentRequests: pendingContentRequests,
            pendingNeighborResponses: pendingNeighborResponses,
            pendingProviderQueries: pendingProviderQueries,
            authenticationWaiters: authenticationWaiters,
            pendingRelayOpens: pendingRelayOpens
        )
        pendingContentRequests.removeAll()
        contentRequestIDs.removeAll()
        for pending in pendingNetworkFetches.values {
            for waiter in pending.waiters { waiter.resume(returning: .empty) }
        }
        pendingNetworkFetches.removeAll()
        servingContentRequests.removeAll()
        pendingNeighborResponses.removeAll()
        pendingProviderQueries.removeAll()
        authenticationWaiters.removeAll()
        pendingRelayOpens.removeAll()
    }

    // MARK: - Private Helpers

    func closestCandidateEntries(
        _ entries: some Sequence<Router.BucketEntry>,
        to targetHash: [UInt8]
    ) -> [Router.BucketEntry] {
        Array(entries)
            .sorted { Router.isCloser($0.hash, than: $1.hash, to: targetHash) }
            .prefix(config.kBucketSize)
            .map { $0 }
    }

    static func preferredSessionID(_ first: SessionID, _ second: SessionID) -> SessionID {
        min(first, second)
    }

#if DEBUG || IVY_TESTING
    var contentReplyConnectionsForTesting: [UUID] = []
    var lifecycleRequestCountForTesting = 0
    var lifecycleStartHookForTesting: (@Sendable () async -> Void)?
    var lifecycleRequestHookForTesting: (@Sendable (Int) async -> Void)?
    var neighborRequestHookForTesting: (@Sendable (PeerID, [UInt8]) async -> [PeerEndpoint])?
    var networkFetchHookForTesting: (
        @Sendable (ContentRequestKey, UInt64, UInt64) async -> AttributedContentResponse
    )?
    var dialEndpointRewriteForTesting: (@Sendable (PeerEndpoint) -> PeerEndpoint)?

    func setLifecycleStartHookForTesting(_ hook: (@Sendable () async -> Void)?) {
        lifecycleStartHookForTesting = hook
    }

    func setLifecycleRequestHookForTesting(_ hook: (@Sendable (Int) async -> Void)?) {
        lifecycleRequestHookForTesting = hook
    }

    func setNeighborRequestHookForTesting(
        _ hook: (@Sendable (PeerID, [UInt8]) async -> [PeerEndpoint])?
    ) {
        neighborRequestHookForTesting = hook
    }

    func setNetworkFetchHookForTesting(
        _ hook: (
            @Sendable (ContentRequestKey, UInt64, UInt64) async -> AttributedContentResponse
        )?
    ) {
        networkFetchHookForTesting = hook
    }

    func setDialEndpointRewriteForTesting(
        _ rewrite: (@Sendable (PeerEndpoint) -> PeerEndpoint)?
    ) {
        dialEndpointRewriteForTesting = rewrite
    }

    func seedConnectedEndpointForTesting(
        _ endpoint: PeerEndpoint,
        connection suppliedConnection: PeerConnection? = nil,
        marker: UInt8
    ) throws {
        let peerKey = try PeerKey(endpoint.publicKey)
        let connection = suppliedConnection ?? PeerConnection(
            endpoint: endpoint,
            routeID: Data(repeating: marker, count: 32),
            carrier: peerKey,
            inboundByteBudget: inboundByteBudget)
        endpointSessions[peerKey] = AuthenticatedSession(
            connection: connection,
            peerKey: peerKey,
            role: .endpoint,
            sessionID: try SessionID(bytes: Data(repeating: marker, count: 32)),
            metadata: PeerMetadata())
    }

    func sendAuthenticatedMessageForTesting(_ message: Message, to peer: PeerID) -> Bool {
        guard let key = try? PeerKey(peer.publicKey),
              let session = authenticatedSession(for: key) else { return false }
        if case .enqueued = enqueue(message, on: session, bypassAdmission: true) {
            return true
        }
        return false
    }

    func handleRelayControlForTesting(_ message: Message, from sender: PeerKey) {
        handleRelayControl(message, from: sender)
    }

    var installedRouteCountForTesting: Int { installedRoutes.count }

    func runPendingReconnectForTesting(_ peer: PeerID) async {
        guard let pending = reconnectTasks[peer],
              let key = try? PeerKey(peer.publicKey) else { return }
        let role: AuthenticatedPeerRole = config.isConfiguredCarrier(key) ? .carrier : .endpoint
        guard let endpoint = configuredReconnectEndpoint(for: key, role: role) else { return }
        pending.task.cancel()
        await runScheduledReconnect(
            to: endpoint,
            peer: peer,
            role: role,
            generation: pending.generation,
            token: pending.token)
    }

    func handleContentRequestForTesting(
        connection: PeerConnection,
        peerKey: PeerKey,
        sessionMarker: UInt8,
        requestID: UInt64
    ) async {
        let session = AuthenticatedSession(
            connection: connection,
            peerKey: peerKey,
            role: .endpoint,
            sessionID: try! SessionID(bytes: Data(repeating: sessionMarker, count: 32)),
            metadata: PeerMetadata())
        running = true
        endpointSessions[session.peerKey] = session
        await handleContentRequest(
            requestID: requestID,
            rootCID: "root",
            cids: [],
            from: peerKey.peerID,
            session: session)
    }

    func selectedSessionIDForTesting(_ peer: PeerID) -> Data? {
        guard let key = try? PeerKey(peer.publicKey) else { return nil }
        return endpointSessions[key]?.sessionID.bytes
    }

    var pendingSessionCountForTesting: Int { pendingSessions.count }

    var sentContentRepliesForTesting: [UUID] { contentReplyConnectionsForTesting }
#endif

    func startListener(
        generation: UInt64
    ) async throws -> (channel: Channel, gate: InboundAdmissionGate) {
        let gate = InboundAdmissionGate(
            maxConnections: config.maxConnections,
            maxConnectionsPerNetgroup: config.maxConnectionsPerNetgroup)
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.autoRead, value: false)
            .childChannelInitializer { channel in
                let connectionBudget = InboundByteBudget(
                    limit: PeerConnection.maxInboundBufferedBytes)
                let decoder = SessionFrameDecoder(
                    budget: self.inboundByteBudget,
                    connectionBudget: connectionBudget)
                let acceptor = InboundConnectionAcceptor(
                    ivy: self,
                    generation: generation,
                    admissionGate: gate,
                    inboundByteBudget: self.inboundByteBudget,
                    connectionInboundByteBudget: connectionBudget
                )
                return channel.pipeline.addHandlers([decoder, acceptor])
            }

        let channel = try await bootstrap
            .bind(host: "0.0.0.0", port: Int(config.listenPort))
            .get()

        return (channel, gate)
    }

}
