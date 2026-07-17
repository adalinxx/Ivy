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
    var helloInitiator: SignedSessionHelloInitiator?
    var helloResponder: SignedSessionHelloResponder?
    var sessionID: SessionID?
    var remoteKey: PeerKey?
    var remoteMetadata: PeerMetadata?
}

private final class AuthenticatedSession {
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

public actor Ivy {
    public let config: IvyConfig
    public let tally: Tally
    var router: Router
    public let localID: PeerID
    let localKey: PeerKey
    let group: EventLoopGroup

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

    /// Endpoint-only view used by the content/routing layer. Pending sessions
    /// and configured carrier identities are deliberately absent.
    var connections: [PeerID: PeerConnection] {
        Dictionary(uniqueKeysWithValues: endpointSessions.map { ($0.key.peerID, $0.value.connection) })
    }
    var serverChannel: Channel?
    var running = false

    let stunClient: STUNClient
    private(set) public var publicAddress: ObservedAddress?
    var routingRefreshTask: Task<Void, Never>?
    var pendingNeighborResponses: [UInt64: PendingNeighborResponse] = [:]
    var healthMonitor: PeerHealthMonitor?
    var connectingPeers: Set<PeerID> = []
    var connectingEndpoints: [PeerID: PeerEndpoint] = [:]
    var reconnectAttempts: [PeerID: Int] = [:]
    var reconnectTasks: [PeerID: Task<Void, Never>] = [:]
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
    var servingContentRequests: Set<InboundContentRequest> = []
    var pendingProviderQueries: [String: PendingProviderQuery] = [:]

    public init(config: IvyConfig, group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton, tally: Tally? = nil) {
        self.config = config
        self.localID = PeerID(publicKey: config.publicKey)
        self.localKey = config.peerKey
        self.tally = tally ?? Tally(config: config.tallyConfig)
        self.router = Router(localID: PeerID(publicKey: config.publicKey), k: config.kBucketSize)
        self.group = group
        self.stunClient = STUNClient(group: group, servers: config.stunServers)
    }

    // MARK: - Lifecycle

    public func start() async throws {
        guard !running, serverChannel == nil else { return }
        try config.validate()
        try await startListener()
        running = true

        if let externalAddress = config.externalAddress {
            let address = ObservedAddress(host: externalAddress.host, port: externalAddress.port)
            publicAddress = address
            delegate?.ivy(self, didDiscoverPublicAddress: address)
        } else if let address = await stunClient.discoverPublicAddress() {
            publicAddress = address
            delegate?.ivy(self, didDiscoverPublicAddress: address)
        }
        guard running else { return }

        for endpoint in config.bootstrapPeers {
            Task { await self.maintainConfiguredConnection(to: endpoint, role: .endpoint) }
        }
        for carrier in config.carriers {
            Task { await self.maintainConfiguredConnection(to: carrier, role: .carrier) }
        }

        let monitor = PeerHealthMonitor(
            config: config.healthConfig,
            onStale: { [weak self] peer in
                guard let self else { return }
                Task { await self.disconnectStale(peer) }
            })
        healthMonitor = monitor
        await monitor.startMonitoring { [weak self] peer, nonce in
            guard let self else { return }
            await self.fireToPeer(peer, .ping(nonce: nonce))
        }
        guard running else { return }

        if config.mode.participatesInPublicDiscovery {
            startRoutingRefresh()
        }
    }

    public func stop() async {
        guard running || serverChannel != nil else { return }
        running = false
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

        connectingPeers.removeAll()
        connectingEndpoints.removeAll()
        for (_, task) in reconnectTasks {
            task.cancel()
        }
        reconnectTasks.removeAll()
        reconnectAttempts.removeAll()
    }

    // MARK: - Authenticated Connections

    private func authenticatedSession(for key: PeerKey) -> AuthenticatedSession? {
        endpointSessions[key] ?? carrierSessions[key]
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
        guard let key = try? PeerKey(endpoint.publicKey) else { throw IvyError.invalidPeerKey }
        guard config.allowsEndpoint(key) else { throw IvyError.peerOutsideMode }
        guard running else { throw IvyError.notRunning }
        try await connectEndpoint(to: endpoint, key: key, allowRelayFallback: true)
    }

    private func connectEndpoint(
        to endpoint: PeerEndpoint,
        key: PeerKey,
        allowRelayFallback: Bool
    ) async throws {
        if endpointSessions[key] != nil { return }
        guard reserveOutgoingDial(to: endpoint) else {
            if endpointSessions[key] != nil { return }
            throw IvyError.identityVerificationFailed
        }

        let connection: PeerConnection
        do {
            connection = try await PeerConnection.dial(
                endpoint: PeerEndpoint(publicKey: key.hex, host: endpoint.host, port: endpoint.port),
                group: group,
                maxFrameSize: config.maxFrameSize)
        } catch {
            finishOutgoingDial(to: key.peerID, connected: false)
            if allowRelayFallback {
                try await connectViaRelay(to: endpoint)
                return
            }
            throw error
        }
        guard running else {
            finishOutgoingDial(to: key.peerID, connected: false)
            connection.cancel()
            throw IvyError.notRunning
        }

        Task { await self.handleInbound(connection) }
        let authenticated = await authenticateInitiator(
            connection,
            expected: key,
            routeBinding: Self.directRouteBinding)
        finishOutgoingDial(to: key.peerID, connected: authenticated)
        guard authenticated else {
            connection.cancel()
            if allowRelayFallback {
                try await connectViaRelay(to: endpoint)
                return
            }
            throw IvyError.identityVerificationFailed
        }
    }

    private func connectCarrier(to endpoint: PeerEndpoint) async throws {
        guard let key = try? PeerKey(endpoint.publicKey), config.isConfiguredCarrier(key) else {
            throw IvyError.peerOutsideMode
        }
        guard running else { throw IvyError.notRunning }
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
                maxFrameSize: config.maxFrameSize)
        } catch {
            finishOutgoingDial(to: key.peerID, connected: false)
            throw error
        }
        guard running else {
            finishOutgoingDial(to: key.peerID, connected: false)
            connection.cancel()
            throw IvyError.notRunning
        }

        Task { await self.handleInbound(connection) }
        let authenticated = await authenticateInitiator(
            connection,
            expected: key,
            routeBinding: Self.directRouteBinding)
        finishOutgoingDial(to: key.peerID, connected: authenticated)
        guard authenticated else {
            connection.cancel()
            throw IvyError.identityVerificationFailed
        }
    }

    func reserveOutgoingDial(to endpoint: PeerEndpoint) -> Bool {
        guard let key = try? PeerKey(endpoint.publicKey),
              authenticatedSession(for: key) == nil,
              !connectingPeers.contains(key.peerID),
              connectionCapacityUsed < config.maxConnections else { return false }

        let targetGroup = NetGroup.group(endpoint.host)
        let pendingInGroup = connectingEndpoints.values.filter {
            NetGroup.group($0.host) == targetGroup
        }.count
        guard connectionCount(inNetgroup: targetGroup, excluding: key.peerID) + pendingInGroup
                < config.maxConnectionsPerNetgroup else {
            return false
        }

        connectingPeers.insert(key.peerID)
        connectingEndpoints[key.peerID] = PeerEndpoint(
            publicKey: key.hex,
            host: endpoint.host,
            port: endpoint.port)
        return true
    }

    func finishOutgoingDial(to peer: PeerID, connected: Bool) {
        connectingPeers.remove(peer)
        connectingEndpoints.removeValue(forKey: peer)
        if connected {
            reconnectAttempts.removeValue(forKey: peer)
            reconnectTasks.removeValue(forKey: peer)?.cancel()
        }
    }

    public func disconnect(_ peer: PeerID) {
        guard let key = try? PeerKey(peer.publicKey) else { return }
        reconnectTasks.removeValue(forKey: key.peerID)?.cancel()
        reconnectAttempts.removeValue(forKey: key.peerID)
        guard let session = authenticatedSession(for: key) else { return }
        teardownAuthenticatedSession(session, reconnect: false)
        session.connection.cancel()
    }

    private func disconnectStale(_ peer: PeerID) {
        guard let key = try? PeerKey(peer.publicKey),
              let session = authenticatedSession(for: key) else { return }
        teardownAuthenticatedSession(session, reconnect: true)
        session.connection.cancel()
    }

    private func scheduleReconnect(to endpoint: PeerEndpoint, peer: PeerID, role: AuthenticatedPeerRole) {
        guard let key = try? PeerKey(peer.publicKey),
              running,
              authenticatedSession(for: key) == nil,
              !connectingPeers.contains(peer),
              reconnectTasks[peer] == nil else { return }

        let delay = reconnectDelay(for: peer)
        reconnectTasks[peer] = Task { [weak self] in
            do {
                try await Task.sleep(for: delay)
            } catch {
                return
            }
            guard let self else { return }
            await self.runScheduledReconnect(to: endpoint, peer: peer, role: role)
        }
    }

    func reconnectDelay(for peer: PeerID) -> Duration {
        let attempt = min((reconnectAttempts[peer] ?? 0) + 1, 16)
        reconnectAttempts[peer] = attempt
        let shift = min(attempt - 1, 10)
        let exponential = Self.reconnectBaseDelayMs * (UInt64(1) << UInt64(shift))
        let capped = min(exponential, Self.reconnectMaxDelayMs)
        return .milliseconds(capped + UInt64.random(in: 0 ... Self.reconnectJitterMs))
    }

    private func runScheduledReconnect(
        to endpoint: PeerEndpoint,
        peer: PeerID,
        role: AuthenticatedPeerRole
    ) async {
        reconnectTasks.removeValue(forKey: peer)
        guard running else { return }
        await maintainConfiguredConnection(to: endpoint, role: role)
    }

    private func maintainConfiguredConnection(
        to endpoint: PeerEndpoint,
        role: AuthenticatedPeerRole
    ) async {
        guard running, let key = try? PeerKey(endpoint.publicKey) else { return }
        do {
            if role == .carrier {
                try await connectCarrier(to: endpoint)
            } else {
                try await connect(to: endpoint)
            }
        } catch {
            scheduleReconnect(to: endpoint, peer: key.peerID, role: role)
        }
    }

    // MARK: - Session Authentication

    private var connectionCapacityUsed: Int {
        authenticatedConnections.count + pendingSessions.count + connectingPeers.count
    }

    func registerInboundConnection(_ connection: PeerConnection) {
        guard connectionCapacityUsed < config.maxConnections else {
            connection.cancel()
            return
        }

        pendingSessions[connection.connectionID] = PendingSession(
            connection: connection,
            direction: .responder)
        Task { await self.handleInbound(connection) }
        schedulePendingTimeout(connection.connectionID)
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
            helloInitiator: signed)

        return await withCheckedContinuation { continuation in
            authenticationWaiters[connection.connectionID] = continuation
            guard sendSessionRecord(.helloInitiator(signed), on: connection) else {
                failPendingSession(connection.connectionID)
                return
            }
            schedulePendingTimeout(connection.connectionID)
        }
    }

    private func schedulePendingTimeout(_ connectionID: UUID) {
        Task { [weak self] in
            do {
                try await Task.sleep(for: .seconds(30))
            } catch {
                return
            }
            await self?.timeoutPendingSession(connectionID)
        }
    }

    private func timeoutPendingSession(_ connectionID: UUID) {
        guard pendingSessions[connectionID] != nil else { return }
        failPendingSession(connectionID)
    }

    private func failPendingSession(_ connectionID: UUID) {
        guard let pending = pendingSessions.removeValue(forKey: connectionID) else { return }
        authenticationWaiters.removeValue(forKey: connectionID)?.resume(returning: false)
        removeRouteConnection(pending.connection)
        pending.connection.cancel()
    }

    private func handleInbound(_ connection: PeerConnection) async {
        for await bytes in connection.records {
            await handleSessionRecord(bytes, on: connection)
        }
        connectionEnded(connection)
    }

    private func handleSessionRecord(_ bytes: Data, on connection: PeerConnection) async {
        let record: SessionWireRecord
        do {
            record = try SessionWireRecord.deserialize(bytes, maxPayload: config.maxFrameSize)
        } catch {
            rejectRecord(on: connection)
            return
        }

        if let authority = authenticatedConnections[connection.connectionID],
           let session = sessionForAuthority(authority),
           session.connection === connection {
            guard case .data(let dataRecord) = record else {
                rejectAuthenticatedSession(session, attributedTo: invalidRecordAttribution(for: session))
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

    private func acceptsInboundHello(_ hello: SessionHelloInitiator, on connection: PeerConnection) -> Bool {
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
        guard pendingSessions[connectionID] != nil,
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

        if let existing, existing.connection.isLive, existing.sessionID <= sessionID {
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

        await healthMonitor?.trackPeer(peerKey.peerID)
        if sessionForAuthority((peerKey, role)) === session,
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
            if isAcceptableDiscoveredEndpoint(endpoint, source: "session metadata", from: peer) {
                return endpoint
            }
        }
        return nil
    }

    private func rejectRecord(on connection: PeerConnection) {
        if let authority = authenticatedConnections[connection.connectionID],
           let session = sessionForAuthority(authority) {
            rejectAuthenticatedSession(session, attributedTo: invalidRecordAttribution(for: session))
            return
        }
        failPendingSession(connection.connectionID)
    }

    private func invalidRecordAttribution(for session: AuthenticatedSession) -> PeerKey? {
        session.connection.isDirect ? session.peerKey : nil
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
        Task { await self.healthMonitor?.removePeer(key.peerID) }
        if session.didNotifyConnect {
            delegate?.ivy(self, didDisconnect: key.peerID)
        }

        guard reconnect,
              running,
              let endpoint = configuredReconnectEndpoint(for: key, role: session.role) else { return }
        scheduleReconnect(
            to: endpoint,
            peer: key.peerID,
            role: session.role)
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
        guard let route = relayRoutes.removeValue(forKey: routeID) else { return }
        for participant in [route.source, route.target] where participant != excluded {
            _ = sendRelayControl(.relayClose(routeID: routeID), to: participant)
        }
    }

    private func closeInstalledRoute(_ routeID: Data, notifyCarrier: Bool) {
        guard let route = installedRoutes.removeValue(forKey: routeID) else { return }
        let connection = routeConnections.removeValue(forKey: routeID)
        if notifyCarrier {
            _ = sendRelayControl(.relayClose(routeID: routeID), to: route.carrier)
        }
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
        let payload = message.serialize(maxFrameSize: config.maxFrameSize)
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
              !SessionWireRecord.data(record).serialize(maxPayload: config.maxFrameSize).isEmpty else {
            return .locallyRejected
        }
        guard sendSessionRecord(.data(record), on: session.connection) else {
            return .notConnected
        }

        tally.recordSent(peer: session.peerKey.peerID, bytes: payload.count)

        return .enqueued(endpoint: session.peerKey.peerID, route: session.connection.route)
    }

    private func sendRelayControl(_ message: Message, to key: PeerKey) -> Bool {
        let session: AuthenticatedSession?
        if let carrier = carrierSessions[key] {
            session = carrier
        } else if case .overlay = config.mode,
                  let endpoint = endpointSessions[key],
                  endpoint.connection.isDirect {
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
            let payload = record.serialize(maxPayload: config.maxFrameSize)
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
        guard record.sessionID == session.sessionID,
              record.isValid(sender: session.peerKey, receiver: localKey),
              session.sequenceState.acceptIncoming(record.sequence) else {
            rejectAuthenticatedSession(session, attributedTo: invalidRecordAttribution(for: session))
            return
        }
        tally.recordReceived(peer: session.peerKey.peerID, bytes: record.payload.count)

        guard let message = Message.deserialize(
            record.payload,
            maxDataPayload: config.maxFrameSize) else {
            rejectAuthenticatedSession(session, attributedTo: session.peerKey)
            return
        }

        if isRelayControl(message) {
            if case .relayClose(let routeID) = message,
               relayCloseMatches(routeID, sender: session.peerKey) {
                // A valid close releases bounded state and must remain available under load.
            } else if !tally.shouldAllow(peer: session.peerKey.peerID) {
                return
            }
            guard sessionMayCarryRelayControl(session) else {
                rejectAuthenticatedSession(session, attributedTo: session.peerKey)
                return
            }
            await handleRelayControl(message, from: session.peerKey)
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
        await handleMessage(message, from: session.peerKey.peerID)
    }

    private func isRelayControl(_ message: Message) -> Bool {
        switch message {
        case .relayOpen, .relayOffer, .relayAccept, .relayReady, .relayPacket, .relayClose:
            return true
        default:
            return false
        }
    }

    private func sessionMayCarryRelayControl(_ session: AuthenticatedSession) -> Bool {
        guard session.connection.isDirect else { return false }
        if session.role == .carrier { return true }
        if case .overlay = config.mode { return true }
        return false
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
        guard let target = try? PeerKey(endpoint.publicKey) else { throw IvyError.invalidPeerKey }
        guard config.allowsEndpoint(target) else { throw IvyError.peerOutsideMode }
        guard running else { throw IvyError.notRunning }
        if endpointSessions[target] != nil { return }
        guard installedRoutes.count + pendingRelayOpens.count < Self.maxRelayRoutes else {
            throw IvyError.noRelayAvailable
        }

        let candidates = carrierSessions.values
            .filter { $0.connection.isDirect }
            .map(\.peerKey)

        for carrier in candidates.sorted() {
            guard let routeID = await requestRelayRoute(target: target, via: carrier) else {
                continue
            }
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
            if authenticated { return }
            closeInstalledRoute(routeID, notifyCarrier: true)
        }
        throw IvyError.noRelayAvailable
    }

    private func requestRelayRoute(target: PeerKey, via carrier: PeerKey) async -> Data? {
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

    private func handleRelayControl(_ message: Message, from sender: PeerKey) async {
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
                connection.feedRecord(opaqueRecord)
                return
            }

            guard let firstRecord = try? SessionWireRecord.deserialize(
                    opaqueRecord,
                    maxPayload: config.maxFrameSize),
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
            routeConnections[routeID] = connection
            registerInboundConnection(connection)
            connection.feedRecord(opaqueRecord)

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
            maxFrameSize: config.maxFrameSize)
    }

    // MARK: - Message Handling

    func handleMessage(_ message: Message, from peer: PeerID) async {
        if let monitor = healthMonitor {
            await monitor.recordActivity(from: peer)
        }
        guard message.isKeepalive || tally.shouldAllow(peer: peer) else { return }
        switch message {
        case .ping(let nonce):
            fireToPeer(peer, .pong(nonce: nonce))

        case .pong(let nonce):
            if let monitor = healthMonitor {
                await monitor.recordPong(from: peer, nonce: nonce)
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
                guard isAcceptableDiscoveredEndpoint(ep, source: "neighbors", from: peer),
                      let key = try? PeerKey(ep.publicKey) else { continue }
                let canonical = PeerEndpoint(
                    publicKey: key.hex,
                    host: ep.host.trimmingCharacters(in: .whitespacesAndNewlines),
                    port: ep.port)
                accepted.append(canonical)
                _ = addDiscoveredPeer(canonical, source: "neighbors", from: peer)
            }
            receiveNeighborResponse(nonce: nonce, endpoints: accepted, from: peer)

        case .contentRequest(let requestID, let rootCID, let cids):
            await handleContentRequest(
                requestID: requestID,
                rootCID: rootCID,
                cids: cids,
                from: peer
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
        timeout: Duration
    ) async -> [PeerEndpoint] {
        guard hasEndpointSession(peer),
              pendingNeighborResponses.count < config.maxPendingRequests else { return [] }
        let nonce = makeFindNodeNonce()
        return await withCheckedContinuation { cont in
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

    func startListener() async throws {
        let maxFrameSize = config.maxFrameSize
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let decoder = SessionFrameDecoder(maxFrameSize: maxFrameSize)
                let acceptor = InboundConnectionAcceptor(
                    ivy: self,
                    maxFrameSize: maxFrameSize
                )
                return channel.pipeline.addHandlers([decoder, acceptor])
            }

        let channel = try await bootstrap
            .bind(host: "0.0.0.0", port: Int(config.listenPort))
            .get()

        self.serverChannel = channel
    }

}
