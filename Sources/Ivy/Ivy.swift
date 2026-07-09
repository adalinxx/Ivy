import Foundation
import NIOCore
import NIOPosix
import Tally
import Crypto

public protocol IvyDataSource: AnyObject, Sendable {
    func data(for cid: String) async -> Data?
    func volumeData(for rootCID: String, cids: [String]) async -> [(cid: String, data: Data)]
    /// Returns true if this node holds a complete-enough copy of the volume rooted
    /// at rootCID to serve a want request. Checks MemoryBroker first, then DiskBroker.
    func hasVolume(rootCID: String) async -> Bool
}

public enum IvyError: Error, Sendable {
    case notRunning
    case identityVerificationFailed
    case noRelayAvailable
}

struct PendingNeighborResponse: Sendable {
    let peer: PeerID
    let continuation: CheckedContinuation<[PeerEndpoint], Never>?
}

struct PendingFindPins {
    var continuations: [CheckedContinuation<[PeerID], Never>]
    var expectedPeers: Set<String>
    let generation: UInt64
}

struct PendingRelayRequestKey: Hashable {
    let relayPeer: PeerID
    let nonce: UInt64
}

public actor Ivy {
    public let config: IvyConfig
    public let tally: Tally
    public let router: Router
    public let localID: PeerID
    public let group: EventLoopGroup

    public weak var delegate: IvyDelegate?
    public weak var dataSource: IvyDataSource?
    public func setDataSource(_ ds: IvyDataSource?) { dataSource = ds }
    public var chainPorts: [String: UInt16] = [:]
    var peerChainPorts: [PeerID: [String: UInt16]] = [:]
    /// Spawn-cert chains peers presented after identify step 2a).
    /// Transport store only — verification/classification against a `trustedRoot`
    /// is the consuming node's policy, via `spawnCertChain(for:)`.
    var peerSpawnCertChains: [PeerID: [SpawnCertificate]] = [:]
    /// This node's own spawn-cert chain, presented right after our identify.
    /// Empty until the node is issued a chain by its spawn-tree parent.
    var ownSpawnCertChain: [SpawnCertificate] = []

    var connections: [PeerID: PeerConnection] = [:]
    // NAT traversal Phase 1 — circuit relay.
    let relayService = RelayService()
    /// In-flight `connectViaRelay` requests, keyed by relay peer + request nonce.
    var pendingRelayRequests: [PendingRelayRequestKey: CheckedContinuation<Bool, Never>] = [:]
    var nextRelayRequestNonce: UInt64 = 0
    /// Relayed connections indexed by the peer's CLAIMED key, for routing inbound
    /// relayData. The connection itself lives in `connections` under a temporary
    /// `inbound-<uuid>` id until a signed identify re-keys it (so an unverified
    /// relayed peer is never attributed to the claimed identity).
    var relayedConnByClaimedKey: [String: PeerConnection] = [:]
    /// Cap on concurrent relayed (channel-less) connections — bounds the phantom
    /// slot DoS where a relay/peer opens relayed entries that never identify.
    static let maxRelayedConnections = 64
    /// Carriers that have successfully opened a circuit for us (endpoint by
    /// public key), bounded and diversity-preferring — the re-dial pool for
    /// `ensureRelayCarrierConnections`. `config.knownRelays` seeds the same
    /// pool at start; a discovered carrier is just as good as a configured one.
    /// A carrier we can re-dial to keep the relay pool populated. Stores the
    /// dialable advertised `endpoint` AND the unforgeable observed `group`
    /// (netgroup captured from the L3 socket at record time) — the group drives
    /// the diversity-preserving eviction and is never re-derived from the
    /// self-advertised endpoint host, which the peer controls.
    struct RelayCarrierSeed: Sendable {
        let endpoint: PeerEndpoint
        let group: String
    }
    var relayCarrierSeeds: [String: RelayCarrierSeed] = [:]
    static let maxRelayCarrierSeeds = 3
    /// Consecutive re-dial failures per carrier seed. A seed that repeatedly
    /// fails to (re)connect is a black hole — dropped from the pool once it hits
    /// `maxRelayCarrierSeedDialFailures` so we stop re-dialing it forever. Reset
    /// on any successful (re)connection.
    var relayCarrierSeedFailures: [String: Int] = [:]
    static let maxRelayCarrierSeedDialFailures = 3
    /// How many relay-capable direct connections a relay-DEPENDENT node keeps
    /// alive (bounded 2-3: one failover alternative + netgroup diversity,
    /// without per-target multi-relay fan-out for the common direct case).
    static let targetRelayCarrierCount = 2
    /// Failover attempts per lost relayed connection before treating the peer
    /// as gone (each attempt already fans out across EVERY connected carrier,
    /// so unlike a direct re-dial there is no point retrying forever — demand
    /// or gossip re-forms the circuit if the peer comes back).
    static let maxRelayFailoverAttempts = 5
    var inboundConnectionIDs: Set<PeerID> = []
    var inboundConnectionOrder: [PeerID] = []
    var pendingRequests: [String: [CheckedContinuation<Data?, Never>]] = [:]
    var serverChannel: Channel?
    #if canImport(Network)
    var discovery: LocalDiscovery?
    #endif
    var running = false

    let stunClient: STUNClient
    private(set) public var publicAddress: ObservedAddress?
    var pendingForwards: [String: [PeerID: UInt64]] = [:]
    var pendingForwardCountsByPeer: [PeerID: Int] = [:]
    var pendingForwardCount = 0
    var nextPendingForwardGeneration: UInt64 = 0
    static let maxPendingForwards = 4_096
    static let maxPendingForwardsPerPeer = 128
    /// Per-peer token bucket for gossip relay. Prevents a single peer
    /// from driving unbounded outbound broadcast amplification.
    var gossipBuckets: [PeerID: TokenBucket] = [:]
    static let announceGossipCapacity: Double = 200
    static let announceGossipRefillPerSec: Double = 50
    /// Per-peer token bucket for inbound findNode (DHT neighbor) requests.
    /// Throttles a peer that floods neighbor queries to map/poison the routing
    /// table, without impeding normal iterative lookups.
    var findNodeBuckets: [PeerID: TokenBucket] = [:]
    var pexTask: Task<Void, Never>?
    var pendingPEX: [UInt64: CheckedContinuation<[PeerEndpoint], Never>] = [:]
    var pendingNeighborLookupNonces: Set<UInt64> = []
    var pendingNeighborResponses: [UInt64: PendingNeighborResponse] = [:]
    var completedNeighborResponses: [UInt64: [PeerEndpoint]] = [:]
    var healthMonitor: PeerHealthMonitor?
    var haveSet = InventorySet()
    var localPeers: [PeerID: LocalPeerConnection] = [:]
    var _serviceBus: LocalServiceBus?
    var connectingPeers: Set<PeerID> = []
    var connectingEndpoints: [PeerID: PeerEndpoint] = [:]
    var reconnectAttempts: [PeerID: Int] = [:]
    var reconnectTasks: [PeerID: Task<Void, Never>] = [:]
    var intentionallyDisconnectedPeers: Set<PeerID> = []
    static let reconnectBaseDelayMs: UInt64 = 500
    static let reconnectMaxDelayMs: UInt64 = 30_000
    static let reconnectJitterMs: UInt64 = 250
    static let kademliaLookupParallelism = 3

    var pinAnnouncements: BoundedDictionary<String, [(publicKey: String, expiry: UInt64)]> = BoundedDictionary(capacity: 10_000)

    // Volume tracking: root CID → provider peer(s) for DHT routing
    var providerRecords: BoundedDictionary<String, [PeerID]> = BoundedDictionary(capacity: 10_000)

    // CONTENT-ADDRESSING INVARIANT
    // ─────────────────────────────────────────────────────────────────────────
    // All data in this network is content-addressed: a CID is the cryptographic
    // hash of its content. Pending Volume fetches are keyed by root CID, not by
    // peer. Ivy treats Volumes as opaque serialized data: any peer can satisfy a
    // root request by returning bytes for that root with matching CIDs. Schema-
    // aware path resolution belongs above Ivy.
    //
    // Peer identity is tracked only for tally/reputation and DHT routing
    // (who to ask), never for demultiplexing responses (what was asked).
    // ─────────────────────────────────────────────────────────────────────────
    struct PendingVolumeRequest {
        var continuations: [CheckedContinuation<AttributedVolumeResponse, Never>]
        var candidates: Set<PeerID>
    }

    /// Per-root, short-lived suppression of peers that served a deficient bundle
    /// for that root (`reportDeficientVolume`). Candidate selection skips a
    /// suppressed peer, so a JIT-deficiency retry routes around it WITHOUT any
    /// per-call exclusion parameter — the punish call IS the routing change.
    /// Self-healing: the entry expires after `deficiencySuppressionWindow`, so a
    /// peer whose miss was transient becomes selectable again. Distinct from
    /// Tally reputation (gradual, global): this is immediate and root-scoped.
    var deficientPeerSuppression: [String: [String: ContinuousClock.Instant]] = [:]
    static let deficiencySuppressionWindow: Duration = .seconds(30)

    var pendingVolumeRequests: [String: PendingVolumeRequest] = [:]
    var pendingFindPins: [String: PendingFindPins] = [:]
    var nextFindPinsGeneration: UInt64 = 0

    public let creditLedger: CreditLineLedger

    public init(config: IvyConfig, group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton, tally: Tally? = nil) {
        self.config = config
        self.localID = PeerID(publicKey: config.publicKey)
        self.tally = tally ?? Tally(config: config.tallyConfig)
        self.router = Router(localID: PeerID(publicKey: config.publicKey), k: config.kBucketSize)
        self.group = group
        self.stunClient = STUNClient(group: group, servers: config.stunServers)
        self.creditLedger = CreditLineLedger(
            localID: PeerID(publicKey: config.publicKey),
            baseThresholdMultiplier: config.baseThresholdMultiplier
        )
    }

    // MARK: - Lifecycle

    public func start() async throws {
        guard !running else { return }
        running = true
        try await startListener()

        #if canImport(Network)
        if config.enableLocalDiscovery {
            startLocalDiscovery()
        }
        #endif

        // An operator-declared external address is authoritative: it overrides
        // STUN, which on cloud hosts (e.g. fly) returns nothing useful and lets
        // the node fall back to advertising its private (172.x) address.
        if let ext = config.externalAddress {
            let addr = ObservedAddress(host: ext.host, port: ext.port)
            publicAddress = addr
            delegate?.ivy(self, didDiscoverPublicAddress: addr)
        } else if let addr = await stunClient.discoverPublicAddress() {
            publicAddress = addr
            delegate?.ivy(self, didDiscoverPublicAddress: addr)
        }

        for bootstrap in config.bootstrapPeers {
            Task { try? await connect(to: bootstrap) }
        }
        // Stay connected to known relays so they are available as relay candidates
        // for connectViaRelay when a direct dial to some other peer fails. These
        // are only SEEDS: every connected peer is a carrier candidate, and
        // carriers that successfully serve a circuit join `relayCarrierSeeds`
        // on equal footing (see ensureRelayCarrierConnections).
        for relay in config.knownRelays where !config.bootstrapPeers.contains(where: { $0.publicKey == relay.publicKey }) {
            Task { try? await connect(to: relay) }
        }

        let monitor = PeerHealthMonitor(
            config: config.healthConfig,
            tally: tally,
            onStale: { [weak self] peer in
                guard let self else { return }
                Task { await self.disconnect(peer) }
            }
        )
        self.healthMonitor = monitor
        await monitor.startMonitoring { [weak self] peer, nonce in
            guard let self else { return }
            await self.fireToPeer(peer, .ping(nonce: nonce))
        }

        if config.enablePEX {
            startPEX()
        }
    }

    public func stop() async {
        config.logger.info("Ivy node shutting down")
        running = false
        pexTask?.cancel()
        pexTask = nil
        if let monitor = healthMonitor { await monitor.stopMonitoring() }

        cleanupAllPending()
        config.logger.debug("Drained all pending operations")

        try? await serverChannel?.close().get()
        serverChannel = nil
        #if canImport(Network)
        discovery?.stop()
        discovery = nil
        #endif
        for (_, conn) in connections {
            conn.cancel()
        }
        connections.removeAll()
        inboundConnectionIDs.removeAll()
        inboundConnectionOrder.removeAll()
        connectingPeers.removeAll()
        connectingEndpoints.removeAll()
        for (_, task) in reconnectTasks {
            task.cancel()
        }
        reconnectTasks.removeAll()
        reconnectAttempts.removeAll()
        relayCarrierSeedFailures.removeAll()
        intentionallyDisconnectedPeers.removeAll()
        clearPendingForwards()
    }

    // MARK: - Connection Management

    public func connect(to endpoint: PeerEndpoint) async throws {
        try await connect(to: endpoint, allowRelayFallback: true)
    }

    /// `allowRelayFallback == false` forces a DIRECT dial with no circuit-relay
    /// fallback. Carrier-seed redial uses this: a seed reachable only via relay is
    /// not a usable carrier (a relayed connection has `channel == nil`), so its
    /// direct-dial failure must count toward eviction rather than silently opening
    /// a channel-less relayed connection that falsely reads as a restored carrier.
    func connect(to endpoint: PeerEndpoint, allowRelayFallback: Bool) async throws {
        let peer = PeerID(publicKey: endpoint.publicKey)
        guard reserveOutgoingDial(to: endpoint) else { return }

        let conn: PeerConnection
        do {
            conn = try await PeerConnection.dial(endpoint: endpoint, group: group, maxFrameSize: config.maxFrameSize)
        } catch {
            finishOutgoingDial(to: peer, connected: false)
            // P0: direct dial failed (likely NAT). Fall back to a circuit relay if
            // any relay-capable peer is connected. `endpoint.host == "relay"` is the
            // synthetic host of an already-relayed endpoint — never relay those.
            if allowRelayFallback, endpoint.host != "relay",
               connections.values.contains(where: { $0.channel != nil }) {
                do { try await connectViaRelay(to: endpoint); return } catch { throw error }
            }
            throw error
        }

        if intentionallyDisconnectedPeers.remove(peer) != nil {
            conn.cancel()
            finishOutgoingDial(to: peer, connected: false)
            return
        }

        connections[peer] = conn
        finishOutgoingDial(to: peer, connected: true)
        router.addPeer(peer, endpoint: endpoint, tally: tally)
        await creditLedger.establish(with: peer)
        if let monitor = healthMonitor { await monitor.trackPeer(peer) }
        delegate?.ivy(self, didConnect: peer)
        Task { await handleInbound(conn) }
        sendIdentify(to: conn)
    }

    func reserveOutgoingDial(to endpoint: PeerEndpoint) -> Bool {
        let peer = PeerID(publicKey: endpoint.publicKey)
        guard connections[peer] == nil, !connectingPeers.contains(peer) else { return false }

        // Enforce netgroup diversity on every outbound dial, not just during
        // periodic refresh. Without this, an attacker can occupy all outbound
        // slots in the 60-second window between refresh cycles [Heilman 2015].
        // Limit: 2 connections per netgroup (IPv4 /16, IPv6 /32).
        let targetSubnet = NetGroup.group(endpoint.host)
        let sameSubnetCount = connections.values.filter {
            NetGroup.group($0.endpoint.host) == targetSubnet
        }.count + connectingEndpoints.values.filter {
            NetGroup.group($0.host) == targetSubnet
        }.count
        guard sameSubnetCount < 2 else { return false }

        connectingPeers.insert(peer)
        connectingEndpoints[peer] = endpoint
        intentionallyDisconnectedPeers.remove(peer)
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

#if DEBUG
    func reserveOutgoingDialForTesting(to endpoint: PeerEndpoint) -> Bool {
        reserveOutgoingDial(to: endpoint)
    }

    func finishOutgoingDialForTesting(to peer: PeerID, connected: Bool) {
        finishOutgoingDial(to: peer, connected: connected)
    }

    func reconnectDelayForTesting(peer: PeerID) -> Duration {
        reconnectDelay(for: peer)
    }
#endif

    public var connectedPeers: [PeerID] {
        var peers = [PeerID]()
        peers.reserveCapacity(connections.count + localPeers.count)
        peers.append(contentsOf: connections.keys)
        peers.append(contentsOf: localPeers.keys)
        return peers
    }

    public var connectedPeerEndpoints: [PeerEndpoint] {
        connections.values.map { $0.endpoint }
    }

    /// Chain ports advertised by each connected peer via identify messages.
    /// Keyed by peer ID, value is [directory: port].
    public var connectedPeerChainPorts: [PeerID: [String: UInt16]] {
        peerChainPorts.filter { connections[$0.key] != nil }
    }

    public var directPeerCount: Int { connections.count }

    /// Register a child chain's listen port so it is included in future
    /// identify messages. Remote peers use this to discover the exact port
    /// for a given chain directory without deterministic calculation.
    public func setChainPort(directory: String, port: UInt16) {
        chainPorts[directory] = port
    }

    public func disconnect(_ peer: PeerID) {
        intentionallyDisconnectedPeers.insert(peer)
        reconnectTasks.removeValue(forKey: peer)?.cancel()
        reconnectAttempts.removeValue(forKey: peer)
        if let conn = connections.removeValue(forKey: peer) {
            conn.cancel()
        }
        untrackInboundConnection(peer)
        router.removePeer(peer)
        peerChainPorts.removeValue(forKey: peer)
        peerSpawnCertChains.removeValue(forKey: peer)
        cleanupPendingForPeer(peer)
        // Drop the per-peer Tally ledger at the teardown choke point so every
        // embedder gets the cleanup for free (a removal — harmless if the
        // delegate also calls resetPeer from didDisconnect).
        tally.resetPeer(peer)
        if let monitor = healthMonitor {
            Task { await monitor.removePeer(peer) }
        }
        delegate?.ivy(self, didDisconnect: peer)
    }

    // MARK: - Sending

    /// Send a peer message (gossip) to a specific connected peer.
    public func sendMessage(to peer: PeerID, topic: String, payload: Data) {
        fireToPeer(peer, .peerMessage(topic: topic, payload: payload))
    }

    /// Send a peer message to all connected peers.
    public func broadcastMessage(topic: String, payload: Data) {
        let msg = Message.peerMessage(topic: topic, payload: payload)
        for (peer, _) in connections {
            fireToPeer(peer, msg)
        }
        for (peer, _) in localPeers {
            fireToPeer(peer, msg)
        }
    }

    func fireToPeer(_ peer: PeerID, _ message: Message, bypassBudget: Bool = false) {
        if let local = localPeers[peer] {
            local.send(message)
            return
        }
        guard let conn = connections[peer] else { return }
        if message.isKeepalive || bypassBudget {
            conn.fireAndForgetMessage(message)
            return
        }
        guard tally.shouldAllow(peer: peer) else { return }
        conn.fireAndForgetMessage(message)
    }

    func firePayloadToPeer(_ peer: PeerID, _ payload: Data) {
        if let local = localPeers[peer] {
            if let msg = Message.deserialize(payload, maxDataPayload: config.maxFrameSize) { local.send(msg) }
            return
        }
        guard let conn = connections[peer] else { return }
        // Pre-serialized payloads are typically block responses (consensus) — always send
        conn.fireAndForget(payload)
    }

    /// Broadcast a pre-serialized payload to all connected network peers except `excluding`.
    func broadcastPayload(_ payload: Data, excluding: PeerID? = nil) {
        for (peer, conn) in connections {
            if let excluded = excluding, peer == excluded { continue }
            guard tally.shouldAllow(peer: peer) else { continue }
            conn.fireAndForget(payload)
        }
    }

    public func announceBlock(cid: String) {
        haveSet.insert(cid)
        let payload = Message.announceBlock(cid: cid).serialize(maxFrameSize: config.maxFrameSize)
        broadcastPayload(payload)
    }

    /// Mark CIDs as locally available for DHT-forward serving without
    /// broadcasting any announcement. Used after recursive Volume storage
    /// so peers' DHT lookups for any subtree root we hold are answered by
    /// `handleDHTForward` instead of being silently dropped.
    func markAvailable(cids: [String]) {
        for cid in cids where !cid.isEmpty {
            haveSet.insert(cid)
        }
    }

    // MARK: - Identify Protocol

    func sendIdentify(to conn: PeerConnection) {
        let observedHost = conn.endpoint.host
        let observedPort = conn.endpoint.port
        var listenAddrs: [(String, UInt16)] = []
        if let ext = config.externalAddress {
            // Advertise ONLY the declared public endpoint — never leak the
            // private/local (172.x) address, which would poison peer routing.
            listenAddrs.append((ext.host, ext.port))
        } else {
            if let pub = publicAddress {
                listenAddrs.append((pub.host, pub.port))
            }
            if let localHost = conn.channel?.localAddress?.ipAddress,
               localHost != "0.0.0.0",
               localHost != "::",
               !listenAddrs.contains(where: { $0.0 == localHost && $0.1 == config.listenPort }) {
                listenAddrs.append((localHost, config.listenPort))
            }
            if listenAddrs.isEmpty {
                listenAddrs.append(("0.0.0.0", config.listenPort))
            }
        }

        var signature = Data()
        if config.signingKey.count == 32 {
            let material = Data(config.publicKey.utf8) + Data(observedHost.utf8)
            if let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: config.signingKey) {
                signature = (try? privateKey.signature(for: material)) ?? Data()
            }
        }

        conn.fireAndForgetMessage(.identify(
            publicKey: config.publicKey,
            observedHost: observedHost,
            observedPort: observedPort,
            listenAddrs: listenAddrs,
            chainPorts: chainPorts,
            signature: signature
        ))
        // Present spawn-tree provenance immediately after identify so the peer
        // (which has just bound our authenticated identity) can verify the chain
        // against its trusted root and classify this connection trusted/federated.
        if !ownSpawnCertChain.isEmpty {
            conn.fireAndForgetMessage(.spawnCertPresentation(chain: ownSpawnCertChain))
        }
    }

    /// Configure this node's spawn-cert chain (root→…→self), presented after
    /// identify. Set once the spawn-tree parent has issued the chain..)
    public func setSpawnCertChain(_ chain: [SpawnCertificate]) {
        ownSpawnCertChain = chain
    }

    /// The spawn-cert chain a peer presented (empty if none). The caller verifies
    /// it with `SpawnCertificateChain.verifiedScope(chain:leaf:trustedRoot:)`,
    /// passing the peer's authenticated `PeerID` as `leaf`.
    public func spawnCertChain(for peer: PeerID) -> [SpawnCertificate] {
        peerSpawnCertChains[peer] ?? []
    }

    func handleIdentify(publicKey: String, observedHost: String, observedPort: UInt16, listenAddrs: [(String, UInt16)], chainPorts: [String: UInt16], signature: Data, from peer: PeerID) async {
        // Canonicalize FIRST and derive the identity from the canonical raw
        // form: the PoW gate below measures the canonical form, so if identity
        // (and the router/ledger/chainPort keys derived from it) used the
        // PRESENTED spelling, one key ground on its raw form would mint TWO
        // live identities (raw + ed01-prefixed) off a single grind. Both
        // spellings must collapse to one PeerID; a second-spelling connection
        // then hits the duplicate-teardown path like any other duplicate.
        let rawPublicKey = KeyDifficulty.canonicalRawHex(publicKey)
        let realID = PeerID(publicKey: rawPublicKey)

        // Require a valid identity signature. An empty or missing signature allows
        // any peer to claim any public key — reject it outright. The signature
        // binds the PRESENTED string (that is what the peer signed); only
        // identity derivation canonicalizes.
        guard !signature.isEmpty,
              let pubKeyBytes = Data(hexString: rawPublicKey), pubKeyBytes.count == 32,
              let verifyKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubKeyBytes) else {
            config.logger.warning("Identify rejected from \(peer.publicKey.prefix(16))…: missing or invalid pubkey/signature")
            disconnect(peer)
            return
        }
        let material = Data(publicKey.utf8) + Data(observedHost.utf8)
        guard verifyKey.isValidSignature(signature, for: material) else {
            config.logger.warning("Identity verification failed for \(publicKey.prefix(16))… — disconnecting")
            disconnect(peer)
            return
        }
        // Enforce minimum key PoW to raise the cost of Sybil routing-table
        // poisoning. Each bit doubles the expected key-generation work, making
        // it progressively harder to generate keys that XOR-cluster near a
        // target CID for DHT capture.
        // Measure the canonical raw form, not the presented spelling: the same
        // key would otherwise score differently when presented ed01-prefixed
        // vs raw, and a key ground to the threshold on its raw form would be
        // wrongly rejected when presented prefixed.
        if config.minPeerKeyBits > 0 {
            let bits = KeyDifficulty.trailingZeroBits(of: rawPublicKey)
            guard bits >= config.minPeerKeyBits else {
                config.logger.warning("Peer \(publicKey.prefix(16))… has \(bits) key PoW bits, need \(config.minPeerKeyBits) — disconnecting")
                disconnect(peer)
                return
            }
        }

        let advertisedEndpoint = firstAdvertisedListenEndpoint(
            publicKey: rawPublicKey,
            listenAddrs: listenAddrs,
            from: peer
        )

        if peer != realID {
            if let existing = connections[realID], existing.isLive {
                if let duplicate = connections.removeValue(forKey: peer) {
                    duplicate.cancel()
                }
                untrackInboundConnection(peer)
                await healthMonitor?.removePeer(peer)
                peerChainPorts.removeValue(forKey: peer)
        peerSpawnCertChains.removeValue(forKey: peer)
                tally.resetPeer(peer)
                delegate?.ivy(self, didDisconnect: peer)
                return
            }

            if let conn = connections.removeValue(forKey: peer) {
                if let deadExisting = connections.removeValue(forKey: realID) {
                    deadExisting.cancel()
                }
                conn.id = realID
                connections[realID] = conn
                remapInboundConnection(from: peer, to: realID)
                router.removePeer(peer)
                if let endpoint = advertisedEndpoint {
                    conn.endpoint = endpoint
                    router.addPeer(realID, endpoint: endpoint, tally: tally)
                }
                Task { await self.creditLedger.establish(with: realID) }
            }
            await movePeerHealthTracking(from: peer, to: realID)
            // Migrate chainPorts from old key to real key.
            peerChainPorts.removeValue(forKey: peer)
        peerSpawnCertChains.removeValue(forKey: peer)
        } else if let endpoint = advertisedEndpoint, let conn = connections[realID] {
            conn.endpoint = endpoint
            router.addPeer(realID, endpoint: endpoint, tally: tally)
        }

        if !chainPorts.isEmpty {
            peerChainPorts[realID] = chainPorts
        }

        // Identify passed the signature + key-PoW gate and the connection is now
        // keyed to its real identity in connections/router/tally. Notify the
        // delegate so it can gate admission on the AUTHENTICATED identity — the
        // inbound `didConnect` only ever saw the temporary `inbound-<uuid>` id and
        // never re-fires here, so a durable ban can only be enforced at this point.
        // Fired for both the temp/dialed→realID re-key path and the matching-id
        // path; never reached on a rejected/disconnected identify (those return early).
        delegate?.ivy(self, didIdentifyPeer: realID, previous: peer)

        // A signed identify frame authenticates who sent the claim, not whether
        // its observed address is reachable by us. Only locally verified address
        // discovery, such as STUN, may mutate publicAddress.
    }

    func firstAdvertisedListenEndpoint(
        publicKey: String,
        listenAddrs: [(String, UInt16)],
        from peer: PeerID
    ) -> PeerEndpoint? {
        for (host, port) in listenAddrs {
            let endpoint = PeerEndpoint(publicKey: publicKey, host: host, port: port)
            if isAcceptableDiscoveredEndpoint(endpoint, source: "identify", from: peer) {
                return endpoint
            }
        }
        return nil
    }

    // MARK: - Message Handling

    func handleInbound(_ conn: PeerConnection) async {
        for await message in conn.messages {
            await handleMessage(message, from: conn.id)
        }
        let peer = conn.id
        let endpoint = conn.endpoint
        if let current = connections[peer], current !== conn {
            return
        }

        let wasCurrentConnection = connections[peer] != nil
        if wasCurrentConnection {
            connections.removeValue(forKey: peer)
            untrackInboundConnection(peer)
            connectingPeers.remove(peer)
            connectingEndpoints.removeValue(forKey: peer)
            router.removePeer(peer)
            cleanupPendingForPeer(peer)
            // Clear per-peer transient state so a later session that re-uses this
            // identity can't inherit it. Critical for spawn-cert trust: a stale
            // chain would mis-classify a reconnecting cert-less peer as trusted,
            // breaking "absent ⇒ federated". (peerChainPorts had the same gap on
            // this natural socket-close teardown path.)
            peerSpawnCertChains.removeValue(forKey: peer)
            peerChainPorts.removeValue(forKey: peer)
            tally.resetPeer(peer)
            delegate?.ivy(self, didDisconnect: peer)
        } else {
            untrackInboundConnection(peer)
        }

        let wasIntentionalDisconnect = intentionallyDisconnectedPeers.remove(peer) != nil
        // Relayed connections have no dialable endpoint (host "relay"); don't try
        // to reconnect to them directly — an IDENTIFIED relayed peer instead
        // fails over to another carrier below (`scheduleRelayFailover`).
        // Drop the claimed-key index entry (kept across the identify re-key, so
        // clean it by the connection's own claimed key, not the current peer id).
        let wasRelayed = conn.relayForward != nil
        if let claimed = conn.relayedClaimedKey { relayedConnByClaimedKey.removeValue(forKey: claimed) }
        // N1: this carrier is gone — reap relayed connections routed through it.
        // They are channel-less (isLive forever) and would otherwise leak a slot.
        // Each reaped orphan's own teardown then schedules its relay failover.
        for orphan in connections.values where orphan.relayCarrierConn === conn {
            orphan.cancel()
        }
        if wasCurrentConnection,
           !peer.publicKey.hasPrefix("inbound-"),
           running,
           !wasIntentionalDisconnect {
            if wasRelayed {
                // Fast failover: the relayed link died (its carrier tore down, or
                // the probe loop declared the circuit silent). Re-establish through
                // another carrier NOW instead of waiting for future demand.
                scheduleRelayFailover(to: endpoint, peer: peer)
            } else {
                scheduleReconnect(to: endpoint, peer: peer)
            }
        }
    }

    /// Schedule a bounded, backed-off attempt to re-form a lost RELAYED
    /// connection through another carrier. Shares the reconnect bookkeeping
    /// (`reconnectTasks`/`reconnectAttempts`) so a peer never has both a direct
    /// reconnect and a relay failover in flight.
    func scheduleRelayFailover(to endpoint: PeerEndpoint, peer: PeerID) {
        guard connections[peer] == nil,
              !connectingPeers.contains(peer),
              reconnectTasks[peer] == nil else { return }
        guard (reconnectAttempts[peer] ?? 0) < Self.maxRelayFailoverAttempts else {
            reconnectAttempts.removeValue(forKey: peer)
            return
        }
        let delay = reconnectDelay(for: peer)
        config.logger.info("Relayed connection to \(String(peer.publicKey.prefix(16)))… lost — failing over to another carrier in \(String(describing: delay))")
        let task = Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard let self else { return }
            await self.runScheduledRelayFailover(to: endpoint, peer: peer)
        }
        reconnectTasks[peer] = task
    }

    func runScheduledRelayFailover(to endpoint: PeerEndpoint, peer: PeerID) async {
        reconnectTasks.removeValue(forKey: peer)
        guard running,
              connections[peer] == nil,
              !connectingPeers.contains(peer),
              !intentionallyDisconnectedPeers.contains(peer) else { return }
        // Top up the carrier pool first so the failover has somewhere to go.
        ensureRelayCarrierConnections()
        do {
            try await connectViaRelay(to: endpoint)
        } catch {
            scheduleRelayFailover(to: endpoint, peer: peer)
        }
    }

    func scheduleReconnect(to endpoint: PeerEndpoint, peer: PeerID) {
        guard connections[peer] == nil,
              !connectingPeers.contains(peer),
              reconnectTasks[peer] == nil else { return }

        let delay = reconnectDelay(for: peer)
        config.logger.info("Connection to \(String(peer.publicKey.prefix(16)))… dropped — reconnecting in \(String(describing: delay))")

        let task = Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard let self else { return }
            await self.runScheduledReconnect(to: endpoint, peer: peer)
        }
        reconnectTasks[peer] = task
    }

    func reconnectDelay(for peer: PeerID) -> Duration {
        let attempt = min((reconnectAttempts[peer] ?? 0) + 1, 16)
        reconnectAttempts[peer] = attempt

        let shift = min(attempt - 1, 10)
        let exponential = Self.reconnectBaseDelayMs * (UInt64(1) << UInt64(shift))
        let capped = min(exponential, Self.reconnectMaxDelayMs)
        let jitter = UInt64.random(in: 0...Self.reconnectJitterMs)
        return .milliseconds(capped + jitter)
    }

    func runScheduledReconnect(to endpoint: PeerEndpoint, peer: PeerID) async {
        reconnectTasks.removeValue(forKey: peer)
        guard running,
              connections[peer] == nil,
              !connectingPeers.contains(peer),
              !intentionallyDisconnectedPeers.contains(peer) else { return }

        do {
            try await connect(to: endpoint)
        } catch {
            scheduleReconnect(to: endpoint, peer: peer)
        }
    }

    // MARK: - NAT traversal: circuit relay (Phase 1)

    /// Establish a RELAYED connection to `endpoint` through one of our connected
    /// relay-capable peers. The result lives in `connections[target]` with a nil
    /// channel, so identify/want/sync flow over it exactly like a direct link.
    ///
    /// Carrier selection is NETGROUP-DIVERSE: candidates are tried grouped by
    /// the carrier's socket-address netgroup, preferring groups that do not
    /// already carry one of our relayed connections (see `diverseCarrierOrder`).
    /// INVARIANT: this never dials — it only bridges over connections we
    /// already hold; an unreachable target fails with `noRelayAvailable`.
    public func connectViaRelay(to endpoint: PeerEndpoint) async throws {
        let targetKey = endpoint.publicKey
        let target = PeerID(publicKey: targetKey)
        guard connections[target] == nil else { return }

        let candidates = connections.compactMap { (pid, conn) -> (peer: PeerID, group: String)? in
            (conn.channel != nil && pid.publicKey != targetKey) ? (pid, carrierNetgroup(conn)) : nil
        }
        // Netgroups already carrying one of our relayed connections: a NEW
        // circuit prefers a carrier outside them, so relay-only reachability
        // spreads across >=2 distinct netgroups whenever the peer set allows.
        let activeCarrierGroups = Set(connections.values.compactMap { conn in
            conn.relayCarrierConn.map { carrierNetgroup($0) }
        })
        for relayPeer in Self.diverseCarrierOrder(candidates: candidates, activeCarrierGroups: activeCarrierGroups) {
            nextRelayRequestNonce &+= 1
            let nonce = nextRelayRequestNonce
            let requestKey = PendingRelayRequestKey(relayPeer: relayPeer, nonce: nonce)
            let success: Bool = await withCheckedContinuation { cont in
                pendingRelayRequests[requestKey] = cont
                fireToPeer(relayPeer, .relayConnect(srcKey: config.publicKey, dstKey: targetKey, nonce: nonce))
                Task { [weak self] in
                    try? await Task.sleep(for: .seconds(10))
                    await self?.timeoutRelayRequest(requestKey)
                }
            }
            if success {
                openRelayedConnection(claimedKey: targetKey, endpoint: endpoint, via: relayPeer)
                noteRelayCarrierSuccess(relayPeer)
                reconnectAttempts.removeValue(forKey: target)  // reset failover backoff
                return
            }
        }
        throw IvyError.noRelayAvailable
    }

    /// Sentinel netgroup for a carrier with no unforgeable observed address.
    /// ALL such carriers collapse onto this one group so a peer cannot fabricate
    /// many distinct "fresh" netgroups (which win diverse-first ordering) via its
    /// self-advertised endpoint. Distinct from every `NetGroup.group` output
    /// (which is always `v4:`/`v6:`/`raw:`-prefixed), so it never collides.
    static let unknownCarrierNetgroup = "unknown:no-observed-addr"

    /// Netgroup of a carrier connection, from an address the peer CANNOT forge:
    /// the L3 remote observed on the socket (captured on both the inbound accept
    /// and the outbound dial, before identify runs). NEVER falls back to the
    /// self-advertised `conn.endpoint.host` — during identify that field is
    /// overwritten with the peer's own listenAddrs, so using it would let an
    /// attacker forge arbitrarily many netgroups and capture every relayed
    /// circuit (the relay-layer eclipse this diversity is meant to prevent).
    /// A carrier without an observed address (should not happen for a live TCP
    /// carrier) is collapsed onto a single sentinel group so it cannot forge
    /// freshness.
    func carrierNetgroup(_ conn: PeerConnection) -> String {
        guard let host = conn.observedHost, !host.isEmpty else { return Self.unknownCarrierNetgroup }
        return NetGroup.group(host)
    }

    /// Order relay-carrier candidates netgroup-diverse-first: round-robin across
    /// netgroups (so consecutive attempts hit DISTINCT groups), with groups that
    /// already carry a relayed connection sorted last. Without this, candidates
    /// were tried in dictionary order and the first success won — a relay-only
    /// node could end up with every circuit riding one carrier (or one netgroup),
    /// a single-operator eclipse [Heilman 2015 applied to the relay layer].
    /// Shuffled within and across groups so selection is not positionally biased.
    static func diverseCarrierOrder(
        candidates: [(peer: PeerID, group: String)],
        activeCarrierGroups: Set<String>
    ) -> [PeerID] {
        var byGroup: [String: [PeerID]] = [:]
        for candidate in candidates.shuffled() {
            byGroup[candidate.group, default: []].append(candidate.peer)
        }
        func roundRobin(_ groups: [String]) -> [PeerID] {
            var queues = groups.compactMap { byGroup[$0] }
            var out: [PeerID] = []
            var advanced = true
            while advanced {
                advanced = false
                for i in queues.indices where !queues[i].isEmpty {
                    out.append(queues[i].removeFirst())
                    advanced = true
                }
            }
            return out
        }
        let fresh = byGroup.keys.filter { !activeCarrierGroups.contains($0) }.shuffled()
        let used = byGroup.keys.filter { activeCarrierGroups.contains($0) }.shuffled()
        return roundRobin(fresh) + roundRobin(used)
    }

    /// Remember a carrier that successfully opened a circuit for us, so a node
    /// that has NEEDED relays can re-dial known-good carriers when its carrier
    /// set thins out (`ensureRelayCarrierConnections`). Bounded and
    /// diversity-preferring; `config.knownRelays` remains just another seed.
    func noteRelayCarrierSuccess(_ relayPeer: PeerID) {
        guard let conn = connections[relayPeer], conn.channel != nil,
              !relayPeer.publicKey.hasPrefix("inbound-"),
              conn.endpoint.port != 0,
              conn.endpoint.host != "relay", conn.endpoint.host != "unknown" else { return }
        // Diversity keys on the UNFORGEABLE observed netgroup, not the advertised
        // endpoint host (which identify overwrites with the peer's listenAddrs).
        recordRelayCarrierSeed(key: relayPeer.publicKey, endpoint: conn.endpoint, group: carrierNetgroup(conn))
        relayCarrierSeedFailures.removeValue(forKey: relayPeer.publicKey)
    }

    /// Insert into the bounded carrier-seed set. When full, a newcomer only
    /// displaces an existing seed if it ADDS a netgroup the set lacks (evicting
    /// one member of a duplicated group), keeping the set diversity-maximal.
    /// `group` is the observed (unforgeable) netgroup of the carrier.
    func recordRelayCarrierSeed(key: String, endpoint: PeerEndpoint, group: String) {
        if relayCarrierSeeds[key] != nil || relayCarrierSeeds.count < Self.maxRelayCarrierSeeds {
            relayCarrierSeeds[key] = RelayCarrierSeed(endpoint: endpoint, group: group)
            return
        }
        let newGroup = group
        let groups = relayCarrierSeeds.mapValues { $0.group }
        guard !groups.values.contains(newGroup) else { return }
        var byGroup: [String: [String]] = [:]
        for (seedKey, seedGroup) in groups { byGroup[seedGroup, default: []].append(seedKey) }
        guard let evict = byGroup.values.first(where: { $0.count > 1 })?.sorted().first else { return }
        relayCarrierSeeds.removeValue(forKey: evict)
        relayCarrierSeeds[key] = RelayCarrierSeed(endpoint: endpoint, group: group)
    }

    /// Keep-N-carriers: a node that depends on relayed reachability keeps a
    /// small set of relay-capable DIRECT connections alive so failover always
    /// has somewhere to go. Reuses existing machinery — it only re-dials
    /// known-good carrier seeds / knownRelays via `connect` (which dedupes);
    /// it never discovers or probes new addresses.
    func ensureRelayCarrierConnections() {
        let hasRelayedConns = connections.values.contains { $0.relayForward != nil }
        guard hasRelayedConns || !relayCarrierSeeds.isEmpty else { return }
        let carriers = connections.values.filter { $0.channel != nil }
        let groups = Set(carriers.map { carrierNetgroup($0) })
        if carriers.count >= Self.targetRelayCarrierCount, groups.count >= 2 { return }
        for (key, seed) in relayCarrierSeeds where connections[PeerID(publicKey: key)] == nil {
            Task { await self.redialRelayCarrierSeed(key: key, endpoint: seed.endpoint) }
        }
        for relay in config.knownRelays where connections[PeerID(publicKey: relay.publicKey)] == nil {
            Task { try? await self.connect(to: relay) }
        }
    }

    /// Re-dial a carrier seed, tracking consecutive failures so a black-holed
    /// seed is eventually evicted instead of re-dialed forever (L1). A success
    /// clears the failure count; hitting `maxRelayCarrierSeedDialFailures`
    /// consecutive failures drops the seed from the pool (size stays bounded at
    /// `maxRelayCarrierSeeds`). Threshold 3 tolerates transient loss / NAT flaps
    /// while still reclaiming a genuinely dead carrier.
    func redialRelayCarrierSeed(key: String, endpoint: PeerEndpoint) async {
        do {
            // DIRECT-ONLY: a seed only reachable via relay cannot serve as a
            // carrier, so a failed direct dial must count toward eviction (below)
            // rather than open a channel-less relayed connection that would falsely
            // read as a restored carrier and suppress future direct redials.
            try await connect(to: endpoint, allowRelayFallback: false)
            relayCarrierSeedFailures.removeValue(forKey: key)
        } catch {
            let failures = (relayCarrierSeedFailures[key] ?? 0) + 1
            if failures >= Self.maxRelayCarrierSeedDialFailures {
                relayCarrierSeeds.removeValue(forKey: key)
                relayCarrierSeedFailures.removeValue(forKey: key)
            } else {
                relayCarrierSeedFailures[key] = failures
            }
        }
    }

    func timeoutRelayRequest(_ requestKey: PendingRelayRequestKey) {
        if let cont = pendingRelayRequests.removeValue(forKey: requestKey) { cont.resume(returning: false) }
    }

    /// Active liveness probing for a relayed connection. A relayed circuit has
    /// no socket of its own, so without probes the only inbound floor is the
    /// health monitor's idle-gated keepalive (worst case ~240s over two hops)
    /// — which is why the old passive stale bound had to be 300s. Pinging the
    /// circuit every `relayedProbeInterval` makes a healthy circuit's inbound
    /// floor ~30s, so `relayedFailoverTimeout` (90s = ~3 unanswered probes)
    /// can declare it silent and fail over quickly. The loop dies with the
    /// connection (superseded, closed, or removed).
    func startRelayedProbe(for conn: PeerConnection) {
        Task { [weak self, weak conn] in
            while true {
                try? await Task.sleep(for: PeerConnection.relayedProbeInterval)
                guard let self, let conn else { return }
                guard await self.probeRelayedConnection(conn) else { return }
            }
        }
    }

    /// One probe tick. Returns false when the loop should stop (connection
    /// gone/superseded, or declared silent and torn down — the teardown path
    /// then schedules the carrier failover).
    func probeRelayedConnection(_ conn: PeerConnection) -> Bool {
        // I1 (acknowledged): each probe tick sends a frame over the circuit, so a
        // relayed circuit is kept alive right up to the relay's 3600s hard cap —
        // idle-reclaim of an abandoned relayed circuit is effectively disabled.
        // This is accepted: relay resource bounds still hold via the per-relay
        // circuit-count, rate, and absolute-lifetime caps in RelayService.
        // No `running` check needed: stop() clears `connections`, which ends
        // every probe loop on its next tick via this identity check.
        guard connections[conn.id] === conn else { return false }
        if conn.inboundIdle >= PeerConnection.relayedFailoverTimeout {
            config.logger.info("Relayed connection to \(String(conn.id.publicKey.prefix(16)))… silent past failover bound — tearing down")
            conn.cancel()
            return false
        }
        conn.fireAndForgetMessage(.ping(nonce: UInt64.random(in: 1...UInt64.max)))
        return true
    }

    func resolveRelayRequest(from relayPeer: PeerID, code: UInt8, nonce: UInt64) {
        let requestKey = PendingRelayRequestKey(relayPeer: relayPeer, nonce: nonce)
        if let cont = pendingRelayRequests.removeValue(forKey: requestKey) {
            cont.resume(returning: code == 0)
            return
        }
        guard nonce == 0 else { return }
        let legacyKeys = pendingRelayRequests.keys.filter { $0.relayPeer == relayPeer }
        guard legacyKeys.count == 1, let legacyKey = legacyKeys.first else { return }
        pendingRelayRequests.removeValue(forKey: legacyKey)?.resume(returning: code == 0)
    }

    /// Open a relayed PeerConnection for a peer CLAIMING `claimedKey`, carried by
    /// `relayPeer`. Treated as an UNVERIFIED inbound connection: keyed under a
    /// temporary `inbound-<uuid>` id and routed through the same admission +
    /// identify-timeout path as a direct inbound socket, so it is NOT attributed
    /// to `claimedKey`, cannot displace a real peer under that key, and is reaped
    /// if it never presents a signed identify. `handleIdentify` re-keys it to its
    /// real id (firing `didIdentifyPeer`) only after the signature verifies. Idempotent.
    func openRelayedConnection(claimedKey: String, endpoint: PeerEndpoint, via relayPeer: PeerID) {
        guard relayedConnByClaimedKey[claimedKey] == nil, let relayConn = connections[relayPeer] else { return }
        // H2 bound: cap concurrent relayed slots so a relay/peer can't open an
        // unbounded number of channel-less entries.
        guard connections.values.filter({ $0.relayForward != nil }).count < Self.maxRelayedConnections else {
            config.logger.warning("Relayed connection cap reached — refusing relayed peer \(claimedKey.prefix(16))…")
            return
        }
        let tempID = PeerID(publicKey: "inbound-relay-\(UUID().uuidString)")
        guard admitInboundConnection(tempID) else { return }
        let conn = PeerConnection(
            id: tempID, endpoint: endpoint, channel: nil, maxFrameSize: config.maxFrameSize,
            relayForward: { payload in
                relayConn.fireAndForgetMessage(.relayData(peerKey: claimedKey, data: payload))
            },
            relayedClaimedKey: claimedKey,
            relayCarrierConn: relayConn)
        connections[tempID] = conn
        relayedConnByClaimedKey[claimedKey] = conn
        trackInboundConnection(tempID)
        if healthMonitor != nil { Task { await self.trackPeerHealth(tempID) } }
        delegate?.ivy(self, didConnect: tempID)
        Task { await handleInbound(conn) }
        sendIdentify(to: conn)
        startRelayedProbe(for: conn)
        let toTimeout = tempID
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(30))
            await self?.timeoutUnidentifiedPeer(toTimeout)
        }
    }

    func handleRelayConnect(srcKey: String, dstKey: String, nonce: UInt64, from peer: PeerID) async {
        if dstKey == config.publicKey {
            // I am the TARGET; `peer` is the relay. Open my (unverified) side toward src.
            openRelayedConnection(claimedKey: srcKey, endpoint: PeerEndpoint(publicKey: srcKey, host: "relay", port: 0), via: peer)
        } else if config.relayEnabled {
            // I am the RELAY. H3: the initiator is the AUTHENTICATED sender, NOT the
            // body's `srcKey` (which a peer could forge to bypass the per-peer cap or
            // impersonate a victim). Account + forward under `peer.publicKey`.
            let realSrc = peer.publicKey
            let dst = PeerID(publicKey: dstKey)
            guard tally.shouldAllow(peer: peer), connections[dst] != nil else {
                fireToPeer(peer, .relayStatus(code: 1, nonce: nonce)); return
            }
            // Initiator netgroup from OUR view of its connection (socket-observed
            // when available) — feeds the reserved-headroom admission.
            let initiatorGroup = connections[peer].map { carrierNetgroup($0) } ?? ""
            if await relayService.createCircuit(initiator: realSrc, target: dstKey, initiatorGroup: initiatorGroup) {
                fireToPeer(peer, .relayStatus(code: 0, nonce: nonce))
                fireToPeer(dst, .relayConnect(srcKey: realSrc, dstKey: dstKey, nonce: nonce))
            } else {
                fireToPeer(peer, .relayStatus(code: 2, nonce: nonce))
            }
        }
    }

    func handleRelayData(peerKey: String, data: Data, from peer: PeerID) async {
        let senderKey = peer.publicKey
        if await relayService.hasCircuit(between: senderKey, and: peerKey) {
            // I am the relay: forward to the other endpoint, tagging the sender.
            // M5: forward via fireToPeer so the carrier's per-peer Tally budget
            // applies to relayed bytes (not just the circuit's byte budget).
            if await relayService.relay(from: senderKey, to: peerKey, bytes: data.count) {
                fireToPeer(PeerID(publicKey: peerKey), .relayData(peerKey: senderKey, data: data))
            }
        } else {
            // I am an endpoint: `data` is a framed message from `peerKey` via relay `peer`.
            // Route into the (unverified) relayed connection for that claimed key.
            if relayedConnByClaimedKey[peerKey] == nil {
                openRelayedConnection(claimedKey: peerKey, endpoint: PeerEndpoint(publicKey: peerKey, host: "relay", port: 0), via: peer)
            }
            if let inner = Message.deserialize(data, maxDataPayload: config.maxFrameSize) {
                relayedConnByClaimedKey[peerKey]?.feedMessage(inner)
            }
        }
    }

    func handleMessage(_ message: Message, from peer: PeerID) async {
        if let monitor = healthMonitor {
            await monitor.recordActivity(from: peer)
        }
        switch message {
        case .ping(let nonce):
            fireToPeer(peer, .pong(nonce: nonce))

        case .pong(let nonce):
            tally.recordSuccess(peer: peer)
            if let monitor = healthMonitor {
                await monitor.recordPong(from: peer, nonce: nonce)
            }

        // NAT traversal Phase 1 — circuit relay.
        case .relayConnect(let srcKey, let dstKey, let nonce):
            await handleRelayConnect(srcKey: srcKey, dstKey: dstKey, nonce: nonce, from: peer)
        case .relayStatus(let code, let nonce):
            resolveRelayRequest(from: peer, code: code, nonce: nonce)
        case .relayData(let peerKey, let data):
            await handleRelayData(peerKey: peerKey, data: data, from: peer)

        case .block(let cid, let data):
            let cpl = Router.commonPrefixLength(router.localHash, Router.hash(cid))
            tally.recordReceived(peer: peer, bytes: data.count, cpl: cpl)
            await meterReceived(peer: peer, bytes: data.count)

            guard ContentAddressVerifier.data(data, matches: cid) else {
                tally.recordFailure(peer: peer)
                break
            }

            tally.recordSuccess(peer: peer)

            if haveSet.contains(cid) {
                resolvePending(cid: cid, data: data)
                break
            }
            haveSet.insert(cid)
            resolvePending(cid: cid, data: data)
            resolveForwards(cid: cid, data: data, from: peer)

            delegate?.ivy(self, didReceiveBlock: cid, data: data, from: peer)

        case .dontHave:
            tally.recordFailure(peer: peer)

        case .findNode(let target, _, let nonce):
            guard tally.shouldAllow(peer: peer) else { return }
            // Only serve identified peers: a findNode from a still-temporary
            // `inbound-<uuid>` id is dropped. The rate-limit bucket below is keyed
            // on the authenticated identity, so a reconnecting attacker cannot
            // reset its budget by churning connection ids.
            guard !peer.publicKey.hasPrefix("inbound-") else { return }
            // Per-peer rate limit: a findNode flood that drains the bucket is
            // dropped silently (and counted as a failure) so it can't be used to
            // map/poison the routing table.
            guard admitFindNode(from: peer) else {
                tally.recordFailure(peer: peer)
                return
            }
            let closest = router.closestPeers(to: Array(target), count: config.kBucketSize)
            let endpoints = closest.map { $0.endpoint }
            fireToPeer(peer, .neighbors(endpoints, nonce: nonce))

        case .neighbors(let endpoints, let nonce):
            guard tally.shouldAllow(peer: peer) else { return }
            guard isExpectedNeighborResponse(nonce: nonce, from: peer) else { return }
            var accepted: [PeerEndpoint] = []
            for ep in endpoints {
                if isAcceptableDiscoveredEndpoint(ep, source: "neighbors", from: peer) {
                    accepted.append(ep)
                    _ = addDiscoveredPeer(ep, source: "neighbors", from: peer)
                }
            }
            receiveNeighborResponse(nonce: nonce, endpoints: accepted, from: peer)

        case .announceBlock(let cid):
            // Rate-limit per-peer broadcast relaying. One announce triggers N
            // outbound broadcasts; without this cap a single peer drives
            // unbounded uplink amplification across all N connected peers.
            if admitGossipRelay(from: peer), !haveSet.contains(cid) {
                haveSet.insert(cid)
                fireToPeer(peer, .dhtForward(cid: cid, ttl: 0))
                let payload = Message.announceBlock(cid: cid).serialize(maxFrameSize: config.maxFrameSize)
                broadcastPayload(payload, excluding: peer)
            }
            delegate?.ivy(self, didReceiveBlockAnnouncement: cid, from: peer)

        case .identify(let publicKey, let observedHost, let observedPort, let listenAddrs, let chainPorts, let signature):
            await handleIdentify(publicKey: publicKey, observedHost: observedHost, observedPort: observedPort, listenAddrs: listenAddrs, chainPorts: chainPorts, signature: signature, from: peer)
        case .spawnCertPresentation(let chain):
            // Sent right after identify, so `peer` is the connection's
            // authenticated identity. Store as transport only (bounded); the node
            // verifies/classifies via spawnCertChain(for:). An empty chain clears.
            // Only bind under an AUTHENTICATED id — ignore a chain presented before
            // identify (still keyed to the temp `inbound-<uuid>`), so a chain can
            // never be stored against an unauthenticated identity.
            guard !peer.publicKey.hasPrefix("inbound-") else { return }
            guard chain.count <= Int(MessageLimits.maxSpawnCertChain) else { return }
            if chain.isEmpty {
                peerSpawnCertChains.removeValue(forKey: peer)
            } else {
                peerSpawnCertChains[peer] = chain
            }
            // The chain is a SEPARATE frame from identify, so a node that classified
            // on `didIdentifyPeer` may have read an empty chain (under-trust). Notify
            // it now that the chain is stored so it can (re)classify against this
            // authenticated identity. Fires on clear (empty) too, to drop stale trust.
            delegate?.ivy(self, didReceiveSpawnCertChain: peer)

        case .dhtForward(let cid, let ttl):
            await handleDHTForward(cid: cid, ttl: ttl, from: peer)

        case .want(let rootCIDs):
            Task { await self.handleWant(rootCIDs: rootCIDs, from: peer) }

        case .wantVolume(let rootCID, let cids):
            Task { await self.handleWant(rootCID: rootCID, requestedCIDs: cids, from: peer) }

        case .pexRequest(let nonce):
            handlePEXRequest(nonce: nonce, from: peer)

        case .pexResponse(let nonce, let peers):
            handlePEXResponse(nonce: nonce, peers: peers, from: peer)

        case .findPins(let cid):
            await handleFindPins(cid: cid, from: peer)

        case .pins(let cid, let providers):
            handlePinsResponse(cid: cid, providers: providers, from: peer)
            delegate?.ivy(self, didReceiveMessage: message, from: peer)

        case .pinAnnounce(let rootCID, let publicKey, let expiry, let signature, let fee):
            handlePinAnnounce(rootCID: rootCID, publicKey: publicKey, expiry: expiry, signature: signature, fee: fee, from: peer)

        case .pinStored:
            delegate?.ivy(self, didReceiveMessage: message, from: peer)

        case .deliveryAck:
            delegate?.ivy(self, didReceiveMessage: message, from: peer)

        case .peerMessage:
            delegate?.ivy(self, didReceiveMessage: message, from: peer)

        case .blocks(let rootCID, let items):
            await handleBlocks(rootCID: rootCID, items: items, from: peer)

            delegate?.ivy(self, didReceiveMessage: message, from: peer)

        case .announceVolume(let rootCID, let childCIDs, let totalSize):
            await handleAnnounceVolume(rootCID: rootCID, childCIDs: childCIDs, totalSize: totalSize, from: peer)

        case .pushVolume(let rootCID, let items):
            await handlePushVolume(rootCID: rootCID, items: items, from: peer)

        case .notHave(let rootCID):
            handleNotHave(rootCID: rootCID, from: peer)
            delegate?.ivy(self, didReceiveMessage: message, from: peer)
        }
    }

    // MARK: - Credit Line Metering

    func meterSent(peer: PeerID, bytes: Int) async {
        await creditLedger.earnFromRelay(peer: peer, amount: Int64(bytes))
    }

    func meterReceived(peer: PeerID, bytes: Int) async {
        await creditLedger.chargeForRelay(peer: peer, amount: Int64(bytes))
    }

    func hasCreditCapacity(peer: PeerID) async -> Bool {
        guard let line = await creditLedger.creditLine(for: peer) else { return true }
        return !line.needsSettlement
    }

    func admitGossipRelay(from peer: PeerID) -> Bool {
        var bucket = gossipBuckets[peer] ?? TokenBucket(
            capacity: Self.announceGossipCapacity,
            refillPerSec: Self.announceGossipRefillPerSec
        )
        let admitted = bucket.tryConsume()
        gossipBuckets[peer] = bucket
        if gossipBuckets.count > 2 * (config.tallyConfig.maxPeers ?? 256) {
            if let first = gossipBuckets.first { gossipBuckets.removeValue(forKey: first.key) }
        }
        return admitted
    }

    func admitFindNode(from peer: PeerID) -> Bool {
        var bucket = findNodeBuckets[peer] ?? TokenBucket(
            capacity: config.findNodeBurst,
            refillPerSec: config.findNodeRefillPerSec
        )
        let admitted = bucket.tryConsume()
        findNodeBuckets[peer] = bucket
        if findNodeBuckets.count > 2 * (config.tallyConfig.maxPeers ?? 256) {
            if let first = findNodeBuckets.first { findNodeBuckets.removeValue(forKey: first.key) }
        }
        return admitted
    }

    // MARK: - Local Peers

    public func serviceBus() -> LocalServiceBus {
        if let existing = _serviceBus { return existing }
        let bus = LocalServiceBus(node: self)
        _serviceBus = bus
        return bus
    }

    func registerLocalPeer(_ conn: LocalPeerConnection, as peerID: PeerID) {
        localPeers[peerID] = conn
        Task {
            await creditLedger.establish(with: peerID)
            await handleLocalInbound(conn, from: peerID)
        }
    }

    func unregisterLocalPeer(_ peerID: PeerID) {
        localPeers.removeValue(forKey: peerID)
    }

    func handleLocalInbound(_ conn: LocalPeerConnection, from peer: PeerID) async {
        for await message in conn.messages {
            await handleMessage(message, from: peer)
        }
        localPeers.removeValue(forKey: peer)
    }

    // MARK: - Public API (Application-Facing)

    /// Retrieve content by CID targeting a specific pinner (from findPins result).
    ///
    /// Records success/failure on `target` in Tally: a peer whose pin announce
    /// we trusted but which then fails to serve the CID is demoted so future
    /// pin-selection sorts it below honest pinners and shouldAllow rejects it
    /// once reputation drops enough.
    public func get(cid: String, target: PeerID) async -> Data? {
        if let data = await dataSource?.data(for: cid) { return data }

        tally.recordRequest(peer: target)

        let targetHash = Data(Router.hash(target.publicKey))
        let closest = router.closestPeers(to: Array(targetHash), count: config.maxConcurrentRequests)
        var sent = 0
        for entry in closest {
            let reachable = connections[entry.id] != nil || localPeers[entry.id] != nil
            guard reachable else { continue }
            fireToPeer(entry.id, .dhtForward(cid: cid, ttl: 0))
            sent += 1
            break
        }
        if sent == 0 { return nil }

        guard canRegisterPending(cid: cid) else { return nil }
        let data: Data? = await withCheckedContinuation { continuation in
            pendingRequests[cid, default: []].append(continuation)
            Task {
                try? await Task.sleep(for: config.requestTimeout)
                self.resolvePending(cid: cid, data: nil)
            }
        }
        if data != nil {
            tally.recordSuccess(peer: target)
        } else {
            tally.recordFailure(peer: target)
        }
        return data
    }

    /// Discover pinners for a CID via findPins. Awaits the first response
    /// or short timeout, then merges with locally-stored announcements.
    public func discoverPinners(cid: String) async -> [String] {
        let discovered = await findPinnersViaDHT(rootCID: cid)
        var seen: Set<String> = []
        var out: [String] = []
        for pk in storedPinAnnouncements(for: cid) where seen.insert(pk).inserted {
            out.append(pk)
        }
        for pid in discovered where seen.insert(pid.publicKey).inserted {
            out.append(pid.publicKey)
        }
        return out
    }

    /// DHT provider lookup: ask K closest peers (by XOR distance to the CID
    /// hash) which pinners they know for `rootCID`, await first non-empty
    /// response or a short timeout, return discovered peers. This is the
    /// IPFS-style provider record path — distinct from the routing-table
    /// XOR-closest-peer set which only covers peers we happen to have in
    /// our buckets, not the broader population that has announced pins.
    func findPinnersViaDHT(rootCID: String) async -> [PeerID] {
        let cidHash = Router.hash(rootCID)
        let initialTargets = reachablePinLookupTargets(for: cidHash)
        guard !initialTargets.isEmpty else {
            _ = await findNode(target: rootCID)
            return await queryPinners(rootCID: rootCID, targets: reachablePinLookupTargets(for: cidHash))
        }

        guard initialTargets.count < config.maxConcurrentRequests else {
            return await queryPinners(rootCID: rootCID, targets: initialTargets)
        }

        let warmRoute = Task { await self.findNode(target: rootCID) }
        let initial = await queryPinners(rootCID: rootCID, targets: initialTargets)
        if !initial.isEmpty { return initial }

        _ = await warmRoute.value
        let refreshedTargets = reachablePinLookupTargets(for: cidHash)
        let initialKeys = Set(initialTargets.map { $0.id.publicKey })
        let hasNewTargets = refreshedTargets.contains { !initialKeys.contains($0.id.publicKey) }
        guard hasNewTargets else { return [] }
        return await queryPinners(rootCID: rootCID, targets: refreshedTargets)
    }

    func reachablePinLookupTargets(for cidHash: [UInt8]) -> [Router.BucketEntry] {
        router.closestPeers(to: cidHash, count: config.maxConcurrentRequests).filter { entry in
            let reachable = connections[entry.id] != nil || localPeers[entry.id] != nil
            return reachable
        }
    }

    func queryPinners(rootCID: String, targets: [Router.BucketEntry]) async -> [PeerID] {
        guard !targets.isEmpty else { return [] }
        return await withCheckedContinuation { cont in
            let expected = Set(targets.map { $0.id.publicKey })
            let generation: UInt64
            if var pending = pendingFindPins[rootCID] {
                pending.continuations.append(cont)
                pending.expectedPeers.formUnion(expected)
                generation = pending.generation
                pendingFindPins[rootCID] = pending
            } else {
                nextFindPinsGeneration &+= 1
                generation = nextFindPinsGeneration
                pendingFindPins[rootCID] = PendingFindPins(
                    continuations: [cont],
                    expectedPeers: expected,
                    generation: generation
                )
            }
            for entry in targets {
                fireToPeer(entry.id, .findPins(cid: rootCID))
            }
            Task {
                try? await Task.sleep(for: .milliseconds(500))
                self.resolvePendingFindPins(rootCID: rootCID, peers: [], generation: generation)
            }
        }
    }

    func resolvePendingPEX(nonce: UInt64) {
        if let cont = pendingPEX.removeValue(forKey: nonce) {
            cont.resume(returning: [])
        }
    }

    func resolvePendingFindPins(rootCID: String, peers: [PeerID]) {
        guard let pending = pendingFindPins.removeValue(forKey: rootCID) else { return }
        for cont in pending.continuations { cont.resume(returning: peers) }
    }

    func resolvePendingFindPins(rootCID: String, peers: [PeerID], generation: UInt64) {
        guard pendingFindPins[rootCID]?.generation == generation else { return }
        resolvePendingFindPins(rootCID: rootCID, peers: peers)
    }

    func collectNeighborResponses(nonces: [UInt64]) async -> [[PeerEndpoint]] {
        guard !nonces.isEmpty else { return [] }
        var responses: [[PeerEndpoint]] = []
        responses.reserveCapacity(nonces.count)
        for nonce in nonces {
            let response = await nextNeighborResponse(nonce: nonce)
            if !response.isEmpty {
                responses.append(response)
            }
        }
        return responses
    }

    func requestNeighbors(from peer: PeerID, targetHash: [UInt8], nonce: UInt64, timeout: Duration) {
        pendingNeighborLookupNonces.insert(nonce)
        pendingNeighborResponses[nonce] = PendingNeighborResponse(
            peer: peer,
            continuation: nil
        )
        Task.detached { [weak self] in
            try? await Task.sleep(for: timeout)
            await self?.resolveNeighborResponse(nonce: nonce, endpoints: [])
        }
        fireToPeer(peer, .findNode(target: Data(targetHash), nonce: nonce))
    }

    func nextNeighborResponse(nonce: UInt64) async -> [PeerEndpoint] {
        if let endpoints = completedNeighborResponses.removeValue(forKey: nonce) {
            pendingNeighborLookupNonces.remove(nonce)
            pendingNeighborResponses.removeValue(forKey: nonce)
            return endpoints
        }
        return await withCheckedContinuation { cont in
            if let pending = pendingNeighborResponses[nonce] {
                pendingNeighborResponses[nonce] = PendingNeighborResponse(peer: pending.peer, continuation: cont)
            } else {
                pendingNeighborResponses[nonce] = PendingNeighborResponse(peer: localID, continuation: cont)
            }
        }
    }

    func receiveNeighborResponse(nonce: UInt64, endpoints: [PeerEndpoint], from peer: PeerID) {
        guard isExpectedNeighborResponse(nonce: nonce, from: peer) else { return }
        if pendingNeighborResponses[nonce]?.continuation == nil {
            completedNeighborResponses[nonce] = endpoints
            pendingNeighborResponses.removeValue(forKey: nonce)
            pendingNeighborLookupNonces.remove(nonce)
            return
        }
        resolveNeighborResponse(nonce: nonce, endpoints: endpoints)
    }

    func resolveNeighborResponse(nonce: UInt64, endpoints: [PeerEndpoint]) {
        guard let pending = pendingNeighborResponses.removeValue(forKey: nonce) else { return }
        pendingNeighborLookupNonces.remove(nonce)
        guard let cont = pending.continuation else {
            completedNeighborResponses[nonce] = endpoints
            return
        }
        cont.resume(returning: endpoints)
    }

    func isExpectedNeighborResponse(nonce: UInt64, from peer: PeerID) -> Bool {
        pendingNeighborLookupNonces.contains(nonce) && pendingNeighborResponses[nonce]?.peer == peer
    }

    func makeFindNodeNonce() -> UInt64 {
        var nonce = UInt64.random(in: 1...UInt64.max)
        while pendingNeighborLookupNonces.contains(nonce) {
            nonce = UInt64.random(in: 1...UInt64.max)
        }
        return nonce
    }

    /// Generate a Curve25519 key pair whose raw-hex public key has at least
    /// `targetDifficulty` trailing-zero work bits. Total: grinds until a
    /// conforming key is found (expected ~2^targetDifficulty keygens), so
    /// callers never need a retry loop or a force-unwrap.
    public static func generateKey(targetDifficulty: Int) -> (publicKey: String, privateKey: Data) {
        while true {
            if let key = grindKey(targetDifficulty: targetDifficulty, maxAttempts: 100_000_000) {
                return key
            }
        }
    }

    /// Generate a Curve25519 key pair with target difficulty, giving up after
    /// `maxAttempts` keygens.
    @available(*, deprecated, message: "Use generateKey(targetDifficulty:) — it is total and never returns nil")
    public static func generateKey(targetDifficulty: Int, maxAttempts: Int = 100_000_000) -> (publicKey: String, privateKey: Data)? {
        grindKey(targetDifficulty: targetDifficulty, maxAttempts: maxAttempts)
    }

    private static func grindKey(targetDifficulty: Int, maxAttempts: Int) -> (publicKey: String, privateKey: Data)? {
        for _ in 0..<maxAttempts {
            let privateKey = Crypto.Curve25519.Signing.PrivateKey()
            let publicKeyBytes = privateKey.publicKey.rawRepresentation
            let hex = publicKeyBytes.map { String(format: "%02x", $0) }.joined()
            let difficulty = KeyDifficulty.trailingZeroBits(of: hex)
            if difficulty >= targetDifficulty {
                return (publicKey: hex, privateKey: privateKey.rawRepresentation)
            }
        }
        return nil
    }

    // MARK: - Cleanup

    func cleanupPendingForPeer(_ peer: PeerID) {
        // H4: release relay state at the teardown choke point so a churning peer
        // can't leak circuits/continuations. (relayedVia is cleared in the
        // handleInbound teardown, which needs it for the reconnect decision.)
        let relayRequestKeys = pendingRelayRequests.keys.filter { $0.relayPeer == peer }
        for requestKey in relayRequestKeys {
            pendingRelayRequests.removeValue(forKey: requestKey)?.resume(returning: false)
        }
        Task { await relayService.removeAllCircuits(forPeer: peer.publicKey) }

        let forwardCIDs = pendingForwards.compactMap { cid, peers in
            peers[peer] == nil ? nil : cid
        }
        for cid in forwardCIDs {
            removePendingForward(cid: cid, requester: peer)
        }

        let volumeRoots = pendingVolumeRequests.compactMap { rootCID, request in
            request.candidates.contains(peer) ? rootCID : nil
        }
        for rootCID in volumeRoots {
            markVolumeCandidateDone(rootCID: rootCID, peer: peer)
        }

        let peerKey = peer.publicKey
        let findPinsRoots = pendingFindPins.compactMap { rootCID, pending in
            pending.expectedPeers.contains(peerKey) ? rootCID : nil
        }
        for rootCID in findPinsRoots {
            guard var pending = pendingFindPins[rootCID] else { continue }
            pending.expectedPeers.remove(peerKey)
            if pending.expectedPeers.isEmpty {
                resolvePendingFindPins(rootCID: rootCID, peers: [])
            } else {
                pendingFindPins[rootCID] = pending
            }
        }
    }

    /// Resume every in-flight continuation with an empty result. Shared by
    /// `cleanupAllPending` (stop/reset) and `deinit` (teardown safety net).
    private static func drainAllPending(
        pendingRequests: [String: [CheckedContinuation<Data?, Never>]],
        pendingVolumeRequests: [String: PendingVolumeRequest],
        pendingPEX: [UInt64: CheckedContinuation<[PeerEndpoint], Never>],
        pendingNeighborResponses: [UInt64: PendingNeighborResponse],
        pendingFindPins: [String: PendingFindPins],
        pendingRelayRequests: [PendingRelayRequestKey: CheckedContinuation<Bool, Never>]
    ) {
        for (_, continuations) in pendingRequests {
            for cont in continuations { cont.resume(returning: nil) }
        }
        for (_, request) in pendingVolumeRequests {
            for cont in request.continuations { cont.resume(returning: .empty) }
        }
        for (_, cont) in pendingPEX {
            cont.resume(returning: [])
        }
        for (_, pending) in pendingNeighborResponses {
            pending.continuation?.resume(returning: [])
        }
        for (_, pending) in pendingFindPins {
            for cont in pending.continuations { cont.resume(returning: []) }
        }
        for (_, cont) in pendingRelayRequests {
            cont.resume(returning: false)
        }
    }

    /// Safety net: resolve all pending continuations when the actor is torn down.
    /// Prevents SWIFT TASK CONTINUATION MISUSE warnings when an Ivy instance is
    /// released while fetches are in flight (e.g. during test teardown or network
    /// reconfiguration). The `withTaskCancellationHandler` paths handle the common
    /// case; deinit catches anything that slips through.
    deinit {
        Self.drainAllPending(
            pendingRequests: pendingRequests,
            pendingVolumeRequests: pendingVolumeRequests,
            pendingPEX: pendingPEX,
            pendingNeighborResponses: pendingNeighborResponses,
            pendingFindPins: pendingFindPins,
            pendingRelayRequests: pendingRelayRequests
        )
    }

    func cleanupAllPending() {
        Self.drainAllPending(
            pendingRequests: pendingRequests,
            pendingVolumeRequests: pendingVolumeRequests,
            pendingPEX: pendingPEX,
            pendingNeighborResponses: pendingNeighborResponses,
            pendingFindPins: pendingFindPins,
            pendingRelayRequests: pendingRelayRequests
        )
        pendingRequests.removeAll()
        pendingVolumeRequests.removeAll()
        pendingPEX.removeAll()
        pendingNeighborResponses.removeAll()
        pendingNeighborLookupNonces.removeAll()
        completedNeighborResponses.removeAll()
        pendingFindPins.removeAll()
        pendingRelayRequests.removeAll()
        clearPendingForwards()
    }

    func clearPendingForwards() {
        pendingForwards.removeAll()
        pendingForwardCountsByPeer.removeAll()
        pendingForwardCount = 0
    }

    // MARK: - Private Helpers

    func getLocalBlock(cid: String) async -> Data? {
        return await dataSource?.data(for: cid)
    }

    func resolvePending(cid: String, data: Data?) {
        guard let continuations = pendingRequests.removeValue(forKey: cid) else { return }
        for cont in continuations {
            cont.resume(returning: data)
        }
    }

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
        let ivyBox = UnsafeMutableTransferBox<Ivy>(self)
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let decoder = MessageFrameDecoder(maxFrameSize: ivyBox.value.config.maxFrameSize)
                let acceptor = InboundConnectionAcceptor(
                    ivy: ivyBox.value,
                    maxFrameSize: ivyBox.value.config.maxFrameSize
                )
                return channel.pipeline.addHandlers([decoder, acceptor])
            }

        let channel = try await bootstrap
            .bind(host: "0.0.0.0", port: Int(config.listenPort))
            .get()

        self.serverChannel = channel
    }

    func registerInboundConnection(_ conn: PeerConnection) {
        let peer = conn.id
        guard admitInboundConnection(peer) else {
            conn.cancel()
            return
        }

        connections[peer] = conn
        trackInboundConnection(peer)
        if healthMonitor != nil {
            Task { await self.trackPeerHealth(peer) }
        }
        delegate?.ivy(self, didConnect: peer)
        Task {
            sendIdentify(to: conn)
            await handleInbound(conn)
        }
        // Disconnect if peer doesn't identify within 30 seconds
        let peerToTimeout = peer
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(30))
            await self?.timeoutUnidentifiedPeer(peerToTimeout)
        }
    }

    func admitInboundConnection(_ peer: PeerID) -> Bool {
        // Rate-gate admission: a peer that has already drained its Tally
        // admission budget is refused without evicting an honest peer. NOTE this
        // gates the still-unauthenticated connection id, so it is a rate-limit,
        // not a durable ban — durable bans are enforced at `didIdentifyPeer`
        // against the AUTHENTICATED identity (see handleIdentify), the only point
        // where the real identity is known.
        guard tally.shouldAllow(peer: peer) else { return false }

        if let maxPeers = config.tallyConfig.maxPeers, connections.count >= maxPeers {
            return false
        }

        let inboundCap = config.tallyConfig.maxPeers ?? IvyConfig.defaultMaxInboundConnections
        guard inboundCap > 0 else { return false }
        if inboundConnectionIDs.count >= inboundCap {
            evictInboundConnection(excluding: peer)
        }
        return inboundConnectionIDs.count < inboundCap
    }

    /// Choose an inbound peer to evict to make room. Targets the most
    /// overrepresented netgroup first (so an inbound flood from one /16 or /32
    /// cannot exceed its share), tie-breaking by lowest reputation then oldest
    /// (FIFO). When every inbound peer is in its own netgroup, falls back to
    /// pure oldest-first FIFO. Only inbound peers are eligible — outbound/direct
    /// peers are never in `inboundConnectionIDs`, so they are protected.
    func evictInboundConnection(excluding peer: PeerID) {
        // Group current inbound peers by netgroup (skip the excluded peer).
        var groupCounts: [String: Int] = [:]
        for id in inboundConnectionOrder where id != peer && inboundConnectionIDs.contains(id) {
            groupCounts[netgroup(of: id), default: 0] += 1
        }
        guard let maxCount = groupCounts.values.max() else { return }

        let victim: PeerID
        if maxCount > 1 {
            // A netgroup dominates: evict its worst member (lowest reputation,
            // then oldest by FIFO position).
            let dominantGroups = Set(groupCounts.filter { $0.value == maxCount }.keys)
            victim = inboundConnectionOrder
                .enumerated()
                .filter { $0.element != peer
                    && inboundConnectionIDs.contains($0.element)
                    && dominantGroups.contains(netgroup(of: $0.element)) }
                .min { lhs, rhs in
                    let lr = tally.reputation(for: lhs.element)
                    let rr = tally.reputation(for: rhs.element)
                    if lr != rr { return lr < rr }
                    return lhs.offset < rhs.offset // older first
                }!
                .element
        } else {
            // No domination → oldest-first FIFO.
            guard let oldest = inboundConnectionOrder.first(where: {
                $0 != peer && inboundConnectionIDs.contains($0)
            }) else { return }
            victim = oldest
        }

        disconnectEvictedInbound(victim)
    }

    /// Netgroup for an inbound peer from its OBSERVED socket address — never the
    /// self-advertised endpoint, which the peer controls and could spread across
    /// fake netgroups to defeat eviction. Peers without an observed address get a
    /// per-id raw group so they never collapse together and falsely "dominate".
    private func netgroup(of peer: PeerID) -> String {
        if let host = connections[peer]?.observedHost, !host.isEmpty {
            return NetGroup.group(host)
        }
        return "raw:peer:" + peer.publicKey
    }

    private func disconnectEvictedInbound(_ candidate: PeerID) {
        inboundConnectionIDs.remove(candidate)
        inboundConnectionOrder.removeAll { $0 == candidate }
        if let conn = connections.removeValue(forKey: candidate) {
            conn.cancel()
        }
        router.removePeer(candidate)
        peerChainPorts.removeValue(forKey: candidate)
        peerSpawnCertChains.removeValue(forKey: candidate)
        cleanupPendingForPeer(candidate)
        tally.resetPeer(candidate)
        if let monitor = healthMonitor {
            Task { await monitor.removePeer(candidate) }
        }
        delegate?.ivy(self, didDisconnect: candidate)
    }

    func trackInboundConnection(_ peer: PeerID) {
        if inboundConnectionIDs.insert(peer).inserted {
            inboundConnectionOrder.append(peer)
        }
    }

    func untrackInboundConnection(_ peer: PeerID) {
        guard inboundConnectionIDs.remove(peer) != nil else { return }
        inboundConnectionOrder.removeAll { $0 == peer }
    }

    func remapInboundConnection(from oldPeer: PeerID, to newPeer: PeerID) {
        guard inboundConnectionIDs.remove(oldPeer) != nil else { return }
        inboundConnectionIDs.insert(newPeer)
        for i in inboundConnectionOrder.indices where inboundConnectionOrder[i] == oldPeer {
            inboundConnectionOrder[i] = newPeer
        }
    }

    func timeoutUnidentifiedPeer(_ peer: PeerID) {
        if connections[peer] != nil, peer.publicKey.hasPrefix("inbound-") {
            disconnect(peer)
        }
    }

    func trackPeerHealth(_ peer: PeerID) async {
        await healthMonitor?.trackPeer(peer)
    }

    func movePeerHealthTracking(from oldPeer: PeerID, to newPeer: PeerID) async {
        await healthMonitor?.removePeer(oldPeer)
        await healthMonitor?.trackPeer(newPeer)
    }

#if DEBUG
    func installHealthMonitorForTesting() {
        healthMonitor = PeerHealthMonitor(config: config.healthConfig, tally: tally, onStale: { _ in })
    }

    func trackHealthPeerForTesting(_ peer: PeerID) async {
        await trackPeerHealth(peer)
    }

    func moveHealthPeerForTesting(from oldPeer: PeerID, to newPeer: PeerID) async {
        await movePeerHealthTracking(from: oldPeer, to: newPeer)
    }

    func healthMonitorTracksPeerForTesting(_ peer: PeerID) async -> Bool {
        await healthMonitor?.tracksPeer(peer) ?? false
    }

    func trackedHealthPeerCountForTesting() async -> Int {
        await healthMonitor?.trackedPeerCount ?? 0
    }

    func registerConnectionForTesting(_ conn: PeerConnection, as peer: PeerID) {
        connections[peer] = conn
    }

    func connectionPeersForTesting() -> [PeerID] {
        Array(connections.keys)
    }

    func inboundPeerHostsForTesting() -> [PeerID: String] {
        var out: [PeerID: String] = [:]
        for id in inboundConnectionIDs {
            out[id] = connections[id]?.endpoint.host ?? ""
        }
        return out
    }

    func inboundPeerObservedHostsForTesting() -> [PeerID: String] {
        var out: [PeerID: String] = [:]
        for id in inboundConnectionIDs {
            out[id] = connections[id]?.observedHost ?? ""
        }
        return out
    }

    @discardableResult
    func addPendingForwardForTesting(cid: String, requester: PeerID) -> Bool {
        addPendingForward(cid: cid, requester: requester)
    }

    func expirePendingForwardForTesting(cid: String, requester: PeerID, generation: UInt64) {
        expirePendingForward(cid: cid, requester: requester, generation: generation)
    }

    func pendingForwardGenerationForTesting(cid: String, requester: PeerID) -> UInt64? {
        pendingForwards[cid]?[requester]
    }

    func pendingForwardCountForPeerForTesting(_ peer: PeerID) -> Int {
        pendingForwardCountsByPeer[peer] ?? 0
    }
#endif

    #if canImport(Network)
    func startLocalDiscovery() {
        let d = LocalDiscovery(
            serviceType: config.serviceType,
            port: config.listenPort,
            publicKey: config.publicKey
        ) { [weak self] endpoint in
            guard let self else { return }
            Task { try? await self.connect(to: endpoint) }
        }
        d.startAdvertising()
        d.startBrowsing()
        self.discovery = d
    }
    #endif

}
