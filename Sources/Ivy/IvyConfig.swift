import Foundation
import Tally

public struct IvyConfig: Sendable {
    public static let defaultMaxFrameSize: UInt32 = 4 * 1024 * 1024
    public static let defaultMaxInboundConnections: Int = 256

    public let publicKey: String
    /// Public-overlay participation versus a single identity-pinned operational
    /// session. Defaults to the existing public overlay behavior.
    public let topology: IvyTopology
    public let listenPort: UInt16
    public let bootstrapPeers: [PeerEndpoint]
    public let enableLocalDiscovery: Bool
    public let tallyConfig: TallyConfig
    public let kBucketSize: Int
    public let maxConcurrentRequests: Int
    public let requestTimeout: Duration
    public let relayTimeout: Duration
    public let serviceType: String
    public let stunServers: [(String, Int)]
    public let defaultTTL: UInt8
    public let healthConfig: PeerHealthConfig
    public let enablePEX: Bool
    public let pexInterval: Duration
    public let pexMaxPeers: Int
    public let signingKey: Data
    public let logger: any IvyLogger
    public let relayFee: UInt64
    public let baseThresholdMultiplier: UInt64
    /// Maximum serialized Ivy wire-frame payload this node will send or accept.
    /// This is node policy, not a consensus rule; operators can raise it for
    /// chains or applications that need larger wire payloads.
    public let maxFrameSize: UInt32
    /// Upper bound on distinct in-flight CIDs/volume queries tracked in `pendingRequests` /
    /// `pendingVolumeRequests`.
    public let maxPendingRequests: Int
    /// Per-CID/query cap on coalesced waiters.
    public let maxWaitersPerPendingCID: Int
    /// Maximum number of peers to broadcast a `want` request to when DHT provider
    /// records are empty.
    public let maxWantCandidates: Int
    /// Minimum trailing-zero bits of SHA256(publicKey) required to accept a peer.
    public let minPeerKeyBits: Int
    /// Per-peer token-bucket burst for inbound findNode requests.
    public let findNodeBurst: Double
    /// Refill rate (tokens/sec) for the per-peer findNode bucket.
    public let findNodeRefillPerSec: Double
    /// Maximum PEX entries accepted from a single response round.
    public let pexMaxAcceptedPerRound: Int
    /// Minimum Tally reputation a PEX responder must have.
    public let pexMinResponderScore: Double

    /// Operator-declared public P2P endpoint advertised in identify, overriding STUN.
    public let externalAddress: (host: String, port: UInt16)?

    /// Serve as a circuit relay. Public/backbone nodes set this true.
    public let relayEnabled: Bool
    /// Relay peers this node will route through when a direct dial fails.
    public let knownRelays: [PeerEndpoint]

    public init(
        publicKey: String,
        listenPort: UInt16 = 4001,
        bootstrapPeers: [PeerEndpoint] = [],
        enableLocalDiscovery: Bool = true,
        tallyConfig: TallyConfig = .default,
        kBucketSize: Int = 20,
        maxConcurrentRequests: Int = 6,
        requestTimeout: Duration = .seconds(15),
        relayTimeout: Duration = .seconds(5),
        serviceType: String = "_ivy._tcp",
        stunServers: [(String, Int)] = STUNClient.defaultServers,
        defaultTTL: UInt8 = 7,
        healthConfig: PeerHealthConfig = .default,
        enablePEX: Bool = true,
        pexInterval: Duration = .seconds(120),
        pexMaxPeers: Int = 16,
        signingKey: Data = Data(),
        logger: any IvyLogger = NullLogger(),
        relayFee: UInt64 = 0,
        baseThresholdMultiplier: UInt64 = 100,
        maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize,
        maxPendingRequests: Int = 4_096,
        maxWaitersPerPendingCID: Int = 64,
        minPeerKeyBits: Int = 0,
        maxWantCandidates: Int = 8,
        findNodeBurst: Double = 40,
        findNodeRefillPerSec: Double = 10,
        pexMaxAcceptedPerRound: Int? = nil,
        pexMinResponderScore: Double = 0,
        externalAddress: (host: String, port: UInt16)? = nil,
        relayEnabled: Bool = false,
        knownRelays: [PeerEndpoint] = [],
        topology: IvyTopology = .publicOverlay
    ) {
        self.publicKey = publicKey
        self.topology = topology
        self.listenPort = listenPort
        self.bootstrapPeers = bootstrapPeers
        self.enableLocalDiscovery = enableLocalDiscovery
        self.tallyConfig = tallyConfig
        self.kBucketSize = kBucketSize
        self.maxConcurrentRequests = maxConcurrentRequests
        self.requestTimeout = requestTimeout
        self.relayTimeout = relayTimeout
        self.serviceType = serviceType
        self.stunServers = stunServers
        self.defaultTTL = defaultTTL
        self.healthConfig = healthConfig
        self.enablePEX = enablePEX
        self.pexInterval = pexInterval
        self.pexMaxPeers = pexMaxPeers
        self.signingKey = signingKey
        self.logger = logger
        self.relayFee = relayFee
        self.baseThresholdMultiplier = baseThresholdMultiplier
        self.maxFrameSize = maxFrameSize
        self.maxPendingRequests = maxPendingRequests
        self.maxWaitersPerPendingCID = maxWaitersPerPendingCID
        self.minPeerKeyBits = minPeerKeyBits
        self.maxWantCandidates = maxWantCandidates
        self.findNodeBurst = findNodeBurst
        self.findNodeRefillPerSec = findNodeRefillPerSec
        self.pexMaxAcceptedPerRound = pexMaxAcceptedPerRound ?? pexMaxPeers
        self.pexMinResponderScore = pexMinResponderScore
        self.externalAddress = externalAddress
        self.relayEnabled = relayEnabled
        self.knownRelays = knownRelays
    }

    /// Effective PEX policy. A pinned session cannot opt back into public discovery
    /// merely by setting `enablePEX`.
    public var shouldRunPEX: Bool {
        topology.participatesInPublicDiscovery && enablePEX
    }

    public var shouldRunLocalDiscovery: Bool {
        topology.participatesInPublicDiscovery && enableLocalDiscovery
    }
}
