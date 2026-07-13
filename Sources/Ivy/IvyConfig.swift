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
    public let maxFrameSize: UInt32
    public let maxPendingRequests: Int
    public let maxWaitersPerPendingCID: Int
    public let maxWantCandidates: Int
    public let minPeerKeyBits: Int
    public let findNodeBurst: Double
    public let findNodeRefillPerSec: Double
    public let pexMaxAcceptedPerRound: Int
    public let pexMinResponderScore: Double
    public let externalAddress: (host: String, port: UInt16)?
    public let relayEnabled: Bool
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

        // A pinned session cannot be widened by caller-provided discovery or relay
        // settings. Keep only the expected bootstrap identity and neutralize every
        // public-overlay discovery mechanism at construction time.
        self.bootstrapPeers = bootstrapPeers.filter { topology.allowsPeer(publicKey: $0.publicKey) }
        self.enableLocalDiscovery = topology.participatesInPublicDiscovery && enableLocalDiscovery
        self.stunServers = topology.participatesInPublicDiscovery ? stunServers : []
        self.enablePEX = topology.participatesInPublicDiscovery && enablePEX
        self.relayEnabled = topology.participatesInPublicDiscovery && relayEnabled
        self.knownRelays = topology.participatesInPublicDiscovery ? knownRelays : []

        self.tallyConfig = tallyConfig
        self.kBucketSize = kBucketSize
        self.maxConcurrentRequests = maxConcurrentRequests
        self.requestTimeout = requestTimeout
        self.relayTimeout = relayTimeout
        self.serviceType = serviceType
        self.defaultTTL = defaultTTL
        self.healthConfig = healthConfig
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
    }

    public var shouldRunPEX: Bool { enablePEX }
    public var shouldRunLocalDiscovery: Bool { enableLocalDiscovery }
}
