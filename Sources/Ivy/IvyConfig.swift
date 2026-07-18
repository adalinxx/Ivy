@preconcurrency import Crypto
import Foundation
import Tally

public struct IvyConfig: Sendable {
    public static let protocolMaxFrameSize: UInt32 = 4 * 1024 * 1024
    public static let defaultMaxConnections = 256
    public static let defaultMaxInboundBufferedBytes = 64 * 1024 * 1024
    public static let defaultSTUNServers: [(String, Int)] = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun.cloudflare.com", 3478),
    ]

    public let signingKey: Curve25519.Signing.PrivateKey
    public let peerKey: PeerKey
    public var publicKey: String { peerKey.hex }
    public let mode: IvyMode
    public let listenPort: UInt16
    public let bootstrapPeers: [PeerEndpoint]
    public let carriers: [PeerEndpoint]
    public let tallyConfig: TallyConfig
    public let kBucketSize: Int
    public let requestTimeout: Duration
    public let relayTimeout: Duration
    public let stunServers: [(String, Int)]
    public let healthConfig: PeerHealthConfig
    public let routingRefreshInterval: Duration
    public let logger: any IvyLogger
    public let maxConnections: Int
    public let maxConnectionsPerNetgroup: Int
    public let maxPendingRequests: Int
    public let maxWaitersPerRequest: Int
    public let maxConcurrentContentRequests: Int
    public let maxContentCandidates: Int
    public let maxInboundBufferedBytes: Int
    public let minPeerKeyBits: Int
    public let externalAddress: (host: String, port: UInt16)?
    public let relayEnabled: Bool

    public init(
        signingKey: Curve25519.Signing.PrivateKey,
        listenPort: UInt16 = 4001,
        bootstrapPeers: [PeerEndpoint] = [],
        tallyConfig: TallyConfig = .default,
        kBucketSize: Int = 20,
        requestTimeout: Duration = .seconds(15),
        relayTimeout: Duration = .seconds(5),
        stunServers: [(String, Int)] = IvyConfig.defaultSTUNServers,
        healthConfig: PeerHealthConfig = .default,
        routingRefreshInterval: Duration = .seconds(120),
        logger: any IvyLogger = NullLogger(),
        maxConnections: Int = IvyConfig.defaultMaxConnections,
        maxConnectionsPerNetgroup: Int = 2,
        maxPendingRequests: Int = 4_096,
        maxWaitersPerRequest: Int = 64,
        maxConcurrentContentRequests: Int = 64,
        maxInboundBufferedBytes: Int = IvyConfig.defaultMaxInboundBufferedBytes,
        minPeerKeyBits: Int = 0,
        maxContentCandidates: Int = 8,
        externalAddress: (host: String, port: UInt16)? = nil,
        relayEnabled: Bool = false,
        carriers: [PeerEndpoint] = [],
        mode: IvyMode = .overlay
    ) {
        self.signingKey = signingKey
        self.peerKey = try! PeerKey(rawRepresentation: signingKey.publicKey.rawRepresentation)
        self.mode = mode
        self.listenPort = listenPort
        self.bootstrapPeers = bootstrapPeers
        self.carriers = carriers
        self.stunServers = mode.participatesInPublicDiscovery ? stunServers : []
        self.relayEnabled = relayEnabled
        self.tallyConfig = tallyConfig
        self.kBucketSize = kBucketSize
        self.requestTimeout = requestTimeout
        self.relayTimeout = relayTimeout
        self.healthConfig = healthConfig
        self.routingRefreshInterval = routingRefreshInterval
        self.logger = logger
        self.maxConnections = maxConnections
        self.maxConnectionsPerNetgroup = maxConnectionsPerNetgroup
        self.maxPendingRequests = maxPendingRequests
        self.maxWaitersPerRequest = maxWaitersPerRequest
        self.maxConcurrentContentRequests = maxConcurrentContentRequests
        self.maxInboundBufferedBytes = maxInboundBufferedBytes
        self.minPeerKeyBits = minPeerKeyBits
        self.maxContentCandidates = maxContentCandidates
        self.externalAddress = externalAddress
    }

    public func validate() throws {
        guard maxConnections > 0,
              maxConnectionsPerNetgroup > 0,
              maxPendingRequests > 0,
              maxWaitersPerRequest > 0,
              maxConcurrentContentRequests > 0,
              maxContentCandidates > 0 else {
            throw IvyModeError.invalidConfiguration("capacity limits must be positive")
        }
        guard maxInboundBufferedBytes >= Int(IvyConfig.protocolMaxFrameSize) + 4 else {
            throw IvyModeError.invalidConfiguration(
                "inbound byte budget must hold one maximum frame")
        }
        guard (1...Int(MessageLimits.maxNeighborCount)).contains(kBucketSize),
              (0...256).contains(minPeerKeyBits),
              requestTimeout > .zero,
              relayTimeout > .zero,
              routingRefreshInterval > .zero else {
            throw IvyModeError.invalidConfiguration("routing and timeout limits are invalid")
        }
        if healthConfig.enabled {
            guard healthConfig.keepaliveInterval > .zero,
                  healthConfig.staleTimeout > healthConfig.keepaliveInterval,
                  healthConfig.maxMissedPongs > 0 else {
                throw IvyModeError.invalidConfiguration("peer health limits are invalid")
            }
        }
        if let externalAddress {
            let host = externalAddress.host.trimmingCharacters(in: .whitespacesAndNewlines)
            guard NetGroup.ipv4Octets(host) != nil || NetGroup.ipv6Hextets(host) != nil,
                  externalAddress.port != 0 else {
                throw IvyModeError.invalidConfiguration(
                    "externalAddress must be an IP literal with a nonzero port")
            }
        }

        let pinned = try mode.pinnedKey()
        if pinned == peerKey {
            throw IvyModeError.identityRoleCollision(peerKey.hex)
        }
        var carrierKeys = Set<PeerKey>()
        for carrier in carriers {
            guard endpointIsDialable(carrier) else {
                throw IvyModeError.invalidConfiguration("carrier endpoint must be dialable")
            }
            guard let key = try? PeerKey(carrier.publicKey) else {
                throw IvyModeError.invalidCarrierIdentity(carrier.publicKey)
            }
            guard carrierKeys.insert(key).inserted else {
                throw IvyModeError.duplicateCarrierIdentity(carrier.publicKey)
            }
            guard key != peerKey, key != pinned else {
                throw IvyModeError.identityRoleCollision(carrier.publicKey)
            }
        }

        for endpoint in bootstrapPeers {
            guard endpointIsDialable(endpoint) else {
                throw IvyModeError.invalidConfiguration("bootstrap endpoint must be dialable")
            }
            guard let key = try? PeerKey(endpoint.publicKey) else {
                throw IvyModeError.invalidEndpointIdentity(endpoint.publicKey)
            }
            guard !carrierKeys.contains(key) else {
                throw IvyModeError.identityRoleCollision(endpoint.publicKey)
            }
            guard key != peerKey else {
                throw IvyModeError.identityRoleCollision(endpoint.publicKey)
            }
            if let pinned, key != pinned {
                throw IvyModeError.peerOutsidePinnedMode(expected: pinned.hex, actual: endpoint.publicKey)
            }
        }
    }

    private func endpointIsDialable(_ endpoint: PeerEndpoint) -> Bool {
        !endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && endpoint.port != 0
    }

    func isConfiguredCarrier(_ key: PeerKey) -> Bool {
        carriers.contains { (try? PeerKey($0.publicKey)) == key }
    }

    func allowsEndpoint(_ key: PeerKey) -> Bool {
        key != peerKey && mode.allowsEndpoint(key) && !isConfiguredCarrier(key)
    }
}
