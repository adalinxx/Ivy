@preconcurrency import Crypto
import Foundation
import Tally

public struct IvyConfig: Sendable {
    /// Default maximum wire frame this node will accept. Operator-tunable via the
    /// `protocolMaxFrameSize` instance field, and negotiated per connection (a
    /// node never sends a frame larger than the peer advertised it will accept).
    public static let defaultProtocolMaxFrameSize: UInt32 = 4 * 1024 * 1024
    public static let defaultMaxConnections = 256
    /// Outbound dials this node will hold into one netgroup. Outbound peers are
    /// the ones a node chooses to learn the chain from, so they must not be
    /// concentrable in one address block: with free peer identities, a single
    /// host could otherwise answer every dial. Two (not Bitcoin Core's one)
    /// leaves room for two honest nodes sharing a cloud /16 while still forcing
    /// an attacker to acquire N/2 distinct netgroups to hold N outbound slots.
    /// Operator-configured bootstrap peers and carriers are exempt.
    public static let defaultMaxOutboundConnectionsPerNetgroup = 2
    public static let defaultMaxInboundBufferedBytes = 64 * 1024 * 1024
    public static let defaultMaxRoutesPerIdentity = 3
    public static let defaultMaxProviderTTLSeconds: UInt64 = 24 * 60 * 60
    public static let defaultMaxInFlightVolumeBytes = 128 * 1024 * 1024
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
    /// Authenticated private-plane peers whose application messages must not
    /// be silently discarded by the receiver's local Tally policy.
    public let inboundAdmissionBypassPeerKeys: Set<PeerKey>
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
    /// Slots held back from inbound handshakes so an outbound configured peer can connect.
    public let reservedOutboundConnectionSlots: Int
    /// Inbound connections admitted per observed netgroup. Separate from the
    /// outbound cap because an L4 proxy presents every inbound peer from one
    /// address, so proxy-fronted nodes must raise this without weakening
    /// outbound diversity.
    public let maxInboundConnectionsPerNetgroup: Int
    /// Outbound connections held per netgroup; see
    /// `defaultMaxOutboundConnectionsPerNetgroup`. Configured bootstrap peers
    /// and carriers are exempt, but still count against the netgroup.
    public let maxOutboundConnectionsPerNetgroup: Int
    public let maxPendingRequests: Int
    public let maxWaitersPerRequest: Int
    public let maxConcurrentContentRequests: Int
    public let maxContentCandidates: Int
    public let maxInboundBufferedBytes: Int
    public let minPeerKeyBits: Int
    /// Operator-tunable guards (sane defaults). Formerly hardcoded constants; a
    /// node may raise or lower them, accepting the resource/policy consequences.
    public let maxRoutesPerIdentity: Int
    public let maxProviderTTLSeconds: UInt64
    public let maxInFlightVolumeBytes: Int
    /// Max wire frame this node will ACCEPT (inbound). Advertised in the handshake
    /// so peers cap what they send us; outbound is capped at the peer's advertised
    /// value. Operator-tunable; the default is the safe framing DoS bound.
    public let protocolMaxFrameSize: UInt32
    public let externalAddress: (host: String, port: UInt16)?
    public let relayEnabled: Bool
    /// Enables direct exact-CID request/response messages on a private network.
    /// Public overlays always support content exchange.
    public let privateContentExchangeEnabled: Bool

    public init(
        signingKey: Curve25519.Signing.PrivateKey,
        listenPort: UInt16 = 4001,
        bootstrapPeers: [PeerEndpoint] = [],
        inboundAdmissionBypassPeerKeys: Set<PeerKey> = [],
        tallyConfig: TallyConfig = .default,
        kBucketSize: Int = 20,
        requestTimeout: Duration = .seconds(15),
        relayTimeout: Duration = .seconds(5),
        stunServers: [(String, Int)] = IvyConfig.defaultSTUNServers,
        healthConfig: PeerHealthConfig = .default,
        routingRefreshInterval: Duration = .seconds(120),
        logger: any IvyLogger = NullLogger(),
        maxConnections: Int = IvyConfig.defaultMaxConnections,
        reservedOutboundConnectionSlots: Int = 0,
        maxInboundConnectionsPerNetgroup: Int = 2,
        maxOutboundConnectionsPerNetgroup: Int = IvyConfig.defaultMaxOutboundConnectionsPerNetgroup,
        maxPendingRequests: Int = 4_096,
        maxWaitersPerRequest: Int = 64,
        maxConcurrentContentRequests: Int = 64,
        maxInboundBufferedBytes: Int = IvyConfig.defaultMaxInboundBufferedBytes,
        minPeerKeyBits: Int = 0,
        maxContentCandidates: Int = 8,
        maxRoutesPerIdentity: Int = IvyConfig.defaultMaxRoutesPerIdentity,
        maxProviderTTLSeconds: UInt64 = IvyConfig.defaultMaxProviderTTLSeconds,
        maxInFlightVolumeBytes: Int = IvyConfig.defaultMaxInFlightVolumeBytes,
        protocolMaxFrameSize: UInt32 = IvyConfig.defaultProtocolMaxFrameSize,
        externalAddress: (host: String, port: UInt16)? = nil,
        relayEnabled: Bool = false,
        privateContentExchangeEnabled: Bool = false,
        carriers: [PeerEndpoint] = [],
        mode: IvyMode = .overlay
    ) {
        self.signingKey = signingKey
        self.peerKey = try! PeerKey(rawRepresentation: signingKey.publicKey.rawRepresentation)
        self.mode = mode
        self.listenPort = listenPort
        self.bootstrapPeers = bootstrapPeers
        self.inboundAdmissionBypassPeerKeys = inboundAdmissionBypassPeerKeys
        self.carriers = carriers
        self.stunServers = mode.participatesInPublicDiscovery ? stunServers : []
        self.relayEnabled = relayEnabled
        self.privateContentExchangeEnabled = privateContentExchangeEnabled
        self.tallyConfig = tallyConfig
        self.kBucketSize = kBucketSize
        self.requestTimeout = requestTimeout
        self.relayTimeout = relayTimeout
        self.healthConfig = healthConfig
        self.routingRefreshInterval = routingRefreshInterval
        self.logger = logger
        self.maxConnections = maxConnections
        self.reservedOutboundConnectionSlots = reservedOutboundConnectionSlots
        self.maxInboundConnectionsPerNetgroup = maxInboundConnectionsPerNetgroup
        self.maxOutboundConnectionsPerNetgroup = maxOutboundConnectionsPerNetgroup
        self.maxPendingRequests = maxPendingRequests
        self.maxWaitersPerRequest = maxWaitersPerRequest
        self.maxConcurrentContentRequests = maxConcurrentContentRequests
        self.maxInboundBufferedBytes = maxInboundBufferedBytes
        self.minPeerKeyBits = minPeerKeyBits
        self.maxContentCandidates = maxContentCandidates
        self.maxRoutesPerIdentity = maxRoutesPerIdentity
        self.maxProviderTTLSeconds = maxProviderTTLSeconds
        self.maxInFlightVolumeBytes = maxInFlightVolumeBytes
        self.protocolMaxFrameSize = protocolMaxFrameSize
        self.externalAddress = externalAddress
    }

    public func validate() throws {
        guard maxConnections > 0,
              maxInboundConnectionsPerNetgroup > 0,
              maxOutboundConnectionsPerNetgroup > 0,
              maxPendingRequests > 0,
              maxWaitersPerRequest > 0,
              maxConcurrentContentRequests > 0,
              maxContentCandidates > 0 else {
            throw IvyModeError.invalidConfiguration("capacity limits must be positive")
        }
        guard (0...maxConnections).contains(reservedOutboundConnectionSlots) else {
            throw IvyModeError.invalidConfiguration(
                "reserved outbound connection slots must fit within maxConnections")
        }
        guard maxInboundBufferedBytes >= Int(protocolMaxFrameSize) + 4 else {
            throw IvyModeError.invalidConfiguration(
                "inbound byte budget must hold one maximum frame")
        }
        // Operator-tunable frame/route/volume/TTL knobs must be usable: a route
        // count of 0 traps range construction, a zero TTL/volume budget is inert,
        // and a frame size too small to carry the largest handshake record would
        // break every connection before it starts.
        guard maxRoutesPerIdentity > 0,
              maxProviderTTLSeconds > 0,
              maxInFlightVolumeBytes > 0,
              Int(protocolMaxFrameSize) >= SessionWireRecord.maxRelayedHandshakeRecordSize else {
            throw IvyModeError.invalidConfiguration(
                "route, provider-TTL, volume, or frame-size limits are invalid")
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
        if case .privateNetwork = mode, relayEnabled || !carriers.isEmpty {
            throw IvyModeError.invalidConfiguration(
                "private network does not support relay transport")
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

        var bootstrapKeys = Set<PeerKey>()
        for endpoint in bootstrapPeers {
            guard endpointIsDialable(endpoint) else {
                throw IvyModeError.invalidConfiguration("bootstrap endpoint must be dialable")
            }
            guard let key = try? PeerKey(endpoint.publicKey) else {
                throw IvyModeError.invalidEndpointIdentity(endpoint.publicKey)
            }
            bootstrapKeys.insert(key)
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
        guard inboundAdmissionBypassPeerKeys.isEmpty || mode == .privateNetwork else {
            throw IvyModeError.invalidConfiguration(
                "inbound admission bypass is private-network only"
            )
        }
        guard !inboundAdmissionBypassPeerKeys.contains(peerKey) else {
            throw IvyModeError.identityRoleCollision(peerKey.hex)
        }
        guard inboundAdmissionBypassPeerKeys.isSubset(of: bootstrapKeys) else {
            throw IvyModeError.invalidConfiguration(
                "inbound admission bypass peers must be configured bootstrap peers"
            )
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

    func isConfiguredPeer(_ key: PeerKey) -> Bool {
        isConfiguredCarrier(key) || bootstrapPeers.contains { (try? PeerKey($0.publicKey)) == key }
    }

    var maxInboundConnections: Int {
        maxConnections - reservedOutboundConnectionSlots
    }
}
