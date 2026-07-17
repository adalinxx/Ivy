import Crypto
import Foundation
@testable import Ivy
import Tally

func deterministicTestSigningKey(_ label: String) -> Curve25519.Signing.PrivateKey {
    try! Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(SHA256.hash(data: Data(label.utf8))))
}

func deterministicTestPeerKey(_ label: String) -> String {
    try! PeerKey(rawRepresentation: deterministicTestSigningKey(label).publicKey.rawRepresentation).hex
}

extension IvyConfig {
    init(
        publicKey: String,
        listenPort: UInt16 = 4001,
        bootstrapPeers: [PeerEndpoint] = [],
        tallyConfig: TallyConfig = .default,
        kBucketSize: Int = 20,
        requestTimeout: Duration = .seconds(15),
        relayTimeout: Duration = .seconds(5),
        stunServers: [(String, Int)] = IvyConfig.defaultSTUNServers,
        healthConfig: PeerHealthConfig = .default,
        routingRefreshInterval: Duration = .seconds(120),
        signingKey: Data = Data(),
        logger: any IvyLogger = NullLogger(),
        maxFrameSize: UInt32 = IvyConfig.defaultMaxFrameSize,
        maxConnections: Int = IvyConfig.defaultMaxConnections,
        maxConnectionsPerNetgroup: Int = 2,
        maxPendingRequests: Int = 4_096,
        maxWaitersPerRequest: Int = 64,
        maxConcurrentContentRequests: Int = 64,
        minPeerKeyBits: Int = 0,
        maxContentCandidates: Int = 8,
        externalAddress: (host: String, port: UInt16)? = nil,
        relayEnabled: Bool = false,
        carriers: [PeerEndpoint] = [],
        mode: IvyMode = .overlay
    ) {
        let privateKey: Curve25519.Signing.PrivateKey
        if let supplied = try? Curve25519.Signing.PrivateKey(rawRepresentation: signingKey) {
            privateKey = supplied
        } else {
            privateKey = deterministicTestSigningKey(publicKey)
        }
        self.init(
            signingKey: privateKey,
            listenPort: listenPort,
            bootstrapPeers: bootstrapPeers,
            tallyConfig: tallyConfig,
            kBucketSize: kBucketSize,
            requestTimeout: requestTimeout,
            relayTimeout: relayTimeout,
            stunServers: stunServers,
            healthConfig: healthConfig,
            routingRefreshInterval: routingRefreshInterval,
            logger: logger,
            maxFrameSize: maxFrameSize,
            maxConnections: maxConnections,
            maxConnectionsPerNetgroup: maxConnectionsPerNetgroup,
            maxPendingRequests: maxPendingRequests,
            maxWaitersPerRequest: maxWaitersPerRequest,
            maxConcurrentContentRequests: maxConcurrentContentRequests,
            minPeerKeyBits: minPeerKeyBits,
            maxContentCandidates: maxContentCandidates,
            externalAddress: externalAddress,
            relayEnabled: relayEnabled,
            carriers: carriers,
            mode: mode)
    }
}
