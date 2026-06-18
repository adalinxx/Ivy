import Foundation

public enum MessageLimits {
    public static let maxStringLength: UInt16 = 8192
    public static let maxNeighborCount: UInt16 = 256
    public static let maxListenAddrs: UInt16 = 16
    public static let maxTxCIDCount: UInt16 = 4096
    public static let maxTransactionCount: UInt16 = 4096
    public static let maxPexPeerCount: UInt16 = 64
    public static let maxChainPorts: UInt16 = 64
    /// Max spawn certificates in an identify-borne chain. A chain mirrors the
    /// chain-tree depth (Nexus→…→leaf), which is shallow; this bounds the
    /// identify message against a forged-oversize-chain DoS.
    public static let maxSpawnCertChain: UInt16 = 64
}
