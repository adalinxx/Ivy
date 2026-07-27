import Foundation

enum MessageLimits {
    static let maxStringLength: UInt16 = 8192
    static let maxNeighborCount: UInt16 = 256
    static let maxListenAddrs: UInt16 = 16
    static let maxContentCIDCount: UInt16 = 4096
    static let maxContentEntryCount: UInt16 = 4096
    static let maxVolumeEntryCount = UInt16.max
    static let maxVolumeChunkCount: UInt16 = 1024
    static let maxVolumeArchiveBytes = 64 * 1024 * 1024
    static let maxInFlightVolumeBytes = 128 * 1024 * 1024

    static func accepts(_ string: String) -> Bool {
        !string.isEmpty
            && string.utf8.count <= Int(maxStringLength)
            && string.utf8.allSatisfy { $0 < 0x80 }
    }
}
