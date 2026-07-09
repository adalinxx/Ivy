import Foundation
import NIOCore
import Tally
import Crypto

extension Ivy {
    // MARK: - Pin Announcements

    func handleFindPins(cid: String, from peer: PeerID) async {
        guard tally.shouldAllow(peer: peer) else { return }

        let stored = pinAnnouncements[cid] ?? []
        let providers = stored.map(\.publicKey)
        fireToPeer(peer, .pins(cid: cid, providers: providers))
    }

    func handlePinAnnounce(rootCID: String, publicKey: String, expiry: UInt64, signature: Data, fee: UInt64, from peer: PeerID) {
        guard tally.shouldAllow(peer: peer) else { return }
        guard publicKey == peer.publicKey else { return }
        guard PinAnnouncementSignature.isExpiryValid(expiry) else { return }
        guard PinAnnouncementSignature.verify(
            rootCID: rootCID,
            publicKey: publicKey,
            expiry: expiry,
            fee: fee,
            signature: signature
        ) else { return }
        guard shouldStorePinAnnouncement(rootCID: rootCID) else { return }

        var existing = pinAnnouncements[rootCID] ?? []
        existing.removeAll { $0.publicKey == publicKey }
        existing.append((publicKey: publicKey, expiry: expiry))

        if existing.count > Int(MessageLimits.maxNeighborCount) {
            existing = Array(existing.suffix(Int(MessageLimits.maxNeighborCount)))
        }
        pinAnnouncements[rootCID] = existing

        fireToPeer(peer, .pinStored(rootCID: rootCID))
    }

    func shouldStorePinAnnouncement(rootCID: String) -> Bool {
        let keyHash = Router.hash(rootCID)
        let peers = router.allPeers()
        guard !peers.isEmpty else { return true }

        let keyBucket = min(Router.commonPrefixLength(router.localHash, keyHash), 255)
        if let deepestPopulatedBucket = peers.map({ min(Router.commonPrefixLength(router.localHash, $0.hash), 255) }).max(),
           keyBucket >= deepestPopulatedBucket {
            return true
        }

        let closest = peers.sorted { Router.isCloser($0.hash, than: $1.hash, to: keyHash) }
        guard closest.count >= config.kBucketSize,
              let kth = closest.prefix(config.kBucketSize).last else {
            return true
        }
        return Router.isCloser(router.localHash, than: kth.hash, to: keyHash)
    }

    /// Resolve any in-flight findPins waiters with the providers that just
    /// arrived, and seed them as candidates for future fetches. Provider
    /// peers may not be in our routing table yet; we just stash the keys
    /// and let fetchVolume gate on connection-reachability.
    func handlePinsResponse(cid: String, providers: [String], from peer: PeerID) {
        guard let pending = pendingFindPins[cid],
              pending.expectedPeers.contains(peer.publicKey) else { return }
        guard !providers.isEmpty else { return }

        let peerIDs = providers.map { PeerID(publicKey: $0) }
        if let waiters = pendingFindPins.removeValue(forKey: cid)?.continuations {
            for cont in waiters { cont.resume(returning: peerIDs) }
        }
        for pk in providers {
            let pid = PeerID(publicKey: pk)
            recordVolumeProvider(rootCID: cid, peer: pid)
        }
    }

    public func publishPinAnnounce(rootCID: String, expiry: UInt64, fee: UInt64) {
        guard let signature = PinAnnouncementSignature.sign(
            rootCID: rootCID,
            publicKey: config.publicKey,
            expiry: expiry,
            fee: fee,
            signingKey: config.signingKey
        ) else {
            return
        }
        publishPinAnnounce(rootCID: rootCID, expiry: expiry, signature: signature, fee: fee)
    }

    public func publishPinAnnounce(rootCID: String, expiry: UInt64, signature: Data, fee: UInt64) {
        guard PinAnnouncementSignature.isExpiryValid(expiry) else { return }
        guard PinAnnouncementSignature.verify(
            rootCID: rootCID,
            publicKey: config.publicKey,
            expiry: expiry,
            fee: fee,
            signature: signature
        ) else { return }

        // Self-record: when we publish that we pin a CID, we are also a
        // valid answer to findPins for that CID. Without this, a node that
        // is itself in the closest-K to the CID hash never appears in its
        // own responses — IPFS provider records are bidirectional.
        var existing = pinAnnouncements[rootCID] ?? []
        existing.removeAll { $0.publicKey == config.publicKey }
        existing.append((publicKey: config.publicKey, expiry: expiry))
        pinAnnouncements[rootCID] = existing

        let msg = Message.pinAnnounce(rootCID: rootCID, publicKey: config.publicKey, expiry: expiry, signature: signature, fee: fee)
        let cidHash = Router.hash(rootCID)
        let closest = router.closestPeers(to: cidHash, count: config.kBucketSize)
        for entry in closest {
            let reachable = hasAnyConnection(entry.id) || localPeers[entry.id] != nil
            guard reachable else { continue }
            fireToPeer(entry.id, msg)
        }
    }

    func storedPinAnnouncements(for cid: String) -> [String] {
        (pinAnnouncements[cid] ?? []).map(\.publicKey)
    }

    // MARK: - Expiry

    public func evict() {
        evictExpiredPins()
        evictExpiredProviders()
    }

    func evictExpiredPins() {
        let now = UInt64(Date().timeIntervalSince1970)
        let rootCIDs = Array(pinAnnouncements.keys)
        for rootCID in rootCIDs {
            guard var announcements = pinAnnouncements[rootCID] else { continue }
            announcements.removeAll { $0.expiry <= now }
            if announcements.isEmpty {
                pinAnnouncements.removeValue(forKey: rootCID)
            } else {
                pinAnnouncements[rootCID] = announcements
            }
        }
    }

    func evictExpiredProviders() {
        let rootCIDs = Array(providerRecords.keys)
        for rootCID in rootCIDs {
            let liveKeys: Set<String>
            if let announcements = pinAnnouncements[rootCID] {
                liveKeys = Set(announcements.map(\.publicKey))
            } else {
                liveKeys = []
            }
            if var providers = providerRecords[rootCID] {
                providers.removeAll { !liveKeys.contains($0.publicKey) }
                if providers.isEmpty {
                    providerRecords.removeValue(forKey: rootCID)
                } else {
                    providerRecords[rootCID] = providers
                }
            }
        }
    }
}
