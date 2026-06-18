import Foundation
import Tally

public protocol IvyDelegate: AnyObject, Sendable {
    func ivy(_ ivy: Ivy, didConnect peer: PeerID)
    func ivy(_ ivy: Ivy, didDisconnect peer: PeerID)
    func ivy(_ ivy: Ivy, didReceiveBlockAnnouncement cid: String, from peer: PeerID)
    func ivy(_ ivy: Ivy, didReceiveBlock cid: String, data: Data, from peer: PeerID)
    func ivy(_ ivy: Ivy, didDiscoverPublicAddress address: ObservedAddress)
    func ivy(_ ivy: Ivy, didReceiveMessage message: Message, from peer: PeerID)
    func ivy(_ ivy: Ivy, didReceiveVolumeAnnouncement rootCID: String, childCIDs: [String], totalSize: UInt64, from peer: PeerID)
    /// Fired after a peer completes the identify handshake and the connection is
    /// re-keyed/admitted under its real (canonical) identity. `realID` is the
    /// authenticated identity; `previous` is the temporary `inbound-<uuid>` id
    /// (inbound) or the dialed id (outbound) the connection was tracked under
    /// before identify. Consumers can use this to enforce durable bans / admission
    /// gating against the real identity that `didConnect` could not provide for
    /// inbound peers.
    func ivy(_ ivy: Ivy, didIdentifyPeer realID: PeerID, previous: PeerID)
    /// Fired after a peer's spawn-cert chain is received and stored 2a),
    /// which arrives as a separate frame *after* identify. Consumers that classify
    /// spawn-tree trust should (re)verify `spawnCertChain(for: peer)` here — the
    /// `didIdentifyPeer` callback may have run before the chain was stored. Fires
    /// on an empty (clearing) presentation too, so stale trust can be dropped.
    func ivy(_ ivy: Ivy, didReceiveSpawnCertChain peer: PeerID)
}

public extension IvyDelegate {
    func ivy(_ ivy: Ivy, didConnect peer: PeerID) {}
    func ivy(_ ivy: Ivy, didDisconnect peer: PeerID) {}
    func ivy(_ ivy: Ivy, didReceiveBlockAnnouncement cid: String, from peer: PeerID) {}
    func ivy(_ ivy: Ivy, didReceiveBlock cid: String, data: Data, from peer: PeerID) {}
    func ivy(_ ivy: Ivy, didDiscoverPublicAddress address: ObservedAddress) {}
    func ivy(_ ivy: Ivy, didReceiveMessage message: Message, from peer: PeerID) {}
    func ivy(_ ivy: Ivy, didReceiveVolumeAnnouncement rootCID: String, childCIDs: [String], totalSize: UInt64, from peer: PeerID) {}
    func ivy(_ ivy: Ivy, didIdentifyPeer realID: PeerID, previous: PeerID) {}
    func ivy(_ ivy: Ivy, didReceiveSpawnCertChain peer: PeerID) {}
}
