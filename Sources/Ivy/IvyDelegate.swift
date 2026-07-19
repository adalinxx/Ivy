import Foundation
import Tally

public protocol IvyDelegate: AnyObject, Sendable {
    func ivy(_ ivy: Ivy, didConnect peer: AuthenticatedPeer)
    func ivy(_ ivy: Ivy, didDisconnect peer: PeerID)
    func ivy(_ ivy: Ivy, didDiscoverPublicAddress address: ObservedAddress)
    func ivy(_ ivy: Ivy, didReceiveMessage message: PeerMessage, from peer: AuthenticatedPeer) async
}

public extension IvyDelegate {
    func ivy(_ ivy: Ivy, didConnect peer: AuthenticatedPeer) {}
    func ivy(_ ivy: Ivy, didDisconnect peer: PeerID) {}
    func ivy(_ ivy: Ivy, didDiscoverPublicAddress address: ObservedAddress) {}
    func ivy(_ ivy: Ivy, didReceiveMessage message: PeerMessage, from peer: AuthenticatedPeer) async {}
}
