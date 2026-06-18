import Foundation
import NIOCore
import Tally

public final class LocalPeerConnection: @unchecked Sendable {
    static let inboundBufferLimit = 256

    public let id: PeerID
    private let inbound: AsyncStream<Message>
    private let inboundContinuation: AsyncStream<Message>.Continuation
    private weak var remoteEnd: LocalPeerConnection?

    public init(id: PeerID) {
        self.id = id
        let (stream, continuation) = AsyncStream<Message>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.inboundBufferLimit)
        )
        self.inbound = stream
        self.inboundContinuation = continuation
    }

    public var messages: AsyncStream<Message> { inbound }

    public func send(_ message: Message) {
        remoteEnd?.inboundContinuation.yield(message)
    }

    public func close() {
        inboundContinuation.finish()
        remoteEnd?.inboundContinuation.finish()
    }

    public static func pair(localID: PeerID, remoteID: PeerID) -> (local: LocalPeerConnection, remote: LocalPeerConnection) {
        let local = LocalPeerConnection(id: localID)
        let remote = LocalPeerConnection(id: remoteID)
        local.remoteEnd = remote
        remote.remoteEnd = local
        return (local, remote)
    }
}

public actor LocalServiceBus {
    private weak var node: Ivy?
    private var services: [String: LocalPeerConnection] = [:]

    public init(node: Ivy) {
        self.node = node
    }

    public func register(name: String, publicKey: String) -> LocalPeerConnection {
        let serviceID = PeerID(publicKey: publicKey)
        guard let node else {
            return LocalPeerConnection(id: serviceID)
        }

        let nodeID = node.localID
        let (serviceSide, nodeSide) = LocalPeerConnection.pair(localID: serviceID, remoteID: nodeID)
        services[name] = nodeSide

        Task {
            await node.registerLocalPeer(nodeSide, as: serviceID)
        }

        return serviceSide
    }

    public func unregister(name: String) async {
        if let conn = services.removeValue(forKey: name) {
            conn.close()
            if let node {
                await node.unregisterLocalPeer(conn.id)
            }
        }
    }

    public var registeredServices: [String] {
        Array(services.keys)
    }
}
