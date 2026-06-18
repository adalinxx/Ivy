import Testing
import Foundation
import NIOCore
import NIOEmbedded
@testable import Ivy
@testable import Tally

///: a single peer flooding announceVolume/pushVolume must not be able to
/// drive unbounded outbound broadcast amplification. The per-peer gossip token
/// bucket (Ivy.announceGossipCapacity / refillPerSec) gates admitGossipRelay, so
/// after the bucket drains the relay fan-out stops even though the flooder keeps
/// sending. These tests assert the THROTTLE on the real handler path, not just
/// that the TokenBucket primitive counts down.
@Suite("Gossip relay throttling")
struct GossipRelayThrottleTests {

    private func throttleConfig() -> IvyConfig {
        IvyConfig(
            publicKey: "gossip-throttle-node",
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            healthConfig: PeerHealthConfig(
                keepaliveInterval: .seconds(999),
                staleTimeout: .seconds(999),
                maxMissedPongs: 99,
                enabled: false
            ),
            enablePEX: false
        )
    }

    /// Count how many length-prefixed frames a testing channel has been asked
    /// to write. broadcastPayload uses fireAndForget → writeAndFlush(buffer).
    private func outboundFrameCount(_ channel: NIOAsyncTestingChannel) async -> Int {
        var count = 0
        while let _ = try? await channel.readOutbound(as: ByteBuffer.self) {
            count += 1
        }
        return count
    }

    @Test("Flooding announceVolume is rate-limited at the relay fan-out")
    func announceVolumeFanOutIsThrottled() async throws {
        let node = Ivy(config: throttleConfig())

        // An observer peer that should receive the relayed announcements.
        let observerChannel = NIOAsyncTestingChannel()
        try await observerChannel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 4001)).get()
        let observerID = PeerID(publicKey: "observer-peer")
        let observerConn = PeerConnection(
            id: observerID,
            endpoint: PeerEndpoint(publicKey: observerID.publicKey, host: "127.0.0.1", port: 4001),
            channel: observerChannel
        )
        await node.registerConnectionForTesting(observerConn, as: observerID)

        // One flooder sends far more announcements than the bucket capacity.
        let flooder = PeerID(publicKey: "flooder-peer")
        let capacity = Int(Ivy.announceGossipCapacity)
        let floodCount = capacity + 200

        for i in 0..<floodCount {
            // Distinct rootCIDs so dedup never short-circuits before the bucket.
            await node.handleAnnounceVolume(
                rootCID: "flood-root-\(i)",
                childCIDs: ["flood-root-\(i)"],
                totalSize: 1,
                from: flooder
            )
        }

        // Drain whatever the observer received. fireAndForget writes happen on
        // the channel's event loop; readOutbound pulls them back out.
        let relayed = await outboundFrameCount(observerChannel)

        #expect(relayed > 0, "some announcements should relay before the bucket drains")
        #expect(relayed <= capacity,
                "flooder must not amplify beyond bucket capacity (\(capacity)) — relayed \(relayed) of \(floodCount)")

        _ = try? await observerChannel.finish()
    }

    @Test("admitGossipRelay throttles a single flooding peer")
    func admitGossipRelayThrottlesFlooder() async {
        let node = Ivy(config: throttleConfig())
        let flooder = PeerID(publicKey: "flooder-peer-direct")
        let capacity = Int(Ivy.announceGossipCapacity)

        var admitted = 0
        for _ in 0..<(capacity + 100) {
            if await node.admitGossipRelay(from: flooder) { admitted += 1 }
        }

        // The bucket may refill a small amount during the loop, but it must be
        // bounded well below the unthrottled total.
        #expect(admitted >= capacity, "the full initial burst should admit")
        #expect(admitted < capacity + 100,
                "a flooder must eventually be throttled — admitted \(admitted)")
    }
}
