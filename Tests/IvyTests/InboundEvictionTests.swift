import Testing
import Foundation
import NIOEmbedded
@testable import Ivy
@testable import Tally

@Suite("Inbound eviction (netgroup-aware)")
struct InboundEvictionTests {

    private func makeConfig(publicKey: String, maxPeers: Int) -> IvyConfig {
        IvyConfig(
            publicKey: publicKey,
            listenPort: 0,
            bootstrapPeers: [],
            enableLocalDiscovery: false,
            tallyConfig: TallyConfig(maxPeers: maxPeers),
            enablePEX: false
        )
    }

    /// Builds an inbound connection. `host` is the OBSERVED socket address used
    /// for netgroup accounting; `advertised` (default = observed) is the
    /// self-advertised endpoint host, which must NOT influence grouping.
    private func inboundConn(key: String, host: String, advertised: String? = nil) -> PeerConnection {
        let conn = PeerConnection(
            id: PeerID(publicKey: key),
            endpoint: PeerEndpoint(publicKey: key, host: advertised ?? host, port: 0),
            channel: NIOAsyncTestingChannel(),
            maxFrameSize: IvyConfig.defaultMaxFrameSize
        )
        conn.observedHost = host
        return conn
    }

    @Test("Inbound flood from one netgroup is capped — eviction targets that group")
    func floodFromOneNetgroupIsCapped() async throws {
        // Cap of 4 inbound. Seed one honest peer in a distinct netgroup, then
        // flood from a single /16 trying to take every slot.
        let node = Ivy(config: makeConfig(publicKey: "evict-flood-node", maxPeers: 4))

        let honest = inboundConn(key: "honest", host: "203.0.113.9")
        await node.registerInboundConnection(honest)

        // Flood many peers all inside 198.51.0.0/16.
        var floodChannels: [PeerConnection] = [honest]
        for i in 0..<12 {
            let conn = inboundConn(key: "flood-\(i)", host: "198.51.\(i).7")
            floodChannels.append(conn)
            await node.registerInboundConnection(conn)
        }

        let inbound = await node.inboundPeerHostsForTesting()
        // The honest peer in its own netgroup must survive the flood.
        #expect(inbound.keys.contains(PeerID(publicKey: "honest")))
        // The single flooding /16 cannot occupy more than its eviction-bounded
        // share: with a cap of 4 and netgroup-aware eviction, it never grows to
        // fill every slot while a distinct-netgroup peer exists.
        let floodCount = inbound.values.filter { NetGroup.group($0) == "v4:198.51" }.count
        #expect(floodCount < 4)
        #expect(inbound.count <= 4)

        for c in floodChannels { c.cancel() }
    }

    @Test("Self-advertised host cannot forge a netgroup — grouping uses the observed socket address")
    func advertisedHostCannotForgeNetgroup() async throws {
        // The flood advertises a DIFFERENT diverse host per connection (trying to
        // look like distinct netgroups), but every connection's observed socket
        // address is inside one /16. Eviction must group by the observed address,
        // so the flood is still capped and the honest peer survives.
        let node = Ivy(config: makeConfig(publicKey: "evict-forge-node", maxPeers: 4))

        let honest = inboundConn(key: "honest", host: "203.0.113.9")
        await node.registerInboundConnection(honest)

        var conns: [PeerConnection] = [honest]
        for i in 0..<12 {
            // Observed: all in 198.51.0.0/16. Advertised: a unique fake /16 each.
            let conn = inboundConn(key: "forge-\(i)", host: "198.51.\(i).7", advertised: "\(i + 1).0.0.1")
            conns.append(conn)
            await node.registerInboundConnection(conn)
        }

        let observed = await node.inboundPeerObservedHostsForTesting()
        #expect(observed.keys.contains(PeerID(publicKey: "honest")))
        let floodCount = observed.values.filter { NetGroup.group($0) == "v4:198.51" }.count
        #expect(floodCount < 4)
        #expect(observed.count <= 4)

        for c in conns { c.cancel() }
    }

    @Test("A banned peer is refused inbound admission")
    func bannedPeerRefused() async throws {
        // perPeerRequestCapacity 1, no refill → after one shouldAllow the peer's
        // token bucket is empty and Tally denies it (durable refusal for the test
        // window).
        let tally = Tally(config: TallyConfig(
            perPeerRequestCapacity: 1,
            perPeerRequestRefillPerSecond: 0,
            maxPeers: 8
        ))
        let node = Ivy(config: makeConfig(publicKey: "evict-ban-node", maxPeers: 8), tally: tally)

        let banned = PeerID(publicKey: "banned-peer")
        // Drain the one admission token so shouldAllow now returns false.
        _ = tally.shouldAllow(peer: banned)
        #expect(tally.shouldAllow(peer: banned) == false)

        let conn = inboundConn(key: "banned-peer", host: "198.51.100.5")
        await node.registerInboundConnection(conn)

        let inbound = await node.inboundPeerHostsForTesting()
        #expect(!inbound.keys.contains(banned))

        conn.cancel()
    }
}
