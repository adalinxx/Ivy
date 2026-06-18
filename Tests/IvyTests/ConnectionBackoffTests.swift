import Testing
import Foundation
@testable import Ivy
@testable import Tally

private func connectionBackoffConfig(publicKey: String) -> IvyConfig {
    IvyConfig(
        publicKey: publicKey,
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

private func durationMilliseconds(_ duration: Duration) -> Int64 {
    let components = duration.components
    return components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000
}

@Suite("Connection backoff and dial dedupe")
struct ConnectionBackoffTests {

    @Test("Only one outbound dial can be reserved per peer")
    func outboundDialReservationIsPerPeer() async {
        let node = Ivy(config: connectionBackoffConfig(publicKey: "dial-dedupe-node"))
        let endpoint = PeerEndpoint(publicKey: "dial-dedupe-peer", host: "10.3.0.1", port: 4001)
        let peer = PeerID(publicKey: endpoint.publicKey)

        let first = await node.reserveOutgoingDialForTesting(to: endpoint)
        let duplicate = await node.reserveOutgoingDialForTesting(to: endpoint)
        await node.finishOutgoingDialForTesting(to: peer, connected: false)
        let afterRelease = await node.reserveOutgoingDialForTesting(to: endpoint)

        #expect(first)
        #expect(!duplicate)
        #expect(afterRelease)

        await node.finishOutgoingDialForTesting(to: peer, connected: false)
    }

    @Test("In-flight dials count toward subnet diversity")
    func inFlightDialsCountTowardSubnetDiversity() async {
        let node = Ivy(config: connectionBackoffConfig(publicKey: "subnet-dedupe-node"))
        let first = PeerEndpoint(publicKey: "subnet-peer-1", host: "10.4.0.1", port: 4001)
        let second = PeerEndpoint(publicKey: "subnet-peer-2", host: "10.4.0.2", port: 4001)
        let third = PeerEndpoint(publicKey: "subnet-peer-3", host: "10.4.0.3", port: 4001)

        let firstReserved = await node.reserveOutgoingDialForTesting(to: first)
        let secondReserved = await node.reserveOutgoingDialForTesting(to: second)
        let thirdReserved = await node.reserveOutgoingDialForTesting(to: third)

        #expect(firstReserved)
        #expect(secondReserved)
        #expect(!thirdReserved)

        await node.finishOutgoingDialForTesting(to: PeerID(publicKey: first.publicKey), connected: false)
        await node.finishOutgoingDialForTesting(to: PeerID(publicKey: second.publicKey), connected: false)
    }

    @Test("Reconnect delay backs off and caps")
    func reconnectDelayBacksOffAndCaps() async {
        let node = Ivy(config: connectionBackoffConfig(publicKey: "reconnect-backoff-node"))
        let peer = PeerID(publicKey: "reconnect-backoff-peer")

        let first = durationMilliseconds(await node.reconnectDelayForTesting(peer: peer))
        let second = durationMilliseconds(await node.reconnectDelayForTesting(peer: peer))
        var latest = second
        for _ in 0..<20 {
            latest = durationMilliseconds(await node.reconnectDelayForTesting(peer: peer))
        }

        #expect(first >= 500)
        #expect(first <= 750)
        #expect(second >= 1_000)
        #expect(second <= 1_250)
        #expect(latest >= 30_000)
        #expect(latest <= 30_250)
    }
}
