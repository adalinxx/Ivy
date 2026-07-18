import Foundation
import Testing
@testable import Ivy
import Tally

private final class DeterministicNonce: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64

    init(startingAt value: UInt64) { self.value = value }

    func take() -> UInt64 {
        lock.withLock {
            defer { value &+= 1 }
            return value
        }
    }
}

private actor PingRecorder {
    private var values: [(PeerID, UInt64)] = []

    @discardableResult
    func record(_ peer: PeerID, nonce: UInt64) -> Bool {
        values.append((peer, nonce))
        return values.count == 1
    }

    var firstPeer: PeerID? { values.first?.0 }
    var peers: [PeerID] { values.map(\.0) }
    var nonces: [UInt64] { values.map { $0.1 } }
}

@Suite("Peer health monitor")
struct PeerHealthMonitorTests {
    @Test("ping, exact pong, and activity reset use deterministic time")
    func pingPongAndActivity() async {
        let clock = TestContinuousClock()
        let nonce = DeterministicNonce(startingAt: 100)
        let pings = PingRecorder()
        let peer = PeerID(publicKey: deterministicTestPeerKey("health-peer"))
        let sessionID = try! SessionID(bytes: Data(repeating: 1, count: 32))
        let monitor = PeerHealthMonitor(
            config: .default,
            onStale: { _, _ in },
            now: { clock.now },
            nextNonce: { nonce.take() })

        await monitor.trackPeer(peer, sessionID: sessionID)
        clock.advance(by: .seconds(60))
        #expect(await monitor.checkAndPing { peer, _, nonce in
            await pings.record(peer, nonce: nonce)
        }.isEmpty)
        #expect(await pings.nonces == [100])

        #expect(!(await monitor.recordPong(from: peer, sessionID: sessionID, nonce: 999)))
        #expect(await monitor.health(for: peer)?.pendingPingNonce == 100)
        clock.advance(by: .seconds(60))
        _ = await monitor.checkAndPing { peer, _, nonce in
            await pings.record(peer, nonce: nonce)
        }
        #expect(await monitor.health(for: peer)?.missedPongs == 1)

        #expect(await monitor.recordPong(from: peer, sessionID: sessionID, nonce: 101))
        #expect(await monitor.health(for: peer)?.pendingPingNonce == nil)
        #expect(await monitor.health(for: peer)?.missedPongs == 0)
        clock.advance(by: .seconds(60))
        _ = await monitor.checkAndPing { peer, _, nonce in
            await pings.record(peer, nonce: nonce)
        }
        await monitor.recordActivity(from: peer, sessionID: sessionID)
        #expect(await monitor.health(for: peer)?.pendingPingNonce == nil)
        #expect(await monitor.health(for: peer)?.missedPongs == 0)
    }

    @Test("misses evict at the limit and replacement starts clean")
    func missesAndReplacement() async {
        let clock = TestContinuousClock()
        let nonce = DeterministicNonce(startingAt: 1)
        let peer = PeerID(publicKey: deterministicTestPeerKey("health-missed-peer"))
        let sessionID = try! SessionID(bytes: Data(repeating: 2, count: 32))
        let monitor = PeerHealthMonitor(
            config: PeerHealthConfig(
                keepaliveInterval: .seconds(60),
                staleTimeout: .seconds(1_000),
                maxMissedPongs: 3),
            onStale: { _, _ in },
            now: { clock.now },
            nextNonce: { nonce.take() })

        await monitor.trackPeer(peer, sessionID: sessionID)
        for _ in 0..<3 {
            clock.advance(by: .seconds(60))
            #expect(await monitor.checkAndPing { _, _, _ in }.isEmpty)
        }
        clock.advance(by: .seconds(60))
        let stale = await monitor.checkAndPing { _, _, _ in }
        #expect(stale.count == 1)
        #expect(stale.first?.0 == peer)
        #expect(stale.first?.1 == sessionID)
        #expect(await monitor.health(for: peer) == nil)

        await monitor.trackPeer(peer, sessionID: sessionID)
        #expect(await monitor.health(for: peer)?.pendingPingNonce == nil)
        #expect(await monitor.health(for: peer)?.missedPongs == 0)
    }

    @Test("default stale timeout is inclusive")
    func defaultStaleTimeout() async {
        let clock = TestContinuousClock()
        let peer = PeerID(publicKey: deterministicTestPeerKey("health-stale-peer"))
        let sessionID = try! SessionID(bytes: Data(repeating: 3, count: 32))
        let monitor = PeerHealthMonitor(
            config: .default,
            onStale: { _, _ in },
            now: { clock.now })

        await monitor.trackPeer(peer, sessionID: sessionID)
        clock.advance(by: .seconds(180))

        let stale = await monitor.checkAndPing { _, _, _ in }
        #expect(stale.count == 1)
        #expect(stale.first?.0 == peer)
        #expect(stale.first?.1 == sessionID)
    }

    @Test("delayed removal cannot erase a replacement session")
    func removalIsSessionScoped() async {
        let peer = PeerID(publicKey: deterministicTestPeerKey("health-replacement-peer"))
        let oldSession = try! SessionID(bytes: Data(repeating: 4, count: 32))
        let replacement = try! SessionID(bytes: Data(repeating: 5, count: 32))
        let monitor = PeerHealthMonitor(config: .default, onStale: { _, _ in })

        await monitor.trackPeer(peer, sessionID: oldSession)
        await monitor.trackPeer(peer, sessionID: replacement)
        await monitor.removePeer(peer, sessionID: oldSession)

        #expect(await monitor.health(for: peer)?.sessionID == replacement)
    }

    @Test("a suspended sweep cannot overwrite a replacement session")
    func reentrantSweepPreservesReplacement() async throws {
        let clock = TestContinuousClock()
        let nonce = DeterministicNonce(startingAt: 1)
        let pings = PingRecorder()
        let firstPing = TestBarrier("first health ping")
        let peerA = PeerID(publicKey: deterministicTestPeerKey("health-reentrant-a"))
        let peerB = PeerID(publicKey: deterministicTestPeerKey("health-reentrant-b"))
        let oldSessionA = try SessionID(bytes: Data(repeating: 6, count: 32))
        let oldSessionB = try SessionID(bytes: Data(repeating: 7, count: 32))
        let replacement = try SessionID(bytes: Data(repeating: 8, count: 32))
        let monitor = PeerHealthMonitor(
            config: .default,
            onStale: { _, _ in },
            now: { clock.now },
            nextNonce: { nonce.take() })

        await monitor.trackPeer(peerA, sessionID: oldSessionA)
        await monitor.trackPeer(peerB, sessionID: oldSessionB)
        clock.advance(by: .seconds(60))

        let sweep = BoundedTestTask {
            await monitor.checkAndPing { peer, _, nonce in
                guard await pings.record(peer, nonce: nonce) else { return }
                do {
                    try await firstPing.arriveAndWait()
                } catch {
                    Issue.record("\(error)")
                }
            }
        }

        try await firstPing.waitForArrivals()
        let observedFirstPeer = try #require(await pings.firstPeer)
        let replacedPeer = observedFirstPeer == peerA ? peerB : peerA
        await monitor.trackPeer(replacedPeer, sessionID: replacement)
        await firstPing.release()

        #expect(try await sweep.value(waitingFor: "peer health sweep").isEmpty)
        #expect(await monitor.health(for: replacedPeer)?.sessionID == replacement)
        #expect(await pings.peers == [observedFirstPeer])
    }
}
