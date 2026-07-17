import Foundation
import Testing
@testable import Ivy
import Tally

@Suite("Inbound admission")
struct InboundAdmissionTests {
    @Test("synchronous leases enforce global and netgroup limits")
    func synchronousGate() {
        let gate = InboundAdmissionGate(maxConnections: 3, maxConnectionsPerNetgroup: 2)
        let first = gate.reserve(observedHost: "10.1.1.1")
        let second = gate.reserve(observedHost: "10.1.2.1")
        #expect(first != nil)
        #expect(second != nil)
        #expect(gate.reserve(observedHost: "10.1.3.1") == nil)

        let otherGroup = gate.reserve(observedHost: "10.2.1.1")
        #expect(otherGroup != nil)
        #expect(gate.reserve(observedHost: "10.3.1.1") == nil)

        first?.release()
        #expect(gate.reserve(observedHost: "10.1.4.1") != nil)
        gate.invalidate()
        #expect(gate.reserve(observedHost: "10.4.1.1") == nil)
    }

    @Test("actor admission rejects stale runs")
    func runScopedActorAdmission() async throws {
        let identity = TransportTestHarness.identity("inbound-admission")
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            maxConnections: 3,
            maxConnectionsPerNetgroup: 1,
            externalAddress: ("127.0.0.1", port)))
        try await ivy.start()
        let generation = await ivy.runGeneration

        let first = connection(label: "current")
        #expect(await ivy.registerInboundConnection(first, generation: generation))

        await ivy.stop()
        try await ivy.start()
        let stale = connection(label: "stale")
        #expect(!(await ivy.registerInboundConnection(stale, generation: generation)))
        #expect(!stale.isLive)
        await ivy.stop()
    }

    @Test("stop and restart serialize with an in-flight start")
    func stopDuringStart() async throws {
        let identity = TransportTestHarness.identity("stop-during-start")
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            externalAddress: ("127.0.0.1", port)))

        let startBarrier = TestBarrier("lifecycle start")
        let stopQueued = TestBarrier("queued stop")
        let restartQueued = TestBarrier("queued restart")
        await ivy.setLifecycleStartHookForTesting {
            do {
                try await startBarrier.arriveAndWait()
            } catch {
                Issue.record("\(error)")
            }
        }
        await ivy.setLifecycleRequestHookForTesting { request in
            if request == 2 {
                do {
                    try await stopQueued.arriveAndWait()
                } catch {
                    Issue.record("\(error)")
                }
            } else if request == 3 {
                do {
                    try await restartQueued.arriveAndWait()
                } catch {
                    Issue.record("\(error)")
                }
            }
        }

        let starting = Task { try await ivy.start() }
        try await startBarrier.waitForArrivals()
        let stopping = Task { await ivy.stop() }
        try await stopQueued.waitForArrivals()
        let restarting = Task { try await ivy.start() }
        try await restartQueued.waitForArrivals()
        await stopQueued.release()
        await restartQueued.release()
        await startBarrier.release()
        try await starting.value
        await stopping.value
        try await restarting.value

        #expect(await ivy.running)
        #expect(await ivy.serverChannel != nil)
        await ivy.stop()
    }

    @Test("stale reconnect callback cannot remove its successor")
    func reconnectCompletionIsTokenScoped() async throws {
        let identity = TransportTestHarness.identity("reconnect-token")
        let port = TransportTestHarness.nextPort()
        let ivy = Ivy(config: IvyConfig(
            signingKey: identity,
            listenPort: port,
            stunServers: [],
            healthConfig: PeerHealthConfig(enabled: false),
            externalAddress: ("127.0.0.1", port)))
        let endpoint = PeerEndpoint(
            publicKey: deterministicTestPeerKey("reconnect-token-peer"),
            host: "127.0.0.1",
            port: TransportTestHarness.nextPort())
        let peer = PeerID(publicKey: endpoint.publicKey)

        try await ivy.start()
        let generation = await ivy.runGeneration
        await ivy.installTestReconnect(peer: peer, generation: generation, token: 2)
        await ivy.runScheduledReconnect(
            to: endpoint,
            peer: peer,
            role: .endpoint,
            generation: generation,
            token: 1)

        #expect(await ivy.testReconnectToken(peer: peer) == 2)
        await ivy.stop()
    }

    private func connection(label: String) -> PeerConnection {
        PeerConnection(
            endpoint: PeerEndpoint(publicKey: "", host: "relay", port: 0),
            routeID: Data(label.utf8) + Data(repeating: 0, count: 32 - label.utf8.count),
            carrier: try! PeerKey(rawRepresentation: Data(repeating: 7, count: 32)))
    }
}

private extension Ivy {
    func installTestReconnect(peer: PeerID, generation: UInt64, token: UInt64) {
        reconnectTasks[peer] = PendingReconnect(
            generation: generation,
            token: token,
            task: Task {})
    }

    func testReconnectToken(peer: PeerID) -> UInt64? {
        reconnectTasks[peer]?.token
    }
}
