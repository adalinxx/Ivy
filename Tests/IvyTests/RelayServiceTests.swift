import Testing
import Foundation
@testable import Ivy

@Suite("Circuit RelayService")
struct RelayServiceTests {
    @Test("createCircuit is idempotent and tracked")
    func createAndTrack() async {
        let relay = RelayService()
        #expect(await relay.createCircuit(initiator: "A", target: "B"))
        #expect(await relay.hasCircuit(between: "A", and: "B"))
        #expect(await relay.hasCircuit(between: "B", and: "A"))  // order-independent
        // idempotent: re-creating the same pair stays a single circuit
        #expect(await relay.createCircuit(initiator: "A", target: "B"))
        #expect(await relay.activeCircuitCount() == 1)
    }

    @Test("per-peer circuit cap is enforced")
    func perPeerCap() async {
        let relay = RelayService()
        for i in 0..<4 { #expect(await relay.createCircuit(initiator: "A", target: "T\(i)")) }
        // 5th circuit for A exceeds maxCircuitsPerPeer (4)
        #expect(await relay.createCircuit(initiator: "A", target: "T4") == false)
        #expect(await relay.activeCircuitCount() == 4)
    }

    @Test("byte budget closes a circuit")
    func byteBudget() async {
        let relay = RelayService()
        #expect(await relay.createCircuit(initiator: "A", target: "B"))
        // within budget
        #expect(await relay.relay(from: "A", to: "B", bytes: 1024))
        // exceeding the 128 KB per-circuit budget closes it
        #expect(await relay.relay(from: "A", to: "B", bytes: 128 * 1024) == false)
        #expect(await relay.hasCircuit(between: "A", and: "B") == false)
    }

    @Test("relay on a missing circuit is refused")
    func missingCircuit() async {
        let relay = RelayService()
        #expect(await relay.relay(from: "X", to: "Y", bytes: 10) == false)
    }

    @Test("removeAllCircuits(forPeer:) tears down a peer's circuits")
    func removeForPeer() async {
        let relay = RelayService()
        _ = await relay.createCircuit(initiator: "A", target: "B")
        _ = await relay.createCircuit(initiator: "C", target: "D")
        await relay.removeAllCircuits(forPeer: "A")
        #expect(await relay.hasCircuit(between: "A", and: "B") == false)
        #expect(await relay.hasCircuit(between: "C", and: "D"))  // unrelated circuit survives
    }
}
