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

    @Test("per-window rate cap throttles a flood without tearing the circuit down; steady legit traffic stays open")
    func byteRateCap() async {
        let relay = RelayService()
        #expect(await relay.createCircuit(initiator: "A", target: "B"))
        // 1 MB of steady traffic — far over the OLD 128 KB hard total (which would have
        // black-holed a real gossip/sync stream), but under the per-window rate cap, so the
        // circuit stays open. This is exactly the regression the fix targets.
        for _ in 0..<8 {
            #expect(await relay.relay(from: "A", to: "B", bytes: 128 * 1024))
        }
        #expect(await relay.hasCircuit(between: "A", and: "B"))
        // A frame that pushes THIS window over the 8 MB/min rate cap is DROPPED (relay → false),
        // but the circuit is KEPT — a rate limiter throttles, it does not destroy a legit stream
        // mid-burst (destroying it would re-introduce black-holing + trip relay/endpoint role
        // confusion). Subsequent over-rate frames also drop until the window rolls.
        #expect(await relay.relay(from: "A", to: "B", bytes: 8 * 1024 * 1024) == false)
        #expect(await relay.hasCircuit(between: "A", and: "B"))  // still open — throttled, not torn down
        #expect(await relay.relay(from: "A", to: "B", bytes: 1024) == false)  // still throttled this window
        #expect(await relay.hasCircuit(between: "A", and: "B"))
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
