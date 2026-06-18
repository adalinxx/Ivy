import Testing
import Foundation
@testable import Ivy

@Suite("Peer diversity policy")
struct PeerDiversityTests {
    private func peer(_ key: String, _ host: String) -> PeerEndpoint {
        PeerEndpoint(publicKey: key, host: host, port: 1)
    }

    @Test("subnet delegates to the NetGroup grain (IPv4 /16, IPv6 /32)")
    func subnet() {
        #expect(PeerDiversity.subnet("192.168.1.1") == "v4:192.168")
        #expect(PeerDiversity.subnet("10.0.0.1") == "v4:10.0")
        #expect(PeerDiversity.subnet("::1") == "v6:0000.0000")
    }

    @Test("a single IPv6 /32 cannot exceed the per-netgroup cap in selection")
    func ipv6CannotBypassCap() {
        // Distinct full IPv6 addresses, all inside the same 2001:0db8::/32.
        let candidates = [
            peer("a", "2001:db8::1"),
            peer("b", "2001:db8:1::2"),
            peer("c", "2001:db8:ffff::3"),
            peer("d", "2001:db8:dead:beef::4"),
        ]
        let selected = PeerDiversity.selectDiversePeers(from: candidates, existing: [], maxNew: 8)
        // All collapse to one netgroup → at most maxPerSubnet admitted.
        #expect(selected.count == PeerDiversity.maxPerSubnet)
        #expect(Set(selected.map { PeerDiversity.subnet($0.host) }).count == 1)
    }

    @Test("shouldConnect enforces the per-subnet cap")
    func shouldConnect() {
        let existing = [peer("a", "10.0.0.1"), peer("b", "10.0.0.2")] // 2 in 10.0 = at cap
        #expect(PeerDiversity.shouldConnect(to: peer("c", "10.0.0.3"), existingPeers: existing) == false)
        #expect(PeerDiversity.shouldConnect(to: peer("d", "11.0.0.1"), existingPeers: existing) == true)
    }

    @Test("selectDiversePeers respects maxNew and the per-subnet cap")
    func selectRespectsCaps() {
        let candidates = [
            peer("a", "10.0.0.1"), peer("b", "10.0.0.2"), peer("c", "10.0.0.3"), // same subnet
            peer("d", "11.0.0.1"), peer("e", "12.0.0.1"),
        ]
        let selected = PeerDiversity.selectDiversePeers(from: candidates, existing: [], maxNew: 8)
        // At most maxPerSubnet (2) from 10.0, and no more than maxNew total.
        let from10 = selected.filter { PeerDiversity.subnet($0.host) == "v4:10.0" }
        #expect(from10.count <= PeerDiversity.maxPerSubnet)
        #expect(selected.count <= 8)
        // All three subnets are representable within the cap (2 from 10.0 + d + e = 4).
        #expect(Set(selected.map { PeerDiversity.subnet($0.host) }).count == 3)
    }

    @Test("a high key-work threshold filters out ordinary keys")
    func keyWorkFilter() {
        let candidates = [peer("00", "10.0.0.1"), peer("11", "11.0.0.1")]
        // No real key has 200 trailing-zero bits → all filtered.
        let none = PeerDiversity.selectDiversePeers(from: candidates, existing: [], maxNew: 8, minKeyWorkBits: 200)
        #expect(none.isEmpty)
        // Threshold 0 disables the gate → both eligible (distinct subnets).
        let all = PeerDiversity.selectDiversePeers(from: candidates, existing: [], maxNew: 8, minKeyWorkBits: 0)
        #expect(all.count == 2)
    }

    @Test("selectDiversePeers with a score closure prefers higher-scored peers")
    func scoreClosurePrefersHigherScored() {
        // Four candidates, each in its own netgroup (all equally diverse).
        let candidates = [
            peer("lo1", "10.0.0.1"),
            peer("lo2", "11.0.0.1"),
            peer("hi1", "12.0.0.1"),
            peer("hi2", "13.0.0.1"),
        ]
        let scores: [String: Double] = ["lo1": 0.1, "lo2": 0.2, "hi1": 0.9, "hi2": 0.8]
        // Only room for 2 → the two highest-scored must win.
        let selected = PeerDiversity.selectDiversePeers(
            from: candidates,
            existing: [],
            maxNew: 2,
            score: { scores[$0.publicKey] ?? 0 }
        )
        #expect(selected.count == 2)
        #expect(Set(selected.map { $0.publicKey }) == ["hi1", "hi2"])
    }

    @Test("findOverrepresentedPeers returns the excess beyond the cap")
    func overrepresented() {
        let peers = [
            peer("a", "10.0.0.1"), peer("b", "10.0.0.2"), peer("c", "10.0.0.3"), peer("d", "10.0.0.4"),
            peer("e", "11.0.0.1"),
        ]
        let excess = PeerDiversity.findOverrepresentedPeers(peers: peers)
        // 4 in 10.0, cap 2 → 2 excess; 11.0 is within cap → none.
        #expect(excess.count == 2)
        #expect(excess.allSatisfy { PeerDiversity.subnet($0.host) == "v4:10.0" })
    }
}
