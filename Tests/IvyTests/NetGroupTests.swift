import Testing
@testable import Ivy

@Suite("NetGroup bucketing")
struct NetGroupTests {

    @Test("IPv4 buckets by /16 (first two octets)")
    func ipv4Grouping() {
        #expect(NetGroup.group("192.168.1.1") == "v4:192.168")
        #expect(NetGroup.group("192.168.250.7") == "v4:192.168")
        #expect(NetGroup.group("10.0.0.1") == "v4:10.0")
        #expect(NetGroup.group("10.1.0.1") != NetGroup.group("10.0.0.1"))
    }

    @Test("two IPv6 addresses in one /32 collapse to one group")
    func ipv6Collapses() {
        let a = NetGroup.group("2001:db8::1")
        let b = NetGroup.group("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
        #expect(a == b)
        #expect(a == "v6:2001.0db8")
        // A different /32 must not collide.
        #expect(NetGroup.group("2001:db9::1") != a)
    }

    @Test("IPv6 forms (brackets, zone, full, ::) normalize consistently")
    func ipv6Forms() {
        let canonical = NetGroup.group("2001:db8::1")
        #expect(NetGroup.group("[2001:db8::1]") == canonical)
        #expect(NetGroup.group("2001:db8::1%en0") == canonical)
        #expect(NetGroup.group("2001:0db8:0000:0000:0000:0000:0000:0001") == canonical)
        #expect(NetGroup.group("::1") == "v6:0000.0000")
    }

    @Test("IPv4-mapped IPv6 (::ffff:) groups by the embedded IPv4 /16")
    func ipv4MappedIPv6() {
        // A dual-stack socket reports an inbound IPv4 peer as ::ffff:a.b.c.d — it
        // must collapse onto the SAME group as the bare IPv4, else it bypasses
        // the netgroup cap.
        #expect(NetGroup.group("::ffff:1.2.3.4") == "v4:1.2")
        #expect(NetGroup.group("::ffff:1.2.3.4") == NetGroup.group("1.2.3.4"))
        #expect(NetGroup.group("::ffff:1.2.99.4") == "v4:1.2")      // same /16 collapses
        #expect(NetGroup.group("::FFFF:1.2.3.4") == "v4:1.2")        // case-insensitive
        #expect(NetGroup.group("[::ffff:1.2.3.4]") == "v4:1.2")      // bracketed
        #expect(NetGroup.group("::ffff:0102:0304") == "v4:1.2")
        #expect(NetGroup.group("::ffff:0102:0304") == NetGroup.group("1.2.3.4"))
        // A genuine IPv6 with a trailing embedded IPv4 still groups by its /32.
        #expect(NetGroup.group("2001:db8::1.2.3.4") == "v6:2001.0db8")
    }

    @Test("IPv4 and IPv6 groups never collide")
    func familiesDoNotCollide() {
        // No v4 group can equal a v6 group due to tag prefixes.
        let v4 = NetGroup.group("0.0.0.1")
        let v6 = NetGroup.group("::1")
        #expect(v4.hasPrefix("v4:"))
        #expect(v6.hasPrefix("v6:"))
        #expect(v4 != v6)
    }

    @Test("malformed hosts fall back to their own raw group")
    func malformedFallsBack() {
        #expect(NetGroup.group("not-an-ip") == "raw:not-an-ip")
        #expect(NetGroup.group("999.1.1.1") == "raw:999.1.1.1")   // octet out of range
        #expect(NetGroup.group("1.2.3") == "raw:1.2.3")            // too few octets
        #expect(NetGroup.group("2001:db8::xyz") == "raw:2001:db8::xyz") // bad hex
        // Two distinct malformed hosts get distinct groups (no merge).
        #expect(NetGroup.group("foo") != NetGroup.group("bar"))
    }
}
