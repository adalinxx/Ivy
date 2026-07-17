import Foundation

/// Network-group ("netgroup") bucketing for peer diversity.
///
/// A netgroup is a coarse address aggregate that is expensive for an attacker
/// to spread across. Per-netgroup caps make eclipse/Sybil floods costly:
///  - IPv4 is bucketed by its /16 (first two octets) — the classic Bitcoin
///    netgroup grain.
///  - IPv6 is bucketed by its /32 (first two hextets). IPv6 prefixes are cheap
///    to obtain in bulk, so we group conservatively (broadly) to deny an
///    attacker thousands of "distinct" addresses inside one allocation.
///
/// Tag prefixes (`v4:` / `v6:` / `raw:`) guarantee groups from different
/// address families can never collide.
enum NetGroup: Sendable {

    /// Coarse network-group key for a host string.
    static func group(_ host: String) -> String {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)

        // NOTE: a static AS-number override map (host/prefix → ASN) could slot
        // in here to bucket by autonomous system instead of raw prefix. Not
        // implemented — kept to a deterministic, dependency-free prefix grain.

        if let v4 = ipv4Group(trimmed) { return "v4:" + v4 }
        // IPv4-mapped / -compatible IPv6 ("::ffff:1.2.3.4", "::1.2.3.4"): the
        // meaningful network is the embedded IPv4, so group by its /16. This is
        // the form a dual-stack socket reports for an inbound IPv4 peer, so it
        // must collapse onto the same group as the bare IPv4 address.
        if trimmed.contains(":"), let mapped = embeddedMappedIPv4(trimmed),
           let v4 = ipv4Group(mapped) {
            return "v4:" + v4
        }
        if trimmed.contains(":"), let v6 = ipv6Group(trimmed) { return "v6:" + v6 }
        return "raw:" + trimmed
    }

    /// Extracts the embedded IPv4 from an IPv4-mapped ("::ffff:a.b.c.d") or
    /// IPv4-compatible ("::a.b.c.d") IPv6 literal; nil for any other input.
    static func embeddedMappedIPv4(_ host: String) -> String? {
        var s = host
        if s.hasPrefix("[") && s.hasSuffix("]") { s = String(s.dropFirst().dropLast()) }
        if let pct = s.firstIndex(of: "%") { s = String(s[s.startIndex..<pct]) }
        let lower = s.lowercased()
        guard lower.hasPrefix("::ffff:") || lower.hasPrefix("::") else { return nil }
        guard let lastColon = s.lastIndex(of: ":") else { return nil }
        let tail = String(s[s.index(after: lastColon)...])
        return tail.contains(".") ? tail : nil
    }

    /// The two hextets that an embedded trailing IPv4 ("...:1.2.3.4") occupies,
    /// so a mixed IPv6 literal still parses. Nil if not a dotted-quad.
    private static func ipv4Hextets(_ quad: String) -> [String]? {
        let parts = quad.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var bytes: [Int] = []
        for part in parts {
            guard !part.isEmpty, part.count <= 3, let v = Int(part), (0...255).contains(v) else {
                return nil
            }
            bytes.append(v)
        }
        return [String(format: "%02x%02x", bytes[0], bytes[1]),
                String(format: "%02x%02x", bytes[2], bytes[3])]
    }

    /// All four octets of a dotted-quad IPv4 address ("192.168.1.1" → [192,168,1,1]).
    /// Returns nil if `host` is not a well-formed dotted-quad. This full-precision
    /// parse lets routability classification pinpoint /24 and /32 special ranges
    /// without the coarse /16 group grain over-rejecting their real-public neighbors.
    static func ipv4Octets(_ host: String) -> [Int]? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [Int] = []
        for part in parts {
            guard !part.isEmpty, part.count <= 3, let v = Int(part), (0...255).contains(v) else {
                return nil
            }
            octets.append(v)
        }
        return octets
    }

    /// First two octets of a dotted-quad IPv4 address ("192.168.1.1" → "192.168").
    /// Returns nil if `host` is not a well-formed dotted-quad.
    private static func ipv4Group(_ host: String) -> String? {
        guard let octets = ipv4Octets(host) else { return nil }
        return "\(octets[0]).\(octets[1])"
    }

    /// The eight 16-bit hextets of an IPv6 address, fully expanded ("2001:db8::1"
    /// → [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]). Returns nil if unparseable. Exposed
    /// at full precision so routability classification can pinpoint /8, /10, /32
    /// special ranges instead of only the coarse /32 group grain.
    static func ipv6Hextets(_ host: String) -> [UInt16]? {
        var s = host
        // Strip surrounding brackets ("[::1]").
        if s.hasPrefix("[") && s.hasSuffix("]") {
            s = String(s.dropFirst().dropLast())
        }
        // Drop any zone identifier ("fe80::1%en0").
        if let pct = s.firstIndex(of: "%") {
            s = String(s[s.startIndex..<pct])
        }
        guard !s.isEmpty else { return nil }

        // Split on "::" to expand the zero-run.
        let runs = s.components(separatedBy: "::")
        guard runs.count <= 2 else { return nil }

        func hextets(_ segment: String) -> [String]? {
            guard !segment.isEmpty else { return [] }
            let groups = segment.split(separator: ":", omittingEmptySubsequences: false)
            var out: [String] = []
            for (idx, g) in groups.enumerated() {
                // A trailing embedded IPv4 ("...:1.2.3.4") occupies the final two
                // hextets; convert it so a mixed literal still parses.
                if g.contains(".") {
                    guard idx == groups.count - 1, let quad = ipv4Hextets(String(g)) else { return nil }
                    out.append(contentsOf: quad)
                    continue
                }
                guard !g.isEmpty, g.count <= 4 else { return nil }
                guard UInt16(g, radix: 16) != nil else { return nil }
                out.append(String(g))
            }
            return out
        }

        var expanded: [String]
        if runs.count == 2 {
            guard let head = hextets(runs[0]), let tail = hextets(runs[1]) else { return nil }
            let fillCount = 8 - head.count - tail.count
            guard fillCount >= 0 else { return nil }
            expanded = head + Array(repeating: "0", count: fillCount) + tail
        } else {
            guard let all = hextets(s), all.count == 8 else { return nil }
            expanded = all
        }
        guard expanded.count == 8 else { return nil }
        return expanded.map { UInt16($0, radix: 16) ?? 0 }
    }

    /// First two hextets (the /32) of an IPv6 address, normalized to four hex
    /// digits ("2001:db8::1" → "2001.0db8"). Returns nil if unparseable.
    private static func ipv6Group(_ host: String) -> String? {
        guard let h = ipv6Hextets(host) else { return nil }
        return String(format: "%04x", h[0]) + "." + String(format: "%04x", h[1])
    }
}
