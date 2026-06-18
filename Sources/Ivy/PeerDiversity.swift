import Foundation
import Tally

/// Connection-manager peer-diversity policy: subnet grouping, Sybil-resistant
/// per-subnet caps, key-work-gated candidate selection, and overrepresentation
/// detection. This is network/reputation policy and lives with the connection
/// manager; consumers pass application signals (the key-work threshold and how
/// many new peers to add) as parameters rather than the policy reaching up into
/// them.
public enum PeerDiversity: Sendable {

    public enum ConnectionType: String, Sendable {
        case inbound
        case outbound
        case blockRelayOnly
    }

    public static let maxPerSubnet: Int = 2
    public static let targetOutbound: Int = 8
    public static let targetBlockRelayOnly: Int = 2

    /// Network-group key for a host. Delegates to the shared `NetGroup` grain
    /// (IPv4 /16, IPv6 /32) so the per-subnet cap can't be bypassed via IPv6.
    public static func subnet(_ ip: String) -> String {
        NetGroup.group(ip)
    }

    public static func shouldConnect(
        to peer: PeerEndpoint,
        existingPeers: [PeerEndpoint]
    ) -> Bool {
        let targetSubnet = subnet(peer.host)
        let sameSubnet = existingPeers.filter { subnet($0.host) == targetSubnet }
        return sameSubnet.count < maxPerSubnet
    }

    /// Pick up to `maxNew` new peers that (a) clear the `minKeyWorkBits` PoW gate
    /// and (b) respect the per-subnet cap given the already-connected `existing`
    /// peers. `minKeyWorkBits == 0` disables the PoW filter (callers that don't
    /// gate on key-work). Key-work is measured with `Tally.KeyDifficulty` — the
    /// SAME measure Ivy's identify/routing gates apply — so a key that satisfies
    /// the gate is not rejected here (and vice versa).
    ///
    /// Ordering: when `score == nil`, candidates are shuffled so selection is not
    /// positionally biased (unchanged behavior). When `score` is provided (e.g. a
    /// Tally reputation lookup), candidates are ranked highest-score-first — among
    /// equally-diverse candidates the higher-scored peer is preferred — with a
    /// shuffle first so equal scores stay unbiased. The hard filters (key-work,
    /// per-subnet cap) are identical in both modes; `score` only reorders.
    public static func selectDiversePeers(
        from candidates: [PeerEndpoint],
        existing: [PeerEndpoint],
        maxNew: Int,
        minKeyWorkBits: Int = 0,
        score: ((PeerEndpoint) -> Double)? = nil
    ) -> [PeerEndpoint] {
        var selected: [PeerEndpoint] = []
        var subnetCounts: [String: Int] = [:]

        for peer in existing {
            let s = subnet(peer.host)
            subnetCounts[s, default: 0] += 1
        }

        let ordered: [PeerEndpoint]
        if let score {
            ordered = candidates.shuffled().sorted { score($0) > score($1) }
        } else {
            ordered = candidates.shuffled()
        }

        for candidate in ordered {
            guard selected.count < maxNew else { break }
            // Drop cheap/free identities before the per-subnet cap so a Sybil
            // flood of low-work keys can't crowd out honest candidates.
            if minKeyWorkBits > 0, KeyDifficulty.keyWorkBits(candidate.publicKey) < minKeyWorkBits {
                continue
            }
            let s = subnet(candidate.host)
            let currentCount = subnetCounts[s, default: 0]
            if currentCount < maxPerSubnet {
                selected.append(candidate)
                subnetCounts[s, default: 0] += 1
            }
        }

        return selected
    }

    /// Peers beyond the per-subnet cap (oldest-first kept), as candidates to drop.
    public static func findOverrepresentedPeers(
        peers: [PeerEndpoint]
    ) -> [PeerEndpoint] {
        var subnetGroups: [String: [PeerEndpoint]] = [:]
        for peer in peers {
            let s = subnet(peer.host)
            subnetGroups[s, default: []].append(peer)
        }

        var toDisconnect: [PeerEndpoint] = []
        for (_, group) in subnetGroups {
            if group.count > maxPerSubnet {
                toDisconnect.append(contentsOf: group.dropFirst(maxPerSubnet))
            }
        }
        return toDisconnect
    }
}
