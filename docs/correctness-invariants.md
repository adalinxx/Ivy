# Correctness invariants

1. A connection is pending or authenticated as exactly one endpoint or carrier.
2. Pending connections are invisible to routing, delegates, content exchange,
   and application messages.
3. Promotion requires a valid signed transcript and finish for one route-bound
   session ID.
4. Duplicate sessions for one peer and role converge on the smallest session ID.
5. Endpoint and configured-carrier identities are disjoint authority domains.
6. Every application record is signed and session-bound; receive sequences
   strictly increase and send sequences never wrap.
7. Frames, collections, pending requests, waiters, routes, and routing state are
   bounded by configuration or protocol limits.
8. Attribution never crosses an unverified identity boundary.
9. `sendMessage` reports local enqueue state, never delivery.
10. A content response is correlated to its request and contains the root plus
    every selected opaque identifier, or the request is unavailable.
11. Ivy never traverses a DAG, validates a CID, or stores content.
12. Provider records are expiring, bounded, non-authoritative routing hints.
13. Overlay discovery uses authenticated Kademlia `findNode`; there is no PEX.
14. Client relay fallback uses configured carriers, while endpoint records remain
    end-to-end authenticated through the route.
15. Chain authority, spawn state, consensus, storage, retention, gossip, fees,
    credit, and settlement remain above the Ivy boundary.
