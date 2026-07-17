# Architecture

Ivy turns an untrusted byte stream into bounded records attributed to peer keys.
Authentication proves key control, not application authority.

```text
caller: authority, validation, storage, protocol meaning
                         |
Ivy: admission, sessions, routing, content, relay
                         |
SwiftNIO: direct TCP or configured carrier
```

## Connections

Inbound capacity is reserved by global and netgroup limits before automatic
reads begin. Rejected sockets cannot buffer protocol input while waiting for the
Ivy actor.

A pending socket is absent from routing, delegates, content, and application
messages. Promotion requires a signed transcript over both identities, fresh
nonces, route binding, and bounded metadata, followed by the initiator's signed
finish.

Application records bind sender, receiver, session ID, sequence, and payload.
Receive sequences strictly increase. Simultaneous sessions for one peer and
role converge on the smaller session ID.

## Bounds

- Every encoder, decoder, direct peer, and relay uses one 4 MiB frame-body cap.
- One node-wide byte budget covers partial headers, declared frame bodies,
  relayed records, and queued records. Its default is 64 MiB; exhaustion closes
  the affected connection without peer blame.
- Canonical session metadata is limited to 64 KiB.
- Strings, collections, connections, netgroups, pending requests, waiters,
  candidates, routing entries, provider hints, and relay routes are bounded.
- Content framing overhead is subtracted before storage materializes bytes.

Tally gates authenticated application work using peer-global traffic evidence
and pressure. Local rate denial is not a protocol violation.

## Routing and content

Overlay mode uses correlated `findNode` responses from authenticated Kademlia
peers. Address scope, mode, identity work, connection capacity, and netgroup
policy apply before admission. Referrals are lookup candidates, not routing
entries; only a successful authenticated session promotes an endpoint into
routing. A referral must use a globally routable IP. A private or loopback
self-advertisement is usable only when it exactly matches the observed socket
address. Pinned mode admits one endpoint identity. Ivy has no peer-exchange
protocol.

A content request is exactly:

```text
rootCID + deduplicated selected identifiers
```

The source must return that set exactly once within the direct or relayed byte
budget. Duplicate, extra, missing, oversized, unsolicited, and unexpected-peer
responses are unavailable, never partial.

Equal requests coalesce across cached providers, fresh discovery, fallback, and
the wire request. Provider hints are bounded and expiring. A failed local dial
does not erase a hint, and a failed address does not suppress a healthy address
for the same identity.

The caller may report content deficient after validation. Ivy then suppresses
that peer briefly for that root; it does not create peer-global blame.

## Relay and attribution

Only configured carriers may relay. Endpoint records remain signed end to end,
so a carrier cannot become the endpoint or enter endpoint routing.

Ivy attributes a violation only after verifying the charged peer's signature.
Signed malformed endpoint payloads remain attributable through relay. Unsigned
bytes are unattributed, and relay-controlled replay or sequence failure is
ambiguous because a carrier can replay a valid record.

Timeouts, failed dials, unavailable content, and local queue pressure remain
route or service state, not protocol violations.

## Lifecycle

Lifecycle calls execute in order. Each run has a generation; dials, reconnects,
lookups, routes, provider queries, and content leaders also carry generations or
tokens. `stop()` invalidates them and resumes waiters, so old completions cannot
mutate a newer run. A callback retains its exact authenticated session and
cannot send a reply through a replacement session for the same peer.

See [correctness-invariants.md](correctness-invariants.md) for the normative
review laws.
