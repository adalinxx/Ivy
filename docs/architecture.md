# Architecture

Ivy is the authenticated network boundary beneath an application. It turns an
untrusted byte stream into bounded records attributed to cryptographic peer
identities. It does not decide whether an identity is authorized to act for an
application.

```text
application policy
  authority | validation | storage | protocol semantics
                         |
                         v
Ivy actor
  lifecycle | sessions | admission | routing | content | relay
                         |
                         v
SwiftNIO channels
  direct TCP or configured carrier transport
```

## Connection state machine

```text
socket
  |
  | reserve global and netgroup capacity before reading
  v
pending
  |
  | signed transcript + route-bound finish
  v
authenticated endpoint OR authenticated carrier
  |
  | close, timeout, policy denial, or stop
  v
closed
```

Inbound capacity is reserved synchronously when a channel becomes active.
Automatic reads remain disabled until actor admission accepts that reservation.
This prevents a connection flood from buffering arbitrary input while waiting
for actor scheduling.

Pending sockets are private. They cannot enter routing, call delegates, serve
content, carry application messages, or consume authenticated peer identity.

## Sessions and identity

Each process owns an Ed25519 `PeerKey`. Initiator and responder sign a canonical
handshake transcript containing both identities, fresh nonces, route binding,
and bounded metadata. The transcript derives one session ID. The initiator's
signed finish proves receipt of the responder's hello before promotion.

Every application record binds the sender, receiver, session ID, sequence, and
payload under a signature. Receive sequences strictly increase; send sequences
cannot wrap. Simultaneous direct cross-dials for the same peer and role converge
on the lexicographically smaller session ID.

Endpoint and carrier identities are separate roles. Configuration rejects role
collisions, including the local identity, pinned identity, bootstrap endpoints,
and configured carriers.

Authentication proves control of a key. Process authorization, membership, and
scope remain application policy.

## Restart-safe lifecycle

Lifecycle operations are serialized, so overlapping `start`, `stop`, and
`start` calls take effect in call order. Each run has a monotonically increasing
generation. Listener work, STUN, health checks, routing refresh, dials,
reconnects, relay setup, provider queries, and content fetch leaders are tagged
with their owning generation or token.

`stop()` invalidates the generation, closes channels, clears pending work, and
resumes waiters. A completion from an older run cannot remove, publish, or
replace state owned by a newer run.

## Bounded work

Ivy applies limits before or at each allocation boundary:

| Resource | Bound |
| --- | --- |
| Frame body | Fixed protocol maximum of 4 MiB |
| Session metadata | Canonical encoding up to 64 KiB |
| Strings and collections | Per-field protocol limits |
| Connections | Global and network-group admission limits |
| Requests and provider queries | Configured pending-operation limits |
| Identical-request followers | Configured waiter limit |
| Content fan-out | Configured candidate limit |
| Routing, provider roots, and hints | Kademlia or fixed local limits |
| Relay routes | Global and per-peer limits plus idle expiry |

The fixed frame law is not negotiated. Every direct peer and carrier therefore
rejects the same oversized body. For content serving, Ivy subtracts exact
encoding and route overhead before asking storage to materialize bytes.

Tally provides a second admission layer for authenticated application work:
raw traffic, concrete protocol violations, global pressure, and challenges.
Rate denial is not itself recorded as a violation.

## Endpoint routing

Overlay mode maintains a bounded Kademlia table. Iterative `findNode` queries
only authenticated endpoint sessions, correlates responses by nonce, and admits
new endpoints after identity, address, mode, key-work, connection, and netgroup
checks. A random periodic lookup refreshes the table.

Address policy is derived from parsed address bits. Equivalent IPv4 and
IPv4-mapped IPv6 spellings therefore receive the same scope, SSRF, and netgroup
classification. Private discovery is enabled only when the local process
explicitly advertises a private address for LAN use.

There is no peer-exchange protocol. Bootstrap peers and configured carriers are
configuration, pending connections are not routes, and `knownPeerEndpoints` is
a read-only snapshot. Pinned mode accepts one endpoint identity and does not
participate in public discovery.

## Exact content transfer

A request names one explicit opaque selection:

```text
selection = rootCID + deduplicated selected identifiers
```

The root is always included. Ivy neither follows root links nor infers the rest
of a DAG. A single object, partial DAG, and complete application object are the
same transport operation with different caller-selected identifiers.

Before invoking `IvyContentSource`, Ivy computes the exact aggregate byte budget
remaining in one direct or relayed response frame. The source must return every
selected entry exactly once within that budget. Duplicate, extra, missing, and
oversized output becomes `contentUnavailable`; partial data is never published
to the requester.

Local and network fetches enforce the same selection contract. Identical callers
coalesce across the complete provider-search pipeline, not merely one wire
attempt. The first complete response from an expected authenticated endpoint
wins and carries `servedBy`. Ivy validates request correlation and response
shape, but not content addresses.

Selections larger than one frame are caller work. Streaming or pagination would
require application-aware boundaries that Ivy does not possess.

## Provider discovery

A provider hint associates a root with a peer, optional endpoint, and expiry near
that root's Kademlia neighborhood. Hints are bounded and may be learned from
authenticated announcements or successful transfers.

Hints are evidence about where to try, not what is true. They grant no storage,
pinning, ownership, canonicity, credit, or authority. A fetch uses this bounded
fallback order:

1. Try cached endpoints and connected hinted peers.
2. Query the DHT for fresh endpoints and try previously unattempted peers.
3. Fall back to other connected endpoints within the candidate limit.

Failed local dialing does not erase the hint. Distinct endpoints for the same
identity remain distinct until a concrete failed endpoint is excluded, so a bad
address cannot suppress a healthy replacement address.

The application may report cryptographically invalid or otherwise deficient
content after its own validation. Ivy then suppresses that peer only for that
root and only briefly. Availability remains local routing state, not peer-global
reputation.

## Peer messages

`peerMessage(topic:payload:)` is the generic signed envelope for caller-owned
protocols. Ivy delivers one hop and preserves authenticated sender attribution,
but assigns no meaning to the topic or payload. Queue acceptance is not delivery
acknowledgement.

Synchronization, application gossip, continuity proofs, and transaction or
block semantics belong in protocols carried by this envelope.

## Carrier relay

Carrier endpoints are configured explicitly and authenticate in the carrier
role. A client attempts relay fallback only through those carriers. Route setup,
continuations, byte rate, idle time, and per-peer route count are bounded and
tied to the authenticated carrier session.

After setup, endpoint session records remain signed end to end and are nested
unchanged inside carrier records. The carrier can forward, replay, reorder, or
drop nested records, but cannot sign as the endpoint. Carriers never enter the
Kademlia table or provider set. Authenticated close records tear down both route
ends.

## Attribution

Ivy assigns peer-global evidence only after verifying the signature of the
identity being charged.

- Unsigned or unverifiable bytes are unattributed.
- A signed malformed endpoint payload is attributable to that endpoint, even
  through a relay.
- A direct endpoint's signed transport violation is attributable to that
  endpoint.
- A replay or sequence failure on a relayed path is not automatically charged
  to the endpoint because the carrier can replay a valid signed record.
- Local queue pressure, dial failure, timeout, and content unavailability are
  not protocol violations.

This keeps Tally limited to peer-global authenticated evidence. Route health,
provider availability, and endpoint retry state remain inside Ivy.

## Ownership boundary

| Ivy owns | The caller or storage layer owns |
| --- | --- |
| Session authentication and replay protection | Process authorization and membership |
| Bounded frames, collections, admission, and pending work | Application batching and semantic limits |
| Endpoint discovery and route maintenance | Service, chain, or shard topology |
| Configured carrier routes | Carrier business or deployment policy |
| Exact opaque selection transfer | CID validation and DAG interpretation |
| Provider hints and local deficiency suppression | CAS/Volume publication, pinning, and retention |
| Signed sender attribution and transport evidence | Consensus, canonicity, fees, credit, and settlement |

See [correctness-invariants.md](correctness-invariants.md) for the laws used to
review changes at these boundaries.
