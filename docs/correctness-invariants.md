# Correctness invariants

These laws define Ivy's security and resource boundary. Authentication proves a
peer key; it never implies application authority.

## IVY-001: admission precedes input

An inbound socket reserves global and netgroup capacity before automatic reads
begin. A rejected or stale reservation cannot buffer protocol input.

## IVY-002: pending state is private

A connection is pending or authenticated as exactly one endpoint or carrier.
Pending connections are absent from routing, delegates, content exchange, and
application messages.

## IVY-003: promotion requires the complete handshake

Promotion requires a valid canonical transcript, fresh nonces, one route-bound
session ID, and the initiator's signed finish. Bounded metadata is part of the
signed transcript.

## IVY-004: application records are session-bound

Every accepted application record is signed over sender, receiver, session,
sequence, and payload. Receive sequences strictly increase, and send sequences
never wrap.

## IVY-005: duplicate sessions converge

Simultaneous sessions for one peer and role converge deterministically on the
lexicographically smallest session ID.

## IVY-006: endpoint and carrier authority are disjoint

One identity cannot simultaneously occupy endpoint and configured-carrier roles
in one Ivy instance. Carriers never enter endpoint routing or provider state.

## IVY-007: stale async work owns no future state

Lifecycle effects are tagged by run generation or operation token. After stop or
replacement, an old listener, STUN result, health callback, dial, reconnect,
route, lookup, provider query, or content fetch cannot mutate successor state.

## IVY-008: protocol and configured resources are bounded

Frames, strings, collections, metadata, connections, pending operations,
waiters, candidates, routes, routing entries, provider roots, and provider hints
have fixed protocol or validated configuration limits.

## IVY-009: one frame law applies everywhere

Every encoder, decoder, direct connection, and relay enforces the same 4 MiB
maximum frame body. Session metadata has one canonical 64 KiB maximum.

## IVY-010: content materialization is pre-budgeted

Ivy computes the exact direct or relayed response-data budget before calling the
content source. The source is never invited to materialize an unbounded response
for later rejection.

## IVY-011: content responses are exact or unavailable

A content response is correlated to its request and contains the root plus every
deduplicated selected identifier exactly once within budget. Duplicate, extra,
missing, oversized, unsolicited, or unexpected-peer output is never returned as
a partial success.

## IVY-012: identifiers and bytes remain opaque

Ivy does not traverse a DAG, validate a CID, publish a Volume, or retain content.
Local and remote selection paths enforce shape and bounds only.

## IVY-013: identical fetches coalesce across the pipeline

Concurrent equal selections share cached-provider attempts, fresh discovery,
fallback, and wire requests within a bounded waiter count. A stale leader cannot
remove or resolve a successor operation.

## IVY-014: provider records are hints

Provider state is bounded, expiring, and non-authoritative. It proves no
possession, pin, validity, ownership, canonicity, credit, or application
authority. Failure to dial locally does not turn a hint into false evidence.

## IVY-015: overlay discovery is authenticated Kademlia

Public discovery uses correlated `findNode` responses from authenticated
endpoints. Parsed address scope, mode, identity work, capacity, and netgroup
policy apply before route admission. Ivy has no peer-exchange protocol.

## IVY-016: relay preserves endpoint identity

Relay clients use only configured carrier identities. Endpoint records remain
signed end to end through the route; a carrier cannot become the endpoint or
grant endpoint routing authority.

## IVY-017: attribution follows cryptographic proof

Ivy charges a peer-global violation only after verifying that peer's signature.
Ambiguous carrier-controlled replay and unsigned malformed bytes remain
unattributed. Signed endpoint payload violations remain attributable end to end.

## IVY-018: queue acceptance is not delivery

`sendMessage` reports local enqueue state only. It does not assert remote
receipt, application acceptance, or durable delivery.

## IVY-019: application authority stays above Ivy

Process authorization, protocol meaning, content validity, storage, retention,
consensus, canonicity, gossip policy, fees, credit, and settlement are not Ivy
state.

## Verification map

| Area | Primary coverage |
| --- | --- |
| Handshake, identity, replay, metadata | `SessionProtocolTests`, `IvyTopologyTests`, `TCPIntegrationTests` |
| Inbound admission and lifecycle generations | `InboundAdmissionTests`, `KademliaConvergenceTests` |
| Frame and parser bounds | `MessageFrameDecoderBoundTests`, `MessageTests`, `ResilienceTests` |
| Exact content, coalescing, and budgets | `ContentExchangeTests`, `PendingRequestCapsTests`, `TCPIntegrationTests` |
| Provider fallback and endpoint identity | `ProviderRefreshTests`, `ProviderSuppressionTests` |
| Kademlia routing and address policy | `KademliaConvergenceTests`, `RoutingIngressHardeningTests`, `NetGroupTests` |
| Relay identity, lifecycle, and attribution | `RelayIntegrationTests`, `SessionProtocolTests` |
