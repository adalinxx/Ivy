# Architecture

Ivy is the network boundary beneath a node. It authenticates peers, bounds
network work, attributes accepted records, and supplies endpoint routing. It
does not interpret application state.

```text
node: consensus, chain/process authority, validation, retention, storage
  |
Ivy: authenticated sessions, routing, relay, exact byte transfer
  |
TCP / carrier route
```

## Sessions and attribution

Each process has an Ed25519 `PeerKey`. A socket begins as private pending state.
The initiator and responder sign a transcript containing both identities, fresh
nonces, the route binding, and canonical bounded metadata. The transcript yields
a session ID; the initiator's signed finish proves receipt of the responder's
hello. Only then can the socket enter authenticated endpoint or carrier state.

Every application record binds its sender, receiver, session ID, sequence, and
payload under a signature. Incoming sequences must strictly increase. Duplicate
sessions for one peer and role converge on the lexicographically smallest
session ID.

Attribution requires a valid signature from the identity being charged. Invalid
nested bytes on a relay route are ambiguous between the endpoint and carrier, so
Ivy closes the route without assigning a violation. Signed metadata is likewise
an authenticated claim, not proof of application authority.

## Endpoint routing

Overlay nodes maintain a bounded Kademlia routing table. `findNode` performs an
iterative lookup over authenticated endpoint responses. A periodic lookup for a
random target refreshes the table. Discovered keys and addresses pass local
admission and address checks before insertion.

There is no peer-exchange protocol. Pending connections and configured carriers
never enter endpoint routing. `knownPeerEndpoints` is a read-only snapshot; the
node cannot mutate Ivy's routing state directly. Pinned mode admits one endpoint
identity and does not participate in public discovery.

## Exact content selection

Content exchange transfers an explicit set of opaque entries:

```text
selection = rootCID + selected CIDs
```

The root is always requested. Additional identifiers are deduplicated and
canonicalized. Ivy neither follows links from the root nor infers the rest of a
DAG. A single-CID request and a partial-DAG request are therefore the same
operation with different selections.

The responder asks its `IvyContentSource` for that exact selection. It returns
all requested entries in one bounded response or reports unavailable. The first
complete response from an expected peer wins and is returned with `servedBy`.
Ivy checks response shape and request correlation, but treats every identifier
and byte string as opaque. A selection that cannot fit one frame must be split by
the caller; Ivy does not paginate or stream a response.

The caller must validate each identifier against its bytes, interpret links,
and store accepted data through its own CAS or `Volume` contract. Reporting a
deficient response only suppresses that peer for the root locally and briefly;
it is not a global reputation judgment.

## Provider hints

Provider discovery is a routing optimization. A hint associates a root with an
endpoint and expiry near that root's Kademlia neighborhood. Hints are bounded,
expire, and may be learned from authenticated peers or successful transfers.

A hint is not proof that the peer stores, pins, validates, or can serve the root.
It carries no canonicity, ownership, credit, or storage authority. The requester
authenticates the eventual serving session and validates the returned content at
the node/storage boundary.

## Peer messages

`peerMessage(topic:payload:)` is the generic signed envelope for node-owned
protocols. Ivy delivers it one hop and preserves authenticated sender
attribution, but assigns no meaning to either field. Chain synchronization,
parent-state continuity, spawn authorization, transaction propagation, and
block gossip belong in node protocols carried by this envelope.

## Carrier relay

Carrier identities are configured explicitly and authenticated separately from
endpoint peers. A client attempts relay fallback only through those configured
carriers. Route control is bounded and tied to the authenticated carrier session.

Once a route is ready, endpoint session records remain end-to-end signed and are
nested unchanged inside signed carrier records. The carrier can transport or
drop them, but cannot become the endpoint identity. Carriers do not enter the
Kademlia table or provider set. Authenticated close records tear down both ends
when a route expires or a participant disconnects.

## Library boundary

| Ivy owns | The node or storage layer owns |
| --- | --- |
| Session authentication and replay protection | Process authorization and chain membership |
| Bounded frames, pending work, and lookups | CID/content validation and DAG interpretation |
| Endpoint discovery and Kademlia refresh | CAS/`Volume` storage, pinning, and retention |
| Configured carrier routes | Chain/spawn state and parent-state continuity |
| Sender attribution and transport violations | Consensus, block/transaction gossip, and canonicity |
| Authenticated traffic evidence and admission hooks | Fees, credit, settlement, and economic policy |

Tally is used only for peer-global transport evidence and admission: authenticated
bytes, concrete protocol violations, pressure, and challenges. Content
availability and route outcomes stay local to Ivy; economic settlement does not
belong here.
