# Ivy

Authenticated, bounded peer transport and routing for Swift.

Ivy connects cryptographic peer identities, discovers endpoint routes, relays
through explicitly configured carriers, transfers exact selections of opaque
content, and carries signed application messages.

Ivy is deliberately not a storage or consensus system. It does not validate
CIDs, traverse DAGs, own a CAS or `Volume`, decide process authority, gossip
blocks, or implement fees and settlement.

## Mental model

```text
application
  validates content, interprets messages, chooses authority and storage
      |
      v
Ivy
  authenticates peers, bounds work, routes endpoints, attributes signed records
      |
      v
direct TCP session or configured carrier route
```

The useful rule is: **Ivy can prove who sent accepted bytes and bound how they
arrived; the application decides what those bytes mean.**

## Start and stop

```swift
import Crypto
import Ivy

let ivy = Ivy(config: IvyConfig(
    signingKey: Curve25519.Signing.PrivateKey(),
    listenPort: 4001,
    bootstrapPeers: bootstrapPeers
))

try await ivy.start()
// ...
await ivy.stop()
```

`start()` and `stop()` are ordered and restart-safe. A connection remains
private pending state until the signed session handshake completes. Only an
authenticated endpoint can enter routing, content exchange, or delegate
callbacks.

## Choose a topology

`IvyMode.overlay` participates in authenticated Kademlia discovery. It is the
default.

```swift
let publicPeer = IvyConfig(signingKey: key, mode: .overlay)
```

`IvyMode.pinned(peer:)` accepts one endpoint identity and disables public
discovery and STUN. Use it for a deliberately fixed peer relationship.

```swift
let fixedPeer = IvyConfig(
    signingKey: key,
    bootstrapPeers: [endpoint],
    mode: .pinned(peer: endpoint.publicKey)
)
```

Configured carriers are a third, separate authority role. Carrier identities
never become endpoint peers or Kademlia entries.

## Serve exact content

Register an `IvyContentSource`:

```swift
public protocol IvyContentSource: Sendable {
    func content(
        rootCID: String,
        cids: [String],
        maxDataBytes: Int
    ) async -> [ContentEntry]
}

await ivy.setContentSource(store)
```

For each request, `cids` is the complete canonical selection and includes
`rootCID`. Return every requested identifier exactly once within
`maxDataBytes`, or return an empty array. The budget is computed before the
storage call from the exact direct or relayed framing overhead, so the source
never needs to materialize an unbounded response that Ivy would later reject.

Ivy treats identifiers and bytes as opaque. The source, requester, or storage
layer validates content addresses.

## Fetch exact content

```swift
let response = await ivy.fetchContent(
    rootCID: rootCID,
    cids: selectedCIDs
)
```

The effective selection is `rootCID` plus the deduplicated selected identifiers.
Ivy does not recurse from the root. A response is either the whole exact
selection or `.empty`; it is never partial.

`servedBy` identifies the authenticated remote endpoint that supplied a network
response. It is `nil` for a local content-source result. Before storing remote
bytes, the caller must validate every identifier, interpret links, and apply its
own storage policy.

Selections must fit one fixed 4 MiB protocol frame body. The caller splits
larger work into separate meaningful selections; Ivy does not paginate a DAG it
cannot interpret.

## Discover providers

```swift
let endpoints = await ivy.discoverProviders(rootCID: rootCID)
```

Provider records are expiring routing hints, not proof of possession, pinning,
validity, or authority. A content fetch gives cached and connected hints one
bounded attempt, performs fresh discovery when needed, then may try other
connected endpoints. The serving session is authenticated independently of the
hint.

After the application proves a response deficient, it may locally suppress that
peer for the root:

```swift
await ivy.reportDeficientContent(rootCID: rootCID, servedBy: peer)
```

This is short-lived Ivy routing state, not a Tally protocol violation.

## Send application messages

```swift
let result = await ivy.sendMessage(
    to: peer,
    topic: "sync",
    payload: encodedMessage
)
```

The topic and payload are opaque to Ivy. An `.enqueued` result means the signed
record entered the local connection queue; it does not prove remote delivery or
application acceptance. Incoming messages arrive through `IvyDelegate` with an
authenticated sender identity.

## Boundary at a glance

| Ivy owns | Its caller owns |
| --- | --- |
| Peer session authentication and replay protection | Process authorization and protocol meaning |
| Connection, frame, request, waiter, route, and lookup limits | Application-level batching and backpressure policy |
| Kademlia endpoint routing and configured carriers | Chain, shard, or service topology |
| Exact opaque content transfer | CID validation, DAG interpretation, CAS/Volume storage |
| Signed sender attribution and transport evidence | Consensus, canonicity, retention, fees, and settlement |

## Documentation

- [Architecture](docs/architecture.md)
- [Correctness invariants](docs/correctness-invariants.md)

## Requirements and verification

- Swift 6
- macOS 14+, iOS 17+, tvOS 17+, watchOS 10+, or visionOS 1+
- One Ed25519 signing key per process identity

```sh
swift build
swift test
```
