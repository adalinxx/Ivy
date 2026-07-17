# Ivy

Ivy is an authenticated, bounded, attributed transport and routing library for
Swift. It connects peer identities, discovers endpoints, relays through
configured carriers, exchanges exact content selections, and carries opaque
peer messages.

Ivy intentionally does not validate CIDs, traverse DAGs, own a CAS or `Volume`,
track chain or spawn state, gossip blocks, or implement fees, credit, or
settlement. Those are node or storage-layer concerns.

## Requirements

- Swift 6
- macOS 14+, iOS 17+, tvOS 17+, watchOS 10+, or visionOS 1+
- An Ed25519 signing key for each process

## Start a peer

```swift
import Crypto
import Ivy

let ivy = Ivy(config: IvyConfig(
    signingKey: Curve25519.Signing.PrivateKey(),
    listenPort: 4001,
    bootstrapPeers: bootstrapPeers
))

try await ivy.start()
```

An endpoint becomes visible only after session authentication. Application
records are signed, bound to that session, and replay-protected.

## Request content

```swift
let response = await ivy.fetchContent(
    rootCID: root,
    cids: selectedCIDs
)
```

The selection is exactly `root` plus the selected opaque identifiers. Ivy does
not recursively expand the root. A successful response contains every requested
entry and identifies the authenticated serving peer; otherwise it is empty. The
caller validates identifiers and bytes, then decides what to retain or store.

Implement `IvyContentSource` and register it with `setContentSource(_:)` to serve
the same exact-selection contract. Ivy passes the exact aggregate data budget
that can fit the selection in one authenticated protocol frame.

## Send node messages

```swift
let result = await ivy.sendMessage(
    to: peerID,
    topic: "consensus",
    payload: encodedNodeMessage
)
```

`peerMessage` is a signed, one-hop envelope. Ivy does not interpret its topic or
payload. `enqueued` reports local queue acceptance, not remote delivery.

## Design

- [Architecture](docs/architecture.md)
- [Correctness invariants](docs/correctness-invariants.md)

```sh
swift build
swift test
```
