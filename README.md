# Ivy

Authenticated, bounded peer transport and routing for Swift.

Ivy proves which peer sent an accepted record and bounds the work needed to
receive it. The caller decides what the record means.

Ivy does not validate CIDs, traverse DAGs, store content, authorize processes,
run consensus, or implement settlement.

## Start

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

A socket remains private until its signed session handshake completes.
`start()` and `stop()` are ordered and restart-safe.
Sessions authenticate and replay-protect cleartext records; Ivy does not provide
encryption or forward secrecy.

`IvyMode.overlay` uses authenticated Kademlia discovery. `.pinned(peer:)`
accepts one endpoint identity and disables public discovery. Configured carriers
govern outbound relay initiation; inbound offers grant transport only and never
turn a carrier into an endpoint peer.

## Network roles

Ivy supplies three small primitives that applications compose:

- `broadcastMessage` announces gossip to the currently connected peers.
- `sendMessage` carries directed sync requests and responses.
- `fetchContent` retrieves one exact content selection from available providers.

The caller defines gossip IDs, deduplication, forwarding, sync order, and CID
validation. Ivy authenticates the sender, bounds each operation, and keeps these
application protocols independent.

## Exact content

Register a source:

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

`cids` is the complete canonical selection and includes `rootCID`. Return every
entry exactly once within `maxDataBytes`, or return `[]`.

Fetch the same explicit selection:

```swift
let response = await ivy.fetchContent(
    rootCID: rootCID,
    cids: selectedCIDs
)
```

Ivy returns the whole selection or `.empty`; it never follows links or returns a
partial success. `servedBy` identifies the authenticated remote endpoint and is
`nil` for a local result. The caller validates identifiers and bytes before
storage.

Selections must fit one fixed 4 MiB frame body. Larger application objects must
be split by caller-defined boundaries.

Provider records are expiring routing hints, not proof of possession, validity,
pinning, or authority.

## Application messages

```swift
let result = await ivy.sendMessage(
    to: peer,
    topic: "sync",
    payload: encodedMessage
)
```

Ivy delivers incoming messages through `IvyDelegate` with an authenticated
sender. `.enqueued` means local queue acceptance, not remote delivery.

Each authenticated peer is an independent availability zone. Unavailable or
caller-reported deficient content changes provider selection for that root; it
does not disconnect the peer or prevent messages and other roots from using the
same session. Tally reduces admission for weak evidence or verified transport
violations under pressure, without turning local service history into a ban.

## Boundary

| Ivy owns | The caller owns |
| --- | --- |
| Session authentication and replay protection | Process authorization and protocol meaning |
| Connection, frame, request, route, and lookup limits | Application batching and policy |
| Endpoint routing and configured carriers | Service or chain topology |
| Exact opaque content transfer | CID validation, DAG interpretation, and storage |
| Signed sender attribution | Consensus, retention, fees, and settlement |

## Documentation

- [Architecture](docs/architecture.md)
- [Correctness invariants](docs/correctness-invariants.md)

## Requirements

- Swift 6
- macOS 14+, iOS 17+, tvOS 17+, watchOS 10+, or visionOS 1+
- One Ed25519 signing key per process identity

```sh
swift build
swift test
```
