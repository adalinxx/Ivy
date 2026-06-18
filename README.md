<p align="center">
  <a href="https://github.com/adalinxx/Ivy/actions/workflows/ci.yml"><img src="https://github.com/adalinxx/Ivy/actions/workflows/ci.yml/badge.svg" alt="CI/CD"></a>
  <img src="https://img.shields.io/badge/swift-6.0+-F05138?style=flat&logo=swift" alt="Swift 6.0+">
  <img src="https://img.shields.io/badge/platforms-macOS%20|%20iOS%20|%20tvOS%20|%20watchOS%20|%20visionOS-lightgrey" alt="Platforms">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/SPM-compatible-brightgreen" alt="SPM Compatible">
</p>

# Ivy

**Reputation-routed P2P storage and retrieval for content-addressed data.**

Ivy is a cooperative peer-to-peer network that replaces blind peer selection with
evidence-based trust. Every routing decision — which peer to query, which connection to
keep, who gets served under load — is informed by measured behavior: bytes relayed, latency
observed, success delivered. The result is a self-healing network where honest nodes
naturally route through honest nodes.

Ivy is standalone and host-agnostic — reputation accounting comes from its dependency
[Tally](https://github.com/adalinxx/Tally), and nothing in Ivy is chain-specific. It is
used in production by [Lattice](https://github.com/adalinxx/lattice-node) as **one
example consumer**.

---

## Why Ivy

Most P2P networks treat all peers equally: connect to anyone, serve anyone, hope for the
best. This works until it doesn't — Sybil floods poison routing tables, freeloaders consume
bandwidth without contributing, and eclipse attacks isolate honest nodes.

Ivy takes a different approach: **your routing table is a trust graph.**

- **Honest peers route through honest peers.** Queries travel through nodes that earned
  their position through direct experience, scored by [Tally](https://github.com/adalinxx/Tally).
- **Freeloaders are progressively excluded.** Under load, serving is gated on reputation
  (`tally.shouldAllow`), so the network degrades gracefully instead of collapsing.
- **Caching is incentivized.** Serving data far from your DHT zone earns more reputation
  (distance-scaled credit), naturally forming a distributed cache along well-traveled paths.
- **New peers can bootstrap.** An optional proof-of-work key floor (`minPeerKeyBits`) raises
  the cost of Sybil identity creation without requiring an existing social graph.

All data is content-addressed: a CID is the hash of its bytes, and every received
`(CID, bytes)` pair is verified (`hash(bytes) == CID`) before use.

---

## Documentation

- **[Whitepaper](docs/whitepaper.md)** — the conceptual model: identity and Sybil
  resistance, work-denominated economics, the trust/credit-line system, pinning, and
  security analysis.
- **[Architecture](docs/architecture.md)** — how it's built: the actor decomposition,
  transports, STUN-based NAT discovery, content routing (DHT forwarding, volume fetching),
  gossip, peer health, the full wire-protocol message catalog, and every config field.

---

## Quick Start

### Starting a node

```swift
import Ivy

let config = IvyConfig(
    publicKey: myPublicKey,
    listenPort: 4001,
    bootstrapPeers: [
        PeerEndpoint(publicKey: "abc...", host: "seed1.example.com", port: 4001),
    ],
    enableLocalDiscovery: true,
    signingKey: mySigningKey   // 32-byte Curve25519 key; required to sign identify/records
)

let node = Ivy(config: config)
try await node.start()
```

### Serving local content

Implement `IvyDataSource` so the node can answer requests from its local store:

```swift
final class MyStore: IvyDataSource {
    func data(for cid: String) async -> Data? { /* local lookup */ }
    func volumeData(for rootCID: String, cids: [String]) async -> [(cid: String, data: Data)] { /* … */ }
    func hasVolume(rootCID: String) async -> Bool { /* … */ }
}

await node.setDataSource(MyStore())
```

### Publishing and fetching

```swift
// Announce a CID you hold; peers pull it via DHT forwarding.
await node.announceBlock(cid: blockCID)

// Announce that you pin a volume root to the peers nearest its hash.
await node.publishPinAnnounce(rootCID: rootCID, expiry: expiry, fee: 0)

// Fetch a volume by root CID (local data source first, then the network).
let volume = await node.fetchVolume(rootCID: rootCID)        // [String: Data]

// Fetch specific child CIDs under a root.
let blocks = await node.fetchVolume(rootCID: rootCID, childCIDs: childCIDs)
```

### Event handling

```swift
final class MyHandler: IvyDelegate {
    func ivy(_ ivy: Ivy, didConnect peer: PeerID) {
        print("Connected to \(peer.publicKey.prefix(16))…")
    }
    func ivy(_ ivy: Ivy, didReceiveBlockAnnouncement cid: String, from peer: PeerID) {
        Task { _ = await ivy.get(cid: cid) }
    }
}

await node.delegate = MyHandler()
```

> `delegate` and `dataSource` are actor-isolated `weak` properties: assign the delegate with
> `await node.delegate = …`, and set the data source via `await node.setDataSource(_:)`.

### Inspecting network state

```swift
let peers   = await node.connectedPeers
let count   = await node.directPeerCount
let rep     = node.tally.reputation(for: somePeer)
let closest = node.router.closestPeers(to: targetHash, count: 10)
```

---

## Wire Protocol

Binary, length-prefixed messages over TCP (SwiftNIO):

```
┌──────────────────────┬──────────────┬────────────────────┐
│ 4 bytes: length      │ 1 byte: tag  │ variable: payload   │
│ (big-endian uint32)  │              │                     │
└──────────────────────┴──────────────┴────────────────────┘
```

Selected message types (full catalog in [docs/architecture.md](docs/architecture.md)):

| Message | Tag | Payload |
|---------|:---:|---------|
| `ping` / `pong` | 0 / 1 | `uint64` nonce |
| `block` | 3 | CID + data |
| `dontHave` | 4 | CID |
| `findNode` | 5 | target hash + fee + nonce |
| `neighbors` | 6 | array of (key, host, port) + nonce |
| `announceBlock` | 7 | CID |
| `identify` | 8 | publicKey + observed addr + listen addrs + chain ports + signature |
| `spawnCertPresentation` | 59 | chain of spawn certificates (presented after `identify`) |
| `dhtForward` | 16 | CID + ttl |
| `want` | 26 | array of root CIDs |
| `pexRequest` / `pexResponse` | 37 / 38 | nonce (+ peers) |
| `findPins` / `pins` | 40 / 41 | CID (+ providers) |
| `pinAnnounce` / `pinStored` | 42 / 43 | rootCID + signature + fee |
| `blocks` | 50 | rootCID + array of (CID, data) |
| `wantVolume` | 53 | rootCID + child CIDs |
| `announceVolume` / `pushVolume` | 54 / 55 | rootCID + items |
| `notHave` | 58 | rootCID |

Frames are bounded by `maxFrameSize` (default 4 MB); strings are capped at 8 KB and
collection counts are bounded per message (`MessageLimits`).

---

## Configuration

Key parameters in `IvyConfig` (full table in [docs/architecture.md](docs/architecture.md)):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `listenPort` | 4001 | TCP listen port |
| `kBucketSize` | 20 | Peers per DHT bucket |
| `maxConcurrentRequests` | 6 | Parallel outbound queries |
| `requestTimeout` | 15s | Per-request deadline |
| `relayTimeout` | 5s | DHT-forward deadline |
| `defaultTTL` | 7 | Hop limit for forwarded messages |
| `enablePEX` | `true` | Peer exchange |
| `pexInterval` | 120s | PEX round interval |
| `enableLocalDiscovery` | `true` | Bonjour/mDNS on LAN (Apple platforms) |
| `minPeerKeyBits` | 0 | Required key-PoW trailing-zero bits (0 = off) |
| `maxFrameSize` | 4 MB | Max wire-frame payload |

---

## Installation

Add Ivy to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/adalinxx/Ivy.git", branch: "main"),
]
```

Then add `"Ivy"` to your target's dependencies.

### Requirements

- Swift 6.0+
- macOS 14+ / iOS 17+ / tvOS 17+ / watchOS 10+ / visionOS 1+

### Dependencies

| Package | Role |
|---------|------|
| [Tally](https://github.com/adalinxx/Tally) | Reputation accounting, rate limiting, distance-scaled credit, `PeerID` |
| [swift-cid](https://github.com/swift-libp2p/swift-cid) / [swift-multihash](https://github.com/swift-libp2p/swift-multihash) | CID parsing and content-address verification |
| [SwiftNIO](https://github.com/apple/swift-nio) | Non-blocking TCP/UDP I/O |

---

## Testing

```bash
swift build
swift test
```

The GitHub Actions pipeline runs release builds, the benchmarks executable build, and the
full Swift test suite on macOS and Linux for pull requests and `main` pushes. Pushing a
`v*` tag runs the same checks and publishes a GitHub Release after both platforms pass.

---

<p align="center">
  <sub>Built by <a href="https://github.com/adalinxx">The Lattice Authors</a></sub>
</p>
