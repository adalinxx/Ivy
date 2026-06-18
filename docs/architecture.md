# Ivy Architecture

This document describes how Ivy is built. It is grounded in `Sources/Ivy/` — every
message type, config field, transport, and limit below is taken from the code. For the
conceptual model (identity, economics, trust, pinning, security) see the
[whitepaper](whitepaper.md).

## Overview

Ivy is a content-addressed P2P storage and retrieval network. One `Ivy` instance is a
single Kademlia overlay: a node with one identity (a Curve25519 public key), one routing
table (`Router`), one reputation ledger (`Tally`), and a set of peer connections. All data
on the wire is **content-addressed** — a CID is the cryptographic hash of its bytes, and
every received `(CID, bytes)` pair is verified with `hash(bytes) == CID` before use
(`ContentAddressVerifier`). Schema-aware interpretation of those bytes lives above Ivy, in
the consuming application (cashew / Lattice).

```
┌──────────────────────────────────────────────────────────────┐
│  Application (Lattice, cashew, or custom)                     │
│  IvyDataSource (serve local data)  ·  IvyDelegate (events)    │
├──────────────────────────────────────────────────────────────┤
│  Ivy actor                                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │ Façade   │ │ Routing  │ │ Content  │ │ Records          │ │
│  │ Ivy.swift│ │ +Routing │ │ +Content │ │ +Records         │ │
│  │ lifecycle│ │ DHT, PEX │ │ Exchange │ │ pin announces    │ │
│  │ connect  │ │ findNode │ │ want/    │ │ + discovery      │ │
│  │ identify │ │          │ │ volume   │ │                  │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘ │
│  Router (trust-weighted Kademlia)  ·  Tally (reputation)      │
│  PeerHealthMonitor  ·  InventorySet  ·  CreditLineLedger      │
├──────────────────────────────────────────────────────────────┤
│  Transport                                                    │
│  PeerConnection (TCP/NIO, length-prefixed frames)             │
│  LocalPeerConnection (in-process)  ·  STUNClient (UDP, NAT)   │
│  LocalDiscovery (Bonjour/mDNS, LAN)                           │
└──────────────────────────────────────────────────────────────┘
```

## Actor Decomposition

The node is one Swift `actor`, `Ivy`, split across four files so that the actor's mutable
state and message dispatch live in one place while feature areas stay readable. All
extensions share the same actor isolation; the split is organizational, not architectural.

| File | Responsibility |
|------|----------------|
| `Ivy.swift` | Façade and transport glue: lifecycle (`start`/`stop`), connection management, dialing, the identify handshake, the central `handleMessage` dispatch, sending primitives, single-CID block fetch, local-peer wiring, the inbound TCP listener, and all pending-continuation bookkeeping. |
| `Ivy+Routing.swift` | DHT iterative lookup (`findNode`), Peer Exchange (PEX), and discovered-endpoint admission (`isAcceptableDiscoveredEndpoint`). |
| `Ivy+ContentExchange.swift` | DHT forwarding (`handleDHTForward`), volume-aware fetching (`want`/`blocks`, `announceVolume`/`pushVolume`), high-bandwidth push, and provider records. |
| `Ivy+Records.swift` | Pin announcements (`findPins`/`pins`/`pinAnnounce`/`pinStored`): signed-announcement storage, provider discovery, and expiry eviction. |

The actor holds all routing-adjacent mutable state directly: `connections`, the various
`pending*` continuation maps (requests, volume requests, forwards, PEX, neighbor lookups,
findPins), `providerRecords`, `pinAnnouncements`, the presented `peerSpawnCertChains`,
the gossip token buckets, and reconnect bookkeeping. Several of these are bounded
(`BoundedDictionary`, `BoundedSet`, `InventorySet`) so that an adversary cannot drive
unbounded allocation by asking for unique CIDs or flooding announcements.

## Transports

### TCP (peer transport)

The only peer-to-peer transport is TCP, built on SwiftNIO. `PeerConnection` wraps a NIO
`Channel`. Every message is a length-prefixed frame:

```
┌──────────────────────┬───────────────────────────┐
│ 4 bytes: length      │ length bytes: payload      │
│ (big-endian uint32)  │ (tag byte + fields)        │
└──────────────────────┴───────────────────────────┘
```

`MessageFrameDecoder` reassembles frames from the TCP stream, rejecting any frame whose
length is `0` or exceeds `maxFrameSize` (closing the channel). `PeerChannelHandler` feeds
decoded `Message` values into a per-connection `AsyncStream` (bounded at 256 buffered
messages, newest-wins). The actor drains that stream in `handleInbound`.

Outbound sends come in two flavors:
- `send(_:)` — `async`, awaits the channel write/flush.
- `fireAndForget(_:)` / `fireAndForgetMessage(_:)` — enqueue without awaiting, used for
  gossip and relayed responses where back-pressure is handled at a higher layer.

There is no UDP peer transport and no separate relay-circuit transport in the code. "Relay"
in Ivy means **DHT message forwarding** (see Content Routing) — a `dhtForward` hops through
intermediate peers' existing TCP connections; there is no dedicated circuit object, lifetime,
or byte cap.

### In-process transport

`LocalPeerConnection` is a paired, in-memory channel (`AsyncStream` in each direction) for
co-located services that want to talk to the node without a socket. `LocalServiceBus`
registers a named local service, creating a connection pair and registering the node side
as a `localPeer`. Local peers participate in the same message dispatch as TCP peers but
bypass the Tally send budget (they are trusted, co-located).

### Inbound connections

`startListener` binds a NIO `ServerBootstrap` on `0.0.0.0:listenPort` (backlog 256). New
channels get a `MessageFrameDecoder` + `InboundConnectionAcceptor`; the acceptor calls
`handleNewInboundChannel`, which registers the peer under a placeholder
`inbound-<UUID>` identity. The real identity is learned from the peer's `identify`
message. An inbound peer that fails to identify within 30 seconds is disconnected, as is
any inbound connection accepted when already at `tallyConfig.maxPeers` capacity.

## NAT Traversal (STUN)

Ivy's only NAT facility is STUN address discovery. `STUNClient` (a UDP `DatagramBootstrap`)
sends an RFC 5389 binding request to the first responsive server in `stunServers`
(default: `stun.l.google.com`, `stun1.l.google.com`, `stun.cloudflare.com`) and parses the
`XOR-MAPPED-ADDRESS` (or `MAPPED-ADDRESS`) attribute, with a 3-second per-server timeout.

On `start()`, the discovered `ObservedAddress` is stored as `publicAddress` and reported via
`delegate.ivy(_:didDiscoverPublicAddress:)`. It is advertised in `identify` `listenAddrs`
so peers learn the node's reachable address.

There is no AutoNAT, hole punching, or UPnP in the code. A signed `identify` authenticates
*who* sent an address claim, not whether that address is reachable — so only locally
verified STUN discovery is allowed to mutate `publicAddress`. There is no default UDP listen
port; UDP is used transiently only for outbound STUN queries.

## The Identify Handshake

Immediately after a connection is established (both directions), each side sends an
`identify` frame: its public key, the observed remote host/port, its listen addresses, its
advertised child-chain ports (`chainPorts`), and a Curve25519 signature over
`publicKey ‖ observedHost`.

`handleIdentify` enforces:
1. **Signature required.** An empty or invalid signature is rejected and the peer
   disconnected — no peer may claim a key it cannot sign for. Keys may be raw 32-byte hex
   or Multikey-prefixed (`ed01…`, 68 chars); the prefix is stripped for verification.
2. **Optional key-PoW floor.** If `minPeerKeyBits > 0`, the peer's key must have at least
   that many trailing zero bits in `SHA256(publicKey)` (`KeyDifficulty.trailingZeroBits`),
   raising the cost of Sybil routing-table poisoning. Each bit doubles expected key-gen work.
3. **Identity rebind.** Inbound peers start under a placeholder `inbound-<UUID>` ID; on a
   valid identify the connection, router entry, health tracking, and credit line all migrate
   to the real `PeerID`.

`chainPorts` advertised by a peer are stored in `peerChainPorts`, letting a node discover
the exact listen port a peer uses for a given child-chain directory without recomputing it.

## Content Routing

### Trust-weighted routing table (`Router`)

`Router` is a Kademlia table: 256 buckets indexed by the common-prefix length between the
local node's `SHA256(publicKey)` and the peer's. Bucket size is `kBucketSize` (default 20).
XOR distance over the SHA-256 hashes orders peers; `closestPeers(to:count:)` returns the
globally closest entries to a target hash or string.

Eviction is standard Kademlia: a full bucket keeps its existing live contacts; a newcomer
is dropped rather than displacing an established peer. A bucket slot is freed only by
explicit removal on liveness failure or disconnect. (Tally reputation gates *who gets
served and routed to*, via `shouldAllow`, rather than rewriting bucket membership.)

The router also provides the hashing primitives used throughout: `hash` (SHA-256),
`commonPrefixLength`, `xorDistance`, `isCloser`, and a bounded `hashCache`.

### Single-CID fetch

`get(cid:target:)` resolves one CID against a specific `target` peer. The path:
1. Try the local `IvyDataSource` first.
2. Record a request against `target`, then send `dhtForward(cid, ttl: 0)` (direct, no further
   forwarding) to the first reachable peer among the `maxConcurrentRequests` closest to the
   target's hash, and arm a `requestTimeout`.
3. A matching `block` response wakes all waiters coalesced on that CID (`pendingRequests`).

Because the request is attributed to `target`, the call records success or failure against
that peer in Tally — a peer that announces content and then fails to deliver is demoted.

### Relay-first DHT forwarding

`handleDHTForward` is the forwarding core. On receiving `dhtForward(cid, ttl)` from a peer:
- Gate on `tally.shouldAllow(peer:)` and credit capacity; otherwise reply `dontHave`.
- If the CID is in `haveSet` and the `IvyDataSource` produces the bytes, reply `block`
  (and credit the peer with distance-scaled byte accounting + relay metering).
- Else if `ttl > 0`, register the requester in `pendingForwards` and re-forward
  `dhtForward(cid, ttl-1)` to the 3 closest reachable peers (excluding the requester and
  self). When the data later arrives via a `block`, `resolveForwards` fans it back to all
  pending requesters.
- Else (`ttl == 0`, not held) fail silently — the requester has its own timeout.

`pendingForwards` is bounded globally (`maxPendingForwards = 4096`) and per-peer
(`maxPendingForwardsPerPeer = 128`), each entry self-expiring after `requestTimeout`.

### Volume fetching

A "volume" is a content-addressed bundle keyed by a root CID — the root plus the child
CIDs reachable from it. Ivy treats volumes as opaque: any peer can satisfy a root request
by returning matching `(CID, bytes)` pairs, and pending volume fetches are keyed by root
CID, never by peer.

```
Requester                                   Provider(s)
   │  want([rootCID])  or  wantVolume(rootCID, [childCIDs])
   │ ─────────────────────────────────────────►
   │                                            (IvyDataSource.volumeData)
   │  blocks(rootCID, [(cid, data), …])         │  or  notHave(rootCID)
   │ ◄─────────────────────────────────────────
   │  verify every hash(data)==cid, require root present
   │  first valid responder wins; wake coalesced waiters
```

`fetchVolume(rootCID:)` checks the local data source, then `fetchVolumeFromNetwork`, which
builds a candidate list in priority order: known providers (`providerRecords`) →
locally-stored pin announcements → DHT-discovered pinners (`findPinnersViaDHT`) → a
broadcast fallback over direct peers capped at `maxWantCandidates` (default 8). It then
sends `want`/`wantVolume` to candidates and awaits the first valid `blocks` response.
`handleBlocks` verifies each item, inserts verified CIDs into `haveSet`, records the
provider, and resolves the request; a `notHave` retires that candidate, and when all
candidates are exhausted the request resolves empty early instead of waiting for timeout.

The responder side, `handleWant`, serves only volumes it actually holds (the root must be
present) and trims the response so the serialized `blocks` frame stays under `maxFrameSize`
(`budgetedWantItems`), prioritizing the root CID. Fetch requests coalesce: concurrent
callers for the same root join one in-flight request (capped at `maxWaitersPerPendingCID`).

## Gossip and Announcements

### Block announcements

`announceBlock(cid:)` inserts the CID into `haveSet` and broadcasts `announceBlock(cid)` to
all connected peers. On receiving an announcement, `handleMessage` (for `.announceBlock`):
- Rate-limits per-peer relay via a token bucket (`admitGossipRelay`, capacity 200, refill
  50/s) so one peer cannot drive unbounded broadcast amplification.
- If the CID is new, marks it in `haveSet`, fires a `dhtForward(cid, ttl: 0)` back to the
  announcer to pull the data, and re-broadcasts the announcement to other peers.
- Notifies `delegate.ivy(_:didReceiveBlockAnnouncement:from:)`.

### Volume announcements and push

The `announceVolume` and `pushVolume` frames are gossip-relay paths handled on receipt:
`handleAnnounceVolume` records the sender as a provider, dedups by root, re-broadcasts the
lightweight `announceVolume(rootCID, childCIDs, totalSize)` to other peers, and notifies
`delegate.ivy(_:didReceiveVolumeAnnouncement:…)`; `handlePushVolume` additionally verifies
every `(CID, bytes)` pair (requiring the root present), inserts verified CIDs into `haveSet`,
credits the sender, and then re-broadcasts the announcement. The node does not itself
originate proactive volume pushes — it forwards what it receives — and content availability
is otherwise driven by pin announcements (`pinAnnounce`/`findPins`) and the fetch path.

### Peer exchange (PEX)

When `enablePEX` is set, `startPEX` runs a periodic loop (first round after 30s, then every
`pexInterval`, default 120s). Each round picks a random connected peer and sends
`pexRequest(nonce)`; the peer answers `pexResponse(nonce, peers)` with up to `pexMaxPeers`
(default 16) endpoints drawn from the closest entries to the requester's hash. Discovered
endpoints are admitted through `isAcceptableDiscoveredEndpoint` (non-empty key, routable
host/port, not self, optional key-PoW floor) and then dialed.

PEX responses are only accepted for a nonce we actually issued; unsolicited responses are
logged and dropped, and a response whose endpoints don't all pass admission demotes the
sender in Tally.

## Peer Connectivity Lifecycle

### Dialing and diversity

`connect(to:)` reserves the dial (`reserveOutgoingDial`), which enforces **/16 subnet
diversity**: at most 2 connections per /16 (first two host octets) across active and
in-progress dials, mitigating eclipse attacks. On success the peer is added to the router,
a credit line is established, health tracking starts, the inbound loop launches, and an
`identify` is sent.

### Reconnection

When a non-inbound connection drops while the node is running and the disconnect was not
intentional, `scheduleReconnect` retries with exponential backoff: base 500ms, doubling per
attempt (shift capped at 10), capped at 30s, plus up to 250ms jitter. `disconnect(peer)`
marks the peer intentionally disconnected (suppressing reconnect), cancels pending work,
removes it from the router, and notifies the delegate.

### Peer health

`PeerHealthMonitor` is a separate actor. Every `keepaliveInterval` (default 60s) it pings
idle peers with a nonce; a peer is declared stale after `maxMissedPongs` (default 3) missed
pongs or `staleTimeout` (default 180s) of silence, at which point the `onStale` callback
disconnects it. Activity (any inbound message) and matching pongs reset the counters and
feed `Tally` success/failure signals.

## Identity and Reputation

### Peer identity

A `PeerID` (from Tally) is a Curve25519 public key. `Ivy.generateKey(targetDifficulty:)`
brute-forces a keypair whose hex public key has at least `targetDifficulty` trailing zero
bits — Ivy's own PoW difficulty tiers for Sybil resistance (distinct from any chain's
block target).

### Reputation (`Tally`)

All reputation accounting is delegated to the `Tally` dependency and is purely local — there
is no global reputation authority. Ivy feeds Tally `recordRequest`, `recordSent`,
`recordReceived` (with the content/peer common-prefix length for distance-scaled credit),
`recordSuccess`, and `recordFailure`, and gates serving and relaying on
`tally.shouldAllow(peer:)`. Inbound capacity, gossip-bucket sizing, and high-bandwidth peer
selection all read from Tally as well.

### Credit lines

`CreditLineLedger` (constructed with `baseThresholdMultiplier`) tracks bilateral byte-metered
credit per peer. `handleDHTForward` and the volume handlers `earnFromRelay` /
`chargeForRelay`, and `hasCreditCapacity` can refuse to relay for a peer whose line needs
settlement. The cooperative defaults make this transparent; the design space (paid relay,
settlement) is covered in the [whitepaper](whitepaper.md).

## Spawn Certificates

A `SpawnCertificate` is a parent process's signed attestation that it spawned a child:
a Curve25519 signature by the issuer (parent) over the child's public key and the
chain-path scope the child serves. Certificates compose along the process tree into a
chain rooted at the top process's key (`SpawnCertificateChain`), so a grandchild can prove
spawn-tree membership to any ancestor.

A node configures its own chain (root→…→self) with `setSpawnCertChain`. Immediately after
sending `identify`, it presents that chain in a separate `spawnCertPresentation` frame, so
the peer — which has just bound the node's authenticated identity via the identify signature
— can verify the chain against *its own* `trustedRoot`. The presented chain is stored per
peer (`peerSpawnCertChains`, retrievable via `spawnCertChain(for:)`), and
`didReceiveSpawnCertChain` fires so a consumer can (re)classify the connection.

Verification (`SpawnCertificateChain.verify` / `verifiedScope`) returns true only when every
certificate's signature is valid, the chain composes (`cert[i].child == cert[i+1].issuer`),
`chain[0]` is issued by the verifier's `trustedRoot`, the last child is the connection's
authenticated `leaf`, no link is self-signed, and each cert's `chainPath` is a strict prefix
of the next (parents spawn children deeper in the tree). The signed payload is a
deterministic length-prefixed encoding under a dedicated domain tag (`ivy.spawnCert.v1`),
and keys are canonicalized to raw hex so `ed01`-prefixed and bare spellings verify
identically. A connection backed by a valid chain to the verifier's trusted root classifies
as **trusted** (and is bounded to its proven scope); everything else is **federated**. The
certificate carries no expiry or revocation — "revocation" is the verifier ceasing to trust
the root. Chains are bounded by `maxSpawnCertChain` (64) and `maxChainPathDepth` (255).

## Multi-Chain Deployment

A single `Ivy` instance is one overlay. In a multi-chain host like Lattice, each chain runs
its own `Ivy` overlay (its own keyspace, routing table, and peer set), and a node simply
runs one `Ivy` per chain it participates in. The cross-chain link surfaces in Ivy through
`chainPorts`/`peerChainPorts` in the identify handshake: a node advertises the listen ports
of the child chains it serves, so a peer that already serves a parent chain can be dialed
directly for a newly-discovered child chain without a fresh discovery round. The full
per-chain overlay and parent-child bootstrap model is documented in the
[whitepaper](whitepaper.md) and in the `lattice-node` docs.

## Wire Protocol

### Framing

Every message is a length-prefixed frame: a big-endian `uint32` length followed by the
payload, whose first byte is a tag. Fields are big-endian; strings and data blobs are
length-prefixed (`uint16` length for strings, capped at 8 KB; `uint32` length for data,
capped at `maxFrameSize`); counts are `uint16` and bounded per message
(`MessageLimits`). Frames exceeding `maxFrameSize` are rejected at decode time.

### Message catalog

Tags are the on-wire `Message.Tag` raw values. Direction: `→` request/outbound,
`←` response/inbound, `↔` either way / gossip. (`isKeepalive` messages — `ping`, `pong`,
`identify` — always send regardless of the Tally budget.)

| Message | Tag | Payload | Dir |
|---------|:---:|---------|:---:|
| `ping` | 0 | `uint64` nonce | ↔ |
| `pong` | 1 | `uint64` nonce | ↔ |
| `block` | 3 | CID + data | ↔ |
| `dontHave` | 4 | CID | ← |
| `findNode` | 5 | target hash + `uint64` fee + `uint64` nonce | → |
| `neighbors` | 6 | array of (key, host, port) + `uint64` nonce | ← |
| `announceBlock` | 7 | CID | ↔ |
| `identify` | 8 | publicKey + observedHost + observedPort + listenAddrs + chainPorts + signature | ↔ |
| `spawnCertPresentation` | 59 | array of spawn certificates (childPublicKey + chainPath + issuerPublicKey + signature) | ↔ |
| `dhtForward` | 16 | CID + `uint8` ttl | → |
| `want` | 26 | array of root CIDs | → |
| `pexRequest` | 37 | `uint64` nonce | → |
| `pexResponse` | 38 | nonce + array of (key, host, port) | ← |
| `findPins` | 40 | CID | → |
| `pins` | 41 | CID + array of provider public keys | ← |
| `pinAnnounce` | 42 | rootCID + publicKey + `uint64` expiry + signature + `uint64` fee | → |
| `pinStored` | 43 | rootCID | ← |
| `deliveryAck` | 46 | `uint64` requestId | ↔ |
| `peerMessage` | 49 | topic + payload | ↔ |
| `blocks` | 50 | rootCID + array of (CID, data) | ← |
| `wantVolume` | 53 | rootCID + array of child CIDs | → |
| `announceVolume` | 54 | rootCID + child CIDs + `uint64` totalSize | ↔ |
| `pushVolume` | 55 | rootCID + array of (CID, data) | ↔ |
| `notHave` | 58 | rootCID | ← |

`findNode` still carries `uint64` `fee` and `nonce` fields, and `pinAnnounce` carries a
`uint64` `fee`, all wire-reserved for the credit-line model; the current handlers default
them to zero / ignore them. (`dhtForward` and `findPins` no longer carry a fee field on the
wire.) Several historical tags are explicitly retired in the source: tag 2 (`wantBlock`,
replaced by `dhtForward(ttl:0)`), 9–12 (AutoNAT dial-back and zone-inventory messages),
13–14 (`haveVolumes`, replaced by `want`/`blocks`), 21–31 (chain-specific), 35–36 (mining
challenge), 44–45 (`feeExhausted`, `directOffer`), 47–48 (`balanceCheck`, `balanceLog`),
51 (`settlementProof`), and 56–57 (`nodeRecord`/`getNodeRecord` — the node-record
subsystem was removed).

### Limits (`MessageLimits` / `IvyConfig`)

| Limit | Value | Purpose |
|-------|-------|---------|
| `maxFrameSize` (default) | 4 MB | Bounds memory per frame / per data field |
| `maxStringLength` | 8 KB | Bounds CID, topic, host strings |
| `maxTxCIDCount` | 4096 | Bounds `want`/`wantVolume`/`announceVolume` CID lists |
| `maxTransactionCount` | 4096 | Bounds `blocks`/`pushVolume` item counts |
| `maxNeighborCount` | 256 | Bounds `neighbors`/`pins` responses |
| `maxPexPeerCount` | 64 | Bounds `pexResponse` size |
| `maxListenAddrs` | 16 | Bounds identify listen addresses |
| `maxChainPorts` | 64 | Bounds identify advertised chain ports |
| `maxSpawnCertChain` | 64 | Bounds spawn certificates in a `spawnCertPresentation` chain |

## Configuration (`IvyConfig`)

| Field | Default | Description |
|-------|---------|-------------|
| `publicKey` | — | Node identity (Curve25519 public key, hex) |
| `listenPort` | 4001 | TCP listen port |
| `bootstrapPeers` | `[]` | Peers dialed on start |
| `enableLocalDiscovery` | `true` | Bonjour/mDNS LAN discovery (Apple platforms) |
| `tallyConfig` | `.default` | Reputation configuration (incl. `maxPeers`) |
| `kBucketSize` | 20 | Kademlia bucket size |
| `maxConcurrentRequests` | 6 | Parallel outbound queries |
| `requestTimeout` | 15s | Per-request deadline |
| `relayTimeout` | 5s | DHT-forward (relay) deadline |
| `serviceType` | `_ivy._tcp` | Bonjour service type |
| `stunServers` | Google/Cloudflare | STUN servers for address discovery |
| `defaultTTL` | 7 | Hop limit for forwarded `dhtForward` |
| `healthConfig` | `.default` | Keepalive/stale thresholds |
| `enablePEX` | `true` | Peer exchange |
| `pexInterval` | 120s | PEX round interval |
| `pexMaxPeers` | 16 | Max endpoints per PEX response |
| `signingKey` | empty | Curve25519 signing key for identify/pins |
| `logger` | `NullLogger` | Diagnostic logger |
| `relayFee` | 0 | Per-hop relay fee (credit-line model) |
| `baseThresholdMultiplier` | 100 | Credit-line threshold multiplier |
| `maxFrameSize` | 4 MB | Max wire-frame payload sent/accepted |
| `maxPendingRequests` | 4096 | Cap on distinct in-flight CID/volume queries |
| `maxWaitersPerPendingCID` | 64 | Cap on coalesced waiters per CID |
| `minPeerKeyBits` | 0 | Required key-PoW trailing-zero bits (0 = off) |
| `maxWantCandidates` | 8 | Cap on broadcast `want` fallback fan-out |

## Application Interface

A consumer wires two protocols:

- **`IvyDataSource`** — supplies local content to serve: `data(for:)`, `volumeData(for:cids:)`,
  and `hasVolume(rootCID:)`. Set via `setDataSource`.
- **`IvyDelegate`** — receives events: `didConnect`/`didDisconnect`, `didReceiveBlock`,
  `didReceiveBlockAnnouncement`, `didReceiveVolumeAnnouncement`, `didReceiveMessage` (for
  `pins`/`pinStored`/`deliveryAck`/`peerMessage`/`notHave`), `didDiscoverPublicAddress`,
  `didIdentifyPeer` (a connection re-keyed to its real identity after identify), and
  `didReceiveSpawnCertChain` (a peer's spawn-cert chain was received/stored). All methods
  have default no-op implementations.

Free-form application messaging rides on `peerMessage(topic:payload:)` via `sendMessage`
(to one peer) and `broadcastMessage` (to all), delivered through `didReceiveMessage`.
