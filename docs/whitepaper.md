# Ivy: A Cooperative Peer-to-Peer Data Storage and Retrieval Network

*The Lattice Authors*

## Abstract

Ivy is a peer-to-peer protocol for cooperative data storage and retrieval. It overlays a content-addressed storage interface and a per-chain Kademlia routing fabric on top of bilateral, byte-denominated credit lines and a reputation layer. Peer identities carry a proof-of-work cost — the **difficulty** of an identity key is the number of trailing zero bits in `SHA256(publicKey)` — which gives Sybil resistance a price floor without a central authority. Every connected peer pair maintains a credit line whose balance moves as the two peers serve each other data; a peer that consistently consumes more than it provides eventually exhausts its capacity and is throttled. Reputation, credit accounting, and identity difficulty are provided by the **Tally** library; Ivy implements the overlay (DHT routing, content exchange, pin announcements, node records) that consumes them.

This paper describes the protocol as implemented. Mechanisms that exist as design intent but are not yet wired into the node are marked **[design intent]**.

---

## 1. Introduction

Decentralized storage networks must be **Sybil-resistant**, **low-latency**, and **economically sustainable** without imposing per-transaction coordination overhead. Existing approaches typically sacrifice one: IPFS/BitTorrent offer free retrieval but weak Sybil resistance and no persistence guarantees; Filecoin/Arweave settle every storage deal on-chain, paying latency and fee overhead; CDNs are low-latency but centrally trusted.

Ivy takes a different position. Routing is standard Kademlia, partitioned per chain so that a node only carries peers relevant to the chains it serves. Cooperation is the default: peers connect freely, serve data, and build reputation through successful exchanges. Underneath that cooperative behavior sits a bilateral credit ledger that meters each relationship by the bytes exchanged, so a node can detect and throttle a peer that free-rides. Identity is anchored to proof-of-work on the public key, making large-scale Sybil populations expensive. The result is an overlay that behaves like a cooperative PEX network in the common case but has the accounting machinery to enforce fairness and, in future, to charge for data.

Ivy is designed as the data and discovery layer beneath a multi-chain blockchain host (Lattice is the running example), but nothing in the core protocol is blockchain-specific: a "chain" here is any path-identified routing partition with its own keyspace, DHT, and peer set.

---

## 2. Identity and Sybil Resistance

### 2.1 Proof-of-Work Key Generation

Every peer is identified by a Curve25519 public key. The **difficulty** of a key is the number of trailing zero bits in `SHA256(publicKey)`:

```
difficulty(pk) = trailingZeroBits(SHA256(pk))
```

Each additional trailing zero bit doubles the expected number of candidate keys a peer must generate to find a qualifying key. A peer generates random keypairs, hashes each public key, and keeps the first that meets its target. A key with 24 trailing zero bits required roughly 2^24 (~16 million) candidates — meaningful work on commodity hardware but not a barrier to legitimate participation; 32+ bits represents substantial investment.

This is Ivy's own identity-difficulty concept — proof-of-work on the *peer key*. It is unrelated to any blockchain mining target. The computation is implemented in Tally's `KeyDifficulty`.

### 2.2 Base Trust

Key difficulty maps to a **base trust** in `[0, 1]` that seeds a new peer's initial credit threshold before any interaction history exists (`KeyDifficulty.baseTrust`):

```
baseTrust(pk) = clamp((difficulty(pk) - minDifficulty) / (maxDifficulty - minDifficulty), 0, 1)
```

with `minDifficulty` and `maxDifficulty` configurable (defaults 0 and 32). Harder keys start with a larger credit line; low-difficulty keys still participate, just with a smaller initial allowance they must grow through reliable service. The same `difficulty(pk)` value also feeds the reputation score (Section 6) as a baseline floor and gates peer admission via a configurable minimum (`minPeerKeyBits`): discovered endpoints below the floor are rejected before they ever enter the routing table.

### 2.3 Difficulty Tiers

| Tier        | Trailing Zero Bits | Approx. Candidate Keys |
|-------------|--------------------|------------------------|
| None        | 0–7                | Trivial                |
| Low         | 8–15               | ~256                   |
| Medium      | 16–23              | ~65K                   |
| High        | 24–31              | ~16M                   |
| Exceptional | 32+                | ~4B                    |

### 2.4 Bootstrapping a New Peer

A new peer connects to a bootstrap node, establishes a credit line at its base-trust threshold, and runs `findNode(self)` lookups to discover and connect to nearby peers (Section 4.2). After O(log n) rounds it has a populated routing table and is reachable. Even a zero-difficulty key receives a small non-zero threshold (the ledger clamps the minimum to 1), enough for trial interactions; a peer expecting serious participation invests in key generation up front to arrive with a larger allowance.

---

## 3. Content-Addressed Storage Interface

Ivy stores **volumes**: a volume is a root CID and the set of content-addressed blocks reachable from it, each block's CID being the hash of its contents. Applications fetch volumes through the node; the node resolves them from a three-tier cache (memory, disk, network) supplied by the host, falling back to the Ivy network only for blocks not held locally.

The wire-level fetch primitives are:

| Operation         | Message(s)                       | Meaning                                              |
|-------------------|----------------------------------|------------------------------------------------------|
| Want a volume     | `want(rootCIDs)`                 | "Send me the blocks of these roots."                 |
| Want named blocks | `wantVolume(rootCID, cids)`      | "Send me these specific child CIDs under this root." |
| Response          | `blocks(rootCID, items)`         | The requested `(cid, data)` pairs.                   |
| Negative response | `notHave(rootCID)`               | "I cannot serve this root."                          |
| Single block      | `dhtForward(cid)` → `block`      | DHT-routed fetch of one CID (Section 4.3).           |

Every returned block is verified against its CID by the receiver (`ContentAddressVerifier`). A `blocks` response that omits the root, or contains any block whose data does not hash to its claimed CID, is rejected and recorded as a failure against the sender. This makes content self-authenticating: a peer cannot substitute garbage for requested data.

> **Selectors.** Selector-scoped (DAG-subset) retrieval is **[design intent]**: the implemented `dhtForward` carries only a CID and a TTL, and responders serve whole blocks/volumes. Pin announcements (Section 5) likewise do not carry a selector in the implemented wire format — a pinner announces that it holds a root, not which subset.

---

## 4. Routing

### 4.1 Per-Chain Kademlia Overlays

Each chain operates its own Kademlia overlay. A node's routing table for chain *X* holds K entries that participate in chain *X*, organized into XOR-distance buckets (`Router`). A single global table would be useless for a sparsely-populated child chain: if chain *X* has 50 of 10,000 nodes, almost none of K random global entries would serve it. Per-chain tables guarantee that `findPins`, block gossip, retrieval, and peer exchange for chain *X* reach actual chain-*X* participants.

A single TCP connection serves all chains two peers share. Peers advertise the chains and ports they serve in the `identify` handshake (`chainPorts`), and each node inserts the peer into every shared chain's table. One connection, many roles; routing-table slots are independent per chain; a peer's behavior on one chain informs its reputation on all shared chains (reputation is per-peer, not per-chain).

The routing table follows standard Kademlia parameters — bucket size K, lookup concurrency α, distance buckets. Eviction is **liveness-based, not reputation-based**: a full bucket keeps its existing live contacts and only frees a slot when an entry is explicitly removed for failing liveness. Reputation and the PoW floor gate *admission* (whether a discovered peer is accepted at all) and *service* (whether a request is answered), not bucket displacement.

### 4.2 findNode

To locate a target hash *T*, a node queries the α closest peers it knows toward *T* with `findNode(T)`, merges the `neighbors` responses, and repeats with the newly-discovered closer peers until the candidate set stabilizes (an iterative Kademlia lookup, bounded by a K-round safety cap). Each hop returns peers sharing at least one more prefix bit with *T*, so common-prefix length grows by ≥1 per round and the target neighborhood is reached in O(log n) rounds.

### 4.3 dhtForward

`dhtForward(cid, ttl)` fetches a single block by routing toward the CID's hash. A receiving peer that holds the block returns it directly as a `block` message; otherwise, while `ttl > 0`, it forwards to its closest known peers toward the CID (decrementing TTL) and relays the eventual `block` back to the original requester. Pending forwards are bounded per-peer and globally and time out on the request timeout. If the data is never found, the request fails silently and the requester's own timeout fires.

### 4.4 Peer Exchange (PEX)

Nodes periodically pick a random connected peer and send `pexRequest`; the peer replies with `pexResponse` carrying endpoints close (in XOR distance) to the requester. Discovered endpoints are filtered (valid address, not self, PoW floor) and dialed. A response whose entries all pass the filter is a reputation success for the responder; a partially-bad response is a failure. PEX is the steady-state mechanism that keeps each chain's table populated; parent-chain bootstrap (Section 7) seeds it for a newly-discovered child chain.

---

## 5. Pinning

### 5.1 Pin Announcements

A peer that holds a volume publishes a **pin announcement** to the K peers closest to the root CID's hash:

```
pinAnnounce(rootCID, publicKey, expiry, signature, fee)
```

The announcement is signed by the pinner over `(rootCID, publicKey, expiry, fee)` (`PinAnnouncementSignature`); receivers verify the signature, that the announcing key matches the sending peer, and that the expiry is in a valid window before storing it. A node also self-records: when it publishes that it pins a CID, it becomes a valid answer to its own `findPins` for that CID. Announcements are refreshed by re-publishing before expiry and are evicted once expired (`evict`).

The `fee` field is carried and signed but is not currently charged on the wire (Section 6.3).

### 5.2 Pin Discovery

`findPins(cid)` returns `pins(cid, providers)` — the list of pinner public keys stored for that CID near its hash. Discovery yields *who* pins the root (provider keys), which the fetch path then resolves to reachable connections and queries with `want`. Discovered providers are remembered in a bounded provider cache to seed future fetches without a fresh DHT lookup.

### 5.3 Retrieval Flow

Retrieval is a single content-fetch phase backed by candidate discovery:

1. Assemble candidates: remembered providers for the root, then stored pin-announcement keys, then (if still thin) pinners discovered via `findPins`/DHT, then a capped broadcast to direct peers as a fallback.
2. Send `want(rootCID)` (or `wantVolume` for named child CIDs) to all candidates and await the first valid `blocks` response. Requests for the same root coalesce: a second caller joins the in-flight request rather than re-sending.
3. Verify every returned block's CID; the first complete, valid response wakes all coalesced waiters. `notHave` from a candidate marks it done; when all candidates are exhausted or the request times out, the fetch resolves empty.

### 5.4 Volume Announcements and Push

The protocol carries two volume-dissemination frames: a lightweight `announceVolume` (root CID, child CIDs, total size) and a full-data `pushVolume`. A node that receives either verifies the content (for `pushVolume`, every block against its CID, root required), records the sender as a provider, and gossips the announcement onward (rate-limited per peer). This builds provider coverage organically: any node that has received a volume can announce itself as a pinner, so popular content acquires nearby copies over time. Proactive origination of `pushVolume` to top-reputation peers — a BIP 152-style high-bandwidth mode that skips the announce→request round trip — is **[design intent]**: the implemented node relays the frames it receives but does not itself initiate a volume push.

### 5.5 Proof of Retrievability

Pin persistence is verified through the ordinary retrieval path. The client (or any auditor — announcements are public) periodically fetches the pinned root and checks the returned blocks against their CIDs. Success proves the pinner has the data; because content is self-authenticating, a successful retrieval cannot be faked. No separate proof protocol is needed: the storage guarantee *is* the retrieval protocol.

> **Pinning contracts** — negotiated terms (duration, replication, rate) brokered hop-by-hop between neighbors, with pinners *pulling* data via the normal retrieval path — are **[design intent]**. The implemented mechanism is the public pin announcement plus voluntary/proactive pinning above; there is no contract-negotiation message in the wire protocol.

---

## 6. Trust, Credit, and Reputation

Trust in Ivy is **local and bilateral** — there is no global trust score. Each node maintains, per peer, both a Tally reputation ledger and a credit line. Both are provided by the Tally library; Ivy drives them from its content-exchange and routing paths.

### 6.1 Reputation (Tally)

Tally computes a per-peer reputation in `[0, 1]` from decaying signals:

| Signal             | Source in Ivy                                            |
|--------------------|----------------------------------------------------------|
| Bytes sent/received| `recordSent` / `recordReceived` on each served/received block, distance-scaled by common-prefix length |
| Success / failure  | `recordSuccess` on a verified response; `recordFailure` on a CID mismatch or bad PEX entry |
| Latency            | EWMA of response times                                   |
| Challenge hardness | PoW challenges a peer has solved (`issueChallenge` / `verifyChallenge`) |
| PoW identity floor | Trailing zero bits of the peer's key, as a baseline      |

Reputation gates behavior through `shouldAllow`: every inbound request first passes a per-peer token bucket, and under bandwidth pressure the node serves only peers whose reputation clears a pressure-scaled threshold (at saturation, only high-reputation peers are served). Below pressure, service is unconditional — the cooperative default. The PoW identity floor gives a brand-new peer a non-zero baseline before any behavioral data exists, which is what makes lightweight Sybil resistance possible at first contact.

### 6.2 Bilateral Credit Lines (Tally)

Each connected peer pair has a `CreditLine` with a signed `balance`, a `sequence`, a `threshold`, and a `successfulSettlements` count. When a node serves bytes to a peer it `earnFromRelay` (balance moves in its favor); when it receives bytes it `chargeForRelay`. A peer that consistently consumes more than it provides drives the balance past the threshold (`needsSettlement`), at which point the node stops serving it new `dhtForward` requests (`hasCreditCapacity`). Symmetric traffic keeps the balance near zero and never triggers settlement — the common case for storage providers and active relays.

The threshold is seeded from base trust and grows logarithmically with successful settlements and halves on a missed one, so trust builds gradually and is lost quickly:

```
initialThreshold     = baseTrust(peer) * baseThresholdMultiplier   // min 1
recordSettlement():    balance → 0; threshold grows ~log2(settlements)
recordMissedSettlement(): threshold → threshold / 2
```

Credit is denominated in **relayed bytes**, the directly-measurable quantity the implementation accounts. (The original design framed the unit as expected SHA-256 work — "1 ivy = 2^16 hashes" — to make settlement-by-mining natural; the implemented ledger meters bytes, and the work-denominated unit is part of the settlement design intent below.)

### 6.3 Settlement — design intent

The `CreditLine` ledger exposes settlement primitives (`recordSettlement`, `recordPartialSettlement`, `recordMissedSettlement`), and the original design specified that a debtor clears its balance by **proof-of-work** — performing computation equal to the debt, optionally as merged mining against a creditor-supplied block template so the work doubles as block production for whatever PoW chain the creditor runs. The corresponding wire messages (`miningChallenge`, `miningChallengeSolution`, `settlementProof`) and the balance-reconciliation messages (`balanceCheck`, `balanceLog`, `feeExhausted`) have been **removed from the protocol**, and the node never calls the settlement methods. The implemented enforcement is throttling at the threshold, not active settlement. Per-message **fee bids** and **per-hop fee cascading** — where a `dhtForward`/`findPins` request carries a budget that each forwarder deducts and the destination keeps the remainder — are likewise **[design intent]**: the `fee` fields exist on the wire but no handler charges or deducts them. The fee economics are documented here as the intended evolution of the credit layer, not as current behavior.

---

## 7. Spawn Certificates and Multi-Chain Bootstrap

### 7.1 Spawn Certificates

A `SpawnCertificate` is a parent process's signed attestation that it spawned a child: a Curve25519 signature by the issuer (parent) over the child's public key and the chain-path scope the child serves. Certificates compose along the process tree into a chain rooted at the top process's key, so a grandchild can prove spawn-tree membership to any ancestor:

| Field            | Description                                              |
|------------------|---------------------------------------------------------|
| childPublicKey   | The spawned child's identity (Curve25519 public key)    |
| chainPath        | The chain-path scope the child was spawned to serve     |
| issuerPublicKey  | The spawning parent's identity                           |
| signature        | Curve25519 signature over the canonical payload         |

A node presents its own chain (root→…→self) in a `spawnCertPresentation` frame sent immediately after `identify`, so the peer — which has just bound the node's authenticated identity via the identify signature — can verify the chain against *its own* trusted root. Verification (`SpawnCertificateChain.verify`) accepts only when every signature is valid, the chain composes (each cert's child is the next cert's issuer), the first cert is issued by the verifier's trusted root, the last child is the connection's authenticated identity, no link is self-signed, and each cert's `chainPath` strictly prefixes the next. A connection backed by a valid chain to the verifier's trusted root classifies as **trusted** (bounded to its proven scope); everything else is **federated**. The signed payload is a deterministic length-prefixed encoding under a dedicated domain tag, and keys canonicalize to raw hex so both spellings of a key verify identically. Certificates carry no expiry; "revocation" is the verifier ceasing to trust the root.

### 7.2 Parent-Child Bootstrap

When a node discovers a new child chain (in Lattice, via a genesis action embedded in a parent block), it has no child-chain peers yet, and pin discovery on the parent chain cannot help — the parent keyspace is organized around parent peer IDs. The resolution exploits the fact that **parent-chain peers already hold the child's data**: under merged mining, every parent peer that processed the child's registration has the child genesis and subsequent blocks. Those peers become the initial entries in the node's child-chain routing table, and PEX within the child overlay grows it from there.

This is recursive: every chain bootstraps the chains it parents, the parent-child edge being the only cross-chain link. The root chain (the Nexus, in Lattice) has no special discovery role beyond being the chain every node joins.

**Reputation inheritance.** A parent-chain peer promoted into a child-chain table carries no child-chain history, but the node already holds reputation data for that peer from the parent chain. Because reputation is tracked per peer rather than per chain, that history immediately informs how the node prioritizes its initial child-chain peers, giving established peers a natural advantage.

### 7.3 Peer Sufficiency

Each chain overlay needs enough peers for mesh gossip, keyspace coverage, and reachable pinners (target ~K per chain). When a chain's table falls below a minimum, the node re-runs PEX within that overlay, re-bootstraps from parent-chain peers, and accepts inbound connections from new participants.

---

## 8. Direct Peer Messaging

Directly connected peers exchange arbitrary application messages with `peerMessage(topic, payload)` — one hop over the existing connection, outside the content-exchange path and unmetered. This is the substrate for application-level gossip:

- **Block and transaction gossip** for a host blockchain — each peer validates and relays to its own neighbors.
- **Block availability** via `announceBlock(cid)` / `announceVolume`, after which downstream nodes fetch the full data through the paid content path. Gossip of identifiers is cheap; data transfer is accounted.
- **Application signaling** of any kind.

Peer messages are not credited because they consume no DHT routing resources; abuse is bounded by the existing relationship — a peer that floods can be rate-limited (a per-peer gossip token bucket admits relayed announcements) or disconnected.

---

## 9. Security

### 9.1 Threat Model

A computationally bounded adversary controls some fraction of peers. It can: generate identities, bounded by key-difficulty cost and the admission floor; refuse to serve, earning no reputation and no credit; and flood pin announcements or gossip, bounded by per-peer rate limits and reputation-gated service. It cannot forge CIDs (collision resistance), forge Curve25519 signatures, or forge another node's record.

### 9.2 Sybil Resistance

Key difficulty puts a price on each identity, and the admission floor (`minPeerKeyBits`) rejects sub-floor keys before they enter any routing table. A fresh identity starts with a small credit threshold and a baseline reputation proportional only to its key cost; it must build behavioral reputation through reliable service before it is preferentially served under load. Thousands of medium-difficulty keys cost hours of computation, and each must independently earn its standing.

### 9.3 Eclipse Resistance

Routing-table admission is gated by the PoW floor, and discovered endpoints are validated before insertion, raising the cost of saturating a victim's table with attacker-controlled peers. Note that buckets are not displaced by reputation — they retain existing live contacts — so an attacker cannot evict an honest established peer simply by presenting higher-reputation newcomers; it can only fill genuinely empty slots, each of which costs a floor-meeting identity.

### 9.4 Free-Riding

A peer that consumes without contributing drives its credit balance to the threshold and is throttled (`hasCreditCapacity`), and under bandwidth pressure low-reputation peers are served last or not at all. The maximum value a single identity can extract before being cut off is bounded by its credit threshold, which is calibrated below the cost of the identity itself.

### 9.5 Content Integrity

Content is self-authenticating: every received block is checked against its CID, and any mismatch is a provable failure recorded against the sender (`recordFailure`) and dropped. A forwarder cannot deliver garbage undetected, and a relayer that did would lose reputation and credit at the first honest verifier.

### 9.6 Privacy

Forwarders see the CIDs and routing targets they relay, comparable to IPFS, where routing peers see CID requests in the clear. This is acceptable for non-sensitive content. Sealed-envelope retrieval, where the requested CID and requester identity are encrypted for the destination only, is **[design intent]**.

---

## 10. Protocol Reference

### 10.1 Implemented Messages

| Message          | Fields                                                              | Direction              |
|------------------|--------------------------------------------------------------------|------------------------|
| `ping` / `pong`  | nonce                                                              | Direct (keepalive)     |
| `identify`       | publicKey, observedHost/Port, listenAddrs, chainPorts, signature  | Direct (on connect)    |
| `spawnCertPresentation` | [SpawnCertificate]                                         | Direct (after identify) |
| `findNode`       | target, fee, nonce                                                 | Iterative DHT lookup   |
| `neighbors`      | [PeerEndpoint], nonce                                              | Response to findNode   |
| `dhtForward`     | cid, ttl                                                          | Routed toward CID      |
| `block`          | cid, data                                                         | Single-block response  |
| `dontHave`       | cid                                                              | Negative response      |
| `want`           | [rootCID]                                                         | Direct content request |
| `wantVolume`     | rootCID, [cid]                                                    | Direct named-block request |
| `blocks`         | rootCID, [(cid, data)]                                            | Volume response        |
| `notHave`        | rootCID                                                          | Negative content response |
| `announceVolume` | rootCID, childCIDs, totalSize                                     | Gossiped               |
| `pushVolume`     | rootCID, [(cid, data)]                                            | Gossiped (full data)   |
| `announceBlock`  | cid                                                              | Gossiped               |
| `findPins`       | cid                                                              | DHT (pin discovery)    |
| `pins`           | cid, [pinnerPublicKey]                                            | Response to findPins   |
| `pinAnnounce`    | rootCID, publicKey, expiry, signature, fee                       | To CID neighborhood    |
| `pinStored`      | rootCID                                                          | Response from holder   |
| `deliveryAck`    | requestId                                                        | Direct                 |
| `peerMessage`    | topic, payload                                                    | Direct (unmetered)     |
| `pexRequest` / `pexResponse` | nonce [, peers]                                       | Direct (peer exchange) |

The `fee` fields that remain — `fee`/`nonce` on `findNode` and `fee` on `pinAnnounce` — are reserved for the credit mechanism in Section 6.3; they are carried but not yet acted on by responders. Selector-scoped retrieval is design intent (Section 3); no selector field is carried on the wire.

> **Removed messages.** Earlier drafts defined `feeExhausted`, `directOffer`, `balanceCheck`, `balanceLog`, `settlementProof`, `miningChallenge`, `miningChallengeSolution`, and the `nodeRecord`/`getNodeRecord` pair. These have been removed from the wire protocol; the settlement, balance-reconciliation, and direct-connect-with-backup mechanisms they implemented are design intent (Section 6.3), not current behavior, and the node-record subsystem was removed entirely.

### 10.2 Key Data Structures

**CreditLine** (Tally, per connected peer pair):

```
CreditLine {
    peerA, peerB:           PeerID
    balance:                Int64    // signed; relayed-byte denomination
    sequence:               UInt64   // incremented per balance change
    threshold:              UInt64   // |balance| ≥ threshold ⇒ needsSettlement
    successfulSettlements:  UInt64   // drives logarithmic threshold growth
}
```

**PinAnnouncement** (stored at K-closest peers to the root CID hash): `rootCID`, `pinnerPublicKey`, `expiry`, `signature` over `(rootCID, publicKey, expiry, fee)`. No selector field is stored.

**SpawnCertificate** (presented after `identify`, composes into a root→leaf chain): `childPublicKey`, `chainPath` (the proven scope), `issuerPublicKey`, `signature` over a canonical length-prefixed payload under a dedicated domain tag. A chain verifies against the verifier's own trusted root (Section 7.1).

### 10.3 Protocol Limits

Frame and field sizes are bounded to cap per-message memory: a maximum frame size, a maximum block payload, a maximum block count per `blocks`/`pushVolume` response, a maximum string-field length (CIDs, selectors, topics), and maxima on neighbors, PEX peers, listen addresses, and chain ports per message (`MessageLimits`). A `blocks` response is additionally fit to the frame budget — oversized volumes are returned partially and completed with follow-up `wantVolume` requests.

### 10.4 Peer Health

Liveness is detected by `ping`/`pong` keepalives and TCP close. A peer that misses consecutive keepalives is treated as unreachable and removed from the routing table (`PeerHealthMonitor`); there is no explicit disconnect message.

---

## 11. Responsibility Boundary: Ivy vs Tally

| Concern                              | Where                                  |
|--------------------------------------|----------------------------------------|
| Identity key difficulty, base trust  | Tally (`KeyDifficulty`)                |
| Per-peer reputation, gating, decay, PoW challenges | Tally (`Tally`)          |
| Bilateral credit lines, thresholds, settlement primitives | Tally (`CreditLine`, `CreditLineLedger`) |
| Kademlia routing, buckets, lookups   | Ivy (`Router`, `findNode`)            |
| Content exchange (want/blocks/dhtForward), volumes, verification | Ivy (`Ivy+ContentExchange`, `ContentAddressVerifier`) |
| Pin announcements and discovery      | Ivy (`Ivy+Records`, `PinAnnouncementSignature`) |
| Spawn certificates, NAT/STUN, transport | Ivy (`SpawnCertificate`, `STUNClient`, NIO) |
| Peer exchange, parent-child bootstrap| Ivy (`Ivy+Routing`)                   |
| Driving reputation/credit from traffic | Ivy calls Tally on each exchange     |

Ivy is the overlay; Tally supplies the trust and accounting primitives Ivy meters against the bytes it relays.

---

## 12. Conclusion

Ivy overlays content-addressed storage and per-chain Kademlia routing on a foundation of proof-of-work identities, per-peer reputation, and bilateral credit lines. In steady state it behaves as a cooperative network — peers serve freely and discover each other through PEX and parent-chain bootstrap — while the underlying byte-denominated credit ledger and reputation gating give it the machinery to detect free-riders, price Sybil identities, and throttle abuse. Content is self-authenticating, so integrity is enforced at every hop without a global authority. The fee-bid retrieval market and proof-of-work settlement remain as a deliberate evolution path: the accounting substrate is in place, and turning on charging is a configuration and protocol extension rather than a redesign.
