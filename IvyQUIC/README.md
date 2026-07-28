# IvyQUIC

QUIC transport for Ivy, backed by [swift-nio-quic](https://github.com/apple/swift-nio-quic).

Kept as a separate package because swift-nio-quic requires a Swift 6.3 toolchain
and macOS 26, floors that would otherwise propagate to every Ivy consumer.

## Status: builds and passes an integration test

Resolves from a clean checkout as of **Tally 3.0.2**, which admits a swift-crypto
prerelease. swift-nio-quic 0.1.0 pins `swift-crypto` **5.0.0-beta.2** exactly, and
SwiftPM never matches a prerelease against a range whose bounds are all releases,
so a dependency declaring `from: "3.0.0"` makes the graph unresolvable. Ivy and
Tally both give their lower bound a prerelease component (`"3.0.0-a"..<"6.0.0"`),
which admits the beta when something demands it while leaving ordinary builds on
the newest stable release — verified: Ivy alone still resolves swift-crypto 3.15.1.

## What is verified against the real library

Two Ivy nodes complete an authenticated session over QUIC
(`Tests/IvyQUICTests`). A standalone probe (Swift 6.3.3 / macOS 26.3) also
established the design's load-bearing assumptions:

- **Admission before reads holds.** Setting `autoRead = false` on a QUIC stream
  channel inside the inbound stream initializer sticks (children otherwise inherit
  the parent's `true`). Data written by the peer immediately was *not* delivered
  until the acceptor enabled reads and called `read()` — the same contract the TCP
  listener relies on for IVY-001, so no pause-buffer workaround is needed.
- **Ephemeral self-signed certificates + `.noVerification`** complete the handshake,
  matching Ivy's stance that TLS supplies confidentiality only and identity comes
  from the signed session handshake.
- **ALPN and stream caps** (`initialMaxStreamsBidi: 1`, `initialMaxStreamsUni: 0`)
  are honoured, so one connection carries exactly one Ivy session stream.

## Known gaps in the 0.1.0 API

- Dialing from the listener's own UDP port shares one socket between the listener
  and the dial, which this code does not yet arrange; a punch therefore leaves
  from whatever port the bind yields.
- No TLS exporter is exposed, so mixing a channel binding into `routeBinding` is not
  possible yet; QUIC dials use the same zero binding as direct TCP.
- Connection migration cannot be disabled through `QUICConfiguration`.

## Building

```
SWIFT_CERTIFICATES_ALLOW_SWIFT_CRYPTO_BETA=1 swift build
```
