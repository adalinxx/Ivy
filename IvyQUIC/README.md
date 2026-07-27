# IvyQUIC

QUIC transport for Ivy, backed by [swift-nio-quic](https://github.com/apple/swift-nio-quic).

Kept as a separate package because swift-nio-quic requires a Swift 6.3 toolchain
and macOS 26, floors that would otherwise propagate to every Ivy consumer.

## Status: does not resolve yet

swift-nio-quic 0.1.0 depends on `swift-crypto` **5.0.0-beta.2**. SwiftPM never
matches a prerelease against a version range, so that beta cannot coexist with any
package requiring a released swift-crypto — including Ivy and, transitively, Tally
(`swift-crypto 3.0.0..<4.0.0`). Forcing Ivy onto the prerelease does not help:

```
error: Dependencies could not be resolved because 'ivy' depends on 'tally' 3.0.0..<4.0.0
and 'ivy' depends on 'swift-crypto' 5.0.0-beta.1..<6.0.0.
```

This unblocks itself when swift-nio-quic (or swift-certificates) ships against a
released swift-crypto 5.x, or when Tally widens its own range. The sources here are
written against the real 0.1.0 API and are ready to build at that point.

## What was verified against the real library

A standalone probe (Swift 6.3.3 / macOS 26.3) established the design's load-bearing
assumptions, so the code here is not speculative:

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

- No TLS exporter is exposed, so mixing a channel binding into `routeBinding` is not
  possible yet; QUIC dials use the same zero binding as direct TCP.
- Connection migration cannot be disabled through `QUICConfiguration`.

## Building, once resolvable

```
SWIFT_CERTIFICATES_ALLOW_SWIFT_CRYPTO_BETA=1 swift build
```
