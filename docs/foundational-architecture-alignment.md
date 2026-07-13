# Foundational architecture alignment

Ivy transports and discovers verifiable content. A public discovery overlay and a direct, identity-pinned operational relationship are different topologies.

This change introduces that distinction explicitly:

- `.publicOverlay` retains ordinary bootstrap, local discovery, STUN, PEX, and relay behavior;
- `.pinnedPeer(publicKey:)` filters bootstrap peers to one canonical identity and disables public discovery, STUN, PEX, relay service, and known-relay substitution;
- `connectInConfiguredTopology(to:)` rejects a substitute identity before network I/O.

The topology does not make received content valid. It limits whom an operational session may contact; protocol verification remains above Ivy.

This is the first migration seam. Callers that represent parent-evidence or other pinned relationships should construct pinned configurations and use the topology-checked connection API. Public content exchange continues to use the public overlay.
