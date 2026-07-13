# Correctness invariants

## TOPOLOGY-001 — pinned identity is canonicalized

Raw and `ed01`-prefixed spellings of the same key identify the same pinned peer; other keys are rejected.

## TOPOLOGY-002 — pinned sessions cannot enable public discovery

Pinned configuration disables local discovery, STUN, PEX, relay service, and known-relay substitution regardless of caller flags.

## TOPOLOGY-003 — pinned bootstrap is identity-scoped

Only bootstrap endpoints matching the configured pinned identity remain in the effective configuration.

## TOPOLOGY-004 — substitute connection fails before I/O

`connectInConfiguredTopology` rejects an endpoint outside the pinned identity before attempting network activity.

Established by: `IvyTopologyTests`.
