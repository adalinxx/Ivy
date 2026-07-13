# Redesign series dependency

This PR is one layer of a coordinated series. `lattice-node` consumes this branch as its integration gate.

The change is intentionally additive and defaults to the existing public overlay. Callers opt into `.pinnedPeer` only for relationships whose operational counterparty is configured and identity-scoped.

A future released Ivy version should replace the temporary branch dependency in the top-level node PR.
