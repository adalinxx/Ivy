# Stack architecture source

The normative architectural laws for this work live in `adalinxx/Lattice/docs/foundational-architecture.md` on the coordinated redesign branch.

Ivy owns authenticated transport, public discovery, and content exchange. Operational topology limits whom a session may contact; it never makes received content valid.
