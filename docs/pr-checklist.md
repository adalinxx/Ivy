# Topology review checklist

- [ ] Public overlay and identity-pinned session are chosen explicitly.
- [ ] Pinned configuration cannot re-enable PEX, STUN, local discovery, relay, or substitute bootstrap peers.
- [ ] Topology checks canonicalize peer key spellings.
- [ ] A rejected substitute fails before network I/O.
- [ ] Topology controls operational contact, never content validity.
