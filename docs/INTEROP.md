# Interop Test Results

Tracks interop validation against real BGP implementations. Updated with
every milestone. "Tested" means validated in the containerlab CI suite,
not "someone tried it once."

---

## Test Matrix

| Peer | Version | Topology | Status | Notes | Known Quirks | NOTIFICATIONs Observed |
|------|---------|----------|--------|-------|--------------|------------------------|
| FRR (bgpd) | 10.x | `tests/interop/m0-frr.clab.yml` | Planned (M0) | Primary interop target | — | — |
| BIRD | 2.x | `tests/interop/m0-bird.clab.yml` | Planned (M0) | Primary interop target | — | — |
| GoBGP | 3.x | — | Planned (M4) | Secondary target | — | — |
| Junos vMX | — | — | Stretch | Lab only, not CI | — | — |
| Arista cEOS | — | — | Stretch | Lab only, not CI | — | — |
| Cisco IOS-XE | — | — | Stretch | If available | — | — |

## Per-Peer Notes

### FRR

- Primary CI target. Must not break.
- FRR bgpd version tracked in containerlab topology.
- Known behavior: (to be filled during M0 testing)

### BIRD

- Primary CI target. Must not break.
- BIRD version tracked in containerlab topology.
- Known behavior: (to be filled during M0 testing)

### GoBGP

- Secondary CI target. Failures investigated, not gating.
- Used as a peer, not as reference implementation.

---

## Cease Subcode Compatibility

Per RFC_NOTES.md, rustbgpd sends Cease subcode 4 (Out of Resources)
for global route limit violations. Track peer behavior here:

| Peer | Accepts Subcode 4 | Fallback Needed | Notes |
|------|--------------------|-----------------|-------|
| FRR | TBD | TBD | — |
| BIRD | TBD | TBD | — |
| GoBGP | TBD | TBD | — |
