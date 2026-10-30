### Fixed

- A grouped receiver that re-registered on its own session channel during a
  GR selection hold no longer keeps rows removed during the hold after release.
  A deleted RTBH route, a withdrawn received route or a row the update group
  dropped stayed advertised until the next refresh, because the rebuilt group
  table no longer carried it; release now withdraws every row the member
  still held from its retained admitted keys. A recovery proof refused while
  its keys were complete now keeps those keys, without growing, until
  recovery completes instead of discarding them.
  **Operator-visible:** `bgp_update_group_recovery_entries` and
  `bgp_update_group_recovery_bytes` include such a refused proof's keys until
  the hold or recovery finishes.
