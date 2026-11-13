### Fixed

- The RIB now answers readiness probes during two more actor turns that
  could walk a whole table without serving them: a session registration
  that is the first member of its update group, which builds the group
  table from the whole Loc-RIB before the initial table is sent, and a
  session teardown or reconnect that releases the member's EVPN recovery
  ledger. **Operator-visible:** the readiness endpoint stays answered
  through these turns; the turns themselves are not shorter, and routes and
  wire output are unchanged.
- Readiness waits served while a session's Adj-RIB-Out or regroup baseline
  is retired at teardown, or while a family that becomes sendable
  mid-session regroups its peer, are now recorded under
  `bgp_rib_readiness_query_wait_seconds{seam="actor_loop"}` instead of
  `seam="policy_transition_fence"`: no policy transition is involved in
  those units.
