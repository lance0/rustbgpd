### Changed

- Readiness waits served while a session's Adj-RIB-Out or regroup baseline
  is retired at teardown, or while a family that becomes sendable
  mid-session regroups its peer, are now recorded under
  `bgp_rib_readiness_query_wait_seconds{seam="actor_loop"}` instead of
  `seam="policy_transition_fence"`: no policy transition is involved in
  those units.
