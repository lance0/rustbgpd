### Fixed

- Keep M67 baseline route and nexthop-group assertions strict when startup drain
  metrics are present. Reusing a live topology now requires explicit manual
  `M67_RERUN=1`; invalid values and CI opt-in fail instead of weakening the proof.
