### Changed

- Route servers now build a cold per-client-best group in bounded steps for
  policy-free eBGP sessions limited to IPv4 or IPv6 unicast and without a
  configured role. Unrelated updates can run while the group ranks candidates
  and prepares the first member’s route-server controls. The initial table
  replay still runs in one turn.
