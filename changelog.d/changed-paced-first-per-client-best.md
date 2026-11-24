### Changed

- Route servers now build a cold per-client-best group in bounded steps for
  policy-free eBGP sessions limited to IPv4 or IPv6 unicast and without a
  configured role. Unrelated updates can run while the group ranks candidates
  and prepares the first member’s route-server controls. If sustained updates
  overflow the build's change log twice, the first member falls back to the
  one-turn build. The initial table replay still runs in one turn.
