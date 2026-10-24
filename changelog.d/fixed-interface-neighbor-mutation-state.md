### Fixed

- Interface-only neighbor policy-chain edits now persist and update the
  selected binding. Mixed peer-group edits wait for live policy convergence
  before reporting success.
- Interface-only neighbors retain late max-prefix shutdowns and lifetime
  counters across binding replacements. Restart-duration edits reschedule
  an armed hold-down when the configuration changes, including while unbound.
