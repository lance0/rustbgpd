### Fixed

- Interface-only neighbor policy-chain edits now persist and update the
  selected binding. Mixed peer-group edits wait for live policy convergence
  before reporting success.
- Interface-only neighbors retain late max-prefix shutdowns and lifetime
  counters across binding replacements, and report the retained
  administrative state while unbound. Membership edits preserve unchanged
  hold-downs; duration edits reschedule an armed hold-down when configuration
  changes, including while unbound.
