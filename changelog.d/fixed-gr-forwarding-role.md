### Fixed

- Advertise GR and LLGR forwarding-state bits for control-plane-only families
  so helpers can retain routes across reconnects. Families with configured
  FIB, blackhole-discard, or EVPN kernel installers keep these bits clear.
  Committed runtime role changes and rollback take effect on the next OPEN
  without restarting unchanged peers; staged candidates remain invisible.
  Uncertain runtime effects keep the affected families' bits clear, including
  lost acknowledgements, failed compensation, and interrupted EVPN convergence.
