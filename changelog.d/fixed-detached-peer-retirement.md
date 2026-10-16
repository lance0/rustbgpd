### Fixed

- Service dedicated readiness probes while retiring detached received routes,
  private advertised routes and regroup baselines during peer teardown, including
  the subsequent unused-attribute sweep. Ordinary reads and mutations remain
  fenced, and the existing stalled-owner deadline is unchanged.
