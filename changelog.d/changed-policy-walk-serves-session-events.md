### Changed

- A long export-policy reload no longer holds BFD and session events until
  it ends. While the peer manager applied a policy change or rolled one
  back, it served only readiness probes and admitted reads, so a BFD Down
  did not stop its BGP session, a crashed session task was not restarted
  and no session event was published until the whole change had finished,
  which at a full table can now be many minutes. Between two steps of the
  change (one peer's session step or one RIB command, about a second at a
  full table) it now serves BFD Down and due `BfdDown` retries, session up,
  down and NOTIFICATION events, and a static neighbor's session
  notifications: a crashed session task is restarted, a max-prefix breach
  or a repeating crash latches the neighbor, an OPEN collision is resolved.
  Link-state changes are served at any moment, so fast external failover
  does not wait for a step.
  **Operator-visible:** still waiting until the change has ended are inbound
  connections, the removal of a dynamic neighbor whose session went idle,
  max-prefix restart timers, configuration changes and peer lifecycle
  commands; during a SIGHUP reload a BFD Up also waits, and the held session
  is started once the reload has committed or rolled back. The shared
  transition of the largest group of peers making the same export change
  has no step boundary: session events wait for it. The `reload generation
  phase timing` log line gains `owned_wait_service_gap_max_us`,
  `events_served` and `event_service_us`. A neighbor latched disabled during
  a SIGHUP reload that is then rolled back has its BFD session stopped, as
  after a reload that commits. A neighbor that a BFD Down holds is no longer
  restarted when its session task crashes, during a reload or outside one:
  the BFD Up that releases the hold starts the replacement. See
  [Configuration reload](../docs/reference/operations.md#configuration-reload-sighup).
