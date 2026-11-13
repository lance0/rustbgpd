### Changed

- An export-policy reload is no longer rolled back because it took longer
  than two minutes. The walk over changed peers was bounded by one two-minute
  deadline in total, so at a full table a reload changing roughly 80 or more
  peers with per-neighbor export policies was rolled back although every
  step was succeeding, and every peer was then resynced a second time. The
  two-minute bound is now a stall timeout measured from the walk's last
  completed piece of work (one peer's session policy change, one RIB command,
  or the Route Refreshes of one step): a reload that keeps making progress
  commits, and one is rolled back only when a peer refuses or fails its step
  or the walk completes nothing for two minutes.
  **Operator-visible:** a large reload of per-neighbor export policies now
  takes as long as its work needs, about one full-table pass per such peer,
  and holds configuration changes and peer lifecycle commands for that time;
  inbound connections, BFD state changes and a first SIGTERM wait as well.
  The 30-minute settlement budget is the outer bound: a walk that reaches
  it, at roughly 1,200 such peers at a full table, is fenced and the daemon
  exits 70. `rbgp reload` still gives up after its `--timeout` (600 seconds
  by default) although the reload may commit later. This walk's timeout
  errors no longer say `shared policy-walk budget`: the batched and paced
  steps name the `policy-walk stall timeout` and the per-peer step the
  `policy-walk budget`. Log lines report a long walk: `authoritative policy walk
  started`, then `authoritative policy walk in progress` or `paced
  export-policy walk in progress` about every ten seconds, as units
  complete. See
  [Configuration reload](../docs/reference/operations.md#configuration-reload-sighup).
