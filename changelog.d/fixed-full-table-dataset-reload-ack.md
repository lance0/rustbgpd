### Fixed

- A SIGHUP that swaps the contents of a dataset used by export policy no
  longer fail-stops, or reports a partial reload, when the RIB needs more
  than five seconds to re-evaluate the affected update groups. At
  full-table scale that work takes tens of seconds; the reload previously
  gave up on the RIB's acknowledgement after five seconds, fenced
  `known_divergence` and exited 70 while the work was still completing.
  The reload now waits for the RIB to finish, serving readiness and
  operator reads meanwhile, bounded by the
  [settlement watchdog](../docs/how-to/settlement-watchdog.md) budget.
