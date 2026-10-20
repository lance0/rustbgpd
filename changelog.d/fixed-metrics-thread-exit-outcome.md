### Fixed

- The metrics/readiness server thread now reports how it ended: a requested
  stop, an accept-loop exit or panic, or a start failure carrying the runtime
  or thread error. A requested stop is no longer reported as "did not start",
  and a thread panic seen while joining at teardown is logged as a warning.
  **Operator-visible:** the `result` field of `metrics/readiness server exited
  unexpectedly` now reads, for example, `Ok(Exited(Ok(())))` or
  `Ok(StartFailed("metrics/readiness runtime did not start: ..."))`; the
  message, coordinated shutdown and exit status 1 are unchanged.
