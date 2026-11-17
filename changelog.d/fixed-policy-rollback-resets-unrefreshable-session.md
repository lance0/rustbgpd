### Fixed

- A rollback that puts a prior import policy back on a peer that did not
  negotiate Route Refresh now resets that one session instead of leaving the
  outcome ambiguous. The prior policy is installed first, and the peer
  resends its routes under it when it reconnects. This covers a config
  transaction (`ApplyConfigTransaction` or gNMI `Set`) whose candidate could
  not be published, and the compensation of a failed live policy or
  peer-group edit. It also closes a gap in that compensation: a peer that
  took the new policy while down and came up without Route Refresh used to
  keep the routes the new policy accepted while the edit reported a complete
  rollback.
  **Operator-visible:** such a config transaction no longer fences the daemon
  or exits 70; it returns `INTERNAL` naming the reset peers, not
  `FAILED_PRECONDITION`, because those peers saw their sessions reset. Each
  reset logs a warning with the peer and `reason="route_refresh_unsupported"`
  and sends Cease/Administrative Reset (a Hard Reset when negotiated). A
  forward import edit for such a peer is still refused before anything is
  applied. If the session does not accept the reset within 500 ms, the
  rollback fences as before. See the
  [settlement watchdog guide](../docs/how-to/settlement-watchdog.md).
