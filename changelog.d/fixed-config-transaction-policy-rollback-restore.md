### Fixed

- When a config transaction (`ApplyConfigTransaction` or gNMI `Set`) has
  applied new policy chains live and then fails to publish the candidate, its
  rollback now restores the prior chains instead of re-applying them as a new
  forward edit. Previously the rollback went through the forward edit's
  qualification, so a peer that came up without Route Refresh after the apply
  made the whole rollback refuse, and every target kept the candidate chains
  until the daemon fenced.
  **Operator-visible:** the rollback is no longer refused by that
  qualification. A peer without Route Refresh gets its prior chain back, and
  its session is reset so it resends the routes it accepted under the
  candidate chain, as described in the
  [settlement watchdog guide](../docs/how-to/settlement-watchdog.md). The log
  reports the restore instead of a refused edit with a disable-the-neighbor
  remedy.
