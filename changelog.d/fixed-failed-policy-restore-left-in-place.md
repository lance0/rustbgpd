### Fixed

- A policy restore that fails partway, during a SIGHUP generation rollback or
  the interface-only restore after a failed peer-group change, no longer
  reinstalls the candidate chains it was removing. Previously a restore that
  failed in a batched export cohort, its RIB transition, its deferred Route
  Refresh (for example, a peer that came up without Route Refresh), or the
  per-peer remainder was unwound back to the candidate import and export
  chains before the daemon fenced.
  **Operator-visible:** the outcome is unchanged: the daemon still fences and
  exits 70, as described in the
  [settlement watchdog guide](../docs/how-to/settlement-watchdog.md). Until it
  exits, peers keep the restored chains, no Route Refresh is sent under the
  candidate chain, and the log says the restored chains are left in place.
