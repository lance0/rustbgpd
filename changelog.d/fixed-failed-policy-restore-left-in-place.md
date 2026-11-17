### Fixed

- A policy restore that fails partway, during a SIGHUP generation rollback or
  the interface-only restore after a failed peer-group change, no longer
  unwinds the chains it already restored back to the candidate chains it was
  removing. Previously a restore that failed in a batched export cohort, its
  RIB transition, its deferred Route Refresh (for example, a peer that came up
  without Route Refresh), or the per-peer remainder reinstalled the candidate
  import and export chains on the peers it had already restored before the
  daemon fenced.
  **Operator-visible:** the outcome is unchanged: the daemon still fences and
  exits 70, as described in the
  [settlement watchdog guide](../docs/how-to/settlement-watchdog.md). Until it
  exits, peers the restore already reached keep their restored chains, peers
  it had not reached yet still run the candidate chains, and the log says the
  restored chains are left in place.
