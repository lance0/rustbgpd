### Fixed

- `rs-config-render recover rollback --apply` exited 5 (`rollback did not
  settle`) and left `current` on the rollback target when the daemon rejected
  the rollback's reload without runtime effect, although the daemon was still
  running the generation it had before. The verb now uses the same
  `rbgp metrics` proof as `activate` (one new `rejected_no_effect` SIGHUP
  outcome from the same process, no settlement in progress, checked again
  after `current` is re-pointed back). With that proof, or when the activation
  command could not start, it restores `current` to the generation it rolled
  away from and changes nothing else.
  **Operator-visible:** that case now exits 2 (`current restored, nothing
  changed`) with fence, journal, activation receipt and upstream lock
  unchanged. If the proof does not hold after `current` is restored, the verb
  exits 5 with `restoring current could not be re-proven`. See the
  [manual-recovery runbook](../docs/cookbook/activation-manual-recovery.md#2-keep-the-candidate-or-roll-back).
