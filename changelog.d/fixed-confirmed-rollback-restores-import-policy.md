### Fixed

- Aborting, canceling (gNMI) or timing out a commit-confirmed config
  transaction now restores the prior import policy even when a peer lost
  Route Refresh inside the confirm window. Before, the rollback was applied as
  a new import edit, which is refused for such a peer, so it failed with
  `abort_failed` / `auto_revert_failed` and the unconfirmed candidate kept
  running behind the mutation fence. The prior policy is installed and that
  one session is reset so the peer resends its routes under it; a forward
  import edit for such a peer, including a history rollback, is still refused.
  **Operator-visible:** the abort result, `rbgp config status` and a warning
  log name each reset peer. A rollback whose policy restore fails partway, for
  example because a session stops answering, is no longer undone back to the
  candidate: the daemon fences and exits 70, and the restart boot-reverts from
  the retained journal, instead of reporting `abort_failed` /
  `auto_revert_failed` with the candidate reinstalled. See the
  [settlement watchdog guide](../docs/how-to/settlement-watchdog.md).
