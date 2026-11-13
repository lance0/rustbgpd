### Fixed

- A rolled-back export-policy reload no longer restores every peer with
  its own prior export policy in one RIB turn. Measured before this change, rolling back about 80 peers with
  distinct export policies at a full table held the RIB for 66 to 68
  seconds, during which no UPDATE, query or timer ran. The rollback now
  restores peers that return to a shared policy as one batch per policy and
  the rest a few per RIB command, so other work runs between commands. A
  peer the failed reload had not yet moved in the RIB costs the rollback no
  re-export. The rollback is still never abandoned, and a peer whose session drops during
  it is skipped and comes back up on the restored policy. One case is not
  yet paced: peers that return from many different policies to one shared
  policy are still restored in a single turn.
  **Operator-visible:** the rollback wait is now a stall detector. It gives
  up, and the daemon fences with `known_divergence`, only when the restore
  completes no RIB command for two minutes; a slow restore that keeps making
  progress is waited for, inside the 30-minute settlement budget, instead of
  being fenced at two minutes in total. A reload that is rolling back can
  therefore take longer to report its outcome. Until a peer's own restore
  command runs, it can receive the results of the rollback's Route Refreshes
  under the rejected export policy; its restore then re-exports its table.
  Three log lines follow it:
  `policy rollback: restoring export policies in the RIB`, a progress line
  every ten seconds, and `policy rollback: export policies restored in the
  RIB` with the duration. See
  [the settlement watchdog guide](../docs/how-to/settlement-watchdog.md).
