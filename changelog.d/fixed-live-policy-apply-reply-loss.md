### Fixed

- A live policy-impact config transaction whose peer manager accepted the
  live policy re-apply but dropped its reply could be reported as an
  ordinary `UNAVAILABLE` error, although sessions may already have been
  running the candidate policy. For a confirmed apply, this also removed the
  commit-confirm revert authority. The lost acknowledgement is now an
  `acknowledgement_lost` recovery fence, as it already was for the reverse
  (rollback) apply: the revert authority is retained, config mutations are
  blocked, and the daemon exits 70 for supervised recovery.
  **Operator-visible:** such an apply no longer returns `UNAVAILABLE`; it
  records `fence_reason="acknowledgement_lost"`, and a confirmed apply
  boot-reverts from its retained authority on restart. See
  [settlement-watchdog.md](../docs/how-to/settlement-watchdog.md).
