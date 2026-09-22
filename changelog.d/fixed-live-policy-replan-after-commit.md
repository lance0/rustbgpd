### Fixed

- A live policy-impact config transaction whose post-commit runtime
  snapshot re-plan failed (the peer manager was unavailable or dropped the
  reply) was reported as an ordinary clean error even though the candidate
  was already durable and live. For a confirmed apply, this removed the
  commit-confirm revert authority, so the unconfirmed candidate could no
  longer roll back automatically. The failure is now a `known_divergence`
  recovery fence: the revert authority is retained, config mutations are
  blocked, and the daemon exits 70 for supervised recovery, as it does for
  other post-commit finalization failures.
  **Operator-visible:** such an apply no longer returns `UNAVAILABLE`; it
  records `fence_reason="known_divergence"`, readiness goes red, and a
  confirmed apply boot-reverts from its retained authority on restart. See
  [settlement-watchdog.md](../docs/how-to/settlement-watchdog.md).
