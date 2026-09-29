### Fixed

- Grow the import explain cache index as decisions arrive, and reject
  explain or rejected-route cache capacities above 2,097,152 entries.
  Update the documented per-session memory budget.
  **Upgrade:** Previously accepted values above the ceiling now fail startup
  and reload validation even when retention is disabled. Reduce both
  `[policy.explain] cache_size` and `[policy.reject_retention] capacity` to
  at most 2,097,152 and run the new binary's `--check --strict` before
  stopping or restarting. Defaults and zero-to-one clamping are unchanged.
