### Fixed

- A config transaction whose live policy re-apply failed, and whose restore
  of the sessions it had already changed also failed, reported a clean
  failure and admitted further config mutations while a session could still
  run the candidate policy chain. It now fences as known divergence: a
  confirmed transaction keeps its revert journal, and further mutations are
  refused until restart. A failure whose sessions were all restored still
  rolls back and reports a clean error. See
  [The Settlement Watchdog](../docs/how-to/settlement-watchdog.md).
