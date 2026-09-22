### Changed

- `ListFibTables` (`rbgp fib-table list`) no longer acquires the exclusive
  runtime-config coordinator lock across its actor query. The configured table
  set is read directly from the authoritative committed configuration snapshot,
  so operator reads during apply-before-persist, failed persistence, or
  transaction rollback expose only the coherent committed table set, never an
  uncommitted candidate. While an actor read is in flight or stalled, unrelated
  config mutations and SIGHUP reloads can acquire the coordinator and complete
  without waiting on the FIB reconciler.
  **Operator-visible:** `rbgp fib-table list` no longer blocks concurrent
  config transactions or SIGHUP reloads, and in-flight uncommitted candidate
  tables are never visible before accepted config publication.
