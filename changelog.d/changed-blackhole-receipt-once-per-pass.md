### Changed

- Write the BLACKHOLE ownership receipt once per reconcile pass instead of once
  per installed or removed prefix. Each write re-encoded the whole receipt and
  ran two fsyncs on the actor, so a burst of host routes cost quadratic bytes and
  delayed withdrawals and the shutdown drain. Removals publish one receipt drop
  per batch before the kernel deletes. A crash between a pass's installs and its
  receipt write leaves that pass's rows unreceipted; restart treats them as
  foreign, as it already did for a single row. See
  [the BLACKHOLE discard reference](../docs/reference/configuration.md).
