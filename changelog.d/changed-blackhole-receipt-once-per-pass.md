### Changed

- Write the BLACKHOLE ownership receipt once per reconcile pass instead of once
  per installed or removed prefix. Each write re-encoded the whole receipt and
  ran two fsyncs on the actor, so a burst of host routes cost quadratic bytes and
  delayed withdrawals and the shutdown drain. A pass now writes the receipt at
  most once ahead of its installs, once after each batch of deletions, and once
  to drop candidates that were not installed; a crash at any point still leaves
  every daemon route receipted for adoption on restart. See
  [the BLACKHOLE discard reference](../docs/reference/configuration.md).
