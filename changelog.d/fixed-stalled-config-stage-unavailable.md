### Fixed

- A config store that never acknowledges a staged runtime-config candidate
  no longer fail-stops the daemon. Before this fix, a hung or very slow
  config filesystem kept the owned mutation waiting until the 30-minute
  settlement budget expired, fenced it as `budget_expired` and exited 70,
  although nothing had been applied. Waits before the first runtime effect
  now end at a pre-effect deadline that reserves a tenth of the budget, up
  to 30 seconds, before the budget expires. The mutation fails as
  `UNAVAILABLE`, the late stage is discarded, and the daemon keeps running.
  This covers the stage acknowledgement in FIB-table, neighbor, peer-group
  and policy CRUD and config transactions, the FIB-table read in FIB-table
  CRUD and in config transactions, the config-transaction persistence-slot
  reservation, the FIB-table CRUD peer-manager handoff, and the peer-group
  `Set` read.
  **Operator-visible:** a stalled config store now yields an `UNAVAILABLE`
  error saying config persistence did not stage the candidate in time and
  nothing was applied, instead of exit 70. Waits after the first runtime
  effect keep the existing fail-stop contract. See
  [settlement-watchdog.md](../docs/how-to/settlement-watchdog.md#the-fence-reasons)
  and [ADR-0127](../docs/adr/0127-config-transaction-settlement-watchdog.md).
