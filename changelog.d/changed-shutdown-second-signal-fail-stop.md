### Changed

- A further SIGINT or SIGTERM during coordinated shutdown now fail-stops an
  owned runtime-config settlement instead of waiting out its budget: the
  owner is fenced with the new closed reason `operator_forced` and the daemon
  exits 70 through the existing settlement watchdog path after the five-second
  grace, leaving the pending transaction on disk for boot-time recovery. A
  signal after an RPC-initiated shutdown escalates the same way; with no
  owner the signal keeps its "stop waiting" meaning and the exit status is
  unchanged.
  **Operator-visible:** `fence_reason="operator_forced"` joins the settlement
  metric labels and fail-stop diagnostic, the signal line is logged at ERROR
  when it fences an owner, and a further signal sent to a running unit ends
  in exit 70, which `Restart=on-failure` restarts (a unit stopped with
  `systemctl stop` is not restarted automatically, whatever its exit
  status). See
  [settlement-watchdog.md](../docs/how-to/settlement-watchdog.md#what-coordinated-shutdown-bounds)
  and [ADR-0127](../docs/adr/0127-config-transaction-settlement-watchdog.md).
