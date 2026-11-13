### Fixed

- A panic in one RPKI cache's RTR client no longer shuts the daemon down. The
  client restarts that cache's session and the panic is handled as an ordinary
  loss of the RTR session: the cache's VRPs and ASPAs stay in use until the
  effective expire, the client reconnects after `retry_interval` and
  resynchronizes with a Reset Query, and BGP sessions and the other caches are
  not touched. Previously the supervisor aborted every RPKI task and the
  daemon exited 1. An unexpected exit of the VRP manager or a validation-table
  forwarder is still fatal. See
  [operations](../docs/reference/operations.md#rpki-subsystem-task-exits-unexpectedly).
  **Operator-visible:** the new `bgp_rpki_rtr_client_restarts_total{cache}`
  counter starts at `0` for each configured cache and counts these restarts;
  each one logs `RTR client panicked; restarting its session with the held
  data retained` at ERROR and leaves a panic report.
