### Changed

- The metrics/readiness HTTP server (`/metrics`, `/readyz`, `/livez`) is now
  restarted in place when it ends on its own, instead of shutting the daemon
  down. A management-plane failure is not evidence about routing state, so
  BGP sessions and routes stay up. After a panic or a failed thread start the
  next run serves the same bound socket; after an unusable listening socket
  the daemon binds the configured address again. Restarts back off from
  100 ms to a 30 second cap with no limit, and none begins once coordinated
  shutdown has started. New counter
  `bgp_management_server_restarts_total{server="metrics"}`, exported at 0,
  counts them, and the alert pack gains `BgpManagementServerRestarted`. A
  bind failure at startup still fails startup. See
  [Metrics/readiness server exits unexpectedly](../docs/reference/operations.md#metricsreadiness-server-exits-unexpectedly).
  **Operator-visible:** the daemon no longer exits 1 for this server, and
  `--help` and the man page no longer list it among the exit-1 causes. The
  ERROR line is now `metrics/readiness server exited unexpectedly; restarting
  it in place`, with `exit` and `restart_in_ms` fields; `initiating shutdown
  due to metrics/readiness server failure` is gone.
