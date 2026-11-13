### Changed

- The gRPC server is now restarted in place when it ends on its own,
  instead of shutting the daemon down
  ([ADR-0147](../docs/adr/0147-management-servers-restart-in-place.md),
  superseding ADR-0022). BGP sessions and routes stay up. All configured
  listeners restart together and bind their TCP addresses and Unix socket
  paths again, with the same backoff as the metrics/readiness server (100 ms
  to a 10 second cap, no limit); a restart whose listeners cannot start is
  retried. While the server is down `/readyz` answers
  `503 not ready: gRPC server is restarting`. Each exit or failed restart
  counts in `bgp_management_server_crashes_total{server="grpc"}`, exported at
  0. Requests in flight on connections that were already open run to their
  own answer, and a runtime-config mutation that had begun still settles
  under the settlement watchdog. A listener that cannot bind or start at
  startup still fails startup. See
  [gRPC server dies unexpectedly](../docs/reference/operations.md#grpc-server-dies-unexpectedly).
  **Operator-visible:** the daemon no longer exits 1 for the gRPC server, and
  `--help` and the man page no longer list it among the exit-1 causes. The
  ERROR line is now `gRPC server exited unexpectedly; restarting it in
  place`, followed by `gRPC server restarted`; `initiating shutdown due to
  gRPC server failure` is gone.
