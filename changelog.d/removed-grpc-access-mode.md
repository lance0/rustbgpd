### Removed

- The gRPC listener `access_mode` key under `[global.telemetry.grpc_tcp]` and
  `[global.telemetry.grpc_uds]` is removed; `max_tier` is the only listener
  ceiling. A config that still sets `access_mode` fails to load, and the
  error names the replacement. The mutating handlers keep refusing calls on
  any listener whose `max_tier` is below `mutating`.
  **Operator-visible:** the `access_mode` label of
  `bgp_grpc_authz_decisions_total` is renamed `listener_max_tier`. Its value
  changes from `read_only` or `read_write` to the listener's `max_tier`
  (`read`, `sensitive_read`, `mutating` or `operator_only`). Update queries
  that group or filter by `access_mode`. `grpc_authz` audit records drop the
  `access_mode` field; their existing `max_tier` field carries the listener
  ceiling. The listener startup log records `max_tier` instead of
  `access_mode`. See the
  [configuration reference](../docs/reference/configuration.md#globaltelemetrygrpc_tcp).
