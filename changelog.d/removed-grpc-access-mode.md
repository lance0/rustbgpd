### Removed

- The gRPC listener `access_mode` key under `[global.telemetry.grpc_tcp]` and
  `[global.telemetry.grpc_uds]` is removed; `max_tier` is the only listener
  ceiling. A config that still sets `access_mode` fails to load with an
  unknown-field error. The mutating handlers keep refusing calls on a
  read-only listener, now keyed off the ceiling: any listener whose
  `max_tier` is below `mutating` is read-only. The `access_mode` label of
  `bgp_grpc_authz_decisions_total` and field of `grpc_authz` audit records
  stay, derived the same way (`read_only` below `mutating`, else
  `read_write`). The startup log fields of the listener records change from
  `access_mode` to `max_tier`. See the
  [configuration reference](../docs/reference/configuration.md#globaltelemetrygrpc_tcp).
