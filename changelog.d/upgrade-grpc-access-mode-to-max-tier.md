### Upgrade notes

- Replace each gRPC listener `access_mode` before upgrading; the key no
  longer loads. With `access_mode = "read_only"`, delete it and set
  `max_tier` to the stricter of `"sensitive_read"` and any `max_tier` the
  listener already has, so `max_tier = "read"` stays `"read"`. With
  `access_mode = "read_write"`, delete it and keep any existing `max_tier`,
  or leave `max_tier` unset to serve every tier. This keeps each listener's
  effective ceiling unchanged. Scripts and benchmark or lab harnesses outside
  this repository that generate listener tables need the same edit. Run
  `rustbgpd --check` on the new config before restarting.
- Rewrite Prometheus queries, alerts and dashboards that use the
  `access_mode` label of `bgp_grpc_authz_decisions_total` to use
  `listener_max_tier`. Select read-only listeners with
  `listener_max_tier=~"read|sensitive_read"` and listeners that admit
  mutations with `listener_max_tier=~"mutating|operator_only"`. Log
  pipelines that read the `access_mode` field of `grpc_authz` records
  should read `max_tier` instead.
