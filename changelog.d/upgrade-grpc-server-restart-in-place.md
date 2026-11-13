### Upgrade notes

- Monitoring that relied on the daemon exiting 1 when its gRPC server failed
  no longer sees that event. Alert on
  `bgp_management_server_crashes_total{server="grpc"}` (the shipped
  `BgpManagementServerCrashed` rule covers it) and on a `/readyz` that stays
  `503 not ready: gRPC server is restarting`. A gRPC server that cannot be
  restarted leaves the daemon running BGP with the API down; restart the
  process to recover it. gRPC clients with a long-lived connection must
  reconnect after a restart: the old connection accepts no new requests.
