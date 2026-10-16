### Added

- `bgp_outbound_eor_deferrals_total{peer}` counts End-of-RIB markers that were
  deferred because the peer writer channel was full or closed. These deferrals
  were previously only logged. The marker stays pending and is retried after
  the peer's next resync. `bgp_outbound_route_drops_total` is unchanged. The
  Grafana "RIB ingest pressure" panel plots the new counter.
