### Changed

- Prometheus series that carry an address family now use one `family` label
  with the canonical configuration family labels (`ipv4_unicast`,
  `l2vpn_evpn`, `linkstate`, and so on). The RIB gauges `bgp_rib_prefixes`,
  `bgp_rib_adj_out_prefixes` and `bgp_rib_loc_prefixes` publish one series
  per family instead of per table, so `afi_safi="all"` no longer hides an
  IPv4 + IPv6 unicast sum. The max-prefix series split the old `scope` into
  `family` and `stage` (`accepted` or `received`), so they join the RIB
  gauges with `on(peer, family)`. `bgp_rpki_vrp_count` labels its address
  family `afi`. The old label names and values are not emitted alongside the
  new ones; see the upgrade note for the complete mapping and the
  [operations reference](../docs/reference/operations.md) for the series.
  **Operator-visible:** dashboards, alerts and scripts that select or
  aggregate on `afi_safi`, `scope` or `af` must be updated; the shipped
  alert rules and Grafana dashboards are.
