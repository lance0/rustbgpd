### Upgrade notes

- Metric family labels were renamed with no compatibility period; update
  every query, recording rule, alert and dashboard that uses them before or
  with the upgrade. Label names:
  `afi_safi` → `family` on `bgp_rib_prefixes`, `bgp_rib_adj_out_prefixes`,
  `bgp_rib_loc_prefixes`, `bgp_route_refresh_in_progress`,
  `bgp_route_refresh_stale_entries`, `bgp_selection_deferral_active`,
  `bgp_selection_deferral_waiters`, `bgp_selection_deferral_releases_total`,
  `bgp_selection_deferral_timeouts_total` and
  `bgp_selection_deferral_ledger_overflows_total`;
  `scope` → `family` plus a new `stage` label on `bgp_max_prefix_usage`,
  `bgp_max_prefix_limit`, `bgp_max_prefix_headroom`,
  `bgp_max_prefix_blocking`, `bgp_max_prefix_blocked_total` and
  `bgp_max_prefix_warning_total`;
  `af` → `afi` on `bgp_rpki_vrp_count` (values `ipv4` and `ipv6` unchanged).
- RIB gauge values (`bgp_rib_prefixes`, `bgp_rib_adj_out_prefixes`,
  `bgp_rib_loc_prefixes`) are now one series per family:
  `all` → `ipv4_unicast` and `ipv6_unicast`;
  `flowspec` → `ipv4_flowspec` and `ipv6_flowspec`; `evpn` → `l2vpn_evpn`;
  `vpn` → `l3vpn_ipv4_unicast` and `l3vpn_ipv6_unicast`;
  `labeled` → `ipv4_labeled_unicast` and `ipv6_labeled_unicast`;
  `bgpls` → `linkstate` and `linkstate_vpn`; `rtc` is unchanged. The old
  `all` value is
  `sum without (family) (bgp_rib_prefixes{family=~"ipv4_unicast|ipv6_unicast"})`.
  `bgp_rib_prefixes` covers `ipv4_unicast`, `ipv6_unicast`, `l2vpn_evpn`,
  `ipv4_flowspec` and `ipv6_flowspec`; the Adj-RIB-Out gauge starts every
  family at 0 for each registered peer.
- Max-prefix values: `scope="aggregate"` →
  `family="aggregate",stage="accepted"`; `scope="ipv4_unicast"` →
  `family="ipv4_unicast",stage="accepted"` (likewise `ipv6_unicast` and every
  non-unicast family);
  `scope="ipv4_unicast_received"` → `family="ipv4_unicast",stage="received"`
  and `scope="ipv6_unicast_received"` →
  `family="ipv6_unicast",stage="received"`.
- BGP-LS family values `bgpls` → `linkstate` and `bgpls_vpn` →
  `linkstate_vpn` on `bgp_exact_export_rejections_total`, the
  route-refresh gauges and the selection-deferral series. Selection-deferral
  and route-refresh series for families with no configuration label, such as
  multicast, report `unsupported`.
