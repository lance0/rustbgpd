### Changed

- The RIB now keys FlowSpec rules by family and Route Distinguisher, so an
  IPv4 VPN FlowSpec rule (`l3vpn_ipv4_flowspec`, SAFI 134) and a global rule
  with the same components are distinct, and each RD is its own rule. VPN
  rules are distributed only to peers that negotiated the family, as SAFI 134
  with their RD, and are never mixed into a SAFI 133 UPDATE, checked by RFC
  9117 validation or gated by RT-Constrain. A neighbor configured with
  `l3vpn_ipv4_flowspec` now lists it in its Graceful Restart and LLGR
  capabilities when those are enabled, as for `ipv4_flowspec`.
  `bgp_rib_loc_prefixes` and `bgp_rib_adj_out_prefixes` report the family
  apart from `ipv4_flowspec`. Rules still cannot be injected until the
  controller API ships ([ADR-0146](../docs/adr/0146-vpn-flowspec.md)).
