### Added

- The `vpnv4-flowspec` policy family matches local IPv4 VPN FlowSpec rules
  separately from global `ipv4-flowspec` and `ipv6-flowspec` rules. Existing
  extended-community actions can add and strip route targets, and
  `NO_ADVERTISE` is honored before and after export policy evaluation.
  The new family remains outside the v1 inventory under
  [ADR-0146](../docs/adr/0146-vpn-flowspec.md).
- `bgp_rib_prefixes{peer="0.0.0.0",family="l3vpn_ipv4_flowspec"}` reports
  locally injected VPN FlowSpec rules separately from global rules, including
  deletion and lease expiry. `bgp_rib_loc_prefixes` retains its separate VPN
  family count. Controller API injection support is a later slice; received
  VPN FlowSpec remains decoded and discarded.
