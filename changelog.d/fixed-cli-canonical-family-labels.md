### Fixed

- `rbgp` prints the canonical configuration family label for every address
  family in event, watch, FlowSpec and RIB output. BGP-LS families now print
  `linkstate` and `linkstate_vpn` instead of `bgp_ls` and `bgp_ls_vpn`, and
  EVPN, L3VPN, labeled-unicast and RT-Constrain families print their labels
  instead of `unknown`. **Operator-visible:** scripts matching `bgp_ls`,
  `bgp_ls_vpn` or `unknown` in `afi_safi` output must match the canonical
  labels.
