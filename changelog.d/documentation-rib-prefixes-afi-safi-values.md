### Documentation

- The `bgp_rib_prefixes` help text and the
  [operations reference](../docs/reference/operations.md) now name the
  `afi_safi` values the gauge actually carries: `all` is IPv4 and IPv6
  unicast combined, with each Add-Path path counted individually, and `evpn`
  and `flowspec` are those tables; there is no per-family series such as
  `ipv4_unicast`, so a selector for one matches nothing. The reference rows
  for `bgp_rib_loc_prefixes` and `bgp_rib_adj_out_prefixes` note that their
  `all` value is unicast too, and the example `BgpPeerAdjRibInEmpty` rule's
  comment no longer describes `all` as an aggregate across every family.
