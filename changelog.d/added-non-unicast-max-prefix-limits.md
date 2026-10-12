### Added

- Neighbors and peer groups accept per-family inbound limits for the
  non-unicast families a route reflector carries:
  `max_prefixes_l3vpn_ipv4_unicast`, `max_prefixes_l3vpn_ipv6_unicast`,
  `max_prefixes_ipv4_labeled_unicast`, `max_prefixes_ipv6_labeled_unicast`,
  `max_prefixes_l2vpn_evpn`, `max_prefixes_ipv4_flowspec`,
  `max_prefixes_ipv6_flowspec` and `max_prefixes_rtc`. Each bounds the unique
  routes accepted in its family, with Add-Path paths of one route collapsed,
  independently of the aggregate `max_prefixes` and of every other family, so
  a VPN leak can be capped without capping the peer's EVPN routes.
  `max_prefix_action` applies per family: `shutdown` sends Cease/1 carrying the
  RFC 4486 AFI, SAFI and bound, `block` withholds net-new routes of that family
  while the session stays Established, and `warning` reports. The keys
  hot-apply on reload. `bgp_max_prefix_usage`, `bgp_max_prefix_limit`,
  `bgp_max_prefix_headroom` and `bgp_max_prefix_blocking` gain the family
  label as a `scope` value while the bound is set. See the
  [neighbor reference](../docs/reference/configuration.md).
