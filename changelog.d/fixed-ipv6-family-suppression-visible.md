### Fixed

- An eBGP session (other than a route-server client) that negotiates IPv6
  unicast but has no IPv6 next hop to advertise, typically IPv6 unicast over
  IPv4 transport without `local_ipv6_nexthop`, no longer withholds every IPv6
  unicast route silently.
  The session logs one WARN when it establishes and increments the new
  `bgp_export_family_suppressed_total{peer,family,reason}` counter
  (`family="ipv6_unicast"`, `reason="missing_ipv6_next_hop"`), and
  `rustbgpd --check` warns about static neighbors in that shape.
  **Operator-visible:** an injected IPv6 RTBH route toward such a peer still
  returns success from `AddPath`; set `local_ipv6_nexthop` and reload to
  export it. See the
  [next-hop self notes](../docs/reference/api.md#next-hop-self).
