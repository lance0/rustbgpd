### Changed

- `bgp_export_family_suppressed_total{peer,family,reason}` joins the v1
  route-server and route-reflector metric floor, with its current values
  `family="ipv6_unicast"` and `reason="missing_ipv6_next_hop"` pinned. Further
  bounded `family` and `reason` values are additive. Its help text and
  reference now say what it counts: session establishments at which a family
  was withheld, not sessions that withhold it throughout, since a reload that
  supplies `local_ipv6_nexthop` restores export without a session reset. See
  the [v1 contract](../docs/reference/v1-stable-contract.md).
