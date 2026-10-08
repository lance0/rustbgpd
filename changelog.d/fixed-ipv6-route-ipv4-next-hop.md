### Fixed

- An IPv6 unicast route is no longer advertised with a 4-octet next hop in
  `MP_REACH_NLRI`; RFC 2545 §3 requires 16 or 32 octets. A receiver may reject
  such a route, treat it as withdrawn, or, as FRR 10.7.1 does, install it with
  an unusable `::` next hop. Import `next-hop self` on a session over IPv4
  transport, or an import or export `set next-hop` with an IPv4 address, could
  give an IPv6 route an IPv4 next hop that iBGP and route-server-client
  exports sent as is. Import `next-hop self` for an IPv6 route now resolves to
  the session's local IPv6 address, else `local_ipv6_nexthop`, and otherwise
  keeps the received next hop. An IPv4 `set next-hop` no longer applies to an
  IPv6 unicast route, matching FRR's `set ip next-hop`.
  **Operator-visible:** see
  [route modifications](../docs/reference/configuration.md#route-modifications-set-actions).
  Export withholds any remaining IPv6 route with an IPv4 next hop from the
  peer and counts it in
  `bgp_exact_export_rejections_total{reason="missing_ipv6_next_hop"}`.
