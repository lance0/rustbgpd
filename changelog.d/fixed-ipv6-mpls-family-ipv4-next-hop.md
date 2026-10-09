### Fixed

- IPv6 labeled-unicast and VPNv6 routes are no longer advertised with an IPv4
  next hop. An export `set next-hop` with an IPv4 address, typical of an
  export policy shared by IPv4 and IPv6 peers, gave these routes a 4-octet
  next hop under AFI 2 / SAFI 4, which receivers reject as malformed
  (RFC 8277), or a 12-octet RD + IPv4 next hop under AFI 2 / SAFI 128, which
  RFC 4659 does not define. An IPv4 `set next-hop` now does not apply to any
  route with IPv6 NLRI, as already for IPv6 unicast, and explain reports the
  route's kept next hop.
  **Operator-visible:** see
  [route modifications](../docs/reference/configuration.md#route-modifications-set-actions).
  Export withholds any remaining labeled-IPv6 or VPNv6 route with an IPv4 next
  hop, including a VPNv6 route received with a 12-octet next hop, and counts
  it in `bgp_exact_export_rejections_total{reason="missing_ipv6_next_hop"}`.
