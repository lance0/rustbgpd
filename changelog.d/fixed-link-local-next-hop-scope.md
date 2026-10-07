### Fixed

- A unicast route whose outbound next hop is an IPv6 link-local address is
  no longer advertised outside the link it was learned on. This applies
  whether or not Link-Local Next Hop capability 77 is configured or
  negotiated. The route is still sent to an interface-bound peer on the same
  interface, or when the next hop is rewritten to a local address (next-hop
  self or `local_ipv6_nexthop`). Previously, IPv4 routes carried over Extended
  Next Hop were reflected between unnumbered peers on different interfaces,
  and a policy `set next-hop` to a link-local address reached peers on other
  links, with a next hop those peers cannot reach. An IPv6 unicast route whose
  only next hop is link-local now also requires capability 77.
  **Operator-visible:** each withheld route increments
  `bgp_exact_export_rejections_total{reason="missing_ipv6_next_hop"}` and logs
  a WARN with detail `link-local next hop cannot be advertised outside its
  interface scope`; a route previously advertised to that peer is withdrawn.
