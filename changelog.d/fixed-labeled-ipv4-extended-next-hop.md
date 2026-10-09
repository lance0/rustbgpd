### Fixed

- Labeled IPv4 (AFI 1 / SAFI 4) routes with an IPv6 next hop are no longer
  advertised to peers that did not negotiate Extended Next Hop for that
  family (RFC 8950 tuple 1/4/2). A route received with an IPv6 next hop, or
  given one by an export `set next-hop`, went out with a 16-octet next hop
  regardless. rustbgpd does not advertise 1/4/2, so such a route is now
  withheld from every peer and counted in
  `bgp_exact_export_rejections_total{reason="ipv4_requires_extended_next_hop"}`,
  as for VPNv4.
  **Operator-visible:** inbound, a labeled-IPv4 `MP_REACH_NLRI` with a 16- or
  32-octet next hop is now malformed (RFC 7606 §7.11) and resets the session
  with UPDATE Message Error / Optional Attribute Error, the same handling as
  IPv4 unicast without Extended Next Hop. Earlier releases accepted and
  reflected such routes. See
  [RFC 8950 notes](../docs/reference/rfc-notes.md#rfc-8950--extended-next-hop).
