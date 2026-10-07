### Fixed

- An IPv4 unicast route whose import policy sets `next-hop self` (or an IPv6
  next hop) is now advertised to iBGP peers and route-server clients with the
  next hop the import chose. Previously such peers received the address the
  route arrived with, while the RIB, FIB and `rbgp rib` used the rewritten
  one; with Extended Next Hop negotiated the route also fell back to a
  4-octet IPv4 `MP_REACH_NLRI`. eBGP and export-policy next-hop rewrites were
  not affected.
  **Operator-visible:** after upgrading, passthrough peers of such routes see
  the import-chosen next hop. A body IPv4 route given an IPv6 next hop on
  import is no longer exported to a passthrough peer without Extended Next
  Hop, matching routes received with an IPv6 next hop.
