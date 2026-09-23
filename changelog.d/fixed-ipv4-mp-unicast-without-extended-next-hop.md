### Fixed

- IPv4-unicast `MP_UNREACH_NLRI` withdrawals and `MP_REACH_NLRI`
  announcements with a 4-octet IPv4 next hop are now applied on sessions that
  did not negotiate Extended Next Hop (RFC 4760, RFC 8950 §4). Previously both
  were ignored with a log line, so a peer that withdrew IPv4 routes this way
  left them in the Adj-RIB-In, and a route server kept advertising them until
  the session reset. An IPv6 next hop on IPv4-unicast NLRI without Extended
  Next Hop is now treat-as-withdraw with Invalid NEXT_HOP and counted in
  `bgp_update_malformed_total`, instead of being dropped with only a log line;
  see [the RFC notes](../docs/reference/rfc-notes.md#rfc-8950--extended-next-hop).
