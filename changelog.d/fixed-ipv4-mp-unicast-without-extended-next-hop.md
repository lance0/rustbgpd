### Fixed

- IPv4-unicast `MP_UNREACH_NLRI` withdrawals and `MP_REACH_NLRI`
  announcements with a 4-octet IPv4 next hop are now applied on sessions that
  did not negotiate Extended Next Hop (RFC 4760, RFC 8950 §4). Previously both
  were ignored with a log line, so a peer that withdrew IPv4 routes this way
  left them in the Adj-RIB-In, and a route server kept advertising them until
  the session reset.
  **Operator-visible:** an IPv6 next hop on IPv4-unicast NLRI without
  negotiated Extended Next Hop is now a malformed `MP_REACH_NLRI` and resets
  the session with UPDATE Message Error / Optional Attribute Error
  (RFC 7606 §7.11), counted in `bgp_update_malformed_total`. Previously the
  UPDATE was ignored with a log line. A peer that sends that form without the
  capability, such as GoBGP or ExaBGP over IPv6 transport to a neighbor
  configured for IPv4 unicast only, now has its session reset; see
  [the RFC notes](../docs/reference/rfc-notes.md#rfc-8950--extended-next-hop).
