### Fixed

- With RFC 8950 Extended Next Hop negotiated, IPv4 unicast routes whose next
  hop is an IPv4 address, and all IPv4 unicast withdrawals, are now sent in the
  classic UPDATE body (`NEXT_HOP` plus NLRI, and Withdrawn Routes) instead of
  `MP_REACH_NLRI` / `MP_UNREACH_NLRI`. Routes with an IPv6 next hop still use
  `MP_REACH_NLRI`, and scoped link-local (unnumbered) sessions keep the MP form
  for everything. OpenBGPD 9.2 resets the session with UPDATE Message Error /
  Optional Attribute Error (3/9) on an IPv4 unicast `MP_REACH_NLRI` with a
  4-octet next hop and on any IPv4 unicast `MP_UNREACH_NLRI`, so a route server
  passing a member's IPv4 next hop through, or withdrawing any IPv4 route,
  flapped an OpenBGPD member that enabled `announce extended nexthop`. Both
  encodings are valid under RFC 4760 and RFC 8950 §3.
  **Operator-visible:** UPDATE wire encoding to Extended Next Hop peers changes
  as described; received routes and session behavior are otherwise unchanged.
