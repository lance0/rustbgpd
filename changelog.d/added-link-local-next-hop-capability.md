### Added

- Experimental Link-Local Next Hop capability 77 negotiation for explicitly
  interface-bound IPv6 link-local peers, following
  `draft-ietf-idr-linklocal-capability-06`. Negotiated IPv4 and IPv6 unicast
  can use a 16-byte link-local next hop; IPv4 also requires Extended Next Hop.
  Reflected link-local next hops require matching interface scope or a rewrite.
  Legacy unnegotiated IPv4 encoding remains available. This draft feature is
  outside the unicast v1 compatibility contract.
