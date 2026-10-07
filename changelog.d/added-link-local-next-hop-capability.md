### Added

- Experimental Link-Local Next Hop capability 77 negotiation for explicitly
  interface-bound IPv6 link-local peers, following
  `draft-ietf-idr-linklocal-capability-06`. Opt in per neighbor or peer group
  with `link_local_next_hop = true` (default `false`); config load rejects it
  on a neighbor or dynamic range without an interface-bound link-local
  address, and a toggle resets the session to renegotiate OPEN. Negotiated
  IPv4 and IPv6 unicast can use a 16-byte link-local next hop; IPv4 also
  requires Extended Next Hop. Peers without the capability keep the legacy
  IPv4 encoding. This draft feature is outside the unicast v1 compatibility
  contract.
