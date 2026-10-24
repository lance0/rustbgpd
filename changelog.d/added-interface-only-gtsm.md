### Added

- `ttl_security` (GTSM, RFC 5082) is accepted on interface-only neighbors.
  When the neighbor binds a learned address, the BGP listener enforces Hop
  Limit 255 on connections from that address on that interface before the
  peer can be matched for inbound, and removes the selector only after that
  endpoint's peer is retired. A connection learned from an inbound SYN gets
  the same check, and active opens send Hop Limit 255. The IPv6 listener
  answers with Hop Limit 255 from startup, or from the reload or config
  transaction that introduces interface-only GTSM, before the neighbor can
  bind, and never lowers it; a GTSM peer that sends no RAs and dials in is
  therefore learned. Turning `ttl_security` on or off reloads as a session
  settings edit, and a deleted neighbor's selector is removed after its peer.
  A connection accepted under a selector that a reload has since turned off
  has its Hop Limit minimum cleared before the new session takes it.
  The selector matches by address and interface, so it never applies to a
  neighbor on another link that shares the address. `ttl_security_hops` above 1 is rejected,
  since the peer is directly connected. See
  [Interface-only neighbors](../docs/reference/configuration.md#interface-only-neighbors).
