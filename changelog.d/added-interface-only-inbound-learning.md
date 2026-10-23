### Added

- An interface-only neighbor now also learns its peer's link-local address
  from the peer's BGP connection arriving on its interface, so a peer that
  sends no Router Advertisements (FRR with `no bgp ipv6-auto-ra` and a static
  `neighbor fe80::…%eth1`) establishes instead of waiting for discovery
  indefinitely. The connection is matched by its arrival interface, never by
  address, binds through the same `duplicate_link_local_address` check as an
  RA binding, and is accepted only while the neighbor has no Established
  session ([ADR-0142](../docs/adr/0142-interface-only-unnumbered-neighbors.md)).
  **Operator-visible:** a learned connection is no longer dropped as
  `unconfigured`; the log records `unnumbered: peer address learned from an
  inbound connection`. A refused one is still counted in
  `bgp_inbound_connections_dropped_total`, as `notification_backoff` when the
  neighbor's NOTIFICATION reconnect wait holds it and as `unconfigured`
  otherwise, and a connection from a second router on the link is logged
  with reason `multiple_routers_on_link`.
