### Added

- Interface-only neighbors are labelled `peer="interface:<name>"` in every
  per-peer metric family, with `interface="<name>"` on the identity gauges.
  The value, and the neighbor's counters, carry across a change of learned
  address, carrier loss and interface removal; removing the neighbor's stanza
  removes them. New families: `bgp_unnumbered_peer_address_info{peer,
  interface,address}` (the bound address), `bgp_unnumbered_address_changes_total`,
  `bgp_unnumbered_ra_conflicts_total` (a second router seen on the link, from a
  Router Advertisement or an inbound connection),
  `bgp_unnumbered_ra_dropped_total{reason}` and
  `bgp_unnumbered_ra_socket_open_failures_total`. See
  [Interface-only neighbor metrics](../docs/reference/operations.md#interface-only-neighbor-metrics).
  **Operator-visible:** the `PeerAdded` and `PeerRemoved` session events of an
  interface-only neighbor's endpoint end with the reason
  (`peer_address_learned`, `peer_address_changed`, `link_down`,
  `interface_removed` or `session_exited`), and the daemon logs
  `unnumbered: peer address changed` when it binds a new address.
