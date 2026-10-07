### Fixed

- `SetPeerGroup` no longer clears peer-group fields its definition does not
  carry. Previously a gRPC edit (or a peer-group change applied by a SIGHUP
  reload on the sequential route) reset `role`, `strict_role`,
  `prefix_orf_receive`, `disable_ipv4_unicast`, the slow-peer, per-family,
  received and outbound prefix limits, `max_prefix_action`,
  `max_prefix_warning_percent`, `next_hop_ownership`, `interpret_rfc1997`,
  `rs_control_communities`, `send_non_transitive_extended_communities` and
  `log_level` on the group and reshaped its members without them; a gRPC
  edit also persisted the loss to the configuration file. These fields now
  keep their configured values.
