### Added

- The neighbor API carries the configured `remote_asn` mode and the session's
  actual ASN. `NeighborConfig.remote_asn_mode` (`NUMERIC`, `EXTERNAL`,
  `INTERNAL`) round-trips `remote_asn = "external"` and `"internal"`: reads
  report `remote_asn = 0` for a non-numeric mode, and `AddNeighbor` requires
  0 with one. `NegotiatedSessionState.remote_asn` reports the ASN the peer
  sent. Interface-only neighbors are listed by interface, with an empty
  `address`, `learned_peer_address` and `discovery_state`, including before an
  address is bound, and an empty address with an `interface` selects one. See
  the [API reference](../docs/reference/api.md#remote-asn-mode-and-the-session-asn).
  **Operator-visible:** `rbgp neighbor <addr> add --remote-asn` accepts
  `external` and `internal`; `rbgp neighbor swp1` selects an interface-only
  neighbor; tables show `swp1 (fe80::2)` (or `swp1 (-)` until bound) and the
  configured mode in the ASN column; detail adds `Learned Address`,
  `Discovery`, and the session ASN beside a non-numeric mode; JSON adds
  `remote_asn_mode`, `learned_peer_address`, `discovery_state` and
  `negotiated_session.remote_asn`.
