### Upgrade notes

- `NeighborService` gains additive fields (`NeighborConfig.remote_asn_mode`,
  `NegotiatedSessionState.remote_asn`, `NeighborState.learned_peer_address`
  and `discovery_state`), an amendment to the pinned pre-v1 stable-surface
  inventory. An unset `remote_asn_mode` means `NUMERIC`, so existing clients
  keep their behavior. A neighbor configured with `remote_asn = "external"`
  or `"internal"` reads `remote_asn = 0` with the mode set; read the session's
  ASN from `negotiated_session.remote_asn`. `ListNeighbors` can return
  interface-only neighbors with an empty `config.address`, including rows with
  no session before an address is learned; a client that keys rows on the
  address alone must key on the interface for those rows. `rbgp neighbor ARG`
  treats an argument that is not an IP address as an interface name.
