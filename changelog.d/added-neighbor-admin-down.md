### Added

- Neighbors and peer groups accept `admin_down = true`, with an optional RFC
  9003 `admin_down_reason` of at most 128 bytes, to keep a configured neighbor
  administratively down across restarts without deleting it. The peer is added
  disabled: it makes no connection attempts, refuses inbound connections,
  reads 0 in `bgp_peer_admin_enabled`, and stays listed in `rbgp neighbor`. On
  `SIGHUP`, setting the key sends Cease/Administrative Shutdown with the
  reason and clearing it enables the peer. The runtime
  `rbgp neighbor <addr> enable|disable` toggle stays transient and holds until
  a restart or a reload that changes the key. `admin_down` is rejected on a
  peer group referenced by `[[dynamic_neighbors]]`. `rbgp config import` maps
  BIRD `disabled`, FRR `neighbor X shutdown [message ...]` and GoBGP
  `admin-down` to the new key. See
  [Administrative down](../docs/reference/configuration.md#administrative-down-admin_down).
