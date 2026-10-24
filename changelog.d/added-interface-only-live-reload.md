### Added

- Interface-only `[[neighbors]]` (`interface` with no `address`) now reload
  live. SIGHUP and config transactions add, delete and edit them, including
  `remote_asn = "external"`/`"internal"` and peer-group membership, and the
  other neighbors keep their sessions. A deleted neighbor's session ends, its
  routes are purged and the learned address it held is released. An edited
  one is rebound under the new settings. The change that adds the first such
  neighbor is refused before any effect without `CAP_NET_RAW`, and removing
  the last one closes the Router Advertisement sockets. `[global.unnumbered]`
  and a neighbor's effective `tcp_mss` stay restart-required. See the
  [reload matrix](../docs/reference/reload-matrix.md#interface-only-neighbors).
  **Operator-visible:** `rustbgpd --diff --json` reports
  `interface_only_neighbors_changed` under `reload_applied` and the new
  `unnumbered_changed` under the restart-required keys, and counts a rebound
  interface-only neighbor in `summary.sessions_will_reset`.
