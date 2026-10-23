### Added

- `ListConditionalAdvertisements` reports each attached neighbor as an
  `attached_neighbors` row, with a bare `peer_address` and the
  `peer_interface` of an IPv6 link-local neighbor. The bare-address
  `attached_peers` list is unchanged and now superseded.
  `rbgp policy conditional-advertisements` shows a link-local neighbor as
  `fe80::1%eth0`, and its `--json` output adds `attached_neighbors` beside
  `attached_peers`.
