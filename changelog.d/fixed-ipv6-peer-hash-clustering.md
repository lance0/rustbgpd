### Fixed

- Update-group per-source counters and the outbound grouping and
  export caches now hash IPv6 peer and next-hop addresses through the
  hasher's byte-string path, as IPv6 prefixes already do. Before this
  change, sequentially numbered IPv6 peers (`::1`, `::2`, ...) shared one
  hashbrown control byte and one starting bucket in those `FxHash` maps, so
  each lookup compared about half of the peers. IPv4 hash values are
  unchanged; no configuration, API, or wire behaviour changes.
