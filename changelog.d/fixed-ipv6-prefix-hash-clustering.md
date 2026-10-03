### Fixed

- IPv6 prefixes now hash their address bytes through the hasher's
  byte-string path. Before this change, sequential /128 and /64 prefixes
  shared one hashbrown control byte and few starting buckets in the RIB's
  `FxHash` maps, so each Loc-RIB lookup compared many candidate keys. Hash
  values change; no configuration, API, or wire behaviour changes.
