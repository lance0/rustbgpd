### Fixed

- `slow_peer_threshold_pct` now measures writer bytes against the level at
  which outbound admission waits: the writer byte budget less one
  maximum-size UPDATE. Because admission stops before the full budget, a
  value above about 90 with Extended Messages, or about 99 without, could
  never start a slow-peer episode or isolation. A value of 100 now means the
  writer is byte-blocked. See the
  [neighbor reference](../docs/reference/configuration.md#neighbors).
