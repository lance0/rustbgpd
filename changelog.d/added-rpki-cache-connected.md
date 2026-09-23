### Added

- `bgp_rpki_cache_connected{cache}` reports whether the daemon has an RTR
  session to each configured cache (`1` connected, `0` otherwise, seeded at
  `0`). A lost session keeps its retained contribution until the effective
  expire (default 7200 seconds, up to two days), so
  `bgp_rpki_cache_end_of_data_ready` and `bgp_rpki_vrp_count` stay unchanged
  and the existing alerts fired only after expiry. The shipped
  `RpkiCacheDisconnected` alert (warning, 15 minutes at `0`) and a
  daemon-side `rbgp doctor` check, `rpki.cache.<addr>.session`, read from
  `ListCaches`, now report the outage while the retained data is still in
  use. See [RPKI cache unreachable](../docs/reference/operations.md#rpki-cache-unreachable).
