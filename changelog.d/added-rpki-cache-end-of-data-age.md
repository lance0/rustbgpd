### Added

- `bgp_rpki_cache_end_of_data_age_seconds{cache}` reports the seconds since
  each configured RTR cache's last accepted End of Data, computed at scrape
  time from the daemon's monotonic clock, so it matches the age
  `rbgp rpki caches` shows. The series appears with the first End of Data,
  keeps advancing through an ordinary disconnect while the contribution is
  retained, restarts on each new End of Data, and is removed on a flush or
  expiry. The shipped `RpkiCacheDataNearExpiry` alert (warning) fires when
  less than a quarter of `bgp_rpki_cache_effective_expire_seconds` remains
  before the retained data expires, for a disconnected cache and for a
  connected session that stopped refreshing.
