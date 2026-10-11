### Changed

- Compatible, already queued unicast route-refresh requests share one bounded
  replay inventory and announcement encoding. Each peer retains its own source
  exclusion, export checks, prefix limits, refresh markers and retry state.
