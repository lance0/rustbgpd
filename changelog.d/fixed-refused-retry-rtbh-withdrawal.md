### Fixed

- During a GR selection hold, a private receiver whose recovery proof was
  refused in the same retry that advertised an RTBH route now counts that
  route. Its advertised count, the prefix limiter and the public advertised
  counts no longer report one row short for the rest of the hold, and an
  RTBH route deleted through the API is withdrawn inside the hold instead of
  dropping traffic until the hold released.
