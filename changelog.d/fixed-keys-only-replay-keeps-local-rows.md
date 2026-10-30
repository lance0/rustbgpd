### Fixed

- When a same-session replay during Graceful Restart selection deferral
  retires a receiver's advertised state, it now keeps the locally injected
  rows (RTBH and other API injections) with their routes and index, and
  drops only received rows. Release and recovery no longer leave a stale
  duplicate Add-Path RTBH path or an already deleted local route advertised
  in that case, and a replay that re-arms the peer's ORF gate no longer
  withdraws an advertised RTBH route before the peer refreshes.
