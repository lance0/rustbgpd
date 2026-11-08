### Fixed

- Settle the RIB actor, synthetic peers, handshakes, collectors and transport
  sessions before the rrtransport smoke harness exits, including failed runs.
  Unexpected task panics and shutdown errors now fail the run; ordinary smoke
  reports success only after cleanup completes. Wire checks, deadlines and
  resource thresholds are unchanged.
