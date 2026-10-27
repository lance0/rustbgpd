### Changed

- After a planned restart, Graceful Restart selection deferral waits only
  for eligible peers that have re-established a session. A configured
  neighbor that stays down no longer holds selection for the full restart
  window. The existing marker-derived upper bound remains.
- Activating a hold preserves each current session's admitted routes while
  RTBH updates continue. Missing initial routes replay before End-of-RIB
  after release, and conditional advertisement settling restarts with its
  full interval. Controller replay grace remains a separate completion gate.
- Neighbor diagnostics distinguish dormant startup rosters from released
  selection-deferral families.
