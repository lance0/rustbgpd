### Fixed

- A connection that ended before Established no longer affects the next
  session on the same neighbor. A Cease/Hard Reset NOTIFICATION received or
  sent before Established, or another NOTIFICATION teardown there, disabled
  Graceful Restart retention when the next Established session later went
  down. The previous connection's NOTIFICATION also became the next session's
  BMP Peer Down reason, reported as a local NOTIFICATION instead of, for
  example, a remote close without one.
