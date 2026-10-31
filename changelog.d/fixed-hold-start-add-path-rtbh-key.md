### Fixed

- When Graceful Restart selection deferral starts, an Add-Path receiver
  that already holds an RTBH path and an ordinary path for one prefix keeps
  both at their path IDs. Previously the RTBH path was renumbered in one
  update whose withdrawal went out before its re-announcement, briefly
  leaving the prefix without a blackhole, and the ordinary path was
  overwritten before selection resumed. During the hold, Add-Path path IDs
  stay put; a new RTBH path reuses a departing path's ID or, at the send
  limit, takes over a held ordinary path's ID.
