### Fixed

- Replace linear per-key Add-Path index searches with logarithmic lookups
  for IPv4/IPv6 unicast, VPN and labeled unicast. A single path remains
  inline. LLGR session cycling can still retain IDs beyond the current
  session's receive cap until End-of-RIB or the original stale deadline;
  this change bounds index work without changing retention or adding a cap.
- Keep retirement checkpoints and covered-prefix validation continuation
  bounded when a prefix holds many Add-Path IDs.
