### Fixed

- `SetPeerGroup` without an MD5 password reads the existing group to keep
  its password, and that read now uses the 2-second peer-manager read bound
  that `GetPeerGroup` uses instead of the 10-minute mutation bound. A
  stalled peer manager now fails the request after 2 seconds with
  `DEADLINE_EXCEEDED` and nothing applied, instead of holding the
  runtime-config lock, and every other config mutation, for up to 10
  minutes. The config persister's writes, fsyncs and renames also moved
  off the async runtime worker threads, so a hung config filesystem no
  longer ties up one of those threads.
