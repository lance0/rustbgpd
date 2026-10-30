### Fixed

- An Add-Path receiver no longer briefly loses an RTBH path when another
  path for the same prefix is announced above it or deleted. Path IDs
  followed rank order, so these changes renumbered the RTBH path, and the
  transport's withdraw-first UPDATE order or a separate re-announcement
  left a window with no blackhole for that prefix. Each Add-Path update now
  also sends its blackholing rows before any ordinary row, so a receiver
  that kept our routes across a session flap never sees an ordinary path
  replace its RTBH path first. A path that starts carrying BLACKHOLE (a
  received update or export policy) in the same pass as an RTBH path is
  deleted takes over that path's ID in place.
