### Fixed

- An Add-Path receiver no longer briefly loses an RTBH path when another
  path for the same prefix is announced above it or deleted. Path IDs
  followed rank order, so these changes renumbered the RTBH path, and the
  transport's withdraw-first UPDATE order or a separate re-announcement
  left a window with no blackhole for that prefix.
