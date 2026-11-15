### Fixed

- Pace export-policy reload and rollback for changed residual peers with no
  currently sendable address family. These peers can still enumerate the
  routing table during regrouping; their work now uses the existing paced
  commands. One peer's full-table operation remains a single actor turn.
