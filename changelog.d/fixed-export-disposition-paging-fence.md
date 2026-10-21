### Fixed

- A paged `ListPathExportDispositions` walk no longer resumes across a change
  that makes its pages disagree. When the route is removed or replaced, or a
  peer joins, leaves or flaps out of the Established set between pages, the
  next page returns `ABORTED` and the client restarts the walk. Previously a
  route deleted mid-walk returned the same `NOT_FOUND` as a key that never
  existed, and a session change could skip or repeat a peer. The page token
  is now opaque and bound to the route key and daemon process: a token for
  another key, an altered token or one from before a restart returns
  `INVALID_ARGUMENT`. See
  [export read-back](../docs/reference/api.md#export-read-back).
