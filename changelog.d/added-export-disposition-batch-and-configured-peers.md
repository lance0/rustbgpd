### Added

- `InjectionService.BatchListPathExportDispositions` reads the export
  dispositions of up to 1000 locally injected unicast route keys per paged
  walk. It lists keys in request order, and a key with no local route when
  its page is read appears with `found = false` instead of the call failing
  with `NOT_FOUND`. A page holds at most `page_size` entries: each peer row is
  one, so one key's rows can span several pages. Each entry costs at most one
  export explain. A resumed page returns `ABORTED` when any named key's route
  content or presence, the Established peer set or their export policy
  differs from the first page. A route added and removed again between pages
  is not detected. See
  [batch read-back](../docs/reference/api.md#batch-read-back).
- `ListPathExportDispositions` and the batch form take `include_configured`.
  It also lists every managed peer without an Established session, with the
  new disposition `PATH_EXPORT_DISPOSITION_NOT_ESTABLISHED` and reason
  `not_established`, so a controller no longer joins the result with
  `ListNeighbors`. A neighbor added or removed between pages, or a listed peer
  becoming Established, returns `ABORTED`.
