### Added

- `InjectionService.BatchListPathExportDispositions` reads the export
  dispositions of up to 1000 locally injected unicast routes in one paged
  walk. It lists keys in request order, and each key appears with
  `found = false` instead of the call failing with `NOT_FOUND`. A page holds at
  most `page_size` entries, and each costs at most one export explain. A
  change to any named key's route, the Established peer set or their export
  policy between pages returns `ABORTED`. See
  [batch read-back](../docs/reference/api.md#batch-read-back).
- `ListPathExportDispositions` and the batch form take `include_configured`.
  It also lists every managed peer without an Established session, with the
  new disposition `PATH_EXPORT_DISPOSITION_NOT_ESTABLISHED` and reason
  `not_established`, so a controller no longer joins the result with
  `ListNeighbors`. A neighbor added or removed between pages, or a listed peer
  becoming Established, returns `ABORTED`.
