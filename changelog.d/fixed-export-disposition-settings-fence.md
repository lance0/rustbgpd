### Fixed

- A paged `ListPathExportDispositions`, `BatchListPathExportDispositions` or
  `ListFlowSpecExportDispositions` walk now returns `ABORTED` when a listed
  peer's export settings change between pages without a session reset: its
  outbound prefix limits, an attached conditional advertisement, its peer
  group, its Add-Path send limits, a withheld family becoming exportable,
  its ORF filter or gate, or its session's outbound encoding profile. Before,
  a walk spanning such a reload could mix rows from before and after it.
  Rewriting a setting to its current value does not abort a walk. See
  [export read-back](../docs/reference/api.md#export-read-back).
