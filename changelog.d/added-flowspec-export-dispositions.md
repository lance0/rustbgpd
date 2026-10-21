### Added

- `InjectionService.ListFlowSpecExportDispositions` reports the per-peer
  export disposition of one locally injected FlowSpec rule, named by its
  `AddFlowSpec` key, with the rows, reasons, `include_configured`, paging and
  `ABORTED` check of `ListPathExportDispositions`. A received rule with the
  same key never counts as the local rule's export. The RPC is a
  `sensitive_read`, and this new diagnostic RPC is outside v1. See
  [FlowSpec read-back](../docs/reference/api.md#flowspec-read-back).
