### Added

- `InjectionService.BatchListFlowSpecExportDispositions` reads the per-peer
  export dispositions of up to 1000 locally injected FlowSpec rules, global
  or VPN, in one paged walk, as `BatchListPathExportDispositions` does for
  unicast keys. A key with no local rule is listed with `found = false`
  instead of failing the call; an empty, oversized or duplicate key list, or
  a malformed key, returns `INVALID_ARGUMENT` naming the key's index. Each
  page reads its keys in one RIB turn, and a resumed page returns `ABORTED`
  when any listed rule changed. The RPC is a `sensitive_read`, like the
  single-key `ListFlowSpecExportDispositions`, and this diagnostic RPC is
  outside v1. Clients need a daemon newer than v0.82.0; older daemons return
  `UNIMPLEMENTED`. See
  [FlowSpec batch read-back](../docs/reference/api.md#flowspec-batch-read-back).
