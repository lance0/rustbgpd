### Fixed

- During Graceful Restart selection deferral, an ordinary injected unicast
  route that a peer already held before the hold now reads back as
  `COMMITTED` in `ListPathExportDispositions`, and `ExplainAdvertisedRoute`
  shows that frozen row instead of `no_best_route`. A route not yet
  admitted, or changed since, still reports `selection_deferred`. When a held
  receiver's recovery proof is refused, an export-policy change that denies
  a still-injected RTBH route now withdraws it, as delete, expiry and
  BLACKHOLE removal already did; an RTBH path that only moves to another
  Add-Path rank stays advertised. See the
  [injection contract](../docs/reference/api.md#unicast-injection-contract).
