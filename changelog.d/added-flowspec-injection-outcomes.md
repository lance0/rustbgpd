### Added

- `InjectionService.AddFlowSpec` now reports whether the local rule was
  `CREATED`, `REPLACED` or `UNCHANGED`, compared with the previous locally
  injected rule for the same `(afi_safi, components)` key.
  `DeleteFlowSpec` reports `DELETED` or `NOT_PRESENT` and gains an opt-in
  `allow_missing` request field: a missing local rule then returns `OK` with
  `NOT_PRESENT` instead of `NOT_FOUND`, which remains the default. The proto
  and the
  [API reference](../docs/reference/api.md#flowspec-injection-contract) now
  document the upsert and delete semantics, the `0.0.0.0` local-injection
  sentinel, and reconciliation through `ListFlowSpecRoutes` with
  `received_peer_address: "0.0.0.0"`. `rbgp flowspec add` prints the outcome
  and adds an `outcome` key to its `--json` result. `rbgp flowspec delete`
  gains `--allow-missing`, which reports a missing rule as not present with
  exit status 0, and its `--json` result gains an `outcome` key. The fields
  are additive; these RPCs remain outside the v1 inventory.
