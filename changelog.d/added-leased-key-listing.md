### Added

- `InjectionService.ListLeasedKeys` lists the injected keys one lease owner
  holds, as the keys `DeletePath` and `DeleteFlowSpec` take, with each key's
  lease generation and remaining time, paged in a fixed key order. Another
  owner's keys and unowned entries never appear. A controller that restarts
  while the daemon runs can now keep exactly the keys it still wants and
  delete the rest. It is a `sensitive_read` and outside the v1 inventory for
  now. See
  [reconcile an owner's keys](../docs/reference/api.md#reconcile-an-owners-keys).
