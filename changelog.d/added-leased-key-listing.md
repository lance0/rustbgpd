### Added

- `InjectionService.ListLeasedKeys` lists the injected keys one lease owner
  holds, as the keys `DeletePath` and `DeleteFlowSpec` take, with each key's
  lease generation and remaining time, paged in a fixed key order. Another
  owner's keys and unowned entries never appear. A controller that restarts
  while the daemon runs can now keep exactly the keys it still wants and
  delete the rest. Each page names the owner's live generation, absent when
  it has no live lease, and a walk that crosses a daemon restart or a new
  generation returns `ABORTED` instead of finishing early. It is a
  `sensitive_read` in the v1 inventory with the rest of the lease
  lifecycle. See [reconcile an owner's keys](../docs/reference/api.md#reconcile-an-owners-keys).
