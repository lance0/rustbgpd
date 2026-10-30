### Changed

- The guarded FlowSpec mutation contract
  ([ADR-0144](../docs/adr/0144-guarded-flowspec-mutations.md)) moves into the
  v1 inventory: `IssueMutationWindow`, `AddGuardedFlowSpec`,
  `DeleteGuardedFlowSpec` and `RenewGuardedLease`, the `admission_revision`
  read-back on `FlowSpecRouteEntry` and `LeasedKey`, and the
  `guarded:<owner>` name in lease listings. They were outside the v1
  inventory when added. The contract pins window-checked commits, the
  window cap on the lease deadline, revision-fenced adds and deletes, the
  guarded owner namespace and the definitive refusal statuses. Like the
  FlowSpec controller boundary, it pins the API shape only; forwarding,
  timing after controller loss and GR/LLGR retention stay outside the
  guarantee. See the
  [v1 contract](../docs/reference/v1-stable-contract.md#guarded-flowspec-mutations).
