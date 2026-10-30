### Added

- Guarded FlowSpec mutations
  ([ADR-0144](../docs/adr/0144-guarded-flowspec-mutations.md)):
  `InjectionService` gains `IssueMutationWindow`, `AddGuardedFlowSpec`,
  `DeleteGuardedFlowSpec` and `RenewGuardedLease`. A guarded add or renewal
  commits only inside a server-issued mutation window (at most 120 s; 64
  live windows per owner). A guarded add never shortens the owner's lease:
  it caps any extension at its window and keeps a later deadline set under
  another window. A guarded renewal sets the lease to exactly
  `now + lease_seconds`, capped at its window, so it can shorten the lease
  of every rule the owner holds. The owner's lease
  never outlives the latest-expiring window it used, so a request delayed
  before its handler, in the RIB queue or behind RIB work cannot revive a
  diversion after the owner's windows end; a controller reads the deadline
  back rather than inferring it from one window. Each guarded add carries
  a nonzero revision, and a guarded delete removes the rule only at its
  revision, so a late delete cannot remove a newer admission of the same
  key. Guarded owners live in their own namespace, reported as
  `guarded:<owner>`, which the leased and unleased methods cannot reach;
  `DeleteFlowSpec` with `override_owner` stays the break-glass. Read-back
  adds `admission_revision` to `FlowSpecRouteEntry` and `LeasedKey`, and
  `ListLeasedKeys` accepts a guarded owner name. All four methods are
  `operator_only`; successful window issues and guarded renewals audit at
  INFO. The methods and fields are outside the v1 contract; see
  [guarded FlowSpec mutations](../docs/reference/api.md#guarded-flowspec-mutations).
  **Operator-visible:** a controller treats `DEADLINE_EXCEEDED`,
  `UNAVAILABLE` or a dropped connection as an unknown outcome and resolves
  it by reading the revision back, never by retrying through the legacy
  methods.
