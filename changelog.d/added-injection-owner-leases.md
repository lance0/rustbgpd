### Added

- Owner-scoped leases on injected routes and FlowSpec rules
  ([ADR-0141](../docs/adr/0141-injection-owner-lease.md)), so a stopped
  controller's state expires instead of living until the daemon restarts.
  `InjectionService.AddLeasedPath` and `AddLeasedFlowSpec` add under an
  owner's lease and return its generation; `RenewLease` renews it and returns
  `FAILED_PRECONDITION` for a generation that is not live, including one from
  before a restart; `ListInjectionLeases` lists the table. When a lease runs
  out, the daemon withdraws all of the owner's entries in one RIB turn, logs
  a WARN line, and counts it in the new `bgp_injection_lease_expiries_total`
  counter; the new `bgp_injection_leases` gauge reports the owners in the
  table. `DeletePath` and `DeleteFlowSpec` gain `owner` and `override_owner`,
  and local route and FlowSpec read-back report `injection_owner`,
  `lease_generation` and `lease_remaining_ms`. Unowned injection is
  unchanged. The new RPCs are outside the v1 inventory until their FRR
  interop leg lands. See
  [leased injection](../docs/reference/api.md#leased-injection).
