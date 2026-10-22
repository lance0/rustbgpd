### Changed

- The ADR-0141 injection lease lifecycle joins the v1 inventory as a whole:
  `AddLeasedPath`, `AddLeasedFlowSpec`, `RenewLease`, `ListInjectionLeases`
  and the new per-owner key listing `ListLeasedKeys`; the `owner` and
  `override_owner` delete fields; and the `injection_owner`,
  `lease_generation` and `lease_remaining_ms` read-back. The first four RPCs
  were outside the v1 inventory in 0.79.0. The contract pins that a renewal
  never resurrects a lease, that a daemon restart invalidates every
  generation, that expiry removes only the expired owner's local intent, that
  a leased add never becomes permanent, and that a key listing crossing a
  restart or a new generation aborts instead of finishing early. Remote
  withdrawal timing and dataplane enforcement stay outside the guarantee. See
  the [v1 contract](../docs/reference/v1-stable-contract.md#injection-lease-lifecycle).
