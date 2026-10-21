### Added

- The gRPC API reports `peer_interface` beside a bare `peer_address` on more
  outputs: `FibRouteStatus`, `BlackholeDiscard`, `DataplaneRouteEvent`,
  `BfdSession`, `BfdSessionEvent` and `PolicyChainStats`, and beside `peer` on
  `TestPolicyDiff` and `TestPolicyRejectedRoute`. The interface is empty for
  numbered neighbors. FIB and blackhole rows take it from the route they
  describe, and FIB owned state keeps it across a restart. `GetBfdSessions`
  with a scoped selector returns only the session on that interface. `rbgp`
  prints these rows' neighbors in the scoped `fe80::1%eth0` form, and the
  birdwatcher adapter example sends the scoped selector for link-local
  neighbors. EVPN, VPN, labeled, RTC, BGP-LS and FlowSpec route entries and
  EVPN route events still report a bare address. See
  [scoped neighbor identity](../docs/reference/api.md#scoped-neighbor-identity).
