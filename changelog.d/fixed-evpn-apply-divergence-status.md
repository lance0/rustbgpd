### Fixed

- `ApplyEvpnRuntime` no longer returns `FAILED_PRECONDITION` for a failed
  converge that changed live EVPN state. When a rollback step does not
  restore the committed model, or a failing Type 3 IMET step may have taken
  effect without an acknowledgement, the apply now returns `INTERNAL` with a
  message saying the state was not restored. `FAILED_PRECONDITION` is kept
  for failures with no effect and for fully rolled-back ones. A rollback to
  an actor that exited counts as restored only when that actor never
  received the candidate. See the
  [EVPN runtime API](../docs/reference/api.md#evpnservice).
  **Operator-visible:** some converge failures change status from
  `FAILED_PRECONDITION` to `INTERNAL`. EVPN is alpha and outside the v1
  compatibility surface.
