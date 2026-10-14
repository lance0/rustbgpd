### Fixed

- The per-family `outbound channel full — <family> update deferred` warnings
  (EVPN, VPN, FlowSpec, labeled unicast, BGP-LS, RT-Constrain) no longer fire
  when the send failed because the peer's session had already closed. That
  case is not backpressure: the peer's dirty state is dropped and the event is
  logged at debug as `outbound channel closed — dropping dirty state instead
  of re-marking`. Mass session teardown no longer produces spurious
  channel-full warnings. **Operator-visible:** the warning now appears only
  while the peer's session is still live, and the deferred update is resent by
  the dirty-peer resync.
