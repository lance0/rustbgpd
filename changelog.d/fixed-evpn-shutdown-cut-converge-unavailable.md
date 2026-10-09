### Fixed

- An EVPN runtime apply that daemon shutdown cuts off after it published to
  the segment and Type 2 originator actors now returns `UNAVAILABLE` with a
  message saying the published state was not restored. It used to return
  `FAILED_PRECONDITION`, which reports no effect, although the publishes
  stayed in place until the shutdown drained those actors. See the
  [EVPN runtime API](../docs/reference/api.md#evpnservice).
