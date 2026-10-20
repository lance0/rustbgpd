### Changed

- `ControlService.CheckLiveness` now returns the daemon's `incarnation`: a
  random, non-zero value drawn once at start (the same value as a lease
  generation's `incarnation`) that changes on every start. A client that
  probes periodically can tell that the daemon restarted even when no probe
  failed. The field is additive and outside the narrow v1 contract; an older
  daemon reports zero. `rustbgpd-gobgp-bridge` uses it to replay its tracked
  bans after a restart quicker than one liveness probe, which previously
  waited for the next reconcile pass. See the
  [bridge README](../tools/gobgp-bridge/README.md#restart-behaviour).
