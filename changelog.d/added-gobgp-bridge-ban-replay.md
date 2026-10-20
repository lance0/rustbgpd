### Added

- `rustbgpd-gobgp-bridge` keeps the bans it has announced in memory and
  re-adds them on a reconcile pass (`--reconcile-interval-secs`, default 30),
  so a rustbgpd restart no longer ends mitigation for detectors that announce
  each ban once. A withdrawal the daemon could not acknowledge is retried on
  each pass and stops the ban from being replayed. The bridge tracks at most
  65,536 paths and refuses new bans beyond that with `RESOURCE_EXHAUSTED`.
  The set does not survive a bridge restart; see the
  [bridge README](../tools/gobgp-bridge/README.md#restart-behaviour).
