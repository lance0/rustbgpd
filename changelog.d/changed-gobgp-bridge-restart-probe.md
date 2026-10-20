### Changed

- `rustbgpd-gobgp-bridge` probes the daemon with `CheckLiveness` every half
  second and replays its tracked bans as soon as the daemon answers again
  after an outage, instead of waiting for the next reconcile pass, which
  stays as the backstop. After a planned rustbgpd restart, a Graceful Restart
  helper upstream loses the blackholes for a moment instead of up to one
  reconcile interval; see the
  [bridge README](../tools/gobgp-bridge/README.md#restart-behaviour).
