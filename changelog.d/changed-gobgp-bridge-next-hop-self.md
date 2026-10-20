### Changed

- `rustbgpd-gobgp-bridge` now passes a `0.0.0.0` or `::` next hop through as
  next-hop self instead of refusing it, so detectors keep their default next
  hop. Withdrawals use `DeletePath` with `allow_missing`, and the bridge logs
  the daemon's add and delete outcome for each request. See the
  [bridge README](../tools/gobgp-bridge/README.md).
