### Added

- `tools/gobgp-bridge` adds `rustbgpd-gobgp-bridge`, a separate tool outside
  the daemon and the v1 contract. It serves GoBGP v3 `AddPath` with binary
  IPv4 or IPv6 unicast NLRI and attributes on loopback, so RTBH detectors that
  drive GoBGP can announce and withdraw blackholes through rustbgpd's
  injection API without client changes. Other GoBGP methods return
  `UNIMPLEMENTED`. Injected routes do not survive a daemon restart; see the
  [bridge README](../tools/gobgp-bridge/README.md) for the supported subset,
  the security warning and restart behaviour.
