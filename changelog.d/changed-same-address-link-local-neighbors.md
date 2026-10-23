### Changed

- One IPv6 link-local address may now name a neighbor on each of several
  interfaces, for example `fe80::1` on both `eth0` and `eth1` toward a
  router that uses one MAC on every port. Each neighbor keeps its own
  routes, metrics series and MRT entries. An equal-route tie between them is
  broken by interface name, so the winner does not depend on configuration
  or connection order. Such neighbors may not use BFD, TCP MD5, TCP-AO or
  differing `log_level` values, and no `[bmp]` collector may be configured
  while a pair exists. See the
  [configuration reference](../docs/reference/configuration.md).
