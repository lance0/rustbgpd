### Changed

- One IPv6 link-local address may now name a neighbor on each of several
  interfaces, for example `fe80::1` on both `eth0` and `eth1` toward a
  router that uses one MAC on every port. Each neighbor keeps its own
  routes, metrics series, MRT entries, FIB peer-group filtering, policy and
  peer-group changes and transaction plans. An equal-route tie between them
  is broken by interface name, so the winner does not depend on
  configuration or connection order. Such neighbors may not use BFD, TCP
  MD5, TCP-AO, differing `log_level` values or differing effective GTSM
  (`ttl_security`, `ttl_security_hops`) settings, and no `[bmp]` collector
  may be configured while a pair exists. See the
  [configuration reference](../docs/reference/configuration.md).
- Config diff and transaction plan output names an interface-scoped
  neighbor with its interface: `--diff` text shows `fe80::1%eth0`, the JSON
  `added`, `changed` and `effective_neighbor_impact` rows gain an
  `interface` field for such neighbors, and `update_group_impact` rows read
  `fe80::1%eth0` in `peer`. Rows for numbered neighbors are unchanged.
