### Upgrade notes

- Configuration that binds one IPv6 link-local address to more than one
  interface, which this release previously rejected with "not supported in
  this release", is now accepted unless it combines that pair with a
  `[bmp]` collector, BFD, TCP MD5, TCP-AO, differing `log_level` values or
  differing effective GTSM settings. Those combinations are refused with an
  error naming both neighbors.
- Tools that parse config diff or transaction plan output for an
  interface-scoped link-local neighbor see its interface: in the `--diff`
  text, in a new `interface` JSON field on neighbor diff and effective-impact
  rows, and in the `update_group_impact` `peer` value (`fe80::1%eth0`).
