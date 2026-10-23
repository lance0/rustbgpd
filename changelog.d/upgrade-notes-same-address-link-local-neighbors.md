### Upgrade notes

- Configuration that binds one IPv6 link-local address to more than one
  interface, which this release previously rejected with "not supported in
  this release", is now accepted unless it combines that pair with a
  `[bmp]` collector, BFD, TCP MD5, TCP-AO or differing `log_level` values.
  Those combinations are refused with an error naming both neighbors.
