### Upgrade notes

- Plain `rbgp rib vpn`, `rbgp rib labeled`, `rbgp rib rtc` and `rbgp evpn`
  print the same rows in a different order: ascending key order from the
  bounded page RPCs, not the daemon's hash-table order. Sort the rows in any
  script that compared listings line by line or took the first row. These
  listings and `rbgp evpn diagnose` now need a daemon that serves
  `ListVpnRibRoutes`, `ListLabeledRibRoutes`, `ListRtcRibRoutes` and
  `ListBestEvpnRoutes` (v0.78.0 or later); against an older daemon they fail
  with `not supported by this daemon`. A listing of a table that keeps
  changing can fail with `aborted`: retry it, or page with `--limit` and
  `--page-token`.
