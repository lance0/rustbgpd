### Changed

- `rbgp rib vpn`, `rbgp rib labeled`, `rbgp rib rtc` and base `rbgp evpn` no
  longer call the deprecated whole-table `ListVpnRoutes`, `ListLabeledRoutes`,
  `ListRtcRoutes` and `ListEvpnRoutes`. They walk every page of the bounded
  `ListVpnRibRoutes`, `ListLabeledRibRoutes`, `ListRtcRibRoutes` and
  `ListBestEvpnRoutes` and print one listing, as `rbgp rib bgpls` does. The
  row set, each row's fields and the JSON array shape are unchanged.
  **Operator-visible:** rows now print in ascending key order instead of the
  daemon's hash-table order. `rib vpn`: Route Distinguisher, prefix, source
  neighbor, path ID. `rib labeled`: prefix, source neighbor, path ID.
  `rib rtc`: origin AS, Route Target, prefix length, source neighbor, path ID.
  `evpn`: route type, Route Distinguisher, the type's remaining key fields,
  source neighbor. A script that depended on the old order must sort the rows
  itself. A table that changes between two pages now fails the listing with
  `aborted: route table changed during pagination; restart with an empty
  page_token` (exit 1, no rows, no retry) where the old call returned one
  snapshot; run it again or page with `--limit` and `--page-token`. An
  invalid `--neighbor` is now reported as `source_peer_filter` instead of
  `peer_filter`, and an `evpn --route-type` above 6 as `route_type_filter
  must be 0 or 1..=6` instead of `invalid route_type_filter N: expected 0 or
  1..=6`. See the
  [CLI guide](../crates/cli/README.md#routes-policy-and-dataplane).
- `rbgp evpn diagnose` reads its Type 2 and Type 3 route counts from
  `total_count` of one single-row `ListBestEvpnRoutes` page per type instead
  of listing both types through `ListEvpnRoutes`. Its output is unchanged.
