### Fixed

- `rbgp events watch --type` help omitted accepted event types, including
  `policy_filtered` and `otc_route_blocked`, and `events sessions --type`
  omitted `peer_added`, `peer_removed` and `max_prefix_warning`. The
  `--type` help and shell completions of `events watch`, `sessions`,
  `policy` and `evpn` now list the values from the same table the event-type
  parser and its error messages use.
