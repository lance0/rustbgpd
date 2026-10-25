### Fixed

- A burst of route-server client session downs no longer serializes
  per-client withdrawal bookkeeping in the RIB. Every route-server client
  with `rs_control_communities` (the default for `route_server_client`)
  built its own admitted-route set on each withdrawal pass, so each
  departing peer cost work proportional to the remaining clients times its
  withdrawn prefixes, and concurrent downs queued behind one another. A
  withdrawal pass whose prior routes carry no control community for the
  client's route-server ASN now uses the shared update-group withdrawal; a
  control-tagged prior still keeps the per-client check, so a client a route
  was suppressed toward is not sent its withdrawal. Each client's
  withdrawals also skip the exact-export rejection lookup when it has no
  rejected route, unlimited clients refresh only their
  `bgp_outbound_prefix_usage` and `bgp_outbound_prefix_blocking` series per
  update, and a departing session's outbound capacity series are removed
  without scanning every other peer's series.
