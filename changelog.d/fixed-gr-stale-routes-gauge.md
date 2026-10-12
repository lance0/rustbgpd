### Fixed

- `bgp_gr_stale_routes{peer}` now falls as a reconnected peer re-advertises
  or withdraws its stale routes before End-of-RIB. It was set only at GR
  entry, LLGR promotion, End-of-RIB and the timer sweeps, so it overstated
  the retained routes for the whole awaiting-End-of-RIB window. The gauge
  now reads per-family counters the RIB maintains on every stale-route
  change instead of scanning the peer's routes. Tearing down a peer whose
  only remaining retention was an LLGR deadline from an earlier restart now
  also clears its `bgp_gr_active_peers` and `bgp_gr_stale_routes` series.
  See [Graceful Restart](../docs/reference/operations.md#graceful-restart).
