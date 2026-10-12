### Fixed

- `bgp_gr_stale_routes{peer}` now falls as a reconnected peer re-advertises
  or withdraws its stale routes before End-of-RIB, and when the GR timer
  purges routes, either at promotion to LLGR (families without LLGR and
  `NO_LLGR` routes) or while older LLGR-stale routes remain. It was set only
  at GR entry, End-of-RIB and the LLGR sweep, so it overstated the retained
  routes in between. The gauge now reads per-family counters the RIB
  maintains on every stale-route change instead of scanning the peer's
  routes. Tearing down a peer whose only remaining retention was an LLGR
  deadline from an earlier restart now also clears its `bgp_gr_active_peers`
  and `bgp_gr_stale_routes` series. See
  [Graceful Restart](../docs/reference/operations.md#graceful-restart).
