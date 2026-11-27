### Changed

- A unicast update-group member that falls behind now resyncs in pages
  when its initial table would be paged (a table of at least 10,000 routes),
  instead of receiving its whole table in one RIB turn. The resync tick
  enrolls the same paced reconcile an interrupted initial replay uses: it
  rescans the table against what the member was sent, then withdraws what
  the table no longer holds, and other peers' updates run between its pages.
  A resync sends no End-of-RIB of its own. A paced replay, initial or
  resync, that rewinds more than 8 times now takes one resync counted
  `lag` whatever made it rewind (a dirty mark, a forced refresh or a
  release, not only a repair-log overflow).
  **Operator-visible:** `bgp_rib_paced_fallback_total` has a new `job` label
  value, `grouped_resync`, for a member in such a shape that still takes the
  one-turn resync, and `bgp_rib_outbound_dirty_peers` keeps counting the
  member until its reconcile completes. See
  [Paced-job fallbacks](../docs/reference/operations.md#paced-job-fallbacks).
