### Changed

- A unicast update-group member that falls behind now resyncs in pages
  when its initial table would be paged (a table of at least 10,000 routes),
  instead of receiving its whole table in one RIB turn. The resync tick
  enrolls the same paced reconcile an interrupted initial replay uses: it
  rescans the table against what the member was sent, then withdraws what
  the table no longer holds, and other peers' updates run between its pages.
  A resync sends no End-of-RIB of its own.
  **Operator-visible:** `bgp_rib_paced_fallback_total` has a new `job` label
  value, `grouped_resync`, for a member in such a shape that still takes the
  one-turn resync, and `bgp_rib_outbound_dirty_peers` keeps counting the
  member until its reconcile completes. See
  [Paced-job fallbacks](../docs/reference/operations.md#paced-job-fallbacks).
