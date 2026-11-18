### Changed

- `bgp_rib_actor_turn_duration_seconds` and
  `bgp_rib_actor_work_duration_seconds` gain a 250 ms bucket edge
  (`le="0.25"`), between the existing 200 ms and 500 ms edges, so a turn or
  work unit can be placed against a 250 ms bound. The existing edges are
  unchanged and buckets are cumulative, so queries and dashboards that read
  an existing `le` value, `_sum` or `_count` are unaffected; each series
  exports one more bucket line. See the
  [metric reference](../docs/reference/operations.md).
