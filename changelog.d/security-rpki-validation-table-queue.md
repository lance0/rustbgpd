### Security

- Bound the merged RPKI validation tables waiting for route selection. Every
  change to the VRP or ASPA data builds a new merged table, a complete copy of
  all caches' data that `max_records_total` does not count. Previously, while
  route selection was busy, each new table waited in its queue, so a cache
  sending distinct full tables in quick succession could make the daemon keep
  many complete copies in memory at once. Now one table of each kind is queued
  for route selection at a time, and tables that arrive meanwhile are combined
  into one waiting behind it: the newest table, with every change since the
  queued one, so no change is skipped. At most five tables of each kind are
  held at once, each no larger than `max_records_total`, and their change
  lists are capped at the table's size. See
  [record limits](../docs/reference/configuration.md#record-limits).
