### Security

- Bound the RPKI data an RTR cache can make the daemon hold. Previously the
  per-transaction record budget reset with every serial update, so a cache could
  keep growing its VRP set through successive updates until memory ran out.
  Records (VRPs plus ASPA provider ASNs) are now counted as each transfer is
  received, against a per-cache limit (`max_records_per_cache`, default
  4000000) and a limit across all caches (`max_records_total`, default
  10000000). A transfer that would exceed either limit is refused before it is
  stored or published. The cache keeps its last accepted data and reconnects to
  request a full table; data that never fits is discarded when it expires. See
  [record limits](../docs/reference/configuration.md#record-limits).
