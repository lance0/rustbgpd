### Upgrade notes

- RPKI caches are now limited to 4000000 records each and 10000000 across all
  caches, counting VRPs plus ASPA provider ASNs. A cache that exceeds a limit is
  refused, and its last accepted data is kept until it expires. The global RPKI
  publishes about 1.03 million VRPs, so a complete cache is far below either
  limit. If you run private or test caches with larger sets, raise
  `max_records_per_cache` and `max_records_total` in `[rpki]` before
  upgrading. See [record limits](../docs/reference/configuration.md#record-limits).
