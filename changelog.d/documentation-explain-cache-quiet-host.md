### Documentation

- Add a quiet-host memory receipt for import-explain cache sizing: daemon
  cgroup, settled RSS and allocator readings at the 4,096 default and raised
  ceilings, with exact eviction-count answers, supporting the flat 4,096
  explain cache default. Rejected-route retention was not exercised.
  See [the receipt](../docs/perf/explain-cache-quiet-host-2026-10.md).
