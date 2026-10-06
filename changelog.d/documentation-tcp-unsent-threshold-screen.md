### Documentation

- Record the [64 KiB](../docs/perf/tcp-unsent-threshold-screen-2026-10.md) and
  [128 KiB](../docs/perf/tcp-unsent-threshold-128k-screen-2026-10.md) TCP unsent-threshold
  screens with compact reproducible evidence. Both candidates missed the
  completion gate; [container sizing guidance](../docs/benchmarks.md#current-evaluator-evidence)
  retains existing socket behavior and uses whole-cgroup reload peaks plus headroom.
