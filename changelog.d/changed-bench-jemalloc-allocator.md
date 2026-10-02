### Changed

- The `rrharness` scale harness and the `rustbgpd-rib` and
  `rustbgpd-transport` bench targets link jemalloc as their global allocator,
  matching the daemon. They time and size the daemon's own RIB and transport
  code in-process, so their numbers now come from the allocator that ships.
  rrharness receipts and Criterion baselines recorded through v0.73.0 were
  taken under glibc malloc and are not comparable on allocation-heavy paths.
  See [`bench/scale/rrharness/README.md`](../bench/scale/rrharness/README.md)
  and [`docs/benchmarks.md`](../docs/benchmarks.md).
