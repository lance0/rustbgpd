### Changed

- The `rrharness` scale harness and every Criterion bench target (the
  `rustbgpd-rib`, `rustbgpd-transport`, `rustbgpd-wire`, `rustbgpd-policy`,
  `rustbgpd-rpki` and `rustbgpd-api` benches and the root `fib_projection`
  bench) link jemalloc as their global allocator, matching the daemon. The
  root `fib_projection` bench follows the daemon's default `jemalloc` feature,
  so a `--no-default-features` build keeps the system allocator. These targets
  time and size the daemon's own code in-process, so their numbers now come
  from the allocator that ships.
  rrharness receipts and Criterion baselines recorded through v0.73.0 were
  taken under glibc malloc and are not comparable on allocation-heavy paths.
  See [`bench/scale/rrharness/README.md`](../bench/scale/rrharness/README.md)
  and [`docs/benchmarks.md`](../docs/benchmarks.md).
