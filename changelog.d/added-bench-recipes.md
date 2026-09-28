### Added

- `just bench-list` prints every Cargo bench target with its required
  features and every benchmark driver with the recipe that runs it.
  `just bench <package> <target>` measures one target pinned to the core in
  `RUSTBGPD_BENCH_CORE` under the shared host lock, and refuses to start
  without that variable. `just bench-compare` runs the Criterion A/B with four
  alternating attempts and the performance-governor check as overridable
  defaults. The RIB memory, route-paging, rrharness, rrtransport, IXP matrix,
  policy-stats, route-server, enhanced route refresh, IRR reload, and VPN
  query drivers each have a `bench-*` recipe that passes their arguments and
  environment through; the drivers keep their own locks, quiet gates, and
  thresholds. No `gate` recipe runs a benchmark. See
  [`bench/README.md`](../bench/README.md#recipes).
