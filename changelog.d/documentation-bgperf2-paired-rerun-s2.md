### Documentation

- Add a dated 2026-10-19 bgperf2
  [paired-read rerun](../docs/benchmarks.md#2026-10-19-paired-read-rerun):
  unreleased rustbgpd against BIRD 2.19.3, BIRD 3.3.3 and GoBGP 4.10.0 on
  three import shapes, three runs per cell, on a harness revision that pairs
  each monitor sample with the target read that started with it. rustbgpd had
  the lowest median total time in all three shapes on that host, at 10 peers
  × 1,000 prefixes within one sampling step of BIRD 2. The same day's
  spot-check is kept as measured and marked superseded.
- Refresh the IXP S2 reload-stall comparison in the
  [performance summary](../docs/perf/README.md) with a 2026-10-19 rerun
  against OpenBGPD 9.3, three processes per daemon on the phased-churner
  `reloadstall` harness. The v0.75.0 campaign's result stays in its receipt.
