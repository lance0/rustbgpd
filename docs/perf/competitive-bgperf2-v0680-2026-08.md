# Cross-stack bgperf2 v0.68.0 refresh — 2026-08-30

This exact-release campaign ran rustbgpd v0.68.0, BIRD 2.19.2, FRR 10.7.0,
and GoBGP 4.8.0 in four counterbalanced repetitions of five fixed import
shapes. All 80 cells reached the exact expected route count with zero tester
errors, timeouts, or failed rows.

The table reports median **convergence seconds / total seconds**:

| Shape | rustbgpd v0.68.0 | BIRD 2.19.2 | FRR 10.7.0 | GoBGP 4.8.0 |
|---|---:|---:|---:|---:|
| 10 peers × 1k | 2 / 8.25 | 2 / 9.21 | 3 / 10.30 | 4 / 11.36 |
| 2 peers × 10k | 2 / 8.24 | 2.5 / 9.81 | 3 / 9.33 | 3 / 10.39 |
| 2 peers × 100k | 3 / 12.45 | 3 / 13.47 | 4 / 13.56 | 4 / 14.59 |
| 30 peers × 1k | 2.5 / 9.31 | 3 / 9.75 | 4 / 10.91 | 4 / 10.93 |
| 100 peers × 1k | 3 / 11.95 | 5 / 14.02 | 7 / 16.55 | 16 / 24.78 |

rustbgpd had the lowest median total time in all five measured shapes and tied
or had the lowest median convergence time. This is a same-host route import
and convergence observation, not a universal throughput claim.

## Provenance and boundary

- rustbgpd exact v0.68.0 commit:
  `d3e6c3571116261c47039b603ec64db14100ea0e`.
- rustbgpd image digest:
  `sha256:73550c1e040d127d83a555c1a5d38fd28e39c28146a9a69c45ae0f7044e6c7fa`.
- bgperf2 commit: `d0449574c10966218377ad4ca30da5fc3d783d5c`.
- Host: AMD Ryzen Threadripper 7970X, 64 logical CPUs, 125 GiB RAM.
- [Compact artifacts](artifacts/competitive-bgperf2-v0680-2026-08/README.md)
  retain all 80 rows and image metadata.

The largest cell is two peers each announcing 100,000 prefixes. The campaign
does not cover a default-free-zone table, export policy, reload, churn, restart,
IPv6, Add-Path, or another host. CPU and memory rankings are intentionally
omitted because the sampler and daemon defaults do not support a portable
claim.
