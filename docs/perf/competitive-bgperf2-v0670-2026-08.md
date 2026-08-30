# Cross-stack bgperf2 v0.67.0 refresh — 2026-08-29

This campaign replaces the corrected July snapshot as the current same-host
comparison. It measured fresh, version-pinned builds of rustbgpd, BIRD, FRR,
and GoBGP in a counterbalanced order with each cell's samplers stopped before
the next cell. The [80 raw rows](artifacts/competitive-bgperf2-v0670-2026-08/results.csv)
are retained in one compact CSV.

## Result

Seventy-nine of 80 campaign cells reached the monitor's expected full table.
The table reports medians over successful repetitions as
**convergence seconds / total seconds / peak raw container cgroup GiB**.
Each target/shape combination has four campaign repetitions except rustbgpd at
100 peers × 1,000 prefixes, which has three successful repetitions and one
disclosed failure.

| Shape | rustbgpd v0.67.0 | BIRD 2.19.2 | FRR 10.7.0 | GoBGP 4.8.0 |
|---|---:|---:|---:|---:|
| 10 peers × 1k | 2 / 8.22 / 0.029 | 2 / 9.23 / 0.010 | 3 / 9.29 / 0.030 | 4 / 11.38 / 0.114 |
| 2 peers × 10k | 2 / 8.26 / 0.038 | 2 / 9.27 / 0.010 | 3 / 9.34 / 0.042 | 3 / 10.39 / 0.076 |
| 2 peers × 100k | 3 / 12.44 / 0.197 | 3 / 13.53 / 0.028 | 4 / 13.56 / 0.259 | 4 / 14.59 / 0.388 |
| 30 peers × 1k | 3 / 9.81 / 0.104 | 3 / 10.30 / 0.013 | 4 / 10.89 / 0.057 | 4 / 11.44 / 0.577 |
| 100 peers × 1k | 3 / 11.91 / 0.248 | 5 / 14.00 / 0.032 | 7 / 16.58 / 0.152 | 16 / 24.75 / 4.902 |

Among successful repetitions, rustbgpd had the lowest median total time in
all five shapes and tied or had the lowest median convergence time. BIRD used
the least peak raw cgroup memory in every shape. These are same-host import and
convergence observations, not universal throughput or memory claims.

## One failed rustbgpd cell

The first 100 peers × 1,000 prefixes rustbgpd cell established no monitor-visible
sessions or routes after an 88-second monitor wait and ended with
`stuck received count 0 neighbors_checked 0`. The host remained idle, and the
tester reported no errors or timeouts. The next three counterbalanced campaign
repetitions completed at 11.90–11.97 seconds total, then a fresh-bridge
[focused run](artifacts/competitive-bgperf2-v0670-2026-08/focused-rerun.csv)
completed 100 of 100 sessions and 100,000 of 100,000 routes in 11.97 seconds.
The failed cell's target and monitor logs were overwritten by the
resumable batch, so this receipt preserves the failure without assigning it a
daemon root cause or including it in the medians.

## Provenance and method

- **Measured release:** rustbgpd `v0.67.0`, commit
  `69b27812eecc66e7affc505fbe887259b48990f5`.
- **Harness:** bgperf2
  `d0449574c10966218377ad4ca30da5fc3d783d5c`.
- **Target images:** rustbgpd
  `sha256:2ae57f95137c8e6a19ff628860e01b9abce8c5a550aa9f16e16dc1c71799de4c`;
  BIRD
  `sha256:e5e814ba77bae6cfbc9ced5a0efff591b6c69511deab94d76b13b0dfd8c3d795`;
  FRR
  `sha256:ff575fdfed463c18badd738e430869f3808f1bf81762870b927cde299bc32e97`;
  GoBGP
  `sha256:3b6e240376cb1c6db7c4aae50173eec127ec4f4ac0bd7a0977872182aa3d7f78`.
- **Competitor sources:** BIRD `v2.19.2` at
  `1d201ed0360c749dfe3d3b3b079329e7148159cd`; FRR `frr-10.7.0` at
  `87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef`; GoBGP `v4.8.0` at
  `10495227d00666041c98244088b73fa80a59f86c`. All four images were rebuilt
  without cache. FRR used the release tag without `--enable-gcov`; its runtime
  suffix is `-my-manual-build`.
- **Load generators:** BIRD 2.19.2 testers and a GoBGP 4.8.0 monitor in every
  cell. The harness reported zero tester errors and zero tester timeouts in all
  80 cells.
- **Order:** each of the five shapes used the same four balanced sequences:
  rustbgpd/BIRD/FRR/GoBGP, BIRD/GoBGP/rustbgpd/FRR,
  GoBGP/FRR/BIRD/rustbgpd, and FRR/rustbgpd/GoBGP/BIRD.
- **Host:** AMD Ryzen Threadripper 7970X, 32 cores / 64 threads, 125 GiB RAM,
  Linux 6.17, Docker. The largest observed foreign CPU load was 9%.

## Claim boundary

`elapsed` is monitor start to the expected route count; total time also
includes session establishment and harness setup. Memory is the peak of
Docker's raw container cgroup usage, not RSS or working set. The one-second CPU
and memory sampler makes CPU peaks too coarse for a headline comparison.

This campaign covers IPv4 route import and convergence on one host. It does
not cover export policy, reload, churn, restart, IPv6, Add-Path, OpenBGPD, or a
different machine. The focused rustbgpd rerun validates only that the failed
cell did not repeat; it is not a fifth balanced repetition and is excluded from
the table.
