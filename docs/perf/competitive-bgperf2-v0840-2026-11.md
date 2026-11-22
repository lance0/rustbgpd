# Cross-stack bgperf2 v0.84.0 refresh — 2026-11-22

This exact-source campaign ran rustbgpd v0.84.0, BIRD 2.19.2, FRR 10.7.0, and
GoBGP 4.8.0, the daemon set and versions of the
[v0.68.0 refresh](competitive-bgperf2-v0680-2026-08.md), in three shuffled
repetitions of its five fixed import shapes. All 60 runs converged to the full
expected route count with zero tester errors, timeouts, or failed rows.

The table reports median **convergence seconds / total seconds**, with the
total's minimum–maximum in parentheses:

| Shape | rustbgpd v0.84.0 | BIRD 2.19.2 | FRR 10.7.0 | GoBGP 4.8.0 |
|---|---:|---:|---:|---:|
| 10 peers × 1k | 2 / 8.26 (8.26–8.28) | 2 / 9.24 (8.28–9.27) | 3 / 10.36 (9.31–10.38) | 3 / 9.33 (9.30–10.34) |
| 2 peers × 10k | 2 / 8.30 (8.28–8.31) | 2 / 9.31 (9.28–10.34) | 3 / 9.36 (9.34–10.40) | 3 / 10.42 (10.39–10.48) |
| 2 peers × 100k | 3 / 12.81 (12.76–12.84) | 3 / 13.79 (13.76–13.89) | 4 / 14.84 (13.86–14.85) | 4 / 14.90 (14.89–14.96) |
| 30 peers × 1k | 2 / 8.88 (8.86–8.89) | 3 / 9.89 (9.88–10.89) | 4 / 10.94 (10.92–10.98) | 4 / 11.00 (10.98–11.97) |
| 100 peers × 1k | 3 / 12.17 (12.09–14.21) | 5 / 14.18 (14.14–21.46) | 7 / 16.20 (16.17–17.25) | 16 / 32.10 (24.92–32.19) |

rustbgpd had the lowest median total time in all five shapes and tied or had
the lowest median convergence time. At 10 peers × 1k, one BIRD repetition
(8.28 s) matched rustbgpd's slowest run. Total time moves in roughly
one-second steps, set by the monitor's poll and stability wait. This is a
same-host route import and convergence observation, not a universal throughput
claim.

## Against the v0.68.0 refresh

The harness changed between the two campaigns, so these are not like-for-like
deltas. Median totals moved by −0.43 to +0.36 s for rustbgpd, −0.50 to +0.32 s
for BIRD, −0.35 to +1.28 s for FRR, and −2.03 to +7.32 s for GoBGP.
The v0.68.0 medians are over four runs and these over three. Neither change is
attributed.

The bgperf2 fork moved from `d0449574` to `68b7402`. The changes that can move
these numbers are:

- each monitor sample is decided against a paired target read, rather than
  against whichever of two free-running polls finished first;
- a run with one completion witness waits until every generator reports
  completion;
- a completion with zero observed routes is refused after the target's
  checkpoint;
- the convergence windows are counted as durations at the monitor's cadence
  (identical decisions at its one-second cadence);
- the BIRD build verifies TLS and filters redundant generator logs, which
  touches the tester path.

The monitor stays GoBGP 4.8.0, as in every earlier receipt; the fork keeps
GoBGP as its default monitor, while upstream's default is a purpose-built
sink.

## Provenance and boundary

- rustbgpd commit `5f5ca6a312d1bdf7094440ae363495574a6ddecc`, image
  `sha256:8f805a5094302e2f0aa534f26cd2515266db3ac2cc5b4af7a48eebaf3d04f565`,
  built with no cache and reporting `rustbgpd 0.84.0`. Its tree is identical to the
  v0.84.0 squash commit `8ac5f59abf2a228dfb5b0611fef6acee9b1a8961`; the tag at
  `0d2c9027a` adds only documentation changes.
- bgperf2 fork commit
  [`68b7402`](https://github.com/lance0/bgperf2/commit/68b74022f73952ba2a112eb87b01ce0487b893bf),
  `batch` with `repetitions: 3`, `order: shuffle` and seeds 20261122
  (10, 30 and 100 peers × 1k) and 20261123 (2 peers × 10k and 100k).
- Comparator, tester and monitor images were rebuilt with no cache the same
  day; [`provenance.json`](artifacts/competitive-bgperf2-v0840-2026-11/provenance.json)
  records every image ID.
- Measured 2026-11-22 from 16:40 to 16:55 UTC on an AMD Ryzen Threadripper
  7970X, 64 logical CPUs, 125 GiB RAM. No compiler or second harness instance
  ran during the window, and the host recorded no swap activity.
- A long-running process outside the benchmark held about one core
  throughout; each run's peak foreign CPU was 105–273% of one core.
- Target-read pairing left 2–14 samples unpaired in 12 runs (FRR at
  2 × 100k, GoBGP at 30 and 100 × 1k, rustbgpd at 100 × 1k); the other 48
  paired every sample.
- [Compact artifacts](artifacts/competitive-bgperf2-v0840-2026-11/README.md)
  retain all 60 rows.

The largest cell is two peers each announcing 100,000 prefixes. The campaign
does not cover a default-free-zone table, export policy, reload, churn, restart,
IPv6, Add-Path, OpenBGPD, BIRD 3, or another host. CPU and memory rankings are
intentionally omitted because the sampler and daemon defaults do not support a
portable claim.
