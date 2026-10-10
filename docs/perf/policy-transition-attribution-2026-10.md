# Policy-transition attribution: the #2952 step, v0.75.0 and v0.73.0 — 2026-10-10

A same-host, same-harness attribution campaign for the drop in the policy-stats
reload cell's RIB export-policy transition, from about 585 ms in the
[2026-09-26 receipt](artifacts/policy-stats-owner-published-2026-09-26/README.md)
to about 50 ms on later main. It ran four predeclared questions (Q1–Q4) on the
night of 2026-10-09 to 2026-10-10 (UTC 01:26–08:00 on 2026-10-10) and is
published retroactively the same day from the retained raw data.

| Question | Verdict | Result |
|---|---|---|
| Q1: the #2952 step at the 1,000-peer cell | **PASS** | RIB `elapsed_ms` 197.5 ms [192–237] before #2952, 56.0 ms [52–60] after, disjoint (24 reloads per arm) |
| Q2: main against v0.75.0, S2 and IRR 0% | **INVALID** | One instrument gap: v0.75.0's own IRR runner records no cgroup peak. Every other primary metric met the bar: S2 RIB transition 206.1 → 78.4 ms per-leg median, disjoint, and nothing worse |
| Q3: does the saving reach filtering reloads? | **PASS** (prediction confirmed) | With 64 filtered routes, every reload in both arms fell back to the per-peer path; cohort transition 794.8 vs 753.1 ms, within the predeclared tolerance |
| Q4: v0.73.0 on today's harness and host | **PASS** (after re-analysis) | RIB `elapsed_ms` 576.5 ms [568–590], inside the predeclared 525–641 ms band |

Taken together: on one host and one harness, the cell's RIB transition reads
576.5 ms at v0.73.0, 197.5 ms at #2952's parent and 56.0 ms at #2952. The
cross-date drop is daemon code, not a harness or host change, and #2952 is the
last ~141 ms of it. **The end-to-end reload did not get faster at this cell:**
see [Q1](#q1-the-2952-step-at-the-1000-peer-cell).

## Arms and instruments

| Label | Commit | Used in |
|---|---|---|
| `pre2952` | `3bbc1576cc3fd1f97a6c723131f183f82d4952f4`, the parent of #2952 | Q1, Q3 |
| `post2952` | `49abbb0171cbb889b7e2618c2bdcec6ea35699ae`, #2952 | Q1, Q3 |
| `v073` | v0.73.0, `335676078965ae5a7d24273821dab12da79222d2` | Q4 |
| `v075` | v0.75.0, `54ed19b5af927f1c8e5064ecb1a497885c15d068` | Q2 |
| `main` | `591ac39d4b50fc2c647942713a9ea99c0588a51a`, origin/main when the window opened | Q2 |

- **Builds.** Q1, Q3 and Q4 daemons were built with `cargo build --release
  --locked -p rustbgpd -p rustbgpctl -p rs-config-render` (Rust 1.99.0), the
  command `just bench-policy-stats` uses. Their hashes are in
  [`provenance.json`](artifacts/policy-transition-attribution-2026-10/provenance.json).
- **One instrument for Q1 and Q4.** Both used `policy_stats_cell.sh` and one
  `reloadstall` (scale profile), both from `591ac39d4`. Only the daemon and
  `rbgp` changed between runs.
- **Own runners for Q2 and Q3.** Q2 is `just bench-headline`, in which every
  arm runs its own runners and harness. Q3 used each arm's own
  `bench/scale/matrix/run-matrix.sh`.
- **Host.** One AMD Ryzen Threadripper 7970X (32 cores, 64 threads), kernel
  7.0.0-30, performance governor. The job held the shared host lock
  throughout. Every cell passed the canonical quiet-host gate: the job's own
  gate for Q1 and Q4, the runners' gate for Q2 and Q3.
- **Predeclared bars.** The bars were fixed on 2026-10-08, before any measured
  cell ([`acceptance.md`](artifacts/policy-transition-attribution-2026-10/acceptance.md)),
  and applied by
  [`analyze.py`](artifacts/policy-transition-attribution-2026-10/analyze.py).

## Q1: the #2952 step at the 1,000-peer cell

The default policy-stats cell: 1,000 route-server peers × 400 IPv4 prefixes,
12 changed-policy reloads that flip a community on every exported route. The
daemon ran on CPUs 2–3, the harness on 4–5, and the probes on 8–15. The arm
order was ABBA (pre, post, post, pre), with values pooled per reload across
both runs, 24 per arm.

| Metric | `pre2952` | `post2952` |
|---|---|---|
| RIB export-policy transition `elapsed_ms` | 197.5 [192.0–237.0] | 56.0 [52.0–60.0] |
| `cohort_rib_transition_us` (ms) | 198.1 [192.8–238.1] | 273.6 [52.4–314.7] |
| SIGHUP → reload complete (ms) | 723.3 [670.3–913.2] | 852.5 [615.5–948.7] |

**The bar holds.** post2952's slowest RIB transition, 60 ms, is below
pre2952's fastest, 192 ms. Both medians fall inside the predicted bands
(170–230 and 45–60 ms). All four runs exited 0.

**The two wider clocks did not improve.**

- The RIB clock starts when the RIB actor receives the cohort's policy
  replacement. The cohort clock starts when the peer manager sends it.
- Before #2952 the two agree within 35 ms on every reload.
- After #2952 they agree on only 6 of 24 reloads. On the other 18, the cohort
  clock reads 238–315 ms against a RIB clock of 55–60 ms.
- SIGHUP → complete also rose, from a 723 to an 853 ms median.

#2952 moves the full exact-export probe into the unfenced prestage that runs
before the fenced transition. The extra 178–258 ms on those reloads is consistent
with that work now landing before the RIB clock starts. It is not attributed
here: the cell records no per-phase timing for the prestage.

## Q2: main against v0.75.0, S2 and IRR 0%

`CELLS=matrix,irr MATRIX_SCENARIOS=s2 RUNS=3 OVERLAPS=0 just bench-headline`
ran with `v075=v0.75.0` and `main=591ac39d4`. The shapes were S2, 700 peers ×
400,400 prefixes with 4 reloads per leg, and IRR at 0% overlap, 320 members ×
183,040 prefixes. Each arm ran three rotating legs per cell, and every leg
passed. The table gives each arm's per-leg medians: median [min–max] of the
three leg values.

| Metric | v0.75.0 | main | Classification |
|---|---|---|---|
| S2 daemon RIB transition (ms) | 206.1 [203.2–209.9] | 78.4 [73.2–78.8] | better (disjoint) |
| S2 SIGHUP → complete (ms) | 749.4 [747.8–750.2] | 753.2 [739.0–765.0] | no difference |
| S2 harness completion p50 (s) | 0.8 | 0.8 | no difference |
| S2 daemon cgroup peak (KiB) | 1,059,664 [986,120–1,068,172] | 1,123,872 [1,043,656–1,150,076] | no difference (ranges overlap) |
| IRR daemon RIB transition (ms) | 372.4 [368.2–376.9] | 361.4 [360.0–361.7] | better (disjoint) |
| IRR SIGHUP → complete (ms) | 564.3 [557.8–564.5] | 558.8 [549.2–561.5] | no difference |
| IRR harness completion p50 (s) | 0.6 | 0.6 | better (disjoint below display precision) |
| IRR daemon cgroup peak (KiB) | not recorded | 757,996 [757,732–816,496] | insufficient |

- **Verdict: INVALID, from one missing metric.** The predeclared rule needs
  three legs per arm for every primary metric. The v0.75.0 IRR legs have no
  cgroup peak because each arm runs its own IRR runner, and v0.75.0's runner
  predates #2942, which added that measurement. The daemon did not fail.
- **The other primary metrics met the bar.** The S2 RIB transition is better
  on main with disjoint legs, and no other metric is worse.
- **SIGHUP → complete did not move.** The S2 transition saved about 128 ms,
  and the end-to-end S2 reload clock stayed flat, as on 2026-10-03.
- **IRR stays flat**, as predicted for a shape that always takes the fallback
  path (Q3).

## Q3: does the saving reach filtering reloads?

This question checks whether the #2930/#2952 saving applies only to
permit-set-preserving grouped transitions.

- **Shape.** S2 at 700 × 400,400, `RELOADS=4 CONTROL_SECS=30`, with 64 routes
  filtered by both the generator and the harness
  (`GEN_FILTER_COUNT=64 RELOADSTALL_FILTER_COUNT=64`).
- **Order.** pre2952, then post2952.
- **Prediction.** No reload takes the clean grouped path, and the per-peer
  cost is equal across arms.

| Arm | RIB transition outcomes | Authoritative fallback | Cohort RIB transition (ms) | Generation total (ms) |
|---|---|---|---|---|
| `pre2952` | `fallback_handoff` × 4 | 4/4 | 794.8 [776.5–799.8] | 1,229.6 [1,208.7–1,252.7] |
| `post2952` | `fallback_handoff` × 4 | 4/4 | 753.1 [741.5–758.2] | 1,188.3 [1,146.3–1,211.4] |

**Bar:** zero committed fast-path transitions (there were none), and cohort
medians within max(10% of pre, 20 ms). The difference was 41.6 ms against an
allowance of 79.5 ms. A single filtered route therefore puts a reload on the
per-peer path, where #2952 has no effect.

## Q4: v0.73.0 on today's harness and host

One default-shape policy-stats run with the v0.73.0 daemon, on the same
instruments as Q1.

| Metric | `v073` (n = 12) |
|---|---|
| RIB `elapsed_ms` | 576.5 [568.0–590.0] |
| `cohort_rib_transition_us` (ms) | 579.2 [568.6–815.2] |
| SIGHUP → reload complete (ms) | 1,113.6 [1,095.7–1,336.2] |

**Bar:** the RIB transition median must fall within 525–641 ms (583 ms ±10%).
576.5 ms meets it.

- **The 2026-09-26 figure reproduces.** That receipt read a 585.5 ms median
  [581–589] at `292c32b39`, before the jemalloc-linked harness (#2886) and
  the pair-lead change (#2993) existed.
- **So the harness is ruled out.** Neither the harness change nor the host
  explains the cross-date drop.

**Analysis history.**

- **First window: Q4 skipped.** A 10:00 cutoff, written for the night the
  queue was first planned, made the first window skip Q4 by design.
- **Rerun alone: rc=0, but printed SKIPPED.** The v0.73.0 cell was then run
  by itself, from 07:51 to 08:00 UTC, and exited 0. The analyzer still
  printed SKIPPED, because it looks for a `q4 skipped` line in the progress
  log, and the first window had left one there.
- **Re-analysis: PASS.** Run on a copy with that stale line removed, the
  unchanged analyzer gives the PASS above. The cell data are untouched.

The bundle keeps all three verdict files, and
[`recompute.py`](artifacts/policy-transition-attribution-2026-10/recompute.py)
reproduces each one byte for byte.

## What this does not establish

- **No end-to-end improvement at the 1,000-peer cell.** At this cell,
  #2952 shortened the fenced RIB transition. The cohort and SIGHUP → complete
  clocks did not improve, and their medians rose (Q1).
- **No measurement of the steps between v0.73.0 and #2952's parent.** That
  part of the drop, about 380 ms, was measured on this cell only at its two
  ends. A separate S2 A/B per change attributes it to #2920, #2921 and #2930;
  this campaign does not repeat that.
- **No result for other shapes or cross-daemon comparisons.** Each result
  covers only its measured shape: the 1,000 × 400 policy-stats cell, S2 at
  700 × 400,400, and IRR 0% at 320 × 183,040.
- **Not a release result.** #2952 is in no release tag yet.
- **No complete Q2 memory comparison.** The IRR cgroup peak is missing for
  v0.75.0, and the S2 cgroup peaks overlap.

## Evidence

[`artifacts/policy-transition-attribution-2026-10/`](artifacts/policy-transition-attribution-2026-10/README.md)
holds:

- the acceptance file and the analyzer, as run;
- the three verdict outputs;
- the job's progress log;
- per-run summaries for Q1 and Q4;
- the Q3 RIB and phase-timing log lines;
- the Q2 headline bundle, without daemon logs;
- `provenance.json`.

`python3 recompute.py` re-runs the analyzer on the bundle and checks all three
verdicts.
