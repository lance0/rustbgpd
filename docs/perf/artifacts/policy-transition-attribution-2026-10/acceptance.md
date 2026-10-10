# J2 acceptance: policy-transition attribution, Q1-Q4

Predeclared 2026-10-08, before any measured cell ran. `analyze_j2.py` encodes these bars.
Each Q gets PASS (prediction confirmed), FAIL (prediction not confirmed; the stated follow-up
applies) or INVALID (a validity check failed; fail closed). Q4 may be SKIPPED if the window ran
past 2026-10-09 10:00 local.

## Arms and binaries

| Label | Commit | Use |
| --- | --- | --- |
| pre2952 | `3bbc1576cc3fd1f97a6c723131f183f82d4952f4` (parent of #2952) | Q1, Q3 |
| post2952 | `49abbb0171cbb889b7e2618c2bdcec6ea35699ae` (#2952) | Q1, Q3 |
| v073 | v0.73.0 `335676078965ae5a7d24273821dab12da79222d2` | Q4 |
| v075 | v0.75.0 `54ed19b5af927f1c8e5064ecb1a497885c15d068` | Q2 |
| main | `591ac39d4b50fc2c647942713a9ea99c0588a51a` (J1 control) | Q2 |

Q1/Q3/Q4 daemons: `cargo build --release --locked -p rustbgpd -p rustbgpctl -p rs-config-render`
(the `just bench-policy-stats` command), copied to `bin/<arm>/` and hashed. Q1 and Q4 share one
`reloadstall` (`bin/harness-main`, built at main) and main's `policy_stats_cell.sh`. Q2 arms are
built by the headline campaign's own commands in `out/q2/trees/` (prebuilt this evening, so the
window's builds are no-ops); Q3 uses each arm's own `run-matrix.sh` and harness.

The job holds the canonical host lock throughout; runners take a job-private
`RUSTBGPD_HOST_LOCK`. Every cell passes the canonical quiet-host gate (the runners' own gate for
Q2/Q3, the job's for Q1/Q4).

## Q1: the #2952 step at the 1,000-peer policy-stats cell

Default cell shape (1,000 x 400k, 12 reloads, CPUs 2-3/4-5/8-15), ABBA: pre, post, post, pre.
- Valid run: engine and daemon exit 0, cell exit 0/1/3 (the read-pairing verdict and audit-stage
  completeness do not affect the transition clocks), 12 reloads in `summary.json`, each with a
  `committed` RIB transition `elapsed_ms`, `cohort_rib_transition_us` and `sighup_to_complete_ms`.
- Signals (pooled per reload over both runs, 24 per arm): RIB `elapsed_ms`,
  `cohort_rib_transition_us`, SIGHUP -> complete.
- **Bar:** post2952's maximum RIB `elapsed_ms` is below pre2952's minimum (disjoint).
  Predicted bands (reported, not gating): pre 170-230 ms, post 45-60 ms.
- FAIL means the S2 attribution does not transfer: bisect `v0.73.0..v0.75.0` on this cell next.

## Q2: the ticket receipt, main vs v0.75.0, same night

`CELLS=matrix,irr MATRIX_SCENARIOS=s2 RUNS=3 OVERLAPS=0 just bench-headline out/q2 v075=v0.75.0
main=591ac39d4`: S2 700 x 400,400 and IRR 0% (320 x 183,040), 3 rotating legs per arm and cell.
- Valid: campaign exit 0 (every leg passed) and 3 legs per arm for every primary metric.
- Per leg, the median over its reloads; per arm, the 3 leg values.
- Classification: clock metrics are better/worse only with disjoint leg ranges; memory (cgroup
  `memory.peak`, swap fenced by the runners' `MemorySwapMax=0` scope) additionally needs a
  median delta of at least 50 MiB (the noise floor's upper end).
- Primary metrics: S2 and IRR daemon SIGHUP -> complete, harness completion p50, daemon cgroup
  peak, RIB transition.
- **Bar:** S2 `daemon_rib_transition` is better on main (predicted ~200 -> ~70 ms) and no primary
  metric is worse. SIGHUP -> complete may not move (2026-10-03 precedent); IRR is predicted flat.

## Q3: filtering discriminator (scope of the #2930/#2952 saving)

Each arm's `run-matrix.sh rustbgpd`, `N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4
CONTROL_SECS=30 GEN_FILTER_COUNT=64 RELOADSTALL_FILTER_COUNT=64`, pre2952 then post2952.
- Valid: status `pass`, daemon exit 0, one `reload generation phase timing` line per reload.
- **Bar:** zero `RIB export-policy transition completed` lines with `outcome=committed` in either
  arm, and the arms' `cohort_rib_transition_us` medians within max(10 % of pre, 20 ms).
- A committed transition means the code reading in the scout comment is wrong: stop and re-read.

## Q4 (if time): v0.73.0 on today's harness and host

One default-shape policy-stats run with the v0.73.0 daemon. Valid as Q1.
- **Bar:** median RIB `elapsed_ms` within 525-641 ms (583 ms +/- 10 %, the 2026-09-26 receipt).
- FAIL means a harness or host component contributes to the cross-date 583 -> 51 ms.

## Publication rule

The receipt claims only the measured shapes. Front-door claims stay unchanged until a release
tag contains #2952. Q1, Q3 and Q4 are attribution evidence, not headline numbers.
