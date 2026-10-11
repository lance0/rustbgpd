# Quiet-host S2 and IRR reload comparison, main against v0.75.0, 2026-10-11

On the S2 shape (700 peers, 400,400 prefixes, attribute-only export change),
main at `0a73ba716` shortens the RIB export-policy transition from about
209 ms to 64 ms against v0.75.0. However, the daemon's own SIGHUP-to-complete
time is about 115 ms **longer** (772 → 887 ms). The work removed from the fenced
transition reappears in unfenced prestage and the deferred route-refresh
dispatch. S2 daemon cgroup `memory.peak` is about 420 MiB lower. On the IRR
0%-overlap shape (320 members, 183,040 prefixes), every primary clock is flat
or slightly better, and memory is flat.

Under the predeclared bar, this comparison **fails**. The S2 RIB transition
improves with disjoint ranges, but S2 SIGHUP-to-complete worsens with
disjoint ranges. These are same-host results for these two shapes and these
two builds only.

The [evidence bundle](artifacts/quiet-main-v075-s2-irr-2026-10-11/) contains
the extracted per-reload values ([summary.csv](artifacts/quiet-main-v075-s2-irr-2026-10-11/summary.csv)),
the per-arm table ([report.md](artifacts/quiet-main-v075-s2-irr-2026-10-11/report.md)),
the bar evaluation ([verdict.json](artifacts/quiet-main-v075-s2-irr-2026-10-11/verdict.json)),
the daemon's reload phase timers ([reload-phases.txt](artifacts/quiet-main-v075-s2-irr-2026-10-11/reload-phases.txt)),
every leg's native exit and status ([legs.tsv](artifacts/quiet-main-v075-s2-irr-2026-10-11/legs.tsv)),
and build and instrument identities ([identity.json](artifacts/quiet-main-v075-s2-irr-2026-10-11/identity.json)).

## Why this replaces the 2026-10-08 IRR comparison

The [2026-10-10 follow-up](policy-transition-release-followup-2026-10-10.md)
marked the earlier main-vs-v0.75.0 comparison invalid for IRR memory.
v0.75.0's own IRR runner predates daemon cgroup peak capture, so its legs
recorded none. This run follows the pairing in the
[preparation recipe](artifacts/policy-transition-release-followup-2026-10-10/quiet-preparation.md):
both daemons run through **one main runner revision**, with identical main
`rbgp`, `rs-config-render` and `reloadstall` binaries. All of the runner's
source, quiet, workload, cgroup and status gates remain. All 12 legs recorded
a cgroup `memory.peak`, with `memory.swap.max` = 0.

### Deviation from the published adapter

The recipe's published adapter removes only `-p rustbgpd` from the IRR
runner's build command. The runner would therefore still rebuild the common
CLI, renderer and `reloadstall` engine inside each runner tree before every
IRR leg, and that rebuild can replace the bytes installed there. This run
instead used an [adapter that removes both build lines](artifacts/quiet-main-v075-s2-irr-2026-10-11/irr-prebuilt-adapter.patch),
so the IRR runner builds nothing. One prebuilt set of common tools was
installed identically into both runner trees. The matrix runner has no build
step and needed no adapter.

The common tools were built once from main `0a73ba716`, the same source as the
main daemon, with Rust/Cargo 1.99.0:

| Tool | Build command | SHA-256 |
|---|---|---|
| `rbgp` | `cargo build --release --locked -j 4 -p rustbgpd -p rustbgpctl` (the main daemon build) | `866e06e2050c42aa0a85fc19124164b85c5761d08ffd8d384f4b4ce1aeb3516b` |
| `rs-config-render` | `cargo build --release --locked -j 4 -p rs-config-render` | `dfd347670e38f3a77157ebec513a23083b0bb00aec0ac979032af14f8f61dc09` |
| `reloadstall` | `cargo build --profile scale --locked -j 4 -p reloadstall` | `395686d97f115a53e746ad11241d618a656f337623412392836b881276941358` |

The IRR runner hashes all four installed binaries (daemon, `rbgp`, renderer
and `reloadstall`) at the start of each leg, and rechecks them during and at
the end of the leg. The matrix runner records and rechecks the daemon and
`reloadstall` hashes. In addition, the window hash-checked all four installed
binaries in both runner trees before and after every leg. Every check
matched.

## Sources and builds

| Arm | Source | Daemon SHA-256 |
|---|---|---|
| v075 | `v0.75.0` (`54ed19b5af927f1c8e5064ecb1a497885c15d068`) | `4d2fc74b73aab0f32225ba8cdbef119dab473dea4feca4e8a1cf057039c9ce6f` |
| main | `0a73ba716ac0a83e5bb9977e0fab4f88f6b54cc9` | `29643828243b09b6bf905f66e6f026530177c342181cf8cd41208b783658df26` |

Both daemons were built fresh with `cargo build --release --locked -j 4
-p rustbgpd -p rustbgpctl` using Rust/Cargo 1.99.0. Each arm used its own
empty target directory. Each arm's actual build closure was captured
immediately after its build: 227 artifact units per arm, and 342 (v075) and
343 (main) including build scripts. `bench-internals` is declared but not
enabled in either. The retained v0.75.0 binary from 2026-10-08 was not used.
Installed binaries were hash-checked before and after every leg. Runner
commit: `225f75667c2ded306aaf16f74603567d9c340971` (parent `0a73ba716`).

## Shape and method

- **S2:** `run-matrix.sh rustbgpd`, `N_PEERS=700 TOTAL_PREFIXES=400400
  RELOADS=4 CONTROL_SECS=30`, with default changed peers and no probes.
- **IRR:** `run-irr-reload.sh rustbgpd-sighup`, `N_MEMBERS=320
  TOTAL_PREFIXES=183040 MIN_LIST=1000 MAX_LIST=40000 SEED=61
  CHANGED_FRACTION=0.1 OVERLAP_FRACTION=0 RELOADS=4 CONTROL_SECS=30`. The
  run used the full measurement source gate against the runner commit.
- **Legs:** three process legs per arm and cell, in the order v075-r1,
  main-r1, main-r2, v075-r2, v075-r3, main-r3. All S2 legs ran first, then
  all IRR legs.
- **Quiet host:** a single window held the canonical host lock. The runners'
  own quiet gates and cooldowns ran unchanged.
- **Validation before measurement:** full-shape inputs for both generations
  passed `--check --strict` with both daemons. Small S2 and IRR smokes passed
  for each arm through the runner.
- **Analysis:** results are per-leg medians over four correlated reloads.
  Each arm has three process legs; the 12 reloads per arm are not
  independent replicates.
- **Classification:** a clock metric counts as better or worse only when the
  arms' leg ranges are disjoint. A memory metric also needs a median
  difference of at least 50 MiB.

## Results

Values are medians, with ranges in brackets, of per-leg medians (n = 3 legs per arm).

| Cell | Metric | v075 | main | Δ | Class |
|---|---|---:|---:|---:|---|
| S2 | RIB transition (`cohort_rib_transition_us`), ms | 209.2 [206.2–211.2] | 63.8 [62.8–69.9] | −145.4 | better |
| S2 | daemon SIGHUP → reload complete, ms | 771.8 [769.1–773.6] | 886.6 [865.9–900.7] | +114.9 | **worse** |
| S2 | harness reload completion p50, s | 0.795 [0.79–0.81] | 0.83 [0.81–0.84] | +0.035 | no difference (ranges touch) |
| S2 | daemon cgroup `memory.peak`, MiB | 1019.5 [992.5–1020.5] | 600.0 [598.9–636.6] | −419.5 | better |
| IRR | RIB transition (`cohort_rib_transition_us`), ms | 374.1 [371.0–379.4] | 359.6 [347.1–362.5] | −14.5 | better |
| IRR | daemon SIGHUP → reload complete, ms | 572.5 [572.2–580.2] | 545.0 [534.4–546.0] | −27.5 | better |
| IRR | harness completion p50, s | 0.583 [0.583–0.595] | 0.595 [0.575–0.599] | +0.012 | no difference |
| IRR | daemon cgroup `memory.peak`, MiB | 740.3 [740.2–779.9] | 738.5 [737.6–738.9] | −1.7 | no difference |

The daemon's own phase timers locate the S2 change. Values are pooled
per-reload medians, n = 12 per arm:

| S2 phase | v075 ms | main ms | Δ ms |
|---|---:|---:|---:|
| cohort prestage session apply | 454.4 | 570.5 | +116.2 |
| cohort RIB transition | 208.9 | 65.1 | −143.8 |
| deferred route-refresh dispatch | 65.1 | 204.5 | +139.4 |
| generation total | 732.4 | 846.9 | +114.5 |

S2 `VmHWM` and the 5 s RSS samples are about the same in both arms. The lower
cgroup peak on main is therefore in memory charged to the daemon's cgroup
outside its resident peak; that charge includes page cache and kernel socket
buffers. This run does not split that charge further, and the data does not
show a smaller heap. IRR changes follow the authoritative-fallback path
and do not use the grouped transition that S2 exercises.

## Comparison with 2026-10-08

On 2026-10-08 the same S2 shape on this host compared v0.75.0 with main
`591ac39d4`. That run used each arm's own runner, which is valid for S2. It
found RIB transition 206.1 → 78.4 ms and SIGHUP-to-complete 749.4 → 753.2 ms,
with no difference. The SIGHUP-to-complete regression and the memory
reduction therefore arrived in `591ac39d4..0a73ba716`. That range includes
shared-encoding slice yielding, shared route-refresh replay and
readiness-during-replay changes. This receipt does not bisect the range or
attribute the regression to a specific commit.

## Scope

- These are two reload shapes on one host. The S2 result applies to
  attribute-only grouped export transitions; IRR exercises the
  authoritative-fallback path.
- The RIB transition clock is not end-to-end reload latency. On S2 the
  daemon's complete reload is slower on main, and harness-observed
  completion p50 does not separate the arms.
- No front-door performance claim changes as a result of this receipt.
