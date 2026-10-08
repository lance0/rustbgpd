# jemalloc run-time option A/B: predeclared acceptance bars

Written 2026-10-08, before any measured leg. `analyze.py` implements these
bars verbatim. Both were in the campaign directory before the first measured
leg and were not edited afterwards; the copies here differ only in the title
and docstring, which drop internal tracker names.

## Question

Does a jemalloc run-time option measure better than the defaults on the fixed
harnesses?

- Stage 1: `main` (defaults) vs `bgth` (`_RJEM_MALLOC_CONF=background_thread:true`).
- Stage 2, only if stage 1's verdict is WIN: `main` vs `bgmt`
  (`_RJEM_MALLOC_CONF=background_thread:true,metadata_thp:auto`), same bars.
- Unprefixed `malloc` for C dependencies (a build-time feature) is out of
  scope: none of these cells enables `[event_history]`, so the bundled SQLite
  never runs and the cells cannot judge it.

## Arms and shape

- Base: origin/main `f15804bc408273095c963a64f92e500b93af7d5c`.
- Arm: a local, never-pushed commit whose only change adds
  `env _RJEM_MALLOC_CONF=CONF` to the daemon launch line (`MEMORY_SCOPE` in
  `bench/scale/cgroup-memory.sh`, used by the matrix and IRR runners, and the
  daemon line of `policy_stats_cell.sh`). Daemon and reloadstall binaries must
  hash identically in both arms; harness processes never see the variable.
- Headline driver: `CELLS=matrix,irr MATRIX_SCENARIOS=s2 RUNS=3 OVERLAPS=0
  IRR_CELLS=rustbgpd-sighup`, arm order rotated each run. S2 is 700 peers x
  400,400 prefixes, 4 reloads; IRR is the canonical ov0 root.
- Operator-read cell: `policy_stats_cell.sh` at its qualification shape
  (1,000 peers x 400 prefixes, 12 reloads), 3 runs per arm, order
  main/arm, arm/main, main/arm, each behind the canonical host-quiet gate.

## Validity (any failure makes the stage INVALID, which is reported, not retried)

- Same binaries. The arms build the same source in different directories,
  and the build embeds its directory (generated protobuf source paths), so the
  raw sha256s differ. String merging places .rodata constants in another
  order, which changes the RIP-relative displacements in .text that point to
  them. Smoke 2 measured this: .text, .eh_frame, .gcc_except_table, .data and
  .data.rel.ro have the same sizes, and only .rodata order, .rela.dyn and
  9,192 .text bytes differ. Arm labels have equal length (`main`, `bgth`,
  `bgmt`). After `/trees/<base>/` is replaced by `/trees/<arm>/`, each
  daemon and reloadstall pair must either be identical or show: the same
  size for every loaded section, a byte-identical `.eh_frame` (identical
  function boundaries) and `.gcc_except_table`, and `.rodata` equal as a
  byte multiset. The check catches a mutated `.eh_frame` or `.rodata` byte
  (negative tests in smoke 2).
- The arm commit's diff touches exactly `bench/scale/cgroup-memory.sh` and
  `bench/scale/reloadstall/policy_stats_cell.sh`.
- Every leg's daemon(s), seen by `watch-daemons.py`: base legs have no
  `_RJEM_MALLOC_CONF` and zero `jemalloc_bg_thd` threads; arm legs have
  exactly CONF in the daemon's environment and at least one
  `jemalloc_bg_thd` thread (jemalloc creates that thread only when
  `opt.background_thread` is on). A leg with no verified daemon is a failure.
- No retries and no exclusions. A failed leg stays failed; it simply does not
  contribute a value. A metric with fewer than 2 values in either arm is
  "insufficient" and cannot be better or worse.
- Policy-stats runs that exit 2 (setup/runtime) or 3 (INVALID) contribute no
  values and are listed. Exit 1 (the cell's own PASS/FAIL criterion missed)
  still contributes its timings.

## Per-leg value

Each leg contributes one value per metric: the median over its reloads for
per-reload metrics (S2 and IRR clocks), the single value otherwise.

## Bars (primary metrics decide; secondary metrics are reported only)

Reload clocks (ranges must be disjoint):
`matrix-s2:daemon_sighup_to_complete`, `matrix-s2:reload_completion_p50`,
`irr-ov0:daemon_sighup_to_complete`, `irr-ov0:completion_p50`.
Better: every arm leg is below every base leg (max(arm) < min(base)).
Worse: min(arm) > max(base). Otherwise: no difference.

Memory (cgroup `memory.peak` primary, swap fenced by `memory.swap.max=0`):
`matrix-s2:daemon_cg_peak`, `irr-ov0:irr_daemon_cg_peak`,
`matrix-s2:settled_rss_last_sample`.
Better: ranges disjoint with the arm lower AND the median difference is at
least 50 MiB (the top of the 30-50 MiB noise floor). Worse: the mirror image.
Otherwise: no difference.

Operator-read latency (policy-stats cell, in-band calls):
`in_band external_ms p50`, `in_band external_ms max`,
`in_band stage_sum_ms max`. Better/worse: disjoint ranges, as for clocks.
Guard: the arm's total of deadline misses plus calls over 2 s must not exceed
the base's; if it does, that counts as a primary regression.

Secondary (reported, not judged): `peak_rss_sample` and `daemon_vmhwm` (S2,
IRR), `settled_cg_current_last_sample`, `daemon_rib_transition`,
`reload_changed_maxgap_p50`/`changed_maxgap_p50`, quiescent read p50, and the
policy cell's own SIGHUP-to-complete p50.

## Verdict

- WIN: at least one primary metric better and none worse (guard included).
- MIXED: at least one better and at least one worse. Not shipped.
- REGRESSION: none better, at least one worse. Not shipped.
- NULL: no primary metric better or worse. Not shipped; recorded as the result.
- INVALID: a validity check failed. Nothing is concluded.

Only WIN ships (build-time `JEMALLOC_SYS_WITH_MALLOC_CONF` plus operator docs
naming `_RJEM_MALLOC_CONF`) and only WIN in stage 1 opens stage 2. If stage 2
is also WIN, the shipped setting is the stage-2 configuration only if it is
not worse than stage 1's on any primary metric when compared by the same bars
(arm vs arm, from the two stages' legs); otherwise stage 1's setting ships.
