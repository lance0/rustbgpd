# Corrected S2 / IRR quiet-host comparison

This is a preparation recipe, **not a run or a queued job**. The original Q2
remains INVALID: the v0.75.0 IRR runner predates #2942 and recorded no daemon
cgroup peak. Use the v0.75.0 **binary through main's runner** in the replacement.
Both arms must use the same main `reloadstall`, CLI, renderer and generators.
Record this instrumentation pairing explicitly; it is different from original
Q2, which ran each arm's own tools.

The accompanying [manifest](quiet-preparation.json) pins the retained v0.75.0
daemon and the main source available when the recipe was prepared. Main must
be frozen and its manifest completed before a future quiet window. The new
main daemon and tools have not been built for this recipe. The retained old
binary was built at the recorded campaign commit, whose Git tree is identical
to the v0.75.0 tag; both commit identities and the binary digest are declared
separately in the manifest.

## Avoid two misleading shortcuts

- `LABEL=MAIN_REF:DAEMON_REF` in the headline driver supports matrix legs
  only; it skips cross-harness IRR arms. It cannot supply the missing IRR leg.
- The main IRR runner builds `rustbgpd` unconditionally. Copying the old
  daemon into its target directory before invoking it would let that build
  replace the measured binary with main.

The preparation-only [adapter patch](quiet-irr-build-adapter.patch) removes
only `-p rustbgpd` from that build command. Apply it **equally to both owned
runner trees**, preserving all host/source/quiet gates, cgroup measurement,
generators, status checks and verifiers. Build each daemon independently, and
copy its pinned binary into the runner tree's `target/release/rustbgpd` before
the leg. Main CLI/renderer and scale-harness builds remain in the runner.
The runner's own binary roster then records the bytes that actually run and
checks that they stay unchanged. Record daemon source separately from runner
source; a main runner's Git identity does not make the old binary main.

No adapter has been applied and no tooling source has been edited for this
preparation. Before the quiet window, instantiate clean owned candidate trees,
record their source and adapter hashes, build the common tools under the host
lock, and perform the compatibility smoke listed in the manifest. Do not
disable the existing source gate or label a changed tree as an unmodified main.

## Future cell invocations

Run from the prepared shared-runner trees, with the independently identified
arm daemon installed and a fresh output root for every leg:

```bash
N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 CONTROL_SECS=30 \
  ARTIFACTS_DIR="$LEG_OUTPUT" bash bench/scale/matrix/run-matrix.sh rustbgpd

N_MEMBERS=320 TOTAL_PREFIXES=183040 MIN_LIST=1000 MAX_LIST=40000 \
  SEED=61 CHANGED_FRACTION=0.1 OVERLAP_FRACTION=0 RELOADS=4 CONTROL_SECS=30 \
  CONFIRM_NO_MAIN_PUSHES=1 MEASUREMENT_CANDIDATE_SHA="$RUNNER_CANDIDATE_SHA" \
  ARTIFACTS_DIR="$LEG_OUTPUT" bash bench/scale/irrreload/run-irr-reload.sh rustbgpd-sighup
```

Run three process legs per arm for each cell, rotating v075/main, main/v075,
v075/main. Hold the canonical host lock for the whole window; where runners
take a lock themselves, use the established private nested-runner lock while
the outer canonical lock stays owned. Preserve the actual quiet samples and
native cooldowns. Do not run this on the daytime loaded host.

## Receipt and validity

Retain daemon SIGHUP → complete, harness completion p50, cgroup `memory.peak`,
cohort transition, logged RIB timer/outcome, prestage and phase clocks, and
changed-observer stall p50. With IRR fallback, the logged RIB `elapsed_ms=0`
handoff is not the authoritative transition cost: preserve the cohort clock
and outcome separately. Check actual cgroup placement and `memory.swap.max=0`
for every native daemon; RSS and VmHWM do not substitute for cgroup peak.

Use the original Q2 rule on process-leg medians: S2 transition must improve
with disjoint arm ranges and no primary metric may worsen with disjoint
ranges. A memory difference needs at least 50 MiB. Any missing cgroup value,
failed leg, missing reload, changed binary or provenance mismatch invalidates
the comparison. Keep correlated reloads separate from process repetitions.

The future receipt must state the main-runner/v0.75.0-binary pairing, exact
daemon and instrument digests, the adapter, every run's status and the scope
of the measured shapes. Do not change front-door claims from this preparation.
