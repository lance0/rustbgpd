# Quiet main-versus-v0.75.0 source preparation

**PREPARATION ONLY: no adapter application/commit, build, config check, smoke,
measurement or queue entry has occurred for this comparison.** These are
future instructions, separate from the completed inventory ABBA.

This updates the execution proposal in the
[published preparation](../policy-transition-release-followup-2026-10-10/quiet-preparation.md)
without rewriting it. The observed source snapshot is
`56cc5c4af5a607951915d175966de17241fca9a9`, tree
`7b9164c074417ba224af5a841403d39f6b51588e`. It is not a measurement freeze
or a claim that this later main was measured. The relevant runners,
generators, renderer, verifier and schemas at that snapshot match the older
prepared `c18a1bd5888e13887f090632931b0a73cce20302` inputs; a future freeze
must requalify then-current bytes.

Original Q2 is **INVALID**: its v0.75 IRR runner supplied no cgroup peak. The
future comparison runs **v0.75.0's daemon binary through main's runner**,
with one immutable frozen-main CLI, renderer and engine in both arms. The
retained v0.75 binary's recorded digest is
`6eb3cad8b8f4b11cd5348f4fa2b3f98d40e7d6e40a3c10a254f37431da350205`;
it was not rehashed or executed during this preparation. Tag commit
`54ed19b5af927f1c8e5064ecb1a497885c15d068`, old binary-build commit
`32942900b6948e2eaaf45ee09ee5142da4784e68`, and old runner commit
`545b91970cdc87012e18f50e2e84d535bbf10d5e` have the same source tree
`47ba5f6a356284c11530a9ada9d991f05df454ac`; these are distinct identities.
Recorded digest/tree proof does not qualify actual old build features.

## Minimal adapter and clean runner identity

The [two-line adapter](quiet-irr-prebuilt-adapter.patch) removes both
unconditional Cargo build lines from main's IRR runner. The older
daemon-only adapter proposal would still rebuild common CLI/renderer/engine,
potentially replacing their installed bytes. Matrix has no build step.
The new proposal preserves every executable/hash/source gate, cgroup window,
quiet/preflight, native status, verifier and acceptance check.

Before a separately authorized window:

1. Freeze then-current main and record its exact commit/tree. Qualify its
   runner, generator, verifier and common tool sources.
2. Apply the adapter in an owned runner source tree and make **one explicit
   adapter commit** based on that frozen main. Record patch digest,
   adapter commit/tree, and frozen-main commit/tree separately.
3. Check out both owned runner trees **clean at that same adapter commit**.
   Set `RUNNER_CANDIDATE_SHA` to its exact 40-hex commit after committing;
   do not use unmodified main or pre-patch HEAD. Install the per-arm daemon
   and identical common tools into separate ignored targets.
4. Full IRR fetches origin/main and requires it to be an ancestor of clean
   HEAD==candidate. If main advances before the freeze/window, refresh or
   rebase the adapter, commit, rebuild common tools and refresh manifests.
   Preserve a source-gate refusal; never disable that gate.

For future fresh daemon builds, use the same normal package command on both
independently clean source arms:

```bash
cargo build --release --locked -j 4 -p rustbgpd -p rustbgpctl
```

Retain immutable binaries and actual normal/including-build unit closures
before reusing the cache. Independently reject daemon/RIB bench-internals;
different releases may legitimately have different dependency/version/unit
inputs, so classify those differences rather than demanding equal graph
bytes. Either qualify the retained old binary's actual build provenance or
make a fresh tag build, retaining the old recorded identity as history.
Build common renderer and scale-profile reloadstall once from frozen main;
use its snapshotted normal CLI. These prerequisites are **unrun**.

## Config compatibility and required future smoke

Source comparison indicates no extra config adapter for the defaults:

| Generated input | Source-compatible fields with v0.75.0 |
| --- | --- |
| S2 | epoch 1; global ASN/router ID/listen/runtime state and `ebgp_requires_policy=false`; JSON/prometheus/owner-only UDS telemetry; rpol files/import/export chains; IPv4 route-server clients with 180 s hold. Worker threads omitted. |
| IRR global/telemetry | Existing renderer plus generator's port 1790/runtime-state patch; graceful-shutdown and eBGP policy booleans; generator replaces telemetry/security with JSON/prometheus/owner-only UDS. Omitted epoch defaults to 1. |
| IRR neighbors | Route-server role/client, per-client-best, control-communities false, IPv4, import chain; existing generator replaces strict next-hop ownership with 180 s hold for the synthetic next hop. |
| IRR policy/datasets | Transparent-export permit definition; static/member rpol units and `irr-member-out` export chain; dataset path bindings. Canonical seed 61, change 0.1 changes 36 prefix files and zero ASN files. |

These are **source compatibility**, not passing actual inputs. After future
freeze/build authorization, retain freshly generated A/B configs and all
policy/dataset inputs. Run both daemons' `--check --strict` on both S2 and
IRR generations, then both through main's tiny S2 (12 peers × 240 prefixes)
and IRR smoke (10 × 100, fixed 100-entry lists), one reload and 5 s control.
Require native status/exit, startup, exact table/EoR/fleet, reload-phase
plumbing and finite nonempty schema-3 cgroup placement/peak/zero-swap proof.
These config checks and smokes are **UNRUN**. IRR smoke omits full source,
quiet and full-dataset acceptance; it cannot replace those full-cell checks.

## Future full-cell invocation inputs

Only after separate execution admission, an outer wrapper owns canonical
host then light locks continuously through full native reap. Both native
runners reopen their inner lock by path; supply one owned nested lock path
while retaining both canonical outer descriptors. Preserve native 300 s
cooldowns, quiet windows, deadlines and first-failure stop, with no automatic
rerun. Refuse inherited shape/test/quiet bypass extensions by names only.

The following are per-leg future calls, with distinct absent output roots,
retained stdout/stderr/native exits and unchanged full acceptance:

```bash
cd "$ARM_RUNNER"
N_PEERS=700 TOTAL_PREFIXES=400400 RELOADS=4 CONTROL_SECS=30 \
  RUSTBGPD_HOST_LOCK="$WINDOW_OUT/nested-runner.lock" \
  ARTIFACTS_DIR="$LEG_OUTPUT" \
  bash bench/scale/matrix/run-matrix.sh rustbgpd

N_MEMBERS=320 TOTAL_PREFIXES=183040 MIN_LIST=1000 MAX_LIST=40000 \
  SEED=61 CHANGED_FRACTION=0.1 OVERLAP_FRACTION=0 RELOADS=4 CONTROL_SECS=30 \
  CONFIRM_NO_MAIN_PUSHES=1 MEASUREMENT_CANDIDATE_SHA="$RUNNER_CANDIDATE_SHA" \
  RUSTBGPD_HOST_LOCK="$WINDOW_OUT/nested-runner.lock" \
  ARTIFACTS_DIR="$LEG_OUTPUT" \
  bash bench/scale/irrreload/run-irr-reload.sh rustbgpd-sighup
```

Native exit 0 alone is insufficient: require the per-cell `status=pass`,
all process exits, exact four reloads, table/EoR/fleet/settlement, cgroup
placement and nonempty finite peak, zero-swap evidence, config/input and
before/after binary/tool integrity. For full IRR, retain actual authoritative
fallback/cohort clocks and full dataset-refresh checks; actor handoff 0 ms
is not complete transition time.

Use three processes per arm per cell in v075/main/main/v075/v075/main order.
Four reloads/process remain correlated. Preserve the original bars: S2
transition improvement with disjoint process-median ranges, no primary
metric regression with disjoint ranges, and memory difference at least
50 MiB; missing required cgroup evidence invalidates. Twelve full cells
require at least 60 minutes of native cooldown plus startup/reloads/quiet
and settlement, roughly a separately reserved 2–3 h window. This preparation
contains **no S2/IRR performance or memory result**.
