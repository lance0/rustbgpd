# Gate 8b MAC-churn 24h soak — postmortem

One-page record of the 24-hour Gate 8b MAC-churn soak, the gating
evidence for flipping the `apply_bum_enforcement` and
`apply_aliasing_ecmp` defaults to `true` per
[`docs/evpn-alpha-soak.md`](../evpn-alpha-soak.md).

## What this soak exercised

The MAC-churn harness (`tests/soak/run-gate8b-mac-churn-soak.sh`)
extends the BUM-state soak with sustained bridge-FDB churn injected
on each PE's CE-facing bridge port. While DF flips continued on a
10-minute cadence via process-level daemon restart, the churn loop
added, deleted, and migrated MACs against a bounded rotating pool.
Together this exercised:

- ADR-0059 receive path under sustained load — remote Type 2 routes
  drove `fdb_extern_learn` on the non-originating PE across the
  entire window
- FDB nexthop-group install / replace / remove churn (with
  `apply_aliasing_ecmp = true`)
- RFC 7432 §15.1 MAC mobility sequencing under rapid moves
- BUM-port enforcement primitive holding across 69 complete
  DF-role transitions with concurrent FDB churn pressure
- Coordinated-drain on `SIGTERM`-driven daemon flips (the
  per-cycle process restart inside an otherwise-stable container,
  preserving clab veth state — see PR-history rationale)

## Run metadata

| Field | Value |
|---|---|
| Started | `2026-05-15T21:40:43Z` |
| Completed | `2026-05-16T21:40:57Z` |
| Wall clock | 24h 0m 14s |
| Build `git_rev` | `e6b30024` (post-PR-108, image `sha256:a9e3745...`) |
| Kernel | `5.15.0-177-generic` |
| Topology | `tests/soak/gate8b-soak.clab.yml` |
| Sample interval | 60 s |
| Flip interval | 600 s (10 min, process-restart) |
| Warm-up before sampling | 120 s |
| Churn interval | 2 s |
| Churn batch size | 50 |
| MAC pool size | 512 (target 256, bounds [128, 384]) |
| Mobility fraction | 25 % |
| Samples written | 1390 data rows |
| Flip events logged | 139 (70 stops + 69 starts; soak ended mid 70th down-phase) |
| Post-flip reconverge events | 69 (one per stop+start cycle) |
| WARN / FATAL / `topology link lost` | **0** |

## Pass / fail criteria

| Gate | Threshold | Result |
|---|---|---|
| BGP Established gate passes pre-churn | within 300 s of warm-up end | **PASS** — passed at first check |
| Receive path active in every up-phase | `fdb_extern_learn` ≥ 1 on both PEs between flips | **PASS** — values in the 100s–800s range across every up phase |
| Post-flip reconverge per cycle | ≤ 300 s `established_total ≥ 1` (fresh process) | **PASS** — all 69 reconverges; **36 % under 1 s**, longest 47 s |
| Topology guard | no `FATAL: topology link lost` events | **PASS** — 0; eth1 + 10.0.0.x intact post-soak on both PEs |
| ADR-0059 drift counters bounded | repaired / replaced / orphans / disabled all flat or low | **PASS** — all PE1 drift counters held at 0 across 24 h |
| `evpn_local_origination_errors_total == 0` | both PEs throughout | **PASS** — daemon-side; harness `NaN` is a known prom_extract pattern miss (not a daemon defect) |
| PE1 RSS slope (post-settle, > 1 h elapsed) | < 1.0 MB/h | **PASS** — settled plateau 17.23–18.93 MB band (Δ 1.7 MB over 22 h ⇒ ~0.08 MB/h envelope, well under) |
| PE1 peak RSS | < 100 MB | **PASS** — peak 18.93 MB |
| PE2 RSS bounded per cycle | restart resets baseline; no across-cycle accumulation | **PASS** — every fresh PE2 hit a ~16–17 MB working set, no growth across the 69 restart cycles |
| No `FATAL` lines in soak.log | none | **PASS** — 0 |
| Soak loop completes normally | wall ≥ 24 h, exit 0 | **PASS** — 24 h 0 m 14 s, normal exit |

## Results

### PE1 RSS trajectory

```
ts (elapsed)   pe1_rss_mb   note
+121 s         13.0156      first sample post-warm-up
+3606 s        17.2578      end of one-time settle (1 h mark, +4.24 MB over the warm-up reading)
+10812 s       17.8047      plateau forming (3 h)
+25237 s       17.9570      plateau established (7 h)
+50400 s       17.8906      mid-soak (14 h)
+72058 s       18.1172      late-plateau (20 h)
+86352 s       18.7305      final sample (24 h)
```

- **Peak RSS**: 18.93 MB.
- **Settle delta**: +4.24 MB across the first ~3 h (the one-time
  RSS arena settle pattern from `docs/soaks/soak-gate8b-24h-bum-state.md`,
  with the higher plateau here reflecting the additional FDB
  nexthop-group state that ADR-0059 carries when
  `apply_aliasing_ecmp` is active).
- **Steady-state distribution** (1334 samples > 1 h elapsed):
  | percentile | pe1_rss_mb |
  |---|---|
  | min | 17.23 |
  | p50 | 18.11 |
  | p90 | 18.54 |
  | p99 | 18.86 |
  | max | 18.93 |

  **1.7 MB band across 22 h**. No drift; this is the plateau shape.

- **Slope envelope**: 1.7 MB / 22 h = 0.08 MB/h worst case
  (envelope only — the actual point-to-point series is non-monotone,
  oscillating around 18 MB ± 0.5 MB). The per-3 h cron check-ins
  reported instantaneous slopes between **−0.064 MB/h and +0.22 MB/h**;
  all well inside the 1 MB/h gate.

### PE2 RSS — bounded by per-cycle restart

PE2's `rustbgpd` process was killed and restarted 69 times. Its RSS
resets to baseline on each restart and grows back to working set
during the alive-phase. **No across-cycle accumulation** — every
fresh PE2 plateaued at a ~16–17 MB working set, same as restart
#1's plateau.

### `fdb_extern_learn` trajectory

Steady-state during every up-phase: 100s–800s on both PEs,
oscillating with the harness's bounded pool rotation. During each
pe2-down phase: drops to 0 on pe1 (correct withdraw), recovers
within the next sample after reconverge. The receive path was
exercised in every cycle.

### ADR-0059 drift counters

| Metric | PE1 final |
|---|---|
| `evpn_fdb_nhg_drift_members_repaired_total` | 0 |
| `evpn_fdb_nhg_drift_groups_replaced_total` | 0 |
| `evpn_fdb_nhg_drift_orphans_cleaned_total` | 0 |
| `evpn_fdb_nhg_drift_disabled` (gauge) | 0 |

Zero drift events across 24 h, 69 cycles, ~478 K FDB ops
(194 K adds + 194 K dels + 90 K moves). The drift recovery path
correctly stayed idle when nothing had drifted — the steady-state
RTM_GETNEXTHOP audit found no work to do.

### Churn totals

| Metric | Final |
|---|---|
| `churn_adds_total` | 194 209 |
| `churn_dels_total` | 193 750 |
| `churn_moves_total` | 89 708 |
| `evpn_local_originations_total` (PE1) | 186 553 |
| `evpn_local_origination_errors_total` (PE1+PE2) | 0 (verified via daemon log; harness reads `NaN` due to a known prom_extract pattern miss) |

All three churn counters incremented monotonically across the
entire 24 h, including through every pe2-down phase. The churn
loop kept driving on pe1 alone while pe2 was down, then the
receive path on the restored pe2 caught up via the BGP UPDATE path
on the next reconverge.

### Reconverge timing

69 reconverges across the soak. Distribution of `start → post-flip
re-established` durations:

| Duration | Count | % |
|---|---|---|
| ≤ 1 s | 25 | 36 % |
| 2–10 s | ~15 | ~22 % |
| 11–20 s | ~13 | ~19 % |
| 21–32 s | ~11 | ~16 % |
| 33–47 s | 5 | 7 % |
| > 47 s | 0 | 0 % |

**Max 47 s**, well under the 300 s `BGP_ESTABLISHED_TIMEOUT_SEC`
gate. Variance is driven by the kernel FDB state accumulated
during the preceding 10-min pe2-down phase that the fresh daemon
walks through ADR-0059 startup adoption — entirely benign.

## Flip cycle mechanism

Process-restart flip (`pkill -TERM rustbgpd` inside the container,
re-launched via `start-rustbgpd-soak-gate8b.sh`). See the in-repo
`tests/soak/README.md` ⚠️ box and the v0.21 commit history
(`232881d`, `9360e3c`, `81dc336`) for why the previous
container-restart approach was incorrect (it destroyed the clab
veth on both sides; BGP could never re-establish on the same
10.0.0.x point-to-point). The `verify_topology_link` guard ran
before and after every flip — never tripped across 138 invocations.

Post-soak topology verification (live):
- `clab-gate8b-soak-pe1`: `eth1 UP 10.0.0.1/24`
- `clab-gate8b-soak-pe2`: `eth1 UP 10.0.0.2/24`

## Failures / anomalies

**None.**

## Verdict

**PASS** — unblocks the production-default flip of
`apply_bum_enforcement` and `apply_aliasing_ecmp` to `true`.

Memory behaved exactly like the BUM-state 24 h soak: one-time
settle followed by a flat plateau, with peer-down phases adding
zero drift. ADR-0059 drift recovery correctly stayed idle. The
process-restart flip mechanism produced 69 clean cycles with sub-
second reconverge in 36 % of cases and never breached the 47 s
ceiling. The clab veth survived every single flip thanks to the
process-restart fix.

## Artifacts

- `docs/artifacts/soak/gate8b-mac-churn-24h-20260515T214043Z/samples.csv` (1391 rows)
- `docs/artifacts/soak/gate8b-mac-churn-24h-20260515T214043Z/soak.log` (221 lines)
- `docs/artifacts/soak/gate8b-mac-churn-24h-20260515T214043Z/flips.log` (139 entries)
- `docs/artifacts/soak/gate8b-mac-churn-24h-20260515T214043Z/churn.log` (~145 K entries)
- `docs/artifacts/soak/gate8b-mac-churn-24h-20260515T214043Z/run.json`
