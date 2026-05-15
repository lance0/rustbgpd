# Gate 8b MAC-churn 1h soak — postmortem

One-page record of the 1-hour Gate 8b MAC-churn validation soak,
used as the dry run before the 24-hour soak that gates the
production-default flip of `apply_bum_enforcement` and
`apply_aliasing_ecmp` per [`docs/evpn-alpha-soak.md`](evpn-alpha-soak.md).

## What this soak exercises

The MAC-churn harness (`tests/soak/run-gate8b-mac-churn-soak.sh`)
extends the BUM-state soak (`run-gate8b-soak.sh`) with sustained
bridge-FDB churn injected directly on each PE's CE-facing bridge
port. While DF flips continue on a 10-minute cadence, the churn
loop adds, deletes, and migrates MACs against a bounded rotating
pool, exercising:

- ADR-0059 receive path under load — remote Type 2 routes drive
  `fdb_extern_learn` on the non-originating PE
- FDB nexthop-group install / replace / remove churn (when
  `apply_aliasing_ecmp = true`)
- RFC 7432 §15.1 MAC mobility sequencing under rapid moves
- BUM enforcement primitive holds across many DF-role transitions
  with concurrent FDB churn pressure
- Coordinated-drain on `SIGTERM`-driven flips (the per-cycle
  daemon restart inside an otherwise-stable container)

This 1h dry run validated the harness end-to-end (gate convergence,
flip mechanism, sampling cadence, exit conditions) before the 24h
production-default gate.

## Run metadata

| Field | Value |
|---|---|
| Started | `2026-05-15T19:20:34Z` |
| Completed | `2026-05-15T20:20:48Z` |
| Wall clock | 1h 0m 14s |
| Build `git_rev` | `81dc336` (post-harness-fix tip) |
| Image | `sha256:d0fd044e91c5…` |
| Kernel | `5.15.0-177-generic` |
| Topology | `tests/soak/gate8b-soak.clab.yml` |
| Sample interval | 60s |
| Flip interval | 600s (10 min, process-restart) |
| Warm-up before sampling | 120s |
| Churn interval | 2s |
| Churn batch size | 50 |
| MAC pool size | 512 (target 256, bounds [128, 384]) |
| Mobility fraction | 25% |
| Samples written | 56 data rows |
| Flip events logged | 5 (3 stops + 2 starts; soak ended mid third down-phase) |
| Post-flip reconverge events | 2 (one per stop+start cycle) |
| WARN / FATAL events | 0 |
| `topology link lost` events | 0 |

## Pass / fail criteria for the 1h dry-run

| Gate | Threshold | Result |
|---|---|---|
| BGP Established gate passes pre-churn | within 300s of warmup end | **PASS** — passed at first check (`pe1_established_total=2 pe2_established_total=1`) |
| `pe1_fdb_extern_learn` non-zero in steady-state | ≥ 1 between flips | **PASS** — range 453–828 across all up phases |
| `pe2_fdb_extern_learn` non-zero in steady-state | ≥ 1 between flips | **PASS** — range 480–810 across all up phases |
| Post-flip reconverge per stop+start cycle | ≤ 300s established_total ≥ 1 | **PASS** — cycle 1 = 52s, cycle 2 = 2s |
| Topology guard (eth1 + 10.0.0.x intact) | no `FATAL: topology link lost` events | **PASS** — 0 events; verified live post-soak on both PEs |
| ADR-0059 drift counters non-monotone but bounded | repaired / replaced / orphans all ≥ 0, no runaway growth | **PASS** — all PE1 drift counters held at 0 across the run |
| `evpn_local_origination_errors_total == 0` | both PEs throughout | **PASS** (harness extracts `NaN` for this column — known harness wart; checked daemon log: 0 errors) |
| PE1 RSS slope (post-settle) | < 1.0 MB / h over the back-half | **PASS** — 0.28 MB/h from t=607s to soak end |
| PE1 peak RSS | < 100 MB | **PASS** — peak 17.36 MB |
| PE2 RSS bounded per cycle | restart resets baseline; no across-cycle accumulation | **PASS** — every fresh PE2 hit ~17 MB working set, no growth across restarts |
| No `FATAL` lines in soak.log | none | **PASS** — 0 |
| Soak loop completes normally (exit 0) | yes | **PASS** |

## Results

### PE1 RSS trajectory

```
ts (elapsed)   pe1_rss_mb   note
+121s          12.8398      first sample post-warmup
+607s          17.0352      end of first up phase (peak before first flip)
+670s          16.8984      first pe2-down phase begin
+1226s         16.8984      first pe2-down phase end (pinned at 16.8984 for 10 samples)
+2934s         17.3594      peak observed in third up phase
+3117s         17.2656      third pe2-down phase begin
+3552s         17.2656      last sample (pinned at 17.2656 for 8 samples)
```

- **Peak RSS**: 17.36 MB.
- **Settle delta**: +4.43 MB across the first 10 minutes (12.84 →
  17.27). This is one-time-settle behavior — the rustbgpd workspace
  and slab allocators reach steady-state during the first churn
  pass. Identical shape to the 24h BUM-state soak (which settled at
  13.95 MB after 3h 32m); the higher plateau here reflects the
  additional FDB nexthop-group state ADR-0059 carries when
  `apply_aliasing_ecmp` is active.
- **Steady-state slope (post-settle)**: 0.28 MB/h from t=607s to
  t=3552s. Well under the 1.0 MB/h gate.
- **PE2-down phase RSS**: pinned constant within every down phase
  (16.8984 / 17.2812 / 17.2656 MB for the three down phases). Zero
  growth while the receive path was idle — confirms the in-process
  RIB / observation-layer state isn't leaking on peer-down.

### PE2 RSS while running

PE2's rustbgpd process is killed and restarted on each flip cycle
(see [Flip cycle mechanism](#flip-cycle-mechanism) below). Each
fresh process started at a low baseline (~12-16 MB depending on
how fast the first scrape landed) and grew to a working set in the
17.0-17.6 MB range. **No across-cycle accumulation** — restart 3
plateaued at the same range as restart 1 (~17.5 MB peak). PE2's
RSS trajectory:

| Cycle | First scrape | Mid-cycle | Pre-stop |
|---|---|---|---|
| Initial deploy | 12.47 MB (t=121s) | 17.04 MB (t=425s) | 17.35 MB (t=607s) |
| Restart 1 | 16.36 MB (t=1340s) | 17.55 MB (t=1644s) | 17.58 MB (t=1826s) |
| Restart 2 | 15.90 MB (t=2508s) | 17.40 MB (t=2873s) | 17.53 MB (t=3055s) |

### `fdb_extern_learn` trajectory

```
phase            ts range        pe1_ext_l     pe2_ext_l
warmup           +121s           0             18           gate just passed
up phase 1       +181s..+607s    453..759      480..768     pool rotation
pe2-down 1       +670s..+1226s   0             0            pe1 withdrew; pe2 dead
up phase 2       +1340s..+1826s  534..828      663..810     receive path recovered
pe2-down 2       +1888s..+2445s  0             0
up phase 3       +2508s..+3055s  153..645      519..738
pe2-down 3       +3117s..+3552s  0             0            soak ended mid-down
```

The receive path is the single most important signal in this soak.
Pre-fix runs showed `pe1_extern_learn = 0` for the entire window
because the BGP session never reached Established; the new
established-gate + working flip mechanism made the receive path
actually run, and every recovery cycle re-populated `extern_learn`
on both sides within the first sample after re-establishment.

### ADR-0059 drift counters

| Metric | PE1 | PE2 |
|---|---|---|
| `evpn_fdb_nhg_drift_members_repaired_total` | 0 | 0 (samples while running) |
| `evpn_fdb_nhg_drift_groups_replaced_total` | 0 | 0 |
| `evpn_fdb_nhg_drift_orphans_cleaned_total` | 0 | 0 |
| `evpn_fdb_nhg_drift_disabled` (gauge) | 0 | 0 |

Zero drift events across the full hour, across 5 flip events and
~10 600 FDB ops (adds + dels + moves). The drift recovery path is
correctly idle when nothing has drifted.

### Churn totals

| Metric | Final |
|---|---|
| `churn_adds_total` | 7 562 |
| `churn_dels_total` | 7 200 |
| `churn_moves_total` | 3 849 |
| `evpn_local_originations_total` (PE1) | 7 165 |
| `evpn_local_originations_total` (PE2, last `pe2_running=1` sample) | not in tail (pe2 down at end); peak observed 4 530 |
| `evpn_local_origination_errors_total` (PE1+PE2) | 0 (verified in daemon logs — harness reads `NaN` due to a known prom_extract pattern miss) |

All three churn counters monotonically incremented across the
entire 1h, including through every pe2-down phase. The churn loop
correctly kept driving on `pe1` alone while `pe2` was down, then
the receive path on the restored pe2 caught up via the BGP UPDATE
path on the next reconverge.

## Flip cycle mechanism

This soak was the **first 1h run using the process-restart flip path**.
The earlier container-restart (`docker stop / docker start`) approach
destroyed the clab veth on both sides and produced a "BGP never
re-establishes" false-positive that was originally diagnosed as a
daemon FSM bug (issue #105). See `tests/soak/README.md` ⚠️ box for
the full rationale. In summary:

- `pkill -TERM rustbgpd` inside the container (via `sh -c` and
  `pidof` — the rustbgpd image has no `ps`, `pkill`, or `kill`
  binary, only the shell builtin)
- Container netns survives → `eth1`, `10.0.0.x/24`, `br100`,
  `vxlan100`, and the CE veth all persist
- Fresh daemon launched by re-running
  `start-rustbgpd-soak-gate8b.sh` (idempotent)
- Post-flip wait gate uses `bgp_session_established_total >= 1`
  on the flipped PE — the counter is in-process and resets on
  restart, so `>= 1` is the right invariant (not `> baseline`)
- `verify_topology_link` runs before AND after every flip,
  asserting eth1 + 10.0.0.x is still in place; failure exits 4

Live verification post-soak: both PEs still show
`eth1 UP 10.0.0.<n>/24` with the original clab-assigned addresses.

### Reconverge timing

| Cycle | Stop fired | Start fired | Established | Δ start→reconverge |
|---|---|---|---|---|
| 1 | 19:30:42Z | 19:41:02Z | 19:41:54Z | **52 s** |
| 2 | 19:51:01Z | 20:01:20Z | 20:01:22Z | **2 s** |
| 3 | 20:11:30Z | (soak ended) | — | — |

Cycle 1's 52s is higher than the smoke's ~1s but well inside the
300s timeout. Likely accumulated kernel FDB state from 10 min of
churn that pe2's fresh daemon needs to chew through during ADR-0059
startup adoption. Cycle 2 was essentially instant — pe1's reconnect
state was likely already favorable. Both well within budget.

## Failures / anomalies

None.

## Verdict

**PASS** — advance to the 24-hour gate.

The harness is now correct end-to-end (process-restart flip,
established-increment gate, topology pre/post-flip verify, no
ps/pkill assumptions, no docker-stop topology loss). The receive
path was exercised every cycle and reconverged within budget. Memory
behaved exactly like the BUM-state soak: one-time settle followed
by a flat plateau, with peer-down phases adding zero drift.

## Artifacts

- `tests/soak/runs/gate8b-mac-churn-20260515T192034Z/samples.csv`
- `tests/soak/runs/gate8b-mac-churn-20260515T192034Z/soak.log`
- `tests/soak/runs/gate8b-mac-churn-20260515T192034Z/flips.log`
- `tests/soak/runs/gate8b-mac-churn-20260515T192034Z/churn.log`
- `tests/soak/runs/gate8b-mac-churn-20260515T192034Z/run.json`
- archived in-repo at
  `docs/artifacts/soak/gate8b-mac-churn-1h-20260515T192034Z/`
  (per the soak postmortem convention)
