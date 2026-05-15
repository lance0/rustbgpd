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

This 1h dry run validates the harness end-to-end (gate convergence,
flip mechanism, sampling cadence, exit conditions) before the 24h
production-default gate.

## Run metadata

| Field | Value |
|---|---|
| Started | `<ISO timestamp from run.json.started_at>` |
| Completed | `<ISO timestamp from soak.log soak-loop-completed>` |
| Wall clock | `<HhMMmSSs>` |
| Build `git_rev` | `<from run.json>` |
| Kernel | `<from run.json>` |
| Topology | `tests/soak/gate8b-soak.clab.yml` |
| Sample interval | 60s |
| Flip interval | 600s (10 min, process-restart) |
| Warm-up before sampling | 120s |
| Churn interval | 2s |
| Churn batch size | 50 |
| MAC pool size | 512 (target 256, bounds [128, 384]) |
| Mobility fraction | 25% |
| Samples written | `<row_count from samples.csv minus header>` |
| Flip events logged | `<from flips.log>` (n stop + n start cycles) |
| Post-flip reconverge events | `<from soak.log: post-flip re-established>` |
| WARN / FATAL events | `<from soak.log>` |

## Pass / fail criteria for the 1h dry-run

| Gate | Threshold | Result |
|---|---|---|
| BGP Established gate passes pre-churn | within 300s of warmup end | TBD |
| `pe1_fdb_extern_learn` is non-zero in steady-state | ≥ 1 between flips | TBD |
| `pe2_fdb_extern_learn` is non-zero in steady-state | ≥ 1 between flips | TBD |
| Post-flip reconverge per stop+start cycle | ≤ 10s established_total ≥ 1 | TBD |
| Topology guard (eth1 + 10.0.0.x intact) | no `FATAL: topology link lost` events | TBD |
| ADR-0059 drift counters non-monotone but bounded | repaired / replaced / orphans all ≥ 0, no runaway growth | TBD |
| `evpn_local_origination_errors_total == 0` | both PEs throughout | TBD |
| PE1 RSS slope (post-settle) | < 1.0 MB / h over the back-half | TBD |
| PE1 peak RSS | < 100 MB | TBD |
| PE2 RSS bounded per cycle | restart resets baseline; no across-cycle accumulation | TBD |
| BUM-port flag triplet flips on DF transition | flood/mcast_flood/bcast_flood off on Non-DF CE port | TBD |
| No `FATAL` lines in soak.log | none | TBD |
| Soak loop completes normally (exit 0) | yes | TBD |

## Results

### PE1 RSS trajectory

```
ts (elapsed)   pe1_rss_mb   note
+120s          <val>        first sample post-warmup
<plateau ts>   <val>        first reading at plateau
+3600s         <val>        last reading (soak end)
```

- **Peak RSS**: `<val>` MB.
- **Settle delta**: `<val>` MB across the first `<duration>`.
- **Steady-state slope (post-settle)**: `<val>` MB/h.
- **Rolling slope (full run)**: `<series at ~10-min checkpoints>`.

### PE2 RSS trajectory

PE2's rustbgpd process is killed and restarted on each flip cycle
(see [Flip cycle mechanism](#flip-cycle-mechanism) below). Its RSS
resets to baseline on each restart and grows back to working-set
during the alive-phase. Observed range across `pe2_running=1`
samples: `<min>` MB to `<max>` MB. No restart accumulated extra
memory across cycles.

### `fdb_extern_learn` trajectory

```
ts (elapsed)   pe1_ext_l   pe2_ext_l   note
+120s          <val>       <val>       gate pass / first sample
<peak ts>      <peak>      <peak>      steady-state high
<stop ts>      0           NaN         PE2 daemon down — pe1 withdrew
<recovery ts>  <val>       <val>       post-flip reconverge
```

The receive path is the single most important signal in this soak.
Pre-fix runs showed `pe1_extern_learn = 0` for the entire window
because the BGP session never reached Established; the new
established-gate + working flip mechanism makes the receive path
actually run.

### ADR-0059 drift counters

| Metric | PE1 | PE2 |
|---|---|---|
| `evpn_fdb_nhg_drift_members_repaired_total` | `<val>` | `<val>` |
| `evpn_fdb_nhg_drift_groups_replaced_total` | `<val>` | `<val>` |
| `evpn_fdb_nhg_drift_orphans_cleaned_total` | `<val>` | `<val>` |
| `evpn_fdb_nhg_drift_disabled` (gauge) | `<val>` | `<val>` |

Expected shape: small non-monotone counts as the drift recovery
catches the residual state changes from flip restarts and pool
rotation. Anything resembling per-second growth is a leak symptom
and needs a follow-up issue.

### Churn totals

| Metric | Final |
|---|---|
| `churn_adds_total` | `<val>` |
| `churn_dels_total` | `<val>` |
| `churn_moves_total` | `<val>` |
| `evpn_local_originations_total` (PE1) | `<val>` |
| `evpn_local_originations_total` (PE2) | `<val>` |
| `evpn_local_origination_errors_total` (PE1+PE2) | `<val>` |

### BUM-port flag state across flips

DF transitions should flip the kernel
`IFLA_BRPORT_FLOOD / MCAST_FLOOD / BCAST_FLOOD` triplet on the
Non-DF PE's CE-facing port:

| Flip # | Time | DF → Non-DF transition | flood / mcast / bcast (Non-DF) |
|---|---|---|---|
| 1 | `<ts>` | PE1 → PE2 (or vice versa) | off / off / off |
| 2 | `<ts>` | ... | ... |
| ... | | | |

## Flip cycle mechanism

This soak is the **first to use the process-restart flip path**,
not the previous container-restart (`docker stop / docker start`).
See `tests/soak/README.md` ⚠️ box for the full rationale; in short:

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

The earlier container-restart approach destroyed the clab veth on
both sides, producing a "BGP never re-establishes" symptom that
was diagnosed as a daemon FSM bug before the topology-lost root
cause was identified.

## Failures / anomalies

(none, or list with timestamps and remediation references)

## Verdict

(pass / fail / advance-to-24h)

## Artifacts

- `tests/soak/runs/gate8b-mac-churn-<UTC>/samples.csv`
- `tests/soak/runs/gate8b-mac-churn-<UTC>/soak.log`
- `tests/soak/runs/gate8b-mac-churn-<UTC>/flips.log`
- `tests/soak/runs/gate8b-mac-churn-<UTC>/churn.log`
- `tests/soak/runs/gate8b-mac-churn-<UTC>/run.json`
- archived into `docs/artifacts/soak/gate8b-mac-churn-<UTC>/` on
  completion (per the soak postmortem convention)
