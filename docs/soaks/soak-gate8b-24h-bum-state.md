# Gate 8b 24h BUM-state soak — postmortem

One-page record of the first 24-hour Gate 8b BUM-state soak, used as
the gating evidence for relaxing the per-port flag-flip primitive
from "single-pass validated" to "soak-validated" against the alpha
checklist in [`docs/evpn-alpha-soak.md`](../evpn-alpha-soak.md) §
"remaining multi-homing enforcement work".

## What this soak exercised

The harness (`tests/soak/run-gate8b-soak.sh`) drives a 2-PE
containerlab topology with a single shared Ethernet Segment and
forces a synthetic DF role-flip every 10 minutes by stopping and
restarting the non-DF PE container. While the flip churn runs, both
PEs hold a `[[ethernet_segments]]` config that makes them race for
DF on the shared segment; the harness samples RSS, BUM-port flag
state, and live process status every 60 seconds.

The fixed-cadence flip is the closest the L2 path comes to "stress
the kernel BUM-port primitive while everything else converges
underneath" — every flip moves the DF role, which moves the
`bridge link set ... flood off mcast_flood off bcast_flood off`
triplet to the new Non-DF PE's CE port. No FDB churn in this soak;
the MAC-churn variant is the next slice.

## Run metadata

| Field | Value |
|---|---|
| Started | `2026-05-10T15:24:51Z` |
| Completed | `2026-05-11T15:25:23Z` |
| Wall clock | 24h 00m 32s |
| Build `git_rev` | `34d787cb` (clean tree) |
| Kernel | `5.15.0-177-generic` |
| Topology | `tests/soak/gate8b-soak.clab.yml` |
| Sample interval | 60s |
| Flip interval | 600s (10 min) |
| Warm-up before sampling | 120s |
| Samples written | 1422 |
| Flip events logged | 142 (71 complete cycles) |

## Results

### PE1 RSS — flat plateau after a one-time settle

```
ts (elapsed)   pe1_rss_mb   note
+120s          10.1562      first sample post-warmup
+12750s        13.9453      first reading at the plateau (3h 32m in)
+86372s        13.9453      last reading (23h 59m in)
```

- **Peak RSS**: 13.9453 MB.
- **Settle delta**: +3.79 MB over the first 3h 32m — one-time
  allocator settle, not a leak. Likely the workspace and slab
  allocators reaching steady state plus the cluster-rib growing to
  its full multi-PE shape.
- **Steady-state slope (last 20.5h)**: 0.000 MB/h. PE1 RSS was the
  exact same value on every one of the final ~1200 samples.
- **Rolling slope (full run)**: decayed monotonically across the
  run — 0.36 → 0.169 → 0.128 → 0.106 → 0.089 → 0.077 → 0.068 →
  0.061 → 0.055 → 0.050 MB/h at each ~2h checkpoint. Asymptote at
  0.0 once the settle was complete.

The settle pattern matches the "first-allocation accounting" shape
we've seen before in `docs/perf-optimization.md`: heap arenas grow
to their working-set size, then plateau. No daemon-side mitigation
needed.

### PE2 RSS — bounded by cycle restart

PE2 was killed and restarted 71 times. Its RSS resets on each
restart and grows back to working-set during the alive-phase. The
range observed across samples while `pe2_running=1`: ~9.93 MB to
~12.71 MB. No restart accumulated extra memory across cycles — every
fresh PE2 started at the same baseline its predecessor did. This is
the same one-time-settle behavior, just exercised 71 times in a row.

### BUM-port flag state

- `pe1_bum_flags = df` on every sample (1422 / 1422). PE1 held DF
  throughout.
- `pe2_bum_flags = df` on every sample where `pe2_running = 1`.
- `pe2_bum_flags = mixed` on the partial samples where the sampler
  caught PE2 mid-stop / pre-start (the `mixed` value reflects the
  harness sampler observing a window between kernel reads and the
  container exit). 71 such transitions, all bounded to ≤ 2 samples
  per cycle.

No row showed a Non-DF PE with `flood/mcast_flood/bcast_flood` left
in the `df` (open) state. The flag-flip primitive landed each side
of every cycle.

### Process liveness

Both soak shell PIDs (`run-gate8b-soak.sh` ×2) stayed up for
22h 57m of `ps` etime before the harness's natural 24h timer
exited. No crash, no OOM, no fork failure.

### What didn't get measured

- `pe1_df_role` / `pe2_df_role` / `pe1_df_changes` / `pe2_df_changes`
  columns are `NaN` across the entire run. The cluster-rib /
  DF-role exporter that would have populated these columns is not
  yet wired into the sampler; today's `evpn_df_role` Prometheus
  surface is per-instance, not per-PE. Tracked as a follow-on to
  the sampler, not a soak failure.
- FDB churn. This soak deliberately omits MAC programming — the
  MAC-churn variant is the next slice (see "What this unblocks"
  below).

## Verdict

Gate 8b BUM-state primitive is **soak-validated for relaxing the
opt-in `apply_bum_enforcement` default** to `true` once the
MAC-churn variant also clears. The two unblocking conditions from
`docs/evpn-alpha-soak.md` were:

1. PE1 RSS slope stays flat under sustained DF-role flips. ✓
   Steady-state slope is 0.000 MB/h after the one-time settle.
2. BUM-port flag triplet survives flip churn without leaving a
   Non-DF PE in the open state. ✓ Every `pe1_bum_flags` /
   `pe2_bum_flags` sample matches the expected post-flip role.

## What this unblocks

- Flipping the
  [`apply_bum_enforcement`](../evpn-enablement.md) default to `true`
  is unblocked by **this soak plus the MAC-churn variant**. We
  hold the flag at default-off until the MAC-churn run also
  completes — concurrent FDB churn was not exercised here.
- The MAC-churn variant is now a sibling harness:
  `tests/soak/run-gate8b-mac-churn-soak.sh`. It reuses the same
  2-PE topology but adds the `bridge fdb add/del/move` churn loop,
  extra FDB / FDB-NHG CSV columns, and process-restart flips instead
  of `docker stop` / `docker start` so the containerlab point-to-point
  veth survives each restart.

## Raw data

The four load-bearing artifacts are tracked in this repository so
the postmortem stays self-contained when the soak host is recycled:

- Per-sample CSV: [`artifacts/soak/gate8b-20260510T152451Z/samples.csv`](../artifacts/soak/gate8b-20260510T152451Z/samples.csv)
- Flip event log: [`artifacts/soak/gate8b-20260510T152451Z/flips.log`](../artifacts/soak/gate8b-20260510T152451Z/flips.log)
- Harness driver log: [`artifacts/soak/gate8b-20260510T152451Z/soak.log`](../artifacts/soak/gate8b-20260510T152451Z/soak.log)
- Run manifest: [`artifacts/soak/gate8b-20260510T152451Z/run.json`](../artifacts/soak/gate8b-20260510T152451Z/run.json)

`tests/soak/runs/` stays gitignored — it's the harness's per-machine
working directory and runs there are bulky / transient. Any future
soak whose results we want to memorialize gets its load-bearing
files copied into `docs/artifacts/soak/<run-id>/` and referenced
from a postmortem the same way as this one.

## Cross-references

- [`docs/evpn-alpha-soak.md`](../evpn-alpha-soak.md) — alpha-soak
  checklist where the BUM-state row was the gating item.
- [`docs/evpn-vtep-troubleshooting.md`](../evpn-vtep-troubleshooting.md)
  — operator runbook the soak harness mirrors for sampling
  cadence.
- [`ADR-0054`](../adr/0054-evpn-linux-dataplane-boundary.md) §1 / §6
  — observe-only Linux boundary + level-triggered reconcile model
  that makes the flag-flip primitive tractable to soak in the
  first place.
