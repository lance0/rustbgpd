# M37 Local-Origination MAC-Churn 24h Soak

**Status:** In flight — soak started 2026-05-18T01:50:56Z, terminal
expected 2026-05-19T01:50:56Z. This postmortem is pre-drafted from the
mid-run data through ~18h; the verdict line, final / peak RSS, total
sample count, and the after-warmup cumulative slope are finalized at
terminal.
**Run ID:** `tests/soak/runs/m37-local-origination-20260518T015056Z`
**Git SHA:** `413b677` (soak topology isolation commit; the deployed
`rustbgpd:dev` image was built from this tip).
**Date:** 2026-05-18 → 2026-05-19 UTC

## Verdict

`TBD at terminal` — pending the final drain phase and analyzer pass.

One-sentence summary of whether local-MAC origination stayed stable
under bounded bridge-FDB churn: `TBD`.

## Run Shape

| Field | Value |
|-------|-------|
| Duration | 24h target (`SOAK_HOURS=24` → 86400 s) |
| Topology | `tests/interop/m37-soak.clab.yml` (name `m37-soak` to isolate from the protected M37 CI smoke) |
| Harness | `tests/soak/run-m37-local-origination-churn-soak.sh` |
| MAC pool | 4096 |
| Live target | 1024 |
| Churn cadence | 25 delete + 25 add every 5 s |
| Sample interval | 60 s |
| Warmup excluded from RSS slope | 300 s |

## Headline Results

`TBD at terminal` rows hold mid-run snapshots through 19:00 UTC
(~17 h elapsed); the analyzer pass after terminal replaces them
with final numbers.

| Signal | Result |
|--------|--------|
| BGP session | Established within 1 s of soak start; no flips, reconverges, or session resets observed through mid-run. |
| Local FDB count | Stable at 2048 entries across the entire mid-run window. |
| FRR Type 2 count | Stable at 1024 (exactly matches `LIVE_TARGET_MACS`). |
| `evpn_local_originations_total{action="inject"}` | Monotonic; ~307 k by 17 h, matching `mac_add_total` to within the +1 startup steady-state offset. |
| `evpn_local_originations_total{action="withdraw"}` | Monotonic; ~306 k by 17 h, lagging inject by exactly `LIVE_TARGET_MACS` (the per-cycle add-before-delete invariant). |
| `evpn_local_origination_errors_total` | 0 across all samples. |
| `evpn_local_observations_dropped_total` | 0 across all samples. |
| `evpn_duplicate_mac_moves_total` | 0 (no deliberate duplicate-MAC injection in this run). |
| PE RSS start / peak / end | 19.129 MB start; mid-run peak 23.469 MB; **end TBD at terminal**. |
| Steady-state RSS slope | Cumulative slope tightening from 1.27 MB/h (warmup-dominated) to 0.253 MB/h at 17 h; **final after-warmup slope TBD at terminal**. |

### Mid-run RSS trajectory

| Tick (UTC) | Elapsed | PE RSS | Slope-since-last | Slope-since-start |
|---|---|---|---|---|
| 03:00 | 2 h 7 m | 21.83 MB | — | 1.27 MB/h (warmup-dominated) |
| 06:00 | 5 h 7 m | 22.45 MB | 0.21 | 0.65 |
| 09:00 | 8 h 9 m | 22.70 MB | 0.085 | 0.44 |
| 12:00 | 11 h 9 m | 22.70 MB | 0.0 (flat 3 h) | 0.321 |
| 16:00 | 14 h 9 m | 23.47 MB | 0.256 | 0.307 |
| 19:00 | 17 h 7 m | 23.47 MB | 0.0 (flat 3 h) | 0.253 |

Cumulative slope monotonically decreasing across all cron windows;
after the warmup region the daemon shows two consecutive flat 3 h
plateaus separated by a single 0.77 MB tick. Consistent with a
one-time-settle-then-plateau shape, opposite of a steady-rate leak.

## Pass / Fail Gates

| Gate | Expected | Result |
|------|----------|--------|
| BGP Established outside startup/shutdown | yes | **Mid-run pass** — Established within 1 s of start, no flips through 17 h. Finalize at terminal. |
| `local_fdb_count` near `LIVE_TARGET_MACS` | yes | **Mid-run pass** — 2048 (each live MAC counts once on each side of the bridge-port enslavement; ratio stable). |
| `frr_type2_count` near `LIVE_TARGET_MACS` | yes | **Mid-run pass** — 1024, exact match. |
| Originations inject/withdraw advance with churn | yes | **Mid-run pass** — inject/withdraw monotonic; +50 ops per 5 s churn cycle, no stalls. |
| Origination errors stay flat | zero | **Mid-run pass** — 0 across 17 h / ~300 k operations. |
| Observation drops stay flat | zero | **Mid-run pass** — 0. |
| Duplicate-MAC moves stay flat | zero unless deliberately injected | **Mid-run pass** — 0 (no duplicate-MAC scenario in this soak). |
| RSS slope after warmup | flat / acceptable | **Trending pass** — cumulative slope 0.253 MB/h at 17 h and still tightening. Final after-warmup-window slope TBD at terminal. |

## Analysis Notes

Mid-run observations (pre-terminal):

- Sample collection: ~770 data rows expected through 17 h at 60 s
  cadence; final count `TBD at terminal` (24 h ≈ 1440 rows minus the
  warmup window).
- The originator's retained-state model has plateaued at the bounded
  MAC pool: `local_fdb_count` and `frr_type2_count` have been
  bit-stable since the prefill phase completed. The
  `BTreeMap<MacAddress, LocalMacOriginationState>` retention design
  (entries kept after Aged so the seq ratchet survives) is behaving
  as designed — no unbounded growth.
- Type 2 routes stuck after final drain: `TBD at terminal` (drain
  runs after the soak loop exits; the post-drain Type 2 count is
  the assertion the drain succeeded).
- Daemon WARN / ERROR / FATAL log entries: **none** through mid-run.
  `soak.log` only shows the startup banner; the harness logs at
  event boundaries only and no event has triggered.
- FRR EVPN session resets: **none** through mid-run.
- The 12 → 16 UTC RSS bump (+0.77 MB after a 3 h flat plateau) is
  the only non-trivial step since the warmup region. Cumulative
  slope continued tightening after it, and the next 3 h window
  returned to flat. Plausibly stochastic settle; not a leak signal.

## Artifacts

Raw artifacts stay local under `tests/soak/runs/` unless intentionally
published elsewhere. After terminal, copy the artifact set to
`docs/artifacts/soak/m37-local-origination-<UTC>/`.

| Artifact | Path |
|----------|------|
| samples.csv | `tests/soak/runs/m37-local-origination-20260518T015056Z/samples.csv` |
| soak.log | `tests/soak/runs/m37-local-origination-20260518T015056Z/soak.log` |
| churn.log | `tests/soak/runs/m37-local-origination-20260518T015056Z/churn.log` |
| rustbgpd.log | `tests/soak/runs/m37-local-origination-20260518T015056Z/rustbgpd.log` |
| consumer.log | `tests/soak/runs/m37-local-origination-20260518T015056Z/consumer.log` |
| run.json | `tests/soak/runs/m37-local-origination-20260518T015056Z/run.json` |

## Follow-Ups

After terminal:

- Run `python3 tests/soak/analyze-m37-local-origination-soak.py
  tests/soak/runs/m37-local-origination-20260518T015056Z` (if the
  analyzer exists; otherwise compute final slope + plot RSS from
  `samples.csv` directly).
- Replace every `TBD at terminal` placeholder above with the
  observed final value.
- Flip the status banner to `Complete — verdict: PASS` (or `FAIL`).
- Copy raw artifacts into `docs/artifacts/soak/m37-local-origination-<UTC>/`.
- Close or update <https://github.com/lance0/rustbgpd/issues/134>.
- Tick the M37 24 h MAC-churn row in `docs/evpn-alpha-soak.md`.
- If verdict is PASS, this soak is the gating evidence to flip
  `apply_bum_enforcement` and `apply_aliasing_ecmp` defaults to
  `true` (see ROADMAP P1 "EVPN production-default decision point").
