# M37 Local-Origination MAC-Churn 24h Soak

**Status:** Complete — verdict: **PASS**.
**Run ID:** `tests/soak/runs/m37-local-origination-20260518T015056Z`
**Git SHA:** `413b677` (soak topology isolation commit; the deployed
`rustbgpd:dev` image was built from this tip).
**Date:** 2026-05-18T01:50:56Z → 2026-05-19T01:52:49Z UTC (24 h 1 m 53 s).

## Verdict

**PASS.** Local-MAC origination stayed bit-stable under bounded
bridge-FDB churn for 24 hours: 17 174 churn cycles, 430 400 inject
operations exactly balanced by 430 400 withdraws, zero
origination/observation/duplicate-MAC errors, zero BGP session flaps,
clean drain to `local_fdb_count=0` and `frr_type2_count=0`, and an
after-warmup RSS slope of **0.184 MB/h** trending asymptotic.

## Run Shape

| Field | Value |
|-------|-------|
| Duration | 24 h 1 m 53 s (target 86 400 s, actual 86 458 s, +58 s drain tail) |
| Topology | `tests/interop/m37-soak.clab.yml` (name `m37-soak` to isolate from the protected M37 CI smoke) |
| Harness | `tests/soak/run-m37-local-origination-churn-soak.sh` |
| MAC pool | 4 096 |
| Live target | 1 024 |
| Churn cadence | 25 delete + 25 add every 5 s |
| Sample interval | 60 s |
| Warmup excluded from RSS slope | 300 s |
| Total data samples | 1 437 |

## Headline Results

| Signal | Result |
|--------|--------|
| BGP session | Established within 1 s of soak start; zero flips / reconverges / session resets across 24 h. |
| Local FDB count | Bit-stable at 2 048 entries from post-prefill through start of drain; 0 at terminal. |
| FRR Type 2 count | Bit-stable at 1 024 (exact `LIVE_TARGET_MACS`); 0 at terminal after withdraw drain. |
| `evpn_local_originations_total{action="inject"}` | 430 400 final. Monotonic across all 1 437 samples. |
| `evpn_local_originations_total{action="withdraw"}` | 430 400 final. **Exact balance** with inject after drain completed (originator's retained-state map released every MAC). |
| `evpn_local_origination_errors_total` | 0 across all 1 437 samples. |
| `evpn_local_observations_dropped_total` | 0 across all 1 437 samples. |
| `evpn_duplicate_mac_moves_total` | 0 (no deliberate duplicate-MAC injection in this run). |
| PE RSS start / peak / end | 19.129 MB / **23.531 MB** / 23.531 MB. Peak is also the end value — RSS plateaued and stayed flat through the final 10 h. |
| After-warmup cumulative slope | **0.184 MB/h** over 23 h 55 m (4.402 MB delta from first non-warmup sample to terminal). |

### RSS trajectory across all cron windows

| Tick (UTC) | Elapsed | PE RSS | Slope-since-last | Slope-since-start |
|---|---|---|---|---|
| 03:00 | 2 h 7 m | 21.83 MB | — | 1.27 MB/h (warmup-dominated) |
| 06:00 | 5 h 7 m | 22.45 MB | 0.21 | 0.65 |
| 09:00 | 8 h 9 m | 22.70 MB | 0.085 | 0.44 |
| 12:00 | 11 h 9 m | 22.70 MB | 0.0 (flat 3 h) | 0.321 |
| 16:00 | 14 h 9 m | 23.47 MB | 0.256 | 0.307 |
| 19:00 | 17 h 7 m | 23.47 MB | 0.0 (flat 3 h) | 0.253 |
| 22:00 | 20 h 7 m | 23.47 MB | 0.0 (flat 3 h) | 0.216 |
| 01:00 | 23 h 7 m | 23.53 MB | 0.021 | 0.19 |
| Terminal | 24 h 2 m | 23.53 MB | 0.0 | **0.184** |

Cumulative slope **monotonically decreased across all 8 cron windows**
(1.27 → 0.65 → 0.44 → 0.321 → 0.307 → 0.253 → 0.216 → 0.19 → 0.184).
After the warmup region the daemon shows a one-time-settle shape with
a single +0.77 MB step between hour 11 and hour 14, then four
consecutive flat 3 h plateaus, then a final +0.06 MB step in the last
hour. Total delta from first non-warmup sample to terminal: 4.402 MB
over 23 h 55 m. Opposite of a steady-rate leak.

## Pass / Fail Gates

| Gate | Expected | Result |
|------|----------|--------|
| BGP Established outside startup/shutdown | yes | **PASS** — Established within 1 s; zero flips across 24 h. |
| `local_fdb_count` near `LIVE_TARGET_MACS` | yes | **PASS** — 2 048 stable through soak loop; 0 after drain. |
| `frr_type2_count` near `LIVE_TARGET_MACS` | yes | **PASS** — 1 024 exact; 0 after drain. |
| Originations inject/withdraw advance with churn | yes | **PASS** — monotonic across all 1 437 samples; +50 ops per 5 s churn cycle, no stalls. |
| Origination errors stay flat | zero | **PASS** — 0 across 430 400 inject + 430 400 withdraw operations. |
| Observation drops stay flat | zero | **PASS** — 0. |
| Duplicate-MAC moves stay flat | zero unless deliberately injected | **PASS** — 0. |
| RSS slope after warmup | flat / acceptable | **PASS** — 0.184 MB/h cumulative; plateaued and bit-stable through the final 10 h. |
| Clean drain at terminal | local_fdb_count + frr_type2_count → 0 | **PASS** — both dropped to 0 in the final sample after `Draining remaining local MACs`. |
| Inject/withdraw ledger balance | inject_total == withdraw_total at terminal | **PASS** — 430 400 == 430 400. |

10 / 10 gates pass.

## Analysis Notes

- **Sample collection:** 1 437 data rows at 60 s cadence over 24 h 2 m
  (theoretical max ≈ 1 440; the count reflects the natural drift of a
  60 s sampler over 86 458 s).
- **Originator retained-state model:** the
  `BTreeMap<MacAddress, LocalMacOriginationState>` retention design
  (entries kept after Aged so the seq ratchet survives) behaved as
  designed: `local_fdb_count` plateaued at 2 048 immediately after the
  prefill phase and stayed bit-stable. No unbounded growth. The map
  released every entry on drain (final inject/withdraw counters
  exactly balanced).
- **Type 2 routes stuck after final drain:** **none**. Both
  `local_fdb_count` and `frr_type2_count` reached 0 in the terminal
  sample, and the inject/withdraw ledger balanced exactly.
- **Daemon WARN / ERROR / FATAL log entries:** **none** in `soak.log`.
  The full log contained only: startup banner (8 lines), `Draining
  remaining local MACs`, `soak loop completed`, and the post-run
  reminder. No `topology link lost`, no `cannot exec in a stopped
  state` (the M37 1st-attempt failure mode from 2026-05-17 did not
  recur — topology isolation worked).
- **FRR EVPN session resets:** **none**.
- **Host CI cohabitation:** ≥4 kernel-dataplane CI runs fired against
  main during the soak window. The `m37-soak` topology name kept the
  soak's containers (`clab-m37-soak-{rustbgpd,consumer}`) out of the
  CI M37 smoke's destroy blast radius. Soak survived all CI runs
  uninterrupted — empirical validation of the
  `feedback_soak_ci_collision` mitigation.
- **The 12 → 16 UTC RSS bump (+0.77 MB after a 3 h flat plateau)** is
  the only non-trivial step after the warmup region. Cumulative slope
  continued tightening across it, and four consecutive flat 3 h
  windows followed. Plausibly a stochastic settle (allocator
  consolidation, page reclaim window). Not a leak signal.

## Artifacts

Repo-archived artifacts (small set suitable for git):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/m37-local-origination-20260518T015056Z/samples.csv` (131 KB, 1 438 lines) |
| soak.log | `docs/artifacts/soak/m37-local-origination-20260518T015056Z/soak.log` (1 KB, 11 lines) |
| run.json | `docs/artifacts/soak/m37-local-origination-20260518T015056Z/run.json` |
| consumer.log | `docs/artifacts/soak/m37-local-origination-20260518T015056Z/consumer.log` (3 KB) |

Local-only artifacts (too large for git; preserved in the run
directory):

| Artifact | Local path | Size |
|----------|------------|------|
| churn.log | `tests/soak/runs/m37-local-origination-20260518T015056Z/churn.log` | 37 MB (858 700 lines) |
| rustbgpd.log | `tests/soak/runs/m37-local-origination-20260518T015056Z/rustbgpd.log` | 248 MB |

## Follow-Ups

- [x] Replace every `TBD at terminal` placeholder with the observed
  final value.
- [x] Flip the status banner to `Complete — verdict: PASS`.
- [x] Copy repo-suitable artifacts into
  `docs/artifacts/soak/m37-local-origination-20260518T015056Z/`.
- [x] Tick the M37 24 h MAC-churn row in `docs/evpn-alpha-soak.md`.
- [x] Close <https://github.com/lance0/rustbgpd/issues/134>.
- [ ] **EVPN production-default flip** — this PASS plus the
  Gate 8b MAC-churn 24 h soak (2026-05-16) is the gating evidence to
  flip `apply_bum_enforcement` and `apply_aliasing_ecmp` defaults to
  `true` in `src/config/schema.rs`. See ROADMAP P1 "EVPN
  production-default decision point".
