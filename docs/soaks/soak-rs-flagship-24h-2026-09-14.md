# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-09-14

**Status:** Complete — verdict: **PASS** under the current gates
(reanalysis with the analyzer at `477c98aac`); the original on-host
verdict is **FAIL**, on the superseded zero-miss `management_cadence` rule
only. Both verdicts are archived; the pass is labelled as a reanalysis
throughout.
**Run ID:** `tests/soak/runs/soak-rs-flagship-20260913T230440Z`
**Daemon version:** v0.70.0 release commit, git SHA
`ee6215af61222a43c3a8019ee0352ecd5df77913`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA)
**Scenario config hash:**
`71ed1bf4663fd440b240fc2b97d41fe38453ae77b4bee085521efbdc1215fb2a`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`31bc187a0c7fc8a68a3419aa233a9bd81c20536205862dedaba6af53c64b488d`;
`rbgp` and `reloadstall` digests in `binaries.sha256`
**Analyzer and gate revision:** two verdicts over the same run directory.

- *Original verdict* — `verdict.json` (sha256
  `cb353d87d8f27c3663ac69cda3483e2b394a052ef1a0c3f4ec55d9f9dd60835e`),
  written on the soak host by `tests/soak/analyze-soak-rs-flagship.py` at
  the run SHA (analyzer sha256
  `c04084da989c0b3e436b492e5edee5972e619f6cdee103618c62a5a4663d1991`)
  against `docs/soaks/soak-acceptance-gates.md` at the run SHA.
- *Reanalysis* — `verdict-calibrated-cadence.json` (sha256
  `28f3d2f0561ceab394c84a5e130cd9a86254f1514859ca8f7b7116a181a2454d`),
  written after the run by the analyzer at `477c98aac` (analyzer sha256
  `fa53868bfa6a4f7ac3eb9be052f88991a329d12a3f4920556ac278293cb944f8`)
  against the gates document at that revision.

**Date:** 2026-09-13T23:04:40Z runner start (build); sampling
2026-09-13T23:18:24Z → management load ended 2026-09-14T23:41:23Z, with the
engine's first Administrative Shutdown 0.2 s later (87,779 s = 24 h 22 m 59 s
measured window; the serialized trip windows extend the 86,400 s target)

## Verdict

**PASS under the current gates (reanalysis); original verdict FAIL on
`management_cadence` only.**

The original on-host verdict failed one of 20 analyzer gates: 17 missed
1 s `/metrics` slots plus the `scheduled interval drift` entry those
skipped slots produce under the zero-miss rule. The reanalysis passes all
20 gates. Every other gate value is identical between the two verdict
files and passes in both: zero management-correctness failures across 140,578
completed operations, 48 of 48 SIGHUP reloads barrier-verified complete,
6 of 6 max-prefix trip chains with exact breach and flap accounting, the
session floor on all 2925 samples, zero readiness breaches, peak RSS
725.8 MB against a 3072 MB ceiling, late-window RSS slope −1.018 MB/h
against 10 MB/h, zero daemon `ERROR` records, and zero abort records.

### Why the two verdicts differ

The analyzer and gates changed in one rule between the run SHA and
`477c98aac`: the management cadence bound
([soak acceptance gates](soak-acceptance-gates.md), scenario 10,
"Management-load lifetime and cadence" row).

| | Original (run SHA) | Current (`477c98aac`) |
|---|---|---|
| Missed schedule slots | zero allowed for any operation | allowed only inside a reload window, `[reload N issued − 2 s, reload N complete + 2 s]` from `cycles.log`, placed on the wall clock through the terminal summary's UTC anchor |
| Per-window limit | — | at most 2 missed slots per window per operation |
| Fails | any missed slot | a miss outside every window, a third miss in one window, a schedule off the interval grid, or a miss that cannot be placed on the wall clock |

The gates document ties the allowance to the
[operator read path decision (ADR-0132)](../adr/0132-operator-read-path.md):
a read that lands during a reload commit gets its deadline, not priority
over route work. The rule change landed on main while this run was in
progress (committed 2026-09-14T16:53Z, before the run's verdict at
23:41Z). The reanalysis applied it to the unchanged run directory after the
run completed; the original verdict is retained as the on-host result.

Both verdicts were reproduced from the retained run directory: the run-SHA
analyzer exits 1 and the `477c98aac` analyzer exits 0, each producing the
archived verdict content exactly (the archived files carry one trailing
newline).

## Release relationship

v0.70.0 (`ee6215af61222a43c3a8019ee0352ecd5df77913`) was tagged on
2026-09-13, before this run started. The
[2026-09-12 run](soak-rs-flagship-24h-2026-09-12.md) that the release
shipped on ran a pre-release commit and failed the cadence gate; its
receipt stated that a qualifying run on the released commit would follow.
This is that run: it qualifies the released commit under the current
gates. It does not cover runtime or dependency changes on main after
v0.70.0. Timing figures from this guest are diagnostic, not performance
claims.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,761 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2925 |

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 118,929–119,708 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,595 scheduled | 140,578 completed | metrics 87,763 of 87,780; neighbor, policy_stats, and rib_prefix 17,556 of 17,556 each; doctor 147 of 147 |

## Gates — measured vs precommitted

Bounds quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
`477c98aac`; measured values from `verdict-calibrated-cadence.json`.
Analyzer gate keys are shown in parentheses. Only the cadence row differs
from the original verdict, shown in the last column.

| Gate | Precommitted bound | Measured | Result | Original verdict |
|------|--------------------|----------|--------|------------------|
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2925 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** | PASS |
| Reload accounting exact (`reload_accounting`) | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** | PASS |
| Trip accounting exact (`trip_accounting`) | executed == planned; full per-cycle evidence chain; zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** | PASS |
| Exceeded-counter exact (`exceeded_exact`) | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** | PASS |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == executed trips | 6 == 6 | **PASS** | PASS |
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 725.8 MB | **PASS** | PASS |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | −1.0176 MB/h | **PASS** | PASS |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** | PASS |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 5,610,021,203 | **PASS** | PASS |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 0 status failures, 0 latency failures, longest consecutive 0; 0 scrape failures, 0 observation gaps | **PASS** | PASS |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** | PASS |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start ≤ measured-window end ≤ stop request ≤ load end ≤ engine release; load end precedes the first received Administrative Shutdown | ordering held, including last operation ≤ load end ≤ engine release; load end (2026-09-14T23:41:23.72Z) precedes the first Administrative Shutdown (23:41:23.93Z) | **PASS** | PASS |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,763; neighbor 17,556; policy_stats 17,556; rib_prefix 17,556; doctor 147 | **PASS** | PASS |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.9998; every other operation 1.0 | **PASS** | PASS |
| Management-load cadence (`management_cadence`) | every missed slot inside a reload window `[issued − 2 s, complete + 2 s]`; at most 2 per window per operation; limit 2 | metrics 17 missed, 1 in each of 17 distinct reload windows, 0 outside; neighbor, policy_stats, rib_prefix, doctor 0 missed; 0 defects | **PASS** | FAIL — `metrics: missed=17`; `metrics: scheduled interval drift` |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | 0 | **PASS** | PASS |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 147 attempts, 0 failures | **PASS** | PASS |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 206,526 records, 0 `ERROR`, 0 defects | **PASS** | PASS |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2925 | **PASS** | PASS |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** | PASS |

20 / 20 gates pass in the reanalysis (`verdict: pass`); 19 / 20 in the
original (`verdict: fail`). Both files are archived below.

## Analysis notes

Observed:

- Sample accounting (`samples.csv`): 2925 rows at a 30 s cadence through
  elapsed 87,761 s, with no scrape failures and no observation gaps.
- RSS trajectory (`samples.csv`): 469.2 MB at the first sample; 5th–95th
  percentile 500.7–561.1 MB; the 725.8 MB peak at 2026-09-14T08:26:10Z,
  inside reload 19 (issued 08:26:07Z, complete 08:26:16Z); late-window
  slope −1.018 MB/h. The intern gauge (`bgp_rib_attr_intern_global_size`)
  stayed at 999–1000 entries. The highest readiness latency was 168.0 ms,
  every response HTTP 200.
- **Cadence detail** (`verdict-calibrated-cadence.json`
  `management_cadence.value.operations.metrics.per_reload`): one missed
  `/metrics` slot in each of reloads 3, 4, 6, 8, 13, 20, 23, 25, 30, 31,
  33, 34, 39, 43, 44, 45, and 46; none outside a reload window, and no
  window holding more than one. Placed on the wall clock through the
  terminal summary's UTC anchor (`management-plane-load.jsonl`, retained
  outside the repository), each missed slot falls 5–7 s after its reload
  was issued and 3–5 s before its barrier-verified completion, to the
  one-second resolution of `cycles.log`. The neighbor, policy_stats,
  rib_prefix, and doctor schedules missed no slot.
- **Management correctness** (`verdict.json` and reanalysis): zero non-`ok`
  results. The management load drained before the engine's first
  Administrative Shutdown.
- **Management latency compared with the 2026-09-12 run**, from each run's
  `management-plane-load.jsonl` (per-operation records, retained outside the
  repository; `duration_ms` of `ok` operation records):

  | Operation | 2026-09-12 p50 / max | 2026-09-14 p50 / max |
  |-----------|----------------------|----------------------|
  | metrics (1 s) | 175.7 / 2,260.3 ms; 46 missed slots | 175.7 / 1,423.3 ms; 17 missed slots |
  | neighbor (5 s) | 86.2 / 1,895.9 ms | 86.0 / 1,558.1 ms |
  | policy_stats (5 s) | 92.1 / 1,876.9 ms | 104.5 / 1,831.7 ms |
  | rib_prefix (5 s) | 71.6 / 1,325.3 ms | 71.5 / 1,138.4 ms |
  | doctor (600 s) | 337.6 / 525.7 ms | 337.3 / 526.2 ms |

  The two runs differ in daemon commit as well as run, so the table records
  observations, not a measured improvement.
- Daemon log census (`verdict-calibrated-cadence.json`
  `daemon_log.value.warnings_by_message`; timing and peer breakdown from
  the retained `rustbgpd.log`): 206,526 records, 0 `ERROR`, 126,306 `WARN`:
  - 125,000 `outbound channel full or closed — marking dirty for resync`
    from 999 peers. 124,981 of them are logged in the shutdown minute
    2026-09-14T23:41Z, all at or after the engine's first Administrative
    Shutdown (23:41:23.93Z) and after the measured window ended
    (23:41:23.68Z), when the engine's final shutdown closed every session.
    The remaining 19 fall on trip minutes (07:23Z, 15:30Z, 19:33Z,
    23:37Z) for the designated member whose session each trip tears down.
    This is shutdown log volume; no gate reads it.
  - 1,005 `TCP connect failed` for previously established sessions: 999
    in the same shutdown minute, after the engine closed every session, and
    6 for the designated member, one at each trip's timed restart. The
    1,000 connect attempts at daemon start, before the engine listens, log
    at `INFO` and are not counted here.
  - 294 `inbound connection from unknown peer, dropping` from `127.0.0.1`
    and `::1` only, 147 each (147 `doctor` listener-reachability probes ×
    two address families).
  - 6 `max prefix exceeded`, one per deliberate breach.
  - 1 startup notice for the RFC 8212 legacy-omission posture.
- Engine (`reloadstall.log`): final `sessions_up 1000/1000 parse_errors=0`.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- Compared with the 2026-09-12 run, no new failure class appeared, the
  readiness breach did not recur, and missed metrics slots fell from 46 to
  17. Every missed slot sits inside a reload commit, which is the shape the
  current cadence rule allows.
- The backpressure `WARN` volume is a terminal-teardown and trip artefact,
  not a signal from the live measured window.
- Durations and latencies in this receipt are recorded facts of one run
  on a virtualized guest. They make no performance claim.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`, every other file byte-for-byte
from the run directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20260913T230440Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20260913T230440Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20260913T230440Z/run.json` |
| verdict.json (original, run-SHA analyzer) | `docs/artifacts/soak/soak-rs-flagship-20260913T230440Z/verdict.json` |
| verdict-calibrated-cadence.json (reanalysis, `477c98aac` analyzer) | `docs/artifacts/soak/soak-rs-flagship-20260913T230440Z/verdict-calibrated-cadence.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20260913T230440Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20260913T230440Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20260913T230440Z/scenario/` |

Retained off-repo (too large for git; preserved with the original run
directory). The analyzer needs the daemon log and management-load evidence,
so neither verdict can be recomputed from the repo-archived subset alone:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~63 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~39 MiB |
| full `/metrics` body per sample | `metrics-snapshots.txt.gz` | ~605 MiB |
| last `doctor` bundle | `doctor-bundle.tar.gz` | ~41 KiB |
| runner, build, and generator logs; final barrier markers | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `engine-finish/` | < 10 KiB |
