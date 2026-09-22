# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-09-21

**Status:** Complete — verdict: **PASS**, on the on-host verdict at the run
SHA. No reanalysis; the archived `verdict.json` is the only verdict.
**Run ID:** `tests/soak/runs/soak-rs-flagship-20260920T231105Z`
**Daemon version:** v0.71.0 tag, git SHA
`4f8b1712274d2d52b07bc014446eced2ed53f2b5`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA)
**Scenario config hash:**
`654b22a90a2e43b43d019b2efb6524be5e2c7205fdc8c675e30f4887e25a7378`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`0a2bfa5c52e7168350a5d344ae7d60d6ea1f57ad5e732f2947fe8eba43ff0aea`;
`rbgp` and `reloadstall` digests in `binaries.sha256`
**Analyzer and gate revision:** `verdict.json` (sha256
`c1052c5cedacfaab6964692929a5f78d163bf9c1a4f4bda9fb2f73b665972b72`),
written on the soak host by `tests/soak/analyze-soak-rs-flagship.py` at the
run SHA (analyzer sha256
`fa53868bfa6a4f7ac3eb9be052f88991a329d12a3f4920556ac278293cb944f8`, the
same analyzer the [2026-09-14 reanalysis](soak-rs-flagship-24h-2026-09-14.md)
used) against `docs/soaks/soak-acceptance-gates.md` at the run SHA. Neither
file changed between the run SHA and the commit publishing this receipt.
**Date:** 2026-09-20T23:11:05Z runner start (build); sampling
2026-09-20T23:24:15Z → management load ended 2026-09-21T23:47:16Z, with the
engine's first Administrative Shutdown 0.2 s later (87,782 s = 24 h 23 m 02 s
measured window; the serialized trip windows extend the 86,400 s target)

## Verdict

**PASS on every gate.**

All 20 analyzer gates pass in the on-host verdict: zero
management-correctness failures across 140,594 completed operations, 48 of
48 SIGHUP reloads barrier-verified complete, 6 of 6 max-prefix trip chains
with exact breach and flap accounting, the session floor on all 2926
samples, zero readiness breaches, peak RSS 759.8 MB against a 3072 MB
ceiling, late-window RSS slope +0.545 MB/h against 10 MB/h, six missed 1 s
`/metrics` slots (each inside a distinct reload window, none outside), zero
daemon `ERROR` records, and zero abort records.

The operator-read tail is the number to read carefully. The slowest
`policy stats` read completed in 1969 ms end-to-end, 31 ms under the 2 s
aggregate deadline the daemon applies to that RPC
([ADR-0132](../adr/0132-operator-read-path.md), `POLICY_STATS_AGGREGATE_TIMEOUT`),
and no operation of any kind took longer than 2 s. The unpublished run on
the v0.70.2 release commit (2026-09-18, retained outside the repository)
failed its management-correctness gate on exactly this read: one
`policy stats` attempt expired inside a reload commit, and its slowest
successful read took 2394 ms. This run is a pass, not a comfortable one:
the worst read still sits about 1.9 s into a 2 s budget under post-commit
pressure, and the margin is one run's observation on a virtualized guest.

## Release relationship

v0.71.0 (`4f8b1712274d2d52b07bc014446eced2ed53f2b5`) was tagged on
2026-09-20T22:38Z, 33 minutes before this run started. This run qualifies
the tagged commit itself: no reanalysis, no gate change between the run and
this receipt. It succeeds the [2026-09-14 run](soak-rs-flagship-24h-2026-09-14.md)
as the published flagship receipt; v0.70.1 and v0.70.2 shipped as patch
releases on their regression tests and main CI without a published
qualifying soak. This run does not cover runtime or dependency changes on
main after v0.71.0. Timing figures from this guest are diagnostic, not
performance claims.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,760 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2926 |

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete, 9–13 s from issue to completion; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 119,437–119,716 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,600 scheduled | 140,594 completed | metrics 87,776 of 87,782; neighbor, policy_stats, and rib_prefix 17,557 of 17,557 each; doctor 147 of 147 |

## Gates — measured vs precommitted

Bounds quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
the run SHA; measured values from `verdict.json`. Analyzer gate keys are
shown in parentheses.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2926 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** |
| Reload accounting exact (`reload_accounting`) | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** |
| Trip accounting exact (`trip_accounting`) | executed == planned; full per-cycle evidence chain; zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** |
| Exceeded-counter exact (`exceeded_exact`) | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == executed trips | 6 == 6 | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 759.8 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | +0.5450 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 5,609,001,265 | **PASS** |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 0 status failures, 0 latency failures, longest consecutive 0; 0 scrape failures, 0 observation gaps | **PASS** |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start ≤ measured-window end ≤ stop request ≤ load end ≤ engine release; load end precedes the first received Administrative Shutdown | ordering held, including last operation ≤ load end ≤ engine release; load end (2026-09-21T23:47:16.48Z) precedes the first Administrative Shutdown (23:47:16.69Z) | **PASS** |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,776; neighbor 17,557; policy_stats 17,557; rib_prefix 17,557; doctor 147 | **PASS** |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.9999; every other operation 1.0 | **PASS** |
| Management-load cadence (`management_cadence`) | every missed slot inside a reload window `[issued − 2 s, complete + 2 s]`; at most 2 per window per operation; limit 2 | metrics 6 missed, 1 in each of 6 distinct reload windows, 0 outside; neighbor, policy_stats, rib_prefix, doctor 0 missed; 0 defects | **PASS** |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | 0 | **PASS** |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 147 attempts, 0 failures | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 77,314 records, 0 `ERROR`, 0 defects | **PASS** |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2926 | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

20 / 20 gates pass. Analyzer verdict: `pass` (`verdict.json` archived
below).

## Analysis notes

Observed:

- Sample accounting (`samples.csv`): 2926 rows at a 30 s cadence through
  elapsed 87,760 s, with no scrape failures and no observation gaps.
- RSS trajectory (`samples.csv`): 482.4 MB at the first sample; 5th–95th
  percentile 505.7–566.1 MB; the 759.8 MB peak at 2026-09-21T15:06:21Z,
  inside reload 32 (issued 15:06:16Z, complete 15:06:27Z); late-window
  slope +0.545 MB/h. The intern gauge (`bgp_rib_attr_intern_global_size`)
  stayed at 999–1000 entries. The highest readiness latency was 182.7 ms,
  every response HTTP 200.
- **Cadence detail** (`verdict.json`
  `management_cadence.value.operations.metrics.per_reload`): one missed
  `/metrics` slot in each of reloads 2, 7, 9, 22, 33, and 45; none outside
  a reload window, and no window holding more than one. Placed on the wall
  clock through the terminal summary's UTC anchor
  (`management-plane-load.jsonl`, retained outside the repository), each
  missed slot falls 6–7 s after its reload was issued and 2–5 s before its
  barrier-verified completion, to the one-second resolution of
  `cycles.log`. The neighbor, policy_stats, rib_prefix, and doctor
  schedules missed no slot.
- **Management correctness** (`verdict.json`): zero non-`ok` results. The
  management load drained before the engine's first Administrative
  Shutdown.
- **Management latency**, recomputed from this run's
  `management-plane-load.jsonl` (`duration_ms` of `ok` operation records,
  end-to-end CLI or HTTP time as the load generator measures it; p99 by
  linear interpolation), beside the same figures from the unpublished
  2026-09-18 run on the v0.70.2 release commit
  (`224e6a1d4f049300bdfb09913a299d7b8cc4383e`, retained outside the
  repository):

  | Operation | Scheduled / completed | p50 | p99 | max | v0.70.2 run p50 / max |
  |-----------|-----------------------|-----|-----|-----|-----------------------|
  | metrics (1 s) | 87,782 / 87,776 (6 missed slots) | 175.5 ms | 216.9 ms | 1,528.0 ms | 173.4 / 1,066.0 ms (4 missed slots) |
  | neighbor (5 s) | 17,557 / 17,557 | 85.9 ms | 239.7 ms | 1,804.7 ms | 85.1 / 1,713.1 ms |
  | policy_stats (5 s) | 17,557 / 17,557 | 127.1 ms | 278.2 ms | 1,969.4 ms | 104.6 / 2,394.4 ms; 1 failed attempt |
  | rib_prefix (5 s) | 17,557 / 17,557 | 71.4 ms | 226.5 ms | 869.1 ms | 71.3 / 875.3 ms |
  | doctor (600 s) | 147 / 147 | 420.9 ms | 481.9 ms | 523.8 ms | 333.6 / 527.7 ms |

  No operation in this run exceeded 2 s; the v0.70.2 run had three
  successful `policy_stats` reads over 2 s besides the one that expired.
  The slowest `policy_stats` (1,969 ms) and `neighbor` (1,805 ms) reads of
  this run started within the same millisecond, 2026-09-21T08:32:04.65Z,
  inside reload 19 (issued 08:31:59Z, complete 08:32:10Z); the slowest
  `/metrics` scrape (1,528 ms) sits inside reload 45. The p50 for every
  operation is within 1 ms of the v0.70.2 run except `policy_stats`
  (+22 ms) and `doctor` (+87 ms). The two runs differ in daemon commit as
  well as run, so the table records observations, not a measured
  improvement or regression.
- Daemon log census (`verdict.json` `daemon_log.value.warnings_by_message`;
  timing and peer breakdown from the retained `rustbgpd.log`): 77,314
  records, 0 `ERROR`, 307 `WARN`:
  - 294 `inbound connection from unknown peer, dropping` from `127.0.0.1`
    and `::1` only, 147 each (147 `doctor` listener-reachability probes ×
    two address families). Expected: the probe deliberately connects from
    an unconfigured address.
  - 6 `TCP connect failed` for the designated member `127.1.0.1`, one at
    each trip's timed restart, when the daemon reconnects before the
    engine re-listens. Expected: one per trip chain, and each chain
    reached `reestablished` within a second of it. The 1,000 connect
    attempts at daemon start, before the engine listens, log at `INFO` and
    are not counted here.
  - 6 `max prefix exceeded`, one per deliberate breach.
  - 1 startup notice for the RFC 8212 legacy-omission posture of the
    scenario configuration, also reported by the pre-start
    `--check --strict` (`daemon-check.log`).
  - The 125,000 shutdown-minute `outbound channel full or closed` records
    that the [2026-09-14 run](soak-rs-flagship-24h-2026-09-14.md) logged
    after its measured window did not appear in this run: the log ends 0.7 s
    after the first Administrative Shutdown. No gate reads either
    behaviour; the receipt records the difference without attributing it.
- Engine (`reloadstall.log`): final `sessions_up 1000/1000 parse_errors=0`.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- Compared with the 2026-09-14 run at v0.70.0 on the same host shape, no
  new failure class appeared, and missed metrics slots fell from 17 to 6,
  each still inside a reload commit. Compared with the unpublished v0.70.2
  run, the read that failed there completed here, with a 31 ms margin on
  the worst sample.
- The reload commit remains the only place where operator reads approach
  their deadline. Under the
  [operator read path decision (ADR-0132)](../adr/0132-operator-read-path.md)
  a read that lands during a reload commit gets its deadline, not priority
  over route work; this run stayed inside that deadline on every attempt,
  and the margin is the diagnostic to watch on the next run.
- Durations and latencies in this receipt are recorded facts of one run
  on a virtualized guest. They make no performance claim, and the receipt
  proves this shape at this tag on this host, nothing wider.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`, every other file byte-for-byte
from the run directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20260920T231105Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20260920T231105Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20260920T231105Z/run.json` |
| verdict.json (on-host, run-SHA analyzer) | `docs/artifacts/soak/soak-rs-flagship-20260920T231105Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20260920T231105Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20260920T231105Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20260920T231105Z/scenario/` |

Retained off-repo (too large for git, or carrying host paths; preserved
with the original run directory). The analyzer needs the daemon log and
management-load evidence, so the verdict cannot be recomputed from the
repo-archived subset alone:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~37 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~38 MiB |
| full `/metrics` body per sample | `metrics-snapshots.txt.gz` | ~605 MiB |
| last `doctor` bundle | `doctor-bundle.tar.gz` | ~41 KiB |
| runner, build, and generator logs; final barrier markers | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `engine-finish/` | < 10 KiB |
