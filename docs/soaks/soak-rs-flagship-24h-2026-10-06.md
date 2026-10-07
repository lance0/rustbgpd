# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-10-06

**Status:** Complete — verdict: **PASS**, on the on-host verdict at the
v0.75.0 tag. No reanalysis; the archived `verdict.json` is the only verdict.
**Run ID:** `tests/soak/runs/soak-rs-flagship-20261006T030554Z`
**Daemon version:** v0.75.0 tag, git SHA
`54ed19b5af927f1c8e5064ecb1a497885c15d068`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd` and `rbgp` were built `--release --locked` and the
`reloadstall` engine `--profile scale --locked` at this SHA)
**Scenario config hash:**
`ac2df1ecac11906a3dda36e9e1f3163a736e985fdecf5e9dca2cffcfb6c5aaf5`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`3db652c3b7341512036df5342b4a362e53c6e8cb1d949be4c3ed519315e2e69b`;
`rbgp` and `reloadstall` digests in `binaries.sha256`. The `reloadstall`
digest equals the one recorded for the
[2026-10-04 run](soak-rs-flagship-24h-2026-10-04.md): between the two tags
its only workspace dependency changed in documentation alone, and Cargo
reused the existing build.
**Analyzer and gate revision:** `verdict.json` (sha256
`8b4ee4e6c22f3b863685156391393a4cd1b32dfd58ebe7c94ff171809c49c26f`),
written on the soak host by `tests/soak/analyze-soak-rs-flagship.py` at the
run SHA (analyzer sha256
`498ba25cdb2509557917c56a33c3b13234ab1642791c203a3acaf4f41f91c4b5`, the
same file as the 2026-10-04 run) against
`docs/soaks/soak-acceptance-gates.md` at the run SHA. Nothing under
`tests/soak/`, and not the gate document, changed between the v0.74.0 tag,
the v0.75.0 tag, and the commit publishing this receipt.
**Date:** 2026-10-06T03:05:54Z runner start (build); sampling
2026-10-06T03:19:34Z → management load ended 2026-10-07T03:38:44.57Z, with
the engine's first Administrative Shutdown 0.19 s later (87,551 s =
24 h 19 m 11 s measured window; the serialized trip windows extend the
86,400 s target)

## Verdict

**PASS on all 20 analyzer gates.**

All 140,185 management operations returned `ok`, among them all 146
`rbgp --json doctor` runs. 48 of 48 SIGHUP reloads were barrier-verified
complete, and 6 of 6 max-prefix trip chains closed with exact breach and
flap accounting. The session floor held on all 2918 samples. Peak RSS was
641.2 MB against a 3072 MB ceiling, and the late-window RSS slope was
−0.47 MB/h against 10 MB/h. The daemon logged zero `ERROR` records, and
`cycles.log` holds zero abort records. Two gates passed with retained
evidence rather than a clean zero:

- **Readiness:** two latency breaches, each a single sample inside the
  consecutive-breach policy (limit 3) and 10,954 s apart: HTTP 200 in
  961.9 ms at elapsed 20,015 s, inside reload 12, and HTTP 200 in 703.7 ms
  at elapsed 30,969 s, inside reload 18, against the 250 ms limit. No status
  failures.
- **Cadence:** 45 missed 1 s `/metrics` slots across 44 reload windows (2 in
  reload 29, 1 in each of 43 others), none outside a reload window (limit 2
  per window).

## Release relationship

v0.75.0 (`54ed19b5af927f1c8e5064ecb1a497885c15d068`, the
release-preparation commit) was tagged on 2026-10-05T13:23Z; this run
started on the tagged commit about 13 hours 43 minutes later. It covers the
v0.75.0 tag and nothing after it. The tag is 14 commits after the v0.74.0
tag, whose [2026-10-04 route-server run](soak-rs-flagship-24h-2026-10-04.md)
passed every gate on the same shape and host. Its runtime changes move the
export-policy reload path: a clean reload builds its shared transition
inventory during the unfenced destination prestage instead of under the RIB
transition fence, the shared encoder groups that inventory with a counting
sort, and telemetry probes stay answerable when idle clients hold listener
connections. The RS flagship's 48 reloads across 1000 peers exercise that
path. No route-reflector flagship has run on v0.75.0. Timing figures from
this guest are diagnostic, not performance claims.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total, IPv4 unicast only), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Daemon, engine, and management-load driver share the guest's vCPUs. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,527 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry. The four `rbgp` schedules start 0.35, 0.5, 0.65 and 0.8 s after the `/metrics` schedule |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2918 |

The shape, cadence, and management-load parameters match the
2026-10-04 run: `run.json` differs only in run ID, git SHA, and monotonic
timestamps; the three policy files are byte-identical; and the scenario
configuration differs only in its per-run temporary runtime directory.

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete, 5–7 s from issue to completion; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 118,805–119,711 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,230 scheduled | 140,185 completed, 140,185 `ok` | metrics 87,506 of 87,551 (45 missed slots); neighbor, policy_stats and rib_prefix 17,511 of 17,511 each; doctor 146 of 146 |

## Gates — measured vs precommitted

Bounds quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
the run SHA; measured values from `verdict.json`. Analyzer gate keys are
shown in parentheses.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2918 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** |
| Reload accounting exact (`reload_accounting`) | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** |
| Trip accounting exact (`trip_accounting`) | executed == planned; full per-cycle evidence chain; zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** |
| Exceeded-counter exact (`exceeded_exact`) | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == executed trips | 6 == 6 | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 641.2 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | −0.4706 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0035 entries/h | **PASS** |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 4,498,091,025 | **PASS** |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 0 status failures, 2 latency failures (HTTP 200 in 961.9 ms at elapsed 20,015 s; HTTP 200 in 703.7 ms at elapsed 30,969 s), longest consecutive 1; 0 scrape failures, 0 observation gaps | **PASS** |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start ≤ measured-window end ≤ stop request ≤ load end ≤ engine release; load end precedes the first received Administrative Shutdown | ordering held, including last operation ≤ load end ≤ engine release; load end (2026-10-07T03:38:44.57Z) precedes the first Administrative Shutdown (03:38:44.76Z) | **PASS** |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,506; neighbor 17,511; policy_stats 17,511; rib_prefix 17,511; doctor 146 | **PASS** |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.99949; every other operation 1.0 | **PASS** |
| Management-load cadence (`management_cadence`) | every missed slot inside a reload window `[issued − 2 s, complete + 2 s]`; at most 2 per window per operation; limit 2 | metrics 45 missed across 44 reload windows (2 in reload 29; 1 in each of 43 others; none in reloads 4, 30, 38 and 41), 0 outside; neighbor, policy_stats, rib_prefix, doctor 0 missed; 0 defects | **PASS** |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | 0 | **PASS** |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 146 attempts, 0 failures | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 76,734 records, 0 `ERROR`, 0 defects | **PASS** |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2918 | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

20 / 20 gates pass. Analyzer verdict: `pass` (`verdict.json` archived
below).

## Management-read latency

Recomputed from this run's `management-plane-load.jsonl` (`duration_ms` of
`ok` operation records, end-to-end CLI or HTTP time as the load generator
measures it, with child-process timing and phase-offset `rbgp` schedules as
on the 2026-10-04 run; p99 by linear interpolation, the same method as the
earlier receipts):

| Operation | Scheduled / `ok` | p50 | p99 | max |
|-----------|------------------|-----|-----|-----|
| metrics (1 s) | 87,551 / 87,506 (45 missed slots) | 171.3 ms | 209.1 ms | 2,137.0 ms |
| neighbor (5 s) | 17,511 / 17,511 | 40.9 ms | 63.7 ms | 1,613.5 ms |
| policy_stats (5 s) | 17,511 / 17,511 | 28.8 ms | 41.5 ms | 1,040.1 ms |
| rib_prefix (5 s) | 17,511 / 17,511 | 32.9 ms | 49.5 ms | 1,108.9 ms |
| doctor (600 s) | 146 / 146 | 267.2 ms | 312.1 ms | 314.7 ms |

Every read over 1 s started inside a reload window: 44 `/metrics` scrapes
(one over 2 s: 2,137.0 ms in reload 29), 8 `neighbor` reads, 2 RIB lookups,
and 1 `policy stats` read. The slowest `neighbor` read, 1,613.5 ms, fell in
reload 30 and the slowest `policy stats` read, 1,040.1 ms, in reload 20. No
read reached the 5 s attempt timeout.

## Analysis notes

Observed:

- Sample accounting (`samples.csv`): 2918 rows at a 30 s cadence through
  elapsed 87,527 s, with no scrape failures and no observation gaps.
- RSS trajectory (`samples.csv`): 441.7 MB at the first sample and 417.7 MB
  at the second; 5th–95th percentile 453.0–481.0 MB; 475.3 MB at the last
  sample. Six samples exceed 500 MB, each inside a reload window (reloads
  6, 12, 23, 28, 34 and 39); the highest sample outside any reload window
  is 490.6 MB. The 641.2 MB peak is the sample at 2026-10-06T20:01:18Z,
  1 s after reload 34 was issued (issued 20:01:17Z, complete 20:01:23Z),
  and the next-highest, 609.6 MB, is the sample at 05:50:35Z, 2 s after
  reload 6 was issued (complete 05:50:38Z). The late window (final 25 %,
  from 2026-10-06T21:33:49Z) opens at 466.7 MB and closes at 475.3 MB; its
  fitted slope is −0.47 MB/h. The intern gauge
  (`bgp_rib_attr_intern_global_size`) stayed at 999–1000 entries, with a
  late-window slope of −0.0035 entries/h.
- **Peak RSS against the 2026-10-04 run.** The
  [2026-10-04 run](soak-rs-flagship-24h-2026-10-04.md) on v0.74.0, on the
  same shape and host, recorded a 564.7 MB peak and a 458.8–478.5 MB
  5th–95th percentile band; this run's peak is 76.5 MB higher. Recomputed
  from both archived `samples.csv` and `cycles.log` files, with a reload
  window of `[issued − 2 s, complete + 2 s]`:

  | Run | Peak | Samples in reload windows | Median in reload windows | Max outside reload windows | 95th percentile outside reload windows |
  |-----|------|---------------------------|--------------------------|----------------------------|----------------------------------------|
  | 2026-10-04, v0.74.0 | 564.7 MB | 17 | 486.9 MB | 487.9 MB | 478.4 MB |
  | 2026-10-06, v0.75.0 | 641.2 MB | 16 | 486.0 MB | 490.6 MB | 480.9 MB |

  Both peaks are single 30 s samples that landed inside a reload window,
  and outside reload windows the two runs differ by 2.7 MB at the maximum
  and 2.5 MB at the 95th percentile. The peak therefore reflects a
  reload-time transient; the 30 s sampler landed inside 16 of this run's
  48 reload windows and 17 of the 2026-10-04 run's. By the 1 s timestamps of `samples.csv` and
  `cycles.log`, this run's two highest samples fell 1 s and 2 s after
  their reload was issued; the 2026-10-04 run's three highest (564.7, 538.5
  and 524.0 MB) fell in the second the reload was issued, and it has no
  sample 1–2 s after an issue, while this run has none in the issue second.
  The archived data cannot separate a larger transient from a different
  sampling phase, so the cause of the higher peak is not established.
  v0.75.0 builds a clean reload's transition inventory during the unfenced
  prestage, alongside route churn, instead of under the RIB fence; that
  overlap is a plausible contributor that this run does not isolate. The
  release's own reload-stall matrix reported VmHWM unchanged on its
  700-member shape.
- **Readiness latency samples** (`verdict.json` `readyz`): the sample at
  2026-10-06T08:53:10Z (elapsed 20,015 s) returned HTTP 200 in 961.9 ms,
  inside reload 12 (issued 08:53:06Z, complete 08:53:11Z), and the sample
  at 11:55:43Z (elapsed 30,969 s) returned HTTP 200 in 703.7 ms, inside
  reload 18 (issued 11:55:40Z, complete 11:55:45Z). The two are 365 samples
  apart, and the samples on either side of each returned within 1 ms, so the longest
  consecutive breach is 1. The daemon logged no readiness warning in the
  run. The next-highest readiness latencies were 13.7 and 11.1 ms. The gate
  passed under its consecutive-breach rule; the samples stay recorded as
  evidence under the
  [readiness acceptance policy](soak-acceptance-gates.md#readiness-acceptance-and-kubernetes-probes),
  and the open [known issue](../reference/known-issues.md) "Reloads can
  produce transient readiness failures" describes reload-window readiness
  breaches.
- **Doctor runs:** all 146 returned `ok` (report size 267,002–268,002
  bytes), so the driver saved no `doctor-report-NNNN.json` file. One ran
  inside a trip window (trip 4, 2026-10-06T19:29:34.58Z, 253.3 ms) and none
  inside a reload window, so this run does not exercise the
  trip-plus-reload overlap recorded for the failed attempt in the
  [2026-09-29 run](soak-rs-flagship-24h-2026-09-29.md).
- Daemon log census (`verdict.json` `daemon_log.value.warnings_by_message`):
  76,734 records, 0 `ERROR`, 305 `WARN`:
  - 292 `inbound connection from unknown peer, dropping`: from `127.0.0.1`
    and `::1`, 146 each — the 146 `doctor` listener-reachability probes,
    each over two address families.
  - 6 `max prefix exceeded` for the designated member, one per scheduled
    trip.
  - 6 `TCP connect failed` for the designated member, one at each trip's
    timed restart.
  - 1 `outbound channel full or closed — marking dirty for resync` for
    member `127.1.4.127` at 2026-10-07T03:38:44.909774Z, during the
    engine's final shutdown: 0.34 s after management load ended, 0.15 s
    after the first Administrative Shutdown, and 29 µs after that member's
    session moved from Established to Idle. The 2026-10-04 run did not log
    this message; the [2026-09-12 run](soak-rs-flagship-24h-2026-09-12.md)
    logged it from 999 peers, almost all during its final shutdown.
- Engine (`reloadstall.log`): final `sessions_up 1000/1000 parse_errors=0`.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- Every gate passed on the on-host verdict with no reanalysis and no gate
  change, so the v0.75.0 tag is qualified by a passing route-server
  flagship soak under the current gates.
- The two readiness latency samples, the six samples above 500 MB, and the
  45 missed `/metrics` slots all fall inside reload windows, where the gate
  document's reload-window and consecutive-breach rules place them. The
  higher peak RSS is recorded as an observation with its cause not
  established; it sits within the 3072 MB ceiling, and the RSS between
  reloads and the late-window slope do not show growth. Durations and
  latencies in this receipt are recorded facts of one run on a virtualized
  guest. They make no performance claim, and the receipt covers this
  IPv4-only shape at the v0.75.0 tag on this host, nothing wider: no
  dual-stack flagship soak has run.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`, every other file byte-for-byte
from the run directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20261006T030554Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20261006T030554Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20261006T030554Z/run.json` |
| verdict.json (on-host, run-SHA analyzer) | `docs/artifacts/soak/soak-rs-flagship-20261006T030554Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20261006T030554Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20261006T030554Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20261006T030554Z/scenario/` |

Retained off-repo (too large for git, or carrying host paths; preserved
with the original run directory). The analyzer needs the daemon log and
management-load evidence, so the verdict cannot be recomputed from the
repo-archived subset alone. The latency figures, doctor-run placement, and
log census above are computed from the retained files; the RSS comparison
uses only repo-archived files:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~37 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~39 MiB |
| full `/metrics` body every 10th sample | `metrics-snapshots.txt.gz` | ~61 MiB |
| last `doctor` bundle | `doctor-bundle.tar.gz` | ~41 KiB |
| runner, build, and generator logs; final barrier markers | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `engine-finish/` | < 10 KiB each |
