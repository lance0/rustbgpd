# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-10-04

**Status:** Complete — verdict: **PASS**, on the on-host verdict at the
v0.74.0 tag. No reanalysis; the archived `verdict.json` is the only verdict.
**Run ID:** `tests/soak/runs/soak-rs-flagship-20261004T024544Z`
**Daemon version:** v0.74.0 tag, git SHA
`4d14851f77b064dd254f2319708dd91f281f9b0d`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd` and `rbgp` were built `--release --locked` and the
`reloadstall` engine `--profile scale --locked` at this SHA)
**Scenario config hash:**
`7ef43b5f6051548e1cd10405f1de4aec6d92d54a0d7439847e434bc376310976`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`c2ff3b2c45601002dcdcda195c88a590da1388e1756653c89907e8a56332bf34`;
`rbgp` and `reloadstall` digests in `binaries.sha256`
**Analyzer and gate revision:** `verdict.json` (sha256
`7f1150f6df63ae88fa363fa932fac02598f356dec5245a8d973f2058fbea2cae`),
written on the soak host by `tests/soak/analyze-soak-rs-flagship.py` at the
run SHA (analyzer sha256
`498ba25cdb2509557917c56a33c3b13234ab1642791c203a3acaf4f41f91c4b5`)
against `docs/soaks/soak-acceptance-gates.md` at the run SHA. Since the
[2026-09-29 run](soak-rs-flagship-24h-2026-09-29.md), the analyzer and
management-load driver gained two changes: a `doctor` attempt that exits
nonzero now keeps its report and names its red checks, and the `rbgp`
schedules are phase-offset from the `/metrics` schedule and timed by the
child process. No gate bound changed. Nothing under `tests/soak/`, and not
the gate document, changed between the v0.74.0 tag and the commit
publishing this receipt.
**Date:** 2026-10-04T02:45:44Z runner start (build); sampling
2026-10-04T03:00:31Z → management load ended 2026-10-05T03:19:46.17Z, with
the engine's first Administrative Shutdown 0.20 s later (87,555 s =
24 h 19 m 15 s measured window; the serialized trip windows extend the
86,400 s target)

## Verdict

**PASS on all 20 analyzer gates.**

All 140,192 management operations returned `ok`, among them all 146
`rbgp --json doctor` runs. 48 of 48 SIGHUP reloads were barrier-verified
complete, and 6 of 6 max-prefix trip chains closed with exact breach and
flap accounting. The session floor held on all 2918 samples. Peak RSS was
564.7 MB against a 3072 MB ceiling, and the late-window RSS slope was
+0.076 MB/h against 10 MB/h. The daemon logged zero `ERROR` records, and
`cycles.log` holds zero abort records. Two gates passed with retained
evidence rather than a clean zero:

- **Readiness:** one isolated latency breach, a single sample inside the
  consecutive-breach policy (limit 3): HTTP 200 in 578.0 ms against the
  250 ms limit at elapsed 20,019 s, inside reload 12. No status failures.
- **Cadence:** 43 missed 1 s `/metrics` slots across 41 reload windows (2
  each in reloads 9 and 12, 1 in each of 39 others), none outside a reload
  window (limit 2 per window).

## Release relationship

v0.74.0 (`4d14851f77b064dd254f2319708dd91f281f9b0d`, the release-preparation
commit) was tagged on 2026-10-04T02:03Z; this run started on the tagged
commit about 42 minutes later. It covers the v0.74.0 tag and nothing after
it. The tag is 131 commits after the v0.73.0 tag, whose
[2026-09-29 route-server run](soak-rs-flagship-24h-2026-09-29.md) failed
the doctor and management-correctness gates on one `rbgp doctor` result.
This is the first passing route-server flagship receipt on a tag since the
[2026-09-21 run](soak-rs-flagship-24h-2026-09-21.md) on v0.71.0. The
[2026-09-28 route-reflector run](soak-rr-flagship-24h-2026-09-28.md) on
v0.73.0 is a separate scenario; no route-reflector flagship has run on
v0.74.0. Timing figures from this guest are diagnostic, not performance
claims.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total, IPv4 unicast only), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Daemon, engine, and management-load driver share the guest's vCPUs. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,549 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry. The four `rbgp` schedules start 0.35, 0.5, 0.65 and 0.8 s after the `/metrics` schedule |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2918 |

The shape, cadence, and management-load parameters match the
2026-09-29 run; `run.json` differs only in run ID, git SHA, and monotonic
timestamps, and the three policy files not at all. The scenario
configuration differs in its per-run temporary runtime directory and in
two lines the scenario generator now writes: `config_epoch = 1` and
`ebgp_requires_policy = false`. They declare the route-server posture the
earlier runs used by default, so the daemon no longer logs a startup notice
for the omitted RFC 8212 setting; the import and export policy is unchanged.

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete, 4–7 s from issue to completion; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 118,909–119,675 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,235 scheduled | 140,192 completed, 140,192 `ok` | metrics 87,513 of 87,556 (43 missed slots); neighbor, policy_stats and rib_prefix 17,511 of 17,511 each; doctor 146 of 146 |

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
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 564.7 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | +0.0764 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 4,757,152,500 | **PASS** |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 0 status failures, 1 latency failure (HTTP 200 in 578.0 ms at elapsed 20,019 s), longest consecutive 1; 0 scrape failures, 0 observation gaps | **PASS** |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start ≤ measured-window end ≤ stop request ≤ load end ≤ engine release; load end precedes the first received Administrative Shutdown | ordering held, including last operation ≤ load end ≤ engine release; load end (2026-10-05T03:19:46.17Z) precedes the first Administrative Shutdown (03:19:46.37Z) | **PASS** |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,513; neighbor 17,511; policy_stats 17,511; rib_prefix 17,511; doctor 146 | **PASS** |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.99951; every other operation 1.0 | **PASS** |
| Management-load cadence (`management_cadence`) | every missed slot inside a reload window `[issued − 2 s, complete + 2 s]`; at most 2 per window per operation; limit 2 | metrics 43 missed across 41 reload windows (2 each in reloads 9 and 12; 1 in each of 39 others; none in reloads 1, 4, 8, 14, 34, 36 and 37), 0 outside; neighbor, policy_stats, rib_prefix, doctor 0 missed; 0 defects | **PASS** |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | 0 | **PASS** |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 146 attempts, 0 failures | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 76,818 records, 0 `ERROR`, 0 defects | **PASS** |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2918 | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

20 / 20 gates pass. Analyzer verdict: `pass` (`verdict.json` archived
below).

## Management-read latency

Recomputed from this run's `management-plane-load.jsonl` (`duration_ms` of
`ok` operation records, end-to-end CLI or HTTP time as the load generator
measures it; p99 by linear interpolation, the same method as the earlier
receipts):

| Operation | Scheduled / `ok` | p50 | p99 | max |
|-----------|------------------|-----|-----|-----|
| metrics (1 s) | 87,556 / 87,513 (43 missed slots) | 171.5 ms | 215.7 ms | 2,116.3 ms |
| neighbor (5 s) | 17,511 / 17,511 | 42.5 ms | 64.7 ms | 1,514.4 ms |
| policy_stats (5 s) | 17,511 / 17,511 | 29.9 ms | 44.9 ms | 1,421.9 ms |
| rib_prefix (5 s) | 17,511 / 17,511 | 34.1 ms | 52.2 ms | 1,453.2 ms |
| doctor (600 s) | 146 / 146 | 268.5 ms | 324.8 ms | 342.3 ms |

The CLI figures are not comparable with earlier receipts. This is the first
flagship receipt with child-process timing and phase-offset `rbgp`
schedules; the
[gate document](soak-acceptance-gates.md) records that earlier CLI
durations were rounded up to wait-poll points and mostly overlapped a
`/metrics` render, so their medians overstate the read itself.

Every read over 1 s started inside a reload window: 40 `/metrics` scrapes
(two over 2 s: 2,116.3 ms in reload 12 and 2,076.3 ms in reload 9),
5 `neighbor` reads, 3 RIB lookups, and 2 `policy stats` reads. The slowest
`neighbor` and `policy stats` reads, 1,514.4 ms and 1,421.9 ms, fell in
reload 35. No read reached the 5 s attempt timeout.

## Analysis notes

Observed:

- Sample accounting (`samples.csv`): 2918 rows at a 30 s cadence through
  elapsed 87,549 s, with no scrape failures and no observation gaps.
- RSS trajectory (`samples.csv`): 446.8 MB at the first sample and 416.3 MB
  at the second; 5th–95th percentile 458.8–478.5 MB; 473.4 MB at the last
  sample. Four samples exceed 500 MB, each inside a reload window (reloads
  7, 18, 23 and 42). The 564.7 MB peak is the sample at
  2026-10-04T23:45:05Z, the second reload 42 was issued (complete
  23:45:09Z). The late window (final 25 %, from 2026-10-04T21:15:01Z) opens
  at 473.8 MB and closes at 473.4 MB; its fitted slope is +0.076 MB/h. The
  intern gauge (`bgp_rib_attr_intern_global_size`) stayed at 999–1000
  entries. The [2026-09-29 run](soak-rs-flagship-24h-2026-09-29.md) on
  v0.73.0 recorded a 726.5 MB peak and a 513.3–571.6 MB 5th–95th
  percentile band on the same shape and host; the runs differ in daemon
  revision as well as run, and this receipt does not attribute the
  difference.
- **Readiness latency sample** (`verdict.json` `readyz`): the sample at
  2026-10-04T08:34:12Z (elapsed 20,019 s) returned HTTP 200 in 578.0 ms,
  inside reload 12 (issued 08:34:07Z, complete 08:34:13Z). The daemon
  logged no readiness warning in the run. The run's slowest `/metrics`
  scrape (2,116.3 ms, scheduled 08:34:09.94Z) fell in the same reload
  window. The next-highest readiness latencies were 62.4 and 19.9 ms. The
  gate passed under its consecutive-breach rule; the sample stays recorded
  as evidence under the
  [readiness acceptance policy](soak-acceptance-gates.md#readiness-acceptance-and-kubernetes-probes),
  and the open [known issue](../reference/known-issues.md) "Reloads can
  produce transient readiness failures" describes reload-window readiness
  breaches.
- **Doctor runs:** all 146 returned `ok` (report size 267,007–268,007
  bytes), so the driver saved no `doctor-report-NNNN.json` file. One ran
  inside a trip window (trip 4, 2026-10-04T19:10:31.74Z, 322.6 ms) and none
  inside a reload window. No doctor run overlapped both a trip
  re-establishment and a reload commit, the coincidence recorded for the
  failed attempt in the 2026-09-29 run, so this run does not exercise that
  overlap.
- Daemon log census (`verdict.json` `daemon_log.value.warnings_by_message`):
  76,818 records, 0 `ERROR`, 304 `WARN`:
  - 292 `inbound connection from unknown peer, dropping`: the 146 `doctor`
    listener-reachability probes, each over two address families.
  - 6 `max prefix exceeded` for the designated member, one per scheduled
    trip.
  - 6 `TCP connect failed` for the designated member, one at each trip's
    timed restart.
- Engine (`reloadstall.log`): final `sessions_up 1000/1000 parse_errors=0`.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- Every gate passed on the on-host verdict with no reanalysis and no gate
  change, so the v0.74.0 tag is qualified by a passing route-server
  flagship soak under the current gates.
- The single readiness latency sample and the 43 missed `/metrics` slots
  fall inside reload windows, where the gate document's reload-window and
  consecutive-breach rules place them. Durations and latencies in this
  receipt are recorded facts of one run on a virtualized guest. They make
  no performance claim, and the receipt covers this IPv4-only shape at the
  v0.74.0 tag on this host, nothing wider: no dual-stack flagship soak has
  run.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`, every other file byte-for-byte
from the run directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20261004T024544Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20261004T024544Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20261004T024544Z/run.json` |
| verdict.json (on-host, run-SHA analyzer) | `docs/artifacts/soak/soak-rs-flagship-20261004T024544Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20261004T024544Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20261004T024544Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20261004T024544Z/scenario/` |

Retained off-repo (too large for git, or carrying host paths; preserved
with the original run directory). The analyzer needs the daemon log and
management-load evidence, so the verdict cannot be recomputed from the
repo-archived subset alone. The latency figures, doctor-run placement, and
log census above are computed from the retained files:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~37 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~39 MiB |
| full `/metrics` body every 10th sample | `metrics-snapshots.txt.gz` | ~61 MiB |
| last `doctor` bundle | `doctor-bundle.tar.gz` | ~41 KiB |
| runner, build, and generator logs; final barrier markers | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `engine-finish/` | < 10 KiB each |
