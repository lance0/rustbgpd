# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-10-11

**Status:** Complete — verdict: **PASS**, on the on-host verdict at the
v0.76.0 tag. No reanalysis; the archived `verdict.json` is the only verdict.
**Run ID:** `tests/soak/runs/soak-rs-flagship-20261011T163518Z`
**Daemon version:** v0.76.0 tag, git SHA
`c4824ad930711eb9f5dd60de48ab7b7166aa653b`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd` and `rbgp` were built `--release --locked` and the
`reloadstall` engine `--profile scale --locked` at this SHA)
**Scenario config hash:**
`dd1d3f9e00cc1e4178291ffbd8ebb76366199170b5ed085edf9ab88d639eb269`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`71b74269fcb2db6f00964921a928eab3502d569be2257e1e3a12609b76714c59`;
`rbgp` and `reloadstall` digests in `binaries.sha256`.
**Analyzer and gate revision:** `verdict.json` (sha256
`e3f5b8e200ffe4da3cc2a97f7fc0fcba2347cdd4ddb70f51f527e74dc4a66d7a`),
written on the soak host by `tests/soak/analyze-soak-rs-flagship.py` at the
run SHA (analyzer sha256
`498ba25cdb2509557917c56a33c3b13234ab1642791c203a3acaf4f41f91c4b5`, the
same file as the 2026-10-04 and 2026-10-06 runs) against
`docs/soaks/soak-acceptance-gates.md` at the run SHA. The analyzer, the
route-server runner, and scenario 10 of the gate document did not change
between the v0.75.0 tag, the v0.76.0 tag, and the commit publishing this
receipt; the gate document's only change in that range rewords the
rapid-peer-flap coverage-gap note.
**Date:** 2026-10-11T16:35:18Z runner start (build); sampling
2026-10-11T16:49:32Z → management load ended 2026-10-12T17:09:16.74Z, with
the engine's first Administrative Shutdown 0.18 s later (87,584 s =
24 h 19 m 44 s measured window; the serialized trip windows extend the
86,400 s target)

## Verdict

**PASS on all 20 analyzer gates.**

All 140,256 management operations returned `ok`, among them all 146
`rbgp --json doctor` runs. 48 of 48 SIGHUP reloads were barrier-verified
complete, and 6 of 6 max-prefix trip chains closed with exact breach and
flap accounting. The session floor held on all 2920 samples. Peak RSS was
601.3 MB against a 3072 MB ceiling, and the late-window RSS slope was
−0.32 MB/h against 10 MB/h. The daemon logged zero `ERROR` records, and
`cycles.log` holds zero abort records. Two gates passed with retained
evidence rather than a clean zero:

- **Readiness:** two status failures, each a single sample inside the
  consecutive-breach policy (limit 3) and 43,714 s apart: HTTP 503 in
  250.7 ms at elapsed 16,411 s, inside reload 10, and HTTP 503 in 250.6 ms
  at elapsed 60,125 s, inside reload 34. Each came shortly after the daemon
  logged its reload complete, and at each the daemon logged a peer-manager
  readiness probe timeout. No latency failures.
- **Cadence:** 26 missed 1 s `/metrics` slots, one in each of 26 reload
  windows, none outside a reload window (limit 2 per window).

## Release relationship

v0.76.0 (`c4824ad930711eb9f5dd60de48ab7b7166aa653b`, the
release-preparation commit) was tagged on 2026-10-11T15:50Z; this run
started on the tagged commit about 44 minutes later. It covers the v0.76.0
tag and nothing after it. The tag is 121 commits after the v0.75.0 tag,
whose [2026-10-06 route-server run](soak-rs-flagship-24h-2026-10-06.md)
passed every gate on the same shape and host. Its runtime changes add alpha
conditional advertisement, experimental Link-Local Next Hop capability
negotiation, live and LACP-derived EVPN Ethernet Segments, and single-homed
VLAN-aware bundle VTEP service with IRB, and promote the scoped FlowSpec
controller role into the v1 inventory, with next-hop export, EVPN DF
election and flood-list fixes. The flagship scenario configuration is
unchanged and enables none of the new features; this run exercises the
v0.76.0 daemon on the existing IPv4 route-server shape. No route-reflector
flagship has run on v0.76.0. Timing figures from this guest are diagnostic,
not performance claims.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total, IPv4 unicast only), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Daemon, engine, and management-load driver share the guest's vCPUs. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,579 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry. The four `rbgp` schedules start 0.35, 0.5, 0.65 and 0.8 s after the `/metrics` schedule |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2920 |

The shape, cadence, and management-load parameters match the
2026-10-06 run: `run.json` differs only in run ID, git SHA, and monotonic
timestamps; the three policy files are byte-identical; and the scenario
configuration differs only in its per-run temporary runtime directory.
The runner's own setting differed: this run set `METRICS_SNAPSHOT_EVERY=1`
and kept a full `/metrics` body for every sample, where the earlier runs
kept every 10th.

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete, 5–8 s from issue to completion; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 118,991–119,707 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,282 scheduled | 140,256 completed, 140,256 `ok` | metrics 87,559 of 87,585 (26 missed slots); neighbor, policy_stats and rib_prefix 17,517 of 17,517 each; doctor 146 of 146 |

## Gates — measured vs precommitted

Bounds quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
the run SHA; measured values from `verdict.json`. Analyzer gate keys are
shown in parentheses.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2920 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** |
| Reload accounting exact (`reload_accounting`) | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** |
| Trip accounting exact (`trip_accounting`) | executed == planned; full per-cycle evidence chain; zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** |
| Exceeded-counter exact (`exceeded_exact`) | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == executed trips | 6 == 6 | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 601.3 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | −0.3173 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 5,085,319,279 | **PASS** |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 2 status failures (HTTP 503 in 250.7 ms at elapsed 16,411 s; HTTP 503 in 250.6 ms at elapsed 60,125 s), 0 latency failures, longest consecutive 1; 0 scrape failures, 0 observation gaps | **PASS** |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start ≤ measured-window end ≤ stop request ≤ load end ≤ engine release; load end precedes the first received Administrative Shutdown | ordering held, including last operation ≤ load end ≤ engine release; load end (2026-10-12T17:09:16.74Z) precedes the first Administrative Shutdown (17:09:16.92Z) | **PASS** |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,559; neighbor 17,517; policy_stats 17,517; rib_prefix 17,517; doctor 146 | **PASS** |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.99970; every other operation 1.0 | **PASS** |
| Management-load cadence (`management_cadence`) | every missed slot inside a reload window `[issued − 2 s, complete + 2 s]`; at most 2 per window per operation; limit 2 | metrics 26 missed, one in each of 26 reload windows, 0 outside; neighbor, policy_stats, rib_prefix, doctor 0 missed; 0 defects | **PASS** |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | 0 | **PASS** |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 146 attempts, 0 failures | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 76,896 records, 0 `ERROR`, 0 defects | **PASS** |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2920 | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

20 / 20 gates pass. Analyzer verdict: `pass` (`verdict.json` archived
below).

## Management-read latency

Recomputed from this run's `management-plane-load.jsonl` (`duration_ms` of
`ok` operation records, end-to-end CLI or HTTP time as the load generator
measures it, with child-process timing and phase-offset `rbgp` schedules as
on the 2026-10-06 run; p99 by linear interpolation, the same method as the
earlier receipts):

| Operation | Scheduled / `ok` | p50 | p99 | max |
|-----------|------------------|-----|-----|-----|
| metrics (1 s) | 87,585 / 87,559 (26 missed slots) | 176.5 ms | 217.2 ms | 1,437.1 ms |
| neighbor (5 s) | 17,517 / 17,517 | 46.3 ms | 69.1 ms | 1,300.9 ms |
| policy_stats (5 s) | 17,517 / 17,517 | 30.7 ms | 42.6 ms | 221.9 ms |
| rib_prefix (5 s) | 17,517 / 17,517 | 35.8 ms | 52.2 ms | 284.9 ms |
| doctor (600 s) | 146 / 146 | 280.7 ms | 364.1 ms | 426.5 ms |

Every read over 1 s started inside a reload window: 22 `/metrics` scrapes
(none over 2 s; the slowest, 1,437.1 ms, in reload 25) and 1 `neighbor`
read (1,300.9 ms, in reload 40). No `policy stats` read, RIB lookup or
`doctor` run exceeded 0.5 s, and no read reached the 5 s attempt timeout.

## Analysis notes

Observed:

- Sample accounting (`samples.csv`): 2920 rows at a 30 s cadence through
  elapsed 87,579 s, with no scrape failures and no observation gaps.
- RSS trajectory (`samples.csv`): 427.3 MB at the first sample and 418.6 MB
  at the second; 5th–95th percentile 455.3–475.8 MB; 463.4 MB at the last
  sample. Eight samples exceed 500 MB, each inside a reload window (reloads
  10, 15, 20, 25, 29, 34, 39 and 48); the highest sample outside any reload
  window is 485.9 MB. The 601.3 MB peak is the sample at
  2026-10-12T02:26:04Z, 1 s after reload 20 was issued (issued 02:26:03Z,
  complete 02:26:08Z), and the next-highest, 588.9 MB, is the sample at
  16:35:11Z, 1 s after reload 48 was issued (complete 16:35:16Z). The late
  window (final 25 %, from 2026-10-12T11:04:38Z) opens at 457.4 MB and
  closes at 463.4 MB; its fitted slope is −0.32 MB/h. The intern gauge
  (`bgp_rib_attr_intern_global_size`) stayed at 999–1000 entries, with a
  late-window slope of −0.0034 entries/h.
- **RSS against the 2026-10-04 and 2026-10-06 runs.** Recomputed from the
  three archived `samples.csv` and `cycles.log` files, on the same shape
  and host, with a reload window of `[issued − 2 s, complete + 2 s]`:

  | Run | Peak | Samples in reload windows | Median in reload windows | Max outside reload windows | 95th percentile outside reload windows |
  |-----|------|---------------------------|--------------------------|----------------------------|----------------------------------------|
  | 2026-10-04, v0.74.0 | 564.7 MB | 17 | 486.9 MB | 487.9 MB | 478.4 MB |
  | 2026-10-06, v0.75.0 | 641.2 MB | 16 | 486.0 MB | 490.6 MB | 480.9 MB |
  | 2026-10-11, v0.76.0 | 601.3 MB | 18 | 495.1 MB | 485.9 MB | 475.6 MB |

  As on the earlier runs, the peak is a single 30 s sample inside a reload
  window. Outside reload windows this run's maximum and 95th percentile are
  the lowest of the three, by 2.0–4.7 MB and 2.8–5.3 MB. The 30 s sampler
  landed inside 18 of the 48 reload windows, so the in-window figures
  depend on where each sample fell in its reload.
- **Readiness samples** (`verdict.json` `readyz`):
  - The sample at 2026-10-11T21:23:04Z (elapsed 16,411 s) returned HTTP 503
    in 250.7 ms, inside reload 10 (issued 21:23:00Z, complete 21:23:06Z).
    The daemon logged `config reload complete` at 21:23:02.75Z and
    `readiness probe failed` with `peer manager probe timed out (200ms
    deadline)` at 21:23:04.18Z, 1.4 s later.
  - The sample at 2026-10-12T09:31:38Z (elapsed 60,125 s) returned HTTP 503
    in 250.6 ms, inside reload 34 (issued 09:31:34Z, complete 09:31:40Z).
    The daemon logged `config reload complete` at 09:31:36.08Z and the same
    `readiness probe failed` / `peer manager probe timed out (200ms
    deadline)` record at 09:31:37.79Z, 1.7 s later.

  The two are 1457 samples apart, and the samples on either side of each
  returned HTTP 200 within 4 ms, so the longest consecutive breach is 1.
  The next-highest readiness latencies were 81.9 and 50.0 ms, both HTTP
  200. Both breaches are single samples inside reload windows, after the
  daemon had logged the reload complete and before the harness's
  generation-marker barrier recorded it; the open
  [known issue](../reference/known-issues.md) "Reloads can produce
  transient readiness failures" describes this behaviour. The gate passed
  under its consecutive-breach rule; both samples stay recorded as evidence
  under the
  [readiness acceptance policy](soak-acceptance-gates.md#readiness-acceptance-and-kubernetes-probes).
- **Doctor runs:** all 146 returned `ok` (report size 267,007–268,007
  bytes), so the driver saved no `doctor-report-NNNN.json` file. One ran
  inside a trip window (trip 4, 2026-10-12T08:59:33.13Z, 298.3 ms) and none
  inside a reload window, so this run does not exercise the
  trip-plus-reload overlap recorded for the failed attempt in the
  [2026-09-29 run](soak-rs-flagship-24h-2026-09-29.md).
- Daemon log census (`verdict.json` `daemon_log.value.warnings_by_message`):
  76,896 records, 0 `ERROR`, 308 `WARN`:
  - 292 `inbound connection from unknown peer, dropping`: from `127.0.0.1`
    and `::1`, 146 each — the 146 `doctor` listener-reachability probes,
    each over two address families.
  - 6 `max prefix exceeded` for the designated member, one per scheduled
    trip.
  - 6 `TCP connect failed` for the designated member, one at each trip's
    timed restart.
  - 2 `readiness probe failed`, the two readiness breaches above.
  - 2 `outbound channel full or closed — marking dirty for resync`, for
    members `127.1.0.196` and `127.1.4.72` at 2026-10-12T17:09:17.06Z and
    17:09:17.39Z, during the engine's final shutdown: 0.14 s and 0.46 s
    after the first Administrative Shutdown, each within 0.1 ms of that
    member's session moving from Established to Idle. The 2026-10-06 run
    logged this message once, also during its final shutdown.
- Engine (`reloadstall.log`): final `sessions_up 1000/1000 parse_errors=0`.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- Every gate passed on the on-host verdict with no reanalysis and no gate
  change, so the v0.76.0 tag is qualified by a passing route-server
  flagship soak under the current gates.
- The two readiness 503 samples, the eight samples above 500 MB, and the 26
  missed `/metrics` slots all fall inside reload windows, where the gate
  document's reload-window and consecutive-breach rules place them. The
  peak RSS sits within the 3072 MB ceiling, and the RSS between reloads and
  the late-window slope do not show growth. Durations and latencies in this
  receipt are recorded facts of one run on a virtualized guest. They make
  no performance claim, and the receipt covers this IPv4-only shape at the
  v0.76.0 tag on this host, nothing wider: no dual-stack flagship soak has
  run.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`, every other file byte-for-byte
from the run directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20261011T163518Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20261011T163518Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20261011T163518Z/run.json` |
| verdict.json (on-host, run-SHA analyzer) | `docs/artifacts/soak/soak-rs-flagship-20261011T163518Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20261011T163518Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20261011T163518Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20261011T163518Z/scenario/` |

Retained off-repo (too large for git, or carrying host paths; preserved
with the original run directory). The analyzer needs the daemon log and
management-load evidence, so the verdict cannot be recomputed from the
repo-archived subset alone. The latency figures, readiness log records,
doctor-run placement, and log census above are computed from the retained
files; the RSS comparison uses only repo-archived files:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~37 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~39 MiB |
| full `/metrics` body every sample | `metrics-snapshots.txt.gz` | ~614 MiB |
| last `doctor` bundle | `doctor-bundle.tar.gz` | ~41 KiB |
| runner, build, generator and watch logs; final barrier markers | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `watch.log`, `engine-finish/` | < 25 KiB each |
