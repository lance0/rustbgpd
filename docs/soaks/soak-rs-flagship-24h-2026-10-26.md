# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-10-26

**Status:** Complete — **PASS with one accepted exception.** The on-host
analyzer verdict is **`fail`**: 19 of 21 gates pass, and the two management
gates driven by `rbgp doctor` fail on one record. No reanalysis; the archived
`verdict.json` is unchanged.

One accepted exception: a single `rbgp doctor` health check (1 of 147) ran
just after reload 28 committed and reported the daemon unavailable when its
peer-manager probe missed the 200 ms deadline twice. Sessions and routing
were unaffected, and no 30 s `/readyz` sample fell inside that window. The
maintainer accepted this one record as an exception for this run; a fix for
the probe miss is in progress.

**Run ID:** `tests/soak/runs/soak-rs-flagship-20261025T223837Z`
**Daemon version:** v0.80.1 tag, git SHA
`2fb2cbf276eaa6a2eb6005e956ce47b23a377dc3`; bare-host run, `rustbgpd` and
`rbgp` built `--release --locked` and `reloadstall` `--profile scale --locked`
at this SHA from a clean tree
**Scenario config hash:** sha256 of `run.json`
`16de46a7da02db4bc62191b49627d3dc820dfe985326c74066f276cc7958871c`
**Executable identities:** `rustbgpd` sha256
`c4e4cb4fc322a3c1595bd4f5cad199e028c8fc43eec581deb6a47ef5d72f66d8`; `rbgp`
and `reloadstall` in `binaries.sha256`
**Analyzer and gate revision:** `verdict.json` (sha256
`425c0971ac32ed1982c5af9682cb2bfaafdd4187f5e8628a1785e918c07c46e5`) written on
the soak host by `tests/soak/analyze-soak-rs-flagship.py` at the run SHA
(sha256 `5aabb6057e187297263809cf6cc36edaa9e8213086c55fdf15ad5ca562f11a28`)
against scenario 10 of `docs/soaks/soak-acceptance-gates.md` at the run SHA.
Since v0.76.0 scenario 10 gained one gate, outbound registration wait (21 in
all); no other bound changed, and neither file changed between the v0.80.1
tag and this receipt's commit.
**Date:** runner start 2026-10-25T22:38:37Z; sampling 2026-10-25T22:55:47Z →
management load end 2026-10-26T23:16:26.52Z, first Administrative Shutdown
0.21 s later (87,639 s = 24 h 20 m 39 s measured window)

## Release relationship and shape

v0.80.1 (`2fb2cbf27`) was tagged 2026-10-25T18:14Z; this run started on the
tagged commit 4 h 24 m later and covers that tag only. v0.80.1 changes
route-server peer-down teardown, which the trip and timed-restart cycles
exercise. The shape is the [2026-10-11 run's](soak-rs-flagship-24h-2026-10-11.md#run-shape)
on the same dedicated 8 vCPU / 15 GiB virtualized host: 1000 eBGP
route-server clients × 400 IPv4 routes under `reloadstall` churn, 48 SIGHUP
reloads, 6 max-prefix trips on `127.1.0.1`, and management load (`/metrics`
1 s; `neighbor`, `policy stats`, exact RIB lookup 5 s; `rbgp --json doctor`
600 s; 5 s timeout, no retry). `run.json` differs from that run only in run
ID, SHA and monotonic timestamps; the policy files are byte-identical.

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP reload | 48 | 48 | All barrier-verified complete, 6–9 s issue to completion |
| Max-prefix trip → timed restart | 6 | 6 | Full chain each cycle; hold-down 118,850–119,612 ms of 120,000; post-recovery `usage=400 limit=450 headroom=50` |
| Management operations | 140,371 scheduled | 140,339 completed, 140,338 `ok` | metrics 87,608 of 87,640 (32 missed slots); neighbor, policy_stats, rib_prefix 17,528 each; doctor 147, one failed |

## Gates — measured vs precommitted

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| `session_floor` | `established == 1000` post-warmup; `999` only in a declared trip window | 0 violations / 2921; `999` on 24 samples, all in trip windows | **PASS** |
| `reload_accounting` | issued == complete; complete ≥ 0.9 × planned | 48 == 48 == 48 | **PASS** |
| `trip_accounting` | executed == planned; full evidence chain | 6 == 6; 0 defects | **PASS** |
| `exceeded_exact` | exceeded counter == executed trips | 6 == 6 | **PASS** |
| `flap_budget` | flap delta == executed trips | 6 == 6 | **PASS** |
| `rss_peak_mb` | < 3072 MB | 680.0 MB | **PASS** |
| `rss_late_slope_per_hour` | < 10 MB/h, final 25 % | +1.339 MB/h | **PASS** |
| `intern_late_slope_per_hour` | < 100 entries/h, same window | −0.0034 entries/h | **PASS** |
| `msgs_sent_monotone` | never decreases | 0 breaks; final 5,631,866,751 | **PASS** |
| `readyz` | < 3 consecutive misses of HTTP 200 within 250 ms; no scrape failure or gap | 0 bad samples, 0 scrape failures, 0 gaps | **PASS** |
| `outbound_registration_wait` | max sampled oldest wait ≤ 300 s | 0 s | **PASS** |
| `management_evidence` | summary matches records and `run.json` | 0 errors, 0 mismatches | **PASS** |
| `management_lifetime` | load brackets the window; ends before first Administrative Shutdown | held | **PASS** |
| `management_operations` | all five present | all present | **PASS** |
| `management_completion` | each ≥ 90 % of scheduled | metrics 0.99963; others 1.0 | **PASS** |
| `management_cadence` | misses only in reload windows, ≤ 2 per window | metrics 32, one in each of 32 reload windows; others 0 | **PASS** |
| `management_failures` | zero non-`ok` and zero invalid `ok` | 1: `doctor`, `doctor_check_failed`, exit 2, `daemon.healthy` | **FAIL**¹ |
| `management_doctor` | every `doctor` attempt `ok` | 147 attempts, 1 failure (same record) | **FAIL**¹ |
| `daemon_log` | complete and well-formed; any `ERROR` fails | 79,506 records, 0 `ERROR`, 0 defects | **PASS** |
| `min_samples` | ≥ 2592 | 2921 | **PASS** |
| `no_abort` | zero `ABORT:` lines | 0 | **PASS** |

19 / 21 gates pass; analyzer verdict `fail`. ¹ Both rows are the one
`rbgp doctor` record accepted as this run's exception.

## The failed doctor record

`doctor-report-0083.json` fails only `daemon.healthy`: `peer manager probe
timed out (200ms deadline)`, retried once with the same result. In the daemon
log, reload 28 (harness barrier 12:35:44Z → 12:35:51Z) waited 2,695 ms on the
cohort destination prestage round trip (12:35:44.58Z → 47.27Z), committed its
RIB transition at 47.63Z and logged `config reload complete` at 47.69Z. The
doctor run started at about 47.79Z; its two `GetHealth` calls returned
unavailable at 48.12Z and 49.33Z, after the prestage and the logged
completion, while runtime-config settlement was still open (settled 50.19Z).
The two readiness HTTP 503 samples on the 2026-10-11 run, 1.4–1.7 s after a
logged reload completion, carried the same probe message. This was the only
doctor run of 147 to start inside a reload window; the failed run took
2,539.9 ms against a 5 s timeout. The `/readyz` samples either side
(12:35:35Z, 12:36:05Z) returned HTTP 200 and did not observe the window.

## Other observations

- RSS: 5th–95th percentile 507.6–547.8 MB; the 680.0 MB peak is a sample
  inside reload 43. Outside reload windows the maximum is 554.0 MB against
  485.9 MB on the 2026-10-11 run; the cause of the ~70 MB higher level is not
  established.
- Management reads: p99 `/metrics` 267.1 ms, `neighbor` 100.2 ms,
  `policy stats` 54.5 ms, RIB lookup 71.5 ms, `doctor` 473.1 ms. All 32 reads
  over 1 s started inside reload windows; none reached the 5 s timeout.
- Daemon log: 306 `WARN` — 294 unknown-peer drops (the 147 doctor listener
  probes, two families each), 6 `max prefix exceeded`, 6 `TCP connect
  failed` (one per trip and restart). No `readiness probe failed` record.
- Engine: final `sessions_up 1000/1000 parse_errors=0`.

## Scope

This receipt covers the IPv4-only route-server shape at the v0.80.1 tag on
one virtualized host; durations are diagnostic, not performance claims. The
gates were not changed for this result. The peer-manager probe miss during
reload settlement is a known daemon behavior with a fix in progress; a later
run on a release containing it is needed for a clean verdict.

## Artifacts

Repo-archived in `docs/artifacts/soak/soak-rs-flagship-20261025T223837Z/`
(absolute checkout paths in `binaries.sha256` and `doctor-report-0083.json`
normalized to `<repo>`; other files byte-for-byte): `samples.csv`,
`cycles.log`, `run.json`, `verdict.json` (on-host, run-SHA analyzer),
`binaries.sha256`, `reloadstall.log`, `doctor-report-0083.json`, and
`scenario/` (config and policy files). Retained off-repo with the run
directory: `rustbgpd.log` (~38 MiB), `management-plane-load.jsonl`
(~39 MiB), `metrics-snapshots.txt.gz` (~689 MiB), `doctor-bundle.tar.gz`
(~49 KiB), and the runner, build, generator and watch logs. The verdict
cannot be recomputed from the repo subset; the timing and log notes above
come from the retained files.
