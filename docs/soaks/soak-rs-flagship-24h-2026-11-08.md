# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-11-08

**Status:** Complete — verdict: **PASS**, 22 / 22 gates on the on-host
`verdict.json`; 0 management correctness failures, 1 tolerated availability
miss (one `rbgp doctor` timeout inside reload 27's window).

**Run ID:** `tests/soak/runs/soak-rs-flagship-20261108T172214Z`
**Daemon version:** v0.82.0 tag, git SHA
`608dcaea0902272474bd2a25bcf30bff3dd3153b`; bare-host, `rustbgpd`/`rbgp`
`--release --locked`, `reloadstall` `--profile scale --locked`, built at this
SHA; the checkout was clean at the tag when inspected after the run
**Scenario config hash:** `run.json` sha256 `efda7053863a10275afe62b9812b8cc901b9509667c95aea3d0d2cc9372ca695`
**Executable identities:** `rustbgpd` sha256 `0bc45af5e7df6636b422a22d7f2596be3ef63af14309585ba928f6ec0f8b90de`;
`rbgp` and `reloadstall` in `binaries.sha256`
**Analyzer and gate revision:** on-host `verdict.json` (sha256
`6eab48dea9a96d9d7df856dadd34cdb3a15b06bd0b943d33d12fba8a2b671e2b`) from
`tests/soak/analyze-soak-rs-flagship.py` at the run SHA (sha256
`aa04ad40d2a3d1b1abcbc3ce4b33d7e0ba18a7c1fbd024d422515819492a3147`, the same
file as the [2026-11-01 run](soak-rs-flagship-24h-2026-11-01.md)) and scenario
10 of `docs/soaks/soak-acceptance-gates.md`, both unchanged from the run SHA
to this receipt's commit
**Date:** runner start 2026-11-08T17:22:14Z; sampling 17:43:38Z → management
load end 2026-11-09T18:04:34.11Z, first Administrative Shutdown 0.24 s later
(87,655 s = 24 h 20 m 55 s measured window)

## Release relationship and shape

v0.82.0 (`608dcaea0`) was tagged 2026-11-08T16:07Z; this run started on the
tagged commit 1 h 15 m later. **It covers the v0.82.0 tag only, not main after
it.** The shape matches the [2026-11-01 run](soak-rs-flagship-24h-2026-11-01.md#release-relationship-and-shape)
on the same 8 vCPU / 15 GiB virtualized host: 1000 eBGP route-server clients ×
400 IPv4 routes under `reloadstall` churn, 48 SIGHUP reloads, 6 max-prefix
trips on `127.1.0.1`, and management load. `run.json` differs from the
2026-11-01 run only in run ID, SHA and monotonic timestamps; the policy files
are byte-identical, and `config.toml` differs only in its temporary runtime
directory. Those `.rpol` files (a prefix reject and community additions) load
and evaluate under the v0.82.0 typed policy language. The runner does not
exercise Add-Path, RPKI, BFD or VPN FlowSpec, so the v0.82.0 resource limits
and controller origination in those areas are not covered here.

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP reload | 48 | 48 | All barrier-verified complete, 6–9 s issue to completion |
| Max-prefix trip → timed restart | 6 | 6 | Full chain each cycle; hold-down 118,836–119,549 ms of 120,000; post-recovery `usage=400 limit=450 headroom=50` |
| Management operations | 140,399 scheduled | 140,368 completed: 140,367 `ok`, 1 `doctor` timeout | metrics 87,625 of 87,656 (31 missed slots); neighbor, policy_stats and rib_prefix 17,532 each; doctor 147 of 147 (146 `ok`) |

## Gates — measured vs precommitted

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| `session_floor` | `established == 1000` post-warmup; `999` only in a declared trip window | 0 violations / 2921; `999` on 24 samples, all in trip windows | **PASS** |
| `reload_accounting` | issued == complete; complete ≥ 0.9 × planned | 48 == 48 == 48 | **PASS** |
| `trip_accounting` | executed == planned; full evidence chain | 6 == 6; 0 defects | **PASS** |
| `exceeded_exact` | exceeded counter == executed trips | 6 == 6 | **PASS** |
| `flap_budget` | flap delta == executed trips | 6 == 6 | **PASS** |
| `rss_peak_mb` | < 3072 MiB | 671.8 MiB | **PASS** |
| `rss_late_slope_per_hour` | < 10 MiB/h, final 25 % | −0.03 MiB/h | **PASS** |
| `intern_late_slope_per_hour` | < 100 entries/h, same window | −0.0034 entries/h | **PASS** |
| `msgs_sent_monotone` | never decreases | 0 breaks; final 5,153,810,241 | **PASS** |
| `readyz` | < 3 consecutive misses of HTTP 200 within 250 ms; no scrape failure or gap | 0 bad samples, 0 scrape failures, 0 gaps | **PASS** |
| `outbound_registration_wait` | max sampled oldest wait ≤ 300 s | 17 s | **PASS** |
| `management_evidence` | summary matches records and `run.json` | 0 errors, 0 mismatches | **PASS** |
| `management_lifetime` | load brackets the window; ends before first Administrative Shutdown | held | **PASS** |
| `management_operations` | all five present | all present | **PASS** |
| `management_completion` | each ≥ 90 % of scheduled | metrics 0.99965; others 1.0 | **PASS** |
| `management_cadence` | misses only in reload windows, ≤ 2 per window | metrics 31, one in each of 31 reload windows; others 0 | **PASS** |
| `management_failures` (correctness) | zero non-`ok` other than availability misses; zero invalid `ok` | 0 | **PASS** |
| `management_availability` | isolated misses only inside a reload window; < 2 consecutive; ≤ 3 per operation | 1 miss (`doctor` timeout, reload 27), 0 violations | **PASS** |
| `management_doctor` | every `doctor` attempt `ok`, except an availability miss | 147 attempts, 0 failures, 1 availability miss | **PASS** |
| `daemon_log` | complete and well-formed; any `ERROR` fails | 79,659 records, 0 `ERROR`, 0 defects | **PASS** |
| `min_samples` | ≥ 2592 | 2921 | **PASS** |
| `no_abort` | zero `ABORT:` lines | 0 | **PASS** |

## Availability miss

The `doctor` run scheduled at 06:53:39.22Z on 2026-11-09 started 0.14 s
before the daemon logged `SIGHUP received` for reload 27. The daemon's audit
log shows its first reads served at once; its effective-config read returned
at 06:53:43.36Z, after the reload generation was applied, and its later reads
were still being served when the runner stopped it at the 5 s timeout
(06:53:44.28Z). The daemon reported reload 27 settled at 06:53:44.33Z. A
timeout leaves no report, so none is archived. This is the only non-`ok`
management result. The
[management availability gate](soak-acceptance-gates.md) tolerates an isolated
miss that overlaps a reload window, at most 3 per operation. The
[v0.80.1 run's](soak-rs-flagship-24h-2026-10-26.md#amendment-2026-10-26-rescored-under-the-split-management-gate)
miss was a different outcome: a completed report whose `daemon.healthy` check
failed on the peer-manager probe deadline.

## Other observations

- RSS: 5th–95th percentile 539.3–575.3 MiB; the 671.8 MiB peak is a sample
  inside reload 42. Outside reload windows (from `issued` to 30 s after
  `complete`) the maximum is 609.7 MiB, during a plateau of about 600–610 MiB
  that followed reload 26 for about 10 minutes before returning to the
  ~570 MiB band. The between-reload median was 561.2 MiB in the first quarter
  of the run and 566.6 MiB in the last. On the
  [v0.81.0 run](soak-rs-flagship-24h-2026-11-01.md), computed the same way on
  the same host and shape, the peak was 698.8 MiB, the 5th–95th percentile
  508.8–573.3 MiB, the between-reload maximum 581.8 MiB, the quarter medians
  526.9 and 561.4 MiB, and the late slope +1.62 MiB/h. The cause of the
  plateau is not established.
- Outbound registration wait: the 17 s maximum is one sample at 18:02:50Z,
  17 s after trip 6's session re-established. The only other nonzero sample
  is 2 s, just after trip 1. The v0.81.0 run's maximum was 2 s.
- Management reads: p99 `/metrics` 300.4 ms, `neighbor` 118.2 ms,
  `policy stats` 58.4 ms, RIB lookup 65.6 ms, `doctor` 699.8 ms. All 32 reads
  over 1 s (31 `/metrics`, plus the `doctor` timeout) started inside reload
  windows; the slowest `ok` read, a `/metrics` scrape in reload 22, took
  1,652 ms. On v0.81.0 the same p99s were 271.7, 106.3, 53.6, 74.0 and
  657.0 ms.
- Daemon log: 308 `WARN`: 294 unknown-peer drops (147 doctor listener
  probes, two families each), 6 `max prefix exceeded`, 6 `TCP connect failed`
  (one per trip and restart), and one pair of `outbound update not sent —
  marking dirty for resync` (`writer_unavailable`) plus `update-group recovery
  lacks complete admitted proof` at 18:04:34.91Z, during shutdown teardown and
  after the measured window. No `readiness probe failed` record. Engine final:
  `sessions_up 1000/1000 parse_errors=0`.

## Scope

IPv4-only route-server shape at the v0.82.0 tag on one virtualized host;
durations are diagnostic, not performance claims. It does not cover main
after v0.82.0. The gates were not changed for this result.

## Artifacts

Repo-archived in `docs/artifacts/soak/soak-rs-flagship-20261108T172214Z/`:
`samples.csv`, `cycles.log`, `run.json`, `verdict.json` (on-host, run-SHA
analyzer), `binaries.sha256`, `reloadstall.log`, and `scenario/` (config and
policy files). Checkout paths in `binaries.sha256` are normalized to
`<repo>`; other files are byte-for-byte. Retained off-repo with the run
directory: `rustbgpd.log` (~38 MiB), `management-plane-load.jsonl`
(~39 MiB), `metrics-snapshots.txt.gz` (~760 MiB), `doctor-bundle.tar.gz`
(~292 KiB), and the runner, build, generator and watch logs. The verdict
cannot be recomputed from the repo subset; the timing and log notes above
come from the retained files.
