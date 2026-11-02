# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-11-01

**Status:** Complete — verdict: **PASS**, 22 / 22 gates on the on-host
`verdict.json`; 0 management correctness failures, 0 availability misses.

**Run ID:** `tests/soak/runs/soak-rs-flagship-20261101T061310Z`
**Daemon version:** v0.81.0 tag, git SHA
`eb1749d7018cd9691e4f4c9adef3b9adb830e9a8`; bare-host, `rustbgpd`/`rbgp`
`--release --locked`, `reloadstall` `--profile scale --locked`, built at this
SHA from a clean tree
**Scenario config hash:** `run.json` sha256 `efe5a7ab8cbdd98088db6b02fa4f6f75ae1b6a278ddb2645cb2cb40f09c822c2`
**Executable identities:** `rustbgpd` sha256 `3b6860ba4474a7ac97f95367b2d6e6b0dcca4865f12afbe885f1c6a1b1c4310e`;
`rbgp` and `reloadstall` in `binaries.sha256`
**Analyzer and gate revision:** on-host `verdict.json` (sha256
`1afda2d98786229e4f90ad06c71e6a6141ce81edf89f16b50ff291c5bd816208`) from
`tests/soak/analyze-soak-rs-flagship.py` at the run SHA (sha256
`aa04ad40d2a3d1b1abcbc3ce4b33d7e0ba18a7c1fbd024d422515819492a3147`, the same
file as the [2026-10-28 run](soak-rs-flagship-24h-2026-10-28.md)) and scenario
10 of `docs/soaks/soak-acceptance-gates.md`, both unchanged from the run SHA
to this receipt's commit
**Date:** runner start 2026-11-01T06:13:10Z; sampling 06:13:36Z → management
load end 2026-11-02T06:34:24.88Z, first Administrative Shutdown 0.15 s later
(87,649 s = 24 h 20 m 49 s measured window)

## Release relationship and shape

v0.81.0 (`eb1749d70`) was tagged 2026-11-01T05:07Z; this run started on the
tagged commit 1 h 6 m later. **It covers the v0.81.0 tag only, not main after
it.** The tag contains both probe fixes that followed the
[v0.80.1 run's](soak-rs-flagship-24h-2026-10-26.md) doctor miss: #3447 (the
SHA of the [2026-10-28 run](soak-rs-flagship-24h-2026-10-28.md)) and #3456
(Established count without querying sessions), which no earlier run covered.
The shape matches the [2026-10-26 run](soak-rs-flagship-24h-2026-10-26.md#release-relationship-and-shape)
on the same 8 vCPU / 15 GiB virtualized host: 1000 eBGP route-server clients ×
400 IPv4 routes under `reloadstall` churn, 48 SIGHUP reloads, 6 max-prefix
trips on `127.1.0.1`, and management load. `run.json` differs from the
2026-10-28 run only in run ID, SHA and monotonic timestamps; the policy files
are byte-identical, and `config.toml` differs only in its temporary runtime
directory. The runner does not exercise dynamic neighbors, graceful restart,
LLGR or FlowSpec, so the v0.81.0 changes in those areas are not covered here.

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP reload | 48 | 48 | All barrier-verified complete, 7–11 s issue to completion |
| Max-prefix trip → timed restart | 6 | 6 | Full chain each cycle; hold-down 118,795–119,571 ms of 120,000; post-recovery `usage=400 limit=450 headroom=50` |
| Management operations | 140,387 scheduled | 140,354 completed, all `ok` | metrics 87,617 of 87,650 (33 missed slots); neighbor, policy_stats and rib_prefix 17,530 each; doctor 147 of 147 |

## Gates — measured vs precommitted

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| `session_floor` | `established == 1000` post-warmup; `999` only in a declared trip window | 0 violations / 2921; `999` on 24 samples, all in trip windows | **PASS** |
| `reload_accounting` | issued == complete; complete ≥ 0.9 × planned | 48 == 48 == 48 | **PASS** |
| `trip_accounting` | executed == planned; full evidence chain | 6 == 6; 0 defects | **PASS** |
| `exceeded_exact` | exceeded counter == executed trips | 6 == 6 | **PASS** |
| `flap_budget` | flap delta == executed trips | 6 == 6 | **PASS** |
| `rss_peak_mb` | < 3072 MB | 698.8 MB | **PASS** |
| `rss_late_slope_per_hour` | < 10 MB/h, final 25 % | +1.62 MB/h | **PASS** |
| `intern_late_slope_per_hour` | < 100 entries/h, same window | −0.0034 entries/h | **PASS** |
| `msgs_sent_monotone` | never decreases | 0 breaks; final 5,566,844,434 | **PASS** |
| `readyz` | < 3 consecutive misses of HTTP 200 within 250 ms; no scrape failure or gap | 0 bad samples, 0 scrape failures, 0 gaps | **PASS** |
| `outbound_registration_wait` | max sampled oldest wait ≤ 300 s | 2 s | **PASS** |
| `management_evidence` | summary matches records and `run.json` | 0 errors, 0 mismatches | **PASS** |
| `management_lifetime` | load brackets the window; ends before first Administrative Shutdown | held | **PASS** |
| `management_operations` | all five present | all present | **PASS** |
| `management_completion` | each ≥ 90 % of scheduled | metrics 0.99962; others 1.0 | **PASS** |
| `management_cadence` | misses only in reload windows, ≤ 2 per window | metrics 33, one in each of 33 reload windows; others 0 | **PASS** |
| `management_failures` (correctness) | zero non-`ok` other than availability misses; zero invalid `ok` | 0 | **PASS** |
| `management_availability` | isolated misses only inside a reload window; < 2 consecutive; ≤ 3 per operation | 0 misses, 0 violations | **PASS** |
| `management_doctor` | every `doctor` attempt `ok`, except an availability miss | 147 attempts, 0 failures, 0 availability misses | **PASS** |
| `daemon_log` | complete and well-formed; any `ERROR` fails | 79,999 records, 0 `ERROR`, 0 defects | **PASS** |
| `min_samples` | ≥ 2592 | 2921 | **PASS** |
| `no_abort` | zero `ABORT:` lines | 0 | **PASS** |

## Other observations

- RSS: 5th–95th percentile 508.8–573.3 MB; the 698.8 MB peak is a sample
  inside reload 37. Outside reload windows (from `issued` to 30 s after
  `complete`) the maximum is 581.8 MB, against 554.0 MB on the v0.80.1 run
  and 485.9 MB on the [v0.76.0 run](soak-rs-flagship-24h-2026-10-11.md),
  computed the same way from the archived samples. The between-reload median
  rose from 526.9 MB in the first quarter of the run to 561.4 MB in the last;
  on v0.80.1 the same medians were 526.5 and 541.0 MB. The late slope stayed
  inside its gate. The cause of either difference is not established.
- Management reads: p99 `/metrics` 271.7 ms, `neighbor` 106.3 ms,
  `policy stats` 53.6 ms, RIB lookup 74.0 ms, `doctor` 657.0 ms. All 36 reads
  over 1 s started inside reload windows; the slowest, a `doctor` run in
  reload 27, took 4,404 ms against the 5 s timeout and returned `ok`.
- Daemon log: 308 `WARN`: 294 unknown-peer drops (147 doctor listener
  probes, two families each), 6 `max prefix exceeded`, 6 `TCP connect failed`
  (one per trip and restart), and one pair of `outbound update not sent —
  marking dirty for resync` (`writer_unavailable`) plus `update-group recovery
  lacks complete admitted proof` at 06:34:25.35Z, during shutdown teardown and
  after the measured window. No `readiness probe failed` record. Engine final:
  `sessions_up 1000/1000 parse_errors=0`.

## Scope

IPv4-only route-server shape at the v0.81.0 tag on one virtualized host;
durations are diagnostic, not performance claims. It does not cover main
after v0.81.0, including later `rpol` language changes. The gates were not
changed for this result.

## Artifacts

Repo-archived in `docs/artifacts/soak/soak-rs-flagship-20261101T061310Z/`:
`samples.csv`, `cycles.log`, `run.json`, `verdict.json` (on-host, run-SHA
analyzer), `binaries.sha256`, `reloadstall.log`, and `scenario/` (config and
policy files). Checkout paths in `binaries.sha256` are normalized to
`<repo>`; other files are byte-for-byte. No doctor report failed, so none is
archived. Retained off-repo with the run directory: `rustbgpd.log`
(~38 MiB), `management-plane-load.jsonl` (~39 MiB),
`metrics-snapshots.txt.gz` (~697 MiB), `doctor-bundle.tar.gz` (~274 KiB), and
the runner, build, generator and watch logs. The verdict cannot be recomputed
from the repo subset; the timing and log notes above come from the retained
files.
