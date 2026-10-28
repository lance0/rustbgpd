# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-10-28

**Opportunistic run on an untagged main SHA, not a release qualification.**
It covers `110dd43f9` only; the latest tagged route-server flagship run is
still the [v0.80.1 run](soak-rs-flagship-24h-2026-10-26.md).

**Status:** Complete — verdict: **PASS**, 22 / 22 gates on the on-host
`verdict.json`; 0 management correctness failures, 0 availability misses.

**Run ID:** `tests/soak/runs/soak-rs-flagship-20261027T050805Z`
**Daemon version:** unreleased main `110dd43f9be38901fc7826eb74673b7c6d2bc0d6`;
bare-host, `rustbgpd`/`rbgp` `--release --locked`, `reloadstall`
`--profile scale --locked`, built at this SHA from a clean tree
**Scenario config hash:** `run.json` sha256 `e322e9ced9ed812f132e71469f170277cf8ee2000e25a3b208bf6f8e7d69a476`
**Executable identities:** `rustbgpd` sha256 `81407b175b32fb5e9fe9980582137196fc4360559e53d6ec584fdb614de9eed5`;
`rbgp` and `reloadstall` in `binaries.sha256`
**Analyzer and gate revision:** on-host `verdict.json` (sha256
`321f4ae563a4f607b10483f0ffa250310835601339d2fc8c18fa3c01a076268e`) from
`tests/soak/analyze-soak-rs-flagship.py` at the run SHA (sha256
`aa04ad40d2a3d1b1abcbc3ce4b33d7e0ba18a7c1fbd024d422515819492a3147`) and
scenario 10 of `docs/soaks/soak-acceptance-gates.md`, both unchanged from the
run SHA to this receipt's commit
**Date:** runner start 2026-10-27T05:08:05Z; sampling 05:24:53Z → management
load end 2026-10-28T05:45:20.77Z (87,628 s measured window)

## Why this run

The [v0.80.1 run](soak-rs-flagship-24h-2026-10-26.md) on this same
8 vCPU / 15 GiB virtualized host had one `rbgp doctor` miss: its
`daemon.healthy` check missed the 200 ms peer-manager probe deadline just
after reload 28 committed. This SHA contains #3447 (health and readiness
probes kept inside their deadlines after a reload) and #3445 (the split
management gate). Here all 147 `rbgp doctor` runs were `ok` and `/readyz` had
0 bad samples. The v0.80.1 miss was 1 record of 147, so one clean run is
consistent with the fix, not proof of it. #3456 landed after this SHA and is
not covered.

## Shape

The shape matches the [2026-10-26 run](soak-rs-flagship-24h-2026-10-26.md#release-relationship-and-shape):
1000 eBGP route-server clients × 400 IPv4 routes under `reloadstall` churn,
48 SIGHUP reloads, 6 max-prefix trips on `127.1.0.1`, and management load.
`run.json` differs from that run only in run ID, SHA and monotonic
timestamps. The policy files are byte-identical, and `config.toml` differs
only in its temporary runtime directory.

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP reload | 48 | 48 | All barrier-verified complete |
| Max-prefix trip → timed restart | 6 | 6 | Full chain each cycle; each recovery logged `usage=400 limit=450 headroom=50` |
| Management operations | 140,353 scheduled | 140,326 completed, all `ok` | metrics 87,601 of 87,628 (27 missed slots); neighbor, policy_stats and rib_prefix 17,526 each; doctor 147 of 147 |

## Gates — measured vs precommitted

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| `session_floor` | `established == 1000` post-warmup; `999` only in a declared trip window | 0 violations / 2920; `999` on 24 samples, all in trip windows | **PASS** |
| `reload_accounting` | issued == complete; complete ≥ 0.9 × planned | 48 == 48 == 48 | **PASS** |
| `trip_accounting` | executed == planned; full evidence chain | 6 == 6; 0 defects | **PASS** |
| `exceeded_exact` | exceeded counter == executed trips | 6 == 6 | **PASS** |
| `flap_budget` | flap delta == executed trips | 6 == 6 | **PASS** |
| `rss_peak_mb` | < 3072 MB | 656.5 MB | **PASS** |
| `rss_late_slope_per_hour` | < 10 MB/h, final 25 % | +1.02 MB/h | **PASS** |
| `intern_late_slope_per_hour` | < 100 entries/h, same window | −0.0034 entries/h | **PASS** |
| `msgs_sent_monotone` | never decreases | 0 breaks | **PASS** |
| `readyz` | < 3 consecutive misses of HTTP 200 within 250 ms; no scrape failure or gap | 0 bad samples, 0 scrape failures, 0 gaps | **PASS** |
| `outbound_registration_wait` | max sampled oldest wait ≤ 300 s | 0 s | **PASS** |
| `management_evidence` | summary matches records and `run.json` | 0 errors, 0 mismatches | **PASS** |
| `management_lifetime` | load brackets the window; ends before first Administrative Shutdown | held | **PASS** |
| `management_operations` | all five present | all present | **PASS** |
| `management_completion` | each ≥ 90 % of scheduled | metrics 0.99969; others 1.0 | **PASS** |
| `management_cadence` | misses only in reload windows, ≤ 2 per window | metrics 27, one in each of 27 reload windows; others 0 | **PASS** |
| `management_failures` (correctness) | zero non-`ok` other than availability misses; zero invalid `ok` | 0 | **PASS** |
| `management_availability` | isolated misses only inside a reload window; < 2 consecutive; ≤ 3 per operation | 0 misses, 0 violations | **PASS** |
| `management_doctor` | every `doctor` attempt `ok`, except an availability miss | 147 attempts, 0 failures, 0 availability misses | **PASS** |
| `daemon_log` | complete and well-formed; any `ERROR` fails | 79,613 records, 0 `ERROR`, 0 defects | **PASS** |
| `min_samples` | ≥ 2592 | 2920 | **PASS** |
| `no_abort` | zero `ABORT:` lines | 0 | **PASS** |

## Other observations

- Daemon log: 314 `WARN`: 294 unknown-peer drops (147 doctor listener
  probes, two families each), 6 `max prefix exceeded`, 6 `TCP connect failed`
  (one per trip and restart), and four pairs of `outbound update not sent —
  marking dirty for resync` (`writer_unavailable`) plus `update-group recovery
  lacks complete admitted proof`, all at 05:45:21Z during shutdown teardown,
  after the measured window. Engine final: `sessions_up 1000/1000 parse_errors=0`.

## Scope

IPv4-only route-server shape at untagged main `110dd43f9` on one virtualized
host; no release qualification and no performance claim. The gates were not
changed for this result.

## Artifacts

Repo-archived in `docs/artifacts/soak/soak-rs-flagship-20261027T050805Z/`:
`samples.csv`, `cycles.log`, `run.json`, `verdict.json` (on-host, run-SHA
analyzer), `binaries.sha256`, `reloadstall.log`, and `scenario/` (config and
policy files). Checkout paths in `binaries.sha256` are normalized to
`<repo>`; other files are byte-for-byte. No doctor report failed, so none is
archived. Retained off-repo with the run directory:
`rustbgpd.log` (~38 MiB), `management-plane-load.jsonl` (~39 MiB),
`metrics-snapshots.txt.gz` (~695 MiB), `doctor-bundle.tar.gz` (~49 KiB), and
the runner, build, generator and watch logs. The verdict cannot be recomputed
from the repo subset.
