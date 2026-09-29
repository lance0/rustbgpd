# Soak Receipt — Route-reflector flagship (reflection under churn) 24 h, 2026-09-28

**Status:** Complete — verdict: **PASS**, on the on-host verdict at the
v0.73.0 tag. A local rerun of the same analyzer over a copy of the run
directory reproduced `verdict.json` exactly; the archived `verdict.json` is
the verdict.
**Run ID:** `tests/soak/runs/soak-rr-flagship-20260928T020014Z`
**Daemon version:** v0.73.0 at git SHA
`335676078965ae5a7d24273821dab12da79222d2` (clean detached checkout of the
tag; image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA)
**Scenario config hash:**
`3c5ab047019fdeb827df63fde01786d0e075c2630590127f7e9a202d4f84e8c0`
(sha256 of `run.json`; pins duration, cadence, pool sizes, and
verification parameters as executed)
**Executable identities:** `rustbgpd` sha256
`000b1385b5eb38ee50bddf51edd0727f526bca30c7ab789b67cf0e7c514ece71`;
`rbgp` and `reloadstall` digests in `binaries.sha256`
**Analyzer and gate revision:** `verdict.json` (sha256
`fea1c49c1e44eeb85032e0e45e5faf453864dbbcbdcc6ef08c4bd09a1bc4206a`),
written on the soak host by `tests/soak/analyze-soak-rr-flagship.py` at the
tag (analyzer sha256
`4689fc8dc7953fb51db3d89d0cbe2d32a739966be416e3424f663886ef5ff1a4`) against
`docs/soaks/soak-acceptance-gates.md` scenario 11 at the tag. Neither file,
nor anything else under `tests/soak/`, changed between the v0.73.0 tag and
the commit publishing this receipt.
**Date:** 2026-09-28T02:00:14Z runner start (build); engine converged and
sampling began 02:00:20Z; hold 2026-09-28T02:00:53Z → 2026-09-29T02:00:53Z
(86,400 s); terminal receipt 2026-09-29T02:03:24Z; runner exit 02:03:25Z
(24 h 3 m 11 s overall)

## Verdict

**PASS on all 13 analyzer gates.** Churn reached 5,483,438 cycles at the end
of the 24 h hold and 5,493,035 at the terminal receipt, having continued
through the refresh. The terminal reflected-delivery verification was
exact: all 1000 clients sent a Normal ROUTE_REFRESH and each received
exactly 99,900 non-self prefixes (`min_unique == max_unique == expected`),
with 0 parse errors and 1000 sessions up. Flap delta was 0 against a budget of 0, and
the session floor held on all 2886 samples. Peak RSS was 427.6 MB against a
1024 MB ceiling, and the late-window RSS slope was +0.7116 MB/h against
10 MB/h. `/readyz` answered HTTP 200 on every hold sample and recovered to
HTTP 200 136 ms after the terminal receipt, against a 60 s bound. The
daemon log holds 22,169 records with zero `ERROR`; `cycles.log` holds zero
abort records.

The only warnings are 5 `readiness probe failed` records, one per sample
inside the terminal ROUTE_REFRESH window. That is the documented
fail-closed readiness behaviour under the deliberate 1000-way refresh, and
the gate passes it by design (see [Analysis notes](#analysis-notes)).

## Release relationship

This is the first route-reflector flagship receipt on a release tag. The
[2026-08-17 run](soak-rr-flagship-24h.md) covered an unreleased SHA, so
reflection had no soak evidence for anything in v0.72.0 or v0.73.0 before
this run. v0.73.0 changes the RIB distribution path (bounded distribution
windows that coalesce already-queued route messages) and boxes the MP path
attributes; this scenario exercises both. The receipt covers the v0.73.0 tag
and this IPv4-only shape on this host, nothing wider.

A 600 s smoke of the same shape at the same tag passed every gate before
the 24 h run. It was a harness check after six weeks without a flagship RR
run, not a receipt attempt, and is not archived here.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 11 — Route-reflector flagship: 1000 real iBGP route-reflector-client sessions × 100 routes each (100,000 total), the `bench/scale/reloadstall` engine's iBGP-RR mode with 8 churners flapping dedicated blocks every 125 ms for the whole window; no reloads and no trips (scenario 10 covers those); closed by the terminal reflected-delivery verification |
| Harness | `tests/soak/run-soak-rr-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rr-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Daemon and engine share the guest's vCPUs. Not a performance-measurement platform |
| Duration | target 86,400 s hold, actual 86,400 s hold + terminal verification; last sample at elapsed 86,574 s |
| Sample interval | 30 s |
| Injection cadence | 8 churners, one announce/withdraw flap message per 125 ms each, running the entire hold; terminal Normal ROUTE_REFRESH from all 1000 clients at hold expiry |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2886 |

The shape matches the [2026-08-17 run](soak-rr-flagship-24h.md): `run.json`
differs only in run ID, git SHA, and the added `nofile_soft` field, and the
scenario configuration only in its per-run temporary runtime directory. The
host differs; see [Claim ceiling](#claim-ceiling).

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| Churn flap cycles (8 churners × 125 ms cadence) | ≥ 2,764,800 (precommitted floor: 0.5 × 64/s × 86,400 s) | 5,483,438 at hold end (`rr_hold elapsed_s=86400`); 5,493,035 at the terminal receipt | Churn continued through the terminal refresh; counter nondecreasing across all 1441 per-minute `rr_hold` status lines; zero monotone breaks |
| Terminal reflected-delivery verification (1000-way Normal ROUTE_REFRESH) | 1 | 1 | `rr_terminal_receipt`: `expected=99900 min_unique=99900 max_unique=99900 sessions_up=1000 parse_errors=0` |

## Gates — measured vs precommitted

Bounds quoted from `docs/soaks/soak-acceptance-gates.md` scenario 11 at the
tag; measured values from `verdict.json`. Analyzer gate keys are shown in
parentheses. The gates table's "reflection under churn" row is evidenced
through `msgs_sent_monotone` and `terminal_delivery_exact`.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2886 | **PASS** |
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, no exceptions | 0 violations | **PASS** |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == 0 | 0 | **PASS** |
| Terminal reflected-delivery exact (`terminal_delivery_exact`) | `min_unique == max_unique == expected == 99,900`; `sessions_up == 1000`; `parse_errors == 0` | exactly that; receipt `churn_cycles=5,493,035` (terminal count); 0 receipt defects | **PASS** |
| Churn-cycle floor (`churn_cycle_floor`) | final `churn_cycles` ≥ 2,764,800, nondecreasing across hold lines | final (terminal-receipt) count 5,493,035; 0 monotone breaks | **PASS** |
| Max-prefix flat (`max_prefix_flat`) | `bgp_max_prefix_exceeded_total` == 0 on every sample | 0 on all 2886 samples | **PASS** |
| Counter advancement (`msgs_sent_monotone`) | `bgp_messages_sent_total` strictly increases across every adjacent sample | 0 breaks, 0 equal intervals; final 4,797,400,577 | **PASS** |
| readyz availability (`readyz`) | (a) hold: HTTP 200 within 250 ms on every sample; (b) terminal-refresh window: every sample records an HTTP response, any code; (c) recovery: 200 within 250 ms no later than 60 s after `rr_terminal_receipt` | (a) 0 bad hold samples, max 8.2 ms; (b) 5 window samples, 0 without a response (all HTTP 503, 201.5–202.3 ms); (c) `recovered_ms=136` | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 1024 MB | 427.6 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | +0.7116 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | 0.0 entries/h | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 22,169 records, 0 `ERROR`, 0 defects; 5 `WARN` | **PASS** |

13 / 13 gates pass. Analyzer verdict: `pass` (`verdict.json` archived
below).

## Analysis notes

Observed:

- Sample accounting: 2886 CSV rows from elapsed 0 to 86,574 s at a 30 s
  cadence (adjacent gaps 30–31 s), one row per interval, no scrape-failure
  gaps.
- RSS trajectory (daemon process-tree RSS, CSV `rss_mb`): 259.4 MB at the
  first sample, then a 237.7–254.6 MB band for the whole post-warmup hold
  (5th–95th percentile 239.0–249.9 MB; median 247.4 MB in the first hold
  hour and 248.3 MB in the last). The 427.6 MB peak is the last sample, in
  the terminal-refresh window (1000 simultaneous full-table Adj-RIB-Out
  re-sends). The analyzer's late window (final 25 %) includes that
  excursion; recomputed over the same window without the five
  terminal-window samples, the slope is +0.10 MB/h. The gate figure is the
  +0.7116 MB/h above.
- Intern gauge (`bgp_rib_attr_intern_global_size`): 1000 entries on every
  sample; late-window slope 0.0. Churn re-interns and releases the same
  fixed attribute universe.
- `/readyz` during the hold: HTTP 200 on every sample, max 8.2 ms. The five
  samples inside the terminal-refresh window (from the engine's
  `rr_terminal refresh` marker at 02:00:53Z) each returned HTTP 503 in
  about 202 ms. The post-receipt probe loop recorded recovery to 200 within
  the 250 ms bound after 136 ms.
- Daemon log census (`verdict.json` `daemon_log.value.warnings_by_message`):
  22,169 records, 0 `ERROR`, 5 `WARN`, all `readiness probe failed` with
  `RIB manager probe timed out (200ms deadline)`, at 02:01:14Z, 02:01:45Z,
  02:02:14Z, 02:02:44Z and 02:03:14Z. Each matches one of the five
  terminal-window samples. None fell in the hold.
- The 2026-08-17 run's daemon log held 361,797
  `channel full or closed — marking dirty for resync` WARNs and 904
  teardown `write/flush failed` lines. This run's log holds none of either.
  The runs differ in daemon revision, host, and log-capture contract, so
  this receipt records the difference without attributing it.
- Engine (`reloadstall.log`): 1000 sessions established with 0 transport
  retries, first exact bitmap at convergence, final
  `rr_terminal_receipt` as above.
- Host cohabitation: the shared bench/soak host lock was held for the
  window; no other soak ran until this run had exited.

Interpretation:

- The terminal receipt is the load-bearing correctness fact: after a full
  day of 8 × 125 ms churn on the v0.73.0 distribution path, the daemon
  re-delivered every observer's exact full-table-minus-own-slice bitmap
  with zero parse errors. A daemon that had stopped reflecting, duplicated,
  or leaked state could not produce that equality.
- The flat hold-window RSS band, zero-slope intern gauge, and flap-free day
  show no leak or stability signal at the flagship RR shape. The terminal
  RSS excursion is the expected cost of 1000 simultaneous full-table
  re-sends and stays inside the ceiling.
- The terminal-window 503s are the deadline-bounded readiness probe failing
  closed while the RIB manager serves the refresh avalanche. Scenario 11's
  readyz gate requires a response, not a 200, inside that window, and
  requires recovery within 60 s afterwards; both held.

## Claim ceiling

This run is on the dedicated soak host, a virtualized guest that is not a
performance-measurement platform. Durations, latencies, churn rates, and
message counts in this receipt are recorded facts of one run. They make no
wall-clock, throughput, or comparative performance claim, including against
the 2026-08-17 run, which ran on a different host.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`, every other file byte-for-byte
from the run directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rr-flagship-20260928T020014Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rr-flagship-20260928T020014Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rr-flagship-20260928T020014Z/run.json` |
| verdict.json (on-host, tag analyzer) | `docs/artifacts/soak/soak-rr-flagship-20260928T020014Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rr-flagship-20260928T020014Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rr-flagship-20260928T020014Z/reloadstall.log` |
| scenario config | `docs/artifacts/soak/soak-rr-flagship-20260928T020014Z/scenario/` |

Retained off-repo (too large for git, or carrying host paths; preserved
with the original run directory). The analyzer needs the daemon log, so the
verdict cannot be recomputed from the repo-archived subset alone:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~7.1 MiB |
| full `/metrics` body per snapshot | `metrics-snapshots.txt.gz` | ~59 MiB |
| 10-minute status-watcher log | `watch.log` | ~30 KiB |
| runner, build, and generator logs; cleanup marker | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `cleanup.complete` | < 10 KiB |

## Follow-ups

- [ ] None arising — every gate passed inside its precommitted bound; no
      threshold or harness changes are proposed from this run.
