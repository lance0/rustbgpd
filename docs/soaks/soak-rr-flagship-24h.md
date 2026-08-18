# Soak Receipt — Route-reflector flagship (reflection under churn) 24 h

**Status:** Complete — verdict: **PASS**
**Run ID:** `tests/soak/runs/soak-rr-flagship-20260817T063821Z`
**Daemon version:** unreleased at git SHA
`a88666c418de3531a0485a6bd1e248a76696f5f0`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA, sha256 digests archived in
`binaries.sha256`)
**Scenario config hash:**
`cf295339689a357abe9569c5e7f34cc1ac610c9757a0ca34aade0f4031f8f27d`
(sha256 of `run.json`; pins duration, cadence, pool sizes, and
verification parameters as executed)
**Date:** 2026-08-17T06:38:21Z → 2026-08-18T06:39:56Z (24 h 2 m: the
86,400 s hold plus the terminal verification and readyz-recovery
probe)

## Verdict

**PASS.** All precommitted gates green, zero failed gates. After
5,486,092 churn cycles across the 24 h hold, the terminal
reflected-delivery verification was exact: all 1000 clients sent a
Normal ROUTE_REFRESH and each received exactly 99,900 non-self
prefixes (`min_unique == max_unique == expected`), with 0 parse errors
and 1000 sessions up. Flap delta was exactly 0 for the whole run
against a budget of 0; the session floor held on all 2883 samples;
peak RSS 342.5 MB against a 1024 MB ceiling; late-window RSS slope
0.2958 MB/h against a 10 MB/h bound; `/readyz` recovered to HTTP 200
within 112 ms of the terminal receipt against a 60 s bound; zero abort
records.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 11 — Route-reflector flagship: 1000 real iBGP route-reflector-client sessions × 100 routes each (100,000 total), the `bench/scale/reloadstall` engine's iBGP-RR mode with 8 churners flapping dedicated blocks every 125 ms for the whole window; no reloads and no trips (scenario 10 covers those); closed by the terminal reflected-delivery verification |
| Harness | `tests/soak/run-soak-rr-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rr-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | AMD Ryzen Threadripper 7970X, 32 cores / 64 threads, 125 GB RAM, Linux 6.17.0-35-generic |
| Duration | target 86,400 s hold, actual 86,400 s hold + 55 s terminal verification |
| Sample interval | 30 s |
| Injection cadence | 8 churners, one announce/withdraw flap message per 125 ms each, running the entire hold; terminal Normal ROUTE_REFRESH from all 1000 clients at hold expiry |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2883 |

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| Churn flap cycles (8 churners × 125 ms cadence) | ≥ 2,764,800 (precommitted floor: 0.5 × 64/s × 86,400 s) | 5,486,092 | Counter nondecreasing across all per-minute `rr_hold` status lines; zero monotone breaks |
| Terminal reflected-delivery verification (1000-way Normal ROUTE_REFRESH) | 1 | 1 | `rr_terminal_receipt`: `expected=99900 min_unique=99900 max_unique=99900 sessions_up=1000 parse_errors=0` |

## Gates — measured vs precommitted

Gates quoted from `docs/soaks/soak-acceptance-gates.md` scenario 11 at
the run SHA.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor | `established == 1000` on every post-warmup sample, no exceptions | 0 violations / 2883 samples | **PASS** |
| Session-flap budget exact | flap delta over the run == 0 | 0 | **PASS** |
| Terminal reflected-delivery exact | `min_unique == max_unique == expected == 99,900`; `sessions_up == 1000`; `parse_errors == 0` | exactly that, after 5,486,092 churn cycles | **PASS** |
| Churn-cycle floor | final `churn_cycles` ≥ 2,764,800, nondecreasing across hold lines | 5,486,092; 0 monotone breaks | **PASS** |
| Reflection under churn | `msgs_sent_total` advancing every sample + the terminal gate | monotone with 0 breaks (final 5,480,254,404) and the terminal receipt exact (the analyzer evidences this gate through `msgs_sent_monotone` + `terminal_delivery_exact`) | **PASS** |
| Max-prefix flat | `bgp_max_prefix_exceeded_total` == 0 on every sample | 0 on all 2883 samples | **PASS** |
| Peak RSS | < 1024 MB | 342.5 MB | **PASS** |
| RSS late-window slope | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | 0.2958 MB/h | **PASS** |
| Intern-table late-window slope | < 100 entries/h over the same window | 0.0 entries/h | **PASS** |
| Counter monotonicity (no restart) | `bgp_messages_sent_total` never decreases between samples | 0 breaks | **PASS** |
| readyz availability | (a) hold: HTTP 200 within 250 ms on every sample; (b) terminal-refresh window: every sample records an HTTP response, any code; (c) recovery: 200 within 250 ms no later than 60 s after `rr_terminal_receipt` | (a) 0 bad hold samples, max 6.2 ms; (b) 2 window samples, both responded (200 at 148.7 ms and 183.4 ms); (c) `recovered_ms=112` | **PASS** |
| Minimum sample count | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2883 | **PASS** |
| No abort record | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

13 / 13 gates pass (the analyzer's `verdict.json` records 12 —
reflection-under-churn is evidenced through `msgs_sent_monotone` +
`terminal_delivery_exact` per the gates table). Analyzer verdict:
`pass` (`verdict.json` archived below).

## Analysis notes

Observed:

- Sample accounting: 2883 CSV rows over 86,471 s at a 30 s cadence —
  one row per interval, no scrape-failure gaps.
- RSS trajectory: 245.0 MB at the first sample, settling into a
  ~220–235 MB band for the whole hold; the 342.5 MB peak occurred in
  the terminal-refresh window (1000 simultaneous full-table
  Adj-RIB-Out re-sends); late-window slope 0.2958 MB/h, dominated by
  that terminal excursion.
- Intern gauge (`bgp_rib_attr_intern_global_size`): pinned at 1000
  entries for the entire run; late-window slope 0.0 — churn re-interns
  and releases the same fixed attribute universe.
- `/readyz` during the hold: HTTP 200 on every sample, max 6.2 ms. The
  two samples inside the terminal-refresh window both responded
  (HTTP 200 at 148.7 ms and 183.4 ms); the post-receipt probe loop
  recorded recovery to 200-within-bound after 112 ms.
- Daemon log census (WARN/ERROR): 361,797 `channel full or closed —
  marking dirty for resync` WARN lines (distribution backpressure
  under 125 ms churn fan-out to 999 receivers per flap; marked peers
  resync, no session dropped); 904 `write/flush failed`
  (BrokenPipe/ConnectionReset) lines, all clustered at
  2026-08-18T06:39:55Z — the engine's disconnect of all 1000 sessions
  at run teardown, immediately after the terminal receipt was
  captured.
- Host cohabitation: none — the `bench-nightly` schedule was paused,
  the shared bench/soak host lock was held for the window, and `main`
  was frozen at the run SHA.

Interpretation:

- The terminal receipt is the load-bearing correctness fact: after a
  full day of 8 × 125 ms churn, the daemon re-delivered every
  observer's exact full-table-minus-own-slice bitmap with zero parse
  errors — a daemon that had stopped reflecting, duplicated, or leaked
  state could not produce that equality.
- The flat hold-window RSS band, zero-slope intern gauge, and
  flap-free day show no leak or stability signal at the flagship RR
  shape; the terminal RSS excursion is the expected cost of 1000
  simultaneous full-table re-sends and is inside the ceiling.
- Durations and latencies in this receipt are recorded facts of this
  single run. No control daemon ran alongside it, so this receipt makes
  no comparative performance claim.

Evidence history:

- A 1 h dry-run at this scenario preceded the 24 h run. The dry-run's
  first attempt failed exactly one gate — readyz — during the terminal
  1000-way refresh avalanche, where the deadline-bounded fail-closed
  probe returned the documented busy signal. The gate was refined in
  #1694 before any receipt run: the hold-window strictness is
  unchanged, the terminal window requires a recorded response, and a
  new explicit recovery bound (200 within 60 s of the receipt) was
  added. The red dry-run attempt is preserved in the local run
  directory per the gates doc; it was a dry-run, not a receipt
  attempt, and does not count toward ADR-0125 E2's two receipts.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` redacted to `<repo>`):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rr-flagship-20260817T063821Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rr-flagship-20260817T063821Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rr-flagship-20260817T063821Z/run.json` |
| verdict.json | `docs/artifacts/soak/soak-rr-flagship-20260817T063821Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rr-flagship-20260817T063821Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rr-flagship-20260817T063821Z/reloadstall.log` |
| scenario config | `docs/artifacts/soak/soak-rr-flagship-20260817T063821Z/scenario/` |

Local-only (too large for git; preserved in the run directory —
full daemon logs are retained off-repo):

| Artifact | Local path | Size |
|----------|------------|------|
| daemon log | `tests/soak/runs/soak-rr-flagship-20260817T063821Z/rustbgpd.log` | ~79 MB |
| runner/build/generator logs | `tests/soak/runs/soak-rr-flagship-20260817T063821Z/` (`soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`) | < 20 KB |

## Follow-ups

- [ ] None arising — every gate passed inside its precommitted bound;
      no threshold or harness changes are proposed from this run.
