# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip) 24 h

**Status:** Complete — verdict: **PASS**
**Run ID:** `tests/soak/runs/soak-rs-flagship-20260816T062037Z`
**Daemon version:** unreleased at git SHA
`a88666c418de3531a0485a6bd1e248a76696f5f0`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA, sha256 digests archived in
`binaries.sha256`)
**Scenario config hash:**
`d6fe886aa15ce8367d45da2bef212decd78fdcc016f66535dc419be7372fcb47`
(sha256 of `run.json`; pins duration, cadence, pool sizes, and
injection parameters as executed)
**Date:** 2026-08-16T06:20:37Z → 2026-08-17T06:37:36Z (24 h 17 m;
87,409 s sampled — the serialized trip windows and the final quiesce
extend the 86,400 s target)

## Verdict

**PASS.** All 12 precommitted gates green, zero failed gates. 48 of 48
SIGHUP policy-file reloads issued and barrier-verified complete; 6 of 6
max-prefix trip/timed-restart cycles executed with the full evidence
chain on every cycle; the session floor held on all 2914 samples (999
only inside declared trip windows); flap delta == exceeded-counter ==
executed trips == 6; peak RSS 581.7 MB against a 3072 MB ceiling;
late-window RSS slope 0.0724 MB/h against a 10 MB/h bound; zero
`/readyz` violations; zero abort records.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total), the `bench/scale/reloadstall` engine's steady churn running throughout, plus serialized SIGHUP-reload and max-prefix-trip injections |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | AMD Ryzen Threadripper 7970X, 32 cores / 64 threads, 125 GB RAM, Linux 6.17.0-35-generic |
| Duration | target 86,400 s, actual 87,409 s sampled |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2914 |

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | ~3 s from `issued` to barrier-verified `complete` on every cycle; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 119,129–119,731 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time; trip 6 settled through the final-quiesce path (#1692) |

## Gates — measured vs precommitted

Gates quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
the run SHA.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2914 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** |
| Reload accounting exact | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** |
| Trip accounting exact | executed == planned; full per-cycle evidence chain (breach counter exact, countdown via `max_prefix_restart_remaining_millis` with `action=restart`, re-Established ≤ restart + 60 s, post-recovery `usage == routes`, `usage + headroom == limit`); zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** |
| Exceeded-counter exact | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** |
| Session-flap budget exact | flap delta over the run == executed trips | 6 == 6 | **PASS** |
| Peak RSS | < 3072 MB | 581.7 MB | **PASS** |
| RSS late-window slope | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | 0.0724 MB/h | **PASS** |
| Intern-table late-window slope | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** |
| Counter monotonicity (no restart) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 5,591,327,757 | **PASS** |
| readyz availability | HTTP 200 within 250 ms on every sample | 0 bad samples / 2914; max 41.0 ms | **PASS** |
| Minimum sample count | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2914 | **PASS** |
| No abort record | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

12 / 12 gates pass. Analyzer verdict: `pass` (`verdict.json` archived
below).

## Analysis notes

Observed:

- Sample accounting: 2914 CSV rows over 87,409 s at a 30 s cadence —
  one row per interval, no scrape-failure gaps.
- RSS trajectory: 447.6 MB at the first sample; a steady band of
  roughly 432–449 MB between injections; excursions up to the 581.7 MB
  peak during reload full-table re-advertisement and trip re-announce
  bursts, settling back into the band each time; late-window slope
  0.0724 MB/h.
- Intern gauge (`bgp_rib_attr_intern_global_size`): 999–1000 entries
  for the whole run; late-window slope −0.0034 entries/h.
- `/readyz`: HTTP 200 on every sample, typically 2–4 ms, max 41.0 ms —
  including samples taken mid-reload and mid-trip.
- Daemon log census (WARN/ERROR): 117,120 `channel full or closed —
  marking dirty for resync` WARN lines (distribution backpressure under
  churn fan-out; the marked peers resync and no session dropped); 6
  max-prefix WARN/ERROR pairs, one per deliberate breach; 58
  `write/flush failed` (BrokenPipe) lines, all clustered at
  2026-08-17T06:37:46Z — the engine's disconnect of all 1000 sessions
  at run teardown, after evidence capture; one startup notice for the
  RFC 8212 legacy-omission posture.
- Host cohabitation: none — the `bench-nightly` schedule was paused,
  the shared bench/soak host lock was held for the window, and `main`
  was frozen at the run SHA.

Interpretation:

- The reload-window RSS excursions with settle-back match the glibc
  reload-retention pattern precommitted in the gate rationale (a
  known-benign allocator behavior — jemalloc erases it; it is not an
  intern/RIB leak); together with the flat late-window slope and the
  pinned intern gauge, there is no leak signal.
- The backpressure WARN volume is the expected shape of 1000-way churn
  fan-out; the dirty-resync path it names is exactly what kept
  delivery correct without dropping sessions.
- Durations and latencies in this receipt are recorded facts of this
  single run. No control daemon ran alongside it, so this receipt makes
  no comparative performance claim.

Evidence history:

- A 1 h dry-run at this scenario preceded the 24 h run. The dry-run's
  first attempt aborted fail-closed on a final-trip evidence race (the
  run could end before the last trip's evidence chain completed); this
  was fixed in #1692 (final-trip evidence hold + bounded events) before
  any 24 h receipt attempt. The red dry-run attempt is preserved in the
  local run directory per the gates doc; it was a dry-run, not a
  receipt attempt, and does not count toward ADR-0125 E2's two
  receipts.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` redacted to `<repo>`):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20260816T062037Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20260816T062037Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20260816T062037Z/run.json` |
| verdict.json | `docs/artifacts/soak/soak-rs-flagship-20260816T062037Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20260816T062037Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20260816T062037Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20260816T062037Z/scenario/` |

Local-only (too large for git; preserved in the run directory —
full daemon logs are retained off-repo):

| Artifact | Local path | Size |
|----------|------------|------|
| daemon log | `tests/soak/runs/soak-rs-flagship-20260816T062037Z/rustbgpd.log` | ~30 MB |
| runner/build/generator logs | `tests/soak/runs/soak-rs-flagship-20260816T062037Z/` (`soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`) | < 20 KB |

## Follow-ups

- [ ] None arising — every gate passed inside its precommitted bound;
      no threshold or harness changes are proposed from this run.
