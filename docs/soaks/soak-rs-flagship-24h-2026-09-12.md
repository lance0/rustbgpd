# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-09-12

**Status:** Complete — verdict: **FAIL**
**Run ID:** `tests/soak/runs/soak-rs-flagship-20260912T212113Z`
**Daemon version:** unreleased at run time (after v0.69.0; v0.70.0 was
later released from a descendant commit) at git SHA
`ec84bc5053e923d0af633d6e790a8d452aa4b491`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA)
**Scenario config hash:**
`81b213933f26f21b3f5595bb2be304638bc048ae7260d762f0150c602ab7c1da`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`17f6146847b50a32a5912f6606634e44e4e3506d136539912ce3e00c7bc6938a`;
`rbgp` and `reloadstall` digests in `binaries.sha256`
**Analyzer and gate revision:** `tests/soak/analyze-soak-rs-flagship.py`
and `docs/soaks/soak-acceptance-gates.md` at the run SHA. No reanalysis;
the archived `verdict.json` (sha256
`4cba7d14f2cba501856b5bcb94481a91be2ae2715a7b54d886e700c85a445e62`) is
the original verdict.
**Date:** 2026-09-12T21:21:13Z runner start (build); sampling
2026-09-12T21:34:04Z → engine and management load completed
2026-09-13T21:56:59Z (24 h 22 m 55 s measured window; the serialized trip
windows extend the 86,400 s target)

## Verdict

**FAIL, on `management_cadence` only.** One of 20 analyzer gates
failed: 46 missed 1 s `/metrics` slots plus the resulting
scheduled-interval drift. Every other gate passed, including zero
management-correctness failures across 140,533 operations, 48 of 48
SIGHUP reloads barrier-verified complete, 6 of 6 max-prefix trip chains
with exact breach and flap accounting, the session floor on all 2925
samples, peak RSS 729.8 MB against a 3072 MB ceiling, late-window RSS
slope 0.444 MB/h against 10 MB/h, zero daemon `ERROR` records, and zero
abort records. `/readyz` recorded one isolated latency breach, within the
precommitted consecutive-failure policy.

## Release relationship

v0.70.0 (`ee6215af61222a43c3a8019ee0352ecd5df77913`) was released on this
run's verdict. The
[release checklist](../project/release-checklist.md#flagship-operating-proof)
flagship item calls for the release candidate's own completed 24-hour run
with every applicable gate passing; this run failed one gate, and its
daemon is not the released commit. The release carries later runtime
changes that this run did not soak, including shared update-group draining
that yields, discarding canceled reads during shared output, cancellation
of abandoned replay admission, serving reads during replay admission,
reading installed import counters without session waits, and a terminal
deadline for policy stats. A qualifying run on the released commit
follows.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,761 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2925 |

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 118,817–119,651 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,579 scheduled | 140,533 completed | metrics 87,724 of 87,770; neighbor, policy_stats, and rib_prefix 17,554 of 17,554 each; doctor 147 of 147 |

## Gates — measured vs precommitted

Gates quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
the run SHA. Analyzer gate keys are shown in parentheses.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2925 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** |
| Reload accounting exact (`reload_accounting`) | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** |
| Trip accounting exact (`trip_accounting`) | executed == planned; full per-cycle evidence chain; zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** |
| Exceeded-counter exact (`exceeded_exact`) | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == executed trips | 6 == 6 | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 729.8 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | 0.4445 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 5,609,926,146 | **PASS** |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 0 status failures, 1 latency failure (HTTP 200 at 561.3 ms), longest consecutive 1; 0 scrape failures, 0 observation gaps | **PASS** |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start ≤ measured-window end ≤ stop request ≤ load end ≤ engine release; load end precedes the first received Administrative Shutdown | ordering held, including last operation ≤ load end ≤ engine release; load end precedes the first Administrative Shutdown (2026-09-13T21:56:53Z) | **PASS** |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,724; neighbor 17,554; policy_stats 17,554; rib_prefix 17,554; doctor 147 | **PASS** |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.9995; every other operation 1.0 | **PASS** |
| Management-load cadence (`management_cadence`) | zero missed cadence slots | `metrics: missed=46`; `metrics: scheduled interval drift` | **FAIL** |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | 0 | **PASS** |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 147 attempts, 0 failures | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 207,755 records, 0 `ERROR`, 0 defects | **PASS** |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2925 | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

19 / 20 gates pass. Analyzer verdict: `fail` (`verdict.json` archived
below).

## Analysis notes

Observed:

- Sample accounting: 2925 CSV rows at a 30 s cadence through elapsed
  87,761 s, with no scrape failures and no observation gaps.
- RSS trajectory: 482.9 MB at the first sample; most samples between
  roughly 513 and 562 MB; excursions up to the 729.8 MB peak during reload
  re-advertisement and trip re-announcement, settling back each time;
  late-window slope 0.444 MB/h. The intern gauge
  (`bgp_rib_attr_intern_global_size`) stayed at 999–1000 entries.
- **Management correctness.** Zero non-`ok` results. The terminal
  ordering fixed after the [2026-09-11 run](soak-rs-flagship-24h-2026-09-11.md)
  held: the management load drained before the engine's first
  Administrative Shutdown.
- **Cadence gate.** The 46 missed `/metrics` slots fall in 41 gap
  windows, each inside a distinct reload cycle shortly before that
  reload's barrier-verified completion — about one per reload commit.
  The `scheduled interval drift` entry is flagged by the same skipped
  slots. Metrics completion stayed at 0.9995 of scheduled attempts.
- **readyz.** One latency breach at elapsed 32,865 s (HTTP 200, longest
  consecutive streak 1), inside reload cycle 19; within the precommitted
  consecutive-failure policy and retained as a finding.
- Daemon log census (WARN; no ERROR): 126,035
  `outbound channel full or closed — marking dirty for resync` from 999
  peers, of which 126,012 fall in the single minute 2026-09-13T21:56Z,
  when the engine's final shutdown closed every session, and the remaining
  23 fall on trip minutes (05:39Z, 09:42Z, 13:46Z, 21:52Z) for the
  designated member whose session each trip tears down; 1,005
  `TCP connect failed` (daemon start before the engine listens, plus the
  tripped member during each restart countdown); 294
  `inbound connection from unknown peer, dropping` from `127.0.0.1` and
  `::1` only (147 `doctor` listener-reachability probes × two address
  families); 6 `max prefix exceeded`, one per deliberate breach; one
  startup notice for the RFC 8212 legacy-omission posture.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- Compared with the 2026-09-11 run at `50d161bbe`, the management
  timeouts and the teardown-ordering failure did not recur, and no new
  failure class appeared. The cadence failure is unchanged in shape.
- The backpressure WARN volume is a terminal-teardown and trip artefact,
  not a signal from the live measured window.
- Durations and latencies in this receipt are recorded facts of one run
  on a virtualized guest. They make no performance claim.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20260912T212113Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20260912T212113Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20260912T212113Z/run.json` |
| verdict.json | `docs/artifacts/soak/soak-rs-flagship-20260912T212113Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20260912T212113Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20260912T212113Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20260912T212113Z/scenario/` |

Retained off-repo (too large for git; preserved with the original run
directory):

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~64 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~39 MiB |
| full `/metrics` body per sample | `metrics-snapshots.txt.gz` | ~603 MiB |
| last `doctor` bundle | `doctor-bundle.tar.gz` | ~41 KiB |
| runner, build, and generator logs; final barrier markers | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `engine-finish/` | < 10 KiB |

## Follow-ups

- [ ] Decide whether the missed 1 s `/metrics` slot during reload commits
      is a daemon target or a gate-design question. The zero-missed-slot
      bound is unchanged by this receipt.
- [ ] Run a qualifying 24-hour flagship soak on the released v0.70.0
      commit and publish its receipt, pass or fail.
