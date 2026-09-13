# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-09-11

**Status:** Complete — verdict: **FAIL**
**Run ID:** `tests/soak/runs/soak-rs-flagship-20260911T184544Z`
**Daemon version:** unreleased (between v0.69.0 and v0.70.0) at git SHA
`50d161bbe2eb17d20897bcda322905e95c845046`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA)
**Scenario config hash:**
`a7b7fb9495835947e9e95eec40591513fe8cf5dee1148456a481ccb04df02f4c`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`0100226b995533ced940c3090d2b9899c240ebaf8ef7e832c1fe583d91326636`;
`rbgp` and `reloadstall` digests in `binaries.sha256`
**Analyzer and gate revision:** `tests/soak/analyze-soak-rs-flagship.py`
and `docs/soaks/soak-acceptance-gates.md` at the run SHA. No reanalysis;
the archived `verdict.json` (sha256
`667dfcc87780701522cf193cea5e055368f9b97822b49f47d4fee439a7a900ab`) is
the original verdict.
**Date:** 2026-09-11T18:45:44Z runner start (build); sampling
2026-09-11T18:58:32Z → engine and management load completed
2026-09-12T19:21:29Z (24 h 22 m 57 s measured window; the serialized trip
windows extend the 86,400 s target)

## Verdict

**FAIL.** Two of 20 analyzer gates failed. `management_failures` counted
3 non-`ok` results out of 140,548 management operations: two genuine CLI
read timeouts during reload 42 and one terminal empty-route result caused
by the runner's teardown ordering. `management_cadence` reported 43 missed
1 s `/metrics` slots plus the resulting scheduled-interval drift. Every
other gate passed: 48 of 48 SIGHUP reloads barrier-verified complete, 6 of
6 max-prefix trip chains with exact breach and flap accounting, the
session floor held on all 2926 samples, peak RSS 691.5 MB against a
3072 MB ceiling, late-window RSS slope 0.553 MB/h against 10 MB/h, zero
daemon `ERROR` records, and zero abort records.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,767 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2926 |

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 118,962–119,530 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,591 scheduled | 140,548 completed | metrics 87,733 of 87,776; neighbor, policy_stats, and rib_prefix 17,556 of 17,556 each; doctor 147 of 147 |

## Gates — measured vs precommitted

Gates quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
the run SHA. Analyzer gate keys are shown in parentheses.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2926 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** |
| Reload accounting exact (`reload_accounting`) | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** |
| Trip accounting exact (`trip_accounting`) | executed == planned; full per-cycle evidence chain; zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** |
| Exceeded-counter exact (`exceeded_exact`) | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == executed trips | 6 == 6 | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 691.5 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | 0.5529 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 5,609,360,986 | **PASS** |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 0 status failures, 2 latency failures (HTTP 200 at 947.6 ms and 841.6 ms), longest consecutive 1; 0 scrape failures, 0 observation gaps | **PASS** |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start and load end ≥ measured-window end | ordering held: load start ≤ measured start ≤ measured end ≤ stop request ≤ load end | **PASS** |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,733; neighbor 17,556; policy_stats 17,556; rib_prefix 17,556; doctor 147 | **PASS** |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.9995; every other operation 1.0 | **PASS** |
| Management-load cadence (`management_cadence`) | zero missed cadence slots | `metrics: missed=43`; `metrics: scheduled interval drift` | **FAIL** |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | 3: `neighbor` `cli_exit` (exit 1), `policy_stats` `cli_exit` (exit 1), `rib_prefix` `route` (exit 0, empty route array) | **FAIL** |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 147 attempts, 0 failures | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 199,526 records, 0 `ERROR`, 0 defects | **PASS** |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2926 | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

18 / 20 gates pass. Analyzer verdict: `fail` (`verdict.json` archived
below).

## Analysis notes

Observed:

- Sample accounting: 2926 CSV rows at a 30 s cadence through elapsed
  87,767 s, with no scrape failures and no observation gaps.
- RSS trajectory: 494.6 MB at the first sample; most samples between
  roughly 509 and 555 MB; excursions up to the 691.5 MB peak during reload
  re-advertisement and trip re-announcement, settling back each time;
  late-window slope 0.553 MB/h. The intern gauge
  (`bgp_rib_attr_intern_global_size`) stayed at 999–1000 entries.
- **Management timeouts in reload 42.** The `neighbor` and
  `policy_stats` reads scheduled at 2026-09-12T15:46:12.7Z (reload 42
  issued 15:46:10Z, barrier-verified complete 15:46:22Z) both exited
  non-zero at the CLI's 2 s read deadline; the API audit log records
  `handler_deadline_exceeded` for the policy-stats handler. The exact
  RIB lookup scheduled at the same instant succeeded. Reload 42 was the
  only reload in the run whose cohort destination prestage did not
  complete within its cap; that cohort committed unprestaged.
- **Cause of those two timeouts: unattributed.** The retained
  `bgp_rib_actor_work_duration_seconds{work_unit}` snapshots straddle
  15:45:45–15:46:15Z and 15:46:15–15:46:45Z. All 1,869
  `distribute_flush` components completed in the first interval fall at
  or below the 25 ms bucket, and all 1,716 in the second at or below the
  200 ms bucket. The retained histogram therefore does not establish a
  single measured RIB work unit lasting as long as the deadline, and this
  receipt does not attribute the timeouts to one. The component
  histogram does not cover all actor work or bound probe latency (see the
  [operations reference](../reference/operations.md#routing)).
- **Terminal empty-route result: runner teardown ordering.** The final
  `rib_prefix` operation, scheduled at 19:21:27Z, returned `[]` (3 bytes,
  sha256 `37517e5f…0985b570`). The lookup prefix belongs to stub 1
  (`127.1.0.2`), which received Administrative Shutdown at
  19:21:23.141805Z as part of the engine's natural end of window; the
  1,000 shutdown notifications span 19:21:23.14Z–19:21:27.79Z. At the run
  SHA the runner stopped the management load only after the engine
  process exited, so the load kept probing a fleet that was being torn
  down. The RIB was correctly empty; the operation failed because of
  harness ordering, not daemon behavior. It remains counted — no operation
  or gate was removed from the verdict.
- **Cadence gate.** The 43 missed `/metrics` slots fall in 41 gap
  windows, each inside a distinct reload cycle shortly before that
  reload's barrier-verified completion — about one per reload commit.
  The `scheduled interval drift` entry is flagged by the same skipped
  slots. Metrics completion stayed at 0.9995 of scheduled attempts.
- **readyz.** Both latency breaches (elapsed 52,897 s and 80,294 s) fall
  inside reload cycles 30 and 45, isolated, and within the precommitted
  consecutive-failure policy.
- Daemon log census (WARN; no ERROR): 118,739
  `outbound channel full or closed — marking dirty for resync`, of which
  118,726 fall in the 19:21Z teardown minute and 13 on trip minutes for
  the designated member; 1,005 `TCP connect failed` (daemon start before
  the engine listens, plus the tripped member during each restart
  countdown); 294 `inbound connection from unknown peer, dropping` from
  `127.0.0.1` and `::1` only (147 `doctor` listener-reachability probes ×
  two address families); 6 `max prefix exceeded`, one per deliberate
  breach; one startup notice for the RFC 8212 legacy-omission posture.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- The two reload-42 timeouts are genuine management-correctness
  failures of this daemon build. Their mechanism remains open; the
  retained histogram evidence rules out the specific explanation of one
  long measured flush unit, not every RIB-side cause.
- The cadence failure has the same shape as an earlier unpublished
  full-window run under management load, which failed this gate the same
  way: a 1 s `/metrics` slot is missed while a reload commits. This
  receipt does not change the zero-missed-slot bound.
- Durations and latencies in this receipt are recorded facts of one run
  on a virtualized guest. They make no performance claim.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20260911T184544Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20260911T184544Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20260911T184544Z/run.json` |
| verdict.json | `docs/artifacts/soak/soak-rs-flagship-20260911T184544Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20260911T184544Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20260911T184544Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20260911T184544Z/scenario/` |

Retained off-repo (too large for git; preserved with the original run
directory):

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~62 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~39 MiB |
| full `/metrics` body per sample | `metrics-snapshots.txt.gz` | ~601 MiB |
| last `doctor` bundle | `doctor-bundle.tar.gz` | ~42 KiB |
| runner, build, and generator logs | `soak.log`, `watch.log`, `generator.log`, `daemon-check.log`, `build-*.log` | < 40 KiB |

## Follow-ups

- [ ] Attribute the two management read timeouts in reload 42. The
      zero-failure management-correctness gate is unchanged.
- [x] Drain the management load at the engine's final ready/acknowledge
      barrier, before session shutdown, and gate that ordering in the
      analyzer. Landed after this run; the
      [2026-09-12 run](soak-rs-flagship-24h-2026-09-12.md) exercised it.
- [ ] Decide whether the missed 1 s `/metrics` slot during reload commits
      is a daemon target or a gate-design question. The zero-missed-slot
      bound is unchanged by this receipt.
- [ ] This run does not qualify `50d161bbe`. Qualification requires a
      completed 24-hour run with every applicable gate passing on a
      candidate that carries the reviewed runtime and runner fixes.
