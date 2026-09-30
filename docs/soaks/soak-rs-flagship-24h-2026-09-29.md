# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-09-29

**Status:** Complete — verdict: **FAIL**, on the on-host verdict at the
v0.73.0 tag. A local rerun of the same analyzer over the retained run
directory reproduced `verdict.json` byte for byte; the archived
`verdict.json` is the verdict.
**Run ID:** `tests/soak/runs/soak-rs-flagship-20260929T094109Z`
**Daemon version:** v0.73.0 tag, git SHA
`335676078965ae5a7d24273821dab12da79222d2`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA)
**Scenario config hash:**
`6219a2b578074548470a2bb8b454cfb01d10c3b28f3cc6561d878deadaa1d348`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`000b1385b5eb38ee50bddf51edd0727f526bca30c7ab789b67cf0e7c514ece71`;
`rbgp` and `reloadstall` digests in `binaries.sha256`
**Analyzer and gate revision:** `verdict.json` (sha256
`5ac48d05ce391eae78172c21b2663c5211aae8735ae7a62780ae0e9e509e7db2`),
written on the soak host by `tests/soak/analyze-soak-rs-flagship.py` at the
run SHA (analyzer sha256
`8394835cbc418fd53e79b365c89705016f7eaec237da59657c8ed480b933b11b`)
against `docs/soaks/soak-acceptance-gates.md` at the run SHA. The analyzer
differs from the one the [2026-09-26 run](soak-rs-flagship-24h-2026-09-26.md)
used only in keeping a bounded stderr excerpt on failed management reads.
Nothing under `tests/soak/` changed between the v0.73.0 tag and the commit
publishing this receipt; the gate document changed only in two external
link anchors.
**Date:** 2026-09-29T09:41:09Z runner start (build); sampling
2026-09-29T09:41:21Z → management load ended 2026-09-30T10:02:34.18Z, with
the engine's first Administrative Shutdown 0.18 s later (87,673 s =
24 h 21 m 13 s measured window; the serialized trip windows extend the
86,400 s target)

## Verdict

**FAIL on two gates that record the same event: the doctor configuration
assertion (`management_doctor`) and management-load correctness
(`management_failures`).**

One of the 147 `rbgp --json doctor` attempts exited 2 with a red check. The
management-load driver accepts exit 2 as a doctor report, parses it, and
classified it `doctor_check_failed`, which by the driver's rule means at
least one check outside the excluded per-peer `peer.*` checks reported
`fail`. That attempt was scheduled at 2026-09-29T21:51:21.38Z and took
997.96 ms; its stderr was empty. The other 146 attempts reported `ok`, and
every other management operation in the run returned `ok`.

The failing check is not identified. The driver records only the byte
count and sha256 of each doctor report, and the retained
`doctor-bundle.tar.gz` is the last attempt's, not this one's. No daemon
defect was found in the retained evidence, but the cause is not recorded,
so the result stays red. This receipt changes no gate and does not
reclassify the failure: v0.73.0 is not qualified by a passing route-server
flagship soak.

The other 18 analyzer gates pass: 48 of 48 SIGHUP reloads barrier-verified
complete, 6 of 6 max-prefix trip chains with exact breach and flap
accounting, the session floor on all 2923 samples, two isolated readiness
HTTP 503 samples inside the consecutive-breach policy, peak RSS 726.5 MB
against a 3072 MB ceiling, late-window RSS slope +0.743 MB/h against
10 MB/h, 48 missed 1 s `/metrics` slots all inside reload windows, zero
daemon `ERROR` records, and zero abort records.

## The failing doctor run

The management load started at monotonic 738,506.99 s
(2026-09-29T09:41:21.38Z, anchored through the terminal summary's UTC
timestamp) and scheduled `doctor` every 600 s. The failing attempt was the
74th, scheduled at monotonic 782,306.99 s, 43,800 s after load start:
2026-09-29T21:51:21.38Z. It completed at 21:51:22.38Z.

`cycles.log` places it inside two injection windows at once:

| Event | Time (UTC) | Relation to the doctor run |
|-------|------------|----------------------------|
| Trip 3 `announce_over`, `torn_down` | 21:49:15Z | Designated member `127.1.0.1` breached its limit and was torn down |
| Trip 3 `reestablished`, `reannounced`; reload 25 `issued` | 21:51:16Z | 5 s before the doctor run |
| Trip 3 `complete` (`usage=400 limit=450 headroom=50`) | 21:51:17Z | 4 s before |
| Doctor scheduled and started | 21:51:21.38Z | — |
| Reload 25 `complete` | 21:51:25Z | 3 s after the doctor run completed |

The analyzer's trip-3 window (announce − 30 s to re-establishment + 30 s)
spans 21:48:45Z–21:51:46Z, and the reload-25 cadence window (issued − 2 s
to complete + 2 s) spans 21:51:14Z–21:51:27Z. This is the only one of the
147 doctor runs that falls inside either kind of window.

Two recorded details set this run apart from the other 146, without
explaining it:

- **Duration:** 997.96 ms, against 373.9 ms median and 521.8 ms maximum for
  the 146 `ok` runs.
- **Report size:** 266,930 bytes, the smallest of the 147 (range
  266,930–268,007 bytes).

The daemon log records this run's two listener-reachability probes at
21:51:22.29Z as `inbound connection from unknown peer, dropping`, one per
address family, as it does for every doctor run (294 records for 147 runs).
The only other WARN between trip 3's teardown and reload 25's completion is
the designated member's expected `TCP connect failed` at its timed restart
(21:51:15.73Z). The daemon logged no `ERROR` in the run.

Follow-up work, tracked separately: keep the failing doctor report (or at
least the names of red checks) in the management-load evidence, and
reproduce a doctor run inside a trip re-establishment and reload window.

## Release relationship

v0.73.0 (`335676078965ae5a7d24273821dab12da79222d2`) was tagged on
2026-09-28T00:45Z; this run started on the tagged commit about 33 hours
later. It covers the v0.73.0 tag and nothing after it. The tag is 79
commits after the untagged main SHA `292c32b39` that passed on
[2026-09-26](soak-rs-flagship-24h-2026-09-26.md). The
[2026-09-21 run](soak-rs-flagship-24h-2026-09-21.md) on the v0.71.0 tag
remains the most recent passing route-server flagship receipt on a tag. The
[route-reflector flagship](soak-rr-flagship-24h-2026-09-28.md) passed on the
same v0.73.0 tag; that is a separate scenario and does not qualify the
route-server shape. Timing figures from this guest are diagnostic, not
performance claims.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total, IPv4 unicast only), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Daemon, engine, and management-load driver share the guest's vCPUs. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,671 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2923 |

The shape, cadence, and management-load parameters match the
2026-09-26 run; `run.json` differs only in run ID, git SHA, and monotonic
timestamps, the scenario configuration only in its per-run temporary
runtime directory, and the three policy files not at all.

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete, 7–10 s from issue to completion; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 118,873–119,773 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,425 scheduled | 140,377 completed, 140,376 `ok` | metrics 87,625 of 87,673 (48 missed slots); neighbor, policy_stats and rib_prefix 17,535 of 17,535 each; doctor 147 of 147, one `doctor_check_failed` |

## Gates — measured vs precommitted

Bounds quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
the run SHA; measured values from `verdict.json`. Analyzer gate keys are
shown in parentheses.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2923 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** |
| Reload accounting exact (`reload_accounting`) | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** |
| Trip accounting exact (`trip_accounting`) | executed == planned; full per-cycle evidence chain; zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** |
| Exceeded-counter exact (`exceeded_exact`) | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == executed trips | 6 == 6 | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 726.5 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | +0.7431 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 4,336,533,073 | **PASS** |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 2 status failures (HTTP 503 in 597.6 ms at elapsed 5461 s; HTTP 503 in 271.5 ms at elapsed 25,475 s), 0 latency failures, longest consecutive 1; 0 scrape failures, 0 observation gaps | **PASS** |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start ≤ measured-window end ≤ stop request ≤ load end ≤ engine release; load end precedes the first received Administrative Shutdown | ordering held, including last operation ≤ load end ≤ engine release; load end (2026-09-30T10:02:34.18Z) precedes the first Administrative Shutdown (10:02:34.36Z) | **PASS** |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,625; neighbor 17,535; policy_stats 17,535; rib_prefix 17,535; doctor 147 | **PASS** |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.99945; every other operation 1.0 | **PASS** |
| Management-load cadence (`management_cadence`) | every missed slot inside a reload window `[issued − 2 s, complete + 2 s]`; at most 2 per window per operation; limit 2 | metrics 48 missed across 43 reload windows (2 each in reloads 1, 15, 17, 32 and 45; 1 in each of 38 others), 0 outside; neighbor, policy_stats, rib_prefix, doctor 0 missed; 0 defects | **PASS** |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | 1: `doctor`, `doctor_check_failed`, exit 2, empty stderr | **FAIL** |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 147 attempts, 1 failure (the same record) | **FAIL** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 77,215 records, 0 `ERROR`, 0 defects | **PASS** |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2923 | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

18 / 20 gates pass. Analyzer verdict: `fail` (`verdict.json` archived
below).

## Management-read latency

Recomputed from this run's `management-plane-load.jsonl` (`duration_ms` of
`ok` operation records, end-to-end CLI or HTTP time as the load generator
measures it; p99 by linear interpolation, the same method as the earlier
receipts), beside the [2026-09-26 run](soak-rs-flagship-24h-2026-09-26.md)
on untagged main `292c32b39`:

| Operation | Scheduled / `ok` | p50 | p99 | max | 2026-09-26 run p50 / p99 / max |
|-----------|------------------|-----|-----|-----|--------------------------------|
| metrics (1 s) | 87,673 / 87,625 (48 missed slots) | 166.7 ms | 213.2 ms | 2,421.9 ms | 174.8 / 233.4 / 1,182.1 ms |
| neighbor (5 s) | 17,535 / 17,535 | 221.7 ms | 274.4 ms | 1,906.0 ms | 81.8 / 271.8 / 1,824.9 ms |
| policy_stats (5 s) | 17,535 / 17,535 | 181.6 ms | 240.8 ms | 1,282.2 ms | 57.9 / 238.4 / 1,099.3 ms |
| rib_prefix (5 s) | 17,535 / 17,535 | 166.7 ms | 224.0 ms | 1,647.0 ms | 70.7 / 224.7 / 828.8 ms |
| doctor (600 s) | 147 / 146 (1 `doctor_check_failed`, 997.96 ms) | 373.9 ms | 477.4 ms | 521.8 ms | 336.4 / 522.5 / 529.6 ms |

Every read over 1 s started inside a reload window: 43 `/metrics` scrapes
(five over 2 s, the slowest 2,421.9 ms in reload 1), 10 `neighbor` reads,
3 RIB lookups, and 2 `policy stats` reads. The slowest CLI reads, a
1,906.0 ms `neighbor` read and a 1,647.0 ms RIB lookup, shared one schedule
slot at 2026-09-29T11:12:21.38Z in reload 4. No read reached the 5 s
attempt timeout.

Against the 2026-09-26 run, the p50 of the three 5 s CLI reads is two to
three times higher while their p99 is about the same, and the run missed
48 `/metrics` slots rather than 3. Both runs used the same scenario and
host shape; they differ in daemon revision as well as run. This receipt
does not attribute the difference.

## Analysis notes

Observed:

- Sample accounting (`samples.csv`): 2923 rows at a 30 s cadence through
  elapsed 87,671 s, with no scrape failures and no observation gaps.
- RSS trajectory (`samples.csv`): 489.4 MB at the first sample; 5th–95th
  percentile 513.3–571.6 MB; the 726.5 MB peak at 2026-09-30T07:58:02Z,
  inside reload 45 (issued 07:57:59Z, complete 07:58:09Z); late-window slope
  +0.743 MB/h. The intern gauge (`bgp_rib_attr_intern_global_size`) stayed
  at 999–1000 entries.
- **Readiness breach 1** (`verdict.json` `readyz`): the sample at
  2026-09-29T11:12:23Z (elapsed 5461 s) returned HTTP 503 in 597.6 ms,
  inside reload 4 (issued 11:12:18Z, complete 11:12:26Z). The daemon logged
  `readiness probe failed` with `peer manager probe timed out (200ms
  deadline)` at 11:12:23.15Z.
- **Readiness breach 2**: the sample at 2026-09-29T16:45:57Z (elapsed
  25,475 s) returned HTTP 503 in 271.5 ms, inside reload 15 (issued
  16:45:52Z, complete 16:46:00Z). The daemon logged `readiness probe
  deadline exceeded` at 16:45:56.78Z.
  Both breaches are single samples inside reload windows, the behaviour the
  open [known issue](../reference/known-issues.md) "Reloads can produce
  transient readiness failures" describes. The gate passed under its
  consecutive-breach rule; both stay recorded as evidence under the
  [readiness acceptance policy](soak-acceptance-gates.md#readiness-acceptance-and-kubernetes-probes).
  The next-highest readiness latencies were 178.1 and 153.7 ms.
- **Cadence detail** (`verdict.json`
  `management_cadence.value.operations.metrics.per_reload`): missed
  `/metrics` slots in 43 of 48 reload windows, at most 2 per window; none in
  reloads 2, 14, 16, 35 and 40, and none outside a reload window.
- Daemon log census (`verdict.json` `daemon_log.value.warnings_by_message`):
  77,215 records, 0 `ERROR`, 311 `WARN`:
  - 294 `inbound connection from unknown peer, dropping`: the 147 `doctor`
    listener-reachability probes, each over two address families. Expected.
  - 6 `TCP connect failed` for the designated member, one at each trip's
    timed restart. Expected.
  - 6 `max prefix exceeded`, one per deliberate breach.
  - 1 `readiness probe failed` and 1 `readiness probe deadline exceeded`:
    the two readiness breaches above.
  - 2 `outbound channel full or closed — marking dirty for resync`, at
    2026-09-30T10:02:34.56Z and 10:02:34.59Z, after the engine's first
    Administrative Shutdown (10:02:34.36Z), during run teardown.
  - 1 startup notice for the RFC 8212 legacy-omission posture of the
    scenario configuration, also reported by the pre-start
    `--check --strict` (`daemon-check.log`).
- Engine (`reloadstall.log`): final `sessions_up 1000/1000 parse_errors=0`.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- The red result rests on one doctor report whose failing check was not
  kept. The driver's rule narrows it to a check outside the excluded
  `peer.*` set, and the timing places it in the one doctor run that
  overlapped a trip re-establishment and a reload commit. That coincidence
  is recorded, not treated as a cause: nothing retained in this run names
  the check.
- Session, reload, trip, memory, readiness, and log behaviour matches the
  earlier runs with no new failure class. The gates stay as written.
  Durations and latencies in this receipt are recorded facts of one run on
  a virtualized guest. They make no performance claim, and the receipt
  covers this IPv4-only shape at the v0.73.0 tag on this host, nothing
  wider: no dual-stack flagship soak has run.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`, every other file byte-for-byte
from the run directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20260929T094109Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20260929T094109Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20260929T094109Z/run.json` |
| verdict.json (on-host, run-SHA analyzer) | `docs/artifacts/soak/soak-rs-flagship-20260929T094109Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20260929T094109Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20260929T094109Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20260929T094109Z/scenario/` |

Retained off-repo (too large for git, or carrying host paths; preserved
with the original run directory). The analyzer needs the daemon log and
management-load evidence, so the verdict cannot be recomputed from the
repo-archived subset alone. The doctor-run timing, latency figures, and
log excerpts above are computed from the retained files:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~37 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~39 MiB |
| last `doctor` bundle (not the failing attempt's) | `doctor-bundle.tar.gz` | ~41 KiB |
| runner, build, and generator logs; final barrier markers | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `engine-finish/` | < 10 KiB |
