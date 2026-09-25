# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-09-24

**Status:** Complete — verdict: **FAIL**, on the on-host verdict at the run
SHA. No reanalysis; the archived `verdict.json` is the only verdict.
**Run ID:** `tests/soak/runs/soak-rs-flagship-20260923T234654Z`
**Daemon version:** v0.72.0 tag, git SHA
`dcbac54420dc92d5b0218916b3568598cd154cd0`
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA)
**Scenario config hash:**
`5899bb8dd061a3e5f6a16a2de8032aefb4f996641d39792ed4153187c3037cb8`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`066cbb19302e556a45432592534765e703db9d5399f09b686a504b82410a4019`;
`rbgp` and `reloadstall` digests in `binaries.sha256`
**Analyzer and gate revision:** `verdict.json` (sha256
`33ecb7aebb1bd4d014faeab5ed8b2d1a316ed94dea5c0ff8278922c085e75927`),
written on the soak host by `tests/soak/analyze-soak-rs-flagship.py` at the
run SHA (analyzer sha256
`fa53868bfa6a4f7ac3eb9be052f88991a329d12a3f4920556ac278293cb944f8`, the
same analyzer the [2026-09-21 run](soak-rs-flagship-24h-2026-09-21.md) used)
against `docs/soaks/soak-acceptance-gates.md` at the run SHA. Neither file,
nor the runner or management-load driver, changed between the run SHA and
the commit publishing this receipt.
**Date:** 2026-09-23T23:46:54Z runner start (build); sampling
2026-09-24T00:00:54Z → management load ended 2026-09-25T00:23:49.78Z, with
the engine's first Administrative Shutdown 0.14 s later (87,775 s =
24 h 22 m 55 s measured window; the serialized trip windows extend the
86,400 s target)

## Verdict

**FAIL on one gate: management-load correctness (`management_failures`).**

One of 17,556 `rbgp --json policy stats --direction both` attempts exited 1
with no output, 2,206 ms after it started at 2026-09-24T14:42:34.54Z, inside
reload 30. The daemon ended that RPC itself: its audit record for the call
reports `handler_deadline_exceeded`, with the export stage complete in
597 ms and the import stage returning `DeadlineExceeded` after 1,471 ms
against the 1,401 ms left of the RPC's shared 2 s deadline. It was not a
client timeout, a refused connection, or an `UNAVAILABLE` response. The gate
requires zero non-`ok` results and allows no retry, so this one expired read
fails the run.

The other 19 analyzer gates pass: 48 of 48 SIGHUP reloads barrier-verified
complete, 6 of 6 max-prefix trip chains with exact breach and flap
accounting, the session floor on all 2926 samples, one isolated readiness
latency breach inside the consecutive-breach policy (in reload 36, not the
same event), peak RSS 735.2 MB against a 3072 MB ceiling, late-window RSS
slope −0.925 MB/h against 10 MB/h, one missed 1 s `/metrics` slot inside a
reload window, zero daemon `ERROR` records, and zero abort records. Of
140,590 management operations, 140,589 returned `ok`.

**Classification:** a recurrence of the known residual operator-read
deadline behaviour, not a new defect class and not a harness defect. The
daemon applied the documented 2 s policy-stats deadline and returned an
honest all-or-error result while it committed a reload. Under the
[operator read path decision (ADR-0132)](../adr/0132-operator-read-path.md),
route work keeps priority and a read that lands in a reload commit gets its
deadline, not priority. The same import-stage expiry inside a reload commit
failed the unpublished 2026-09-18 run on the v0.70.2 release commit, and the
[known issue](../reference/known-issues.md) for fleet policy statistics
during reloads remains open for exactly this residual. This receipt changes
no gate and does not reclassify the failure: v0.72.0 is not qualified by a
passing flagship soak.

## Release relationship

v0.72.0 (`dcbac54420dc92d5b0218916b3568598cd154cd0`) was tagged on
2026-09-23T21:43Z; this run started on the tagged commit about two hours
later. It covers the v0.72.0 tag and nothing after it. The
[2026-09-21 run](soak-rs-flagship-24h-2026-09-21.md) on the v0.71.0 tag
remains the most recent passing flagship receipt, and it covers only
v0.71.0. Between the two tags, the policy-service changes touched mutation
settlement deadlines, and the shared actor-read helpers gained not-found
handling for unknown peers; no change targeted policy-statistics
collection. The two runs still differ in daemon revision as well as in
run. Timing figures from this guest are diagnostic, not performance
claims.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,766 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2926 |

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete, 9–12 s from issue to completion; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 118,891–119,698 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,591 scheduled | 140,590 completed, 140,589 `ok` | metrics 87,775 of 87,776; neighbor and rib_prefix 17,556 of 17,556 each; policy_stats 17,556 of 17,556, one of them the expired read; doctor 147 of 147 |

## Gates — measured vs precommitted

Bounds quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
the run SHA; measured values from `verdict.json`. Analyzer gate keys are
shown in parentheses.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2926 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** |
| Reload accounting exact (`reload_accounting`) | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** |
| Trip accounting exact (`trip_accounting`) | executed == planned; full per-cycle evidence chain; zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** |
| Exceeded-counter exact (`exceeded_exact`) | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == executed trips | 6 == 6 | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 735.2 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | −0.9250 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 5,609,559,548 | **PASS** |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 0 status failures, 1 latency failure (369.9 ms at elapsed 63,884 s), longest consecutive 1; 0 scrape failures, 0 observation gaps | **PASS** |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start ≤ measured-window end ≤ stop request ≤ load end ≤ engine release; load end precedes the first received Administrative Shutdown | ordering held, including last operation ≤ load end ≤ engine release; load end (2026-09-25T00:23:49.78Z) precedes the first Administrative Shutdown (00:23:49.92Z) | **PASS** |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,775; neighbor 17,556; policy_stats 17,556; rib_prefix 17,556; doctor 147 | **PASS** |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.99999; every other operation 1.0 | **PASS** |
| Management-load cadence (`management_cadence`) | every missed slot inside a reload window `[issued − 2 s, complete + 2 s]`; at most 2 per window per operation; limit 2 | metrics 1 missed, in reload 48's window, 0 outside; neighbor, policy_stats, rib_prefix, doctor 0 missed; 0 defects | **PASS** |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | **1**: `policy_stats`, result `cli_exit`, exit 1 | **FAIL** |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 147 attempts, 0 failures | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 77,162 records, 0 `ERROR`, 0 defects | **PASS** |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2926 | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

19 / 20 gates pass. Analyzer verdict: `fail` (`verdict.json` archived
below).

## Root cause of the failed read

Sources: the load generator's operation record in
`management-plane-load.jsonl`, the daemon's gRPC authorization audit and
reload records in `rustbgpd.log` (both retained off-repo), `cycles.log`,
and `reloadstall.log`.

**What the client saw.** The operation record is line 84,735 of
`management-plane-load.jsonl`:

```json
{"bytes":0,"completed_monotonic":324582.362618,"duration_ms":2205.918,"exit":1,"operation":"policy_stats","record":"operation","result":"cli_exit","scheduled_monotonic":324580.156176,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","started_monotonic":324580.1567}
```

`rbgp` exited 1 with an empty stdout (the SHA-256 is that of zero bytes).
The driver discards the child's stderr, so the CLI's own error text was not
kept. The terminal summary's anchor (`completed_unix` 1790295829.778 at
monotonic 359455.391) places the start at 2026-09-24T14:42:34.54Z and the
exit at 14:42:36.75Z. The anchor is consistent with the audit records of
the three reads scheduled in the same slot: each daemon audit timestamp
precedes the matching client completion by 40–170 ms. The attempt ended
well inside the driver's 5 s timeout (so the result is `cli_exit`, not
`timeout`) and the CLI's 30 s read bound. Exit 1 is `rbgp`'s documented
code for a connection, daemon, or runtime failure.

**What the daemon did.** One audit record answers the rest. It is the only
record of the run whose result is not `handler_ok` (54,143 others are):

```json
{"timestamp":"2026-09-24T14:42:36.693748Z","level":"INFO","fields":{"message":"gRPC authorization audit decision","path":"/rustbgpd.v1.PolicyService/GetPolicyStats","service":"rustbgpd.v1.PolicyService","method":"GetPolicyStats","tier":"sensitive_read","known_method":true,"result":"handler_deadline_exceeded","listener":"unix:///tmp/rsfs.QxG5mZ/grpc.sock","access_mode":"read_write","max_tier":"operator_only","authn":"uds_owner","role":"operator","principal":"local-operator","request_summary":"stage=export elapsed_ms=597 budget_ms=1999 rpc_elapsed_ms=598 code=Ok; stage=import elapsed_ms=1471 budget_ms=1401 rpc_elapsed_ms=2070 code=DeadlineExceeded"},"target":"grpc_authz"}
```

The request was authenticated and authorized, and it reached the handler.
The export stage (typed RIB term hits) returned in 597 ms. The import stage
(installed import counters, per
[ADR-0133](../adr/0133-installed-import-counter-reads.md), collected from
the 1,000 sessions under the remainder of the same deadline) then ran out of its 1,401 ms and returned
`DeadlineExceeded`. The handler replied 2,070 ms after the RPC started,
70 ms past the nominal aggregate deadline. The daemon therefore returned
`DEADLINE_EXCEEDED`: this was not `UNAVAILABLE` during reload, a connection
failure, or a client-side timeout.

**Where it landed.** Reload 30's daemon records, on the same clock:

| UTC (2026-09-24) | Event |
|------------------|-------|
| 14:42:29.433 | SIGHUP received (`cycles.log`: `reload 30 issued` 14:42:30Z) |
| 14:42:29.634 | 1,000-member export-policy cohort partitioned |
| 14:42:33.208 | Cohort destination prestage round trip complete, 3,571 ms |
| 14:42:33.236 | Session hot-apply 1000/1000 |
| 14:42:34.54 | `policy stats`, `neighbor`, `rib_prefix`, and `/metrics` reads start in one schedule slot |
| 14:42:34.936 | RIB export-policy transition committed, 1,651 ms |
| ~14:42:35.22 | Export stage done; import collection begins (audit stage timings) |
| 14:42:35.458 | Partitioned policy snapshot committed, 5,823 ms after partitioning; reload generation applied |
| 14:42:35.654 | Reload complete; settlement enters `settling_rollback` |
| 14:42:35.834 | Config persister adopts the SIGHUP snapshot |
| 14:42:36.694 | `GetPolicyStats` import stage `DeadlineExceeded` (the audit record above) |
| 14:42:36.75 | `rbgp` exits 1 |
| 14:42:36.793 | Settlement settled |
| 14:42:39.593 | Next `policy stats` read: `handler_ok` |
| 14:42:40 | `cycles.log`: `reload 30 complete` |

The read collected import counters while all 1,000 sessions were re-sending
their re-exported routes after the export-policy commit (`reloadstall.log`
reload 30: completion p50 8.30 s, max 9.41 s) and while the settlement and
persistence steps ran. The neighbor read that started in the same
millisecond took 1,512 ms and succeeded; it was the run's slowest neighbor
read. The records do not attribute the 1,471 ms further inside the import
path (admission, per-session collection, or runtime scheduling). That is
the open qualification question, not something this run can settle.

**Classification.** The daemon behaved as documented. Policy statistics
share one absolute 2 s deadline across stages
([ADR-0132](../adr/0132-operator-read-path.md#budget-boundaries),
`POLICY_STATS_AGGREGATE_TIMEOUT`), results are all-or-error, and route
work keeps priority over operator reads during a reload commit. The
failure has the same signature as the unpublished v0.70.2 run on
2026-09-18: one `policy stats` read expired in its import stage (export
394 ms, import 1,607 ms against a 1,604 ms remainder) during a reload's
generation commit. It is the residual that the open
[known issue](../reference/known-issues.md) "Fleet policy stats can time
out during reload" describes: fleet calls "can return `DEADLINE_EXCEEDED`
during reload activity, with no partial rows", and "remaining import-read
latency can still arise in peer-manager selection, publication collection,
or response delivery". It is recorded against that existing work rather
than as a new defect. It is not a harness defect: the driver recorded the attempt
exactly, and the gate counted it as designed. The reload-window allowance
covers missed schedule slots, not expired reads, and this receipt does not
extend it.

## Analysis notes

Observed:

- Sample accounting (`samples.csv`): 2926 rows at a 30 s cadence through
  elapsed 87,766 s, with no scrape failures and no observation gaps.
- RSS trajectory (`samples.csv`): 494.5 MB at the first sample; 5th–95th
  percentile 499.8–560.5 MB; the 735.2 MB peak at 2026-09-24T23:49:40Z,
  inside reload 48 (issued 23:49:36Z, complete 23:49:48Z); late-window
  slope −0.925 MB/h. The intern gauge (`bgp_rib_attr_intern_global_size`)
  stayed at 999–1000 entries.
- **Readiness breach** (`verdict.json` `readyz`): one sample,
  2026-09-24T17:45:39Z (elapsed 63,884 s), returned HTTP 200 in 369.9 ms
  against the 250 ms limit. It fell in reload 36 (issued 17:45:33Z, complete
  17:45:43Z), in the second after that reload's RIB export-policy
  transition committed (17:45:38.05Z) and while its settlement finished
  (settled 17:45:39.20Z). It is a separate event from
  the failed read, three hours later, but it comes from the same reload-commit
  pressure. The next-highest readiness latencies were 246.7, 220.9, and
  165.4 ms; every response was HTTP 200. The gate passed under its
  consecutive-breach rule.
- **Cadence detail** (`verdict.json`
  `management_cadence.value.operations.metrics.per_reload`): one missed
  `/metrics` slot, in reload 48's window. The neighbor, policy_stats,
  rib_prefix, and doctor schedules missed no slot.
- **Management latency**, recomputed from this run's
  `management-plane-load.jsonl` (`duration_ms` of `ok` operation records,
  end-to-end CLI or HTTP time as the load generator measures it; p99 by
  linear interpolation), beside the [2026-09-21 run](soak-rs-flagship-24h-2026-09-21.md)
  on v0.71.0:

  | Operation | Scheduled / `ok` | p50 | p99 | max | v0.71.0 run p50 / max |
  |-----------|------------------|-----|-----|-----|-----------------------|
  | metrics (1 s) | 87,776 / 87,775 (1 missed slot) | 173.7 ms | 225.1 ms | 1,166.9 ms | 175.5 / 1,528.0 ms (6 missed slots) |
  | neighbor (5 s) | 17,556 / 17,556 | 84.1 ms | 243.4 ms | 1,512.4 ms | 85.9 / 1,804.7 ms |
  | policy_stats (5 s) | 17,556 / 17,555 (1 expired) | 93.3 ms | 279.9 ms | 1,852.1 ms | 127.1 / 1,969.4 ms |
  | rib_prefix (5 s) | 17,556 / 17,556 | 70.0 ms | 226.0 ms | 833.6 ms | 71.4 / 869.1 ms |
  | doctor (600 s) | 147 / 147 | 337.4 ms | 525.0 ms | 529.9 ms | 420.9 / 523.8 ms |

  No successful operation exceeded 2 s. The six slowest successful
  `policy stats` reads (1,349–1,852 ms) each started inside a reload
  window: reloads 17, 26, 27, 28, 29, and 31, with the slowest in reload 31
  (started 15:12:44.54Z, issued 15:12:40Z, complete 15:12:50Z). The slowest
  `/metrics` scrape falls in reload 48 and the slowest RIB lookup in
  reload 17. Lower p50s and maxima than the v0.71.0 run do not offset the
  expired read: the gate counts results, and the worst case now crosses the
  deadline once in 17,556 attempts. The two runs differ in daemon commit as
  well as run, so the table records observations, not a measured change.
- Daemon log census (`verdict.json` `daemon_log.value.warnings_by_message`):
  77,162 records, 0 `ERROR`, 307 `WARN`:
  - 294 `inbound connection from unknown peer, dropping`: the 147 `doctor`
    listener-reachability probes, each over two address families. Expected.
  - 6 `TCP connect failed` for the designated member, one at each trip's
    timed restart. Expected.
  - 6 `max prefix exceeded`, one per deliberate breach.
  - 1 startup notice for the RFC 8212 legacy-omission posture of the
    scenario configuration, also reported by the pre-start
    `--check --strict` (`daemon-check.log`).
- Engine (`reloadstall.log`): final `sessions_up 1000/1000 parse_errors=0`.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- Session, reload, trip, memory, readiness, and log behaviour at v0.72.0
  matches the v0.71.0 run with no new failure class. The one failure is
  the operator-read deadline under reload-commit pressure that the v0.70.2
  run also showed and the v0.71.0 run passed by 31 ms. Three runs on this
  host shape at three revisions now give one pass with a thin margin and
  two single-read expiries. That is not evidence of a regression, and it is
  not evidence that the residual is resolved.
- The gate stays as written. A read that expires is a failed operator
  command, and retrying it would not turn this sample into a pass. The
  deadline and route-work priority stay unchanged. Whether policy-stats
  collection can meet its budget in the post-commit window belongs to the
  isolated qualification that the known issue describes, not to a gate
  change here.
- Durations and latencies in this receipt are recorded facts of one run
  on a virtualized guest. They make no performance claim, and the receipt
  covers this shape at the v0.72.0 tag on this host, nothing wider.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`, every other file byte-for-byte
from the run directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20260923T234654Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20260923T234654Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20260923T234654Z/run.json` |
| verdict.json (on-host, run-SHA analyzer) | `docs/artifacts/soak/soak-rs-flagship-20260923T234654Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20260923T234654Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20260923T234654Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20260923T234654Z/scenario/` |

Retained off-repo (too large for git, or carrying host paths; preserved
with the original run directory). The analyzer needs the daemon log and
management-load evidence, so the verdict cannot be recomputed from the
repo-archived subset alone. The two records quoted under the root cause
are copied verbatim from the retained files:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~37 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~39 MiB |
| full `/metrics` body per sample | `metrics-snapshots.txt.gz` | ~606 MiB |
| last `doctor` bundle | `doctor-bundle.tar.gz` | ~42 KiB |
| runner, build, and generator logs; final barrier markers | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `engine-finish/` | < 10 KiB |
