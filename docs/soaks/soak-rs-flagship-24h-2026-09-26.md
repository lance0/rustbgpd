# Soak Receipt — Route-server flagship (SIGHUP reload + max-prefix trip + management-plane load) 24 h, 2026-09-26

**Status:** Complete — verdict: **PASS**, on the on-host verdict at the run
SHA. No reanalysis; the archived `verdict.json` is the only verdict.
**Run ID:** `tests/soak/runs/soak-rs-flagship-20260926T011146Z`
**Daemon version:** unreleased — untagged main at git SHA
`292c32b39d1c9f8f056a472ed0c6d0a72658e87f` (`v0.72.0-18-g292c32b39`)
(image `rustbgpd:dev` built from this SHA: not applicable — bare-host
run; `rustbgpd`, `rbgp`, and the `reloadstall` engine were built
`--release --locked` at this SHA)
**Scenario config hash:**
`9957684d9499f44d2ecf27711c3e169105dd1c1807a4f49dab11d75e4c57d0e9`
(sha256 of `run.json`; pins duration, cadence, pool sizes, injection and
management-load parameters as executed)
**Executable identities:** `rustbgpd` sha256
`db44704f7d61d3050aa3c80da1fde5147696d7ee05ff80a6c147b465755dfef2`;
`rbgp` and `reloadstall` digests in `binaries.sha256`
**Analyzer and gate revision:** `verdict.json` (sha256
`5a01a09102f95fa2e73c5123d112cce3f87e825121cb6d3741ca5c6e5380f722`),
written on the soak host by `tests/soak/analyze-soak-rs-flagship.py` at the
run SHA (analyzer sha256
`fa53868bfa6a4f7ac3eb9be052f88991a329d12a3f4920556ac278293cb944f8`, the
same analyzer the [2026-09-21](soak-rs-flagship-24h-2026-09-21.md) and
[2026-09-24](soak-rs-flagship-24h-2026-09-24.md) runs used) against
`docs/soaks/soak-acceptance-gates.md` at the run SHA. Neither file, nor
anything else under `tests/soak/` (runner, management-load driver, daemon-log
checker), changed between the v0.72.0 tag, the run SHA, and the commit
publishing this receipt.
**Date:** 2026-09-26T01:11:46Z runner start (build); sampling
2026-09-26T01:25:25Z → management load ended 2026-09-27T01:47:56.22Z, with
the engine's first Administrative Shutdown 0.21 s later (87,751 s =
24 h 22 m 31 s measured window; the serialized trip windows extend the
86,400 s target)

## Verdict

**PASS on all 20 analyzer gates**, including management-load correctness
(`management_failures`) with the gate unchanged.

All 140,548 management operations returned `ok`, among them all 17,551
`rbgp --json policy stats --direction both` attempts. The slowest of those
took 1,099.3 ms end to end. 48 of 48 SIGHUP reloads were barrier-verified
complete, and 6 of 6 max-prefix trip chains closed with exact breach and
flap accounting. The session floor held on all 2925 samples. Peak RSS was
756.4 MB against a 3072 MB ceiling, and the late-window RSS slope was
+0.223 MB/h against 10 MB/h. The daemon logged zero `ERROR` records, and
`cycles.log` holds zero abort records. Two gates passed with retained
evidence rather than a clean zero:

- **Readiness:** two isolated breaches, each a single sample, inside the
  consecutive-breach policy (limit 3). One was an HTTP 503 at elapsed
  21,876 s in reload 13; the other was HTTP 200 in 259.2 ms against the
  250 ms limit at elapsed 85,706 s in reload 48.
- **Cadence:** 3 missed 1 s `/metrics` slots, one each in the windows of
  reloads 18, 34 and 36, none outside a reload window (limit 2 per window).

This is the first route-server flagship run on a build with owner-published
counter reads ([ADR-0136](../adr/0136-owner-published-counter-reads.md)).
It meets that record's soak qualification condition: the flagship soak
passes `management_failures` with the gate unchanged.

## Release relationship

The run SHA is untagged main, 18 commits after the v0.72.0 tag. Those
commits include the ADR-0136 record, the isolated policy-stats reload cell,
self-describing counter instances, the import sub-stage audit timing, and
the import and export roster reads (#2714, #2715). The receipt covers this
SHA and nothing else: it qualifies no release tag. A later tag needs its own
run, or a recorded decision to ship without one. The
[2026-09-21 run](soak-rs-flagship-24h-2026-09-21.md) remains the most recent
passing flagship receipt on a tag (v0.71.0), and the
[2026-09-24 run](soak-rs-flagship-24h-2026-09-24.md) on the v0.72.0 tag
failed management correctness on one expired read. Timing figures from
this guest are diagnostic, not performance claims.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 10 — Route-server flagship: 1000 real eBGP route-server-client sessions × 400 routes each (400,000 total, IPv4 unicast only), the `bench/scale/reloadstall` engine's steady churn running throughout, serialized SIGHUP-reload and max-prefix-trip injections, and mandatory management-plane load |
| Harness | `tests/soak/run-soak-rs-flagship.sh` |
| Analyzer | `tests/soak/analyze-soak-rs-flagship.py` |
| Topology | Bare-host daemon + `bench/scale/reloadstall` engine over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM; `nofile_soft = 65536`. Daemon, engine, and management-load driver share the guest's vCPUs. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 87,746 s |
| Sample interval | 30 s |
| Injection cadence | SIGHUP policy-file reload every 1800 s (48 planned); max-prefix trip every 14,400 s on the designated member `127.1.0.1` (6 planned, every 8th reload cycle; `max_prefixes = 450`, `max_prefix_restart_seconds = 120`) |
| Management-plane load | `/metrics` every 1 s; `rbgp --json neighbor`, `rbgp --json policy stats --direction both`, and an exact RIB lookup of `20.1.144.0/24` every 5 s; `rbgp --json doctor` every 600 s; 5 s attempt timeout, no retry |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2925 |

The shape, cadence, and management-load parameters match the
2026-09-24 run; `run.json` differs only in run ID, git SHA, and monotonic
timestamps, and the scenario configuration only in its per-run temporary
runtime directory.

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| SIGHUP policy-file reload (generation-marker completion barrier) | 48 | 48 | Every reload barrier-verified complete, 8–13 s from issue to completion; zero session flaps attributable to reloads |
| Max-prefix trip → hold-down → timed restart (designated member) | 6 | 6 | Full evidence chain on every cycle; observed hold-down countdown 118,796–119,727 ms of the 120,000 ms window (`action=restart`); post-recovery `usage=400 limit=450 headroom=50` each time |
| Management-plane operations | 140,551 scheduled | 140,548 completed, 140,548 `ok` | metrics 87,748 of 87,751 (3 missed slots); neighbor, policy_stats and rib_prefix 17,551 of 17,551 each; doctor 147 of 147 |

## Gates — measured vs precommitted

Bounds quoted from `docs/soaks/soak-acceptance-gates.md` scenario 10 at
the run SHA; measured values from `verdict.json`. Analyzer gate keys are
shown in parentheses.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Session floor (`session_floor`) | `established == 1000` on every post-warmup sample, except exactly `999` inside a declared trip window (designated member only) | 0 violations / 2925 samples; `999` on exactly 24 samples, all inside the six declared trip windows | **PASS** |
| Reload accounting exact (`reload_accounting`) | issued == barrier-verified complete; complete ≥ 0.9 × planned | 48 issued == 48 complete == 48 planned | **PASS** |
| Trip accounting exact (`trip_accounting`) | executed == planned; full per-cycle evidence chain; zero unexpected latch-offs | 6 executed == 6 planned; zero chain defects | **PASS** |
| Exceeded-counter exact (`exceeded_exact`) | final `bgp_max_prefix_exceeded_total` == executed trips | 6 == 6 | **PASS** |
| Session-flap budget exact (`flap_budget`) | flap delta over the run == executed trips | 6 == 6 | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 3072 MB | 756.4 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % (window ≥ 1 h, evaluated) | +0.2234 MB/h | **PASS** |
| Intern-table late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h over the same window | −0.0034 entries/h | **PASS** |
| Counter monotonicity (`msgs_sent_monotone`) | `bgp_messages_sent_total` never decreases between samples | 0 breaks; final 5,609,569,540 | **PASS** |
| readyz availability (`readyz`) | Fewer than 3 consecutive samples miss HTTP 200 within 250 ms; any scrape failure or observation gap fails | 30 s sample interval; limits 250 ms and 3 consecutive; 1 status failure (HTTP 503, 276.5 ms, elapsed 21,876 s), 1 latency failure (HTTP 200, 259.2 ms, elapsed 85,706 s), longest consecutive 1; 0 scrape failures, 0 observation gaps | **PASS** |
| Management-load evidence (`management_evidence`) | terminal summary is the final complete JSONL record; its counts and configuration match the observed records plus `run.json` | 0 schema errors, 0 count mismatches | **PASS** |
| Management-load lifetime (`management_lifetime`) | load start ≤ measured-window start ≤ measured-window end ≤ stop request ≤ load end ≤ engine release; load end precedes the first received Administrative Shutdown | ordering held, including last operation ≤ load end ≤ engine release; load end (2026-09-27T01:47:56.22Z) precedes the first Administrative Shutdown (01:47:56.44Z) | **PASS** |
| Management-load operations present (`management_operations`) | all five operations present | metrics 87,748; neighbor 17,551; policy_stats 17,551; rib_prefix 17,551; doctor 147 | **PASS** |
| Management-load completion (`management_completion`) | each operation completes ≥ 90 % of its scheduled attempts | metrics 0.99997; every other operation 1.0 | **PASS** |
| Management-load cadence (`management_cadence`) | every missed slot inside a reload window `[issued − 2 s, complete + 2 s]`; at most 2 per window per operation; limit 2 | metrics 3 missed, one each in reloads 18, 34 and 36, 0 outside; neighbor, policy_stats, rib_prefix, doctor 0 missed; 0 defects | **PASS** |
| Management-load correctness (`management_failures`) | zero non-`ok` results and zero invalid `ok` results | 0 | **PASS** |
| Doctor configuration assertion (`management_doctor`) | every `doctor` attempt reports `ok`; at least one attempt | 147 attempts, 0 failures | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed captured log; every `ERROR` fails | 77,940 records, 0 `ERROR`, 0 defects | **PASS** |
| Minimum sample count (`min_samples`) | ≥ 2592 (0.9 × 86,400 ÷ 30) | 2925 | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines in `cycles.log` | 0 | **PASS** |

20 / 20 gates pass. Analyzer verdict: `pass` (`verdict.json` archived
below).

## Management-read latency

Recomputed from this run's `management-plane-load.jsonl` (`duration_ms` of
`ok` operation records, end-to-end CLI or HTTP time as the load generator
measures it; p99 by linear interpolation, the same method as the earlier
receipts), beside the [2026-09-24 run](soak-rs-flagship-24h-2026-09-24.md)
on v0.72.0 and the [2026-09-21 run](soak-rs-flagship-24h-2026-09-21.md) on
v0.71.0:

| Operation | Scheduled / `ok` | p50 | p99 | max | v0.72.0 run p50 / p99 / max | v0.71.0 run p50 / max |
|-----------|------------------|-----|-----|-----|-----------------------------|-----------------------|
| metrics (1 s) | 87,751 / 87,748 (3 missed slots) | 174.8 ms | 233.4 ms | 1,182.1 ms | 173.7 / 225.1 / 1,166.9 ms | 175.5 / 1,528.0 ms |
| neighbor (5 s) | 17,551 / 17,551 | 81.8 ms | 271.8 ms | 1,824.9 ms | 84.1 / 243.4 / 1,512.4 ms | 85.9 / 1,804.7 ms |
| policy_stats (5 s) | 17,551 / 17,551 | 57.9 ms | 238.4 ms | 1,099.3 ms | 93.3 / 279.9 / 1,852.1 ms (plus 1 expired at 2,206 ms) | 127.1 / 1,969.4 ms |
| rib_prefix (5 s) | 17,551 / 17,551 | 70.7 ms | 224.7 ms | 828.8 ms | 70.0 / 226.0 / 833.6 ms | 71.4 / 869.1 ms |
| doctor (600 s) | 147 / 147 | 336.4 ms | 522.5 ms | 529.6 ms | 337.4 / 525.0 / 529.9 ms | 420.9 / 523.8 ms |

No operation exceeded 2 s. One `policy stats` read exceeded 1 s: the
1,099.3 ms read started at 2026-09-26T14:36:20.52Z in reload 27 (issued
14:36:16Z, complete 14:36:25Z). The next two, 886.0 ms and 781.3 ms, also
fell inside reload windows (reloads 12 and 36); every other read took
under 325 ms.

The daemon's `grpc_authz` audit records for the 17,551 `GetPolicyStats`
calls all report `handler_ok`, with `publications=1000/1000` and `yields=0`
on every import stage. Their staged `rpc_elapsed_ms` (export, import, and
dataset stages together) had a median of 3 ms and a maximum of 25 ms. The
audit record for the 1,099.3 ms read reports 16 ms, logged 139 ms after the
client started the call. The rest of its end-to-end time lies outside the
recorded handler stages: CLI process start and connection, response
encoding and delivery (about 0.87 MB of JSON), and scheduling on the shared
guest. This run does not attribute it further.

The [isolated reload cell](../perf/artifacts/policy-stats-owner-published-2026-09-26/README.md)
on the same SHA measured a slowest end-to-end call of 229 ms; this soak's
slowest was 1,099.3 ms, almost five times as long. The two are not the same
measurement environment: the cell ran the daemon on two dedicated cores
with the generator and probes on separate cores, while this soak shares an
8 vCPU virtualized guest between the daemon, the churn engine, and the
management load. The difference is recorded, not explained away: the cell
result is not evidence of the soak host's tail, and this soak's tail is the
figure that applies to this host.

The `neighbor` read is not in ADR-0136's scope and still goes through the
peer manager. It is now the slowest CLI operation in this load: 12 reads
exceeded 1 s, the slowest 1,824.9 ms at 2026-09-26T06:59:50.52Z in reload 12,
in the same schedule slot as the 886.0 ms `policy stats` read.

## Analysis notes

Observed:

- Sample accounting (`samples.csv`): 2925 rows at a 30 s cadence through
  elapsed 87,746 s, with no scrape failures and no observation gaps.
- RSS trajectory (`samples.csv`): 490.2 MB at the first sample; 5th–95th
  percentile 504.9–561.8 MB; the 756.4 MB peak at 2026-09-26T04:27:00Z,
  inside reload 7 (issued 04:26:57Z, complete 04:27:05Z); late-window slope
  +0.223 MB/h. The intern gauge (`bgp_rib_attr_intern_global_size`) stayed
  at 999–1000 entries.
- **Readiness breach 1** (`verdict.json` `readyz`): the sample at
  2026-09-26T07:30:02Z (elapsed 21,876 s) returned HTTP 503 in 276.5 ms. It
  fell in reload 13 (issued 07:29:56Z, complete 07:30:05Z). The daemon
  logged `readiness probe failed` with `peer manager probe timed out (200ms
  deadline)` at 07:30:01.51Z, 1.35 s after that reload's RIB export-policy
  transition committed (07:30:00.16Z) and 0.54 s after its settlement
  settled (07:30:00.97Z). This is the behaviour the open
  [known issue](../reference/known-issues.md) "Reloads can produce transient
  readiness failures" describes; ADR-0136 did not change readiness. It is
  the only status failure across the 2026-09-21, 2026-09-24 and 2026-09-26
  runs.
- **Readiness breach 2**: the sample at 2026-09-27T01:13:52Z (elapsed
  85,706 s) returned HTTP 200 in 259.2 ms against the 250 ms limit, in
  reload 48 (issued 01:13:46Z, complete 01:13:56Z). The next-highest
  readiness latencies were 164.5 and 157.7 ms. The gate passed under its
  consecutive-breach rule; both breaches stay recorded as evidence under the
  [readiness acceptance policy](soak-acceptance-gates.md#readiness-acceptance-and-kubernetes-probes).
- **Cadence detail** (`verdict.json`
  `management_cadence.value.operations.metrics.per_reload`): one missed
  `/metrics` slot in each of reloads 18, 34 and 36. The neighbor,
  policy_stats, rib_prefix, and doctor schedules missed no slot.
- Daemon log census (`verdict.json` `daemon_log.value.warnings_by_message`):
  77,940 records, 0 `ERROR`, 308 `WARN`:
  - 294 `inbound connection from unknown peer, dropping`: the 147 `doctor`
    listener-reachability probes, each over two address families. Expected.
  - 6 `TCP connect failed` for the designated member, one at each trip's
    timed restart. Expected.
  - 6 `max prefix exceeded`, one per deliberate breach.
  - 1 `readiness probe failed`: readiness breach 1 above.
  - 1 startup notice for the RFC 8212 legacy-omission posture of the
    scenario configuration, also reported by the pre-start
    `--check --strict` (`daemon-check.log`).
- Engine (`reloadstall.log`): final `sessions_up 1000/1000 parse_errors=0`.
- Host cohabitation: the shared bench/soak host lock was held for the
  window.

Interpretation:

- The failure class of the v0.72.0 run, a `policy stats` read expiring at
  its 2 s deadline during a reload commit, did not recur in 17,551 attempts,
  and the handler's staged collection stayed at or under 25 ms throughout,
  reloads included. The slowest end-to-end read was 1,099.3 ms, against
  1,852.1 ms (successful) and 2,206 ms (expired) on v0.72.0 and 1,969.4 ms
  on v0.71.0. This is one run: it shows the gate passing on this SHA, not a
  bound on the tail, and the three runs differ in daemon commit as well as
  run.
- Session, reload, trip, memory, and log behaviour matches the earlier
  runs with no new failure class. The readiness 503 is the known reload
  readiness residual, not a new one.
- The gate stays as written. Durations and latencies in this receipt are
  recorded facts of one run on a virtualized guest. They make no
  performance claim, and the receipt covers this IPv4-only shape at SHA
  `292c32b39` on this host, nothing wider: no dual-stack flagship soak has
  run, and no release tag is covered.

## Artifacts

Repo-archived (small, git-suitable; absolute checkout paths in
`binaries.sha256` normalized to `<repo>`, every other file byte-for-byte
from the run directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-rs-flagship-20260926T011146Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-rs-flagship-20260926T011146Z/cycles.log` |
| run.json | `docs/artifacts/soak/soak-rs-flagship-20260926T011146Z/run.json` |
| verdict.json (on-host, run-SHA analyzer) | `docs/artifacts/soak/soak-rs-flagship-20260926T011146Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-rs-flagship-20260926T011146Z/binaries.sha256` |
| engine log (reloadstall) | `docs/artifacts/soak/soak-rs-flagship-20260926T011146Z/reloadstall.log` |
| scenario config + policy files | `docs/artifacts/soak/soak-rs-flagship-20260926T011146Z/scenario/` |

Retained off-repo (too large for git, or carrying host paths; preserved
with the original run directory). The analyzer needs the daemon log and
management-load evidence, so the verdict cannot be recomputed from the
repo-archived subset alone. The latency figures and audit-record timings
above are computed from the retained files:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~37 MiB |
| management-plane load evidence | `management-plane-load.jsonl` | ~39 MiB |
| full `/metrics` body per sample | `metrics-snapshots.txt.gz` | ~607 MiB |
| last `doctor` bundle | `doctor-bundle.tar.gz` | ~42 KiB |
| runner, build, and generator logs; final barrier markers | `soak.log`, `generator.log`, `daemon-check.log`, `build-*.log`, `engine-finish/` | < 10 KiB |
