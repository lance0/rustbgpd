# Soak Receipt — EVPN route reflector (Type 2/5 churn, client flaps, reloads) 24 h, 2026-10-12

**Status:** Complete — verdict: **PASS**, on the on-host verdict at the
v0.77.0 tag.
**Run ID:** `tests/soak/runs/soak-evpn-rr-20261012T231350Z`
**Daemon version:** v0.77.0 at git SHA
`77fb3ef14b3724a8faa84258930ead80cf2c5291` (image `rustbgpd:dev` built from
this SHA: not applicable — bare-host run; `rustbgpd`, `rbgp`, and the
`evpn-rr-soak` driver were built `--release --locked` at this SHA)
**Scenario config hash:**
`aa3ccf9d66434cb5c89651a02b90c7d6ade569410149ba744452859b002c5c68`
(sha256 of `run.json`; pins duration, epoch cadence, churn volume, flap and
reload schedules, and the management-plane load as executed)
**Executable identities:** `rustbgpd` sha256
`de2b59d4a3dca5d1b071073b014b0639c05648ac1b439e432a60fce1d2d8a55a`;
`rbgp` and `evpn-rr-soak` digests in `binaries.sha256`
**Analyzer and gate revision:** `verdict.json` (sha256
`0da285a30d936ba0e33bf1205a7f81e919c86f083dbdeb3d53b9ef63ece01662`),
written on the soak host by `tests/soak/analyze-soak-evpn-rr.py` at the tag
(analyzer sha256
`87a26b964aee272546c9d6d73611aafd6788b3b08be2c7aa918de74357ddae98`; runner
`tests/soak/run-soak-evpn-rr.sh` sha256
`c368b0d9d1607ecedd4316d6a2dab1862b37a16de4e63f6ce626b70b00fe77e5`) against
scenario 12 of `docs/soaks/soak-acceptance-gates.md` at the tag. None of
`tests/soak/`, `bench/evpn-load/` or the acceptance-gates document changed
between the tag and the main branch this receipt was written against.
**Date:** 2026-10-12T23:13:50Z runner start (build); daemon ready
23:29:01Z; driver converged and sampling began 23:29:19Z; hold
2026-10-12T23:29:19Z → 2026-10-13T23:29:19Z (86,400 s); analyzer
23:29:26Z (24 h 15 m 36 s overall)

## Verdict

**PASS on all 25 analyzer gates.** All 1440 one-minute epochs converged
exactly: after every epoch, each of the 150 clients held exactly the current
37,250 routes of the other 149 clients, with 0 invalid reflected routes,
0 self-reflected routes and 0 UPDATE parse errors. The terminal receipt
repeats that equality after 288 deliberate client flaps and 48 SIGHUP reloads.
The daemon's flap count equals the scheduled flaps exactly, and no session
was lost outside the schedule. `/readyz` answered HTTP 200 on every one of
2881 samples, slowest 35 ms. Peak RSS was 2654.4 MB against a 4096 MB
ceiling. It occurred at the first sample, after the initial table dump; the
hold settled at 2137–2160 MB with a late-window slope of +0.04 MB/h. All
138,390 management-plane operations completed `ok`, including 145
`rbgp doctor` runs and 34,562 paged EVPN view reads. The daemon log holds
67,773 records with zero `ERROR`.

## Release relationship

This is the first EVPN route-reflector soak receipt. Earlier EVPN soaks (M33,
M67, the gate 8b and gate 9 runs) target attribute-intern growth or VTEP
behavior; none combined client flaps, reloads and an exact per-epoch
reflection check across many clients. The receipt covers the v0.77.0 tag
and this shape on this host, nothing wider; it is evidence for the scoped
`route-reflector-evpn` v1 role, not a support claim for any other EVPN role.

Two later fixes on the main branch postdate this tree:

- The three `outbound channel full — EVPN update deferred` WARNs below are
  the closed-channel teardown race; #3127 (`966541f44`) changes that log so a
  peer that is already gone no longer reads as backpressure. This tree
  predates the fix, so it still logs the old text.
- #3129 and #3130 (update-group event/recovery parity and EVPN recovery
  preparation) do not change production EVPN distribution: EVPN update-group
  ownership stays disabled in both. This tree predates them.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 12 — EVPN route reflector: 150 real iBGP route-reflector-client sessions reflecting `l2vpn_evpn` only; each client advertises a sliding window of 200 Type 2 MAC/IP and 50 Type 5 IPv4-prefix routes with its own RD, a route target and the VXLAN encapsulation community (37,250 reflected routes per receiver); per epoch each client replaces 20 + 5 routes over the first 30 s; every fifth epoch one client (never client 0) resets and re-announces; every thirtieth epoch a SIGHUP reload swaps neighbor descriptions; management-plane load as scenario 10 with the EVPN operation set |
| Harness | `tests/soak/run-soak-evpn-rr.sh` (driver: `bench/evpn-load`, `evpn-rr-soak`) |
| Analyzer | `tests/soak/analyze-soak-evpn-rr.py` |
| Topology | Bare-host daemon + `evpn-rr-soak` driver over loopback sessions (no containerlab topology) |
| Host shape | Dedicated soak host: KVM guest, 8 vCPU (generic QEMU CPU model), 15 GiB RAM, 4 GiB swap file; `nofile_soft = 65536`. Daemon, driver and management load share the guest's vCPUs. Not a performance-measurement platform |
| Duration | target 86,400 s hold, actual 86,400 s; last sample at elapsed 86,400 s |
| Epochs | 1440 × 60 s (30 s churn, then the exact convergence check) |
| Sample interval | 30 s |
| Warmup excluded from slopes | 300 s |
| Total data samples | 2881 |

## Injections executed

| Injection | Planned | Executed | Notes |
|-----------|---------|----------|-------|
| Route churn (20 Type 2 + 5 Type 5 replaced per client per epoch) | 1440 epochs × 7500 events | 1440 epochs, each `churn_events=7500` | Every epoch rotates route identities |
| Client flaps (Cease/Administrative Reset, reconnect, re-announce) | 288 (every 5th epoch, never client 0) | 288, numbered 1…288 | Re-established in 52–56 ms (median 53 ms) per `cycles.log` |
| SIGHUP reloads (description generation swap on every neighbor) | 48 (every 30th epoch) | 48 issued, 48 `complete` | Driver verifies `bgp_sighup_reload_outcomes_total` per reload |
| Management-plane load | `/metrics` 1 s, `rbgp neighbor` 5 s, client 0's paged `rbgp evpn received` / `advertised` 5 s each, `rbgp doctor` 600 s | 86,402 / 17,281 / 17,281 / 17,281 / 145 | All scheduled operations completed, 0 failures |

## Gates — measured vs precommitted

Bounds quoted from `docs/soaks/soak-acceptance-gates.md` scenario 12 at the
tag (scenario 10 rules where it defers to them); measured values from
`verdict.json`. Analyzer gate keys are in parentheses.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Minimum sample count (`min_samples`) | ≥ 2592 | 2881 | **PASS** |
| Session floor (`session_floor`) | all 150 Established on every post-warmup sample, except one client inside its flap window | 0 violations | **PASS** |
| Flap accounting exact (`flap_accounting`) | executed == planned (288), numbered 1…288, never client 0, each re-established within 120 s | 288 of 288, 0 defects | **PASS** |
| Session-flap budget exact (`flap_budget`) | daemon flap delta == executed flaps | 288 == 288 | **PASS** |
| Reload accounting exact (`reload_accounting`) | issued == complete == planned (48) | 48 / 48 / 48 | **PASS** |
| EVPN reflected-route convergence (`evpn_convergence`) | one exact `evpn_epoch` per planned epoch: `converged=1`, 150 receivers, `min_live == max_live == 37,250`, 0 invalid, 0 self-reflected, 0 parse errors, `converge_ms` ≤ 60 s | 1440 of 1440, 0 defects; converge p50 209 ms, max 213 ms | **PASS** |
| EVPN terminal receipt (`evpn_terminal_receipt`) | exactly one receipt matching planned epochs, flaps and reloads, every client at 37,250 | 1440 epochs, 288 flaps, 48 reloads, 150 receivers at `min_live == max_live == 37,250`, 0 invalid / parse errors / self-reflected | **PASS** |
| No lost session (`evpn_sessions_not_lost`) | zero `evpn_session_lost` | 0 | **PASS** |
| Deferred-update recovery (`evpn_deferral_recovery`) | every deferral before the final teardown followed by a later passing exact epoch | 0 deferrals before teardown; 3 excluded as teardown | **PASS** |
| Per-series sent counters (`sent_counters_monotone`) | every `bgp_messages_sent_total{peer,type}` series persists and never decreases | 289 snapshots, 750 series, 0 decreases, 0 vanished | **PASS** |
| Aggregate sent counter (`msgs_sent_monotone`) | sum never decreases | 0 breaks; final 66,198,831 | **PASS** |
| Max-prefix flat (`max_prefix_flat`) | `bgp_max_prefix_exceeded_total` == 0 on every sample | 0 | **PASS** |
| Peak RSS (`rss_peak_mb`) | < 4096 MB | 2654.4 MB | **PASS** |
| RSS late-window slope (`rss_late_slope_per_hour`) | < 10 MB/h over the final 25 % | +0.0408 MB/h | **PASS** |
| Intern late-window slope (`intern_late_slope_per_hour`) | < 100 entries/h | 0.0 | **PASS** |
| readyz availability (`readyz`) | fewer than 3 consecutive misses of HTTP 200 within 250 ms; no dropped scrape or observation gap | 0 bad samples, 0 scrape failures, 0 gaps; max 35 ms | **PASS** |
| No abort record (`no_abort`) | zero `ABORT:` lines | 0 | **PASS** |
| Daemon log (`daemon_log`) | complete, well-formed log; every `ERROR` fails | 67,773 records, 0 `ERROR`, 0 defects; 293 `WARN` (below) | **PASS** |
| Management evidence, lifetime, operations, completion, cadence, failures, doctor (`management_*`, 7 gates) | scenario 10 rules with the EVPN operation set; completion ≥ 0.9 per operation; ≤ 2 missed slots | completion 1.0 for every operation; 0 missed slots; 0 failures; 145 of 145 doctor runs passed; load window covered the measured window | **PASS** |

25 / 25 gates pass. Analyzer verdict: `pass`.

## Analysis notes

Observed:

- Sample accounting: 2881 CSV rows from elapsed 0 to 86,400 s at a 30 s
  cadence (30 or 31 s steps, plus a 5 s final step to the hold end), no
  scrape-failure gaps. All 150 sessions Established on every sample.
- RSS (CSV `rss_mb`): 2654.4 MB at the first sample, taken right after the
  initial 150-way table dump, then 2137.7 MB at 30 s and a 2136.8–2160.3 MB
  band for the rest of the run (5th–95th percentile 2147.8–2155.0 MB).
  At 6, 12, 18 and 24 h: 2150.1, 2154.0, 2153.1 and 2151.9 MB. The median
  was 2146.3 MB in the first hold hour and 2153.0 MB in the last.
- Live heap (`jemalloc_allocated_bytes` in the 289 retained `/metrics`
  snapshots): 2095.2–2096.5 MiB for the whole run. jemalloc resident bytes
  fell from 2709.9 MiB at the first snapshot to 2124.0–2139.7 MiB afterwards.
  The live-heap figure is independent of swap. The host has a 4 GiB swap
  file; swap use during the run was not recorded, and it read 0 B after the
  run.
- Intern gauge (`bgp_rib_attr_intern_global_size`): 1 entry on every
  sample; late slope 0.0.
- `/readyz`: HTTP 200 on all 2881 samples, max 35 ms, 99th percentile
  11.1 ms.
- Daemon log census (`verdict.json` `daemon_log.value.warnings_by_message`):
  67,773 records, 0 `ERROR`, 293 `WARN`:
  - 290 `inbound connection from unknown peer, dropping`, 145 each from
    `127.0.0.1` and `::1`, at the 600 s `rbgp doctor` cadence: the doctor's
    listener-reachability probe over two address families. Expected, as in
    the route-server flagship receipts.
  - 3 `outbound channel full — EVPN update deferred`, for three different
    clients between 23:29:20.268Z and 23:29:20.270Z, after the driver's
    final Administrative Shutdown at 23:29:20.253Z. The analyzer excludes
    them as teardown (`teardown_excluded=3`). The channel was closed, not
    full: the peer had gone, and nothing was left to deliver. This is the
    benign log-text defect fixed after this tree by #3127.
- Engine (`driver.log`, `cycles.log`): 1440 `evpn_epoch` lines, 288 flap
  down/up pairs, 48 reload issued/complete pairs, one `evpn_receipt`, zero
  `evpn_session_lost`, zero `ABORT`.
- Host cohabitation: the shared bench/soak host lock was held for the
  window; no other soak ran on the host until this run had exited.

Interpretation:

- The per-epoch exact check is the load-bearing correctness fact. For
  1440 consecutive minutes of Type 2/5 replacement, client resets and hot
  reloads, every receiver held exactly the announced set of every other
  client and none of the withdrawn routes. A reflector that dropped,
  duplicated, altered or self-reflected a route, or failed to withdraw one,
  could not produce that equality.
- RSS and the live heap are flat after the initial dump. The 500 MB drop
  after the first sample is allocator retention released after the initial
  load, not routes or queued updates (see the memory envelope below).

## Memory envelope at this shape

This run's live heap of about 2.1 GB comes almost entirely from per-receiver
EVPN Adj-RIB-Out state. A separate local attribution (a development host,
not this soak host, and not a receipt) measured the same 150 × 250 shape at
2,094 MiB of live heap and attributed it as follows:

- Each receiver keeps its own EVPN Adj-RIB-Out hash map. One entry costs
  217 B (a 64 B route key, a 152 B route and a 1 B control byte), plus the
  empty buckets the map carries after power-of-two growth.
- At this shape, 37,250 entries per receiver and 150 receivers, that is
  about 382 B per route per receiver: 217 B occupied plus 165 B slack.
  Encoded UPDATEs are not retained, attributes are shared with the Loc-RIB,
  and the outbound queues were empty at rest.
- The per-route cost depends on where the entry count falls against the
  map's capacity: 217 B × next_pow2(⌈entries × 8/7⌉) ÷ entries, between
  about 248 B and 496 B. With no routes, the daemon and 150 sessions held
  about 41 MiB of live heap.
- Peak above settled memory is allocator retention from tables that doubled
  during the initial load. It is not queued work, and churn, flaps and
  reloads did not raise it above the initial-load peak.

Memory therefore scales with receivers × reflected routes. Size an EVPN route
reflector from that product, not from the unicast route-reflector receipts,
whose per-route cost is much lower. Sharing EVPN Adj-RIB-Out state across
update groups is being designed and would change this envelope; until it
ships, these numbers apply. Shapes other than this one were not soaked.

## Claim ceiling

This run is on the dedicated soak host, a virtualized guest that is not a
performance-measurement platform. Convergence times, re-establishment times,
readiness latencies and message counts are recorded facts of one run, not
wall-clock, throughput or comparative performance claims. The receipt covers
the v0.77.0 tag and this 150-client, 37,250-routes-per-receiver,
Type 2/5-only, IPv4-loopback shape. It says nothing about Types 1, 3, 4 or
6 under churn, other client counts or route volumes, RT-Constrain, export
policy, forwarding, or any VTEP behavior.

## Artifacts

Repo-archived (small, git-suitable; the absolute checkout path in
`binaries.sha256` is normalized to `<repo>` and the host home directory in
`soak.log` to `<SOAK_HOME>`; every other file is byte-for-byte from the run
directory):

| Artifact | Path |
|----------|------|
| samples.csv | `docs/artifacts/soak/soak-evpn-rr-20261012T231350Z/samples.csv` |
| cycles.log | `docs/artifacts/soak/soak-evpn-rr-20261012T231350Z/cycles.log` |
| driver log | `docs/artifacts/soak/soak-evpn-rr-20261012T231350Z/driver.log` |
| runner log | `docs/artifacts/soak/soak-evpn-rr-20261012T231350Z/soak.log` |
| run.json | `docs/artifacts/soak/soak-evpn-rr-20261012T231350Z/run.json` |
| verdict.json (on-host, tag analyzer) | `docs/artifacts/soak/soak-evpn-rr-20261012T231350Z/verdict.json` |
| binaries.sha256 | `docs/artifacts/soak/soak-evpn-rr-20261012T231350Z/binaries.sha256` |
| scenario configs (both reload generations) | `docs/artifacts/soak/soak-evpn-rr-20261012T231350Z/scenario/` |

Retained off-repo (too large for git, or carrying host paths; preserved with
the original run directory). The analyzer needs the daemon log, the metric
snapshots and the management-load record, so the verdict cannot be
recomputed from the repo-archived subset alone:

| Artifact | File | Size |
|----------|------|------|
| daemon log | `rustbgpd.log` | ~30 MiB |
| management-plane load record | `management-plane-load.jsonl` | ~38 MiB |
| full `/metrics` body per snapshot | `metrics-snapshots.txt.gz` | ~13 MiB |
| final doctor support bundle | `doctor-bundle.tar.gz` | ~59 KiB |
| build, generator and daemon-check logs; cleanup marker | `build-*.log`, `generator.log`, `daemon-check.log`, `cleanup.complete` | < 2 KiB each |

## Follow-ups

- [ ] None arising from the gates — every gate passed inside its precommitted
      bound. The deferral log text is already fixed on the main branch, and
      the memory envelope above is the documented posture until shared EVPN
      update-group storage ships.
