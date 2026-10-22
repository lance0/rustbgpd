# Soak Receipt — Inject-churn with owner leases 24 h, 2026-10-21

**Status:** Complete — verdict: **PASS**, on the on-host verdict. No reanalysis.
**Run ID:** `tests/soak/runs/soak-inject-churn-20261021T011741Z`
**Daemon version:** unreleased, git SHA `536b538675404b0ca6e38c69a7f726fd97ade17d`
(image `rustbgpd:dev` built from this SHA: yes; the runner's source check matched
image `sha256:d89f6bbf35677ae148f659e8506c7fb6e5c869df3079f9e99801a08e22c22e64`
to the checked-out tree)
**Scenario config hash:** `3528f9fe06c765d75c3560059f588b09a9090924af30856dffb82932f60853a6`
(sha256 of the on-host `run.json`, before the path normalization noted below)
**Analyzer and gate revision:** `verdict.json` (sha256
`9fa33e2875ea4149e96a51a4b171ebfb9cee71d51ad964568fedb6f0bc8ca5fc`), written by
`tests/soak/analyze-soak-inject-churn.py` at the run SHA against scenario 3 of
`docs/soaks/soak-acceptance-gates.md` at the run SHA. The gates, analyzer and runner
were committed before the run started and have not changed since.
**Date:** runner start 2026-10-21T01:17:43Z; sampling 2026-10-21T01:19:39Z →
2026-10-22T01:19:52Z (86,412 s elapsed at the last sample)

## Verdict

**PASS on all 15 analyzer gates.** 125 lease flaps each expired after the lease
deadline and inside the gate's bound. All 250 stale renewals (125 after expiry,
125 at a superseded generation) were refused. The healthy owners held all their keys
at FRR in every post-warmup sample. `/readyz` answered 200 on all 85,151 probes.
RSS stayed flat (peak 45.5 MB), the session never flapped, and the daemon logged no
`ERROR` record.

## Run shape

| Field | Value |
|-------|-------|
| Scenario | 3 — Inject-churn (gRPC route injection) in lease mode (`LEASE_MODE=1`) |
| Harness / analyzer | `tests/soak/run-soak-inject-churn.sh` / `tests/soak/analyze-soak-inject-churn.py` |
| Topology | `tests/soak/soak-inject-churn.clab.yml` (rustbgpd and one FRR consumer) |
| Host shape | Dedicated soak host: virtualized guest, 8 vCPU (hypervisor-masked CPU model), 15 GiB RAM. Not a performance-measurement platform |
| Duration | target 86,400 s; last sample at elapsed 86,412 s |
| Unowned churn | 25 deletes + 25 adds every 5 s over a 4096-prefix pool, live target 1024 |
| Leases | 4 owners × 512 leased /32s (pool disjoint from the churn pool), 30 s lease, renewal every 10 s; the last owner flaps every 600 s |
| Sampling | 60 s (`samples.csv`, `lease-samples.jsonl`); `/readyz` probed at 1 Hz |
| Warmup excluded from slopes | 120 s |

Each flap cycle stops renewing, waits for FRR to lose the owner's keys, renews the
expired generation (must be refused), re-adds, renews the old generation again (must be
refused as superseded), then waits for the keys to return at FRR.

## Gates — measured vs precommitted

Bounds from scenario 3 of `soak-acceptance-gates.md` at the run SHA, including its
lease-mode table; measured values from `verdict.json`.

| Gate | Precommitted bound | Measured | Result |
|------|--------------------|----------|--------|
| Intern-table slope (post-warmup) | < 1.0 entries/h | 0.0 entries/h | **PASS** |
| RSS slope (post-warmup) | < 1.0 MB/h | −0.0017 MB/h over 1,390 samples | **PASS** |
| Peak RSS | < 512 MB | 45.5 MB | **PASS** |
| Churn cycles completed | ≥ 0.5 × ((86,400 − 120) ÷ 5) = 8,628 | 15,899 | **PASS** |
| Final consumer convergence | FRR route count == live target | 1024 == 1024 | **PASS** |
| Session-flap budget / established at end | flap delta == 0; established at end | 0 flaps over 86,413 s of uptime; established | **PASS** |
| Daemon log | complete, well-formed log; every `ERROR` fails | 900,231 records, 0 `ERROR`, 0 defects | **PASS** |
| Lease controllers | every controller exits 0; no failed leased add | 4 of 4 exit 0; 0 add failures | **PASS** |
| Ordinary renewals | each owner renews; none refused or failed | 8,536 / 8,535 / 8,536 / 7,514 renewed (the last is the flapping owner); 0 other | **PASS** |
| Healthy-owner presence | every post-warmup sample: FRR holds all keys and the lease is live | 1,389 samples, 0 violations | **PASS** |
| Flap expiry | first FRR drop ≥ send + lease; all gone by reply + lease + 5 s; all back after re-add; ≥ max(1, (86,400 − 120) ÷ (2 × 630)) = 68 cycles | 125 cycles, 0 violations | **PASS** |
| Stale renewal refused | attempts > 0; refused == attempts | 250 of 250 (expired 125/125, superseded 125/125) | **PASS** |
| Generation | flapping owner's incarnation constant, sequence strictly increasing | one incarnation; sequence 4 → 129 over 126 adds | **PASS** |
| `/readyz` | every probe 200; ≥ 43,200 probes | 85,151 probes, 0 failures | **PASS** |

The gate document asks for the achieved churn cadence: 15,899 cycles over the
86,292 s post-warmup window. Expiry offsets past the deadline (0.14–0.65 s) and the
`/readyz` maximum (9.0 ms) are recorded facts of this run on a virtualized guest, not
performance claims.

Besides 862,272 per-call gRPC authorization audit records, the daemon logged 146
warnings: 125 lease-expiry withdrawals (one per flap), 18 rejected-route retention
evictions, and three startup posture advisories (unfiltered eBGP policy, gRPC TCP
without transport encryption, legacy RFC 8212 posture), all expected for this lab
configuration.

## Scope

This receipt covers source `536b53867` only, on one lab shape: a single FRR consumer,
IPv4 unicast leases, and four owners. It says nothing about later commits, FlowSpec
leases, or scale. The soak host is a virtualized guest and not a measurement platform,
so the receipt makes no wall-clock or throughput claim.

## Artifacts

In `docs/artifacts/soak/soak-inject-churn-20261021T011741Z/`, byte-for-byte from the run
directory except `run.json`, whose absolute topology path is normalized to `<repo>`:
`run.json`, `verdict.json`, `samples.csv`, `readyz.csv`, `lease-events.log` and
`lease-samples.jsonl`.

Retained off-repo with the original run directory: the daemon log (`rustbgpd.log`,
about 438 MiB, mostly authorization audit records), the churn log (`churn.log`, about
31 MiB) and the runner log (`soak.log`, which carries host paths and lab addresses). The
analyzer reads the daemon log, so the verdict cannot be recomputed from the
repo-archived subset alone.
