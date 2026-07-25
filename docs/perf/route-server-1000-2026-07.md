# 1,000-peer route-server retained receipt — 2026-07

This receipt answers one bounded capacity question: can a real rustbgpd route
server hold 1,000 uniform eBGP member sessions, distribute a 400,000-route
IPv4 table, and complete repeated export-policy changes while remaining
observable? On this host and exact commit, yes.

This is an acceptance receipt, not a before/after optimization claim or a
competitor comparison. It is one same-host loopback campaign, so its timings
describe this disclosed fleet rather than a universal deployment forecast.

**Measured commit:** `cb2c924f117fe264991f12b24ea44c2b15b132e2`

> **Default drift since this run.** The scenario config declares a bare
> `[policy]` with no `[policy.explain]` override, so this campaign ran
> with the import-decision explain cache **enabled** — the default at the
> time. That default is now `false` (ADR-0073), which means the RSS
> figures below include retention a current daemon does not pay for by
> default. How much they would drop is a separate before/after
> measurement that has not been run; do not read a saving out of this
> receipt.

## Result

| Precommitted check | Result |
|---|---:|
| Sessions established | 1,000 / 1,000 in 0.9 s |
| Cold convergence | 21.1 s (gate: at most 60 s) |
| Routes injected / expected at each observer | 400,000 / 399,600 |
| Policy reload cycles generation-complete | 4 / 4 |
| Sessions up after every reload | 1,000 / 1,000 |
| UPDATE parse errors after every reload | 0 |
| Final update groups / grouped members / fallback peers | 1 / 1,000 / 0 |
| Finalize actor-poll counter delta | 4 |
| `/readyz` | 1,259 / 1,259 HTTP 200; maximum 128.385 ms (gate: 250 ms) |
| Daemon process-tree RSS | maximum 1,082,584 KiB (1,057.2 MiB; gate: 2 GiB) |
| Representative export explain | advertise; export policy passed; grouped |

The run completed with a successful driver status and all three continuous
samplers exited cleanly. The retained checksum manifest verifies every
published artifact.

## Fleet and workload

- One rustbgpd route server with ASN `4200000000`, a private four-octet ASN
  selected to be disjoint from every generated member ASN.
- 1,000 unique loopback eBGP route-server clients, remote ASNs 64512–65511,
  IPv4 unicast only. A load-bearing emitted-config test checks every indexed
  address and ASN, the all-eBGP property, the common grouping shape, and a real
  `rustbgpd --check` invocation.
- 400 routes originated by each client: 400,000 total. Split horizon means
  every observer must receive the other 999 slices, or 399,600 unique routes.
  Cold convergence therefore represents 399.6 million observer-NLRI
  deliveries over loopback.
- One uniform export-policy group. This deliberately exercises the dominant
  grouped route-server shape; it does not model per-client-best selection,
  peer-context policies, ORR, mixed negotiated capabilities, or fallback
  members.
- Eight clients each churn 16 dedicated prefixes every 125 ms throughout the
  measurement. The 30-second no-reload control window observed per-client
  maximum-gap p50 42.62 ms and maximum 59.35 ms.
- Four alternating export-only A/B policy reloads. Every observer must receive
  every expected unique prefix with the requested generation community before
  a row is emitted.

## Reload observations

| Reload | completion p50 / p95 / max | delivery-gap p50 / p95 / max | first UPDATE p50 / p95 / max | RSS before / after |
|---:|---:|---:|---:|---:|
| 1 | 2.794 / 3.214 / 3.242 s | 602 / 951 / 1,190 ms | 8.7 / 10.9 / 37.8 ms | 896 / 921 MiB |
| 2 | 2.583 / 3.123 / 3.240 s | 843 / 1,504 / 1,843 ms | 7.1 / 10.5 / 36.9 ms | 901 / 926 MiB |
| 3 | 2.337 / 2.998 / 3.115 s | 947 / 1,594 / 2,147 ms | 3.3 / 6.1 / 39.2 ms | 911 / 904 MiB |
| 4 | 2.264 / 3.073 / 3.115 s | 969 / 2,029 / 2,158 ms | 87.4 / 91.6 / 96.0 ms | 888 / 907 MiB |

Completion is the stronger correctness result: all 1,000 observers reached
the exact new generation in every cycle. The delivery-gap tail reached 2.16 s
under this 399.6-million-NLRI fanout and is published without converting it
into a win. The earlier 700-peer receipts use different fleet shapes and
purposes; this document makes no direct speedup or regression claim against
them.

## Method and fail-closed gates

The no-argument driver at
`bench/scale/route-server-1000/run-receipt.sh` owns a host lock and refuses to
run unless the exact Git commit and tree are clean. Before and after the real
release build it requires load below 2, all 64 CPU governors in performance
mode, no competing build/daemon/benchmark process, no swap I/O over a
two-second sample, free ports, at least 16 GiB available memory, and a file
descriptor limit of at least 4,096.

The measured phase has a 600-second watchdog. It fails on cold convergence
over 60 seconds, RSS over 2 GiB, a non-200 or slower-than-250-ms readiness
sample, a failed metrics scrape, missing sampler coverage, any malformed or
generation-incomplete reload row, fewer than 1,000 sessions, any parse error,
group/fallback drift, fewer than four finalize actor polls, a failed export
explain, or source/tree/worktree drift. The run retained 1,259 readiness, 511
metrics, and 143 RSS samples.

The generator regression is load-bearing: changing the local ASN back to
65500 makes peer 988 iBGP and the test fails at that exact peer before daemon
validation. Restoring `4200000000` returns it to green.

## Reproduce and artifacts

On a dedicated Linux host with loopback addresses available:

```console
git checkout cb2c924f117fe264991f12b24ea44c2b15b132e2
bench/scale/route-server-1000/run-receipt.sh
```

The driver emits private raw output below `target/route-server-1000/`. The
[retained artifact set](artifacts/route-server-1000-2026-07/README.md) includes
the sanitized config and policies, exact commands and binary hashes, build and
daemon logs, per-reload rows, continuous readiness/RSS/metrics streams, export
explain, environment, validation summary, and checksums.
