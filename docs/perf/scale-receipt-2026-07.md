# 1000-peer route-reflector scale receipt — 2026-07-03

The capstone measurement of the July 2026 perf thread: profile the RR
fanout end to end, fix what the profile indicted (#667, #668, #671,
#672, #675, and the ADR-0098 update-groups arc #674/#676/#677), then
prove the result at 1000 uniform iBGP route-reflector clients with
100k IPv4 unicast routes.

**Commit measured:** `b26ff11c` (main, update-groups arc complete).

## Headline

| Metric (1000 RR clients × 100k routes) | Value |
|---|---|
| Cold convergence, staged (last route staged to every peer's outbound view) | **1.80 s** |
| Cold convergence, wire (all 100M NLRI decoded by the client peers) | **1.82 s** |
| Whole-process RSS at convergence (RR + all 1000 client stubs in one process) | **419 MiB** |
| Update groups formed | 1 (all 1000 peers) |
| Sustained aggregate advertisement rate (fresh 100k blocks, steady) | ~49 M prefix-advertisements/s |
| Pre-arc extrapolation for the same scenario | ~59 s (linear model, see below) |

## Environment

| Field | Value |
|---|---|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores / 64 threads), 125 GiB RAM |
| Kernel | Linux 6.17.0-20-generic |
| rustc | 1.96.0 (2026-05-25) |
| Build | `--release`, `debug = 1` for symbols |
| State | Host otherwise idle; every timed run held the shared bench host lock; no concurrent builds |

## Methodology — what this harness is and is not

`rrharness` is the same in-process probe that produced the profile that
started this thread (see `docs/adr/0098-update-groups.md`). It runs:

- the **real `RibManager`** (`crates/rib`, `mgr.run()`, cluster-id set:
  acting as a route reflector);
- **N real transport `PeerSession`s** spawned through the public
  `PeerHandle::spawn` (`crates/transport`), each configured as an iBGP
  RR client, each dialing a distinct loopback address;
- N minimal BGP stub clients (`bench/evpn-load`) that complete
  OPEN/KEEPALIVE and **decode every received UPDATE**, so every
  advertisement crosses a real TCP socket and a real wire encode/decode
  round trip.

Routes are injected into the manager from 4 synthetic ingress source
peers; the manager reflects them to all N client sessions, exercising
outbound staging, update-group delta fanout, per-session
`prepare_outbound_attributes`, wire encode, and `write_all` syscalls.

Two convergence gauges, both reported:

- **staged** — every peer's advertised (adj-out) count reaches the
  full table. For grouped members this is intended state at staging
  time (ADR-0098 as-built note).
- **wire** — the stub clients have decoded `N × routes` NLRI entries
  off their sockets. This is the honest "last UPDATE drained through
  the socket and parsed by the client" number and is the one quoted as
  the headline.

**What it does not measure:** a real NIC (loopback writes skip
driver/TSO cost; syscall *count* is identical to production), BGP OPEN
storms from remote misbehaving peers, RPKI/BMP/gRPC side machinery
(not attached), or the event-history outbox (not attached). RSS
numbers are **whole-process**: they include the 1000 stub clients and
1000 session tasks in the same address space as the RR, so they are an
upper bound on the RR-side footprint for this workload.

## Scenario A — cold convergence scaling curve (no policy)

100k IPv4 /24 routes flooded from 4 ingress peers to N established RR
clients, one update group (`GROUPS {"group:0": N}` verified per run):

| N clients | staged | wire | RSS established | RSS converged (peak=steady) | sustained flood (fresh 100k blocks / 20 s) |
|---|---|---|---|---|---|
| 256 | 0.562 s | 0.562 s | 31 MiB | 272 MiB | 29 (~36 M pfx-adv/s) |
| 512 | 0.971 s | 0.993 s | 53 MiB | 325 MiB | 18 (~45 M pfx-adv/s) |
| 1000 | 1.805 s | 1.815 s | 93 MiB | 419 MiB | 10 (~49 M pfx-adv/s) |

Scaling is ~linear in peers with a sublinear constant (2× peers ≈
1.8× wall) and no knee up to 1000 — the remaining per-peer work is
the transport encode + socket write, by design. Aggregate delivered
throughput *rises* with fanout because the shared staging pass
amortizes. The wire gauge trails the staged gauge by ≤ 25 ms at every
point: session writers (parallel across cores) keep pace with the
single-threaded manager. CPU self-time during the 1000-peer sustained
flood (pprof 997 Hz, stub clients excluded from the denominator):
staging+AdjRibOut 14.4%, prepare+encode 42.0%, writer+syscalls 36.7%,
recompute 1.3% — ~79% of RR cycles now go to the wire, versus 82.8%
spent on per-peer staging before the arc.

## Scenario B — churn at 1000 peers

Worst-case candidate density: 1000 synthetic ingress sources each
announce the same 3000 prefixes (1000 candidates per prefix), then
waves rotate the winning source with escalating LOCAL_PREF — every
wave is 3000 best-path flips re-fanned to all 1000 clients.

| Metric | Value |
|---|---|
| Flap waves completed / 20 s | 372 (18.6 waves/s) |
| Best-path flips propagated | ~55,800 flips/s, each delivered to 1000 clients |
| RSS after prime (3M Adj-RIB-In routes, 1000 distinct attr sets/prefix) | 5230 MiB |
| RSS after 372 waves | 5306 MiB (+76 MiB; churn state, no growth trend) |

CPU self-time shares during the churn window (pprof 997 Hz, bucketed
by task subtree; RR-work denominator excludes the stub clients):

| bucket | share | pre-arc (churn-256, same buckets) |
|---|---|---|
| staging + AdjRibOut | 15.5% | 44.9% |
| prepare + encode (transport) | 44.6% | 8.6% |
| writer + syscalls | 31.8% | 0.5% |
| recompute_best scan | **1.6%** | **45.2%** |
| other | 6.5% | 0.7% |

The pre-arc column is the 2026-07-03 measurement at 256 candidates ×
256 peers; today's is at 1000 × 1000 — a *harder* shape, and the
`recompute_best` full-rescan line the profile indicted (40–45%,
growing with candidates) is now 1.6% (#675 incremental best-path +
announcing-peers index). Like the flood, churn cycles now go
overwhelmingly to the wire.

## Scenario C — policy-on (M80 tagging chain on all 1000 clients)

Every client carries the compiled `.rpol` export chain from the M80
parity fixture (`customer-in(200)` + `edge-out`: as-path regex guard,
MED set, community add — modifications non-empty for every permitted
route). The chain is peer-context-free, so all 1000 peers still form
one group and the chain is evaluated **once per prefix per pass**
(#671 memo + ADR-0098 single group eval), not 1000 times:

| Metric (1000 × 100k, policy on) | value | vs no-policy |
|---|---|---|
| Cold convergence (staged / wire) | 1.87 s / 1.87 s | +3% |
| RSS converged | 453 MiB | +34 MiB (+8%) |
| Sustained flood blocks / 20 s | 10 | equal |
| Churn waves / 20 s | 358 | −4% (372 no-policy) |
| Churn RSS (prime → end) | 5272 → 5351 MiB | +~45 MiB |

## Scenario D — mixed fleet (900 grouped + 100 per-peer fallback)

Every 10th client gets a chain containing a `peer.asn` criterion — an
ADR-0098 v1 disqualifier — so 900 peers share one group and 100 ride
the legacy per-peer path (`GROUPS {"group:0": 900,
"policy_peer_context": 100}` verified):

| Metric | mixed 900+100 | uniform 1000 |
|---|---|---|
| Cold convergence (staged / wire) | 8.44 s / 8.44 s | 1.80 s / 1.82 s |
| RSS converged | 2647 MiB | 419 MiB |

Both paths coexist at scale and the fleet converges; the deltas are
the honest price of the fallback, and they are exactly the pre-arc
per-peer costs scaled to 100 peers: convergence is gated by 100
per-peer staging passes (~100/1000 of the pre-arc ~59 s model ≈ 6 s,
measured 8.4 s total), and RSS grows by ~22 MiB per fallback peer —
each of the 100 keeps a full private Adj-RIB-Out (100k `Route`s +
prefix trie), the structure grouped members no longer have. A fleet's
memory/CPU scales with its *fallback* count, not its size.

## Scenario E — VPNv4 at scale (update-groups v2, #685/#686)

Measured at the v2 close slice (`2ba6ce52` + the channel-full
source-flip fix — a failure-path-only change). Same harness, new
modes: `vpnflood` (100k VPNv4, distinct RDs, RTs from a 64-pool, no
RTC negotiated) and `vpnfloodhet` (RTC negotiated on every client,
each client's Φ = 6/64 RTs ≈ 10%, memberships installed before the
flood, SAFI-132 excluded from the wire gauge). 1000-client values are
3-run medians from this slice; 256-client values are the 3-run-median
A/Bs from the #685/#686 PRs, same host. Wire targets: 100 M NLRI
uniform, 9.38 M heterogeneous (each client decodes only its Φ share).

| Scenario | 256 per-peer (measured) | 256 grouped (measured) | 1000 per-peer (**extrapolated**) | 1000 grouped (measured) |
|---|---|---|---|---|
| Uniform VPN flood, converge (wire) | 18.66 s | 3.75 s | ~73 s | **12.60 s** |
| Uniform VPN flood, RSS converged | 8227 MiB | 492 MiB | ~31 GiB | **625 MiB** |
| Heterogeneous ~10% Φ, converge (wire) | 3.21 s | 1.10 s | ~12.5 s | **3.92 s** |
| Heterogeneous ~10% Φ, RSS converged | 1481 MiB | 482 MiB | ~5.7 GiB | **636 MiB** |

The 1000-client per-peer baselines are the 256-client baselines scaled
linearly in peers (the same model the unicast receipt used, and the
same caveat: **extrapolated, never measured** — the per-peer VPN
Adj-RIB-Out and the per-peer staging pass both scale with peers, so
linear is the honest first-order shape). One update group forms in
every run (`GROUPS {"group:0": 1000}`); heterogeneous Φ does NOT
shatter the group — the RT filter is applied per member at emit
(ADR-0099), never keyed. The heterogeneous flood converges faster
than uniform because each client's wire share is ~10% of the table;
its RSS is slightly higher than uniform's because every client also
carries SAFI-132 state and the per-member advertised counters.

**Membership-flip latency at scale** (the ADR-0099 membership-delta
path, end to end): with 100k VPNv4 staged and 1000 clients converged,
one member widens its Φ by one RT (1600 matching routes) and then
narrows it back. Time from the RTC UPDATE hitting the manager to the
member-scoped delta fully decoded on that member's wire, 3-run
medians:

| Flip | routes in delta | latency (median) | runs |
|---|---|---|---|
| Widen (announce-only delta) | 1600 | **15.1 ms** | 16.2 / 15.1 / 12.3 ms |
| Narrow (withdraw-only delta) | 1600 | **11.7 ms** | 53.3 / 11.4 / 11.7 ms |

Zero export-policy evaluations, group table untouched (pinned by a
manager test at the same scale); the one 53 ms outlier was the first
narrow after the profiler detached. The pre-v2 shape for the same
event was a full per-peer VPN restage (policy eval over 100k keys).

## The storyline — profile → fix → receipt

The 2026-07-03 profiles (dhat heap pass + pprof CPU pass, both
in-tree-methodology, artifacts in the perf-thread reports) indicted,
and the arc (#667–#686) fixed:

| Indictment (measured pre-arc) | Fix | Receipt (this document) |
|---|---|---|
| Per-peer outbound staging = 82.8% of RR CPU; flood-256 convergence 15.1 s; ~59 s extrapolated at 1000 peers (linear model) | Update groups: one staged table + one policy eval + one equality diff per group; Arc-shared announce payload (#674/#676/#677, ADR-0098) | 256 peers: 0.56 s measured (~27×); 1000 peers: 1.82 s measured (~32× vs the extrapolated ~59 s) |
| Adj-RIB-Out stored a full `Route` per (peer × prefix): ~30–40 GB extrapolated at 1000 × 100k | Group-owned table, O(1) per member (ADR-0098 Decision 4) | Whole-process RSS at 1000 × 100k: 419 MiB — the extrapolated structure simply no longer exists; the mixed-fleet scenario shows it re-appearing at ~22 MiB per fallback peer |
| Policy-modified export fanout un-shared attributes: 4.21 GB live at 256 × 10k (5.5× no-policy, dhat), ~130 GB shape at 1000 × 100k | Pass-scoped export memo (#671) + group single-eval (ADR-0098) | Policy-on RSS at 1000 × 100k: 453 MiB, +8% over no-policy; convergence +3% |
| `recompute_best` full candidate rescan: 40–45% of churn CPU, growing with candidate count | Incremental best-path + announcing-peers index (#675) | Churn recompute share at 1000 candidates/prefix: 1.6% |
| SipHash on outbound attr-cache keys dominated the prepare+encode bucket | FxHash outbound caches (#677) | SipHash gone from the top frames; prepare+encode is now the honest per-peer encode work (42–45%) |
| BMP loc-rib synthesis deep-cloned attrs per emission (11.6× alloc multiplier) | Borrowed-attr encode (#668) | Not re-measured here (BMP not attached); receipt is the #668 A/B in that PR |
| Per-peer VPN staging: `stage_vpn_routes` 27.3% + per-peer commit 40.2% of vpnflood CPU at 256; 18.7 s / 8.2 GiB at 256 × 100k VPNv4 | Update-groups v2 slice 1: family-extended key, shared VPN group staging + source-flip emit (#685, ADR-0099) | Scenario E: 256 grouped 3.75 s / 492 MiB (~5× / ~17×); 1000 grouped 12.60 s / 625 MiB vs ~73 s / ~31 GiB extrapolated per-peer |
| RTC negotiation forced the whole VPN family per-peer (the RFC 4684 Φ filter was a staging exclusion); het-256 3.21 s / 1481 MiB | v2 slice 2: Φ per member at emit + the zero-eval membership-delta path (#686, ADR-0099) | Scenario E: het-256 1.10 s / 482 MiB; het-1000 3.92 s / 636 MiB; one-RT membership flip at 100k staged delivers its 1600-route delta in ~15 ms (widen) / ~12 ms (narrow) with zero policy evals |

Pre-arc baselines were measured at 64/256 peers on the same harness,
same host (flood-64 3.5 s, flood-256 15.1–15.2 s, ~linear in peers).
The "~59 s at 1000" figure is that linear model, **extrapolated, not
measured** — running the pre-arc code at 1000 peers was never done.

## bgperf2 cross-daemon comparison

Skipped, honestly: stock bgperf2 drives N testers → target → **one**
monitor container — an ingest-convergence shape with a single
downstream client. It cannot express a 1-ingress → 1000-client RR
fanout, so no comparable cross-daemon configuration exists in that
harness. The existing bgperf2 ingest comparisons (rustbgpd / BIRD /
GoBGP, same host) remain in [`BENCHMARKS.md`](../BENCHMARKS.md).

## Caveats

- In-process, single machine, loopback TCP: no NIC driver cost, no
  network latency/loss, no remote flow control beyond real kernel TCP
  buffers. Syscall and PDU counts match production; absolute writer
  CPU on a real NIC would be somewhat higher (measured ≤ a few % of
  the pipeline here).
- RSS is whole-process (RR + 1000 stub clients + harness); the
  RR-attributable share is strictly smaller.
- All 1000 peers are uniform iBGP RR clients negotiating IPv4 unicast
  only — deliberately the update-groups sweet spot; the mixed-fleet
  scenario bounds the heterogeneous case at a 10% fallback share.
  Fleets that are 100% disqualified (per-peer ORR/Add-Path/ORF/
  peer-context policy) get pre-arc per-peer behavior plus #675/#672.
- Churn uses worst-case candidate density (1000 candidates/prefix);
  real tables have far fewer candidates per prefix.
- Session establishment (1000 concurrent OPEN handshakes over
  loopback) completed within the harness's 100 ms poll granularity in
  every run; establishment storms from slow or misbehaving remotes are
  not modeled.
- Single measurement per point (no repeat statistics). The 256-peer
  point independently reproduces the ADR-0098 number from a separate
  run on the same host (0.54 s there, 0.56 s here) — spread on this
  harness is small relative to the 27–32× deltas being demonstrated.

## Reproduction

The harness is a scratch crate (kept out of the repo; the receipt
pins its shape here). Structure: `RibManager::new` + `mgr.run()` on a
tokio runtime (12 workers), N `PeerHandle::spawn` RR-client sessions
dialing N `bench/evpn-load` stub listeners on distinct loopback IPs
(`127.0.x.y:20179`), route injection via `RibUpdate::RoutesReceived`,
a primary-channel `QueryLocRibCount` FIFO barrier for pacing,
`QueryAdjRibOutCounts` polling for the staged gauge, and stub-side
NLRI counting for the wire gauge. Scenario knobs:

```text
rrharness <flood|vpnflood|vpnfloodhet|churn> <n_peers> <n_prefixes> <churn_n> <secs> <out_prefix> [none|policy|mixed]
  flood: 100k cold flood + sustained fresh-block rounds for <secs>
  vpnflood: single-shot VPNv4 flood (distinct RDs, RTs from a 64-pool, no RTC)
  vpnfloodhet: RTC negotiated on every client, Φ = 6/64 RTs installed
          pre-flood; after convergence, a one-RT widen/narrow flip on
          client 0 timed to full wire decode (the Scenario E flip probe)
  churn: prime <n_peers> candidates × <churn_n> prefixes, then LP-flip waves for <secs>
  policy: M80 fixture export chain (tests/interop/configs/rustbgpd-m80-policy.rpol,
          customer-in(200) + edge-out) on every client
  mixed:  every 10th client gets a peer.asn-matching chain (update-group
          disqualifier -> per-peer fallback)
```

Two harness notes for reproducers: (1) synthetic AS paths must avoid
AS 65500 — the M80 fixture's `transit-guard` term rejects it and the
full-table convergence gauge will never complete; (2) fd budget is
~2 sockets per peer plus listeners — raise `ulimit -n` above ~4k for
1000 peers if your soft limit is the default 1024.
