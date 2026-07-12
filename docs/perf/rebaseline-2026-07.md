# Post-update-groups re-baseline: manager phases + memory attribution — 2026-07

Two measurements the July perf arc left open, both taken at commit
`e6ed41fe` (post-update-groups v2, post-writer-coalescing #788):

1. **ADR-0100 slice 0** — the RIB-manager task's own CPU phase
   breakdown, which every speedup estimate in that ADR flagged as
   "ASSUMED". Verdict against the pre-committed kill criteria below.
2. **Whole-daemon memory attribution at 2 peers × 100k** (the
   `BENCHMARKS.md`/`COMPARISON.md` headline shape) — the previous
   attribution (2026-06-02: "~76% bucket arrays, Adj-RIB-Out largest")
   predates the update-groups arc that deleted per-peer unicast
   Adj-RIB-Out for grouped members. Nothing current attributed the
   246 MB figure. Verdict for the memory program (slab-storage premise)
   below.

> **Reproducibility status:** the tables below are retained as historical
> decision evidence, but they are not a revision-reproducible receipt. The CPU
> harness was reconstructed and committed after `e6ed41fe`, and the original
> folded profiles, classifier, DHAT derivative, and same-run CSV were not
> archived. Do not compare a new run against these values as if it were the
> same-revision baseline. The replacement procedure, deterministic mappings,
> fixtures, and artifact contract are committed in
> [`bench/scale/rebaseline/README.md`](../../bench/scale/rebaseline/README.md);
> a replacement table must pin one measured source SHA and archive the
> checksummed artifacts produced from that exact checkout.

## Environment

| Field | Value |
|---|---|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores / 64 threads), 125 GiB RAM |
| Kernel | Linux 6.17.0-35-generic |
| Build (CPU harness) | `--release`, `debug = 1` |
| Build (memory) | `--profile release-prof --features dhat-heap` (bgperf2 `profile='dhat'` image) |
| Load discipline | every measured run gated on 1-min loadavg < 2.0 before start; per-run load logged (all runs started at 0.09–1.99; the harness itself is the only load during a run) |

Durable numbers here are the *shares* (phase percentages, attribution
percentages); absolute walls and rates are host-specific and quoted
only to anchor the shares.

## Part 1 — ADR-0100 slice 0: manager-task phase table

### Method

The 2026-07-03 rrharness was reconstructed as a committed harness
(`bench/scale/rrharness/`, a standalone crate kept out of the
workspace) in a **manager-direct** variant:

- the real `RibManager` (`RibManager::new` + `mgr.run()`, cluster-id
  set) runs alone on a dedicated OS thread named `ribmgr` under a
  current_thread tokio runtime — every sample on that thread is
  manager-task work, no bucketing heuristics needed;
- N iBGP RR clients are registered via `RibUpdate::PeerUp` (IPv4
  unicast, no policy, one update group verified by the profile itself:
  all staging goes through `stage_group_prefixes`); their bounded
  outbound channels (capacity 8192) are drained by trivial counter
  tasks on a separate 12-worker runtime;
- routes are injected via `RibUpdate::RoutesReceived` (1000-route
  batches, `session_id 0` ingress emitters, 4 flood sources / N churn
  sources), staged gauge via `QueryAdjRibOutCounts` polling, drained
  gauge via per-message NLRI counting at the consumers;
- profiler: in-process pprof at 997 Hz (unprivileged `perf` is blocked
  on this host), samples filtered to the `ribmgr` thread, classified
  leaf-first by owning function into the ADR-0100 slice-0 phases;
- manager busy fraction cross-checked against
  `/proc/self/task/<tid>/stat` CPU time for the window.

**What this variant does not measure:** transport sessions do not
exist in-process, so prepare/encode/writer costs (42% + 37% of RR CPU
in the full-pipeline receipt, `scale-receipt-2026-07.md`) are absent
by construction. That is the point: slice 0 attributes the manager
task alone, and the manager's inbound/outbound seams (channel
messages) are identical in both variants. Consequences to keep in
mind: no wire backpressure (channels never fill → always the fast
emit path), and absolute walls are faster than the full-pipeline
receipt (e.g. cold flood 256×100k staged in 0.31 s here vs 0.56 s
there).

Scenarios (each run twice, back to back; both runs shown — spread is
the honest error bar):

- **flood** — cold-converge 100k IPv4 /24s, then sustained fresh-100k
  blocks for 20 s under the profiler (the profiled window), at 256 and
  1000 clients.
- **churn** — prime N candidate sources × 3000 prefixes (N candidates
  per prefix), then LOCAL_PREF-rotation flap waves (every wave = 3000
  best-path flips fanned to all clients) for 20 s under the profiler,
  at 256×256 and 1000×1000.

### Phase table — sustained flood (fresh-block ingest + full fanout)

Share of ribmgr-thread CPU samples during the 20 s window:

| Phase | 256 clients (run A / B) | 1000 clients (run A / B) |
|---|---|---|
| ingest + Adj-RIB-In insert (incl. intern, announcer index) | 33.3% / 35.0% | 28.3% / 23.4% |
| recompute (best-path select + install; classify not separable at sample level) | 19.5% / 19.1% | 17.9% / 14.5% |
| group-table commit (`apply_delta`) | 19.2% / 19.4% | 18.2% / 13.4% |
| member-emit (`emit_group_deltas_for_member` + try_send) | 7.1% / 6.1% | 11.4% / 20.4% |
| distribute residual (per-peer loop, pass-scoped memo setup, **shared-`Arc` refcount traffic**) | 6.5% / 5.9% | 12.0% / 16.9% |
| event-publish (route-event ring + broadcast) | 5.4% / 5.4% | 5.1% / 4.3% |
| staging walk (`stage_group_prefixes` residual) | 4.1% / 4.1% | 3.2% / 3.1% |
| staging eval (`distribute_single_best_prefix`, export tail) | 3.2% / 3.4% | 2.5% / 2.6% |
| shared-emit build | 0.9% / 0.8% | 0.7% / 0.6% |
| other | 0.9% / 0.9% | 0.9% / 0.8% |

Manager busy fraction during the window: 0.97–0.99 (pegged core,
confirming the full-pipeline receipt's "the manager is the wall-clock
gate"). Blocks delivered in 20 s: 50/51 (256), 37/33 (1000).

The 1000-client A/B spread on member-emit vs table-commit (the two
trade ~7 points) tracks allocator/map-capacity state (end-RSS differed
4955 vs 2891 MiB after ~3.6M cumulative prefixes); the phase
*aggregates* the verdict uses are stable across both runs.

### Phase table — churn (1000 candidates/prefix worst case)

| Phase | 256×256 (A / B) | 1000×1000 (A / B) |
|---|---|---|
| ingest + Adj-RIB-In insert | 50.3% / 49.2% | 54.2% / 54.3% |
| member-emit | 8.8% / 8.5% | 14.7% / 14.7% |
| distribute residual | 9.0% / 8.8% | 14.2% / 14.1% |
| recompute | 7.3% / 7.4% | 4.4% / 4.8% |
| staging eval | 7.2% / 7.3% | 3.4% / 3.2% |
| event-publish | 5.6% / 6.1% | 2.2% / 2.3% |
| group-table commit | 5.1% / 5.8% | 3.3% / 2.8% |
| staging walk | 3.4% / 3.7% | 2.0% / 2.1% |
| shared-emit build | 1.9% / 2.0% | 0.9% / 0.9% |
| other | 1.5% / 1.5% | 0.9% / 0.9% |

Waves delivered: ~142/s (256), ~56/s (1000) — 3000 flips per wave,
each fanned to every client (168k flips/s at 1000 clients,
manager-direct). Manager busy fraction 0.74–0.82 (wave pacing waits on
full fan-out drain). Recompute at 4.4–7.4% independently confirms the
#675 incremental-best-path receipt at worst-case candidate density.

Sub-attribution worth recording (leaf histograms):

- **distribute residual is dominated by `Arc` refcount traffic**: at
  1000 clients, ~23% `fetch_sub`/drop + ~20% `fetch_add`/clone of the
  shared announce payload, plus ~16% pass-scoped `ExportMemo`
  construction. Together with member-emit this is a per-member O(N)
  emit tail of 13–30% of manager CPU depending on shape.
- **ingest+insert** is memcpy + hash/trie insert + attr-intern
  (FxHasher over `Arc<Vec<PathAttribute>>`) — prefix-local work.
- **recompute and table-commit** are memcpy/hash dominated
  (Route clones into Loc-RIB and the group table) — prefix-local.

### Verdict against the ADR-0100 slice-0 kill criteria

The ADR's (d) proposal parallelizes **staging-eval +
recompute-classify + shared-emit-build**, with group-table commit as
an optional internal-sharding extension. Pre-committed kill line:
parallelizable phases < 35% of manager wall → skip (d).

Crediting *all* of recompute as classify (upper bound — install/event
share cannot be separated at sample level and is certainly not zero):

| Scenario | eval + recompute + emit-build | + commit (optimistic extension) |
|---|---|---|
| flood 256 | ~23% | ~43% |
| flood 1000 | ~19% | ~35% |
| churn 256 | ~16% | ~22% |
| churn 1000 | ~9% | ~12% |

**Kill criterion met. Skip the (d) parallel-compute slices
(slices 1–3 as speedup vehicles).** Without commit sharding, no
scenario reaches 35%; Amdahl at 12 effective threads gives ≤ 1.24×
(flood-1000) — under the slice-3 1.3× kill line before any overhead.
The optimistic commit-sharding extension clears 35% only on the
uniform flood (≈ 1.5× ceiling) and is decisively dead on churn
(~12%), which the ADR itself predicted ("(d) buys nothing on churn —
don't claim it").

What the assumed decomposition (ADR §3) got wrong, now measured: group
staging eval+clone was assumed 25–40% of manager wall; post-arc it is
**3–10%** — ADR-0098/0099 collapsed it so thoroughly that the
fork-join prize evaporated. The manager's cycles actually go to
**ingest+insert (23–54%)**, the **per-member emit tail (13–30%,
`Arc` refcounts + per-member try_send)**, and **prefix-local
recompute/commit (8–37% combined)** — all of which shard by prefix or
by member, none of which fork-join inside a pass.

**Consequence for the (b) decision (ADR §6 slice 5):** these numbers
are the input the gate asked for. Prefix-local work (ingest +
recompute + commit + staging) is **~64% at flood-1000 and ~68% at
churn-1000**; the member-local emit tail is another **~29–30%**; the
genuinely serial residue (event publish + bookkeeping) is **under
6%**. Prefix-range sharding attacks the first bucket and distributes
the second, where (d) attacked ≤ ~20%. The emit tail also suggests a
cheaper standalone lever — emit-side offload (moving the per-member
`Arc` clone + try_send loop off the hot task) — which was out of
scope for (d) as specified.

Slice-1's compute/commit output restructure remains useful *as (b)
preparatory work only* — not as a speedup vehicle.

## Part 2 — whole-daemon memory attribution at 2p × 100k

### Method

The `BENCHMARKS.md` "Heap profiling with dhat" workflow, re-run at
this commit: bgperf2 `profile='dhat'` image built `nocache` from this
tree, `bench -t rustbgpd -n 2 -p 100000` (2 BIRD testers × ~100k
distinct prefixes each → ~200k-route Loc-RIB, 1 GoBGP monitor
receiving the full table — the `COMPARISON.md` headline shape),
SIGTERM to the daemon after convergence (graceful shutdown drops the
profiler → `dhat-heap.json`), attribution by live-bytes-at-t-gmax per
allocation stack. Single capture (structural map capacities are
deterministic for a fixed route count); the same-run harness CSV
reported 253 MB max RSS, consistent with the 246 MB headline row
(2026-07-09) plus dhat jitter.

### Live heap at peak, by component (218.5 MiB tracked)

| Component | live at peak | share |
|---|---:|---:|
| **Group RIB-Out table** (ADR-0098 shared staging table: route map + delta bookkeeping) | 69.8 MiB | 32.0% |
| **Loc-RIB best-path map** | 42.3 MiB | 19.3% |
| **Adj-RIB-In route map** (incl. attr intern) | 28.7 MiB | 13.1% |
| Transport known-path memory (per-session inbound path map) | 14.5 MiB | 6.6% |
| Announcing-peers index (`unicast_prefix_peers`, #675) | 14.3 MiB | 6.5% |
| Transport session buffers/scratch (in-flight `Vec<Route>` batches) | 13.7 MiB | 6.3% |
| Prefix-trie index — Adj-RIB-In | 10.3 MiB | 4.7% |
| Prefix-trie index — group table | 8.0 MiB | 3.7% |
| Daemon core (fixed channel capacity, e.g. 4096-slot event broadcasts) | 4.9 MiB | 2.3% |
| Transport import-decision cache (ADR-0073) | 4.8 MiB | 2.2% |
| RIB other | 4.5 MiB | 2.1% |
| API / peer-manager | 2.3 MiB | 1.1% |
| **Per-peer Adj-RIB-Out** | **0.2 MiB** | **0.1%** |
| Telemetry / tokio / rest | 0.2 MiB | 0.1% |

Top single allocation sites are hashbrown `resize_inner` bucket
arrays: 57.4 MiB (group-table route map, via
`GroupRibOut::apply_delta` → `AdjRibOut::insert`), 42.3 MiB (Loc-RIB
map via `LocRib::recompute`), 28.7 MiB (Adj-RIB-In map).

### What changed vs the 2026-06-02 attribution

| 2026-06-02 claim (pre-update-groups) | Now |
|---|---|
| Per-peer **Adj-RIB-Out route map ~86 MB + its index ~29 MB — the single largest component** | **Gone: 0.2 MiB.** The downstream peer is a (1-member) update group; its advertised state is the shared group table (69.8 MiB incl. bookkeeping + 8.0 MiB trie) — the structure no longer scales with peer count (ADR-0098 Decision 4, now proven at the operator-facing shape) |
| "~76% RIB map/index bucket storage" | **Still true, redistributed: ~79%** (group table 32.0 + Loc-RIB 19.3 + Adj-RIB-In 13.1 + tries 8.4 + announcing-peers index 6.5) |
| Operational surfaces negligible (<1 MB) | Still negligible; but **transport-side per-session memory is now visible: ~15%** (known-path memory 6.6% + session scratch 6.3% + import cache 2.2%) — it was previously drowned out by the per-peer Adj-RIB-Out |

### Verdict — the slab-storage premise (memory program gate)

**Holds, with a re-aimed target list.** The dominant allocations are
still prefix-keyed hashbrown bucket arrays holding inline `Route`
values — ~65% of tracked heap across the three route maps (group
table, Loc-RIB, Adj-RIB-In) plus ~15% in their side indexes. Any
slab/arena storage work should aim at those three maps. Two
corrections to any plan written against the old attribution:

1. **Per-peer Adj-RIB-Out is not a target anymore** — it does not
   exist for grouped peers. Plans quoting the "~115 MB Adj-RIB-Out"
   figure must re-point at the *group table* (one instance per group,
   not per peer — the leverage per byte saved is correspondingly
   lower at high fanout, but it is the largest single map at 2p).
2. The **announcing-peers index (14.3 MiB) and transport known-path
   memory (14.5 MiB)** are new, individually visible line items at
   this scale — each comparable to the whole Adj-RIB-In trie index —
   and were invisible in the 2026-06-02 profile.

## Reproduction

CPU harness (`bench/scale/rrharness/`, a standalone crate kept out of
the workspace; shape pinned above): modes
`flood <n_clients> <n_prefixes> <secs> <out>` and
`churn <n_clients> <n_cand> <n_prefixes> <secs> <out>`; folded-stack
output per run classified by the committed leaf-first mapping in
`bench/scale/rebaseline/classify_cpu.py`. Build with
`cd bench/scale/rrharness && cargo build --release`, then run
`./target/release/rrharness <mode> <args>`. Runs:

```text
rrharness flood 256  100000 20 flood-256-{a,b}
rrharness flood 1000 100000 20 flood-1000-{a,b}
rrharness churn 256  256  3000 20 churn-256-{a,b}
rrharness churn 1000 1000 3000 20 churn-1000-{a,b}
```

Memory pass: the `BENCHMARKS.md` "Heap profiling with dhat" workflow
verbatim (bgperf2 `profile='dhat'` image built `nocache` from this
commit, `bench -t rustbgpd -n 2 -p 100000`, SIGTERM to the daemon
after convergence — dhat records the live-at-peak snapshot at t-gmax
regardless — `dhat-heap.json` extracted from the target container),
run with nothing else on the host.

This historical command sketch is insufficient for a replacement receipt on
its own. Follow the artifact naming, load gate, manifest, sanitization,
classification, and checksum steps in `bench/scale/rebaseline/README.md`.
