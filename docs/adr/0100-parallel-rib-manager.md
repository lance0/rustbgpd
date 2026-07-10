# ADR-0100: Parallelizing the RibManager

**Status:** Proposed (research blueprint — not scheduled; execute via the staged slices below)
**Date:** 2026-07-03

**Repo:** rustbgpd, main ≥ `21a5ffaa`. Design only; nothing implemented.
**Inputs:** `docs/perf/scale-receipt-2026-07.md` (measured), scratchpad `cpu-flamegraph-2026-07-03.md` (measured), ADR-0098/0099 (invariants), code read at HEAD.

## 0. The measured starting point (facts, not estimates)

- 1000 RR clients × 100k routes cold convergence: **1.80 s staged / 1.82 s wire** (`docs/perf/scale-receipt-2026-07.md`, commit `b26ff11c`). Wire trails staged by ≤ 25 ms at every point → **the single-threaded manager task is the wall-clock gate**; the 1000 session tasks (prepare+encode 42%, writer 37% of RR CPU) already parallelize across cores and keep pace.
- Manager-task share of RR CPU post-arc: staging+AdjRibOut 14.4% + recompute 1.3% (+ ingest/events inside "other"). The manager is a **single pegged core**, not a CPU hog — it is a *serialization* bottleneck, not a cycles bottleneck.
- Scaling is ~linear in peers with no knee to 1000; ~linear in table size. The next order of magnitude (1M routes, or 5000 peers, or sub-500ms convergence) needs manager-side parallelism.
- **Critical unknown — RESOLVED (slice 0 executed, 2026-07):** the manager task's phase breakdown is now measured in [`docs/perf/rebaseline-2026-07.md`](../perf/rebaseline-2026-07.md). The §3 ASSUMED decomposition was wrong where it mattered: group staging eval is 3–10% of manager CPU (assumed 25–40%), while ingest+insert is 23–54% and the per-member emit tail (member try_send + shared-`Arc` refcount traffic) is 13–30%. The slice-0 kill criterion for (d) is met — see §6.

## 1. Parallelism inventory — what the code actually permits (verified)

Read: `crates/rib/src/manager/mod.rs` (actor struct + run loop, lines 87–339, 2780–3010), `distribution/mod.rs` (recompute + distribute, lines 780–1500), `update_groups.rs` (staging, lines 960–1230), `distribution/export_memo.rs`, `loc_rib.rs`, `adj_rib_in.rs`, `src/main.rs:1286–1425`.

**Per-prefix independence inside one pass — holds.**
- `distribute_single_best_prefix` (`distribution/unicast.rs:949`) is an associated fn taking `&LocRib`, `&AdjRibOut` (group table), `&HashMap<IpAddr,bool>`, `Option<&PolicyChain>`, `&mut ExportMemo`, and per-call output `Vec`s. No hidden `&mut self`. Same shape for `stage_vpn_routes`. Per-prefix evaluation reads only shared-immutable state.
- `PolicyChain` term-hit counters are **`AtomicU64`** (`crates/policy/src/eval.rs:38–52`, `Arc<PolicyHitCounters>` via `PolicyChain::share`) → concurrent evaluation is safe and counter totals stay exact (ordering of increments is irrelevant — they're aggregates, and ADR-0099 already carved counters out of stream-parity).
- `Route.attributes` is `Arc<Vec<PathAttribute>>` (interned per-peer in `AdjRibIn::attr_intern`, `adj_rib_in.rs:101`) — `Send + Sync`, clone is a refcount bump. Regex/as-path machinery in policy is `Sync`.
- **`ExportMemo` is the one non-Sync piece**: `FxHashMap` keyed on `Arc::as_ptr` (`export_memo.rs:36–66`). But `ExportMemo::apply` memoizes a **pure function** of `(source-attr identity, RouteModifications)` — its own doc says so — so *per-thread memos are correct by construction*; the only loss is cross-thread dedup (bounded: ≤ threads × distinct (source, mods) extra allocations per pass; the dhat receipt for #671 measured the win at attr-set granularity, and per-thread still captures the dominant sharing since routes with identical attrs cluster).
- Sequential-only state per pass: the group table commit (`GroupRibOut::apply_delta` — prefix-trie insert), `LocRib` writes, `unicast_prefix_peers` lazy prune (`recompute_best`'s `peers.retain`, `distribution/mod.rs:1067–1078`), route-event publish (ring + broadcast + monotonic `next_route_event_id`), per-peer `try_send` emit, metrics gauges. All of these are **apply/commit** steps that can run after a parallel **compute** step.
- `recompute_best_after_announce`/`recompute_best` split naturally: classification + winner selection is read-only over `ribs`/`loc_rib`/index; installation + event publish is the mutation. Two-phase (parallel classify, sequential ordered apply) preserves outputs exactly, with the index prune folded into the sequential phase.

**Family independence — holds with two named edges.**
`LocRib` is seven disjoint maps (`loc_rib.rs:21–41`): unicast (v4+v6 in ONE map), flowspec, evpn, bgpls, vpn, labeled, rtc. Cross-family edges: (1) **RTC → VPN**: SAFI-132 Adj-RIB-In mutations rebuild `RtcMembership` → `set_rt_membership` (single seam, `mod.rs:2500`) → membership-delta emit against the group VPN table (ADR-0099 D4). (2) **BGP-LS → ORR → unicast** (`recompute_orr` at every BGP-LS seam feeds per-vantage export). EVPN EAD/aliasing is intra-EVPN. Also **per-peer state spans families**: one outbound channel per peer carries all families in one `OutboundRouteUpdate`; dirty is per-peer across families (ADR-0099 D1, explicitly); GR/LLGR/refresh windows are per-(peer, family) but swept per peer.

**The emit funnel is already concurrent downstream.** Per-peer `mpsc` channels, transport sessions consume in parallel; manager-side emit is O(1)/member (Arc clone) since ADR-0098 D6. Nothing to win there.

**The load-bearing single-owner invariants**, verbatim: ADR-0099 D3 — "the single-task manager never interleaves the two mid-pass" (staging emit vs membership-delta); the distribute-coalesce partial-progress property (`mod.rs:281–302` doc comment: queries interleave *between* chunks and see accurate intermediate state); session-staleness gating assumes one task observes `PeerUp`/`PeerDown`/routes in channel order; the differential oracle (`manager/tests/update_groups_oracle.rs`) compares per-peer streams of two single-task managers.

## 2. Candidate architectures assessed

### (a) Family-sharded actors — REJECT as primary
One task per family group (RTC+VPN co-located, BGP-LS+unicast co-located because of ORR). Problems: speedup bounded by #active families and real workloads are one-family dominated (the flagship receipts are 100% unicast or 100% VPN — sharding buys ~1× there); per-peer lifecycle/dirty/EoR spans families → every `PeerUp`/`PeerDown`/dirty needs cross-actor coordination on the *hot* correctness paths (session-staleness, ADR-0099's per-peer dirty); the per-peer outbound message currently carries all families atomically. High invariant damage, near-zero win on the measured workloads.

### (b) Prefix-range sharding within a family — THE REAL SCALE ANSWER, staged behind a decision gate
N shard tasks, each owning `AdjRibIn` slices, its `LocRib` slice, its slice of every `GroupRibOut`, and its slice of the reverse index, for `hash(prefix) % N`. Session `RoutesReceived` batches split deterministically by prefix → per-(peer, prefix) inbound FIFO preserved (mpsc per-sender FIFO per shard). Each shard emits directly to per-peer channels (per-shard FIFO suffices for the ordering contract, §4). Prefix-local work — recompute, staging, source-flip emit, trie insert — scales ~linearly with shards; membership/lifecycle/policy-replace events broadcast to all shards through a coordinator that owns per-peer state and fences (§4). Costs: EoR/BoRR/EoRR barriers per (peer, family); dirty-resync coordination; scatter-gather queries (the partial-progress property becomes per-shard); the differential oracle and invariant checkers need rework (§5); ~every file in `manager/` touched. This invalidates and must re-argue the ADR-0099 D3 invariant — the argument survives *per shard* (each shard is a single task owning its prefix slice; staging emit and membership-delta for one prefix never interleave because one shard owns that prefix), which is exactly the re-derivation the oracles must then check.

### (c) Pipeline (decode→rib→stage→emit) — REJECT
Decode/encode already live in session tasks. Splitting rib-apply from staging into pipeline stages needs a Loc-RIB snapshot or hand-off per batch, caps at ~2× (two stages of comparable weight at best), and breaks the "staging reads the state the recompute just wrote" simplicity for a bounded prize. Dominated by (d) on cost and by (b) on ceiling.

### (d) Data-parallel hot loops inside the single actor — RECOMMENDED FIRST
Keep ONE logical owner, one message stream, one commit order. Inside a synchronous section of one pass (never across an `.await`), fork-join the per-prefix **compute**, then **apply sequentially in deterministic order**:

1. **Group staging** (`stage_group_prefixes`): snapshot the pass's prefixes into a `Vec` (this snapshot order becomes *the* pass order for both sequential and parallel modes); `par_chunks` → each worker runs `distribute_single_best_prefix` with a thread-local `ExportMemo` and per-prefix output structs (deltas + eval label + filtered keys — note: today's `out.evals.take_last()` per prefix restructures naturally into a per-prefix return); indexed collect preserves input order; then the existing sequential tail: `apply_delta` commits, tombstones, `build_shared_emit`, per-member emit. Same restructure for `stage_group_vpn_keys` (slice 4).
2. **Recompute** (`recompute_best`, `recompute_best_after_announce`): parallel phase computes per-prefix verdict + winner + prune decision read-only; sequential phase applies `loc_rib.recompute`, index prune, event publish, BMP synth in snapshot order. Outputs provably identical — the classification logic is unchanged, only *where* it runs moves.
3. **Per-peer fallback staging** (mixed fleets, Scenario D's 8.4 s): the same per-prefix restructure applies to the ungrouped path per peer — and independently, *peers* on the fallback path are independent of each other for the compute phase (each reads Loc-RIB + own AdjRibOut, writes own outputs) → parallelize across fallback peers. This attacks the "fleet scales with its fallback count" cost directly.

Actor model INTACT: message ordering, query interleave points, session-staleness, ADR-0099 D3, the partial-progress property, the explain dry-run, ADR-0073's per-session import cache (transport-side, untouched) — all unchanged. Oracles survive trivially (§5). Bounded by Amdahl on the manager's serial residue (ingest inserts, commits, emit, events).

**Runtime interaction:** the parallel section is synchronous (rayon `join`/`par_chunks` from within the async fn, no await held). The manager already occupies a tokio worker for multi-ms stretches per chunk; keep the existing chunking + `drain_queries` cadence for query latency. Use a dedicated rayon pool (size = config knob) so tokio workers aren't stolen; rayon is already vendored in `Cargo.lock` (criterion transitive) — it becomes a direct dep of `crates/rib` behind a cargo feature. Sequential cutoff: passes below ~256 prefixes skip the pool entirely (churn waves and small updates stay byte-for-byte on today's path, zero overhead).

**Config:** `[rib] parallel_workers = N` (default 0 = off, sequential path untouched), read once at construction like `TEST_INGEST_STALL_ENV`. A cargo feature `parallel-rib` gates the dependency; the knob gates behavior.

## 3. Recommendation and expected-speedup arithmetic

**Recommendation: (d) now, (b) designed but gated on (d)'s receipts and a named workload trigger.**

Arithmetic at 1000 peers × 100k, from the 1.80 s staged wall (manager-gated):

- MEASURED: sessions are not the gate (wire lag ≤ 25 ms); manager wall = staged wall.
- ASSUMED (slice 0 replaces): manager wall decomposes roughly as ingest+AdjRibIn insert+index ~20–30%, recompute+events ~15–25%, group staging eval+clone ~25–40%, group-table trie commit ~10–20%, emit+channel ~5–10%. Basis: pre-arc frames (trie insert and candidate scan dominated their buckets) and the post-arc collapse factors; explicitly not measured.
- (d) parallelizes: staging eval/clone + recompute classify + shared-emit build ≈ **45–60% of manager wall** at effective 8–16 threads → wall × (0.45 + 0.55/12) ≈ 0.5 → **~1.8–2.2×** (staged ~0.8–1.0 s). If the trie commit proves dominant and gets the internal-shard treatment (partition the group table's unicast maps by prefix hash — a data-structure change, not an actor change), parallel share rises to ~70% → **~2.5–3×** ceiling.
- (d) on Scenario D mixed fleets: the 100-peer fallback staging is embarrassingly parallel across peers → the 8.44 s convergence approaches (serial share + 6 s/12) ≈ **~3–4×** for mixed fleets — arguably the biggest honest win, since uniform fleets are already at 1.8 s.
- (b) at 16 shards: prefix-local work (ingest insert, recompute, staging, commit, emit) all shard-parallel; serial residue = coordinator fences + barriers, target <10% → **~6–8×** (staged ~0.25–0.3 s at 1000×100k), and — the real point — **~linear headroom in table size**: 1M routes × 1000 peers ≈ 2.5–3 s instead of ~18 s.
- Churn: post-#675 recompute is 1.6% — **(d) buys nothing on churn**; don't claim it.

**The BIRD 3 framing, honestly:** at 1.82 s / 1000 × 100k the current numbers already lead the field receipts on record. (b) is the competitive-frontier move; it should be executed against a named target (1M-route RR convergence, or a 5000-peer receipt), not speculatively. (d) is cheap, invariant-preserving, and de-risks (b) by forcing the per-prefix compute/commit separation (b) needs anyway — the slice-1 refactor is shared work.

## 4. Ordering/consistency contract (what any design must preserve)

Verified against RFC 4271/4724/7313 semantics and the code's own assumptions:

1. **Per-(peer, NLRI-key) monotonicity — REQUIRED.** A peer must never receive emissions for one key that regress staging order (RFC 4271 implicit-withdraw semantics make the *latest* UPDATE authoritative; reordering same-key updates advertises stale state). Today: single manager task + single mpsc/peer + transport FIFO. Under (d): unchanged (emit stays sequential on the actor). Under (b): one shard owns each key; per-shard emit order + mpsc per-sender FIFO ⇒ per-key FIFO holds. **This is the invariant a new checker must pin (§5).**
2. **Cross-key reorder is legal** (each NLRI independent to the receiver) — (b) exploits exactly this. But note the oracle currently asserts full per-peer stream equality; the *legal* contract is weaker than the *tested* contract. (d) keeps the tested contract; (b) must weaken the oracle deliberately (§5), never accidentally.
3. **Intra-message atomicity.** The source-flip matrix emits a flip's announce+withdraw in ONE `OutboundRouteUpdate` (`update.rs:27–67` — announce and withdraw ride together). Per-message atomicity must survive; under (b) a flip is single-prefix ⇒ single-shard ⇒ holds. The channel-full member-scoped-withdraw fix (ADR-0099 as-built #3) keys off the *send-failure seam* — per-shard sends keep that seam local.
4. **Barriers: EoR (RFC 4724) after the family's initial dump; BoRR/EoRR (RFC 7313) bracketing refresh responses; GR deferred-EoR ordering (`gr_deferred_eor`).** All are cross-prefix, per-(peer, family) fences. (d): unchanged. (b): needs a per-peer coordinator that releases the marker after all shards ack the dump/refresh slice — the single genuinely new ordering mechanism in (b).
5. **Lifecycle fencing.** `PeerUp`/`PeerDown`/session-staleness (`outbound_session_ids`, `live_sessions` collision handling, `mod.rs:97–115`) must be observed at one point in each shard's stream relative to that shard's route processing; (b) broadcasts lifecycle to shards through the coordinator with a sequence number, and staleness checks stay per-shard-deterministic.
6. **Queries.** Preserve: (i) query-between-chunks liveness (partial-progress property — PR3's deliberate design); (ii) Adj-RIB-Out views = "what we have staged/sent" consistency per peer. (d): identical. (b): queries scatter-gather; each shard's answer is internally consistent, the union is not a point-in-time cut. Consumers audit: `QueryLocRibCount` (harness pacing barrier — per-shard sum, fine), BMP loc-rib dump + MRT snapshot (want coherence; acceptable as per-shard-sequential dump given the already-accepted BMP dump→live overlap race, but must be stated in the ADR), gRPC list surfaces (eventual, fine), explain (single-prefix ⇒ single-shard, fine).
7. **Event streams.** Route-event history ids are monotonic process-local (`next_route_event_id`); (b) needs either coordinator-assigned ids (serialization point — cheap, events are post-commit) or per-shard streams merged at the sink. Decide in the (b) design pass; (d) unchanged.

## 5. Oracle survival plan

**Under (d):**
- All existing tests/oracles run unchanged with the knob off — the sequential path is not modified beyond the per-prefix output restructure (slice 1, which they gate).
- **Determinism by construction:** parallel collect is indexed over the same snapshot `Vec` the sequential path iterates ⇒ byte-identical outputs. (Run-to-run stream order already varies today — `pending_distribute_changed` is a std `HashSet` with `RandomState` — parallelism makes this no worse.)
- New: **seq-vs-par differential oracle** (mirror of `update_groups_oracle.rs`): drive identical scenarios through knob-off and knob-on managers, assert identical per-peer streams AND folded state. Reuse the existing scenario corpus wholesale.
- New: **CI leg running the full `crates/rib` suite with the knob forced on** (env var, like `test_force_ungrouped`'s pattern) — every existing oracle becomes a parallel oracle for free.
- New: same-scenario-twice determinism test with the knob on (catches accidental unordered collects).
- Not needed: loom/linearizability machinery — no locks, no shared mutable state in the parallel region; the compiler enforces the read-only fork via `&` borrows. Keep it that way (do-not-do #1).

**Under (b) (design obligations for the gate, not now):**
- Oracle weakens deliberately from full-stream equality to: per-(peer, key) subsequence equality + folded-state equality + barrier-position assertions (EoR after all covered routes). Write the comparator first; port scenarios second.
- The adv(m) invariant checker (ADR-0099 D3) recomputes per shard — the invariant statement survives shard-locally.
- New checker: **per-key monotonicity monitor** — test-build generation counter per staged key, asserted non-decreasing at the transport-boundary consumer.
- **Deterministic replay mode**: shards driven by a test scheduler (round-robin message pumping, seeded) so failures reproduce. This is the expensive new oracle; it is the price of (b) and belongs in its slice 1, not its slice N.

## 6. Slices for post-window execution (each independently landable, kill criteria attached)

- **Slice 0 — instrumented baseline (measure, no product code). DONE (2026-07, [`docs/perf/rebaseline-2026-07.md`](../perf/rebaseline-2026-07.md)). KILL CRITERION MET: skip (d).** Measured parallelizable share (staging-eval + recompute credited fully + emit-build): flood ~19–23%, churn ~9–16% — under 35% everywhere; the optimistic +commit extension clears 35% only on uniform flood (~35–43%, ≈1.5× Amdahl ceiling) and is dead on churn (~12–22%). Slices 1–3 are skipped as speedup vehicles (slice 1's compute/commit output restructure remains valid as (b) preparatory work). The (b) decision (slice 5) takes these numbers as input: prefix-local work (ingest+insert, recompute, commit, staging) is ~64–68% of manager CPU and the member-local emit tail another ~29–30% — shard-parallel or distributable under (b), where (d) could reach ≤ ~20%; the genuinely serial residue (event publish + bookkeeping) is under 6%.
- **Slice 1 — per-prefix output restructure (refactor, sequential, no flag).** `stage_group_prefixes` / `recompute_best*` restructured to compute-phase → ordered-apply-phase with per-prefix output structs (`take_last()` label capture becomes a per-prefix return). All oracles green, zero behavior change, A/B benchmark to prove no regression. **Kill:** >2% convergence regression → rework before proceeding.
- **Slice 2 — parallel compute behind `[rib] parallel_workers` (default off) + `parallel-rib` feature.** Thread-local `ExportMemo`s, dedicated rayon pool, ≤256-prefix sequential cutoff. Land the seq-vs-par oracle + knob-on CI leg + determinism test in the same PR. **Kill:** any oracle divergence not explained by the documented counter carve-outs → revert, root-cause before retry.
- **Slice 3 — measure and decide the default.** Same-host 3-run-median A/B (the `/bench` discipline): flood 256/1000 × 100k, mixed-fleet, churn (expect ~0 change), dhat pass for per-thread memo memory. **Kill:** < 1.3× staged wall at 1000×100k uniform AND < 1.5× on mixed-fleet → ship default-off as a scale knob, write the receipt, and jump to the (b) decision. **Ship:** ≥ 1.5× → flip default on after a 24 h churn soak (existing soak harness).
- **Slice 4 — extend where slice 0/3 indicts:** fallback-peer parallel staging (mixed fleets), VPN group staging twin, group-table internal sharding if commit dominates. Each with its own A/B. **Kill per item:** < 1.2× on its target scenario.
- **Slice 5 — the (b) decision gate.** Inputs: slice-3 receipts (the measured serial floor), a named workload target (e.g. 1M × 1000 or 5000 peers), and this doc's §4 barriers / §5 oracle obligations expanded into a full ADR. (b) proceeds only with a receipt-worthy target; otherwise the frontier claim rests on (d) + the existing arc.

## 7. Risks, ranked

1. **Amdahl disappointment** — post-arc the manager's parallelizable share may be small (staging already collapsed 1000×). Mitigation: slice 0 before any code; kill criteria are pre-committed numbers.
2. **Hidden `&mut` coupling in the export tail** — the `ExportTarget::Group { evals }` accumulator and label capture; anything similar found during slice 1 (e.g. metrics recorded mid-eval). Mitigation: slice 1 is a standalone sequential refactor where the compiler surfaces every coupling before threads exist.
3. **Oracle erosion by nondeterminism** — an unordered collect silently reorders streams and the oracle starts flapping. Mitigation: indexed collect rule, determinism test, knob-on CI leg.
4. **Query/latency regression** — long parallel sections monopolize the pass; queries still only interleave between chunks. Mitigation: keep chunk granularity and `drain_queries` cadence; measure membership-flip latency (the 15 ms receipt) in slice 3.
5. **Memory from per-thread memos** — bounded, but verify with dhat in slice 3 (policy-on scenario is the sensitive one).
6. **Two managers to reason about** (sequential + parallel modes) — mitigated the ADR-0098 way: one body, the mode is only *where* compute runs; the sequential mode is the oracle forever.
7. **(b) blast radius** — barriers, fences, scatter-gather, oracle rework across all of `manager/`. Mitigation: it is gated, and slice 1's compute/commit separation is shared preparatory work.
8. **Competitive overreach** — building (b) for BIRD-3 parity without a workload receipt. Mitigation: slice 5's named-target requirement.

## 8. Do-not-do list

- **Do NOT shard the actor while keeping shared mutable maps behind `RwLock`/dashmap** — destroys every single-owner invariant argument *and* adds contention; the worst point in the design space.
- **Do NOT shard by peer** — re-introduces per-peer staging, deleting the update-groups win (ADR-0098's entire prize).
- **Do NOT parallelize across route batches/chunks of different ingress peers in (d)** — changes recompute/event interleaving semantics the partial-progress property and event history depend on.
- **Do NOT move export-policy evaluation into session tasks** — it runs once per group now; transport-side eval re-multiplies it by peers (the measured pre-arc disaster).
- **Do NOT hold the fork-join across an `.await`** — the parallel region must be invisible to the actor's message granularity.
- **Do NOT let per-member state (Φ, dirty, ORF) into the shared parallel compute** — ADR-0099 D2/D3 depend on member state applying only at emit.
- **Do NOT build a transport-encode-sharing variant** — the flamegraph already killed it (~1.2× ceiling).
- **Do NOT touch the family twins (VPN/EVPN/labeled/LS) in slice 2** — unicast first, where the receipts are; twins follow the proven pattern in slice 4.

### Critical Files for Implementation
- crates/rib/src/manager/update_groups.rs — `stage_group_prefixes`/`stage_group_vpn_keys`, the compute/commit split target
- crates/rib/src/manager/distribution/mod.rs — `recompute_best*`, `distribute_changes`, the pass structure
- crates/rib/src/manager/distribution/unicast.rs — `distribute_single_best_prefix`, the shared export body that must stay `&`-parallel-safe
- crates/rib/src/manager/distribution/export_memo.rs — per-thread memo semantics
- crates/rib/src/manager/tests/update_groups_oracle.rs — the oracle pattern the seq-vs-par differential clones