# rustbgpd Roadmap

## What rustbgpd is

rustbgpd is an API-first BGP daemon written in Rust, shipping in a public
v0.x alpha. It is a BGP-only control plane — not a full routing suite — built
around a gRPC-first mutation/query surface (with mTLS + tier authorization),
Prometheus metrics, structured logs, and a reusable, fuzzed wire codec
(`rustbgpd-wire`, published on crates.io). It runs as a Route Reflector and as
an EVPN VXLAN VTEP / IRB speaker (alpha), with Rust's memory safety and
predictable, GC-free performance under load. The goal is to be the best
programmable BGP control plane for data-center fabrics, route servers, and
automation-heavy environments — not to replace FRR or BIRD as a complete
routing suite. v1.0 is not on a timeline: the core programmable-control-plane
path is feature-complete by the criteria that matter, and the project keeps
shipping focused v0.x cuts; real-world deployment feedback, if it materializes,
will reshape priorities.

---

## Status at a glance

Shipped = production-usable in the v0.x posture. Partial = alpha or a
deliberately-scoped subset. Planned = on the roadmap below. For the detailed
vs-FRR/GoBGP/BIRD/OpenBGPD breakdown, see
[docs/COMPARISON.md](docs/COMPARISON.md) and
[docs/gobgp-parity.md](docs/gobgp-parity.md) — this table does not duplicate
those.

| Area | Status | Notes |
|------|--------|-------|
| BGP core (RFC 4271 FSM, 4-byte ASN, capabilities, collision detection) | Shipped | All 6 states, property-tested |
| Address families: IPv4/IPv6 unicast (MP-BGP, RFC 4760) | Shipped | Dual-stack, FRR-interop validated |
| Extensions: Add-Path (7911), Extended Messages (8654), Extended Nexthop (8950) | Shipped | |
| Graceful Restart (4724) + LLGR (9494) + Notification GR (8538) | Shipped | Helper + minimal restarting speaker |
| Route Refresh (2918) + Enhanced Route Refresh (7313) | Shipped | |
| BGP Roles + Only-to-Customer (9234) | Shipped | Static eBGP, IPv4/IPv6 unicast (ADR-0071, M55) |
| BGP unnumbered / IPv6 link-local peering | Shipped | Static interface-bound link-local (ADR-0069, M53) |
| Confederation (5065) | Planned | |
| EVPN-VXLAN: Route Reflector (7432, types 1–5) | Shipped | |
| EVPN-VXLAN: single-homed VTEP (Type-2 / Type-3 IMET origination, FDB program) | Partial (alpha) | Linux/VXLAN only |
| EVPN-VXLAN: multi-homing (ESI, Type-1/4, DF election, BUM suppression, aliasing ECMP) | Partial (alpha) | Production-default enforcement with opt-out |
| EVPN-VXLAN: symmetric IRB (Type-5 / L3VNI, 9136 §4.4.2) | Partial (alpha) | Receive-side overlay-index recursion shipped |
| FIB / dataplane: unicast Linux FIB install, ECMP, weighted multipath, BLACKHOLE discard | Shipped | Opt-in `[[fib_tables]]` (ADR-0061/0066/0068) |
| Security: TCP MD5, GTSM, static TCP-AO, native gRPC mTLS + tier authz | Shipped | TCP-AO BIRD-interop (M43); ADR-0064 authz |
| RPKI origin validation (6811 + 8210) | Shipped | RTR client, VRP table, policy match |
| ASPA verification | Shipped | RTR v2, role-aware upstream/downstream verification, policy match |
| Policy: prefix lists, named chains, actions, community/AS_PATH/validation match | Shipped | GoBGP-style chain evaluation |
| BFD single-hop async + RFC 5882 coupling | Shipped | M51 |
| Observability & API: gRPC (11 services), Prometheus, structured logs, durable event history | Shipped | ADR-0072 outbox + `SubscribeFromEvent` |
| gNMI / OpenConfig telemetry (read-only) | Partial | `Get` / `Subscribe`, BGP state subset; `Set` planned (M54/M56) |
| BMP exporter (7854), MRT dump (6396) | Shipped | EVPN + unicast |
| FlowSpec (8955/8956, IPv4/IPv6) | Shipped | All 13 component types |

For per-release feature deltas see [CHANGELOG.md](CHANGELOG.md); for the
build-order history see [docs/milestones.md](docs/milestones.md).

### Where rustbgpd fits

The BGP daemon space is dominated by monolithic C implementations that bundle
BGP with OSPF, IS-IS, and every other routing protocol. GoBGP proved that an
API-first, gRPC-driven BGP daemon is what operators want; rustbgpd keeps that
shape while using Rust's predictable, GC-free memory model and shipping a
reusable codec. Observability and automation — Prometheus metrics, structured
JSON logs, machine-parseable errors, gRPC-first paths, reproducible interop
gates — are first-class product surface, not afterthoughts.

| Project | Language | Model | Strengths | Gaps |
|---------|----------|-------|-----------|------|
| FRR | C | Full routing suite | Feature-complete, wide adoption, production FIB / EVPN depth | Monolith, CLI-first, limited API |
| BIRD | C | Full routing suite / route-server mainstay | Excellent filter language, lightweight, BIRD 3 multithreading, TCP-AO | CLI-first, no native gRPC |
| OpenBGPD | C | BGP-only | Clean design, OpenBSD pedigree | Limited platform support, no API |
| GoBGP | Go | BGP-only, gRPC API | API-first, Zebra/FIB, EVPN, broad library docs | GC runtime, Go-specific protos |

Target users: cloud and AI-scale data-center fabric operators, network
automation teams, IX / route-server operators, and whitebox / lab users who
want an API-first BGP daemon with memory safety and predictable performance.

---

## Roadmap

One prioritized, forward-looking list. Items are grouped **Next** (committed
near-term), **Later** (planned, not yet scheduled), and **Maybe /
demand-shaped** (deferred until operator signal). The current priority call is
to finish the transaction surface and improve operational proof. Protocol
breadth and additional performance work stay measurement- or demand-shaped.

Prioritization is **technical-merit first, pilot-aware second**: lead with work
that deepens rustbgpd's existing identity (a programmable BGP control plane),
and use real-operator credibility only as a tie-breaker between
technically-equal options — never as a reason to chase breadth rustbgpd doesn't
need. Every major feature should leave behind **pilot-grade evidence** (interop,
soak, or bench receipts), because credibility is a technical artifact, not
marketing. Concretely: no speculative service-provider breadth just because FRR
has it, no broad performance sprints without profile evidence.

### Next

- **Config transaction coverage + OpenConfig bridge** *(highest priority,
  ADR-0076 foundation shipped).* Native gRPC now has validate-only planning,
  optimistic snapshot tokens, commit/apply/confirm/abort/status, persistence
  acknowledgement, and rollback for the v1 committable families. **Done:**
  established dynamic peers now keep the canonical longest-prefix-match range
  that accepted them, pure dynamic-range policy moves now reuse the
  resolved-policy live executor with Route Refresh gating and captured rollback
  state, and static peer-group/session reshapes now rebuild affected sessions
  with captured prior configs. **Done:** the gNMI `Set` bridge now maps
  supported OpenConfig changes into candidate TOML and feeds this transaction
  model rather than inventing a parallel commit primitive; it provides redacted
  audit summaries, delete / replace / update normalization, response shaping,
  daemon hook wiring, and a first static numbered BGP neighbor subset for
  `neighbor-address` / `peer-as` / `description` / `peer-group`. Next slices:
  standard gNMI commit-confirmed extension handling and operator proof with
  `gnmic` examples / smoke coverage. Exit: atomic commit where supported,
  explicit restart-required/rejected surfaces, rollback/receipt model, no
  partial silent drift. Gated by ADR-0064 tier authz.
- **Operational proof / scale automation** *(parallel priority, small slices).*
  Re-stand the proof loop that makes the v0.x posture credible: a continuous
  churn/soak shape, automated or easy-to-trigger Criterion comparisons on the
  `[self-hosted, rustbgpd-bench]` runner, and a fixed high-N memory harness for
  regressions that `memory_profile` no longer scales to. **Done:** bounded
  `bgp_config_transaction_lifecycle_total{operation,outcome}` exposes confirmed
  transaction confirm / abort / auto-revert failures without unbounded labels
  (`confirm_id`, candidate content, and error text stay out of Prometheus).
  Exit: one repeatable soak result operators can inspect, bench comparison
  receipts for perf PRs, and memory tracking that covers full-table scale
  without relying only on bgperf2.
- **MPLS / VPN / BGP-LS address-family ADR** *(done — implementation remains
  deferred).* ADR-0077 draws the address-family-expansion boundaries while the
  substrate is still small: a control-plane AFI/SAFI route-key model for
  VPNv4/v6 (RFC 4364 / RFC 4659), labeled-unicast (RFC 8277), Route Target
  Constraints (RFC 4684), and BGP-LS (RFC 9552, which obsoletes RFC 7752), with
  BGP-LS *export* and route-reflector-only VPN/MPLS families as the on-identity
  entry points (controller-feed / RR, not a forwarding plane). **Explicit
  non-goal, stated up front: rustbgpd does not install MPLS labels in the
  dataplane** — these are BGP-carried families, not a step toward a full MPLS
  router (see Non-goals). The ADR also preserves the ORF Address-Prefix guard:
  only IPv4/IPv6 unicast entries are parsed today, and future VPN/MPLS-family
  ORF support must be family-specific. Implementation stays demand-shaped (see
  *Out-of-niche address families* under Maybe).

### Later

- **FIB operational hardening** *(decision gate — pull only
  operator-confidence pieces).* ADR-0061/0066/0068 cover configured-table
  install, ECMP, per-class caps, `multipath_relax`, and Link Bandwidth
  weighting; the next pain points are lifecycle and scale, not base
  capability. **Done:** hot-swap `[[fib_tables]]` without a restart — SIGHUP
  soft-reload and gRPC/`rustbgpctl fib-table` CRUD (`SetFibTable` /
  `DeleteFibTable` / `ListFibTables`), ack-gated with no runtime/config drift.
  Decide based on signal: over-cap detail APIs beyond the sampled
  `route_limit_exceeded` rows. Defer unless perf-gated or demanded: incremental
  equal-cost sibling index for wide full-table multipath; platform-diversity
  interop for weighted multipath.
- **ASPA verification — test hardening.** Role-aware upstream/downstream
  verification now ships with the draft-v25 first-AS precondition, §6.2
  IPv4/IPv6-unicast family gate, best-path preference, and
  `match_aspa_validation` import/export policy. Direct policy-match unit coverage
  now pins all ASPA verdicts plus combined RPKI+ASPA predicates. Remaining
  hardening is external-vector breadth rather than feature scope: import
  NIST-BRIO ASPA vectors when they are easy to automate.
- **EVPN standards tail.** Native overlay-index Type-5 local origination +
  protected recursion-path interop smoke; multi-homed-gateway ECMP; single-active
  backup-path pre-install (proactive receive-side backup VTEP next-hop so
  failover is sub-second instead of waiting for BGP reconvergence — single-active
  is correct today, just reconvergence-speed); a cross-vendor preference-DF smoke
  against FRR; runtime mixed-edit composer (the remaining non-teardown
  add+delete/redefine shape that fails closed today). Demand-shaped; keep as
  follow-up inventory.
- **EVPN Linux VTEP hardening.** VLAN-aware bridge support; rustbgpd-managed
  bridge / VXLAN / VRF netdev creation; `RTNLGRP_LINK` eventing instead of
  poll-only link inventory; learned-port-to-ESI disambiguation so one local VNI
  can participate in multiple Ethernet Segments. Low-priority operational polish
  once core convergence is complete.
- **Policy / explain follow-ups** *(operator polish, not feature).* Stable
  `reason` labels across the remaining ingress filter paths; per-feature counter
  unit-test coverage; per-statement attribution within a matched import chain
  (the `rustbgpctl policy explain --neighbor X --prefix Y` decision trace itself
  shipped in v0.31.0, ADR-0073); best-path explain surfacing the tiebreaker step
  that won (RIB-side sibling to the export-side policy-clause attribution).
  Also: named-policy / statement identity in explain output; verbose policy
  trace including non-match steps; route history / why-changed timeline;
  looking-glass integration for explain; `rustbgpd --diff` output formatted by
  reload class (cross-reference each diff line against `docs/reload-matrix.md`).
- **Performance — remaining items.** The scale & memory sprint shipped
  (inlined `SmallVec<[u32; 1]>` Adj-RIB-In prefix index, FxHash route maps,
  coalesced multi-chunk initial-load distribution; #306/#308/#309), as did the
  bulk-initial-load and pinned-bench compare tooling. The inbound UPDATE path now
  does one policy-context scan (`PolicyAttrSummary`) and shares the canonical
  attribute `Arc` across same-UPDATE NLRI when policy makes no modifications
  (`RouteAttrBundle` / `materialize_attrs`), cutting per-UPDATE attribute-clone
  churn. Cold-start BGP reconnect also retries the first TCP-level dial misses
  quickly before returning to the slower exponential guard, reducing boot-order
  establishment delay when rustbgpd starts before passive peers. Remaining
  backlog, in rough priority order. Near-term performance/polish targets are
  the remaining FIB projection table-name ownership and high-volume CLI / JSON
  serializer allocation cleanups.
  - FIB projection: shipped the configured-table policy precompile so
    `allowed_neighbors` is parsed once per projection pass and peer /
    peer-group membership checks reuse prebuilt sets. The new root
    `fib_projection` Criterion bench covers tables × candidates × ECMP width
    behind the `bench-internals` feature. Remaining possible cleanup:
    table-name ownership in projected status/drop rows, if a future profile
    shows those allocations matter enough to justify changing the data shape.
  - API route listing: shipped the API-service cleanup that fuses family
    filtering, route filters, pagination, and `route_to_proto` response
    construction into one pass over the RIB snapshot; canonical large-community
    filters now compare typed values instead of allocating a per-route
    `Vec<String>`. Remaining: CLI route JSON still maps proto routes into a
    second owned `JsonRoute` tree before serialization; replace that with
    borrowed/streaming serializers if route-list JSON output shows up in
    profiles.
  - RPKI validation: shipped the bucketed VRP lookup index and RFC 6811
    `maxLength` correctness fix, replacing the linear VRP scan with an
    ancestor-bucket lookup while preserving overlapping-VRP semantics. Cache
    updates now also trigger targeted inbound refresh for established peers
    whose resolved import policy matches RPKI/ASPA state, so previously denied
    routes can be reconsidered after VRP/ASPA changes. The
    `bgp_validation_import_refreshes_total{dependency, outcome}` metric now
    exposes the cache-triggered refresh work. Remaining follow-up, only if
    operator scale justifies it: parallelize or otherwise de-block the per-peer
    refresh loop for very large validation-dependent peer sets.
  - Export-policy AS_PATH formatting: shipped in #340 — the export-policy
    evaluator no longer calls `AsPath::to_aspath_string()` for every export
    candidate unless the effective export policy contains an AS_PATH-regex match,
    gated by the `export_policy_eval` bench's eager-vs-lazy arms (~45 ns/route
    saved on a no-AS_PATH-regex chain). `AS_SET` / empty-path formatting is
    preserved when the string is needed; the import path still renders it
    (event / OTC attribution). A cached `requires_as_path_string` flag is
    deferred until `PolicyChain` stops exposing directly mutable `policies`;
    constructor-only caching would otherwise risk stale derived state when
    implicit import policies are appended.
  - Transport max-prefix accounting: shipped — sessions keep a per-prefix
    refcount beside the Add-Path `(prefix, path_id)` set, so max-prefix
    enforcement and state queries count unique unicast prefixes without
    rebuilding a temporary set after every UPDATE. Add-Path multiplicity remains
    correct: multiple path IDs for one prefix still count as one prefix.
  - Policy engine matching: the cheap-predicate short-circuit landed —
    `PolicyStatement::matches` now evaluates predicates cheapest-first with early
    returns, so a cheap match failure skips the AS_PATH regex and community scan
    entirely (`policy_predicate_eval` bench: a regex-bearing statement drops from
    ~80 ns to ~27 ns and a 64-community statement from ~51 ns to ~27 ns per
    route-statement when a cheaper predicate fails first; the regex is confirmed
    the costliest predicate, so "regex last" is the right order). The bundled
    prefix-mask / `ge`-`le` precompute is **deferred**: the `prefix_heavy` bench
    measures full prefix evaluation at ~4.4 ns per statement, so a build-time
    precompute would shave ~1-2 ns — below the bench noise floor and not worth
    the ~66-site `PolicyStatement` construction churn. Revisit only if a future
    `prefix_heavy` run shows prefix matching as a real bottleneck.
  - Export-policy fanout batching: investigate whether peers with identical
    effective export policy/context can share evaluation results during full
    dirty resyncs or route-server fanout. Design-gated: peer address/ASN/group,
    negotiated family, route type, RPKI/ASPA state, policy counters,
    `policy_filtered_routes`, and export modifications all affect correctness.
    The manager-level `fanout` Criterion bench shipped in #350 and is the
    baseline: first-advertise distribution is ~178 ns per advertisement with no
    policy, and a cheap scalar-guard export chain adds ~18%. Use that harness
    for any batching/coalescing PR, adding heavy-policy variants if the proposed
    optimization targets AS_PATH-regex or large-community chains.
  - Adj-RIB-In attribute interning: explore storing a stable fingerprint beside
    interned `Arc<Vec<PathAttribute>>` sets to avoid hashing every attribute on
    each insert, with full equality fallback. Gate on `adj_rib_in_insert`,
    `bulk_initial_load`, and churn benches across typical, rich, and
    many-unique attribute sets; do not regress the memory win from interning.
  - General FIB runtime: investigate prefix-dirty reconcile so a single prefix
    change does not necessarily trigger full RIB query + full kernel dump +
    full projection. Design-gated because drift recovery, ECMP siblings,
    peer-group allow-lists, and max-route freeze semantics are non-local.
  - EVPN dataplane supervisor: move from periodic whole-EVPN-RIB
    query/project/equality suppression toward generation/dirty-driven
    projection. Design-gated because EAD mass-withdraw, aliasing, quarantine,
    and IP-VRF config changes can invalidate more than one route key.
  - Add-Path export: avoid sorting all candidate paths when `send_max` is small
    if deterministic ordering and export-policy filtering can be preserved.
  - Session establishment tuning: expose connect-retry timing as per-neighbor /
    peer-group config if operators need it, and only then consider widening FSM
    timer actions from whole seconds to `Duration` for sub-second retry floors.
    The current fixed fast path covers refused TCP dials during boot ordering;
    timeout-bound unreachable peers and protocol/config failures deliberately
    stay on slower guards.
  - Explain cache: store pre-policy attributes behind `Arc<Vec<PathAttribute>>`
    when `[policy.explain]` is enabled, matching the route-storage sharing model
    and avoiding a deep attr clone per explained NLRI.
  - Wire codec NLRI allocation cleanup: remove the non-AddPath IPv4 body-NLRI
    decode-then-map temporary `Vec` in `Update::parse` / build paths if codec
    benches show a clear win at bulk sizes. Low blast radius, but gate on
    `update_parse` / `update_build` and decode/proptest coverage.
  - Wire community storage: investigate `SmallVec` for standard / extended /
    large community attribute payloads only if `size_of::<PathAttribute>` does
    not grow and codec / `memory_profile` runs show a real transient-allocation
    or unique-attribute win. Public `rustbgpd-wire` API churn makes this
    measurement-gated.
  - CLI/API JSON outside route listing: the CLI JSON error path is hardened —
    runtime serializers now return `CliError::Json` instead of panicking on
    `serde_json` failures. Remaining work here is allocation/data-shape cleanup:
    after the route-listing cleanup, apply the same borrowed `Serialize` wrapper
    / direct serializer pattern to high-volume event and telemetry JSON so the
    CLI and API do not build a second owned JSON tree from already-owned
    proto/event data.
  - Benchmark infrastructure: automatic per-PR CI bench triggering on the pinned
    `[self-hosted, rustbgpd-bench]` runner (the manual `Criterion Bench Compare`
    workflow exists); a continuous churn bench (short criterion variant of the
    M33 soak shape); and `memory_profile` high-N harness non-scaling.
  - `best_path_cmp`: root-cause the ~6% full-tiebreak regression. The common
    LOCAL_PREF early-exit is unaffected (~1 ns/comparison, dwarfed by the
    -40-62% insert/pipeline wins), and a single-pass attribute summary was
    measured flat (+0.01%), so route accessor rescans are not currently a
    proven lever. Reopen only with profile evidence, long-AS_PATH benches, or a
    clear ladder-level culprit (RPKI/ASPA/cluster/originator steps).
  - Do-not-chase-until-proven list: reshaping `MP_REACH_NLRI` / `MP_UNREACH_NLRI`
    to avoid unused empty `Vec` fields is public wire-API churn and `vec![]`
    itself does not allocate; a general policy evaluation-result cache carries
    high invalidation risk — with AS_PATH laziness (#340) and predicate
    short-circuiting (#343) now landed and measured, the cheap policy wins are
    already captured, so a result cache stays deferred on invalidation-risk
    grounds unless a profile shows policy evaluation is still hot.
  The bgperf2 cross-stack comparison was refreshed for v0.32.0 (full-daemon RSS
  dropped ~21% from the inbound clone-churn fix, but now exceeds GoBGP's ~203 MB
  at 200k; see `docs/BENCHMARKS.md`), and that re-run drove the **v0.32.0
  event-history default flip to opt-in / off** (done — the always-on outbox cost
  ~62 MB RSS + ~2× peak CPU at 2p/100k). Later whole-daemon dhat profiling
  showed the durable heap is dominated by the three-layer RIB route/index
  storage, especially hash bucket arrays, not operational surfaces. Stage-1
  trie-backed prefix indexes shipped; the larger LocRib trie swap remains
  deferred because the naive version regressed recompute. Shared route storage
  was measured and rejected — see Deferred.
- **AIGP best-path support (RFC 7311).** Standards completeness for deployments
  that carry accumulated IGP cost in BGP — the one best-path step we don't
  implement (the chain is otherwise 11/11). Not a headline feature unless
  operators ask.
- **Conditional advertisement.** Policy feature for advertise-if-present /
  advertise-if-absent workflows (FRR and GoBGP have it). Useful and common, but
  less tied to the current positioning than ORF — defer until operator demand is
  clearer.

### Maybe / demand-shaped

- **TCP-AO dynamic / rotation polish.** Static TCP-AO + BIRD interop (M43) are
  shipped. Dynamic-neighbor wildcard-MKT design, runtime key rotation /
  multi-key rollover, and public accepted-socket inspection / observability
  matter to some route-server / security operators but are demand-shaped, not
  core-feature blockers.
- **ORF / Outbound Route Filtering follow-ups.** Receive-side Address-Prefix ORF
  (capability code 3, type 64; ADR-0075) is shipped and closes the IX
  route-server control-plane gap for clients pushing filters to rustbgpd.
  Send-side ORF (rustbgpd pushing filters to upstreams) and advertising legacy
  Cisco type 128 stay deferred pending operator demand; type 128 is accepted on
  decode only today.
- **Confederation (RFC 5065).** Required for service-provider deployments, but
  SPs are not the initial target market. (Unblocks several deferred RFC 9234
  confederation-scope items and the RFC 8326 confederation gating.)
- **Out-of-niche address families.** L3VPN (VPNv4/v6, RFC 4364 / RFC 4659),
  labeled-unicast (RFC 8277), Route Target Constraints (RFC 4684), BGP-LS
  (RFC 9552, obsoleting RFC 7752 / RFC 9029), SR Policy / SRv6 (RFC 9514),
  IPv4/v6 multicast, VPLS. This is the dominant AFI-count gap vs FRR / GoBGP,
  but it is entirely service-provider / traffic-engineering / full-router scope —
  outside rustbgpd's fabric / route-server / automation niche. Demand-shaped:
  pursuing them is a deliberate strategic pivot, not parity-chasing. (Of these,
  BGP-LS *export* is the closest fit to the API-first / controller story if a
  controller-integration headline ever materializes.) When adding VPN/MPLS-family
  support, extend the ORF Address-Prefix decoder deliberately: it currently
  parses only IPv4/IPv6 unicast and preserves L2VPN / unknown SAFIs as raw ORF
  groups to avoid silently applying plain-IP prefix semantics to future families.
- **Route dampening (RFC 2439).** Suppress flapping routes with penalty/decay.
- **Scriptable policy engine.** User-defined attribute-transformation functions
  (Lua, Starlark, or WASM) beyond static match/action rules. Policy evaluation
  is already a pure `(route, context) -> (action, modifications)` function, so
  sandboxing a scripting layer there would be clean — more expressive than FRR
  route-maps, simpler than BIRD's filter DSL. Post-v1 per Non-goals.
- **Observability future extensions.** Richer per-MAC EVPN dataplane event
  categories; WatchRoutes missed-event signaling if it gains an envelope;
  precomputed dataplane summary counters / watch channels if status-snapshot
  polling becomes expensive; subscription-side indexing or a dedicated event bus
  if subscriber count / event rate makes post-broadcast filtering expensive; a
  TUI live event view.
- **EVPN adjacent standards.** PBB-EVPN (RFC 7623), EVPN-MVPN integration
  (RFC 9251, route types 6/7/8), RFC 9572 BUM segmentation (types 9/10/11), EVPN
  optimized ingress replication (RFC 9574), tunnel aggregation / common labels
  (RFC 9573), multihoming split-horizon for non-VXLAN tunnel families (RFC 9746),
  Proxy ARP/ND extended-community behavior (RFC 9161 / RFC 9047), MPLS/SRv6
  encapsulation, EVPN VPWS / E-Tree service models, Add-Path for EVPN (RFC 9252).
  Service-provider EVPN use cases.
- **Evaluate buffa for protobuf codegen.** Anthropic's
  [buffa](https://github.com/anthropics/buffa) is a pure-Rust protobuf
  implementation with editions-first design, zero-copy views, and `no_std`
  support. Benchmark against prost/tonic for encode/decode and type ergonomics;
  needs a tonic codec adapter (buffa has no gRPC transport layer).
- **gNMI breadth.** `Set` + config datastore mapping onto ADR-0076 candidate
  transactions, per-family/per-neighbor counters, negotiated-capability state,
  wider encodings/AFIs, and BFD / FIB / EVPN OpenConfig-adjacent surfaces — each
  lands on demand or when the underlying snapshot exposes the data. Itemized
  under the ADR-0070 counterpart in Deferred. YANG / NETCONF / RESTCONF stays
  deprioritized — gNMI is the telemetry-first surface.

---

## Deferred (with rationale)

These have explicit rationale and, where noted, are the roadmap counterpart of
an ADR "Deferred" section that points back here. Tightened, not dropped.

- **Shared route storage / compact RIB indexing — measured, rejected
  (2026-05-29).** The realistic policy-robust `RouteData` split (identity shared
  via `Arc`; attributes + next-hop kept per-copy so per-client export policy
  still shares identity) clears only ~5–13% of route-reflector heap, well under
  the ≥25% gate, for the largest `&Route`-consumer blast radius in the codebase.
  The naive `Arc<Route>` whole-shell share would reach ~31–37% but is
  unachievable (the per-RIB-mutable stale/validation flags can't be shared).
  Harness at `crates/rib/tests/route_data_sharing_profile.rs`; see BENCHMARKS.md.
  The shipped scale/memory wins came from trie-backed prefix indexes, inlined
  SmallVec path-id lists, FxHash route maps, and coalesced multi-chunk
  distribution instead.

- **EVPN VXLAN local-bias split-horizon (remaining all-active correctness
  gate).** RFC 8365 §8.3.1: a DF must drop BUM whose VXLAN overlay source is an
  ES-peer VTEP while still flooding other BUM and forwarding known unicast.
  ADR-0065's netns spike confirmed this is not achievable with stateless
  `tc-flower` on the standard bridged-VXLAN softswitch — the overlay source is
  not visible to `tc` at the VXLAN ingress hook (the FRR #15400 failure mode) —
  so it is ASIC/offload-dependent. The only remaining softswitch avenue
  (underlay-ingress eBPF with per-MAC state, or `collect_metadata` VXLAN) is a
  separate ADR if demand appears. The shipped multi-homing enforcement is
  role-based DF/non-DF BUM suppression + aliasing ECMP, not source-conditioned
  local-bias.

- **RFC 9234 (BGP Roles + OTC) follow-ups** *(ADR-0071 counterpart).* None
  blocking — v1 ships static eBGP Role config + IPv4/IPv6 unicast OTC, proven by
  M55. Deferred: iBGP Roles (RFC §4 scopes Roles to eBGP; iBGP would need
  working-group semantics first); AS Confederation sub-AS Roles (RFC marks NOT
  RECOMMENDED; if confederation later exports OTC across the boundary, the OTC
  ASN MUST be the Confederation Identifier per §5 — captured so the future
  implementer doesn't recreate the trap); complex peering on a single eBGP
  session (RFC: MUST NOT mix Peer/Customer roles on one session; split into
  multiple sessions today); dynamic role change without session restart
  (`role` / `strict_role` is live-effective-next-session in
  `docs/reload-matrix.md`; in-place re-evaluation needs Route-Refresh +
  revalidation + a compatibility-matrix replay look); operator override of OTC
  behavior (forced egress strip, per-neighbor opt-out — config sugar over the
  policy engine, deliberately not in v1); OTC scope beyond IPv4/IPv6 unicast
  (RFC §5 scopes it to AFI 1/2 SAFI 1; the egress hook would land in the
  FlowSpec / EVPN attribute-prep paths if a future RFC extends it).

- **gNMI / OpenConfig follow-ups** *(ADR-0070 counterpart).* v1 ships read-only
  `Capabilities` / `Get` / `Subscribe` (`ONCE` / `POLL` / `STREAM SAMPLE`) over
  the strict OpenConfig BGP state subset, plus `ON_CHANGE` for the neighbor
  session-state leaf (M54/M56), plus a first transaction-backed `Set` subset for
  static numbered BGP neighbor config. Deferred until the underlying snapshot
  exposes the data or demand appears: broader `Set` config subsets beyond static
  neighbors; per-AFI-SAFI prefix counters; per-neighbor
  installed/accepted split; `supported-capabilities` + negotiated AFI-SAFI;
  global total-prefixes/total-paths; absolute `last-established`; `PROTO` /
  `ASCII` encodings, multicast / VPN AFIs, full OpenConfig coverage; BFD / FIB /
  EVPN OpenConfig-adjacent surfaces; YANG / NETCONF / RESTCONF (deprioritized).

- **RFC 8326 confederation gating.** When confederations land, the EBGP gate
  inside `effective_policy_chains_for_neighbor` (currently
  `remote_asn != self.global.asn`) needs an explicit `is_external_neighbor()`
  helper aware of confederation sub-AS topology. The current gate is correct for
  the traditional EBGP/iBGP topology today.

- **Wire / API strictness items.** Typed error variants for API deletion
  handlers (today deletion matches `error.contains("still referenced")` —
  fragile string coupling); unknown FlowSpec component forward-compatibility
  (component types >13 hard-error today; should skip-to-allow future RFC
  extensions); large-community duplicate normalization on receipt/encode (stored
  and re-advertised unchanged today); ERR-window / pending-refresh-stale gauges;
  inbound BoRR/EoRR retry on channel-full (dropped-with-warning today, unlike
  outbound which has `pending_refresh` retry); MRT snapshot encode allocation
  pressure on very large dumps; BMP periodic-stats scalability (serial
  `query_state().await` per peer) and BMP client connect-loop shutdown
  observation; SIGHUP reconcile rollback semantics (reports structured per-peer
  failures and keeps the prior snapshot, but does not roll back already-applied
  runtime peer changes); dynamic-neighbor `handle_inbound` split for readability;
  config snippets / examples in gRPC validation error detail.

---

## Engineering velocity / tech debt

Cross-cutting cleanups that don't move user-facing capability on their own but
lower the cost of every future PR. None block a release — grab one when your
branch is between features.

- [ ] **Doc-collision discipline for `ROADMAP.md` / `CHANGELOG.md` /
  `docs/evpn-alpha-soak.md` / `docs/evpn-enablement.md`.** Multi-PR batches keep
  conflicting on the same handful of rows. Lighter-touch fixes: append-only
  convention for `[Unreleased]` (newest entry at the bottom of its subsection),
  separate "shipped this PR" sentences rather than rewriting summary prose, one
  row per concern in the roadmap. Heavier option if drift continues: a
  structured manifest the docs are generated from.
- [ ] **Test fixture extraction into a shared `test-support` surface.** Helpers
  like `route_event`, `session_event`, `policy_event`, `lifecycle_event`, and
  the per-test config builders have drifted across `crates/api`, `crates/cli`,
  `crates/rib`, and `src/`. A field addition (e.g. `event_id`) forces touching
  three or four copies. A single `rustbgpd-test-support` crate (or a
  re-exported `pub mod test_support` per crate) would centralize them.
- [ ] **`unwrap()` audit on daemon-runtime paths.** Production-code unwraps
  outside `#[cfg(test)]` measure at ~5 sites after the v0.30 quality scan
  (TLS-cert reads downstream of validated `is_some()`, one const `try_from`
  cast, a few defensive parses of already-validated strings). Kept open as a
  forcing function when these stragglers come up for refactor; not blocking.
- [x] **`panic!` → typed-error sweep on the one production site.**
  `crates/bfd/src/discriminator.rs` now returns a typed discriminator-exhaustion
  error instead of panicking. The daemon logs and refuses to install the new BFD
  session if the 32-bit non-zero discriminator space is ever exhausted.
- [ ] **Stringly command errors → typed errors where API status depends on
  class.** PR #334 introduced `DynamicRangeError` so
  `AddDynamicNeighbor` / `DeleteDynamicNeighbor` can map duplicate, not-found,
  and invalid-input failures to stable gRPC status codes without parsing error
  strings. ADR-0076 transaction planning uses a typed stale-snapshot /
  invalid-candidate error for gRPC status mapping, and `StageConfigSnapshot`
  now returns typed candidate-validation vs previous-snapshot-serialization
  errors to the transaction executor. Older peer-manager / RIB commands still
  commonly return
  `Result<_, String>`; keep that for one-status surfaces, but migrate to small
  typed enums when a caller needs to distinguish `ALREADY_EXISTS`, `NOT_FOUND`,
  `INVALID_ARGUMENT`, or similar API-visible classes.
- [x] **Config transaction live-impact policy / peer-group executor.**
  Policy definitions, `neighbor_sets`, `peer_groups`, and global named
  policy-chain edits that move existing static neighbors' or accepted dynamic
  peers' resolved import/export policy chains now commit as transactions: stage
  the candidate snapshot, re-apply resolved chains to affected live sessions
  with captured priors, persist with ack, and restore live chains plus the
  snapshot on failure.
- [x] **Config transaction static peer-group/session reshape executor.**
  Peer-group field edits and static-neighbor peer-group reassignments that
  reshape existing static sessions now commit as transactions: stage the
  candidate snapshot, reconfigure affected peers with captured prior configs,
  persist with ack, and restore live peers plus the snapshot on failure.
  Dynamic-range session reshapes remain deferred until accepted dynamic sessions
  can be targeted with equivalent rollback semantics.
- [x] **Config transaction commit-confirmed core.**
  `ApplyConfigTransaction` can now enter a singleton pending-confirm state with
  `confirm_id` and a bounded confirm timer. Confirm makes the change permanent;
  abort or timer expiry rolls back by applying the captured pre-commit runtime
  snapshot through the same transaction executor. Persisted runtime config
  mutators are fenced while a confirmed transaction is applying or pending.
- [x] **`rustbgpctl` commit-confirmed workflow.**
  The CLI can now run safe deploys end to end: `config apply --confirm-id
  --confirm-timeout`, `config status`, `config confirm`, and `config abort`
  expose the confirmed transaction lifecycle with text and JSON output.
- [x] **Config transaction catalog snapshot executor.** ADR-0076 can now commit
  catalog-only policy definitions, policy `neighbor_sets`, `peer_groups`, and
  global named policy-chain assignments under the same
  reserve/stage/persist-ack/rollback ordering used by full-snapshot
  dynamic-neighbor transactions, while routing pure resolved-policy impact to
  the live-policy executor and rejecting broader inheritance/session impact.
- [x] **Config transaction static-neighbor resolution scaling.**
  Static-neighbor add/modify transactions now resolve only the touched
  `[[neighbors]]` entries through the same single-neighbor inheritance path,
  instead of resolving the full candidate neighbor set and then selecting the
  added or changed peers.
- [x] **Peer-manager add-without-start path for disabled reconfigure.**
  Static-neighbor modify, SIGHUP changed-peer reconcile, and peer-group
  hot-apply now rebuild a disabled peer as disabled, without transient session
  start. Enabled peers still start immediately unless strict BFD withholds them.
- [x] **SIGHUP baseline from live runtime snapshot.** SIGHUP now reads the peer
  manager's current runtime snapshot after taking the runtime-config coordinator
  lock, so a reload queued behind a committed transaction starts from the
  transaction-updated baseline instead of main.rs' stale process-local copy.
- [x] **SIGHUP reconcile for `[[dynamic_neighbors]]` TOML edits (#338).**
  `ReplaceConfigSnapshot` rebuilds the live accept matcher, `--diff` classifies
  direct TOML edits as reload-applied, and runtime dynamic-neighbor CRUD shares
  the runtime-config coordinator lock with SIGHUP through config-persistence
  acknowledgement. Persistence rejection rolls the runtime matcher back instead
  of letting it drift ahead of disk.
- [x] **Static neighbor CRUD persistence/SIGHUP serialization.**
  `AddNeighbor` / `DeleteNeighbor` now share the runtime-config coordinator
  lock with SIGHUP through config-persistence acknowledgement. Persistence
  rejection rolls the accepted runtime mutation back, completing the same
  lock/ack/rollback invariant used by FIB-table and dynamic-neighbor CRUD.
- [ ] **`#[expect(clippy::too_many_lines)]` reduction.** ~30 suppressions
  workspace-wide (down from 94). Concentrated in long dispatchers (FSM action
  loop, EVPN reconcilers, encode/decode match arms). Some are honest match-heavy
  dispatch; track the absolute count downward release over release rather than
  gating individual PRs.
- [ ] **`#[allow(clippy::too_many_arguments)]` cluster tidy-up.** ~25 sites —
  RIB distribution functions, EVPN originators, BFD socket setup. A
  `DistributionContext` parameter struct would absorb the metric / policy
  threading; same trick fits the EVPN originators.
- [ ] **`#[allow(clippy::result_large_err)]` in `crates/api/src/rib_service.rs`.**
  6 suppressions for a large `Result<_, RibServiceError>` enum. Box the error
  variant only if it shows up in a benchmark or RIB query hot-path; cosmetic
  until then.
- [ ] **Measurement-gated hash-map hasher audit.** The durable unicast RIB
  storage now uses `FxHashMap` / trie-backed prefix indexes, but manager,
  route-refresh, EVPN, RPKI, config, and API support paths still contain
  ordinary `std::collections::HashMap` / `HashSet` sites. Do **not** bulk-convert
  them: keep std's randomized hasher for config/API/user-keyed surfaces unless a
  benchmark or heap profile identifies a hot, bounded, internal map. Candidate
  follow-ups are RIB-manager temporary prefix/peer sets and other
  non-adversarial control-plane maps that show up in `dhat` or Criterion.
- [ ] **CI gate: `#[allow(clippy::*)]` requires `reason = "..."`.** ~171
  escape-hatches workspace-wide (~40 are `cast_possible_truncation` in the wire
  codec, intentional after a length check). A CI lint that rejects new
  `#[allow(clippy::*)]` without an explicit `reason` arg; backfill one crate at a
  time.
- [ ] **`cargo deny` for license / dependency / advisory audit.** Resurrect the
  stale `chore/dependabot-and-cargo-audit` branch, modernize to `cargo deny check
  advisories bans licenses sources`, and wire into CI. Pairs with the next
  dependency audit.
- [ ] **Workspace `cargo doc` warning posture.** CI runs
  `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --lib --no-deps`; keep that
  as the standing local pre-flight expectation so broken intra-doc links surface
  on the developer machine rather than at PR time. `--lib` keeps the root
  daemon bin out of the doc target set (avoiding the lib/bin same-name collision);
  Cargo's default job parallelism is intentionally left enabled so rustdoc does
  not serialize the whole workspace.
- [ ] **Mega-module splits.** The large `src/` modules have been split, but
  `crates/api/src/event_service.rs` remains borderline. Keep splitting only where
  it reduces real conflict or review cost.

---

## Non-goals / scope

rustbgpd is an API-first BGP daemon. The following are explicitly out of scope:

- **Full routing suite.** No OSPF, IS-IS, LDP, RSVP-TE, PIM, or MPLS dataplane
  control plane. This is a BGP daemon. BGP-carried MPLS/VPN families
  (labeled-unicast, VPNv4/v6, EVPN MPLS encapsulation) are demand-shaped
  address-family breadth, not a commitment to become a full MPLS router.
- **CLI-first operation.** The gRPC API is the primary interface; the CLI and
  TUI are polished convenience wrappers, but gRPC is the contract.
- **GoBGP proto compatibility.** Our protos are our own. A compat adapter can
  exist as a separate project if anyone wants it.
- **Windows support.** Linux is the target; macOS for dev builds only.
- **Full web UI / dashboard.** Grafana + Prometheus is the monitoring story; the
  built-in looking glass is read-only JSON for NOC integration. (Market research
  shows IXPs use external presentation layers — Alice-LG, IXP Manager — so a
  built-in web UI is not a differentiator.)
- **Plugin system in v1.** Policy is built-in and minimal; WASM/DSL plugins are
  post-v1 if the core is stable enough to warrant them.
- **Kubernetes operator.** Adjacent opportunity but premature; nail the IX/SDN
  use case first.

If you need these features, combine rustbgpd with purpose-built tools.

---

## Pointers

- **[CHANGELOG.md](CHANGELOG.md)** — per-release shipped detail and feature
  deltas.
- **[docs/milestones.md](docs/milestones.md)** — build-order history (the
  M0–M9 initial milestones plus the post-v0.1 feature history relocated from
  this roadmap).
- **[docs/INTEROP.md](docs/INTEROP.md)** — the full M-NN interop test matrix.
  The automated scripts cover the M-series against FRR 10.3.1, BIRD 2.0.12 /
  3.2.1, GoBGP 4.3.0, and StayRTR; M0 (FRR, BIRD) are manual smokes. Privileged
  kernel-dataplane smokes (EVPN VTEP / IRB, FIB, BFD, TCP-AO — M36–M53) run in
  the hosted `kernel-dataplane` workflow; large-scale churn (M33) is a manual
  soak harness under `tests/soak/`.
- **[docs/COMPARISON.md](docs/COMPARISON.md)** + **[docs/gobgp-parity.md](docs/gobgp-parity.md)**
  — the detailed competitive / parity tables vs FRR, BIRD, GoBGP, OpenBGPD.
- **[docs/evpn-enablement.md](docs/evpn-enablement.md)** — the EVPN enablement
  guide. **[docs/evpn-alpha-soak.md](docs/evpn-alpha-soak.md)** —
  EVPN alpha-soak status and remaining follow-ups.
- **[docs/BENCHMARKS.md](docs/BENCHMARKS.md)** — convergence, CPU, and memory results
  (bgperf2 vs BIRD / GoBGP; criterion micro-benches) with methodology and the
  noise-floor stamp.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — development setup, code style, and PR
  process. Issues labeled `good first issue` are good entry points.

### Infrastructure

GitHub Actions CI (fmt / clippy / test on every push/PR), nightly wire-decoder
fuzz CI, a multi-stage Docker image, containerlab interop topologies, automated
M-series interop scripts, cross-compiled linux-amd64/arm64 binary releases, and
crates.io publishing for `rustbgpd-wire` (other crates remain internal). Open
infrastructure item: a Homebrew formula.
