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
| ASPA verification | Partial | Upstream-path verification (RTR v2); downstream/customer-cone planned |
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
demand-shaped** (deferred until operator signal). The performance / scale /
memory / CI-benchmark phase that headlined the previous cycle has largely
shipped — see [CHANGELOG.md](CHANGELOG.md) and the "Performance" note under
Later for what remains.

### Next

- **Config transaction model and runtime/file diff UX** *(decision gate —
  start or defer, do not bundle into polish).* gRPC owns truth after startup,
  and a future gNMI `Set` requires transaction semantics. `Set` is a stable
  `UNIMPLEMENTED` contract today, so deferring breaks no operator promise.
  Decide explicitly: start as the next major feature, or declare mutation
  surfaces out of scope for this cycle. Exit: candidate config object,
  validate-only, diff against live effective runtime, atomic commit where
  supported, explicit restart-required surfaces, rollback/receipt model, no
  partial silent drift. Gated by ADR-0064 tier authz.
- **FIB operational hardening** *(decision gate — pull only
  operator-confidence pieces).* ADR-0061/0066/0068 cover configured-table
  install, ECMP, per-class caps, `multipath_relax`, and Link Bandwidth
  weighting; the next pain points are lifecycle and scale, not base
  capability. In scope now: hot-swap `[[fib_tables]]` (operator confidence).
  Decide based on signal: over-cap detail APIs beyond the sampled
  `route_limit_exceeded` rows. Defer unless perf-gated or demanded: incremental
  equal-cost sibling index for wide full-table multipath; platform-diversity
  interop for weighted multipath.

### Later

- **ASPA verification — full scope.** Upstream-path verification ships
  (`ValidationSnapshot`, `match_aspa_validation` import policy, draft-v25 §5.4
  algorithm fidelity + §6.2 per-AFI/SAFI gate, #294). Extend toward the full
  draft-ietf-sidrops-aspa-verification scope (downstream / customer-cone) as
  ASPA reaches GA across RIRs (ARIN Jan 2026, RIPE production, APNIC Q2 2026),
  matching BIRD / OpenBGPD router-side verification; pairs with BGP Roles as the
  2026 route-leak-prevention bundle for the MANRS / IXP audience. Remaining gaps
  (deferred, not blocking): draft v25 §5.4 step 2 first-AS precondition (no
  `enforce-first-as`-equivalent today); NIST-BRIO test vector import;
  `match_aspa_validation` import/export policy-match unit coverage.
- **Convergent import validation on cache update.** Import
  `match_rpki_validation` / `match_aspa_validation` is best-effort at ingress;
  later VRP/ASPA cache updates do not re-run import policy. Fix: on cache
  update, trigger `SoftResetIn` for peers whose resolved import policy uses
  validation-state matches (infrastructure exists). Not urgent — current
  semantics match FRR/BIRD and are documented in `KNOWN_ISSUES.md`.
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
  bulk-initial-load and pinned-bench compare tooling. Remaining: automatic
  per-PR CI bench triggering on the pinned `[self-hosted, rustbgpd-bench]`
  runner (the manual `Criterion Bench Compare` workflow exists); a continuous
  churn bench (short criterion variant of the M33 soak shape); root-cause the
  `best_path_cmp` ~6% full-tiebreak regression (the common LOCAL_PREF early-exit
  is unaffected; ~1 ns/comparison, dwarfed by the −40–62% insert/pipeline wins);
  fix the `memory_profile` high-N harness non-scaling; and a fresh bgperf2
  cross-stack comparison on current `main` (BIRD/GoBGP columns are a v0.4.2
  snapshot). Shared route storage was measured and rejected — see Deferred.

### Maybe / demand-shaped

- **TCP-AO dynamic / rotation polish.** Static TCP-AO + BIRD interop (M43) are
  shipped. Dynamic-neighbor wildcard-MKT design, runtime key rotation /
  multi-key rollover, and accepted-socket inspection / observability matter to
  some route-server / security operators but are demand-shaped, not core-feature
  blockers.
- **Confederation (RFC 5065).** Required for service-provider deployments, but
  SPs are not the initial target market. (Unblocks several deferred RFC 9234
  confederation-scope items and the RFC 8326 confederation gating.)
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
- **gNMI breadth.** `Set` + config datastore, per-family/per-neighbor counters,
  negotiated-capability state, wider encodings/AFIs, and BFD / FIB / EVPN
  OpenConfig-adjacent surfaces — each lands on demand or when the underlying
  snapshot exposes the data. Itemized under the ADR-0070 counterpart in Deferred.
  YANG / NETCONF / RESTCONF stays deprioritized — gNMI is the telemetry-first
  surface.

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
  The shipped scale/memory wins came from the inlined SmallVec prefix index,
  FxHash route maps, and coalesced multi-chunk distribution instead.

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
  session-state leaf (M54/M56). Deferred until the underlying snapshot exposes
  the data or demand appears: `Set` + config datastore (gated on the
  config-transaction model); per-AFI-SAFI prefix counters; per-neighbor
  installed/accepted split; `supported-capabilities` + negotiated AFI-SAFI;
  global total-prefixes/total-paths; absolute `last-established`; `PROTO` /
  `ASCII` encodings, multicast / VPN AFIs, full OpenConfig coverage; BFD / FIB /
  EVPN OpenConfig-adjacent surfaces; YANG / NETCONF / RESTCONF (deprioritized).

- **RFC 8326 confederation gating.** When confederations land, the EBGP gate
  inside `effective_policy_chains_for_neighbor` (currently
  `remote_asn != self.global.asn`) needs an explicit `is_external_neighbor()`
  helper aware of confederation sub-AS topology. The current gate is correct for
  the traditional EBGP/iBGP topology today; tracked in `KNOWN_ISSUES.md`.

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
- [ ] **`panic!` → typed-error sweep on the one production site.**
  `crates/bfd/src/discriminator.rs` panics on discriminator-space exhaustion. The
  2^32 space makes it theoretically unreachable, but a `Result<Discriminator,
  AllocError>` removes the only `panic!()` outside tests; caller logs and refuses
  to install the new session.
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
- [ ] **CI gate: `#[allow(clippy::*)]` requires `reason = "..."`.** ~171
  escape-hatches workspace-wide (~40 are `cast_possible_truncation` in the wire
  codec, intentional after a length check). A CI lint that rejects new
  `#[allow(clippy::*)]` without an explicit `reason` arg; backfill one crate at a
  time.
- [ ] **`cargo deny` for license / dependency / advisory audit.** Resurrect the
  stale `chore/dependabot-and-cargo-audit` branch, modernize to `cargo deny check
  advisories bans licenses sources`, and wire into CI. Pairs with the next
  dependency audit.
- [ ] **Workspace `cargo doc` warning posture.** CI already runs
  `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`; make that the
  standing local pre-flight expectation too, surfacing broken intra-doc-links on
  the developer machine rather than at PR time.
- [ ] **Mega-module splits.** The large `src/` modules have been split, but
  `crates/api/src/event_service.rs` remains borderline. Keep splitting only where
  it reduces real conflict or review cost.

---

## Non-goals / scope

rustbgpd is an API-first BGP daemon. The following are explicitly out of scope:

- **Full routing suite.** No OSPF, IS-IS, LDP, MPLS, PIM. This is a BGP daemon.
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
