# rustbgpd Roadmap

## Market Context

The BGP daemon space is dominated by monolithic C implementations that
bundle BGP with OSPF, IS-IS, and every other routing protocol:

| Project | Language | Model | Strengths | Gaps |
|---------|----------|-------|-----------|------|
| FRR | C | Full routing suite | Feature-complete, wide adoption, production FIB / EVPN depth | Monolith, CLI-first, limited API |
| BIRD | C | Full routing suite / route-server mainstay | Excellent filter language, lightweight, BIRD 3 multithreading, TCP-AO | CLI-first, no native gRPC |
| OpenBGPD | C | BGP-only | Clean design, OpenBSD pedigree | Limited platform support, no API |
| GoBGP | Go | BGP-only, gRPC API | API-first, Zebra/FIB, EVPN, broad library docs | GC runtime, Go-specific protos |

**Why rustbgpd exists:**

- **GoBGP proved the model.** API-first BGP with gRPC works. Operators
  want programmable routing, not CLI scripting. rustbgpd keeps that
  shape while using Rust's predictable memory model and Rust-native
  reusable crates.
- **No Rust BGP daemon exists for production use.** Memory safety,
  zero-cost abstractions, and no GC make Rust ideal for a control plane
  that must be reliable and predictable under load.
- **The codec is independently valuable.** `rustbgpd-wire` as a
  standalone, fuzzed BGP codec library fills a gap in the Rust ecosystem.
  Anyone building BGP tooling in Rust (monitors, analyzers, test harnesses)
  can use it without pulling in a full daemon.
- **Observability and automation are the differentiators.** Prometheus
  metrics, structured JSON logs, machine-parseable errors, gRPC-first
  mutation/query paths, and reproducible interop gates are first-class
  product surface.

**Target users:** cloud and AI-scale data-center fabric operators, network
automation teams, IX / route-server operators, and whitebox / lab users who
want an API-first BGP daemon with memory safety and predictable performance.
rustbgpd is not trying to replace FRR/BIRD as a full routing suite; it is
trying to be the best programmable BGP control plane for fabrics, route
servers, and automation-heavy environments.

---

## Completed

- [x] MP-BGP (IPv6 unicast) — RFC 4760: `MP_REACH_NLRI` / `MP_UNREACH_NLRI` decode/encode, `Ipv6Prefix` type, `Prefix` enum for AFI-agnostic RIB, AFI/SAFI capability negotiation, dual-stack route exchange, IPv6 route injection via gRPC, FRR dual-stack interop validated
- [x] BGP wire codec — OPEN, UPDATE, NOTIFICATION, KEEPALIVE, NLRI, path attributes, communities, RFC-compliant flag validation, fuzz harness
- [x] RFC 4271 state machine — all 6 states, full transition table, OPEN negotiation, property tests
- [x] Tokio transport — single task per peer, inbound listener, TCP MD5/GTSM, session counters, NLRI batching, TCP collision detection (RFC 4271 §6.8)
- [x] RIB — Adj-RIB-In, Loc-RIB best-path (RFC 4271 §9.1.2 with eBGP preference), Adj-RIB-Out with split horizon, dirty peer resync, route injection, WatchRoutes streaming
- [x] Policy — prefix lists with ge/le matching (IPv4 + IPv6), per-peer import/export, global fallback
- [x] gRPC API — 11 services: Global, Config, Neighbor, Policy, PeerGroup, RIB, BFD, Event, Injection, Control, Evpn (all IPv6-capable)
- [x] Dynamic peer management — add, delete, enable, disable neighbors at runtime (IPv4 + IPv6)
- [x] Observability — Prometheus metrics at all RIB mutation points, structured JSON logging
- [x] Operations — coordinated shutdown (ctrl-c + gRPC), gRPC server supervision, metrics server hardening
- [x] Interop validated — automated milestone suite (see `docs/INTEROP.md` for
  the full matrix), foundation tier PR-gated, primarily against FRR 10.3.1 plus
  GoBGP / StayRTR and documented BIRD M0 + M43 coverage; privileged kernel
  dataplane smokes run locally
- [x] Graceful Restart — helper mode + minimal restarting speaker (RFC 4724): capability negotiation, stale route demotion, End-of-RIB detection/sending, timer-based stale sweep, coordinated-restart `R=1` signaling
- [x] Extended Communities (RFC 4360) — wire decode/encode, common subtypes (route target, route origin, 4-byte AS), RIB storage, gRPC API exposure (ADR-0025)
- [x] Extended Communities Policy Matching — match on RT/RO values in prefix lists, TOML community-match clauses (ADR-0026)
- [x] Route Refresh (RFC 2918) + Enhanced Route Refresh (RFC 7313) — inbound re-advertisement, outbound SoftResetIn gRPC, BoRR/EoRR refresh windows, capability negotiation (ADR-0027, ADR-0038)
- [x] AS_PATH loop detection (RFC 4271 §9.1.2) — routes containing local ASN discarded before RIB entry (all peers)
- [x] iBGP split-horizon (RFC 4271 §9.1.1) — non-route-reflector speaker suppresses iBGP-to-iBGP re-advertisement
- [x] Standard Communities Policy Matching (RFC 1997) — filter on standard community values in import/export policy, well-known names (ADR-0028)
- [x] Route Reflector (RFC 4456) — client/non-client reflection rules, ORIGINATOR_ID and CLUSTER_LIST attributes, inbound loop detection, best-path tiebreakers (ADR-0029)
- [x] Policy Actions — route modification on import/export: `set_local_pref`, `set_med`, `set_next_hop`, `set_community_add/remove`, `set_as_path_prepend`. Policy engine renamed from prefix-list to engine terminology. (ADR-0030)
- [x] AS_PATH regex matching — `match_as_path` in policy statements with Cisco/Quagga `_` boundary convention (ADR-0030)
- [x] AS_PATH length matching — `match_as_path_length_ge` / `match_as_path_length_le` in policy statements for inclusive range-based filtering
- [x] Large Communities (RFC 8092) — 12-byte wire codec, RIB accessor, gRPC API, policy matching and set/delete actions (ADR-0031)
- [x] Review hardening: IPv4 NEXT_HOP wire path, RT/RO ASN validation, AS_PATH regex AS_SET braces, zero-length LC rejection, EC logical add/remove equivalence, AS_SEQUENCE overflow guard
- [x] Extended Messages (RFC 8654) — raise 4096-byte BGP message limit to 65535 bytes; capability code 6, unconditional advertisement, dynamic buffer sizing (ADR-0032)
- [x] Add-Path (RFC 7911) — dual-stack receive + multi-path send (route server mode); capability code 69, NlriEntry composite keying, RIB re-keying with (Prefix, path_id), multi-candidate best-path selection, rank-based path ID assignment, per-candidate export policy, gRPC path_id fields (ADR-0033)
- [x] Extended nexthop (RFC 8950) — capability code 5; automatic dual-stack capability advertisement, IPv4 unicast NLRI over IPv6 next hop via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` (ADR-0037)
- [x] RPKI origin validation (RFC 6811 + RFC 8210) — RTR client, VRP table, best-path integration, policy `match_rpki_validation`, new rpki crate (ADR-0034)
- [x] Config persistence + SIGHUP reload — gRPC neighbor add/delete mutations persist to TOML via atomic write; SIGHUP triggers config reload with structured per-peer reconciliation
- [x] LLGR (RFC 9494) — two-phase GR timer: GR-stale routes promote to LLGR-stale with LLGR_STALE community, configurable llgr_stale_time per peer, NO_LLGR routes purged at transition, effective stale time = min(local, peer)
- [x] **ADR-0072 follow-up sprint (v0.30.0, 2026-05-27)** — closes the three deferrals the durable-event-history v1 unblocked: PR #291 wired the dataplane FIB / blackhole producers through EHM (closes the ADR-0072 v1 dataplane deferral); PR #292 added the structured `OtcRouteBlockedEvent` payload under `EVENT_CATEGORY_POLICY` with the next-free `BGP_EVENT_TYPE_OTC_ROUTE_BLOCKED` enum, sourced from a new `TransportEventSink` trait that mirrors `RibEventSink` from PR5 (closes the ADR-0071 deferral); PR #293 wired gNMI `STREAM ON_CHANGE` for `…/neighbor[neighbor-address=*]/state/session-state`, sourcing live FSM transitions from `EventHistoryManager::subscribe_live()` with fresh-snapshot-on-reconnect semantics (closes the ADR-0070 deferral). The follow-ups preserve or extend relevant interop coverage — #293 ships M56 (gNMI ON_CHANGE against FRR 10.3.1), #292 leans on the existing M55 OTC interop for the counter half of the contract, and #291 is unit + integration test coverage (no new interop milestone, dataplane events are exercised by the EVPN kernel-dataplane suite). Each PR preserves the original ADR deferral text with a "Resolved by PR #N" annotation rather than striking it.
- [x] Workspace tests — unit, integration, property, and fuzz smoke coverage

For detailed milestone build orders, see [docs/milestones.md](docs/milestones.md).

---

## Planned Features

*Ordered by market impact and what unlocks production adoption. Updated after
the BFD + unicast ECMP / weighted multipath work and a May 2026 market pass:
FRR remains the full routing-suite benchmark, GoBGP remains the closest
API-first peer, Cumulus / SONiC / FRR-style whitebox fabrics set the data-center
baseline, and BIRD / IXP Manager continue to define route-server operator
expectations.*

*For feature parity details, see [docs/gobgp-parity.md](docs/gobgp-parity.md)
and [docs/COMPARISON.md](docs/COMPARISON.md).*

### Release stance

**rustbgpd ships in v0.x indefinitely.** The core programmable-control-plane
path is feature-complete by the criteria that matter — full BGP-4 + the
extensions a modern operator needs (MP-BGP, Add-Path, Extended Messages,
Graceful Restart + LLGR, Route Refresh + Enhanced Route Refresh, TCP MD5 /
TCP-AO, BFD with RFC 5882 coupling, ECMP with weighted multipath, EVPN VXLAN
with aliasing ECMP and DF election, RPKI + ASPA verification, BGP Roles +
OTC, FlowSpec, durable event history, native gNMI / OpenConfig telemetry),
all behind a gRPC-first control plane with mTLS + tier authorization.

The active work remains feature breadth where it matters for protocol
parity, polish, and code quality. v1.0 is not currently on a timeline: if
real-world deployment feedback materializes it will reshape priorities; if
not, the project keeps shipping focused v0.x cuts as items below land.
Anyone who wants to audit, deploy, or stress-test rustbgpd has the
documentation to do so — that's the v0.x posture.

### Current Priority Order

These are the near-term items that move adoption the most. Older completed
work and long-tail protocol parity remain below as reference; this table is
the active planning surface.

| Priority | Item | Why now | Main proof / exit condition |
|----------|------|---------|-----------------------------|
| P0 | **Performance / polish phase** *(ASPA PR1 correctness slice landed as kickoff)* | ASPA momentum is real but mostly ecosystem readiness (Cloudflare Radar deployment visibility, NIST BRIO tooling, RIPE signing maturity) rather than obvious operator pull — upstream-only verification covers the route-leak prevention story for the common case today. Adoption-moving work sits in perf/polish: bulk initial load, churn benchmarks, CI benchmark tracking, shared route storage / compact indexing research. The ASPA correctness slice (PR #294) closed algorithm-fidelity uncertainty cheaply; downstream verification + cache-update revalidation + remaining test coverage stay planned but deferred until operator signal materializes or the MANRS / route-leak-prevention bundle becomes the explicit next headline. | Kickoff (shipped): ASPA PR1 (PR #294) — bounds-equivalence proof against draft-ietf-sidrops-aspa-verification-25 §5.4 documented; per-AFI/SAFI gate applied at the validation entry point. Main phase: define and track convergence + steady-state memory benchmarks in CI; bulk initial-load and churn improvements to ship as discrete PRs; shared route storage / compact indexing research informs the next bigger refactor. |
| P1 | **Config transaction model and runtime/file diff UX** *(decision gate — start or defer, do not bundle into polish)* | gRPC owns truth after startup, and gNMI `Set` would require transaction semantics. Substrate-shaped, not cleanup. `Set` is currently a stable `UNIMPLEMENTED` contract — deferring transactions breaks no operator promise. **Decide explicitly:** either start as the next major feature after ASPA, or defer and declare mutation surfaces out of scope for the perf/polish phase. | Candidate config object, validate-only, diff against live effective runtime, atomic commit where supported, explicit restart-required surfaces, rollback/receipt model; no partial silent drift. |
| P1 | **FIB operational hardening** *(decision gate — pull only operator-confidence pieces)* | ADR-0061/0066/0068 cover configured-table install, ECMP, per-class caps, `multipath_relax`, and Link Bandwidth weighting. The next pain points are lifecycle and scale rather than base capability. Pull only the pieces that move operator confidence or unblock perf testing; defer the rest. | Hot-swap `[[fib_tables]]` (operator confidence; in-scope); over-cap detail APIs beyond sampled `route_limit_exceeded` rows (decide based on operator pain signal); incremental equal-cost sibling index for wide full-table multipath (defer unless perf-gated); platform-diversity interop for weighted multipath (defer unless demanded). |
| P2 | **Policy / explain follow-ups** *(operator polish, not feature)* | Operator-polish surface: `reason` label coverage, FlowSpec/EVPN counter unit tests, import explain, best-path explain attribution. UX-shaped, not protocol gaps. | Stable `reason` labels across remaining ingress filter paths; per-feature counter unit-test coverage; `rustbgpctl policy explain --neighbor X --prefix Y` showing the chain that matched and the action taken; best-path explain surfacing the tiebreaker step that won. |
| P2 | **EVPN / VXLAN standards tail** *(demand-shaped — defer unless requested)* | EVPN is alpha-complete for the core VXLAN DC story, with the Linux softswitch local-bias limitation honestly documented. Remaining work follows demand and closes standards gaps that matter to real fabrics. | Native overlay-index Type 5 origination + protected recursion-path interop; optional single-active backup-path preinstall; runtime mixed-edit composer if operators need fewer split requests; VLAN-aware bridges / managed netdev creation. Keep as follow-up inventory; don't let it block a perf/polish pivot. |
| P2 | **TCP-AO dynamic / rotation polish** *(demand-shaped — defer unless requested)* | Static TCP-AO and BIRD interop (M43) are shipped. Dynamic-neighbor wildcard MKT and key rollover matter to some route-server / security operators but are demand-shaped, not core-feature blockers. | Dynamic-neighbor wildcard-MKT design; runtime key rotation / multi-key rollover; accepted-socket inspection and observability. |
| P3 | **Engineering velocity and maintainability** | The large `src/` mega-modules have been split, but `crates/api/src/event_service.rs` remains borderline and `clippy::too_many_lines` suppressions still trend high. | Keep splitting only where it reduces real conflict or review cost; reduce `too_many_lines` suppressions over time; centralize duplicated test fixtures when field churn makes it painful. |

Recent shipped differentiators now treated as baseline, not active priorities:
durable event history / replay end-to-end (ADR-0072, PRs #286–#290) and the
ADR-0072 follow-up sprint that closed its three downstream deferrals —
dataplane events through EHM (#291), `OtcRouteBlocked` structured event payload
(#292), gNMI `Subscribe ON_CHANGE` v1 for neighbor session-state (#293, M56);
BGP unnumbered / IPv6 link-local peering (ADR-0069, M53), BFD single-hop async
with RFC 5882 coupling (ADR-0067, M51), unicast ECMP / weighted multipath
(ADR-0066/0068, M50/M52), EVPN production-default BUM enforcement and aliasing
ECMP, ADR-0064 gRPC tier authorization, and the major mega-module splits.

### Sustainability / Engineering Velocity

Cross-cutting cleanups that don't move user-facing capability on their
own but lower the cost of every future PR. Treat the items here as
"open to grab when your branch is between features" — none of them
block a release, but they keep the contributor experience from
degrading as the codebase grows. The mega-module split lives in the
priority table above because it has the biggest blast radius.

- [ ] **Doc-collision discipline for `ROADMAP.md` / `CHANGELOG.md` /
  `docs/evpn-alpha-soak.md` / `docs/evpn-enablement.md`.** Almost every
  multi-PR batch this release cycle conflicted on the same handful of
  rows (the Real-time event/history surface row, the `[Unreleased]
  ### Added` chunk, the Gate 8b residual checklist). Lighter-touch
  fixes: append-only convention for `[Unreleased]` (newest entry at
  the bottom of its subsection), separate "shipped this PR" sentences
  rather than rewriting existing summary prose, one row per concern in
  the priority table. Heavier option if drift continues: extract a
  structured manifest the docs are generated from.
- [ ] **Test fixture extraction into a shared `test-support` surface.**
  Helpers like `route_event`, `session_event`, `policy_event`,
  `lifecycle_event`, and the various per-test config builders have
  drifted across `crates/api`, `crates/cli`, `crates/rib`, and `src/`
  with subtly different signatures. The recurring symptom is that a
  field addition (e.g. `event_id`) forces touching three or four copies
  in one PR. A single `rustbgpd-test-support` crate (or a `pub mod
  test_support` per existing crate, re-exported under `#[cfg(test)]`)
  would centralize the fixtures and stop the per-PR churn.
- [ ] **`unwrap()` audit on daemon-runtime paths.** Raw count is ~2k
  in non-test source; **actual production-code unwraps (outside
  `#[cfg(test)] mod tests` blocks) measure at ~5** sites after the
  v0.30 quality scan (2026-05-26) — TLS-cert reads downstream of
  validated `is_some()` (`src/config/validation.rs:93-95`), one
  `u32::try_from(MAX_ROUTE_LIMIT_EXCEEDED_DROPS_PER_TABLE).unwrap()`
  const cast in `src/fib.rs:726`, and a few defensive parses of
  already-validated strings. The bulk of the raw count is fixtures /
  asserts inside inline test modules. Item kept open as a forcing
  function for the audit when these few stragglers come up for
  refactor; not blocking v1.0.
- [ ] **`panic!` → typed-error sweep on the one production site.**
  `crates/bfd/src/discriminator.rs:39` panics with
  `"BFD discriminator space exhausted"`. 2^32 discriminator space
  makes the case theoretically unreachable, but defensive returns
  are free and remove the only `panic!()` outside tests in the
  workspace. Replace with `Result<Discriminator, AllocError>`;
  caller logs and refuses to install the new session.
- [ ] **`#[expect(clippy::too_many_lines)]` reduction.** ~30
  suppressions workspace-wide (down from 94 — credit the FSM /
  policy refactors). Concentrated in long dispatchers (FSM action
  loop, EVPN reconcilers, encode/decode match arms). Some are
  honest match-heavy dispatch and should stay; the rest indicate
  functions ready for extraction. Track absolute count downward
  release over release rather than gating individual PRs on it.
- [ ] **`#[allow(clippy::too_many_arguments)]` cluster tidy-up.**
  ~25 sites — distribution functions in `crates/rib/src/manager/`,
  EVPN originators in `src/evpn_originator/`, BFD socket setup. The
  Operator Confidence Polish Sprint's PR2b had to thread three new
  parameters (`&BgpMetrics + &mut policy_stats + &str peer_label`)
  through `distribute_multipath_prefix` /
  `distribute_single_best_prefix` / `stage_flowspec_rules` /
  `stage_evpn_routes` because those four were already past the
  threshold. A `DistributionContext` parameter struct would absorb
  them; same trick fits the EVPN originators. Cosmetic, but it
  buys headroom for the next slice of metric / policy threading.
- [ ] **`#[allow(clippy::result_large_err)]` in
  `crates/api/src/rib_service.rs`.** 6 suppressions for a large
  `Result<_, RibServiceError>` enum. Box the error variant if it
  ever shows up in any benchmark or RIB query hot-path; until then
  the cost is purely cosmetic.
- [ ] **CI gate: `#[allow(clippy::*)]` requires `reason = "..."`.**
  171 clippy escape-hatches workspace-wide; ~40 are
  `cast_possible_truncation` in the wire codec (intentional after a
  length check), the rest split across `too_many_lines`,
  `too_many_arguments`, and `result_large_err`. Mechanical
  forcing function: a CI lint that rejects new `#[allow(clippy::*)]`
  without an explicit `reason = "..."` arg. ~171 sites to backfill,
  best done as a polish-sprint side quest one crate at a time.
- [ ] **`cargo deny` for license / dependency / advisory audit.**
  `chore/dependabot-and-cargo-audit` is a stale branch on origin.
  Resurrect, modernize to `cargo deny check advisories bans
  licenses sources`, and wire into the CI workflow. Pairs naturally
  with the next dependency audit before v1.0.
- [ ] **Workspace `cargo doc` warning posture.** CI already runs
  `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`. Make
  that the standing local pre-flight expectation too — surfacing
  broken intra-doc-links and bare crate references on the developer
  machine rather than at PR time.

### Performance & Polish

Active work theme during v0.30.0+. The ASPA PR1 correctness slice
(PR #294, v0.30.0) was the kickoff that unblocked this phase. Current
focus is making perf improvements measurable so the phase compounds —
without continuous regression signal, every perf claim costs hours of
manual bisecting to validate.

**Load-bearing first step: CI bench tracking on a pinned runner.**
The v0.30.0 BENCHMARKS.md refresh established a ~30% empirical noise
floor on this box for unpinned criterion runs. PR #295's
`adj_rib_in_insert/10000` regression was found accidentally during a
doc refresh, not by automation, because no per-PR bench signal exists.
The Route boxing fix is in tree; the missing infrastructure is what
would have caught the regression at PR time.

**Prerequisite (out of code scope, on operator list):** a replacement
self-hosted runner. The previous box was retired; CI bench tracking
needs `taskset` + `performance`-governor pinning that GitHub-hosted
runners cannot provide. Until the runner exists, the CI-bench-tracking
items below are gated.

#### Active

- [x] **Manual pinned-bench runbook + compare script.** `bench/`
  now contains a `taskset -c <core>` + Criterion baseline wrapper that
  records commit SHAs, host metadata, logs, raw Criterion artifacts,
  and a paste-ready Markdown delta table. This lets us grade perf PRs
  by hand until the CI runner lands, and becomes the prior art the
  runner workflow will port from.
- [ ] **CI bench tracking** *(blocked on replacement runner)* —
  manual `Criterion Bench Compare` workflow exists and reuses the
  local compare script on a `[self-hosted, rustbgpd-bench]` runner.
  Automatic PR triggering is intentionally still disabled until that
  runner exists and its noise floor is calibrated. Final shape:
  path-scoped PR runs for `crates/{rib,wire,transport}/src/` or
  `bench/`, paste-ready PR comment, raw Criterion artifacts, and
  advisory thresholds before any hard regression gate.
- [x] **Bulk initial-load bench.** `rustbgpd-rib/rib_ops` now has a
  `bulk_initial_load` Criterion group for cold single-peer table load
  into pre-sized Adj-RIB-In / Loc-RIB / Adj-RIB-Out. Runner-backed
  tracking of this group still depends on CI bench calibration.
- [ ] **Continuous churn bench in CI** *(depends on CI bench tracking)*
  — short criterion variant of the M33 soak shape (announce + withdraw
  cycles over a pre-loaded RIB), so steady-state hot-path regressions
  surface per-PR rather than only at soak time.
- [ ] **Shared route storage / compact indexing research.** Next
  bigger structural perf refactor (interning beyond Arc-dedup,
  columnar layout, prefix-tree). Research PR first; prototype grading
  needs CI bench tracking to be useful.

#### Shipped (this phase)

- [x] **BENCHMARKS.md v0.30.0 refresh + methodology stamp** (`4ad4507`)
  — corrected hardware stamp, documented the ~30% noise floor for
  unpinned runs, refreshed every criterion-tracked table.
- [x] **Route struct shrink — `next_hop_scope` boxed** (PR #295,
  `f4cf9b8`) — recovered the 14% `adj_rib_in_insert/10000` regression
  by shrinking `Route` from 136 → 120 B. The delta is consistent
  with crossing a clone-codegen / cache-pressure threshold; no
  perf / asm capture was taken, but the small-N hit cleared and
  large-N stayed flat. First perf PR after the phase kickoff.
- [x] **Release asset hygiene** (`d0d9c49`, `43b3833`) — version-less
  tarball filenames + `releases/latest/download/` URLs eliminate
  per-release deployment.md maintenance; release checklist aligned
  with the actual ship workflow conventions.

### Pre-v1.0 Worklog

Operator-visible gaps and completed work that feed the priority table above.
New planning should start from **Current Priority Order**; this section keeps
the historical context and lower-level implementation notes that explain why
those priorities exist.

- [x] **SIGHUP policy/peer-group reconciliation** (v0.12.0) —
  `reload_config` now applies named-policy / neighbor-set /
  peer-group / global-chain edits, not just `[[neighbors]]` deltas.
  Each delta routes through the existing
  `apply_policy_change` / `apply_peer_group_change` paths so
  runtime effect matches the gRPC API. Inline `policy.import` /
  `policy.export` still require restart (no runtime swap surface);
  `--diff` flags this under Restart-required.
- [x] **Effective neighbor diff via peer-group resolution**
  (v0.12.0) — `rustbgpd --diff` surfaces per-neighbor
  "effective impact" via `effective_neighbor_impact` so a single
  peer-group / policy / neighbor-set edit shows every neighbor
  whose resolved chain would move at reload, not just the raw
  upstream change.
- [x] **Native gRPC mTLS** (v0.11.0) — TCP listeners terminate
  TLS in-process via tonic + rustls/ring. `tls_cert_file`,
  `tls_key_file`, and `tls_client_ca_file` are all required together
  on `[global.telemetry.grpc_tcp]`; partial config is rejected at
  `Config::load`, and the three PEM files are read at config-load /
  `--check` time so missing, unreadable, empty, non-PEM, or
  wrong-kind material fails before the daemon ever starts. No
  "TLS-without-mTLS" half-mode — server identity + client-cert
  verification land together. Closes the audit-prep item; UDS
  listeners are unchanged (file-system permissions remain their
  auth surface).
- [ ] **EVPN VTEP alpha-soak slate.** With Gates 7a / 7b / 7b+1 /
  7b+2 / 7c / 8 / 8b landed (v0.17.0) and Gate 9 slice 6 symmetric
  Interface-less IRB end-to-end live (v0.18.0: PR A origination +
  PR B import + M39 hosted smoke against FRR 10.3.1 + sub-second
  `RTNLGRP_IPV4_ROUTE` withdraw),
  the bidirectional VTEP loop covers MAC-only and MAC+IP origination
  under the FRR replace model with sub-second mobility convergence,
  plus observable DF election against shared Ethernet Segments and
  observable IP-VRF readiness state. Hosted CI for M36 + M37 +
  M37+IP + M38 runs in `.github/workflows/kernel-dataplane.yml`, the
  M37 local-origination 24 h MAC-churn soak completed (postmortem
  `docs/soak-m37-local-origination-churn-24h.md`), and the RFC 7432
  §15.1 duplicate-MAC story is complete: detect-only by default, opt-in
  `suppress_local` quarantine, remote-route processing suppression,
  receive-side intent filtering, and a manual clear API
  (`ClearDuplicateMacQuarantine`). **The EVPN runtime-mutation surface
  (ADR-0063 / #210) is alpha-complete:** the daemon actor converger commits
  single L2VNI add/delete/redefine, single IP-VRF add/standalone-delete/redefine
  with unchanged L3VNI/device/table identity, single Ethernet Segment
  add/delete/redefine (including ES add/redefine over a member VNI added by an
  earlier live L2VNI add), atomic tenant teardown (M47/M48), and `ip_vrf` relink.
  The only edits that remain restart-required are L3VNI/device/table IP-VRF
  identity changes (a kernel VRF lifecycle operation, restart-required by design)
  and non-teardown mixed edits (an add combined with a delete/redefine — fail
  closed with a "split the request" error, pending a generalized
  converge-to-candidate follow-up).
- [x] **`rustbgpctl` policy / peer-group / neighbor-set commands**
  (PR #61) — three new subcommand trees wrap `PolicyService` (18
  RPCs) and `PeerGroupService` (6 RPCs):
    - **Read** — `rustbgpctl policy list/get`,
      `peer-group list/get`, `neighbor-set list/get`.
    - **Write** — `rustbgpctl policy set/delete`,
      `peer-group set/delete`, `neighbor-set set/delete`. `set`
      accepts a JSON file via `--from-file PATH` whose shape
      mirrors the proto message; `serde(deny_unknown_fields)`
      rejects typos at parse time.
    - **Chain management** — `rustbgpctl policy chain
      show|set-import|set-export|clear-import|clear-export
      [--neighbor ADDR]` for global / per-neighbor import/export
      chains. Empty `set-*` is rejected at the CLI layer with a
      pointer at the matching `clear-*` command.
    - **Peer-group binding** — `rustbgpctl peer-group
      attach ADDR --group NAME` / `detach ADDR`.
  29 mock-server / clap-parse tests pin the dispatch path.
  `--explain-peer` extension on `rib --explain` (Add-Path send
  view) shipped alongside in the same PR.

  **Runtime-vs-file dry-run:** daemon-side `rustbgpd --diff` now
  reports reload-applied policy / peer-group / effective-neighbor
  impact, restart-required startup-only surfaces, and hot-applied
  global honor flags. A live `rustbgpctl policy diff <candidate.toml>`
  that compares against an API-exported runtime snapshot remains a
  larger config-snapshot design task if operators need it.
- [x] **Auto-retry pending soft-resets and policy hot-applies across
  SIGHUP boundaries.** Shipped on the SIGHUP reconcile branch.
  `update_runtime_policies` is now bail-and-retry across every
  downstream step:
  - `ManagedPeer.pending_refresh` covers unfired Route Refresh
    intent (failed `soft_reset_in`, bail-before-refresh on any
    side, or non-Established peer carrying inherited intent).
  - `ManagedPeer.pending_export_apply` covers unfired session-side
    export updates with the same bail-and-carry semantics.
  - `update_runtime_policies` defers advancing
    `managed.import_policy` / `managed.export_policy` until the
    session ACKs, and bails before the RIB update + Route Refresh
    when any session-side hot-apply fails under apply-changing
    intent — for any session state, not just Established. Cross-
    side carry: when one side succeeds (advancing bookkeeping)
    but another side bails, both pending flags re-arm so the
    retry pipeline picks up every unfired downstream step. The
    RIB-failure path also re-arms `pending_refresh` so a transient
    RIB-channel failure doesn't silently lose refresh intent.
  Closes the silent-stale-routes class across import / export /
  RIB / refresh failure modes; six unit tests + one interop test
  pin the regressions.
- [x] **Dead-letter pending flags on dynamic-peer auto-removal**
  (v0.13.2) — `PeerManager` now carries a per-IP
  `dead_lettered_pending` side table (bounded at
  `dynamic_neighbor_limit`) that snapshots `pending_refresh` /
  `pending_export_apply` before `BackToIdle`'s `peers.remove(...)`
  and restores them when `handle_inbound` recreates a dynamic
  `ManagedPeer` at the same address. Closes the silent-loss case
  for transient TCP drops on `[[dynamic_neighbors]]` peers carrying
  unfired hot-apply intent. The reconcile delete-then-readd shape
  is structurally similar but a separate code path; tracked
  separately if it ever surfaces operationally.
- [x] **Post-reload sync resilience in `main.rs`** (v0.13.2) —
  lifted the post-reload sync into `apply_reload_outcome` and
  reordered: peer manager first (unbounded, can only fail on
  receiver-drop and never blocks), config bridge second. Failure
  surfaces as a named stage (`peer_mgr_snapshot` / `config_bridge`)
  so the operator log is actionable. Same release also fixed a
  related bug — the gRPC `ConfigEvent` → persister bridge was
  holding a stale `current_config` across SIGHUP, so a post-reload
  gRPC mutation would overwrite the persisted file with the
  pre-reload snapshot plus that one mutation. Replacement now
  routes through the bridge so the bridge's snapshot and the
  persister advance in lockstep.
- [x] **EVPN IPv6 next-hop roundtrip test** (v0.13.1) — added
  `mp_reach_evpn_ipv6_next_hop_roundtrip` pinning the 16-byte single-
  address IPv6 form end-to-end through `encode_mp_reach_nlri`'s
  EVPN branch, plus a paired `mp_reach_evpn_rejects_32byte_next_hop`
  that asserts `NH-Len=32` for L2VPN/EVPN is rejected (RFC 7432 §7.5
  vs RFC 2545 unicast). Closes the validate-side audit gap.
- [x] **Tighten test failure-mode coverage.** All four hot-apply
  failure tests inject the same shape (drop the reply oneshot).
  Production paths can also fail with channel-full / channel-
  closed / actual timeout. If the bail logic ever conditioned on
  the *kind* of error, these would pass while regressing real
  cases. Also missing: a concurrent-update race test (two
  back-to-back calls for the same peer interleaving with
  `pending_refresh` consumption), and a peer-deletion-mid-update
  test (peer vanishes between the import apply and the bail
  bookkeeping). ~150 LOC across three new tests; pure unit-test
  hardening, no production code change.
- [x] **Soften M34 session-uptime-epoch assertion** (v0.13.1) —
  M34 now reads rustbgpd's own `NeighborState.flapCount` and
  `uptimeSeconds` via gRPC instead of FRR's
  `bgpTimerUpEstablishedEpoch`. Cross-check pins session continuity:
  `flapCount` must not increase AND `uptimeSeconds` must
  monotonically advance. The dual check catches both increment-then-
  equal and full handle replacement (every fresh `PeerSession` starts
  at `flap_count = 0`, so flapCount alone would let a hypothetical
  tear-down + fresh-establish slip through; uptime resets to ~0 on a
  new handle, so the monotonicity guard catches that case).
  Mirrors the M33 scale harness's flapCount pattern.
- [x] **BGP Graceful Shutdown (RFC 8326)** — landed end-to-end.
  Wire crate exposes `COMMUNITY_GRACEFUL_SHUTDOWN`. Policy engine
  accepts `"GRACEFUL_SHUTDOWN"` as a community alias on both match
  and set sides. Receiver behavior: opt-in `[global]
  honor_graceful_shutdown = true` knob appends an implicit
  chain-tail rule (`match GRACEFUL_SHUTDOWN → set local_pref = 0`)
  to every EBGP peer's import chain — chain tail (not head) so the
  demotion wins last-writer-accumulation against any operator
  policy that also sets `LOCAL_PREF`; iBGP exempt. Initiator
  behavior: gRPC `NeighborService.SetGracefulShutdown { address,
  enabled }` (empty address = all peers) + `rustbgpctl gshut
  [--peer X] [--clear]` operator-runtime toggle stored on
  `ManagedPeer` + mirrored to live session, replayed on session
  restart, triggers `RibUpdate::RefreshPeerOutbound` so the wire
  state updates immediately. M35 interop validates both legs +
  the clear leg against FRR 10.3.1. ADR-0053. See `KNOWN_ISSUES.md`
  for the confederation gating + restart-persistence + dynamic-peer
  replay limitations called out below.
- [ ] **RFC 8326 confederation gating.** When confederations land,
  the EBGP gate inside `effective_policy_chains_for_neighbor` —
  currently `neighbor.remote_asn != self.global.asn` — needs to
  key off an explicit `is_external_neighbor()` helper that knows
  about confederation sub-AS topology. The current gate is correct
  for the traditional EBGP/iBGP topology rustbgpd supports today;
  this becomes load-bearing only when confederations land. Tracked
  in `KNOWN_ISSUES.md`.
- [x] **RFC 8326 dynamic-peer GShut replay.** Static + collision-
  replaced + static-reconcile-rebuilt sessions inherit
  `advertise_graceful_shutdown` from `ManagedPeer` on spawn.
  Dynamic peers now inherit it too: the per-peer dead-letter side
  table on `PeerManager` (introduced in v0.13.2 for `pending_refresh`
  / `pending_export_apply`) snapshots `advertise_graceful_shutdown`
  before `BackToIdle` auto-removal and replays it into the new
  `ManagedPeer` / inbound session when the peer re-establishes at the
  same address.
- [x] **RFC 8326 honor knob hot-reload.** SIGHUP flips of
  `[global] honor_graceful_shutdown` now hot-apply through the peer
  manager: the live config snapshot advances, every EBGP peer
  recomputes its effective import/export chains, and any established
  peer with changed import policy gets the existing route-refresh
  retry semantics.
- [x] **M35 FlowSpec + EVPN initiator-leg coverage.** The outbound
  attach helper `attach_graceful_shutdown_if_enabled` is wired at
  all three outbound sites (unicast, FlowSpec, EVPN); CI now exercises
  each family-specific outbound emission path against FRR. M35 covers
  IPv4 unicast, M35b injects FlowSpec and toggles GShut without route
  churn, and M35c injects an EVPN Type 2 route and toggles GShut
  without route churn.
- [x] **RFC 7999 BLACKHOLE receiver + opt-in FIB discard** (v0.21.0). Natural sibling to RFC 8326
  GShut. Well-known `BLACKHOLE` community (`65535:666`) signals
  "drop traffic to this prefix" for DDoS mitigation. Different
  semantic class from GShut: receiver behavior is **data-plane**
  (install a discard/null route) not control-plane (de-pref). The
  control-plane half is now wired:
    - **Wire**: `COMMUNITY_BLACKHOLE: u32 = 0xFFFF_029A` next to
      `COMMUNITY_GRACEFUL_SHUTDOWN`, plus RFC 1997 well-known
      constants for `NO_EXPORT`, `NO_ADVERTISE`, and
      `NO_EXPORT_SUBCONFED`.
    - **Policy alias**: `parse_community_match` accepts `"BLACKHOLE"`
      everywhere `match_community` / `set_community_add` /
      `set_community_remove` parse community values.
    - **Inbound scoping (opt-in)**: `[global] honor_blackhole = true`
      appends an EBGP import chain-tail rule
      (`match BLACKHOLE → permit, add BLACKHOLE + NO_ADVERTISE`) and
      hot-applies on SIGHUP through the peer manager when FIB discard
      is not configured. When paired with
      `install_blackhole_discard = true`, it is restart-required because
      the kernel-discard reconciler is spawned once at startup.
    - **Operator surface**: `rustbgpctl` accepts and renders
      `BLACKHOLE`, `NO_EXPORT`, `NO_ADVERTISE`,
      `NO_EXPORT_SUBCONFED`, `GRACEFUL_SHUTDOWN`, `LLGR_STALE`, and
      `NO_LLGR` anywhere the CLI parses or displays standard
      communities.
    - **Interop**: M41 is CI-gated against FRR 10.3.1. FRR advertises
      a host route with `65535:666`; rustbgpd verifies receiver-side
      scoping by preserving `BLACKHOLE` and adding `NO_ADVERTISE`
      under `[global] honor_blackhole = true`.
    - **FIB discard (opt-in)**: `[global] install_blackhole_discard = true`
      starts a Linux kernel-discard reconciler when paired with
      `honor_blackhole = true`. It installs daemon-owned
      `RTN_BLACKHOLE` routes for EBGP-learned BLACKHOLE best routes,
      defaults to host routes only (`/32` and `/128`), preserves
      existing kernel routes by refusing overwrite, cleans up on
      withdraw / shutdown, and surfaces status through
      `rustbgpctl rib blackholes` plus Prometheus counters.
  Remaining BLACKHOLE work:
    - **FIB hardening**: add per-peer / peer-group allow-lists, active
      blackhole limits, rate limits, startup adoption or explicit stale
      cleanup policy, and broader audit trails around who requested each
      discard.
    - **Outbound advertise**: gRPC `SetBlackhole { peer, prefix,
      enabled }` or operator-policy attachment via
      `set_community_add = ["BLACKHOLE"]` on a per-prefix import
      filter. Per-prefix route injection is the likely surface.
- [x] **ADR-0061 opt-in unicast Linux FIB integration** (v0.21.0) —
  configured `[[fib_tables]]` blocks start a default-off reconciler that
  projects unicast Loc-RIB best routes into explicit non-reserved Linux
  route tables. Pure intent/diff model plus a runtime actor; conservative
  ownership (`RTPROT_BGP` is not ownership proof, so pre-existing and
  externally-drifted rows are preserved and reported as
  `foreign_route_exists`); status via `RibService.ListFibRoutes`,
  `rustbgpctl rib fib`, and Prometheus `bgp_fib_*` counters; privileged
  netns harness selector plus the M42 FRR containerlab smoke. Follow-up
  hardening added per-peer / peer-group allow-lists, route-count caps, and
  exact-match crash-restart recovery through persisted owned-state under
  `runtime_state_dir`.
- [x] **Resolve open `cargo audit` findings** (v0.13.2 / v0.14.0) —
  vulnerability cleared in v0.13.1; soundness warning accepted as
  unreachable in v0.13.2; v0.14.0 follow-up granted `checks: write`
  to the audit workflow (the rustsec/audit-check action posts
  findings via the GitHub Checks API; default GITHUB_TOKEN is
  read-only on push-to-main since GitHub's 2023 default-token
  change, so the action got "Resource not accessible by
  integration" once Gate 7b's `paste` transitive dep gave it a
  finding to post) and accepted RUSTSEC-2024-0436 (paste 1.0.15
  unmaintained, transitive via `netlink-packet-utils → rtnetlink`,
  no replacement until upstream swaps to `pastey`):
    - [x] **RUSTSEC-2024-0437** (protobuf 2.28.0, "Crash due to
      uncontrolled recursion") — pulled in via `prometheus 0.13.4`.
      Cleared in **v0.13.1** by bumping `prometheus 0.13 → 0.14`;
      0.14 moves to protobuf 3.x. Migrated four test/internal files
      to the proto-3 field/method API split (`MetricFamily.metric`
      and `Metric.label/.counter/.gauge` are now public fields;
      `LabelPair.name()` / `.value()` / `Counter.value()` /
      `Gauge.value()` stay as methods). Stale ignore entry in
      `.cargo/audit.toml` dropped in **v0.13.2**.
    - [x] **RUSTSEC-2026-0097** (rand 0.8.5 + 0.9.2, "unsound with a
      custom logger using `rand::rng()`") — accepted as
      unreachable in **v0.13.2**. Transitive via
      `phf_generator → phf_macros → phf → termwiz →
      ratatui-termwiz` (CLI / `top` command). Verified upstream
      that ratatui-termwiz 0.1.0 is the latest release and the
      `phf` ecosystem hasn't bumped `rand` to a fixed version yet.
      The workspace does not install a custom rand logger, so the
      unsoundness condition is not reachable. Documented in
      `.cargo/audit.toml` with the rationale; revisit on the next
      ratatui-termwiz release.
    - [x] **RUSTSEC-2024-0436** (paste 1.0.15, "no longer
      maintained" — the upstream author archived the repo) —
      accepted in **v0.14.0**. Informational, no security
      vulnerability. Transitive via `netlink-packet-utils →
      rtnetlink → rustbgpd-evpn-linux` (Gate 7b). The paste
      invocation upstream is a `nla_get_*` / `nla_put_*` macro
      generator — pure proc-macro, no runtime behavior.
      Documented in `.cargo/audit.toml` with rationale; revisit
      when netlink-packet-utils swaps `paste` for `pastey` or
      equivalent.
- [x] **Spawn `reload_config` onto its own task** (v0.13.2) —
  `reload_config` now runs on a dedicated tokio task tracked as
  `Option<JoinHandle<...>>`. Main `select!` polls the completion
  handle via the standard `std::future::pending().await` arm-gating
  pattern; SIGINT / SIGTERM / gRPC shutdown observation is no
  longer blocked by an in-flight reload. Concurrent reloads are
  rejected with a `"SIGHUP received while previous reload still in
  flight; ignoring"` warning — they would race on `peer_mgr_tx`
  command ordering and double-fire the post-reload sync.
  Coordinated shutdown aborts any in-flight reload before tearing
  down the peer manager.
- [x] **Stress-test sweep** — peer flap storms, gRPC churn, repeated
  GR recovery. Trivial to script on the existing M33 soak harness;
  closes four open P3.5 bullets.
- [x] **`match_evpn_route_type` policy clause** — operators currently
  filter EVPN by RT/community; route-type-keyed match is the natural
  ergonomics.

#### Recently shipped (post-v0.7.0)

- [x] **Durable event history — local outbox** (ADR-0072, PRs #286 → #290) — daemon-local SQLite WAL outbox with monotonic `event_id` that survives daemon restart. New `crates/event-history` crate hosts the `EventHistoryManager` actor + the 3-step actor-ordered cursor handoff for `SubscribeFromEvent` (replay → live without gaps or duplicates). PR5 lit up the runtime: producer wiring (RIB route + EVPN through a `RibEventSink` trait; PeerManager session-lifecycle + notification + policy through in-place enqueue; BFD bridge enqueue alongside the proto `BgpEvent` construction it already does); the gRPC handler replacing the `UNIMPLEMENTED` stub with the cursor handler (single-category-cursor fast path + post-filter for repeated categories / `event_types` / `afi_safi` / `prefix_length`, leading `StreamLagEvent` when the requested cursor is older than the retention floor); CLI `rustbgpctl events watch --from-event-id <u64>` (mutually exclusive with `--backfill`); `examples/event-bridge/` reference binary. Legacy `WatchEvents` / `WatchRoutes` / `List*Events` surfaces stay byte-identical to pre-PR — the contract split is that the durable cursor is `SubscribeFromEvent`'s only consumer; the EHM-owned broadcast is the only path where `no-live-without-durable` applies. `bgp_event_outbox_cursor_gap_total` counts subscribe requests that emitted a leading lag event (operator signal that retention is undersized for the collector reconnect SLA). Notification events are durably persisted for the first time, closing ADR-0071's notification-history gap. The three downstream deferrals (v1 dataplane producer set, `OtcRouteBlocked` structured event, gNMI `Subscribe ON_CHANGE`) shipped as the **ADR-0072 follow-up sprint** — see the dedicated entry above for the per-PR details.
- [x] **EVPN aliasing dataplane ECMP via FDB nexthop groups** (v0.19.0, ADR-0059, PRs #84 / #86 / #87 / #88 / #89) — multi-homed Type 2 routes on the receive path now program FDB nexthop groups in the kernel via `NDA_NH_ID` / `NHA_FDB` (raw-netlink construction because `rtnetlink 0.21` exposes no nexthop API). Slice 1 (#84) added portable intent (`RemoteMacEntry::alias_group_key`) + projection same-AF guard. Slice 2 (#86) added the `nexthop_raw` netlink primitive with the canonical member-set encoder. Slice 3a (#87) added the state types (`NhIdAllocator` with 0x3000/0x4000 tag bits, `GroupOwnedMap` refcount) + apply primitive + CVE-2025-39851 inline guard (refuses install on a VXLAN device with `learning on`). Slice 3b (#88) is the operational-behavior-change slice: `compute_diff` Pass 1b emitting `InstallFdbNhg` / `UpdateFdbNhgMembers` / `RemoveFdbNhg`, reconcile actor coordinator orchestrating ADR-0059 §5 invariant order, `NexthopOps` impls on `LinuxDataplane` + `InMemoryDataplane`, startup NHID adoption with snapshot-aware retention set (blocks cleanup when FDB-NHG ops are permanently suppressed and when a kernel FDB row still references an adopted NHID), partial-install rollback (orphan-aware), three-key-space retry schedule (FDB by `(VNI, MAC)`, BUM by ifindex, FDB-NHG by `AliasGroupKey`), `pending_deletes` retry queue for steady-state GC failures with permanent-error classification, `drain()` branched on `OwnedEntryKind` so FdbNhg-owned MACs go through the `RemoveFdbNhg` teardown sequence on shutdown, and actor-level FDB-NHG test coverage (multi-homed install, shared-group refcount teardown, adoption-retention live-FDB-ref, perm-suppress blocks cleanup). Slice 4 (#89) added M40 containerlab smoke against FRR EVPN-MH 10.3.1 — three-node topology with rustbgpd VTEP observer + 2× FRR VTEPs sharing ES1 via the FRR-required bond shape, 16/16 PASS first-shot validating the expected `NHG_TAG | n` / `VTEP_NH_TAG | n` tag scheme on the kernel side and the clean drain-to-single-dst transition when an alias withdraws (the projection invariant `empty alias_vtep_ips ⇔ alias_group_key.is_none()` forces N=2 → N=1 to fall back). Slice 3.5 follow-ups (periodic `RTM_GETNEXTHOP` drift recovery, `apply_aliasing_ecmp` operator off-switch, IPv6 alias members) deferred from v0.19.0 and shipped post-release in PRs #91 / #92 / #93. M40 now runs in the hosted `kernel-dataplane` CI workflow.

- [x] **EVPN Gate 9 slice 6 — symmetric Interface-less IRB end-to-end** (v0.18.0, ADR-0058, PRs #66 / #67 / #72 / #73 / #74 / #75 / #76 / #77 / #78 / #79) — `[[evpn_ip_vrfs]]` TOML schema with VRF / L3VXLAN device binding, operator-supplied Router MAC, and an L2VNI `ip_vrf` link; pure-logic `IpVrf` / `IpVrfTable` domain types in `crates/evpn::ip_vrf` with config-load validation. Pure-logic Type 5 origination (`originate_ip_prefix_route`) + projection (`project_ip_prefix_routes`) helpers enforce the RFC 9136 §4.4.2 Interface-less symmetric IRB model. `IpVrfStatus` readiness probe checks the seven ADR-0058 §3 predicates (VRF device exists + UP + matches `table_id`; L3 VXLAN exists + UP + matches VNI + matches local VTEP IP + enslaved to the VRF + MAC matches Router MAC). `crates/evpn-linux` adds rtnetlink-backed VRF / L3VXLAN dumps that build an `IpVrfKernelSnapshot`. A new `Dataplane::probe_ip_vrfs` trait method wires the snapshot through `LinuxDataplane`; the reconcile actor calls it every pass, plumbs the `IpVrfTable` through `DataplaneIntent`, and surfaces readiness transitions via `tracing::info!` / `warn!`. `DataplaneReport.ip_vrf_status` rows, the new `EvpnService.ListIpVrfs` / `EvpnService.GetIpVrf` gRPC RPCs, and `rustbgpctl evpn vrfs [NAME]` expose the verdict to operators. Slice 6 PR A (#77) adds the runtime feed: per-IP-VRF kernel-route dump on every reconcile pass (classifier filters routes installed by other routing daemons, non-forwardable types, and routes whose output device is the L3 VXLAN), a `tokio::sync::watch` observation channel mirrored from `DataplaneReport.ip_vrf_routes`, the L3 originator task that turns observations into `RibUpdate::InjectEvpn` gated on readiness with a level-triggered diff loop, `IpVrfState.originated_routes_count` surfaced via gRPC + CLI, and three new Prometheus series. Slice 6 PR B (#78) closes the loop with remote Type 5 import + L3 FIB programming: best-path subscription drives `project_ip_prefix_routes()` against a transactional `L3OwnedState` model (`crates/evpn-linux/src/l3_diff.rs`) that tracks per-prefix install state plus shared `kernel_neighbors: BTreeMap<(idx, ip), MacAddress>` and `kernel_fdb: BTreeMap<(idx, MacAddress), IpAddr>` so the diff catches both refcount changes and value drift (Router MAC or next-hop transition under the same prefix triggers an atomic `.replace()` on the kernel-side rows). A four-phase apply ordering (route-remove → resolution-add → route-add → resolution-remove) keeps the kernel forwarding-safe across transitions; Router MAC conflicts (two prefixes mapping `(L3VXLAN idx, router_mac)` to different next-hops) drop conflicting prefixes with `L3Drop::RouterMacConflict`; foreign state preservation is enforced by diffing only against `L3OwnedState`. `DataplaneReport.ip_vrf_installed_routes`, `IpVrfState.installed_routes_count`, and install counters expose the surface to operators. 11 unit tests in `l3_diff.rs` and two privileged netns integration tests at `crates/evpn-linux/tests/netns_l3_install.rs` (gated on `EVPN_LINUX_NETNS=1`) validate kernel programming against Linux 6.17 including foreign-route preservation. **M39 hosted kernel-dataplane smoke** at `tests/interop/m39-evpn-type5-symmetric-irb.clab.yml` validates the bidirectional symmetric IRB datapath against FRR 10.3.1 — origination both directions, kernel route + L3 neighbor + L3VXLAN FDB rows, bidirectional `ip vrf exec vrf1 ping`, and the withdraw leg.
- [x] **ASPA verification** (v0.7.0) — upstream path verification with RTR v2 support, ADR-0049
- [x] **Config diff** (v0.7.0) — `rustbgpd --diff` previews SIGHUP changes
- [x] **Looking glass REST API** (v0.7.0) — birdwatcher-compatible endpoints
- [x] **Best-path explain** (v0.7.0) — `ExplainBestPath` RPC + `--explain` CLI
- [x] **EVPN Route Reflector Phase 1** (v0.9.0) — RFC 7432 RR role, all 5 route types, M29-M33 interop
- [x] **ADR-0051 writer-task split** (v0.10.0) — closes the +46-min `GetHealth` wedge under sustained churn; validated on 1h + 4h + 12h M33 soaks
- [x] **BMP `bmp_*_total` Prometheus counters** (v0.10.0) — 4 counters cover source / collector / replay / control-event drops
- [x] **EVPN BMP + MRT export** (v0.11.0) — RouteMonitoring already flowed; MRT now emits `RIB_GENERIC` for EVPN with `MP_REACH_NLRI` in RFC 6396 §4.3.4 reduced form
- [x] **`EvpnRibRoute` payload+key refactor** (v0.11.0) — drops cached key, identity derived on demand
- [x] **IPv6 link-local next-hop preserved end-to-end** (v0.11.0) — 32-byte `MP_REACH_NLRI` next-hops (RFC 4760 §3 / RFC 2545) round-trip through wire codec, RIB, and MRT exports; closes the long-standing "link-local discarded" KNOWN_ISSUES limitation. `rustbgpd-wire` 0.7.0 → 0.8.0 (breaking — adds `link_local_next_hop` field to `MpReachNlri`).
- [x] **EVPN VTEP foundation — declarative EVI/VNI domain model** (v0.13.0) — Gate 7a per `docs/evpn-enablement.md`. New `crates/evpn` exposes the runtime [`EvpnInstance`] / [`EvpnInstanceTable`] types; `[[evpn_instances]]` config block lands the operator-facing TOML surface (VNI, RD, RTs, local VTEP IP, optional bridge, `advertise_svi_mac`); read-only `EvpnService.ListEvpnInstances` + `rustbgpctl evpn instances` surface the resolved table. Wire crate gains `RouteDistinguisher::from_str`. Empty by default — RR-only deployments unchanged. Kernel reconciliation landed in Gate 7b; Type 2 local-MAC origination + Type 3 IMET landed in Gate 7b+1. ADR-0052.
- [x] **Tier-1 post-release cleanup bundle** (v0.13.1) — three small operational items: prometheus 0.13 → 0.14 (clears RUSTSEC-2024-0437; protobuf 3.x API migration in 4 internal/test files); M34 SIGHUP-policy interop test now reads rustbgpd's own `flapCount` + `uptimeSeconds` instead of FRR's `bgpTimerUpEstablishedEpoch` (cross-checked monotonicity catches handle replacement that flapCount alone would miss); EVPN MP_REACH IPv6 next-hop roundtrip + 32-byte rejection tests close the validate-side audit gap from v0.11.0.
- [x] **Tier-2 patch bundle** (v0.13.2) — four operational-debt fixes: dead-letter side table on `PeerManager` so dynamic peers don't lose `pending_refresh` / `pending_export_apply` across `BackToIdle` auto-removal; gRPC `ConfigEvent` → persister bridge no longer holds a stale snapshot across SIGHUP (replacement now routes through the bridge so subsequent gRPC mutations don't overwrite the persisted file with `stale_pre_reload + one_mutation`); `apply_reload_outcome` helper tightens post-reload sync ordering with named failure stages; `reload_config` runs on a dedicated tokio task so SIGINT/SIGTERM observation is no longer blocked by an in-flight reload. Stale RUSTSEC-2024-0437 ignore dropped from `.cargo/audit.toml`.
- [x] **RFC 8326 BGP Graceful Shutdown** (v0.13.3) — well-known `GRACEFUL_SHUTDOWN` community (`65535:0` / `0xFFFF_0000`) end-to-end. Wire constant in `crates/wire`, policy alias on match + set sides, opt-in `[global] honor_graceful_shutdown = true` knob that appends an implicit chain-tail rule (`match GRACEFUL_SHUTDOWN → set local_pref = 0`) to EBGP imports — running at the chain tail rather than head guarantees the demotion wins last-writer accumulation against operator policies that also set `LOCAL_PREF`. Initiator side: gRPC `NeighborService.SetGracefulShutdown` + `rustbgpctl gshut [--peer X] [--clear]` toggle. Desired state lives on `ManagedPeer` and replays into freshly spawned sessions on collision-replace / inbound-accept; new `RibUpdate::RefreshPeerOutbound` forces re-emission of `AdjRibOut` routes so the toggle is visible on the wire immediately. Typed `SetGshutError::PeerNotFound` / `Internal` distinguishes operator-typo from session/RIB failures at the gRPC layer. New `Route.local_pref_attr` proto field surfaces the explicit-vs-default `LOCAL_PREF` distinction. M35 interop validates both legs (FRR → rustbgpd inbound honor + rustbgpd → FRR outbound advertise + clear) end-to-end against FRR 10.3.1. ADR-0053. Confederation gating + cross-restart persistence + dynamic-peer replay tracked as follow-ups.
- [x] **Tier-3 patch bundle** (v0.13.4) — closes RFC 8326's three known limitations plus the long-deferred test-failure-mode coverage gap. `[global] honor_graceful_shutdown` now hot-applies on SIGHUP via a best-effort `set_honor_graceful_shutdown` on `PeerManager` that precomputes every EBGP peer's effective chain against the new snapshot, advances `current_config` unconditionally, and accumulates per-peer failures so a partial apply doesn't drift the live snapshot from `working_config` (the reload path absorbs the partial-apply `Err` as a `warn!` and aligns `working_config.global.honor_graceful_shutdown` to the peer manager's view). The per-peer dead-letter side table on `PeerManager` (introduced in v0.13.2) now also snapshots `advertise_graceful_shutdown` alongside `pending_refresh` / `pending_export_apply` before `BackToIdle`'s `peers.remove`, so dynamic peers re-establishing at the same address inherit the toggle instead of restarting at `false`. M35b (FlowSpec) and M35c (L2VPN/EVPN) containerlab tests validate `attach_graceful_shutdown_if_enabled` on the family-specific outbound emission paths, with per-flow TCP-reassembly capture parsers and a `wait_for_capture` polling helper so segmentation and re-emit timing don't flake under CI load. Three new `peer_manager` unit tests cover channel-full policy update, back-to-back hot-apply update, and peer-deletion-mid-retry shapes. No wire-crate change — `rustbgpd-wire` stays at `0.8.5`.
- [x] **EVPN VTEP local-MAC origination — Gate 7b+1** (v0.15.0, PR #35 merged 2026-05-07) — closes the upward EVPN flow that Gate 7b's foundation left as a stub. ADR-0055 locks the boundary. New `crates/evpn/src/origination.rs` ships the pure deterministic `LocalMacOriginator` state machine encoding RFC 7432 §15.1 (first-Learned-no-contender ⇒ seq=0 / no extcomm; first-Learned-vs-contender at R ⇒ R+1 with extcomm; remote announces M ≥ N ⇒ bump to `max(M, N) + 1`; aged-then-relearn preserves the seq ratchet); 17 in-module tests including a monotonicity invariant. New `crates/wire/src/pmsi.rs` adds the PMSI Tunnel path attribute (RFC 6514 §5, type 22) with a typed `PmsiTunnelType` (preserves unknown values for forward-compat) and a `for_evpn_ingress_replication(vni, ip)` constructor encoding the label as the raw 24-bit VNI per RFC 8365 §5.1.3; 16 codec tests + an integration round-trip through the full `PathAttribute` dispatch. New daemon-side `src/evpn_originator.rs` actor mirrors `evpn_dataplane.rs` on the upward flow — `tokio::select!` over local-MAC channel, RIB poll (5s default), and shutdown drain; per-instance `LocalMacOriginator`s, self-NH filter via the existing `project_evpn_routes`, shutdown drain emits Withdraws for every still-advertising MAC under a 5s bound. New `src/evpn_imet.rs` originates one Type 3 IMET (RFC 7432 §7.3) per `EvpnInstance` at startup and withdraws at shutdown; lifecycle decoupled from kernel Ready/NotReady because IMET advertises BGP-level VNI membership, not data-plane programmability. Upward channel surface in `crates/evpn-linux`: new `Dataplane::take_local_mac_rx` trait method (default `None`), `InMemoryDataplane` test inject hook, `LinuxDataplane::connect` calls `add_membership(RTNLGRP_NEIGH)` on the rtnetlink socket and spawns a worker that drains the unsolicited multicast stream and classifies via a pure `classify_neigh` function (drops `NTF_EXT_LEARNED` echoes, drops VXLAN-port ifindexes, resolves bridge-port → VNI via a new `LinkCache::bridge_port_to_vni` map). Daemon main wiring spawns the originator alongside the reconciler under the same `[[evpn_instances]]` gate; coordinated shutdown drains originator → IMET withdraws → reconciler. RR-only deployments still spawn no background tasks; macOS dev builds still build cleanly. M37 containerlab interop smoke (`tests/interop/m37-evpn-local-origination.clab.yml`) validates rustbgpd as a Type 2 + Type 3 originator against an FRR consumer. Deferred and tracked at the time were MAC-with-IP origination, `advertise_svi_mac`, sticky/static MAC config, duplicate-MAC handling, Gate 7c convergence, `RTNLGRP_LINK`, runtime `[[evpn_instances]]` mutation, and multi-homing; later releases closed the MAC+IP, SVI-MAC, sticky-MAC, Gate 7c, and local-origin duplicate-MAC suppression slices, while duplicate-MAC remote-route processing / dataplane loop-protection remains tracked in [#139](https://github.com/lance0/rustbgpd/issues/139).
- [x] **EVPN Linux dataplane reconciler — Gate 7b foundation** (v0.14.0, PR #34 merged 2026-05-06) — ADR-0054 contract closed end-to-end with real netlink. New workspace crate `crates/evpn-linux` ships the level-triggered `ReconcileActor<D: Dataplane>`, the pure `compute_diff` function with structural foreign-entry preservation (delete pass iterates `OwnedSet`, never the kernel snapshot), per-op exponential backoff (100 ms → 5 s with deterministic ±25% jitter), per-op-fingerprint permanent-failure suppression (mobility / add↔remove on the same key clears stale suppression inline; cross-key isolation is structural; generation churn alone never clears anything), and a `tokio::sync::watch<Arc<DataplaneIntent>>` input from the daemon. `crates/evpn` gains `DataplaneIntent` / `RemoteMacTable` / `LocalMacObservation` plus a pure `project_evpn_routes` from RIB best-paths. Daemon `src/evpn_dataplane.rs` polls the RIB's existing `QueryEvpnRoutes` channel every 5 s, publishes intents, and only bumps the intent generation on semantic `RemoteMacTable` change; empty `[[evpn_instances]]` short-circuits the spawn (RR-only deployments incur zero dataplane cost — verified by `tests/evpn_dataplane_rr_only.rs`). The `LinuxDataplane` programs FDB via a single `RTM_NEWNEIGH` targeting the VXLAN port ifindex with combined `NTF_SELF | NTF_MASTER | NTF_EXT_LEARNED` and `ndm_state = NUD_NOARP | NUD_PERMANENT` (matching iproute2's wire shape), the FDB dump path merges the kernel's `NTF_SELF` (carries `dst`) and `NTF_MASTER` (no `dst`) rows for the same `(VNI, MAC)` so `dst` survives, and the errno-based classifier maps `EPERM`/`EACCES` → `PermissionDenied`, `EOPNOTSUPP` → `KernelTooOld`, `EINVAL` → `InvalidArgument` (all permanent-class) through rtnetlink 0.14 / netlink-packet-route 0.19. Per-instance probe enforces the ADR §4 five-point readiness check. M36 real-VTEP containerlab smoke (`tests/interop/m36-evpn-vtep-smoke.clab.yml`, `scripts/test-m36-evpn-vtep-smoke.sh`) passes 8/8 locally against Linux 6.17 + FRR 10.3.1 with rustbgpd-as-VTEP and FRR-as-originator over iBGP/AS65000, asserting `extern_learn` per-row on both the bridge and the VXLAN-self rows plus `dst` and foreign-entry preservation through withdraw. Privileged netns integration test at `crates/evpn-linux/tests/netns_dataplane.rs` carries the same per-row assertions (gated by `EVPN_LINUX_NETNS=1`; privileged-runner CI job is a deferred follow-up, not in the PR). +87 net workspace tests (1406 → 1493). Deferred from PR #34 but later shipped in PR #35: `RTNLGRP_NEIGH` local-MAC observation, local MAC-only Type 2 origination, and Type 3 IMET per L2VNI. Still deferred and tracked: `RTNLGRP_LINK` / reconcile-trigger event subscription, bridge / VXLAN netdev creation (operator pre-creates per ADR §4), VLAN-aware bridges (probe rejects with `NotReady`), L3VNI / IRB / Type 5 dataplane, MAC-with-IP origination, sticky/static MAC policy, duplicate-MAC remote-route processing / dataplane loop-protection, `advertise_svi_mac` flag wiring, gRPC mutation surface for `[[evpn_instances]]`, and multi-homing execution (Gate 8).

### P0–P2.5 — Complete

All foundational features shipped. See Completed section above.

- [x] **Policy actions** — route modification on import/export (ADR-0030)
- [x] **AS_PATH regex matching** — Cisco/Quagga-style patterns in policy (ADR-0030)
- [x] **Large communities** (RFC 8092) — full feature track (ADR-0031)

### Deferred Hardening

Items identified during review that improve strictness, correctness, or long-run operational safety.

#### Highest Priority

- [x] **Critical control message channel-full resilience** — inbound `EoR`, route-refresh lifecycle markers, `PeerUp`, `SetPeerPolicyContext`, `PeerDown`, and `PeerGracefulRestart` now use reliable `send(...).await` delivery to the RIB instead of lossy `try_send`
- [x] **GR timer vs buffered `EoR` race** — the RIB manager now drains already-buffered main-channel updates before executing GR/LLGR/refresh timer sweeps so buffered `EoR` work is processed first
- [x] **LLGR_STALE community stripping for non-LLGR peers** — outbound transport now strips `LLGR_STALE` (65535:6) for destination peers that did not negotiate LLGR for that family, matching RFC 9494 §4.6
- [x] **Attribute intern table garbage collection** — `AdjRibIn::gc_intern_table()` now runs on unicast withdraw chunks, and empty per-peer `AdjRibIn` entries are removed on `PeerDown`

#### API / Wire Correctness

- [x] **Injection API zero-value local_pref/MED** — injection now uses presence semantics, allowing valid `local_pref=0` and `med=0` values
- [x] **Peer group API validation parity** — peer group families and `remove_private_as` strings are validated and normalized through the same helpers as dynamic neighbors
- [x] **Policy action string validation at API layer** — invalid `default_action` and statement actions are now rejected with `INVALID_ARGUMENT`
- [x] **Add-Path explain support** — `ExplainBestPath` now optionally scopes to a peer; in peer-scoped mode every candidate that the peer would actually receive (export-policy permitted + sendable-family + not suppressed by split-horizon or iBGP/RFC 4456 RR rules + within `add_path_send_max`) gets a non-zero `advertised_path_id` reflecting its rank. CLI `rustbgpctl rib --prefix X --explain --explain-peer P`. JSON output preserves the v0.7.0 global-view shape (new fields skip-when-default). Proto changes additive.
- [x] **FlowSpec NLRI length encoding >4095 bytes** — locally injected / withdrawn FlowSpec rules now validate their encoded NLRI payload length before entering the RIB; rules above the 4095-byte RFC 8955 rule-length ceiling are rejected instead of silently wrapping the 12-bit length field
- [x] **AS_PATH segment >255 ASN encoding** — long `AS_SEQUENCE`/`AS_SET` segments are now split into multiple wire segments during encode instead of silently truncating via `u8` wrap
- [x] **IPv6 next-hop policy rewrite completeness** — export policy `set_next_hop = "<ipv6>"` is covered end-to-end for MP_REACH exports and route explain; classic IPv4 `NEXT_HOP` handling remains unchanged
- [x] **LOCAL_PREF/MED policy match implicit defaults** — `match_local_pref_ge/le` and `match_med_ge/le` now apply RFC 4271's implicit defaults (100 for `LOCAL_PREF`, 0 for `MED`) when the attribute is absent. A policy `match local-preference >= 100` reads identically against eBGP-received routes (no LP on the wire) and iBGP routes (LP attribute present), matching FRR / BIRD / GoBGP convention.
- [ ] **Typed error variants for API deletion handlers** — policy and peer-group deletion operations match error messages with `error.contains("still referenced")` instead of typed error variants; fragile coupling to internal error strings
- [x] **Deduplicate `validate_policy_action()` / `proto_statement_to_input()`** — extracted to `policy_helpers.rs`, shared by `policy_service.rs` and `peer_group_service.rs`

#### Operational / Observability Hardening

- [ ] **Unknown FlowSpec component forward compatibility** — component types >13 currently cause hard decode errors; should skip unknown types to allow future RFC extensions without breaking interop
- [x] **gRPC UDS + bearer auth hardening** — gRPC now defaults to a local Unix domain socket, TCP listeners are explicit opt-in, and per-listener bearer-token auth is available via `token_file`
- [x] **FlowSpec fuzz target** — `decode_flowspec` fuzz target added for direct FlowSpec NLRI decoding coverage
- [x] **FlowSpec GR/LLGR lifecycle parity** — FlowSpec routes now stale-mark, promote/sweep, clear on `EoR`, recompute/distribute, and remove locally injected `LLGR_STALE` tags in lockstep with unicast GR/LLGR handling
- [x] **Policy engine test modularization** — extracted the `merge_from` + `PolicyChain` test cluster into `engine/tests/chain.rs` to reduce monolithic test sprawl while preserving behavior
- [ ] **Large community duplicate normalization** — received UPDATEs with duplicate large communities are stored and re-advertised unchanged; strict RFC 8092 behavior would dedup on receipt and before encode
- [x] **RTR persistent session + Serial Notify** — RTR client now keeps the TCP session open after EndOfData, honors Serial Notify for immediate updates, and uses refresh_interval as a fallback serial-poll timer (RFC 8210 §8)
- [x] **RTR expire_interval enforcement** — config and server-advertised expire timers are now enforced; VRPs are cleared if no fresh EndOfData arrives before the expiry window
- [ ] **ERR metrics** — no gauge for active enhanced route refresh windows or pending refresh-stale route count; would improve operational visibility during soft resets
- [ ] **Inbound BoRR/EoRR retry on channel-full** — inbound BoRR/EoRR markers are silently dropped (with warning) when the RIB channel is full; unlike outbound responses which have `pending_refresh` retry, inbound markers have no recovery path
- [x] **BMP collector reconnect replay** — `BmpManager` caches live Peer Up state and replays it only to the collector that just reconnected
- [x] **BMP periodic Stats Report** — `PeerManager` now emits per-peer periodic BMP Stats Report messages (type 7: Adj-RIB-In routes) every 60 seconds
- [x] **BMP Termination on daemon shutdown** — coordinated shutdown now signals `BmpManager` explicitly, then drains manager/client tasks with bounded waits so connected collectors receive Termination before process exit
- [x] **BMP event-drop counters** (v0.10.0) — `bmp_source_drops_total{peer, reason}`, `bmp_collector_drops_total{collector, phase, reason}`, `bmp_replay_attempts_total{collector}`, and `bmp_control_event_drops_total{collector, kind, reason}` cover every drop / replay / control-event-drop site. Replay aborts attribute every cached `PeerUp` as dropped (not just the first failed `try_send`), and `CollectorConnected` uses an awaited 1 s send so a wedged manager surfaces as a counter increment instead of a silent skipped replay.
- [x] **BMP transport integration tests** — session-to-BMP emission paths (PeerUp/PeerDown/RouteMonitoring) now covered by transport crate tests
- [ ] **BMP periodic stats scalability** — `emit_periodic_bmp_stats` serializes `query_state().await` per peer; at hundreds of peers this could stall the PeerManager select! loop; consider concurrent queries or cached counts
- [ ] **BMP client connect-loop shutdown** — client stuck in TCP connect-backoff cannot observe channel close until next `rx.recv()`; mitigated by abort timeout but prevents clean Termination to unreachable collectors
- [x] **Duplicate BMP collector address detection** — config validation now rejects duplicate collector addresses
- [x] **CLI gRPC integration tests** — mock gRPC server over both TCP+token and UDS, covering health, global, neighbor add, and soft-reset command-to-RPC paths
- [ ] **Dynamic neighbor `handle_inbound` refactor** — `handle_inbound()` grew to ~130 lines with the dynamic branch; split into `handle_inbound_static` and `handle_inbound_dynamic` for readability (behind `#[expect(clippy::too_many_lines)]` for now)
- [x] **RTR/RPKI cache interop** — M21 containerlab scenario with StayRTR: RTR session, v2→v1 fallback, VRP delivery, origin validation (Valid/Invalid/NotFound). Found and fixed real v2→v1 version fallback bug.
- [x] **ASPA/RTR v2 cache interop** — M27 containerlab scenario with Python RTR v2 mock server (StayRTR lacks ASPA support): RTR v2 negotiation, ASPA record delivery, validation states (valid/invalid/unknown), best-path preference at step 0.7 with two FRR peers, ROA+ASPA coexistence over single session.
- [x] **FlowSpec peer interop** — M22 containerlab scenario: FlowSpec injection via gRPC, distribution to FRR, withdrawal propagation. FRR 10.3.1 receives but cannot originate.
- [x] **GoBGP peer interop** — M23 containerlab scenario: bidirectional route exchange, attributes, withdrawal against GoBGP 4.3.0.
- [x] **BMP collector interop** — M24 containerlab scenario: Python BMP receiver validates Initiation, PeerUp, RouteMonitoring messages and ordering.
- [x] **TCP MD5/GTSM interop** — M25 containerlab scenario: two FRR peers, one with MD5 auth, one with GTSM/TTL security. Both sessions establish and exchange routes.
- [x] **Cease subcode compatibility** — M26 containerlab scenario: FRR accepts Cease/1 (Max Prefixes) cleanly, session re-establishes. INTEROP.md table updated.
- [ ] **SIGHUP reconcile rollback semantics** — reload now reports structured per-peer failures and keeps the prior config snapshot, but does not roll back already-applied runtime peer changes from earlier reconcile steps
- [x] **SIGHUP policy/peer-group reconciliation** (v0.12.0) — `reload_config` now applies named-policy, neighbor-set, peer-group, and global-chain deltas via the same `apply_policy_change` / `apply_peer_group_change` paths the gRPC API uses. Order: definitions/sets/peer-groups/chains add+change first, then `[[neighbors]]` reconcile, then deletes in reverse-dependency order. Inline `policy.import` / `policy.export` still require restart (no runtime swap surface) and surface under "Restart-required" in `--diff`.
- [x] **Effective neighbor diff via peer-group resolution** (v0.12.0) — `ConfigDiff::effective_neighbor_impact` lists neighbors whose resolved chain moves at reload, with the upstream change(s) (peer_group / policy / neighbor_set / global chain) responsible. Surfaced under "Reload-applied" in `rustbgpd --diff` and the JSON diff output.
- [ ] **MRT snapshot encode allocation pressure** — `TABLE_DUMP_V2` encode path currently builds grouped route vectors and clones attributes per entry; correct but allocation-heavy on very large dumps (optimize if MRT CPU/latency becomes material)
- [x] **gRPC listener split** — each configured gRPC listener can now run in `read_only` or `read_write` mode, allowing monitoring/query exposure without exposing mutating control-plane RPCs
- [x] **Optional Prometheus listener** — `prometheus_addr` is now optional; omit it to skip the metrics HTTP server while still collecting metrics for gRPC health and internal counters
- [x] **Native gRPC mTLS** (v0.11.0) — TCP listeners terminate TLS in-process via tonic + rustls/ring. TCP listeners require complete certificate/key/CA material; UDS listeners keep filesystem permissions as their auth boundary.
- [x] **Finer-grained gRPC authorization** — ADR-0064 now has a checked
  72-RPC method-tier matrix, runtime decision telemetry, tier enforcement,
  staged `[security.grpc.roles]`, explicit non-mTLS listener principal labels,
  mTLS certificate principal extraction, listener `max_tier` caps, and
  hardened result/request audit records. Remaining work is the external
  security audit, tracked as a v1.0 gate.
- [x] **FSM stale timer event handling** — timer events (ConnectRetry/Hold/Keepalive) arriving in states where the timer should not be running per RFC 4271 §8.1 now emit `Action::StaleTimerIgnored { state, timer }` and leave the session in place, instead of falling through to FsmError + teardown. The daemon hooks the action and bumps `bgp_fsm_stale_timer_events_total{peer, state, timer}` so the events stay observable. 11 explicit (state, timer) arms across all 6 FSM states; matches FRR / BIRD / GoBGP behavior.
- [x] **Validation snapshot delivery to transport sessions** — `match_rpki_validation` and `match_aspa_validation` now work in import policy. `ValidationSnapshot` (VRP + ASPA tables) delivered to transport sessions via `tokio::sync::watch` channel. Each session borrows the latest immutable snapshot and evaluates import policy against it. RIB-side revalidation remains the correctness backstop. Config rejection for import validation matches removed.
- [ ] **Convergent import validation on cache update** — import `match_rpki_validation` / `match_aspa_validation` is currently best-effort at ingress time; later VRP/ASPA cache updates do not re-run import policy or trigger route refresh for affected peers. Fix: on cache update, trigger `SoftResetIn` for peers whose resolved import policy uses validation-state matches. Infrastructure exists (route refresh, per-peer policy tracking). Not urgent — current semantics match FRR/BIRD behavior and are documented in KNOWN_ISSUES.

#### RFC 9234 (BGP Roles + OTC) follow-ups

Tracked here in the Deferred Hardening table so the ADR-0071 "Deferred"
section has an operator-visible roadmap counterpart. None are blocking
— v1 ships static eBGP Role configuration + IPv4/IPv6 unicast OTC
procedures, and the M55 interop proves it.

- [ ] **iBGP Roles** — RFC 9234 §4 scopes Roles to eBGP today. iBGP Roles would extend the leak-detection surface inside a confederation / cluster; needs the working-group discussion to settle on semantics first.
- [ ] **AS Confederation sub-AS Roles** — RFC marks NOT RECOMMENDED; if confederation support later exports OTC across the confederation boundary, the OTC ASN MUST be the **Confederation Identifier**, not a member AS (RFC 9234 §5). Captured here so the future confed implementer doesn't recreate the same trap.
- [ ] **Complex peering on a single eBGP session** — RFC: MUST NOT configure Roles on a session that is Peer for some prefixes and Customer for others. Operators with mixed relationships split into multiple sessions today. A per-prefix role surface would need a separate ADR + working-group precedent.
- [ ] **Dynamic role change without session restart** — `role` / `strict_role` reload class is **live (effective next session)** in `docs/reload-matrix.md`. Lifting that to in-place re-evaluation needs a Route-Refresh + revalidation pass plus a careful look at the compatibility-matrix replay against an already-Established session. Future ADR if demand appears.
- [ ] **Operator override of OTC behaviour** — e.g. forced strip on egress for asymmetric leak protection, or per-neighbor opt-out of the I1/I2 drop. Deliberately not exposed in v1; would be config sugar over the existing policy engine.
- [ ] **OTC scope beyond IPv4 / IPv6 unicast** — RFC 9234 §5 explicitly scopes the procedures to AFI 1/2 SAFI 1, and v1 honors that. If a future RFC extends OTC to FlowSpec / EVPN / VPN-IPv4, the egress hook would land in `prepare_outbound_attributes_flowspec` / `_evpn`; the v1 code path leaves them untouched.
- [x] **`OtcRouteBlocked` structured event payload** — shipped as PR #292 (v0.30.0). `OtcRouteBlockedEvent` rides on `EVENT_CATEGORY_POLICY` with the next-free `BgpEventType` enum value; payload carries `peer`, `direction`, `reason`, `prefixes`, `local_role` / `remote_role`, optional `otc_value`, and a lossless string AS_PATH. The legacy `bgp_otc_routes_blocked_total{peer, reason}` counter and `NeighborState.otc_routes_blocked` scalar are unchanged.

#### gNMI / OpenConfig telemetry follow-ups (ADR-0070)

Tracked here so the ADR-0070 "Deferred" section has a roadmap counterpart. v1 ships read-only `Capabilities` / `Get` / `Subscribe` (`ONCE` / `POLL` / `STREAM SAMPLE`) over the strict OpenConfig BGP state subset; the gNMI interop suite (M54) covers the surface end-to-end.

- [ ] **gNMI `Set` + config datastore** — needs the ADR-0064-gated config transaction model (separately tracked as P2). v1 `Set` returns a stable `Unimplemented`.
- [x] **`Subscribe ON_CHANGE`** — shipped as PR #293 (v0.30.0). v1 covers `STREAM` + `ON_CHANGE` for `…/neighbor[neighbor-address=*]/state/session-state` only (both the explicit `*` wildcard and the no-key shorthand). The handler consumes live `CommittedEvent`s from `EventHistoryManager::subscribe_live()` and emits per-leaf OpenConfig Updates. Initial sync emits one Update per configured peer + `sync_response`; reconnect = fresh snapshot (no replay); broadcast `Lagged` = `DataLoss` close. Counter leaves and `enabled` remain SAMPLE/POLL-only. Authz unchanged (still `SensitiveRead`).
- [ ] **Per-AFI-SAFI prefix counters** (`received` / `sent` / `installed`) — no trustworthy per-family source today; lands when the RIB exposes per-family install counts.
- [ ] **Per-neighbor `installed` / `accepted` prefix split** — only a global Loc-RIB best-path count exists today.
- [ ] **`supported-capabilities` + negotiated AFI-SAFI state** — needs a peer snapshot extension that surfaces the negotiated capability set (the data exists internally but isn't on the snapshot today).
- [ ] **`global/state/total-prefixes` and `total-paths`** — `total-prefixes` means prefixes *received* in OpenConfig context, which the Loc-RIB best-path count doesn't represent; `total-paths` has no pre-best-path aggregate.
- [ ] **`neighbors/neighbor[...]/state/last-established`** — absolute last-transition timestamp on the peer snapshot. Only elapsed-since-Established is tracked today; lift to a wall-clock instant.
- [ ] **gNMI `PROTO` / `ASCII` encodings, multicast / VPN AFIs, full OpenConfig BGP coverage** — v1 ships JSON / JSON_IETF over the BGP subset; widen on demand.
- [ ] **BFD / FIB / EVPN OpenConfig(-adjacent) telemetry surfaces** — after the BGP subset proves the path-parser + renderer pattern.
- [ ] **YANG / NETCONF / RESTCONF** — deprioritized; gNMI is the telemetry-first surface.

#### Operator Confidence Polish Sprint 1 follow-ups

Sprint 1 (PRs #282 / #283 / #284 / #285) shipped the reload matrix, the
`bgp_policy_routes_total` counter across both directions, the four
scalar `NeighborState` aggregates, the CLI Policy Stats block, and the
deployment guide. These items were explicitly carved out at the time
of merge.

- [ ] **`reason` label on `bgp_policy_routes_total`** — per-clause attribution (which statement inside the named policy matched). Pushes cardinality from ~1k to ~8k labelsets; still bounded by config but not free. Pairs naturally with the best-path explain enrichment below.
- [ ] **FlowSpec / EVPN policy-counter explicit unit tests** — the counter wiring in `stage_flowspec_rules` / `stage_evpn_routes` is exercised via `distribute_*` but lacks dedicated unit cases asserting `direction="export", action ∈ {permit, deny}` with the right policy label. Sprint 1 PR2b review noted this as a NIT.
- [ ] **Best-path explain enrichment** — RIB-side sibling to PR2a's policy-explain enrichment. The `ExplainBestPath` deny / no-best path currently reports the structural reason (no candidate, RR split-horizon, etc.) but not the policy-clause attribution that PR2a added on the export side. Lifting that the same way — without metric double-count — gives operators "why is THIS the best route" with structured reasons.
- [x] **Import policy explain** — shipped as ADR-0073 (`rustbgpctl policy explain --neighbor X --prefix Y`). Rather than the originally-sketched `RibUpdate::ExplainImportedRoute` re-evaluation (which can only answer for *accepted* routes), this is backed by a bounded per-session import-decision cache in transport that records every permit **and** deny at the eval site — so the load-bearing "why was this denied?" case is answerable even though denied routes never reach the RIB. `PolicyService.ExplainImportPolicy`, IPv4 / IPv6 unicast, outcomes permit/deny/withdrawn/evicted/stale/not_seen. `[policy.explain].enabled` gates the write-path cost; statement-level attribution remains a deferred follow-up (see the `reason`-label item above).
- [ ] **`rustbgpd --diff` output formatted by reload class** — `--diff` currently groups changes by section. Cross-reference each diff line against `docs/reload-matrix.md` so the operator sees "(live)" / "(restart-required)" inline. Polish.

### P1 — Core Protocol Gaps

Features that close meaningful protocol gaps vs GoBGP.

- [x] **Extended Messages** (RFC 8654) — raise 4096-byte limit to 65535; capability code 6 (ADR-0032)
- [x] **Add-Path** (RFC 7911) — dual-stack receive + family-aware multi-path send (route server mode); composite RIB keying, multi-candidate best-path, rank-based path IDs (ADR-0033)
- [x] **RPKI validation** — RTR client (RFC 8210) for route origin validation; VRP table, best-path step 0.5, policy matching (ADR-0034)
- [x] **FlowSpec** (RFC 8955/8956) — IPv4 and IPv6 unicast FlowSpec (SAFI 133); all 13 component types, numeric/bitmask operators, FlowSpec actions via extended communities, gRPC injection/query (ADR-0035)
- [x] **BGP Roles + OTC** (RFC 9234, ADR-0071, M55) — static eBGP neighbors can advertise Provider / Customer / Peer / RS / RS-Client Roles, reject incompatible or contradictory Role OPENs with NOTIFICATION 2/11, and apply Only-to-Customer (OTC) route-leak procedures for IPv4/IPv6 unicast. M55 proves compatible FRR role pairs, mismatch / strict-mode rejection, OTC egress set, deliberate ingress leak rejection, and malformed-OTC treat-as-withdraw. FlowSpec/EVPN are intentionally untouched in v1.
- [ ] **ASPA verification — complete scope** — ASPA path verification ships (VRP/ASPA `ValidationSnapshot`, `match_aspa_validation` import policy, draft-v25 §5.4 algorithm fidelity + §6.2 per-AFI/SAFI gate via PR #294). Extend toward the full draft-ietf-sidrops-aspa-verification scope (downstream / customer-cone in addition to the upstream path) as ASPA reaches GA across RIRs (ARIN Jan 2026, RIPE production, APNIC Q2 2026), matching BIRD / OpenBGPD router-side verification. Pairs with BGP Roles as the 2026 route-leak-prevention bundle for the MANRS / IXP audience. **Remaining gaps beyond PR #294 (deferred, not blocking):** draft v25 §5.4 step 2 first-AS precondition (no `enforce-first-as`-equivalent today — ASPA verdicts against peers that strip or rewrite the leftmost AS may be misleading); NIST-BRIO test vector import; `match_aspa_validation` import/export policy-match unit coverage.

### P2 — High-Impact Parity Gaps

Features that close the most impactful gaps vs GoBGP for the target user base.
Each moves overall parity 3-5% while disproportionately improving real-world usability.

- [x] **Transparent route server mode** — `route_server_client` per neighbor: skip automatic local ASN prepend on eBGP re-advertisement for IX route-server clients, preserve original unicast NEXT_HOP, and apply the same transparent AS_PATH behavior to FlowSpec export (ADR-0039)
- [x] **GR restarting speaker** — minimal honest mode: static peers advertise `R=1` after coordinated restart via persisted marker file; `forwarding_preserved` remains false until restart-safe forwarding-state verification exists (ADR-0040)
- [x] **Policy chaining + named policies** — named TOML definitions, GoBGP-style chain evaluation (permit=continue, deny=stop), configurable default_action (ADR-0036)
- [x] **Peer groups + peer-aware policy matching** — reusable peer templates with runtime CRUD, neighbor-set matching, route-type matching, exact next-hop matching, and MED / `LOCAL_PREF` comparison in policy; persisted through TOML config snapshots
- [x] **Extended nexthop** (RFC 8950) — capability code 5, automatic dual-stack negotiation, IPv4 unicast over IPv6 next-hop via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` (ADR-0037)
- [x] **BGP unnumbered / IPv6 link-local peering** (v0.29.0, ADR-0069, M53) — static interface-bound IPv6 link-local neighbors over true unnumbered fabric links. Scoped peer identity `(address, interface)` threaded through active connect (scoped `SocketAddrV6`), passive accept (arrival scope-id match), TCP collision handling, `PeerManager`, and the gRPC / CLI / status surfaces (`fe80::x%ifname`); IPv6 GTSM via Hop-Limit / `IPV6_MINHOPCOUNT`. RFC 8950 Extended Next Hop is required and **fails closed** for `ipv4_unicast` on such peers (no IPv4 body-NLRI fallback, inbound or outbound); outbound emits the FRR-proven 32-byte link-local/link-local `MP_REACH` next-hop. The Linux unicast FIB installs IPv4 routes via IPv6 link-local gateways with the correct egress `dev` (`RTA_VIA` + `RTA_OIF` single-path, per-hop `rtnh_ifindex` for ECMP / weighted multipath), keyed by `(address, ifindex)` so the same `fe80::` over different interfaces stays distinct and diff-stable; missing scope is rejected as `link_local_next_hop_scope_missing`. M53 proves establish / IPv4-over-link-local exchange / two-FRR-peer scoped kernel ECMP / withdraw-collapse / recovery against FRR 10.3.1, with no IPv4 on the fabric links. **Deferred:** the same link-local address bound to *multiple* interfaces (the RIB still keys peers by bare address, so config rejects it on load + SIGHUP until a scoped RIB peer key lands — the RIB's ECMP next-hop dedup and the Linux FIB layer already key by `(address, ifindex)`); FRR-style `neighbor IFACE interface remote-as external` interface autodiscovery; IPv6 link-local BFD for unnumbered peers (follows naturally now that scoped BGP peer identity exists — lifts the ADR-0067 deferral); Link-Local Next Hop Capability code 77 / 16-byte link-local-only next-hop (the M53 capture shows FRR 10.3.1 sends the 32-byte form and does not advertise cap 77, so it is not a prerequisite for the pinned target); and multihop / non-point-to-point unnumbered plus policy-driven link-local next-hop synthesis without an interface.
- [x] **CLI tool** — `rustbgpctl` wrapping gRPC with human-readable and JSON output; covers all supported RPCs
- [x] **Admin shutdown communication** (RFC 8203) — human-readable reason text in Cease NOTIFICATION; threaded from gRPC DisableNeighbor through transport
- [x] **Enhanced Route Refresh** (RFC 7313) — BoRR/EoRR demarcation and inbound family replacement semantics for `SoftResetIn`
- [x] **EVPN Route Reflector — Phase 1** (RFC 7432) — L2VPN/EVPN (AFI 25 / SAFI 70) RR role for VXLAN-EVPN DC fabrics. All 5 RFC 7432 route types (EAD per-ES, EAD per-EVI, MAC/IP, IMET, Ethernet Segment, IP Prefix per RFC 9136), MAC mobility best-path per §15.1 with sticky-flag preservation, RFC 4456 reflection applied to EVPN routes, 6 typed extended-community accessors (BGP Encapsulation for VXLAN per RFC 8365/9012, MAC Mobility, ESI Label, ES-Import RT, Router MAC per RFC 9135, Default Gateway). `ListEvpnRoutes` gRPC RPC + `rustbgpctl evpn` CLI. Gates 0-6 closed on `feat/evpn-rr`: capability sanity (M29), real Type 2 MAC reflection with kernel VXLAN (M30), GR/LLGR stale handling, MAC mobility / sticky preservation interop (M31), multi-homing Type 1 EAD-per-EVI + Type 4 ES reflection (M32 — FRR ES on a bond interface), 50k-route scale validation with churn (M33), and controller-driven injection via `AddEvpnRoute` / `DeleteEvpnRoute` gRPC. Includes review correctness fixes: source-peer split horizon, same-peer attribute-change detection, full RFC 4456 tie-break chain (stale → ORIGIN → CLUSTER_LIST → ORIGINATOR_ID), max-prefix counting EVPN keys + FlowSpec rules, EVPN withdrawals propagated through both AS_PATH and CLUSTER_LIST loop branches, EVPN initial dump for late-joining peers, EVPN ERR refresh tracking, Type 5 prefix in policy context, proto3 default-correct `disable_vxlan_encap` field. See ADR-0050 and [docs/evpn-enablement.md](docs/evpn-enablement.md) for the Gate 0-9 ladder.
- [x] **EVPN Phase 2 — VTEP mode (single-homed L2VNI alpha)** — local EVI/VNI state, MAC learning from kernel FDB, local route origination. Required for general-purpose routing; not required for RR-only deployments. Kernel integration design in ADR-0054 (Gate 7b foundation, v0.14.0) and ADR-0055 (Gate 7b+1 origination boundary, v0.15.0). The bidirectional VTEP loop is closed — kernel-learned local MACs flow up via RTNLGRP_NEIGH → BGP EVPN Type 2 originations with RFC 7432 §15.1 mobility, and one Type 3 IMET per L2VNI carries RFC 6514 §5 PMSI Tunnel for ingress-replication BUM. Gate 7b+2 closes the MAC-with-IP path under ARP/ND suppression (v0.17.0), Gate 7c switches the originator to push-notified RIB broadcasts for sub-second mobility convergence (v0.17.0), `advertise_svi_mac` originates the bridge's own MAC on Ready (v0.17.0), `sticky_macs` config carries the RFC 7432 §15.4 sticky bit on origination (v0.17.0, ADR-0056), and the RFC 7432 §15.1 duplicate-MAC detector now supports the opt-in `suppress_local` quarantine action that withdraws and holds offending `(VNI, MAC)` Type 2 routes until the recovery window elapses. Runtime mutation foundation now exposes a generationed startup model through `GetEvpnRuntime`, has the ADR-0063 coordinator core / commit gate, and includes the public `ApplyEvpnRuntime` validation/no-op/fail-closed API contract; single L2VNI/IP-VRF/Ethernet-Segment add/delete/redefine, atomic tenant teardown, and `ip_vrf` relink now commit live, while VLAN-aware bridges and rustbgpd-managed bridge / VXLAN netdev creation remain operator-demand follow-ups — see `docs/evpn-enablement.md`.
- [x] **EVPN Phase 3 partial — Multi-homing foundation (Gate 8)** (v0.17.0, ADR-0057) — observable DF election + Type 1/4 origination. Pure DF election state machine (RFC 7432 §8.5 service carving + RFC 8584 §3.2 Highest Random Weight + RFC 9785 Highest-/Lowest-Preference, with fallback to default when candidates disagree), three Type 1/4 originator state machines (Type 4 ES, Type 1 EAD-per-ES with MAX_ET, Type 1 EAD-per-EVI), daemon orchestrator subscribed to the EVPN best-path broadcast, Prometheus `evpn_df_role{esi,vni,role}` gauge + `evpn_df_role_changes_total` counter, and an ADR-0063 runtime owner/control surface that keeps complete desired-ES snapshots under the segment actor rather than generic Type 1/4 route injection. M38 smoke topology (2-PE rustbgpd shared ESI) covers default modulo; M46 covers HRW; M49 covers RFC 9785 Highest-Preference. Gate 8b forwarding enforcement has since shipped: BUM suppression and aliasing ECMP are production defaults with explicit opt-out flags. RFC 9785 local Don't-Preempt origination shipped (`df_dont_preempt`); the DP bit is origination + parse only (a stateless `preference_winner` can't implement "don't preempt the incumbent", so it is not an election input). Stateful non-revertive election + single-active backup-path pre-install remain deferred.
- [x] **EVPN Phase 3 partial — Gate 8b prep extcomms** (v0.17.0, ADR-0057) — auto-derived ES-Import RT extcomm (RFC 7432 §7.6) on Type 4 ES routes and ESI Label extcomm (RFC 7432 §7.5) on Type 1 EAD-per-ES routes. `[[ethernet_segments]].redundancy_mode` now sets the ESI Label `single_active` flag (`all-active` default, `single-active` opt-in), and the receiver suppresses all-active aliasing ECMP for remote single-active ES reachability. M38 driver asserts the base extcomms appear on the wire; single-active backup-path pre-install remains a follow-up.
- [x] **EVPN Phase 3 partial — Gate 8b enforcement intent foundation** (v0.17.0) — DF-election role state now feeds the Linux dataplane supervisor as a portable `(ESI, VNI)` BUM-enforcement table. The reconciler resolves bridge, VXLAN ifindex, and CE-facing port identity and reports the desired action (`allow` for DF, `suppress` for Non-DF) through `DataplaneReport.bum_enforcement`. Observable-only: no kernel filter mutation yet.
- [x] **EVPN Phase 3 partial — Gate 9 slice 6 symmetric Interface-less IRB end-to-end** (v0.18.0, ADR-0058) — `[[evpn_ip_vrfs]]` TOML schema with VRF / L3VXLAN device binding and operator-supplied Router MAC, pure-logic Type 5 origination + projection helpers (RFC 9136 §4.4.2 Interface-less IRB), `IpVrfStatus` readiness probe checking the seven ADR-0058 §3 predicates, Linux rtnetlink dumps for VRF / L3VXLAN inventory, and `Dataplane::probe_ip_vrfs` called every reconcile pass with readiness surfaced via `tracing::info!` / `warn!` + `DataplaneReport.ip_vrf_status` + `EvpnService.ListIpVrfs` / `GetIpVrf` gRPC + `rustbgpctl evpn vrfs`. Slice 6 PR A (#77) wires daemon-side origination (kernel-route dump + conservative classifier + L3 originator task + `originated_routes_count`); slice 6 PR B (#78) wires dataplane-side import (best-path subscription + projection + transactional `L3OwnedState` with value-aware drift detection + four-phase apply ordering + Router MAC conflict detection + foreign-state preservation + `installed_routes_count`). M39 hosted kernel-dataplane smoke validates the bidirectional symmetric IRB datapath against FRR 10.3.1.
- [x] **EVPN Phase 3 partial — ADR-0059 aliasing dataplane ECMP via FDB nexthop groups** (v0.19.0, ADR-0059, PRs #84 / #86 / #87 / #88 / #89) — multi-homed Type 2 routes on the receive path now program FDB nexthop groups (`NDA_NH_ID` / `NHA_FDB`). Slices 1-4 plus M40 hosted kernel-dataplane smoke against FRR EVPN-MH 10.3.1 all shipped on `main`. M40 16/16 PASS first-shot validates kernel programming under the expected `NHG_TAG | n` / `VTEP_NH_TAG | n` tag scheme. Slice 3.5 follow-ups (periodic `RTM_GETNEXTHOP` drift recovery, `apply_aliasing_ecmp` operator off-switch, IPv6 alias members) deferred at v0.19.0 and shipped post-release in PRs #91 / #92 / #93.
- [x] **EVPN Phase 3 partial — ADR-0059 slice 3.5 aliasing-ECMP hardening** (v0.20.0, ADR-0059, PRs #91 / #92 / #93) — the three slice 3.5 follow-ups have shipped on `main`: PR 1 (`apply_aliasing_ecmp` per-instance off-switch — `[[evpn_instances]].apply_aliasing_ecmp` TOML knob, default `true`, restart-required, diff layer takes `&EvpnInstanceTable` to gate the FDB-NHG dispatch on the per-VNI bit), PR 2 (periodic `RTM_GETNEXTHOP` drift recovery — every `periodic_dump` interval the reconcile actor re-dumps tagged kernel NHIDs and heals missing/mis-shaped per-VTEP members, missing or member-set-drifted groups, stale tagged FDB rows from a prior daemon, and untracked tagged NHIDs in kernel; permanent dump failures latch drift off mirroring startup-adoption semantics; the `(VNI, MAC)` desired-intent guard prevents stale-row cleanup from removing forwarding state for a MAC we still intend to program), PR 3 (homogeneous IPv6 alias members — `encode_add_fdb_member` picks `AF_INET` / `AF_INET6` from the gateway form, `NexthopSocket::add_fdb_member` no longer rejects v6, diff layer's `all_v4` predicate becomes `all_same_family`). Post-v0.20 cleanup: the obsolete `NexthopError::Ipv6Unsupported` compatibility variant has been removed on `main` for v0.21.0.
- [x] **EVPN Phase 3 — Production-default multi-homing enforcement** — ADR-0059 aliasing dataplane ECMP via FDB nexthop groups has **fully shipped on `main`**: slice 1 (portable intent — `RemoteMacEntry::alias_group_key`, PR #84), slice 2 (`nexthop_raw` netlink primitive, PR #86), slice 3a (state types + apply primitive + CVE-2025-39851 guard, PR #87), slice 3b (PR #88, the operational-behavior-change slice — diff Pass 1b + reconcile actor coordinator + `NexthopOps` impls + startup NHID adoption + Docker-runnable netns test + actor-level FDB-NHG coverage), slice 4 (PR #89, M40 hosted kernel-dataplane smoke against FRR EVPN-MH 10.3.1 — 16/16 PASS first-shot validates that rustbgpd consumes real FRR EVPN-MH routes and programs an FDB-NHG on the receiving VTEP, with the expected `NHG_TAG | n` / `VTEP_NH_TAG | n` tag scheme and a clean drain-to-single-dst transition when an alias withdraws), and slice 3.5 (PRs #91 / #92 / #93 — operator off-switch, periodic drift recovery, IPv6 alias members). M39 / M40 / M42 and the `fdb_nhg` / `fib_runtime` Docker selectors are now in the hosted `kernel-dataplane` CI workflow. The Gate 8b 24 h MAC-churn soak plus M37 local-origination 24 h soak cleared the default-flip gate; `apply_bum_enforcement` and `apply_aliasing_ecmp` now default to `true` while explicit `false` remains supported for opt-out deployments. Note this is *role-based* DF/non-DF BUM suppression + aliasing ECMP, not source-conditioned local-bias split-horizon (next item).
- [ ] **EVPN VXLAN local-bias split-horizon (remaining all-active correctness gate)** — RFC 8365 §8.3.1: a DF must drop BUM whose VXLAN overlay source is an ES-peer VTEP while still flooding other BUM and forwarding known unicast. ADR-0065's netns spike confirmed this is **not achievable with stateless `tc-flower` on the standard bridged-VXLAN softswitch** — the overlay source is not visible to `tc` at the VXLAN ingress hook (the FRR #15400 failure mode) — so it is ASIC/offload-dependent. Deferred; the only remaining softswitch avenue (underlay-ingress eBPF with per-MAC state, or `collect_metadata` VXLAN) is a separate ADR if demand appears.
- [ ] **EVPN single-active follow-up — backup-path pre-install** — proactive receive-side backup-path pre-install for a single-active ES: a non-DF PE pre-programs the backup VTEP next-hop so failover is sub-second instead of waiting for BGP reconvergence (single-active is correct today, just reconvergence-speed). The other RFC 8584/9785 + single-active follow-ups have shipped: the **preference-DF election smoke** (M49, rustbgpd×2 — proves preference drives the election vs. modulo fall-back; the byte-exact DF Election extcomm + DP bit are unit-tested), the **single-active `(next-hop, ESI)` duplicate-fold** dataplane test, and **RFC 9785 local Don't-Preempt origination** (`df_dont_preempt`). A *cross-vendor* preference-DF smoke against FRR remains an additional follow-up (FRR's on-the-wire DP/extcomm behavior is unverified).
- [ ] **EVPN Gate 9 follow-ups — overlay-index IRB** — Gate 9 slice 6 ships the Interface-less symmetric IRB model, auto-derived Route Targets (RFC 8365 §5.1.2.1) are available as an explicit config opt-in for `[[evpn_instances]]` and `[[evpn_ip_vrfs]]`, and receive-side RFC 9135 §9.2 recursion now resolves non-zero Type 5 Gateway Address routes through linked Type 2 MAC/IP state in L2VNIs linked to the target IP-VRF, tie-breaking contenders by MAC mobility sequence and resolving a multi-homed single MAC to a deterministic next_hop. Controller injection can synthesize non-zero Gateway Address Type 5 routes while native IP-VRF origination remains Interface-less; M45 now covers Type 5 controller injection, including the non-zero Gateway Address form, against FRR. Missing links, unresolved gateways, gateways resolving to multiple distinct MACs, self-originated rows, quarantined MACs, mass-withdraw-filtered Type 2 rows, RT misses, and L3VNI mismatches stay fail-closed. Remaining standards-completeness items: native local overlay-index origination, multi-homed-gateway ECMP, protected recursion-path interop smoke, and any future per-route recursive-drop detail operators prove they need beyond the current bounded counters.
- [ ] **EVPN Linux VTEP hardening** — low-priority operational polish once core convergence is complete: VLAN-aware bridge support, rustbgpd-managed bridge / VXLAN / VRF netdev creation, `RTNLGRP_LINK` eventing instead of poll-only link inventory, and learned-port-to-ESI disambiguation so one local VNI can participate in multiple Ethernet Segments.
- [ ] **EVPN Phase 4 — Adjacent standards** — PBB-EVPN (RFC 7623), EVPN-MVPN integration (RFC 9251, Route Types 6/7/8), RFC 9572 BUM segmentation route types 9/10/11, EVPN optimized ingress replication (RFC 9574), EVPN tunnel aggregation / common labels (RFC 9573), EVPN multihoming split-horizon extensions for non-VXLAN tunnel families (RFC 9746), Proxy ARP/ND extended-community behavior (RFC 9161 / RFC 9047), MPLS/SRv6 encapsulation, EVPN VPWS / E-Tree service models, and Add-Path for EVPN (RFC 9252). Service-provider EVPN use cases.
- [ ] **EVPN polish + observability gaps** (low-priority, Phase 1 known limitations):
  - [x] Type 5 (IP Prefix) interop test against FRR (M30b, `tests/interop/m30b-evpn-type5-frr.clab.yml`) — single-VTEP origination from FRR vrf1 / L3VNI 100; rustbgpd RR decodes the Type 5 NLRI and surfaces RD, prefix, next-hop, VNI label, RT extended community, and VXLAN encap via `ListEvpnRoutes`. Withdrawal validated. RR-reflection of Type 5 (2-VTEP topology, ORIGINATOR_ID + CLUSTER_LIST asserts) tracked as M30c.
  - [x] **`match_evpn_route_type` policy clause** (v0.11.0) — `match_evpn_route_type: u8` on `PolicyStatement` filters EVPN by RFC 7432/§9136 route type (1-5; non-EVPN never matches). Wired through TOML config, gRPC `PolicyStatement` (proto field 24), and the EVPN evaluation sites in `crates/transport/src/session/inbound.rs` + `crates/rib/src/manager/distribution.rs::stage_evpn_routes`.
  - [x] **EVPN BMP export and MRT dump integration** (v0.11.0) — BMP `RouteMonitoring` already flows for EVPN at the raw-PDU emit site (no AFI/SAFI gate; pinned by `inbound_evpn_update_emits_bmp_route_monitoring` regression test). MRT `TABLE_DUMP_V2` now emits `RIB_GENERIC` (subtype 6, RFC 6396 §4.3.5) records with AFI 25 / SAFI 70 for every Adj-RIB-In EVPN route. Type 2 + Type 5 round-trip tests assert the wire shape. ADR-0044 carries the encoding choice.
  - GR / LLGR interop harness (kill / restart / measure) — unit tests cover the EVPN GR pipeline; FRR-vs-rustbgpd kill-and-recover interop is not in the M29-M33 set.
  - [x] **M33 soak harness** — `tests/soak/run-m33-soak.sh` extends M33 to arbitrary durations (default 24h, `SOAK_SEC` override for sub-hour smokes), samples cgroup RSS + Prometheus gauges every minute into `samples.csv`, and runs a stdlib-only Python analyzer that gates on memory slope, peak RSS, session flaps, drop deltas, gRPC health continuity, and process-restart detection (counter monotonicity). The first runs surfaced ADR-0051 — see "Sustained-churn writer-task split" below — and `tests/soak/runs/20260427T172938Z/` is the post-fix reproducer of record (drops 613→1, slope 58.5→12.6 MB/h, GetHealth always responsive). Still open: a 24h soak with the writer-split build to confirm the +49-min wedge transition is the only saturation event under continuous load.
  - [x] **`EvpnRibRoute` payload + key redundancy** — landed post-v0.10.0. The cached `EvpnRouteKey` field was removed from `EvpnRibRoute`; identity is now derived on demand via `EvpnRibRoute::key()` (one-line wrapper around `EvpnRoute::key()`, which is O(1) and allocation-free). Adding RFC 9251 Route Types 6-8 will only need new arms in `EvpnRoute::key()` rather than parallel synchronization at every construction site.
  - **CI wiring for M29-M33** — interop scripts running cleanly on a developer box but tied into the GitHub Actions matrix. **M29 + M30 done** — `.github/workflows/interop.yml` runs the EVPN cap-negotiation gate (M29) and the Type 2 MAC-reflection gate with kernel VXLAN + bridge (M30) against FRR 10.3.1 on every push and PR. M30 was unblocked by replacing `start_rustbgpd`'s 3 s fixed sleep with a 10 s poll + diagnostic dump on failure (the original probe failed under heavy CI load before the daemon registered in `/proc`). **M30b blocked on hosted runners** — the Azure-tuned kernel on ubuntu-latest (6.17.0-1010-azure) ships without the `vrf` module, so `ip link add ... type vrf` fails inside the FRR container and FRR cannot bind the L3VNI to originate Type 5; verified empirically via a throwaway probe workflow. M31 (MAC mobility with 3 VTEPs), M32 (multi-homing on a bond ES), and M33 (50k-route scale + churn) were the heavier wall-time gates. **Resolved by the kernel-dataplane hosted migration (2026-05):** `ubuntu-latest` now loads the `vrf` module via `linux-modules-extra`, so the privileged EVPN / IRB smokes (M36–M53) run on GitHub-hosted runners and the self-hosted runner was retired; large-scale churn (M33) stays a manual soak harness under `tests/soak/`.

### P2.5 — Operational Polish

Features that improve day-to-day operations.

- [x] **Config persistence** — gRPC neighbor add/delete mutations persist to TOML and SIGHUP reload reconciles neighbor deltas
- [x] **BMP exporter** (RFC 7854) — stream route monitoring data to collectors (OpenBMP, pmacct); per-collector TCP client with reconnect, fan-out manager, raw PDU capture (ADR-0041)
- [x] **LLGR** (RFC 9494) — two-phase GR timer with LLGR-stale promotion and configurable stale time per peer
- [x] **MRT dump export** (RFC 6396) — TABLE_DUMP_V2 for offline analysis and archival; periodic + on-demand gRPC trigger, optional gzip, CLI `mrt-dump` subcommand (ADR-0044)

### P3 — Operator Experience ("wow factor")

Make first use and continued use feel magical. These are the features that
get blog posts written and make operators switch.

#### First-Run Experience

- [x] **Rust-compiler-style config errors** — config validation errors display the offending TOML source line with column markers and underlined spans, using `toml_edit::Document` for span lookup (formerly `ImDocument` in toml_edit ≤ 0.24). Zero new deps (hand-rolled renderer, `toml_edit` already transitive).
- [x] **`rustbgpd --check config.toml`** — validate config without starting the daemon. Print structured errors or "config OK". Operators run this before every reload and deploy.
- [x] **Startup banner with topology summary** — on boot, print a clean tree showing ASN, router-id, peer count by type, named policies, neighbor sets, listener endpoints, optional subsystems (RPKI caches, BMP collectors, MRT output). First thing an operator sees after starting the daemon.
- [x] **Shell completions** — `rustbgpctl completions {bash,zsh,fish}` generates completions from clap derives. Pre-generated files shipped in `examples/completions/`.

#### CLI Polish

- [x] **Colored, tabular CLI output** — aligned tables, colored session states (green=Established, yellow=OpenSent, red=Idle/Active), human-readable uptime ("2d 4h 12m" not seconds), dynamic column widths, `--no-color` / `NO_COLOR` support. Uses `owo-colors` with auto-detection for piped output.
- [x] **Route filtering in CLI** — `rustbgpctl rib --prefix 10.0.0.0/8 --longer --community 65001:100 --origin-asn 65003`. Server-side filtering via gRPC with prefix (exact/longer), origin ASN, community, and large community filters. Works on best, received, and advertised views.
- [x] **`--version` flag** — both `rustbgpd --version` and `rustbgpctl --version`.
- [x] **Config diff** — shipped as `rustbgpd --diff` (daemon-side, alongside `--check`)

#### Debugging & Observability

- [x] **Minimal route explain (export)** — `rustbgpctl rib advertised <peer> --prefix 203.0.113.0/24 --explain` explains whether the current best route would be advertised to one peer, with decisive reasons and applied export modifications. gRPC: `RibService.ExplainAdvertisedRoute`.
- [x] **Config diff on SIGHUP** — field-level change logging on reload: each changed neighbor logs exactly which fields differ (e.g. "hold_time: Some(90) → Some(45), families: [...] → [...]"). Sensitive fields (md5_password) log `<changed>` without revealing values.
- [x] **Per-peer log filtering** — each peer session runs in a tracing span with `peer_addr`, `remote_asn`, `peer_group` fields. Per-peer `log_level` config field overrides the global `RUST_LOG` default. Also filterable via `RUST_LOG=info,peer{peer_addr=10.0.0.1}=debug`.
- [x] **Route diff on policy change** — after hot-applying an export policy change, logs announced/withdrawn counts per peer at info level

#### Advanced UX

- [x] **Live TUI dashboard** — `rustbgpctl top`: a terminal UI (ratatui) showing sessions, prefix counts, message rates per peer, RPKI VRP counts, route events — all updating live via polling + WatchRoutes stream. Peer table with sort/navigate/detail, toggleable events panel, help overlay. Configurable poll interval (`-i`).
- [x] ~~**Built-in looking glass**~~ — replaced by the birdwatcher-compatible REST API. Market research shows IXPs use external presentation layers (Alice-LG, IXP Manager); a built-in web UI is not a differentiator.
- [ ] **Config snippets / examples in error messages** — when a gRPC call fails validation, include a working example in the error detail: "invalid families value; try: `families: [\"ipv4_unicast\", \"ipv6_unicast\"]`"
- [x] **Neighbor auto-discovery logging** — when an unknown peer connects, the warning includes a suggested `rustbgpctl neighbor <addr> add --asn <ASN>` command to help operators bootstrap new peers.

Deferred explain follow-ups (after best-path explain shipped):
- [ ] **Named policy / statement attribution in explain** — include exact policy and statement identity in explain output
- [ ] **Import explain** — dry-run import policy, RPKI, and inbound acceptance for one received route
- [ ] **Verbose policy trace** — include non-match steps and full decision trace instead of only decisive reasons
- [ ] **Route history / why-changed timeline** — retain explain history across best-path and policy changes
- [ ] **Looking glass integration for explain** — expose explain output via the future read-only HTTP/JSON looking glass

### P3.5 — Scale & Hardening

Prove it works under pressure before 1.0.

- [x] **RIB scale benchmarks** — criterion benchmarks for AdjRibIn insert (10k–500k), best-path comparison, LocRib recompute, full pipeline, route churn
- [x] **Wire codec benchmarks** — criterion benchmarks for NLRI encode/decode, UPDATE build/parse, path attribute codec, validation
- Continuous churn benchmark + per-PR CI regression tracking are now tracked under [Performance & Polish](#performance--polish) above; the criterion suites above are the inputs the tracking will run against.
- [x] **Peer flap storms** (`tests/chaos/chaos-flap-storm.sh`) — bounces a configured peer via `EnableNeighbor`/`DisableNeighbor` in a tight loop; verifies the daemon stays responsive (gRPC `GetHealth` clean throughout), memory growth across the storm < 10 MB, and the FSM completes ≥3 disable→enable cycles without stuck state. Smoke verdict: `clean` after 3 cycles in 10 s, mem delta 1.14 MB.
- [x] **gRPC churn** (`tests/chaos/chaos-grpc-churn.sh`) — fires concurrent `AddNeighbor`/`DeleteNeighbor`/`SoftResetIn` calls via `xargs -P` against 10.99.0.0/16 churn IPs; verifies no deadlock (≥90 % of shots produce a structured response, including expected validation errors), no `GetHealth` probe failures during the storm, no process restart. Smoke verdict: `clean` at 3 328 shots / 100 % response / 0 probe failures.
- [x] **Repeated GR recovery** (`tests/chaos/chaos-gr-cycles.sh`) — bounces FRR's bgpd repeatedly under negotiated GR (M16 LLGR topology); verifies each cycle peaks `bgp_gr_stale_routes > 0` (GR path fires) and returns to 0 within the configured window (stale-sweep correctness). Documented for the M16 topology — runs against any GR-capable peer.
- [x] **Long-duration stability** — M33 1 h + 4 h + 12 h soak runs (`tests/soak/runs/20260427T230448Z/`, `20260428T150509Z/`, `20260429T004656Z/`) all `verdict: clean` under sustained 1 k-rps EVPN churn. 12 h slope **+0.0094 MB/h** (essentially zero), 0 drops, 0 flaps, 0 gRPC health failures, no daemon restart, p99 RSS 85 MB. Anchors the writer-split (ADR-0051) validation across three independent run lengths.
- [x] **AdjRibIn prefix index** — secondary `HashMap<Prefix, HashSet<u32>>` index on `iter_prefix()` for O(1) prefix lookup. Pipeline 50k prefixes: 7.1s → 82ms (86x improvement). Full-table (900k) extrapolated ~1.5s
- [x] **End-to-end system benchmarks** — bgperf2-based multi-peer ingestion tests (10p/1k, 2p/10k, 2p/100k) against BIRD 2.18 and GoBGP 4.3.0; results in BENCHMARKS.md
- [x] **Memory profiling** — tracking allocator test measures per-route footprint: 252 B/route with interning, 547 MB for full table (900k x 2 peers + LocRib); 15-29x less than GoBGP, approaching BIRD-class efficiency
- [x] **Published performance comparison** — bgperf2 benchmarks against BIRD 2.18 and GoBGP 4.3.0 at 10p/1k, 2p/10k, 2p/100k; convergence, CPU, memory results published in BENCHMARKS.md with methodology
- [x] **Path attribute interning** — `HashSet<Arc<Vec<PathAttribute>>>` intern table in `AdjRibIn`; routes with identical attributes share one allocation; `gc_intern_table()` cleans orphaned entries; `Hash` derived on `PathAttribute` and all constituent types
- [x] **Chunked RoutesReceived processing** — `PendingRoutesReceived` splits large batches into 1024-prefix chunks with per-chunk recompute/distribute; `VecDeque` queue preserves ordering; main channel blocked while chunks pending to prevent control message reordering
- [x] **Bounded fair RIB scheduling** — replaced biased priority query drain with bounded fair scheduling: process one route chunk, then up to 8 queries, then yield; prevents trading route starvation for query starvation at scale
- [x] **Outbound UPDATE construction optimization** — `send_route_update()` now uses hash-indexed attribute grouping instead of `Vec::find()`, per-call prepared outbound attribute caching, and pointer fast-paths for outbound route equality; RIB-to-transport send sites use `try_reserve()` to avoid clone-before-send overhead
- [ ] **Bulk initial load mode** — special-case initial table flood: accumulate larger affected-prefix sets before distribution, emit fewer/larger outbound updates; initial load tradeoffs differ from steady-state churn
- [x] **AdjRibIn/AdjRibOut pre-sizing** — `AdjRibIn::with_capacity()` constructor; first `RoutesReceived` per peer uses batch size hints to pre-size routes, prefix_index, and intern table maps
- [x] **Outbound attribute caching** — per-call prepared outbound attribute cache reuses identical attribute rewrites inside `send_route_update()`, covering unicast export without introducing long-lived invalidation state
- [x] **AdjRibOut secondary prefix index** — `HashMap<Prefix, SmallVec<[u32; 1]>>` index for O(1) `path_ids_for_prefix()` and `iter_prefix()`. Previous O(N) full-scan caused 560x cost blowup at 200k routes; 2p/100k convergence: 71s → 12s (5.9x)
- [x] **AdjRibOut index memory compaction** — `SmallVec<[u32; 1]>` for single-best case; zero-alloc `&[u32]` return from `path_ids_for_prefix()`; marginal RSS impact (~9 MB) confirming memory is structural
- [x] **dhat heap profiling** — feature-gated `dhat-heap` profiler with Docker/bgperf2 integration; SIGTERM handler for clean PID 1 shutdown; 284 MB live heap captured at 2p/100k
- [x] **Skip unnecessary Arc deep clones in distribution** — `Arc::make_mut()` was called unconditionally on every route in `distribute_single_best_prefix()`, forcing deep clone of `Vec<PathAttribute>` even when no export policy modifications were needed (~85% of routes). Added `RouteModifications::is_empty()` guard; unmodified routes now share the same `Arc` across LocRib and AdjRibOut. 2p/100k memory: 415 MB → 257 MB (-38%)
- [x] **AdjRibOut capacity pre-sizing** — `AdjRibOut::with_capacity()` constructor; all distribution-path creation sites use `loc_rib.len()` as capacity hint. Eliminates rehash churn during initial table load.
- [x] **Sustained-churn writer-task split** (ADR-0051) — peer session task no longer owns the TCP write half. A new dedicated writer task per peer holds the `OwnedWriteHalf` plus a bounded bulk channel + unbounded priority channel, with biased select so NOTIFICATION/KEEPALIVE/OPEN preempt UPDATE backlog. When the bulk channel saturates the session emits `Cease/8` (Out of Resources) and tears down — silent drops become observable flaps with clean BGP restart semantics. Closes the deterministic +46-min `GetHealth` wedge surfaced by the M33 soak (drops 613→1, memory slope 58.5→12.6 MB/h, GetHealth never blocks). Bounded `query_state_timeout` containment in `0735dd9` keeps RPC liveness independent of session-task health regardless. See ADR-0051 and `tests/soak/runs/20260427T172938Z/`.
- [x] **Investigate +49-min monitor saturation under M33 1k rps churn** — root cause was a load-test bug, not a daemon bug. `bench/evpn-load`'s synthetic peers expose `PeerHandle.rx` for inbound traffic, but the reader task back-pressures on a 65 536-deep mpsc channel. The tester binary held `handle.tx` to inject routes but never drained `handle.rx`. RR-side reflection of the other tester's churn (~25 UPDATE/sec) filled the channel in ~65 536 / 25 ≈ 43.7 minutes — matching the deterministic wedge timing exactly. Fix in `7491b1b`: spawn a discard task on the tester. Post-fix soak (`tests/soak/runs/20260427T230448Z/`) ran clean for the full hour: 0 drops, 0 flaps, slope 0.50 MB/h under the clean-tier threshold, memory flat 83.15 → 82.87 MB. The writer-split (ADR-0051) was always correct; it kept Cease/8-disconnecting a broken consumer because that's its job.
- [ ] **Shared route storage across RIBs** — store route payload once and reference from AdjRibIn/LocRib/AdjRibOut via lightweight handles
- [ ] **Compact RIB indexing** — reduce HashMap count/shape overhead; dhat profile shows ~160 MB in hashbrown bucket arrays across ~10+ large HashMaps

### P4 — Future Work

Valuable but not blocking production use or 1.0. Ordered by market signal.

- [ ] **Confederation** (RFC 5065) — required for service provider deployments but SPs are not the initial target market
- [x] **Dynamic neighbors** (prefix-based) — `[[dynamic_neighbors]]` TOML section with prefix range, peer group inheritance, `remote_asn = 0` (accept any ASN from OPEN). Auto-accept inbound connections, auto-remove on disconnect. Configurable limit (`dynamic_neighbor_limit`, default 100). FSM `remote_asn = 0` sentinel skips ASN check. gRPC `ListDynamicNeighbors` query, `is_dynamic` flag in peer info. Runtime Add/Delete deferred (TOML is primary config surface).
- [ ] **Observability future extensions** — after durable event history lands, remaining optional work is richer per-MAC EVPN dataplane categories, WatchRoutes missed-event signaling if/when it gains an envelope, precomputed dataplane summary counters or watch channels if full status-snapshot polling becomes expensive, optional subscription-side indexing or a dedicated event bus if subscriber count or event rate makes post-broadcast filtering expensive, and a TUI live event view.
- [x] **Route history prefix drilldown** — recent add / withdraw / best-path changes are queryable from the bounded RIB event ring by exact prefix via gRPC and `rustbgpctl events --prefix <PREFIX>`. Future depth beyond the fixed in-memory window remains part of the broader observability roadmap.
- [ ] **Route dampening** (RFC 2439) — suppress flapping routes with penalty/decay
- [ ] **Scriptable policy engine** — user-defined attribute transformation functions (Lua, Starlark, or WASM plugins) beyond static match/action rules. Policy evaluation is already a pure function `(route, context) -> (action, modifications)` — sandboxing a scripting layer there would be clean. More expressive than FRR's route-maps, simpler than BIRD's filter DSL.
- [ ] **Evaluate buffa for protobuf codegen** — Anthropic's [buffa](https://github.com/anthropics/buffa) is a pure-Rust protobuf implementation with editions-first design, zero-copy views, and `no_std` support. Benchmark against prost/tonic for gRPC message encode/decode performance; evaluate generated type ergonomics (e.g. `MessageField<T>` vs prost `Option<T>`, `EnumValue<T>` vs raw `i32`). Requires tonic integration story (buffa has no gRPC transport layer — would need a tonic codec adapter or wait for upstream support).
- [x] **gNMI / OpenConfig telemetry adapter — shipped under ADR-0070.** Read-only gNMI (`Capabilities` / `Get` / `Subscribe` ONCE+POLL+SAMPLE) is a thin adapter over rustbgpd's existing typed snapshots, exposing a *small, exactly-implemented* OpenConfig BGP subset (global + neighbor `state` — no per-AFI-SAFI counters or capabilities in v1) rather than claiming full OpenConfig coverage. M54 verifies the mTLS TCP path with `gnmic` against a real daemon. Constraints: `Capabilities` advertises the OpenConfig modules backing the supported paths (`ModelData` is module-level, not per-path), with the path whitelist enforced at `Get` / `Subscribe`; `Subscribe ON_CHANGE` v1 shipped (PR #293, M56) for the `…/neighbor[neighbor-address=*]/state/session-state` leaf only — sourced from the durable event broadcast, with `FailedPrecondition` when EHM is disabled and fresh-snapshot-on-reconnect semantics. Other leaves under `ON_CHANGE` remain `Unimplemented`, and wider OpenConfig coverage (counter leaves, `enabled`, additional state surfaces) stays deferred. `Set` deferred and gated on a real config-transaction model (see "Runtime-vs-file diff and config UX") and reusing ADR-0064 tier authz. Distinct from the deprioritized YANG/NETCONF item below — gNMI is gRPC-based and telemetry-first, and the target is a standard OpenConfig collector, not SONiC-schema parity.

### Deprioritized

Features that market research indicates are lower value than originally planned.

- **YANG model / NETCONF** — FRR can't finish their BGP YANG model; gRPC is the modern interface; low ROI. (Read-only gNMI / OpenConfig — the gRPC-based telemetry-first successor — shipped under ADR-0070 and is distinct from YANG/NETCONF.)
- **Built-in web UI** — IXPs use Alice-LG / IXP Manager; replaced by API-first looking glass approach
- **Kubernetes operator** — adjacent opportunity but premature; nail the IX/SDN use case first

### Interop Test Coverage

The automated interop scripts (see `docs/INTEROP.md` for the full
matrix) cover the M-series against FRR 10.3.1, BIRD 2.0.12 / 3.2.1,
GoBGP 4.3.0, and StayRTR. M0 (FRR, BIRD) are manual smoke tests. M36 is the Gate 7b real-VTEP smoke (rustbgpd-as-VTEP,
FRR-as-originator, iBGP/AS65000) — 8/8 PASS locally against Linux
6.17 + FRR 10.3.1; M37 is the Gate 7b+1 local-origination smoke
(rustbgpd-as-originator, FRR-as-consumer) — 4/4 PASS locally against
the same kernel/FRR pair; M37+IP is the Gate 7b+2 MAC-with-IP
origination smoke; M38 is the Gate 8 DF-election smoke
(2-PE rustbgpd shared ESI). M36/M37/M37+IP/M38 now run in the
hosted `kernel-dataplane` workflow because privileged
kernel state is required. M39 (Gate 9 slice 6
symmetric Interface-less IRB) is in place — bidirectional Type 5
between rustbgpd and FRR 10.3.1 with kernel route + L3 neighbor +
L3VXLAN FDB programming validated end-to-end. M40 (ADR-0059
slice 4 aliasing-ECMP) is in place — rustbgpd-as-receiver with
2× FRR VTEPs sharing ES1 via bond, validates FDB nexthop group
programming on the receiving VTEP under the expected
`NHG_TAG | n` / `VTEP_NH_TAG | n` tag scheme, 16/16 PASS first-shot
against FRR 10.3.1. M41 is CI-gated for RFC 7999 BLACKHOLE receiver
scoping plus opt-in kernel discard install / withdraw. M42 validates
the ADR-0061 general unicast FIB runtime against FRR 10.3.1 and a real
Linux route table: selected EBGP route install into configured table
1000, foreign-route preservation, FRR withdraw cleanup, and SIGTERM
drain. Crash-restart adoption is intentionally deferred because
`RTPROT_BGP` is not rustbgpd-specific ownership proof. M43 validates
static-neighbor TCP-AO against BIRD 3.2.1: matching keys establish and import
`203.0.113.43/32`; a mismatched key withdraws the route and fails closed.
M36 / M37 / M37+IP / M38 / M39 / M40 / M42 and the Docker `fdb_nhg` /
`fib_runtime` netns selectors now run in the hosted
`kernel-dataplane` workflow. M43 also runs there on the current
TCP-AO-capable runner; the job retains a `CONFIG_TCP_AO` probe so future
runner drift skips loudly instead of failing unrelated dataplane gates. M44
validates ADR-0064 native mTLS tier authorization, M54 validates ADR-0070
gNMI / OpenConfig telemetry with `gnmic` over mTLS, and M45 validates EVPN
Type 5 control-plane injection.

**Must-test (high signal, high risk):**

- [x] **M13: Policy engine** — FRR ↔ rustbgpd: `set_local_pref`, `set_med`, community add, AS_PATH prepend, AS_PATH regex match, export deny, policy chain accumulation (15/15)
- [x] **M14: Route Reflector** (RFC 4456) — iBGP client/non-client reflection, ORIGINATOR_ID/CLUSTER_LIST, 3-node topology (14/14)
- [x] **M15: Route Refresh** (RFC 2918 + 7313) — `SoftResetIn` via gRPC, session stability, import policy reapplication (10/10)
- [x] **M16: LLGR** (RFC 9494) — GR → LLGR-stale promotion, reconnect clears stale (8/8)

**Should-test (important, lower blast radius):**

- [x] **M17: Add-Path multi-path send** (RFC 7911) — rank-based path IDs, multiple candidates advertised to FRR, AS_PATH differentiation (15/15)
- [x] **M18: Extended next-hop** (RFC 8950) — IPv4 unicast over IPv6 next-hop via `MP_REACH_NLRI`, capability negotiation (9/9)
- [x] **M19: Transparent route server** — skip ASN prepend, preserve original NEXT_HOP on eBGP re-advertisement; FRR 10.x requires per-neighbor `no enforce-first-as` (13/13)
- [x] **M20: Private AS removal** — all three modes (`remove`, `all`, `replace`) validated against FRR with all-private and mixed AS_PATHs (22/22)

**Should-test (follow-up):**

- [x] **M28: Dynamic neighbors** — FRR peer connecting into a `[[dynamic_neighbors]]` prefix range; auto-accept, peer group inheritance, route exchange, `is_dynamic` flag, `ListDynamicNeighbors`, auto-removal on disconnect (11/11).

**Deferred (hard to interop-test or low wire-level risk):**

- MRT (offline format), config persistence/SIGHUP (daemon-internal), Notification GR, Admin Shutdown, Extended Messages (capability negotiation only), gRPC security (not wire protocol)

### Interop Test Infrastructure

- [ ] **`trap cleanup EXIT`** — auto-destroy topology on failure; guard with a `--deploy` flag so manual workflows aren't disrupted
- [x] **EoR detection by polling** — replaced `sleep 10` in M11 test 3 with a polling loop on `get_stale_route_count()` (15 attempts × 2s)
- [x] **Timestamps in log output** — `date +%H:%M:%S` in `log()`/`ok()`/`fail()` via shared `test-lib.sh` across all 22 scripts
- [x] **Pre-flight checks** — verify `grpcurl`, `docker`, and topology container exist on source via `test-lib.sh`
- [x] **Shared test library** — `test-lib.sh` extracted from 22 scripts: pre-flight, timestamps, `resolve_ip`, `resolve_grpc_addr`, `start_rustbgpd`, `wait_frr_established`, `print_summary` (-250 lines of duplication)

---

## Pre-1.0 Worklog

Items historically tracked as pre-1.0 requirements during the v0.x build-out.
All shipped. v1.0 itself is not currently on a timeline (see "Release
stance" above) — this section is retained as a historical worklog rather
than an active gate list. Code-side polish continues in v0.x releases (see
"Current Priority Order" above).

- [x] MP-BGP (at least IPv6 unicast)
- [x] Graceful restart
- [x] Extended communities
- [x] Policy actions (match + modify + filter)
- [x] Large communities (RFC 8092)
- [x] ASPA verification — upstream verification with RTR v2 (ADR-0049)
- [x] Wire crate API stability (`rustbgpd-wire` published on crates.io)
- [x] Comprehensive rustdoc for public API (hand-written crates; generated proto stubs excluded)
- [x] **RibManager submodule split** — 8,318-line manager.rs split into 7 submodules (mod.rs, distribution.rs, peer_lifecycle.rs, route_refresh.rs, graceful_restart.rs, helpers.rs, tests.rs)
- [x] **RTR expire_interval enforcement** — VRPs are now cleared if no fresh EndOfData arrives before the expiry window

---

## Competitive Landscape

See [docs/COMPARISON.md](docs/COMPARISON.md) for a detailed feature comparison
with FRR, BIRD, GoBGP, and OpenBGPd.

| | FRR / BIRD | GoBGP | rustbgpd |
|---|---|---|---|
| **Primary interface** | CLI | gRPC | gRPC |
| **Runtime** | C | Go (GC) | Rust (no GC) |
| **Scope** | Full routing suite | BGP-only | BGP-only |
| **Memory (200k routes)** | 7–30 MB | 578 MB | 257 MB |
| **Dynamic peers** | Config reload | gRPC | gRPC |
| **Real-time events** | Log parsing | BMP/MRT | gRPC streaming + BMP + MRT |
| **Observability** | SNMP, CLI | Prometheus | Prometheus + structured logs |
| **Wire codec reuse** | No | No | `rustbgpd-wire` on crates.io |
| **ASPA** | Yes (BIRD, OpenBGPd) | No | Yes (upstream) |

---

## Scope Creep / Non-Goals

rustbgpd is an **API-first BGP daemon**. The following are explicitly out of scope:

- **Full routing suite.** No OSPF, IS-IS, LDP, MPLS, PIM. This is a BGP daemon.
- **CLI-first operation.** The gRPC API is the primary interface. The CLI
  and TUI are convenience wrappers — polished and opinionated, but gRPC
  is the contract.
- **GoBGP proto compatibility.** Our protos are our own. A compat adapter
  can exist as a separate project if anyone wants it.
- **Windows support.** Linux is the target. macOS for dev builds only.
- **Full web UI / dashboard.** Grafana + Prometheus is the monitoring story.
  The built-in looking glass is read-only JSON for NOC integration, not a
  full management UI.
- **Plugin system in v1.** Policy is built-in and minimal. WASM/DSL
  plugins are post-v1 if the core is stable enough to warrant them.

If you need these features, combine rustbgpd with purpose-built tools.

---

## Infrastructure

- [x] GitHub Actions CI (fmt, clippy, test on every push/PR)
- [x] Nightly fuzz CI (wire decoder fuzzing)
- [x] Docker image (multi-stage Dockerfile)
- [x] Containerlab interop topologies (FRR 10.3.1, BIRD 2.0.12 / 3.2.1)
- [x] Automated interop test scripts across the M-series (see `docs/INTEROP.md` for the matrix)
- [x] Binary releases (GitHub Releases with cross-compiled linux-amd64/arm64 binaries)
- [ ] Homebrew formula
- [x] crates.io publishing (`rustbgpd-wire` published; other crates remain internal)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style,
and PR process. Issues labeled `good first issue` are good entry points.
