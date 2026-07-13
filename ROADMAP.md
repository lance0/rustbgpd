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
routing suite. v1.0 is not on a timeline. Its intended contract is narrower
than the complete daemon surface: stable IPv4/IPv6 route-server and
route-reflector operation, policy, automation, and monitoring APIs, with the
already-proven controller-feed/RR families explicitly scoped. EVPN VTEP/IRB
and broader dataplane roles remain alpha outside that contract. Until real
shadow/canary deployment feedback supports a freeze, the project keeps
shipping focused v0.x cuts.

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
| Extensions: Add-Path (7911), Extended Messages (8654), Extended Nexthop (8950) | Partial | Extended Message send/receive directionality and per-type size-limit correction shipped |
| Graceful Restart (4724) + LLGR (9494) + Notification GR (8538) | Partial | GR helper + minimal restarting speaker shipped; LLGR reconnect/consecutive-reset/per-AFI/SAFI timer corrections shipped; interop re-proof queued |
| Route Refresh (2918) + Enhanced Route Refresh (7313) | Shipped | |
| BGP Roles + Only-to-Customer (9234) | Shipped | Static eBGP, IPv4/IPv6 unicast (ADR-0071, M55) |
| BGP unnumbered / IPv6 link-local peering | Shipped | Static interface-bound link-local (ADR-0069, M53) |
| Confederation (5065) | Planned | |
| EVPN-VXLAN: Route Reflector (7432, types 1–5) | Shipped | |
| EVPN-VXLAN: single-homed VTEP (Type-2 / Type-3 IMET origination, FDB program) | Partial (alpha) | Linux/VXLAN only |
| EVPN-VXLAN: multi-homing (ESI, Type-1/4, DF election, BUM suppression, aliasing ECMP) | Partial (alpha) | Production-default enforcement with opt-out |
| EVPN-VXLAN: symmetric IRB (Type-5 / L3VNI, 9136 §4.4.2) | Partial (alpha) | Receive-side GW-IP overlay-index recursion shipped; native GW-IP + ESI overlay-index origination shipped; single-active ESI overlay-index receive v1 shipped; all-active ESI overlay-index Type 5 writer shipped with same-host netns proof and M72 real-peer proof (ADR-0087/0090, FRR consume-side M68 for GW-IP, GoBGP receive-side M71 for single-active ESI recursion, GoBGP ×2 receive-side M72 for all-active ESI recursion) |
| FIB / dataplane: unicast Linux FIB install, ECMP, weighted multipath, BLACKHOLE discard | Shipped | Opt-in `[[fib_tables]]` (ADR-0061/0066/0068) |
| Security: TCP MD5, GTSM, static TCP-AO, native gRPC mTLS + tier authz | Shipped | TCP-AO BIRD-interop (M43); ADR-0064 authz |
| RPKI origin validation (6811 + 8210) | Partial | VRP table and policy match shipped; RTR epoch/reconnect-retention/identity/transaction-bound corrections shipped; M84 multi-cache RTR/ASPA epoch conformance lab shipped |
| ASPA verification | Partial | Role-aware verification and policy match shipped; RTR v2 replacement/withdrawal semantics shipped; M84 RTR/ASPA epoch conformance lab shipped |
| Policy: prefix lists, named chains, actions, community/AS_PATH/validation match | Shipped | GoBGP-style chain evaluation |
| Policy: `.rpol` typed compiled language (ADR-0096) | Shipped | Named sets, `u32` parameters, in-language tests (`rbgp policy check`), live-RIB dry run (`rbgp policy test`), per-term explain traces + live hit counters (`rbgp policy stats`); M80 FRR route-map parity receipt |
| BFD single-hop async + RFC 5882 coupling | Partial | M51 base receipt; receive-work budgeting and remote-AdminDown coupling corrections shipped; re-receipt queued |
| Observability & API: gRPC (11 services), Prometheus, structured logs, durable event history | Shipped | ADR-0072 outbox + `SubscribeFromEvent` |
| gNMI / OpenConfig telemetry + Set subset | Partial | `Get` / `Subscribe`, BGP state subset; static numbered-neighbor `Set` + commit-confirmed; broader OpenConfig config/state deferred |
| BMP trio (7854 + 8671 Adj-RIB-Out + 9069 Loc-RIB) + BMPv4/path-marking drafts, MRT dump (6396) | Shipped | Per-collector views + `version = 3\|4`; ADR-0097, M81 receipt |
| FlowSpec (8955/8956, IPv4/IPv6) | Shipped | All 13 component types |
| BGP-LS receive + reflection + API export (RFC 9552, SAFI 71/72) | Partial | Controller-feed / RR only; no local topology production (ADR-0077) |

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

One prioritized, forward-looking list. Items are grouped **Immediate** (audited
correctness and release work), **Next** (committed near-term), **Later**
(planned, not yet scheduled), and **Maybe / demand-shaped** (deferred until
operator signal). The current priority call is to finish the transaction
surface and improve operational proof. Protocol breadth and additional
performance work stay measurement- or demand-shaped.

Prioritization is **technical-merit first, pilot-aware second**: lead with work
that deepens rustbgpd's existing identity (a programmable BGP control plane),
and use real-operator credibility only as a tie-breaker between
technically-equal options — never as a reason to chase breadth rustbgpd doesn't
need. Every major feature should leave behind **pilot-grade evidence** (interop,
soak, or bench receipts), because credibility is a technical artifact, not
marketing. Concretely: no speculative service-provider breadth just because FRR
has it, no broad performance sprints without profile evidence.

### Immediate: post-v0.50 audit remediation (2026-07-09)

A repository-wide read-only audit at `155b24c2` found the workspace test,
Clippy, formatting, and doc gates green, but adversarial lifecycle and
failure-path review exposed correctness gaps that the happy-path suites do not
exercise. This remediation tranche takes priority over new protocol breadth
and the research-shaped queue below.

**Release blockers — finish before the next tag:**

- [x] **Commit-confirm recovery state machine.** Preserve the pre-transaction
  journal whenever apply completion is ambiguous (post-persist finalization,
  reply loss, or compound rollback failure); do not clear the mutation fence
  after failed abort/auto-revert while that journal can still boot-revert later
  accepted intent. Add post-persist, failed-rollback, second-mutation, and boot
  recovery tests (`src/config_transaction_control.rs`).
- [x] **Fail-closed release publication.** Require tag/version equality and a
  named pre-release test/audit/package gate before publishing binaries or the
  container image; include `LICENSE-MIT` and `LICENSE-APACHE` in release
  archives and the runtime image, with artifact-content assertions.
- [x] **Restore dependency-audit green.** Update dev-only
  `crossbeam-epoch 0.9.18` to a graph resolving `>= 0.9.20` for
  RUSTSEC-2026-0204; keep the advisory gate fail-closed rather than adding an
  ignore for a fixable dependency.
- [x] **Repair vacuous operational proofs.** Make M37 distinguish FRR query
  failure from valid route absence; require numeric Gate 8b DF-counter samples
  before restart monotonicity can pass; make M33 reject missing CSV columns.
  Re-run or explicitly downgrade only the affected proof claims — the archived
  Gate 8b memory/flip-cycle evidence and complete M33 receipt remain valid.

**Correctness tranche 1 — highest-impact runtime work:**

- [x] **Transport saturation teardown.** After a bounded writer queue fills,
  make Cease the final frame, close without draining queued UPDATEs, and drive
  `TcpConnectionFails`/RIB/session cleanup from the real run loop. Add an
  end-to-end regression that does not manually inject the FSM event.
- [x] **RTR/RPKI transaction state.** Model `(protocol version, session ID,
  serial)` as one per-cache epoch; retain usable cache data through reconnect
  until expiry/full replacement; validate Cache Response/EoD identity; correct
  ASPA replacement and empty-provider withdrawal semantics; bound each RTR
  transaction by deadline, expiry, PDU/record/byte budgets. Describe the
  supported 8210bis subset honestly until the complete contract is proven.
- [x] **LLGR per-AFI/SAFI lifecycle.** Preserve the original LLST through
  reconnect, retain LLGR-stale routes across consecutive resets until that
  timer expires, and represent/sweep deadlines per AFI/SAFI. Prove mixed LLSTs
  and reconnect-before-expiry across all supported families.
- [x] **Linux dataplane foreign-state ownership.** Preflight exact-key foreign
  routes, neighbors, and FDB rows before any `replace`; relinquish cached L2/L3
  ownership when a live snapshot shows a foreign replacement; revalidate
  ownership before withdrawal, NotReady, or shutdown deletion. Pin same-key
  foreign-state survival in in-memory and privileged netns tests.
- [x] **Failed `.rpol` reload consistency.** Do not publish the candidate rpol
  registry as the runtime snapshot when `SyncRpolPolicies` rolls back or
  rejects; keep existing and newly created sessions on one registry and retain
  the failed candidate only as desired/config-file intent.

**Correctness tranche 2 — bounded follow-through:**

- [x] **BFD receive and coupling bounds.** Cap socket packets/work per actor
  turn so timers and shutdown cannot starve; bound or coalesce the state-change
  channel; publish coupling-level changes when remote `AdminDown` changes even
  if the local BFD state remains `Down`.
- [x] **Reload and listener truth.** Classify and pin `[security.grpc]`,
  `[event_history]`, and `[managed_netdevs]` restart-only edits; bound the two
  remaining PeerManager-to-RIB reply waits; make BGP bind failure visible in
  readiness or fatal; turn readiness red and stop mutating/BGP admission at the
  beginning of coordinated shutdown.
- [x] **EVPN mobility wrap policy.** Implement an RFC 7432-compliant policy for
  a received MAC Mobility sequence of `u32::MAX` in MAC-only and MAC+IP
  origination. Do not substitute unchecked or naive `wrapping_add`; pin all
  first-learn and contender-update cases.
- [x] **RIB/API bounded reads.** Move filtering/pagination into bounded,
  resumable RIB actor queries with cancellation; stop `rbgp best`, `received`,
  and `advertised` from silently truncating at 100 rows; skip canceled MRT
  requests before snapshot/encoding/file creation.
- [x] **FlowSpec policy context.** Represent a legal FlowSpec rule without a
  destination-prefix component as `prefix = None`, never fabricated IPv4
  `0.0.0.0/0`, and prove IPv4/IPv6 import/export policy behavior.
- [x] **BMP connection-generation synchronization.** Fence/cancel stale dump
  tasks on collector reconnect and serialize initial Loc-RIB dump versus live
  changes so an older dump announcement cannot follow a newer withdrawal.

**Contained hardening and design follow-ups:**

- [x] Bound rpol `apply()` DAG depth, expansion, and evaluation work; remove the
  unconditional policy-name allocation from the non-attributed hot path.
- [x] Make managed-netdev partial creation converge: roll back known in-process
  pre-stamp failures, retry safely stamped incomplete bindings, and prune stale
  managed/NHG permanent-suppression entries after intent withdrawal.
- [x] Make Type-1/2/4 EVPN origination acknowledgement-aware, with explicit
  desired/pending/confirmed state and idempotent retry. Separately bound
  unmatched pending IP bindings; design a safe-forget contract before pruning
  MAC-mobility ratchet history.
- [x] Define NHID ownership authority. Numeric ranges plus `NHA_FDB` are not
  kernel-enforced proof against arbitrary co-resident writers; either document
  and validate a single-writer reserved-range deployment contract or stamp and
  verify `nh_protocol` with a fail-closed fallback.
- [x] Correct Extended Message directionality and custom-limit encoding for
  NOTIFICATION/ROUTE-REFRESH; rustbgpd's advertised capability controls inbound
  acceptance, while the peer's capability controls outbound size.
- [x] Add CI compilation for transport `bench-internals`; make fuzz target
  discovery fail on errors/zero targets and align public PR-smoke claims with
  the actual workflow.

The hosted-runner VRF/TCP-AO **skip-with-notice** behavior remains an accepted,
documented availability contract, not an audit defect. A green conditional job
does not claim a skipped receipt ran; coverage resumes automatically when the
host capability is available.

### Post-v0.51 stabilization path

The next product milestone is operational trust for the route-server / route-
reflector beachhead, not another breadth sprint. Work in this section outranks
new AFI/SAFI and EVPN dataplane expansion.

- **Narrow v1 role contract shipped (#862 / LAN-355).** The machine-checked
  contract freezes only the configuration and API used by IPv4/IPv6 route
  servers and route reflectors, `.rpol`, RPKI/ASPA, Roles/OTC, transactions,
  BMP/MRT/events, and the already-proven RR/controller-feed families, with
  explicit stability, migration, deprecation, and compatibility rules. EVPN
  VTEP/IRB remains alpha and outside this first contract.
- **Make changed-policy reload the primary performance program.** A corrected
  unique-prefix 700-client × 400,400-route rerun under alternating A/B policy
  markers happened, but its exact raw output, daemon log, generated inputs,
  and provenance were not retained as one durable bundle. First rerun it through
  the revision-pinned LAN-350 wrapper
  and fail-closed validator. Then compute shared group-to-group migration work
  once, chunk member resync so queries and churn interleave, and gate repeated
  heterogeneous reloads on completion time, control-query latency, session
  continuity, and folded advertised-state equivalence. Both the original
  occurrence-counted run and the corrected-but-unarchived `< 1 s` result remain
  non-acceptance evidence until the retained receipt replaces them.
- **Expose groupability before apply.** Config transaction planning now projects
  established-peer update-group membership with exact fallback reasons,
  affected peers/families, shared/private totals, resync scope, and bounded
  receipt-envelope capacity classes. Remaining: surface the same classifier in
  policy linting and add a post-renegotiation projection; until then session
  reshape stays explicitly indeterminate. Do not present byte-precise memory or
  time estimates until a calibrated model exists.
- **Keep update-group correctness as a permanent fault program.** The bounded
  deterministic foundation is shipped: grouped and forced-per-peer output are
  compared under channel saturation/virtual retry, dirty policy swaps and
  repeated regrouping, stale session generations, and RTC membership churn,
  with fixed PR schedules plus a hard-capped weekly 24-fixture parameter sweep.
  Seeds vary identities, not operation ordering or scenario length. Remaining:
  automated failure minimization, a broader fault matrix, restart/persistence,
  growth measurement, and long-running folded-state comparison (LAN-18) rather
  than relying only on bounded convergence receipts.
- **Turn shipped shadow tooling into external evidence.** The canonical semantic
  diff engine, `rbgp diff`, incumbent snapshot adapters, and BMP Adj-RIB-Out
  importer are shipped. The remaining adoption gate is a real BIRD/FRR/GoBGP
  shadow or canary run with explained differences, exact sanitized inputs, and
  an operator-readable rollback record.
- **Tighten lifecycle security without reopening scope.** Preserve the shipped
  unprivileged base service and opt-in dataplane capability profile; finish
  typed API-error migration and decide the v1 posture for live management-plane
  credential rotation and received eBGP-only attributes. Privilege separation
  remains a larger architectural choice, not a release-checkbox claim.

### Next (research-shaped, July 2026)

This phase was shaped by a strategic pass over the competitive landscape
(BIRD 2/3, FRR, GoBGP, OpenBGPd; IOS-XR/cRPD as the commercial reference),
IETF GROW/IDR/SIDROPS activity, and documented operator-demand signals
(top-voted feature requests, NANOG/RIPE/DENOG talks, the OpenBGPd
route-server re-entry playbook, and the Route Server Support Foundation's
software-diversity funding). Two findings converge:

1. **BMP depth is the open, niche-defining gap.** No open-source daemon
   ships the full monitoring trio — RFC 7854 (Adj-RIB-In), RFC 8671
   (Adj-RIB-Out), RFC 9069 (Loc-RIB): FRR and GoBGP stop at Loc-RIB (and
   FRR documents BMP+Add-Path as unreliable), BIRD's BMP is experimental,
   OpenBGPd has none. Per-client Adj-RIB-Out monitoring is the
   observability twin of ORR — proving *what the RR actually sent each
   client*. On top of that, the BMPv4 TLV framework
   (draft-ietf-grow-bmp-tlv) plus the path-marking
   (draft-ietf-grow-bmp-path-marking-tlv) and route-event-logging
   (draft-ietf-grow-bmp-rel) drafts have no router-side implementation
   anywhere — and rustbgpd already computes per-path `BestPathReason` and
   per-policy discard/validation reasons, making path-marking and REL
   largely serialization work. pmacct (whose maintainers co-author the
   drafts) is the live collector-side interop partner.
2. **Explainability is the demand signal.** GoBGP's top-voted open
   feature request is export-side "why is this route not advertised to
   peer X" — with the ADR-0096 policy-language arc shipped (import
   explain, live-RIB policy dry-run, ORR explain, per-term traces +
   live hit counters; M80 parity receipt), export-side explain
   completion (now shipped — the gate-ladder
   `ExplainAdvertisedRoute`) closed the trilogy in a moat no
   competitor has started.

**The BMP arc — shipped 2026-07-02/03 (#660–#665, ADR-0097)**: RFC 8671
Adj-RIB-Out + RFC 9069 Loc-RIB on the existing exporter → BMPv4 TLV
framing → path-marking TLV (streaming "why this path won/lost" — the
best-path/ORR reasons on the wire) → the M81 pmacct/gobmp/tshark interop
receipt. REL was deferred from the arc (zero collectors decode it
today; the policy-discard/validation inputs it needs already exist).
Details in the "Recently shipped" section below and ADR-0097.

**Next, in rough order** (each research-backed, sized about one slice):

- **Trust/adoption hygiene sweep** (all small): keep the cargo-fuzz / OSS-Fuzz
  onboarding and per-RFC receipts/conformance page current, and keep the
  published Grafana dashboard aligned with the shipped metrics. The secure
  route-server profile and RFC 9687 Send Hold Timer pieces are now shipped.
- **Route-server adoption polish** — the ADR-0101/M83 profile shipped the
  secure preset: RFC 7947 transparency, Add-Path and `per_client_best`
  path-hiding mitigation, RFC 9234 OTC toward members (including dynamic /
  gRPC-added peers), ASPA/ROV/reject-AS_SET hygiene, RFC 8097 OV_* tagging,
  and a curated `examples/route-server` profile. The canonical semantic diff
  engine, `rbgp diff`, BIRD/FRR/GoBGP/MRT adapters, and BMP Adj-RIB-Out import
  are also shipped. Remaining demand-shaped work: a real shadow/canary receipt,
  Alice-LG adapter, a 1000+-peer route-server scale receipt, and an ARouteServer
  target.
- **RFC 9857 SR-Policy-state-in-BGP-LS** (receive/reflect/API) — published
  RFC, no open-source implementation found, drops onto the existing
  BGP-LS substrate; deepens the controller feed (TE controllers reading
  SR policy state over gRPC).
- **ASPA/RTRv2 conformance refresh** against the latest drafts — cheap
  insurance for a day-one-RFC-compliant claim while BIRD's ASPA sits in a
  side branch and FRR has none.
- **Paths-Limit capability** (draft-abraitis-idr-addpath-paths-limit) —
  small, RR-relevant (bounds Add-Path fanout), FRR 10.1 interop available.

**The route-server (IXP) track** — the core is shipped; remaining work is
adoption tooling. ADR-0101/M83 covers RFC 7947 transparency, Add-Path and
`per_client_best` path-hiding mitigation, RFC 9234 OTC, ASPA/ROV hygiene, and
multi-stack BIRD/GoBGP/FRR/StayRTR proof. Next useful slices are an Alice-LG
gRPC source adapter, a 1000+-peer route-server scale receipt, shadow/canary
RIB-diff tooling (`rbgp diff` against an incumbent's MRT/BMP feed), and an
ARouteServer target once the pilot surface is stable.

**Researched and rejected** (recorded so they aren't re-litigated):
confederations (RFC 5065 — no demand signal in two years of issues and
talks; solves the problem RRs already solve), diverse-path RFC 6774 /
advertise-best-external (commercial-only; superseded by Add-Path, which
rustbgpd ships across families), Flowspec v2 (codepoint churn), BGP-CT/CAR
(PE-scale, out of niche), custom Kafka/NATS bridges (BMP *is* the bridge;
gobmp/pmacct already terminate it into Kafka), and BGPsec.

### Recently shipped (2026-07-01/03, condensed — details in CHANGELOG/ADRs)

- **Export-side explain completion (the GoBGP-demand item)** —
  `ExplainAdvertisedRoute` / `rbgp rib advertised <peer> --explain` now
  answers "why did/didn't route X go to peer Y" with the full export
  gate ladder in live evaluation order (split horizon, RFC 4456
  reflection, family, RFC 9494 LLGR, RFC 5291 ORF + initial-ORF gate,
  export policy with `.rpol` per-term labels, Adj-RIB-Out
  staged-vs-in-sync diff), plus a `--rd` VPN form adding the RFC 4684
  RT-membership gate. Truthful by construction: a read-only dry run of
  the same staging body live export executes (`ExportTarget::Explain`),
  update-grouped peers included (grouped-vs-ungrouped verdict equality
  is test-pinned); explain never skews policy counters. Later exports
  on the wire via the BMPv4 path-marking TLV.

- **The BMP arc (ADR-0097, #660–#665 + M81)** — the full monitoring
  trio on one exporter with per-collector view selection: RFC 8671
  post-policy Adj-RIB-Out tapped at the transport byte funnel
  (byte-exact wire PDUs, O+L flags, stats 15/17) and RFC 9069 Loc-RIB
  synthesized at the recompute seams (peer type 3 instance peer,
  fabricated OPEN, `"global"` table name) with a chunked non-blocking
  collector-connect table dump + per-family EoR — **no other
  open-source daemon ships the trio**. Plus the first router-side
  BMPv4 implementation: per-collector `version = 3|4` (default 3,
  v3 byte-identical, all draft code points in one module for the
  pre-IANA renumber) and the Path Marking TLV on Loc-RIB (Best/Stale
  bits only, reason re-derived best-vs-runner-up from the explain
  ladder, unmappable reasons omitted). M81 proves it against pmacct +
  gobmp + tshark at once, with v4 code points byte-pinned against the
  drafts' wire figures (no shipped collector decodes tlv-20 yet — two
  pmacct upstream findings recorded). Deferred: REL (zero collectors
  decode it), BMPv4 optional TLVs, path-marking statistics,
  Nonselected/Add-Path marking.
- **The `.rpol` typed compiled policy language (ADR-0096, #654–#658 +
  M80)** — public typed IR with indexed match sets behind the unchanged
  engine (set-heavy matching ~270× faster; golden decision-parity corpus
  vs the legacy walker), the `.rpol` frontend (named prefix/community
  sets, parameterized policies monomorphized at load, `apply()`
  composition, in-language `test` blocks, ariadne diagnostics), daemon
  integration (`[policy] rpol_files`, mixed TOML/rpol chains, SIGHUP
  hot-apply scoped to peers whose resolved chains changed), and the
  explain surfaces (per-term traces in `policy explain`, the
  `rbgp policy test` live-RIB dry run, `rbgp policy stats` live per-term
  hit counters). M80 proves route-for-route parity against FRR
  route-maps expressing the same intent, plus refresh-scoping on an
  `.rpol` edit under traffic. Follow-up: an import-side read surface for
  the (already-accumulating) import hit counters.
- **Optimal Route Reflection (RFC 9107)** — per-client best paths
  via SPF over the BGP-LS-sourced topology; typed topology accessors, graph +
  hand-rolled Dijkstra + NH-cost resolution, `orr_vantage` config, the
  interior-cost tiebreak at RFC 4271's step-(e) slot, `rbgp topology`/`rbgp
  orr`. The SPF graph is default-topology-only: non-default/malformed inputs
  are isolated before graph insertion, with aggregate API/CLI/metric/explain
  diagnostics; Flex-Algorithm data is inert. M76 proves live divergent bests,
  topology-driven flips with zero churn to unaffected clients, and clean
  fallback. **No other open-source BGP daemon ships ORR.** The M76 lab also
  surfaced and fixed a latent
  negotiation bug: implicit IPv4 unicast was added against explicit MP
  capability sets, leaking classic NLRI onto linkstate/VPN/RTC-only
  sessions (#632; capability-less-legacy-peers-only now).
- **RT-Constrain (RFC 4684)** and **VPNv4/v6 route-reflection (RFC
  4364/4659)** — see the address-family arc below and the ADR-0077
  amendment (M74/M75 receipts; strict per-peer VPN filtering; the M75 lab
  caught the missing-AS_PATH default-origination bug pre-CI).

- **Config transaction coverage + OpenConfig bridge** *(complete —
  ADR-0076).* Native gRPC now has validate-only planning,
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
  `neighbor-address` / `peer-as` / `description` / `peer-group`; the standard
  gNMI commit-confirmed extension now maps `commit` / `confirm` / `cancel`
  onto ADR-0076's confirmed transaction lifecycle. **Done:** peer-group object
  Set can now create/update/delete native peer-group catalog entries for the
  OpenConfig leaves with exact rustbgpd mappings (`peer-group-name`,
  `auth-password`, `remove-private-as`, and `timers/config/hold-time`); leaves
  without a native inherited model stay `UNIMPLEMENTED`. **Done:**
  dynamic-neighbor prefix Set maps OpenConfig `prefix` + `peer-group` ranges to
  native `[[dynamic_neighbors]]` with `remote_asn = 0` and native validation
  gates. M54 now proves the supported Set and commit-confirmed flows with
  `gnmic` over mTLS. Exit: atomic commit
  where supported, explicit restart-required/rejected surfaces,
  rollback/receipt model, no partial silent drift. Gated by ADR-0064 tier authz.
- **Operational proof / scale automation** *(parallel priority, small slices).*
  Re-stand the proof loop that makes the v0.x posture credible: a continuous
  churn/soak shape, automated or easy-to-trigger Criterion comparisons on the
  `[self-hosted, rustbgpd-bench]` runner, and a fixed high-N memory harness for
  regressions. **Done:** the EVPN single-active failover + ES
  drain/undrain soak shape now exists as the M67 link-driven drain churn
  harness under `tests/soak/`: it repeats the real carrier-loss trigger and
  analyzes route withdrawal/return, DF-role gauges, drain reasons, AC-gate
  state, blackout/release timing, restart counters, and RSS. It is a harness,
  not yet an archived 24 h receipt. **Done:** bounded
  `bgp_config_transaction_lifecycle_total{operation,outcome}` exposes confirmed
  transaction confirm / abort / auto-revert failures without unbounded labels
  (`confirm_id`, candidate content, and error text stay out of Prometheus).
  **Done:** the ignored high-N RIB structural memory profile now emits
  machine-readable rows for Adj-RIB-In, Full-RIB, and RR/route-server fanout
  shapes at 100k/500k/900k prefixes, and `bench/compare-rib-memory.sh` produces
  A/B CSV + Markdown receipts under the shared bench/soak host mutex.
  **Done:** `docs/OPERATIONAL_PROOF.md` now consolidates CI interop, hosted
  kernel dataplane, benchmark, high-N memory, and archived 24 h soak receipts
  into one operator-facing proof index.
  Exit: one repeatable soak result operators can inspect, bench comparison
  receipts for perf PRs, and memory tracking that covers full-table scale
  without relying only on bgperf2.
- **MPLS / VPN / BGP-LS address-family arc** *(BGP-LS receive + reflection +
  API-export, VPNv4/v6 route-reflection, RT-Constrain, and IPv4/IPv6
  labeled-unicast route-reflection shipped — the ADR-0077 family quartet is
  complete).*
  ADR-0077 draws the address-family-expansion boundaries while the
  substrate is still small: a control-plane AFI/SAFI route-key model for
  VPNv4/v6 (RFC 4364 / RFC 4659), labeled-unicast (RFC 8277), Route Target
  Constraints (RFC 4684), and BGP-LS (RFC 9552, which obsoletes RFC 7752), with
  BGP-LS *receive/API export plus reflection* and route-reflector-only VPN/MPLS
  families as the on-identity entry points (controller-feed / RR, not a
  forwarding plane).
  **Done:** the BGP-LS wire/RIB/API tranche accepts `linkstate` /
  `linkstate_vpn`, decodes BGP-LS and BGP-LS VPN MP_REACH/MP_UNREACH, stores
  learned topology objects in typed Adj-RIB-In / Loc-RIB tables, and exposes
  opaque NLRI/TLV bytes through `RibService.ListBgpLsRoutes` and
  `rbgp rib bgpls`. **Done:** BGP-LS routes now flow through initial table
  dumps, outbound reflection/export, route-refresh replay, and dirty
  Adj-RIB-Out resync for eligible negotiated peers; M73 proves the SAFI 71
  reflection and withdrawal path with a GoBGP 4.6.0 route source and sink. GR
  entry now conservatively withdraws BGP-LS routes and Enhanced Route Refresh
  sweeps omitted BGP-LS objects instead of reporting stale controller-feed data
  as live; BGP-LS Add-Path and BGP-LS VPN
  interop, and local topology production remain deferred.
  **Done:** the VPNv4/VPNv6 (AFI 1/2, SAFI 128) route-reflector slice shipped
  end-to-end as four stacked tranches: typed RIB substrate (RD + prefix route
  key with the MPLS label stack as route data, Add-Path path-id reserved),
  receive + read-only API (`l3vpn_ipv4_unicast` / `l3vpn_ipv6_unicast`
  families, `RibService.ListVpnRoutes`, `rbgp rib vpn`, RFC 8277 §2.4
  withdraw-mode compatibility-field codec, RFC 4364/4659 RD-prefixed
  next-hops incl. the 48-byte link-local form), RFC 4456 reflection with RD /
  label-stack / next-hop / Route-Target preservation (same-peer relabels
  re-advertise; every ineligibility branch withdraws), and the Enhanced Route
  Refresh stale lifecycle (BoRR/EoRR sweep, family-isolated, intern-GC-safe).
  GR entry conservatively withdraws SAFI-128 routes (no stale preservation);
  Add-Path and next-hop rewriting stay rejected/inert per ADR-0077 §6. M74
  proves the VPNv4 reflection, preservation, withdrawal, and
  no-dataplane-install path with a GoBGP source and sink.
  **Done:** RT-Constrain (RFC 4684, AFI 1 / SAFI 132) shipped as the VPN RR
  scalability companion: RTC NLRI codec with RFC-faithful 96-bit prefix
  matching (GoBGP-divergence documented in the ADR-0077 amendment), full
  receive/reflect/API slice (`rtc` family, `ListRtcRoutes`, `rbgp rib rtc`),
  self-originated default membership, and strict per-peer VPN reflection
  filtering with RFC-minimal announce/withdraw deltas on membership change —
  driven through the same dirty-restage machinery as export-policy
  replacement. Enhanced Route Refresh sweeps re-derive membership and restage
  VPN. Deferred (ADR-0077 amendment): §3.2(ii) non-client attribute-swap, §6
  60s EoR delay, eBGP RTC subtleties, RTC×ORF, Add-Path. M75 proves strict
  filtering, widen/narrow-without-reset, RTC reflection, and the unfiltered
  non-RTC-peer path against GoBGP.
  **Done:** IPv4/IPv6 labeled-unicast (RFC 8277, AFI 1/2, SAFI 4) closed the
  quartet as one complete slice: typed RIB substrate + announce/withdraw
  codec (the §2.4 withdraw-compatibility field on transmit, label-stack
  withdraws survived on receive), receive/reflect with label stack and
  next-hop preserved verbatim, GR/LLGR stale preservation, ORR, Add-Path,
  `ipv4_labeled_unicast` / `ipv6_labeled_unicast` families,
  `RibService.ListLabeledRoutes`, and `rbgp rib labeled`. M79 proves
  reflection (incl. a multi-label stack and a v6 next-hop over the v4
  session), relabel implicit replace, multi-label withdraw with zero session
  flap, the GR window + EoR sweep, and no dataplane install against GoBGP.
  **Explicit non-goal, stated up front: rustbgpd does not install MPLS labels
  in the dataplane** — these are BGP-carried families, not a step toward a full
  MPLS router (see Non-goals). The ADR also preserves the ORF Address-Prefix
  guard: only IPv4/IPv6 unicast entries are parsed today, and future
  VPN/MPLS-family ORF support must be family-specific. Follow-up substrate work
  must either remain unreachable from peers/operators or ship a complete typed
  family slice; constant-only negotiation or config-only "support" is
  explicitly out of scope.

### Later

- **FIB operational hardening** *(decision gate — pull only
  operator-confidence pieces).* ADR-0061/0066/0068 cover configured-table
  install, ECMP, per-class caps, `multipath_relax`, and Link Bandwidth
  weighting; the next pain points are lifecycle and scale, not base
  capability. **Done:** hot-swap `[[fib_tables]]` without a restart — SIGHUP
  soft-reload and gRPC/`rbgp fib-table` CRUD (`SetFibTable` /
  `DeleteFibTable` / `ListFibTables`), ack-gated with no runtime/config drift.
  Decide based on signal: over-cap detail APIs beyond the sampled
  `route_limit_exceeded` rows. Defer unless perf-gated or demanded: incremental
  equal-cost sibling index for wide full-table multipath; platform-diversity
  interop for weighted multipath.
- **ASPA verification — test hardening.** Role-aware upstream/downstream
  verification now ships with the draft-v25 first-AS precondition, §6.2
  IPv4/IPv6-unicast family gate, best-path preference, and
  `match_aspa_validation` import/export policy. Direct policy-match unit coverage
  now pins all ASPA verdicts plus combined RPKI+ASPA predicates. A compact
  offline subset of the NIST-BRIO ASPA demo corpus (b7.1.2) is imported as
  verifier unit tests for upstream/downstream Valid, Invalid, Unknown, and
  ASPA-Valid attack-limit cases. Remaining ASPA work is demand-shaped policy
  breadth, not feature scope.
- **EVPN standards tail.** The current VXLAN/Linux EVPN lane is broad but
  intentionally bounded. Native RFC 9136 GW-IP and ESI overlay-index Type 5
  origination now ship, and the single-active ESI overlay-index receive path
  now has a real-peer interop proof (M71, GoBGP route source); near-term
  standards work is broader protected-recursion interop, especially the
  all-active ESI path; demand-shaped
  VXLAN operability includes VLAN-aware bridge support and rustbgpd-managed
  bridge / VXLAN / VLAN upper / VRF netdev creation. **ADR-0088 records that boundary:**
  VLAN-aware bridges require an explicit EVPN-to-Linux binding, and managed
  netdev creation must be opt-in and one ownership class at a time.
  **ADR-0089's first programming target landed:** VNI-per-broadcast-domain
  EVPN over Linux `vlan_filtering=1` bridges, with a local bridge-VLAN
  binding, `NDA_VLAN` remote-MAC FDB attribution, AF_BRIDGE local-MAC VLAN
  attribution, and Ethernet Tag ID still `0`; true RFC VLAN-aware bundle /
  non-zero-Ethernet-Tag service stays deferred. **LAN-64 SVD /
  collect-metadata Ready/programming landed:** rustbgpd now detects
  `external` / `vnifilter` VXLAN devices, accepts an unambiguous
  `(bridge_vlan, tunnel_info id <VNI>)` mapping as a Ready VXLAN target,
  programs single-dst and FDB-NHG rows with `NDA_SRC_VNI`, and parses
  explicit-VNI rows on known SVD ifindexes. **ADR-0091 bridge-class
  lifecycle landed:** `[managed_netdevs]` accepts opt-in bridge desired state,
  derives the durable `rustbgpd:bridge:<owner>:<name>` altname stamp, exposes
  desired/observed/orphan/foreign/unsafe status through
  `EvpnService.ListManagedNetdevs` and `rbgp evpn managed-netdevs`, creates
  missing managed bridges, adopts exact stamped bridges after restart, and
  safely reaps same-owner orphans. **ADR-0091 fixed-VNI VXLAN lifecycle
  landed:** `[managed_netdevs]` accepts fixed-VNI VXLAN desired rows, derives
  `rustbgpd:vxlan:<owner>:<name>` stamps, parses named VXLAN links from the
  Linux snapshot, exposes desired/observed/orphan/foreign/unsafe VXLAN
  status, creates missing fixed-VNI VXLANs on the desired bridge, adopts exact
  stamped VXLANs after restart, and safely reaps same-owner VXLAN orphans
  while preserving a stamped orphan that drifted into a collect-metadata or
  vnifilter mode the fixed-VNI lifecycle never creates;
  `managed_ready` proves that a rustbgpd-created bridge plus rustbgpd-created
  fixed-VNI VXLAN make the real EVPN L2 instance probe Ready only after both
  links are owned-safe. **ADR-0091 VRF/L3VXLAN lifecycle landed:** managed
  VRF and L3VXLAN rows create missing links, stamp them, adopt exact stamped
  links after restart, reap exact same-owner orphans in L3VXLAN-before-VRF
  order, and preserve foreign or owned-unsafe links. `managed_ip_vrf_ready`
  proves on a real kernel that the rustbgpd-created VRF plus L3VXLAN topology
  drives the IP-VRF readiness probe from NotReady to Ready.
  **ADR-0091 VLAN upper lifecycle landed:** `[managed_netdevs]` accepts VLAN
  upper rows bound to configured `[[evpn_instances]] bridge` / `bridge_vlan`
  pairs, creates `ip link add link BR name BR.VLAN type vlan id VID` helpers,
  stamps and adopts exact links after restart, and reaps same-owner VLAN upper
  orphans before their parent bridge. `managed_vlan_upper` proves create /
  adopt / reap / foreign-preserve on a real kernel. **ADR-0091 SVD /
  collect-metadata VXLAN lifecycle landed:** `[managed_netdevs]` accepts SVD
  VXLAN rows, derives bridge-VLAN -> VNI tunnel mappings from configured
  EVPN instances, creates `external` / `vnifilter` / `nolearning` VXLAN
  devices, stamps and adopts exact links after restart, preserves foreign or
  owned-unsafe drift, and reaps exact same-owner SVD VXLAN orphans.
  `managed_svd_vxlan` proves create / adopt / reap / foreign-preserve on a
  real kernel.
  The `svd_fdb_vni` netns proof
  covers Ready + add + same-MAC two-VNI isolation + scoped delete on a real
  kernel; sparse `NDA_VLAN` / `NDA_DST` echoes are handled by configured-VLAN
  inference plus owned-state convergence. Service-provider EVPN breadth
  (route types 6-11, PBB-EVPN,
  multicast EVPN/MVPN, VPWS/E-Tree, MPLS/SRv6 service encapsulation) stays out
  of the current lane until operator demand justifies a new ADR. **Native
  GW-IP overlay-index origination landed
  (ADR-0087):** per-IP-VRF `overlay_index_mode = "gateway_ip"` originates
  Type 5 with the kernel via (when it lands on a connected tenant subnet) in
  the Gateway Address and no Router-MAC extcomm, feeding the already-shipped
  receive-side recursion; default `"interface_less"` is unchanged. Proven by
  self-consistency tests (own origination → own projection resolves end-to-end,
  fallback interface-less projection, and via appears/disappears in-place
  re-origination) and M68, a hosted FRR consume-side proof that holds the Type 5
  unresolved until the companion Type 2 appears, then imports it via
  `enable-resolve-overlay-index`. Path **B (ESI overlay index, RFC 9136
  §4.3) also landed as an explicit origination mode**:
  `overlay_index_mode = "esi"` emits RT-5 with non-zero ESI, zero Gateway
  Address, L3VNI label, and the configured virtual/transit Router MAC, with
  config validation tying the selected ESI to a linked local L2VNI. The
  receive side now ships a deliberately bounded single-active v1: non-zero-ESI
  RT-5s import only when scoped EAD-per-EVI state in a linked L2VNI yields
  exactly one single-active remote VTEP, using the RT-5 Router MAC as the inner
  destination MAC. Ambiguous candidates stay fail-closed. ADR-0090 now owns the
  all-active receive contract: deterministic remote-VTEP target sets,
  route-level ECMP over the L3VXLAN device, per-VTEP L3 neighbors, L3VXLAN
  FDB-NHG for the shared Router MAC, and M72 as the real-peer success proof. The
  single-active receive path now has a real-peer ESI protected-recursion interop proof,
  M71: a hosted GoBGP route source injects an ESI overlay-index Type 5 plus
  the resolving EAD-per-ES (single-active) / EAD-per-EVI, and rustbgpd holds
  it unresolved without the EADs, imports it into vrf1 once they arrive
  (kernel route via the PE VTEP), and re-fails-closed when the EAD-per-ES is
  advertised without the Single-Active flag. **LAN-70's kernel
  mechanism receipt landed:** the privileged `l3_multipath` netns selector
  proves that Linux accepts VRF-table route multipath over one L3VXLAN, that
  duplicate single-dst FDB rows for one Router MAC collapse to one destination,
  and that FDB nexthop groups work on the L3VXLAN device. That proves the
  viable object model for the ADR-0090 all-active receive design. The pure
  projection substrate also landed: Type 5 ESI resolution now distinguishes
  single-active, all-active, and conflicting EAD redundancy signals and can
  model deterministic all-active remote-VTEP target sets. The L3 diff boundary
  now carries that target-set shape far enough to validate family and Router-MAC
  conflicts; single-member all-active target sets and incompatible Router-MAC
  claims fail closed instead of degrading to scalar state. The Linux dataplane
  has the L3 ownership substrate and writer for that shape: distinct L3 NHID
  ranges, a separate L3 owned-nexthop dump surface, Router-MAC FDB-NHG refcount
  state partitioned from ADR-0059's L2 aliasing domain, VRF-table ECMP route
  programming, per-VTEP L3 neighbors, and clean all-active withdraw/collapse
  cleanup. Restart adoption now reclaims crash-leftover all-active ECMP routes,
  every remote-VTEP neighbor, the Router-MAC L3VXLAN FDB-NHG row, and the
  existing L3 NHID member/group tree before desired state reclaims it or the
  deferred reap deletes it. **LAN-76's same-host production-path proof landed:** the privileged
  `l3_all_active_writer` netns selector drives a real
  `ReconcileActor<LinuxDataplane>` through the all-active writer and asserts the
  route, neighbor, FDB-NHG, cleanup, and restart-adoption state. **M72's real-peer proof landed:**
  two GoBGP PEs advertise all-active EAD state, rustbgpd imports the ESI-overlay
  Type 5 as a two-way VRF ECMP route over `l3vxlan100` with a Router-MAC
  `nhid` FDB row, then withdraws cleanly on target-set collapse and Type 5
  delete. The
  single-active arc below is **done (ADR-0083, all four slices):** remote
  single-active MACs ride per-`(ESI, EthTag)` one-member FDB nexthop
  groups with a pre-created standby NH, and an EAD-per-ES withdrawal
  with surviving eligible PEs swaps the group membership to the backup
  in one atomic netlink replace (MAC rows untouched); proven by M65
  with a measured ~4.5 s blackout. Follow-ups from the arc: (1)
  event-driven intent recompute — **done:** the dataplane supervisor
  subscribes to the RIB's EVPN route-event broadcast and re-projects
  after a 200 ms debounce (5 s poll retained as backstop); M65
  re-measured the AC-failure blackout at 300 ms (from ~4.5 s) and its
  hard bound tightened from 30 s to 3 s; (2) Ethernet-Tag
  alignment — **done:** EAD-per-EVI now originates with
  `ethernet_tag = 0` and the VNI in the label field per RFC 7432 §6.1
  / RFC 8365 §5.1.3 (FRR parity), so rustbgpd-originated EAD-per-EVI
  joins remote `(ESI, tag 0)` alias/eligible sets; (3)
  origination-side withdrawal stimulus — **complete end-to-end**:
  the manual half landed
  (ADR-0084): `SetEthernetSegmentDrain` / `rbgp evpn es drain`
  withdraws the ES's Type 4/EAD routes + member VNIs' local Type 2
  state without replay, in-memory v1, and the M66 interop job proves
  the drain end-to-end as a service handover with rustbgpd on both
  sides (the rustbgpd-originated proof M65 had to fake with GoBGP);
  the ES↔interface binding **landed** (ADR-0085
  decisions 1–3, slice 2 on top of the slice-1 `RTNLGRP_LINK` carrier
  monitor): `[[ethernet_segments]].interface` drives a `link` drain
  reason through the same primitive — AC carrier loss emits the
  EAD-withdrawn-MACs-retained mass-withdraw shape automatically,
  recovery holds `recovery_delay_secs` (re-armed per up edge), and
  operator/link reasons compose so neither trigger overrides the
  other; the same-ESI local bias **landed** (ADR-0085 decision 5,
  slice 3): a remote Type 2 whose ESI is locally attached, healthy,
  not drained, and entitled to forward (all-active always;
  single-active only as DF — a healthy backup keeps the remote row)
  programs no remote FDB row, fixing the M66 usurpation at its root;
  and the link-driven M66 sibling proof **landed** (M67, the final
  ADR-0085 slice): a real AC failure inside the active PE — no RPC —
  drives the drain, the §8.2 wire shape, the DF handover, the
  sub-second-sampled recovery hold-off, flap damping, and the
  operator/link composition against a real kernel, with a measured
  100–300 ms failover blackout. ADR-0085 arc done.
  The cross-vendor preference-DF smoke against FRR is now covered by
  M69. Still open from the arc: generalized runtime mixed-edit composer
  for broader ES/IP-VRF-linked candidates (pure additive build-up,
  standalone/IP-VRF-linked L2VNI swaps, and L2VNI-only
  add/delete/redefine compositions, including L2VNI-only batch redefines,
  now commit live; additive L2VNI adds may also expand an existing ES
  `member_vnis` set when every new member VNI is added in that same request;
  ES-member deletes are live only through delete-only tenant teardown, pure
  `ip_vrf` relinks commit live, and relinks mixed with row edits plus broader
  IP-VRF/ES row edits in the same request still fail closed today).
  **Done:** shape-aware
  EVPN `--diff` classification now
  distinguishes coordinator-supported SIGHUP shapes from restart-required
  identity changes; actor availability and convergence failure
  remain runtime SIGHUP outcomes. Demand-shaped; keep the remaining items as
  follow-up inventory.
- **EVPN Linux VTEP hardening.** VLAN-aware bridge support and
  rustbgpd-managed bridge / VXLAN / VLAN upper / VRF netdev creation are now scoped by
  ADR-0088, with ADR-0089 selecting the first VLAN-aware programming
  subset: traditional multi-VXLAN-device Linux bridges, local
  `bridge_vlan` attribution, and EVPN Ethernet Tag ID `0`. **Readiness +
  FDB + local-MAC attribution landed for the traditional multi-VXLAN shape:**
  `bridge_vlan` instances validate observed bridge/VXLAN VLAN membership,
  single-dst and FDB-NHG rows program `NDA_VLAN`, and snapshot / owned /
  adoption-reap state is VLAN-scoped; AF_BRIDGE local-MAC observations resolve
  `NDA_VLAN` through configured bridge-VLAN bindings before Type 2
  origination, and AF_INET / AF_INET6 MAC+IP observations on VLAN upper
  devices resolve through the same configured bindings before Type 2 MAC+IP
  origination. **Cross-vendor receipt landed:** M70 has FRR originate the same
  MAC in VNI100 and VNI200 while rustbgpd programs and withdraws only the
  matching VLAN-scoped FDB row on one `vlan_filtering=1` bridge. **SVD /
  collect-metadata Ready/programming landed:** link inventory records
  `external` / `vnifilter`, probe accepts unambiguous bridge-VLAN tunnel
  mappings as Ready, single-dst and FDB-NHG rows program `NDA_SRC_VNI`, and
  `svd_fdb_vni` proves same-MAC two-VNI isolation plus scoped delete against a
  real kernel. **LAN-78 netns receipt landed:** `macip_vlan_attribution`
  proves same-MAC+IP VLAN10/VNI100 and VLAN20/VNI200 observations on real VLAN
  upper devices, while bridge-ifindex ARP/ND on a `vlan_filtering=1` bridge
  remains fail-closed unless a future FDB-correlation design proves freshness
  and ambiguity handling. True RFC VLAN-aware bundle / non-zero Ethernet Tag
  remains a separate ADR gate. **ADR-0091 managed-netdev bridge +
  VXLAN + SVD + VLAN upper + VRF/L3VXLAN lifecycle landed:**
  `[managed_netdevs]` bridge, fixed-VNI VXLAN, SVD / collect-metadata VXLAN,
  VLAN upper, VRF, and L3VXLAN rows are validated as restart-required startup
  desired state, Linux link dumps parse rustbgpd altname stamps plus named
  VXLAN / SVD / VLAN upper protected attributes, and `ListManagedNetdevs` /
  `rbgp evpn managed-netdevs` report
  `desired-absent`, `foreign-present`, `owned-unsafe`, `owned-safe`,
  `orphaned`, or `unknown`; the dataplane actor creates missing managed
  bridges, fixed-VNI VXLANs, VLAN uppers, VRFs, and L3VXLANs, adopts exact
  stamped links after restart, and safely reaps same-owner orphans in
  dependency order.
  `managed_ready` proves that this rustbgpd-created bridge + VXLAN topology
  drives the real EVPN L2 probe to Ready, `managed_svd_vxlan` proves SVD
  create / adopt / reap / foreign-preserve on a real kernel, and
  `managed_ip_vrf_ready` proves that the rustbgpd-created VRF + L3VXLAN
  topology drives the real IP-VRF readiness probe to Ready. A dedicated counter
  for unattributable-VLAN local-MAC
  classifier misses is intentionally not a feature: those events fail closed as
  normal "not ours" outcomes, while downstream originator backpressure is
  already metered by `evpn_local_observations_dropped_total{reason}`. The
  early-boot cache-miss window is bounded by startup link-cache priming plus
  the first probe / supervisor dump, with no cross-VNI leak. `RTNLGRP_LINK`
  eventing instead of
  poll-only link inventory — **carrier eventing landed** (ADR-0085 slice 1:
  the `link_carrier` monitor subscribes for the attributes link-driven
  drain needs — name + `IFF_LOWER_UP`), and the poll-cadence tail sweep
  added `RTNLGRP_LINK` eventing on the notify socket so EVPN-surface link
  drift wakes the reconcile actor (the inventory itself is still rebuilt
  by dump — now event-triggered rather than periodic-only); **L2 readiness
  visibility landed**: `ListEvpnInstances` / `rbgp evpn instances` now expose
  the existing L2 `Ready` / `NotReady` / `Unbound` verdict and the concrete
  `NotReady` reason, including the VLAN-aware bridge rejection; learned-port-to-ESI
  disambiguation so one local VNI
  can participate in multiple Ethernet Segments; same-ESI local bias in the
  remote-MAC projection — **RESOLVED** (ADR-0085 decision 5, slice 3): M66
  surfaced an ES peer's Type 2 for a MAC on a locally-configured segment
  being programmed as a remote row, usurping the kernel-learned local AC
  row; with the ES↔interface binding the projection now suppresses remote
  rows for locally-attached, healthy, entitled-to-forward (ESI, VNI) pairs
  (DF-aware in single-active mode — a healthy backup keeps the remote row
  toward the active PE). The second half M66 surfaced — the in-place FDB port move
  emitting no local-delete observation, so the originator's cache kept
  claiming the MAC and undrain replayed it stale — is RESOLVED: the
  classifier now surfaces VXLAN-port `RTM_NEWNEIGH` as an
  `ObservedOnVxlanPort` observation and the originator drops the stale local
  claim, live or drained. Low-priority operational polish
  once core convergence is complete.
- **Single-active non-DF full AC blocking — RESOLVED** (2026-06-12,
  the ADR-0085 binding follow-on). The non-DF PE of a **bound**
  single-active ES now blocks its whole AC: the dataplane drives the
  bound bridge port's `IFLA_BRPORT_STATE` (`disabled` when non-DF for
  every member VNI or drained, `forwarding` when DF) through the same
  DF-role flow and `apply_bum_enforcement` knob as the BUM filter,
  with the drain path reusing it (any drain reason blocks; the
  recovery hold-off keeps it blocked until re-convergence) and M67
  asserting the transitions across a real failover. Remaining
  limitations, by design: unbound single-active segments stay
  BUM-flood-only (no port handle — bind the AC for full enforcement),
  and the gate is per PORT, not per VLAN — RFC 8584 service carving
  that splits DF roles across member VNIs falls back to BUM-only
  enforcement (warned + `evpn_es_ac_gate{state="mixed-roles"}` gauge;
  per-VLAN state would need `vlan_filtering` + per-VLAN STP state).
  Distinct from the deferred all-active local-bias item.
- **Wedged post-Established advertisement path (observed once, CI,
  2026-06-12 — mechanism identified and reproduced 2026-06-12;
  RESOLVED by session-identity stamping, see below).**
  During an M66 CI run, every advertisement pe1 issued AFTER initial
  convergence (fresh Type 2 origination, drain withdrawals) failed to
  reach the peer VTEP for ~10 minutes and across an in-job redeploy,
  while the session stayed Established (keepalives flowing) and
  previously-advertised state kept forwarding. Bring-up was instant.
  **Root-cause analysis (code-verified):** `RibUpdate::PeerUp`/`PeerDown`
  carry no session identity, and during the RFC 4271 §6.8 collision
  window two live session tasks exist for one peer address (M66's pe1
  and vtep dial each other simultaneously at container start). If the
  collision loser reaches Established and its `CollisionDump`-driven
  `PeerDown` is processed AFTER the winner's `PeerUp`, the stale
  `PeerDown` removes the winner's `outbound_peers` registration —
  `distribute_changes` iterates `outbound_peers` only, so the peer is
  never visited, never marked dirty, no resync fires, and no warning
  logs: a fully silent wedge while the session stays Established
  (keepalives are writer-owned, ADR-0078, on BOTH sides — which is
  exactly why neither hold timer fired). Bring-up advertisements ride
  the first `PeerUp`'s initial dump, post-convergence ones are lost;
  heal requires a new session (`PeerUp` re-registration), consistent
  with the observed ~17:58 recovery. Alternatives ruled out: RIB
  manager wedge (the vtep manager answered `ListEvpnRoutes` once per
  second throughout; the manager loop has no production awaits);
  dirty-resync starvation (1s persistent timer, and the wedge never
  marks dirty at all); session-TX/writer (bulk-channel saturation
  triggers a loud Cease/8 teardown, TCP backpressure would stall
  keepalives too and trip the remote hold timer in 90s).
  **Reproduced** at the manager level:
  `stale_peer_down_after_replacement_peer_up_is_discarded`
  (crates/rib/src/manager/tests.rs), originally a characterization of
  the silent-wedge end state, now flipped to a delivery assert.
  **Shipped observability:**
  `bgp_rib_outbound_registered_peers` gauge (Established sessions >
  registered peers = this wedge), `bgp_rib_outbound_registration_replaced_total`
  (the collision-overlap precondition), `bgp_rib_dirty_resync_total`,
  `bgp_rib_ingest_channel_depth`, a WARN on same-peer registration
  replacement, and an INFO on every outbound deregistration.
  **Resolved (the fix specified here, shipped):**
  `PeerUp`/`PeerDown`/`PeerGracefulRestart` carry the transport session
  id (the peer-manager-scoped `SessionIdentity` generation, stamped at
  every transport emit site including the GR path); the RIB manager
  records the registered id at `PeerUp`, discards a teardown whose id
  doesn't match (whole handler — Adj-RIB-In clear, GR/LLGR aborts and
  outbound deregistration included; INFO log +
  `bgp_rib_stale_peer_down_ignored_total`), and treats a replacement
  `PeerUp` as a session reset (clears the prior session's
  Adj-RIB-In/Out before re-registering, except routes under GR/LLGR
  stale retention, which stay deadline-bounded).
  **Completed for the symmetric interleaving (M66 failed on the fix
  PR's own CI):** with the winner's `PeerUp` processed FIRST, the
  loser's later `PeerUp` becomes the active registration (the
  replacement reset clears the winner's Adj-RIB-In) and the loser's
  `PeerDown` *matches* the registered id — the id gate alone runs the
  full teardown against a peer that still has an Established session.
  Session ids cannot arbitrate this (the §6.8 survivor is chosen by
  BGP-ID comparison, not event order), so the RIB manager now tracks
  every live session per address (bounded, collision window = 2) and
  fails the registration over to the survivor on an active-session
  down: re-register, re-dump the initial table, and request an inbound
  ROUTE-REFRESH through the survivor's channel (`OutboundRouteUpdate::
  request_refresh`; the session task enforces RFC 2918 capability) —
  Adj-RIB-In is per-address and the replacement reset already cleared
  the survivor's received routes, so inbound recovery must come from
  the peer. A GR-down of the active
  session with a live survivor fails over instead of entering stale
  retention. New `bgp_rib_outbound_registration_failover_total{peer}`.
  Manager tests pin all interleavings of {PeerUp(W), PeerUp(L),
  PeerDown(L)}. Residual evidence
  note: the M66 job logs contained no pe1-side daemon logs, so the
  collision itself was inferred, not observed — the WARN/INFO lines,
  gauge and discard/failover counters make any recurrence
  self-attributing.
  **Follow-up resolved — the remaining bare-peer-IP `RibUpdate`
  variants are now stamped and gated too.** A superseded session's
  queued data messages processed after the winner's `PeerUp` were
  still attributed by IP only: `RoutesReceived` (stale routes landing
  in the replacement's Adj-RIB-In), `EndOfRib` (premature GR-sweep
  completion), `BeginRouteRefresh`/`EndRouteRefresh` (an enhanced-
  refresh window opened/closed by the wrong session, sweeping
  refresh-stale routes early), `RouteRefreshRequest` (spurious
  re-advertisement), and `PeerOrfUpdate` (stale ORF entries installed
  as the replacement's outbound filter). All six now carry
  `session_id`; the RIB manager drops any whose id doesn't match the
  active registration (INFO log + the
  `bgp_rib_stale_session_message_ignored_total{peer,kind}` counter,
  `kind` ∈ routes/eor/refresh/orf/policy_context). A message for a peer
  with no registration keeps accept-all, mirroring the teardown rule.
  `SetPeerPolicyContext` now carries the same transport `session_id` and
  is dropped on a non-matching id; the pre-existing symmetric-failover
  manager tests already pin that subsequent outbound advertisements
  reach the survivor. `PeerDeleted` is config-scoped by design and stays
  unstamped.
- **ES drain withdrawal-ordering guarantee.** The Ethernet Segment drain
  primitive fans out to two actors (segment orchestrator withdraws
  Type 1/4; local originator withdraws Type 2) over independent
  channels, so the EAD-per-ES-before-MAC ordering that maximizes the
  remote receivers' single-active backup-swap window is convergent but
  not guaranteed. Assessed 2026-06-12: the coordinator already
  PUBLISHES segment-side first (EADs before the originator's MAC
  withdrawals — `apply_ethernet_segment_drain`), so the favorable
  order is best-effort today; guaranteeing it needs a consumption
  ack/generation-confirm seam in the segment actor before the
  originator publish. Deferred: M67 measured the link-driven drain
  blackout at 100-300 ms WITHOUT pinned ordering, so the ack plumbing
  would buy a narrower transient that measurement says is already
  acceptable. Revisit only if a soak or scale test shows the
  unknown-unicast gap mattering. Either order converges — now pinned
  by `reverse_publish_order_converges_to_the_same_withdrawn_state`
  (`src/evpn_es_drain.rs`, the cross-actor seam audit).
- **EVPN multi-homing hardening follow-ups** *(robustness/test) —
  resolved.* ADR-0085 ES↔interface binding now detects STP-owned
  bridge-port states (`listening`, `learning`, `blocking`) on a bound
  access-circuit port, warns once per conflict, and refuses to
  overwrite the state until the port returns to `disabled` /
  `forwarding`. ADR-0083 single-active backup-path now pins the failed
  backup-swap path: if the group membership `REPLACE` fails, the old
  active group and MAC row remain intact, the pre-created backup
  nexthop remains available for retry, and no completed-swap counter is
  emitted. The operator diagnose seam now has a read-only joined
  surface (`EvpnService.ListEthernetSegments` / `rbgp evpn es list`)
  that exposes configured membership, drain reasons, per-member
  DF/BUM action, same-ESI local-bias eligibility, AC-gate state, and
  matching FDB-NHG refs in one place.
- **Kernel-state crash-restart reconciliation** *(from the 2026-06 deep
  audit; decided in ADR-0079 — startup adoption sweeps on kernel ownership
  markers, reap deferred until reconvergence, no new persisted files).*
  Today only the unicast FIB survives an unclean restart; the other
  dataplane writers track ownership in memory only: RFC 7999 blackhole
  discard routes (a crash leaves a permanent kernel discard route invisible
  to every status surface, and preflight then rejects re-owning the
  still-desired row as `foreign_route_exists`); EVPN symmetric-IRB L3 state
  (VRF routes, permanent neighbors, and L3VXLAN FDB rows are never reaped
  after an unclean restart — a Type 5 withdrawn while the daemon was down
  keeps steering tenant traffic into a dead tunnel); and single-dst
  `extern_learn` FDB rows (ADR-0054 §7 promises next-startup cleanup that
  exists only for NHG-tagged rows). Ship order per the ADR: blackhole sweep
  first (fold in batching its presence checks into one kernel dump per
  pass) — **done:** adopt-at-startup + implicit re-claim + 500 s deferred
  reap + one-dump-per-pass shipped for the blackhole reconciler — then
  single-dst FDB — **done:** diff-level implicit re-claim (a marker row
  absent from the OwnedSet is a crash leftover, not a foreign entry) +
  startup adoption + deferred reap behind the ADR-0059 convergence gate —
  then L3 — **done:** marker-keyed adoption dump (proto-bgp+onlink VRF
  routes, permanent extern_learn neighbors / L3VXLAN FDB rows on managed
  devices), implicit re-claim through the replace-semantics apply path (no
  diff change), and a deferred reap behind a clean-L3-pass gate that tears
  down routes before their resolution rows.
  Related: scope the unicast owned-state signature per table and compare it
  set-wise so a crash plus any `[[fib_tables]]` edit — even stanza
  reordering — doesn't quarantine-freeze stale kernel routes — **done:**
  per-table `(table_id, metric)`-keyed signature matching; only the edited
  or removed table re-projects, with a `.stale` evidence copy beside the
  still-live owned-state file.
- **EVPN runtime apply cancellation-safety** *(decided in ADR-0080 —
  detached-task shield + shutdown fencing).* **Done:** the
  `ApplyEvpnRuntime` / SIGHUP converge + coordinator commit now runs on a
  detached task the caller merely awaits (the FIB-CRUD pattern), so a
  client disconnect or reload abort mid-apply loses only the response —
  never the rollback ladder, Degraded record, or committed-baseline
  advance; coordinated shutdown takes the apply lock (bounded) before EVPN
  teardown so it cannot interleave with an in-flight converge; and the
  IMET controller self-heals on withdraw `not_found` (previously one
  dropped reply left the tracked key out of sync and every later
  delete/redefine of that VNI rejected until restart).
- **Transport→RIB inbound backpressure contract** *(decided in ADR-0078 —
  block, never drop, matching the FRR/BIRD consensus).* **Done:**
  `RoutesReceived` now falls back from `try_send` to a blocking send — a
  full RIB channel parks the session task, stops the socket read, and TCP
  receive-window backpressure paces the sender instead of silently dropping
  a batch (`bgp_inbound_rib_backpressure_total` counts blocked sends); the
  KEEPALIVE cadence moved into the per-connection writer task so a parked
  session keeps feeding the peer's hold timer; and a hold-timer expiry with
  unprocessed peer input pending re-arms instead of expiring
  (`bgp_hold_timer_rearmed_pending_input_total`). The interop-coverage
  follow-up is **done** — the M63 smoke
  (`test-m63-stalled-rib-hold-timer.sh`) proves hold-timer survival under
  an artificially stalled RIB (`RUSTBGPD_TEST_RIB_INGEST_STALL_MS` +
  `RUSTBGPD_TEST_RIB_CHANNEL_CAPACITY`) against a real FRR peer, with the
  saturation counter, the exact never-drop route count, and zero flaps as
  receipts. Remaining follow-up: revisiting the RIB channel capacity
  default against the bench convergence shapes now that overflow is a pacing
  knob rather than a correctness cliff.
- **Graceful-restart session-boundary hygiene.** GR flaps bypass `PeerDown`
  cleanup. **Done:** all four resulting state leaks are fixed: ORF filters and
  the ORF initial-advertisement gate surviving into the new session (#415),
  the configured LLGR stale time being consumed at GR→LLGR promotion (a
  peer re-establishing during LLGR always got the 360 s default), a
  GR/LLGR peer that never re-establishes leaving an empty Adj-RIB-In plus
  identity maps (and MRT peer-index entries) behind forever, and EoR being
  sent immediately for ORF-gated families — telling an RFC 4724 restarter
  to sweep retained routes before the gated flood arrives. A restarter's
  gated family now has its EoR withheld until the gate lifts and the gated
  flood is sent; non-GR ORF peers keep the immediate EoR (a client that
  never sends ROUTE-REFRESH must still see EoR).
- **Peer lifecycle hardening.** The `resolve_neighbor` cluster-id gap and the
  dynamic-peer `DeleteNeighbor` hazards are fixed (#416, v0.37.0):
  runtime-added neighbors resolve `cluster_id` like restart-built ones, and a
  parity test pins the two transport-construction paths to full
  `TransportConfig` equality so the next added field cannot silently diverge;
  `DeleteNeighbor` refuses dynamic-range peers with a typed error before any
  state or persistence mutation, so the `dynamic_neighbor_limit` slot stays
  accounted (the `BackToIdle` decrement still runs at session end) and the
  persist-failure rollback can no longer resurrect an ephemeral peer as
  persisted static config. The BFD-down collision-candidate gap is also fixed
  (#416, v0.37.0): a BFD Down now shuts a pending collision candidate down
  too, and `BackToIdle` promotion checks the BFD withhold before promoting.
  The inbound state-query-timeout hazard is fixed as well: the collision
  state query now distinguishes a deadline expiry from an exited session
  task, and a timeout drops the inbound connection instead of treating the
  existing — possibly Established — session as Idle and replacing it
  (RFC 4271 §6.8); a dead session task still accepts the inbound.
  Peer-group field edits now reach live dynamic sessions on the transaction
  path (v0.39.0, ADR-0086): the session reshape executor gracefully
  resets affected dynamic sessions after persist so they re-accept under the
  committed config. SIGHUP and targeted peer-group RPCs now hot-apply
  policy-only peer-group edits to live dynamic sessions; session-shaping
  peer-group edits on those no-preview paths still leave dynamic sessions on
  their running config until reconnect (deliberate; see ADR-0086's deferral).
  No-op targeted peer-group mutations now short-circuit before publish/reshape,
  so identical `SetPeerGroup` updates no longer bounce affected static
  sessions.
  (The per-peer Prometheus series leak listed here previously was fixed —
  deleted peers now reap their label series.)
- **Policy / explain follow-ups** *(operator polish, not feature).* Stable
  `reason` labels across the remaining ingress filter paths — **shipped in
  v0.39.0**: the canonical vocabulary is pinned in
  `crates/telemetry/src/reason_labels.rs` (typed `OtcBlockReason` /
  `RrLoopReason` shared by the metric labels, log tokens, and the structured
  OTC event; exact strings pinned by tests; documented per metric in
  `docs/OPERATIONS.md` "Ingress rejection / route-leak detection").
  Per-statement attribution within a matched import chain —
  **shipped in v0.39.0**: each `policy explain` permit/deny match carries
  a statement trace (policy + statement identity, matched conditions with
  stable labels, default-action fallthrough, `before -> after` attribute
  edits), re-derived at query time from the ADR-0073 cached pre-policy
  attributes so the live import path is untouched, agreement-tested against the
  live evaluator (the decision trace itself shipped in v0.31.0; this also
  covers the "named-policy / statement identity in explain output" item that
  used to sit below — traces attach to current-generation permit/deny outcomes
  only, not `stale`/`withdrawn`). Best-path explain surfacing the tiebreaker
  step that won (the RIB-side sibling to the export-side policy-clause
  attribution — shipped in v0.39.0: per-loser decisive step with
  compared values, the winner's step vs the runner-up, multipath-cut
  classification, `NOT_FOUND` for unknown prefixes).
  Also: verbose policy trace including non-match steps (the shipped trace
  reports the deciding statement per policy, not every statement consulted);
  route history / why-changed timeline;
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
  - Export-policy fanout batching: **shipped as RIB-level update groups**
    (ADR-0098, #674/#676 + cold-path/payload slice). Peers with identical
    staged output (export-chain content, eBGP/RR-client role, unicast
    families, LLGR families) share one staging pass, one group-owned
    outbound table, and one Arc-shared announce payload; joins/refreshes/
    queries replay or synthesize from the group table. Structural per-peer
    fallback for peer-context policy / Add-Path send / ORR / ORF — no
    knob — with a differential oracle pinning identical output. Measured
    ~28× single-shot 100k-route convergence at 256 uniform RR clients
    (15.1 s → 0.54 s); staging falls from 82.8% to 30.5% of RR CPU.
    v2 (ADR-0099, #685/#686): per-family keying and RT-filter-aware VPN
    grouping are **done** — VPNv4/v6 stage through the group table with
    the RFC 4684 Φ filter applied per member at emit (never keyed, so
    heterogeneous PE fleets share one group) and a zero-policy-eval
    membership-delta path; 1000 clients × 100k VPNv4 converge in 12.6 s
    / 625 MiB uniform, 3.9 s / 636 MiB at ~10% heterogeneous Φ.
    Remaining, recorded in ADR-0099: grouping Add-Path-send peers —
    verdict **unsound without per-member path-id state** (shared rank
    holes or per-member renumbering both break wire parity / the group
    equality baseline; a v3 needs per-member id maps or nothing); and
    per-(vantage, key) ORR groups — cut (win bounded by
    peers-per-vantage, second staged-table dimension), un-defer trigger:
    an operator running many peers per vantage.
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
    `serde_json` failures. The high-volume CLI BGP event stream now uses
    borrowed `Serialize` wrappers for event envelopes and EVPN route payloads
    instead of cloning proto fields into a second `serde_json::Value` tree.
    Remaining allocation/data-shape cleanup: CLI route JSON still maps proto
    routes into a second owned `JsonRoute` tree, and lower-volume API/CLI
    snapshot/reporting paths should only be changed when a profile shows value.
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

- **TCP-AO rotation polish.** Static TCP-AO + BIRD interop (M43), direct
  dynamic-prefix listener MKTs, fail-closed accepted-socket validation, and
  live neighbor API/CLI inspection are shipped. Ordered startup keyrings allow
  a restart-coordinated rollover: every key is installed, with a preferred or
  declaration-order-selected non-deprecated key used for startup transmission.
  Live key rotation without a daemon restart (LAN-16 / #159), runtime
  protected-range CRUD, and per-socket metrics remain demand-shaped rather
  than core-feature blockers.
- **Dataplane-aware readiness.** The shipped `/readyz` (and the bounded
  `GetHealth`) probe scopes readiness to the **control-plane core** — PeerManager
  + RIB responsiveness within a 200 ms deadline — and deliberately excludes the
  dataplane actors (FIB / EVPN / event-history). So a wedged `fib_runtime` does
  not fail `/readyz`: routes are no longer reaching the kernel even though the
  RIB stays responsive. A future `/readyz?detailed=true` or a separate
  `/dp-readyz` could surface per-dataplane-actor liveness for orchestrators that
  want the stricter gate. Demand-shaped / v2 — the control-plane gate is the
  right default (most readiness consumers want "is the BGP control plane up",
  and folding a slow or optional dataplane actor into the default gate risks
  flapping pods), so the stricter probe should be opt-in, not a redefinition.
- ~~**Optimal Route Reflection (RFC 9107).**~~ **Shipped 2026-07-02**
  (ADR-0095, M76) — see "Recently shipped" under Next. The remaining ORR
  tail (backup vantages, inter-RR Add-Path for multi-cluster, selectable
  TE/non-default/Flex-Algorithm SPF, §3.2 per-policy Decision Processes) is
  recorded in ADR-0095's deferral register with un-defer triggers.
- **ORF / Outbound Route Filtering follow-ups.** Receive-side Address-Prefix ORF
  (capability code 3, type 64; ADR-0075) is shipped and closes the IX
  route-server control-plane gap for clients pushing filters to rustbgpd.
  Send-side ORF (rustbgpd pushing filters to upstreams) and advertising legacy
  Cisco type 128 stay deferred pending operator demand; type 128 is accepted on
  decode only today. End-of-RIB for ORF-gated families is deferred only for
  GR-restarter peers (the premature-sweep fix); the conformance-purist
  alternative — defer EoR for every ORF peer, with a timeout backstop so a
  client that never sends its ROUTE-REFRESH still converges — stays deferred
  until interop evidence shows a non-GR receiver misreading the early EoR.
- **Confederation (RFC 5065).** Required for service-provider deployments, but
  SPs are not the initial target market. (Unblocks several deferred RFC 9234
  confederation-scope items and the RFC 8326 confederation gating.)
- **Out-of-niche address families.** L3VPN (VPNv4/v6, RFC 4364 / RFC 4659),
  labeled-unicast (RFC 8277), Route Target Constraints (RFC 4684), and BGP-LS
  (RFC 9552, obsoleting RFC 7752 / RFC 9029) shipped as the ADR-0077
  route-reflector / controller-feed quartet (see the address-family arc
  above) — the remaining gap here is the forwarding-plane PE role (VRF
  import, label allocation, MPLS FIB) plus SR Policy / SRv6 (RFC 9514),
  IPv4/v6 multicast, and VPLS. That remainder is entirely service-provider /
  traffic-engineering / full-router scope — outside rustbgpd's fabric /
  route-server / automation niche. Demand-shaped: pursuing it is a deliberate
  strategic pivot, not parity-chasing. When extending VPN/MPLS-family
  support, extend the ORF Address-Prefix decoder deliberately: it currently
  parses only IPv4/IPv6 unicast and preserves L2VPN / unknown SAFIs as raw ORF
  groups to avoid silently applying plain-IP prefix semantics to future families.
  The first acceptable implementation step is either private typed substrate that
  cannot be negotiated/configured, or a complete vertical slice with codec, RIB,
  policy context, route-refresh/GR behavior, API/CLI surfaces, caps, docs, and
  interop receipts.
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
- **EVPN adjacent standards.** PBB-EVPN (RFC 7623), RFC 9251 IGMP/MLD proxy
  multicast EVPN routes (types 6/7/8), RFC 9572 BUM segmentation
  (types 9/10/11), EVPN optimized ingress replication (RFC 9574),
  tunnel aggregation / common labels
  (RFC 9573), multihoming split-horizon for non-VXLAN tunnel families (RFC 9746),
  Proxy ARP/ND extended-community behavior (RFC 9161 / RFC 9047), MPLS/SRv6
  service encapsulation (including RFC 9252 SRv6 BGP overlay services), EVPN
  VPWS / E-Tree service models, and BGP Add-Path (RFC 7911) for L2VPN EVPN.
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

- **Peer-group persist-failure double-bounce removal (ADR-0081 decision 3
  follow-up).** A persist failure after a successful targeted peer-group
  reshape rolls members back through the same atomic fan-out — apply
  forward, bounce; roll back, bounce again. Correct and loud, never silent,
  but noisy. Removing the second bounce requires inverting the shared
  catalog-mutator contract (live apply → acked persist → capture-prior
  rollback) for reshape-bearing commands: split the atomic persist into a
  fallible *stage* (temp write + fsync, where disk-full/permission failures
  live) and a near-infallible *commit* (rename), and run the reshape
  between them. That is a two-phase persister protocol with its own new
  failure states (stage succeeds / reshape fails / temp cleanup fails;
  rename vs dir-fsync ordering; death between stage and commit) — real
  persistence-architecture work for a rare full-disk-mid-edit annoyance.
  Deferred until operator signal; the stage/commit split is the agreed
  shape if it is ever picked up.

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

- **gNMI / OpenConfig follow-ups** *(ADR-0070 counterpart).* v1 ships
  `Capabilities` / `Get` / `Subscribe` (`ONCE` / `POLL` / `STREAM SAMPLE`) over
  the strict OpenConfig BGP state subset, `ON_CHANGE` for the neighbor
  session-state leaf (M54/M56), and a first transaction-backed `Set` subset for
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

- **Wire / API strictness items.** Continue typed error variants where
  API-visible peer-manager / RIB boundaries still return opaque `String`
  errors; large-community duplicate normalization on receipt/encode (stored and
  re-advertised unchanged today); MRT snapshot encode allocation pressure on
  very large dumps; BMP periodic-stats scalability (serial `query_state().await`
  per peer) and BMP client connect-loop shutdown. FlowSpec unknown component
  pass-through was investigated and rejected: RFC 8955 treats unknown component
  types as malformed NLRI. Inbound BoRR/EoRR channel-full retry was also
  investigated and rejected: the receive path already backpressures with
  `send().await`.
  observation; SIGHUP reconcile rollback semantics (reports structured per-peer
  failures and keeps the prior snapshot, but does not roll back already-applied
  runtime peer changes); dynamic-neighbor `handle_inbound` split for readability;
  config snippets / examples in gRPC validation error detail.

---

## Engineering velocity / tech debt

Cross-cutting cleanups that don't move user-facing capability on their own but
lower the cost of every future PR. None block a release — grab one when your
branch is between features.

- [x] **Legacy GR/LLGR RFC gaps in unicast/FlowSpec/EVPN — RESOLVED.**
  The RR families (VPN/BGP-LS/RTC, #636–#638) implement the strict
  semantics; the pre-existing paths had three documented divergences,
  all now closed: (1) consecutive-restart deletes already-stale routes
  instead of re-marking them in place (RFC 4724 §4.1); (2) the EoR arms
  sweep non-readvertised stale/LLGR-stale routes before clearing flags
  on the re-advertised remainder (RFC 4724 §4.1 / RFC 9494 §4.2) —
  including the re-establish-during-LLGR path, all families; and
  (3) the RFC 9494 §4.4 LLGR-stale export restriction, repo-wide: every
  family's Adj-RIB-Out staging suppresses (withdraw-if-present)
  LLGR-stale routes toward eBGP peers that didn't advertise the LLGR
  capability for the family (receiver capabilities plumbed from session
  negotiation via `PeerUp`), while non-LLGR iBGP peers take the §4.6
  intra-AS exception — NO_EXPORT attached and LOCAL_PREF zeroed in
  transport's per-peer attribute rewrite, LLGR_STALE community riding
  unchanged.

- [x] **EVPN origination cross-actor seam audit — RESOLVED** (2026-06-12,
  PR #477). The seam inventory (drain vs. replay, withdrawal ordering,
  drained-set GC, bias/AC-gate coherence, DF-flip fanout, startup
  first-probe, apply-lock serialization, two-actor rollback) is enumerated
  in the PR and each holding invariant is pinned at the coordinator level:
  `evpn_es_drain.rs` (drain/undrain through the primitive against BOTH real
  actors with exact-replay assertions, reverse-publish-order convergence,
  apply-lock serialization, originator-failure rollback),
  `evpn_segment.rs` (GC'd re-added ESI starts undrained, exhaustive
  bias-eligibility ⇒ gate-not-Blocked matrix, DF flip republishing bias +
  AC gate together), `evpn_es_link_drain.rs` (down-at-boot convergence of
  drain state + bias + gate against a real segment actor), and
  `evpn_runtime_converger.rs` (an unrelated L2VNI add preserves an
  operator drain on every actor). Known bounded transients, by design and
  documented at the seams: the segment actor's first bias/gate publish does
  not wait for the carrier monitor's first probe (a bound dead-AC ES is
  bias-eligible for one fanout chain at boot; M67 measured the whole drain
  chain at 100-300 ms), and the two dataplane snapshots ride separate watch
  channels (one supervisor wake of skew). Single-ownership consolidation
  evaluated and not justified — see the PR's proposal section.
- [x] **Drain-GC split-state on a failed ES-delete apply — RESOLVED**
  (2026-06-12). `publish_ethernet_segment_runtime_snapshot` /
  `converge_tenant_teardown` GC'd the coordinator's drain entries BEFORE
  the actor publishes; on a mid-converge publish failure the rollback
  (per ADR-0084, deliberately) did not restore the GC'd entry — and the
  segment actor's drained-set mirror was never updated either, so the ES
  stayed withdrawn while the coordinator (gauge, RPC reasons) reported it
  undrained, and an operator undrain was an idempotent no-op. Fixed with
  GC-after-success: both paths now GC + push the GC'd set only after the
  last fallible actor publish succeeded, so a failed converge leaves the
  entry intact on both sides (still drained, still agreeing) and there is
  nothing for the rollback to restore — ADR-0084's no-restore stance is
  preserved by construction. Invariant pinned at the converger level
  (failed publish ⇒ coordinator state + actor mirror agree, and a
  subsequent undrain fans out) for both the ES-delete and tenant-teardown
  paths; the ADR-0084 annotation is updated to resolved.
- [x] **Poll-cadence tail sweep.** The dataplane intent recompute went
  event-driven with the 5 s poll demoted to a backstop, and segment
  re-election subscribes to the EVPN event broadcast with a 10 s backstop
  tick. The sweep found the originator RIB repoll already converted (RIB
  broadcast + local-MAC netlink observations; its 5 s tick is the backstop
  plus the duplicate-MAC quarantine recovery sweep, whose ≤5 s tail on a
  minutes-long quarantine window isn't worth a deadline timer) and the
  reconcile actor already event-driven for intent and custom-table route
  changes — what was missing was kernel-side drift eventing: programmed
  remote-MAC rows flushed off a managed VXLAN port and bridge-port
  flag/state drift (BUM-filter / AC-gate surface) repaired only on the
  60 s periodic dump. **Converted:** the notify task now wakes the
  reconcile actor on `AF_BRIDGE` FDB deletes on managed VXLAN ports and on
  classified `RTNLGRP_LINK` events (port flags/state, VXLAN/managed-bridge
  topology, enslavement), repairing within the 50 ms coalesce window; the
  periodic dump stays as the backstop. **Stays on cadence, deliberately:**
  BMP statistics (RFC 7854 interval reporting), BFD protocol timers, MRT
  dump rotation, and the retained backstop ticks themselves. **Follow-up
  (done):** the FIB runtime and blackhole reconcilers bounded *kernel*-side
  drift at 30 s — RIB-side changes were already event-driven — and now
  subscribe their own NETLINK_ROUTE connections to `RTNLGRP_IPV4/6_ROUTE`
  (`src/kernel_route_notify.rs`), surfaced through the `UnicastFib` /
  `BlackholeFib` seams: a delete of an owned-signature row (`proto bgp` in
  a configured table identity / the ADR-0079 blackhole marker in `main`)
  or a foreign replace on an owned identity wakes a coalesced reconcile
  (200 ms debounce, shared with the RIB-event path); install echoes and
  unrelated host churn stay silent, and the 30 s pass remains the
  backstop.

- [x] **Doc-collision discipline for `ROADMAP.md` / `CHANGELOG.md` /
  `docs/evpn-alpha-soak.md` / `docs/evpn-enablement.md`.** Multi-PR batches keep
  conflicting on the same handful of rows. The lightweight convention is now
  documented in `CONTRIBUTING.md`, prompted in the PR template, and checked in
  `docs/RELEASE_CHECKLIST.md`: append `[Unreleased]` entries within their
  subsection, keep one roadmap row per concern, and update exact tracking-doc
  gates instead of rewriting unrelated summary prose. A generated manifest stays
  deferred unless this process guidance fails to reduce drift.
- [x] **Test fixture extraction into a shared `test-support` surface.** Helpers
  like `route_event`, `session_event`, `policy_event`, `lifecycle_event`, and
  the per-test config builders had drifted across `crates/api`, `crates/cli`,
  `crates/rib`, and `src/`; a field addition (e.g. `event_id`) forced touching
  three or four copies. Resolved as private per-crate `#[cfg(test)]
  test_support` modules (a shared `rustbgpd-test-support` crate was rejected —
  it would force `pub` visibility and dependency edges). `crates/api` covers
  the service-test `PeerInfo`/metrics/event-stream fixtures and fake harnesses;
  `crates/cli` already shared its mock-server fixtures; `crates/rib` now
  centralizes the `Route` / `FlowSpecRoute` unit-test constructors; the daemon
  bin centralizes the EVPN (`vni`/`rd`/`mac`/instance) and FIB
  (table/key/route/route-event) builders. Deliberately left local: bench and
  integration-test helpers (separate compilation units — sharing would require
  new public surface) and intentionally divergent fixtures (the blackhole
  community-route builder, the EVPN MAC/IP route family, per-module
  minimal-config TOML snippets).
- [ ] **`unwrap()` audit on daemon-runtime paths.** Production-code unwraps
  outside `#[cfg(test)]` measure at ~5 sites after the v0.30 quality scan
  (mostly startup metric-registration invariants, poisoned-lock guards, and a
  few defensive parses of already-validated strings). The practical prefix-map
  conversion, BFD socket-option setup, BFD timer-pop sites, and raw EVPN
  nexthop netlink encode length conversions have been cleaned up; keep this
  open as a forcing function when the remaining invariants come up for refactor.
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
  errors to the transaction executor. Static-peer lifecycle/admin replies and
  policy/catalog replies (policy definitions, neighbor sets, peer groups,
  global named chains, and per-neighbor policy/peer-group membership) now also
  use typed errors where callers need status-class distinctions. The transport
  peer-session command ACK surface (`SendRouteRefresh`, live import/export
  policy updates, and graceful-shutdown toggles) now uses typed errors while
  preserving the existing peer-manager operator text. Older peer-manager / RIB
  commands still commonly return
  `Result<_, String>`; keep that for one-status surfaces, but migrate to small
  typed enums when a caller needs to distinguish `ALREADY_EXISTS`, `NOT_FOUND`,
  `INVALID_ARGUMENT`, or similar API-visible classes.
- [x] **RTR encode length conversions → checked typed errors.** The
  clippy-reason ratchet documented a few pre-existing RTR encode-path casts
  from `usize` to `u32`. They are not peer-reachable today — the encoder is fed
  rustbgpd-controlled/bounded records — but converting them to checked
  conversions with typed encode errors removes the remaining theoretical
  silent-truncation edge and makes the documented invariant executable.
- [x] **Catalog mutator persistence + lock convergence** *(from the 2026-06
  deep audit — shipped).* All 16 policy/peer-group gRPC mutators now follow
  the `AddNeighbor`/FIB-CRUD/`ApplyConfigTransaction` contract: detached-task
  shield, runtime-config coordinator lock with the mutation gate checked
  inside it, acked persist before lock release, and capture-prior runtime
  rollback on persist failure (peer-group rollback restores the unredacted
  stored secret). Confirmed-transaction abort/auto-revert also now treat a
  non-committable rollback re-apply as a rollback failure instead of
  reporting success.
- [x] **`SetPolicy` fan-out atomicity** *(remaining slice of the catalog
  convergence item).* The peer manager's direct `SetPolicy` apply fanned out
  per-peer runtime-policy updates in a loop; a mid-loop failure left
  already-updated peers on the new chains while later peers kept the old
  ones. The catalog fan-out (`apply_policy_change`, shared by all 12 policy
  / neighbor-set / chain mutators) now resolves every affected peer's chains
  first, then commits the set through the resolved-policy-snapshot primitive
  (`ApplyResolvedPolicySnapshot`, the live-impact transaction executor's
  capturing mechanism): a mid-fanout failure restores the already-updated
  peers to their captured priors and `current_config` does not advance.
  Peer-group reshapes (session teardown/rebuild) remain a separate deferral.
- [x] **Config transaction live-impact policy / peer-group executor.**
  Policy definitions, `neighbor_sets`, `peer_groups`, and global named
  policy-chain edits that move existing static neighbors' or accepted dynamic
  peers' resolved import/export policy chains now commit as transactions: stage
  the candidate snapshot, re-apply resolved chains to affected live sessions
  with captured priors, persist with ack, and restore live chains plus the
  snapshot on failure.
- [x] **Config transaction peer-group/session reshape executor.**
  Peer-group field edits and static-neighbor peer-group reassignments that
  reshape existing static sessions now commit as transactions: stage the
  candidate snapshot, reconfigure affected peers with captured prior configs,
  persist with ack, and restore live peers plus the snapshot on failure.
  Dynamic-range session reshapes shipped in v0.39.0 (ADR-0086): after a
  successful persist, the executor gracefully resets the live dynamic sessions
  accepted by an affected range (Cease + RFC 8203 shutdown communication);
  each remote's reconnect is re-accepted under the committed config and the
  accept-slot accounting stays owned by the normal `BackToIdle` reaping.
  Dynamic-range peer-group *reassignments* stay outside the reshape family (a
  `[[dynamic_neighbors]]` record edit; sessions accepted under the old group
  cannot be live-reassigned).
- [x] **Config transaction commit-confirmed core.**
  `ApplyConfigTransaction` can now enter a singleton pending-confirm state with
  `confirm_id` and a bounded confirm timer. Confirm makes the change permanent;
  abort or timer expiry rolls back by applying the captured pre-commit runtime
  snapshot through the same transaction executor. Persisted runtime config
  mutators are fenced while a confirmed transaction is applying or pending.
- [x] **`rbgp` commit-confirmed workflow.**
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
- [ ] **CI gate: `#[allow(clippy::*)]` / `#[expect(clippy::*)]` requires
  `reason = "..."`.** The ratchet exists and CI enforces it for
  `crates/rib/src`, whose suppressions are backfilled. Remaining work:
  add more paths to `scripts/check-clippy-reasons.py` as each crate/file
  group is backfilled; do not flip this to complete until the whole
  workspace is covered.
- [x] **`cargo deny` for license / dependency / advisory audit.** Done: the
  dependabot + cargo-audit half of the stale branch had already landed;
  `deny.toml` now gates `cargo deny check advisories bans licenses sources`
  (permissive-license allowlist, path-wildcard exemption for the deliberately
  unversioned `rustbgpd-wire` path dep, duplicate-version warnings kept
  visible but non-blocking) and runs as a second job in
  `.github/workflows/audit.yml` alongside `cargo audit`. The two ignore lists
  deliberately differ: cargo-deny warns (not fails) on unsound-class
  advisories, so only the unmaintained `paste` entry needs a deny.toml
  ignore while `.cargo/audit.toml` also carries the rand unsoundness entry.
- [ ] **`netlink-packet-route` 0.31 upgrade — proven ready, blocked on rtnetlink
  lockstep.** 0.31.0's two breaking changes (`InfoIpTunnel::CollectMetadata`,
  `InfoVxlan::Df`) don't affect us — rustbgpd compiles clean against 0.31 with no
  source changes. The blocker is upstream: `rtnetlink` (latest crates.io 0.21.0)
  pins `netlink-packet-route ^0.30`, and our code feeds `netlink_packet_route`
  types straight into `rtnetlink::Handle`, so a lone bump produces a
  duplicate-version tree and ~31 type-mismatch errors. **Readiness is proven** —
  draft PR #538 validates the upgrade against a git-pinned upstream `rtnetlink`
  revision already on 0.31: workspace check/clippy/test/doc, the privileged netns
  selectors, and M42/M50/M58/M70 containerlab receipts all green. To stop the
  un-mergeable nag, Dependabot now **ignores `netlink-packet-route` `>= 0.31`**
  (0.30.x security patches still flow). **Revisit when `rtnetlink` 0.22+ lands on
  crates.io with 0.31 support**: drop the Dependabot ignore + the
  `[patch.crates-io]` pin, bump the pair together in one PR, rerun the #538 matrix
  (raw `IFLA_PROTINFO` AC-gate encode + `link_carrier` flag reads are the surfaces
  to re-verify), and merge. #452 stays the upstream-watch tracker. Verified during
  the FIB route-drift eventing work (#482). **Upstream nudge filed 2026-06-23:**
  rust-netlink/rtnetlink#173 — a "New release 0.22.0" version-bump + CHANGELOG PR
  against their `main` (which already carries the 0.31 dep) — requests the release
  that unblocks this; execute the close-out above if/when any `rtnetlink` 0.22+
  publishes.
- [ ] **Workspace `cargo doc` warning posture.** CI runs
  `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --lib --no-deps`; keep that
  as the standing local pre-flight expectation so broken intra-doc links surface
  on the developer machine rather than at PR time. `--lib` keeps the root
  daemon bin out of the doc target set (avoiding the lib/bin same-name collision);
  Cargo's default job parallelism is intentionally left enabled so rustdoc does
  not serialize the whole workspace.
- [ ] **Mega-module splits.** The large `src/` modules have been split, and
  `crates/rib/src/manager/distribution.rs` (which had absorbed the BGP-LS/VPN/
  RTC/ORR arcs) is now a directory module with per-family concern submodules.
  `crates/rib/src/manager/tests.rs` (the largest file in the repo) is now
  `manager/tests/` — shared fixtures in `mod.rs` plus per-concern sibling test
  modules. `crates/api/src/event_service.rs` remains borderline. Keep splitting
  only where it reduces real conflict or review cost.
- [ ] **Doc-precision + lint-policy consistency sweep (v0.41.0 review).** A
  whole-codebase review found no correctness or security defects; the actionable
  residue is documentation/policy drift, all low-risk:
  - ARCHITECTURE.md design-invariant #3 understates the intentional
    unbounded-channel set — it names only the collision-notification channel, but
    `bfd_runtime` (state-change fan-out), `peer_manager` (internal + session-notify),
    `main` / `reload.rs` (config + internal-command coordinator), and
    `transport::session::writer` (priority) all carry justified unbounded channels.
    Re-enumerate the intentional set so the invariant stays a usable review gate.
  - ARCHITECTURE.md ownership table: note that the EVPN originator subsystem
    (`evpn_originator`, `evpn_l3_originator`) uses `Arc<RwLock>` generation counters
    by design — the "no shared mutable routing state" invariant is narrowly about
    the RIB hot path, not lower-frequency kernel-observation daemon glue.
  - `#![deny(unsafe_code)]` is missing on `crates/event-history` (lib) and
    `crates/cli` (bin) although CONTRIBUTING.md says "every crate"; both are
    unsafe-free today — add for consistency + future-proofing.
  - SECURITY.md "No unsafe code. Every crate enforces `#![deny(unsafe_code)]`"
    overstates: `crates/transport` carries a scoped `#[allow(unsafe_code)]` on
    `socket_opts` (TCP_MD5SIG / IP_MINTTL / TCP-AO FFI — the only unsafe in the
    tree). Reword to acknowledge the documented exception.
  - Optional periodic hygiene: trim the `thiserror` 1.x duplicate (1.0.69 + 2.0.18
    both resolved) at the next dependency refresh.
- [x] **Retire `rustbgpctl` in favor of `rbgp` (single CLI name).** The CLI
  crate now ships only the `rbgp` binary. The old `include!` alias/shim and
  long-form binary are removed; supported docs, package artifacts, generated
  completions, first-party scripts, and tests use `rbgp`.

---

## Non-goals / scope

rustbgpd is an API-first BGP daemon. The following are explicitly out of scope:

- **Full routing suite.** No OSPF, IS-IS, LDP, RSVP-TE, PIM, or MPLS dataplane
  control plane. This is a BGP daemon. BGP-carried MPLS/VPN families
  (labeled-unicast, VPNv4/v6, EVPN MPLS encapsulation) are demand-shaped
  address-family breadth, not a commitment to become a full MPLS router.
- **Lossless-fabric / RDMA transport tuning.** No RoCEv2 lossless-Ethernet
  configuration (PFC, ECN, DCQCN) and no RDMA transport protocols (e.g. NVIDIA
  Spectrum-X "Multipath Reliable Connection" / MRC) — these are NIC and
  switch-ASIC dataplane concerns, not a routing daemon's job. rustbgpd's role in
  an AI / RoCE fabric is the control plane it already provides: a BGP L3-ECMP
  underlay (including IPv6 link-local / unnumbered peering, ADR-0069) plus the
  EVPN/VXLAN overlay.
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
  kernel-dataplane smokes now run in the hosted `kernel-dataplane` workflow for
  the EVPN VTEP / IRB / adoption / multihoming / VLAN / overlay-index receipts
  plus the FIB, BFD, TCP-AO, BGP-unnumbered, and BLACKHOLE kernel receipts; see
  `INTEROP.md` for the current M36-M72 span. Large-scale churn (M33) is a
  manual soak harness under `tests/soak/`.
- **[docs/OPERATIONAL_PROOF.md](docs/OPERATIONAL_PROOF.md)** — the consolidated
  operator-facing receipt index for CI interop, hosted dataplane, benchmarks,
  high-N memory profiles, and archived 24 h soaks.
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
