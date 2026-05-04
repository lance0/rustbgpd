# rustbgpd Roadmap

## Market Context

The BGP daemon space is dominated by monolithic C implementations that
bundle BGP with OSPF, IS-IS, and every other routing protocol:

| Project | Language | Model | Strengths | Gaps |
|---------|----------|-------|-----------|------|
| FRR | C | Full routing suite | Feature-complete, wide adoption | Monolith, CLI-first, limited API |
| BIRD | C | Full routing suite | Excellent filter language, lightweight | CLI-first, no native gRPC |
| OpenBGPD | C | BGP-only | Clean design, OpenBSD pedigree | Limited platform support, no API |
| GoBGP | Go | BGP-only, gRPC API | API-first, good ergonomics | GC pauses at scale, Go-specific protos |

**Why rustbgpd exists:**

- **GoBGP proved the model.** API-first BGP with gRPC works. Operators
  want programmable routing, not CLI scripting. But GoBGP carries Go's
  GC overhead and its protos are Go-flavored.
- **No Rust BGP daemon exists for production use.** Memory safety,
  zero-cost abstractions, and no GC make Rust ideal for a control plane
  that must be reliable and predictable under load.
- **The codec is independently valuable.** `rustbgpd-wire` as a
  standalone, fuzzed BGP codec library fills a gap in the Rust ecosystem.
  Anyone building BGP tooling in Rust (monitors, analyzers, test harnesses)
  can use it without pulling in a full daemon.
- **Observability is an afterthought in existing daemons.** Prometheus
  metrics, structured JSON logs, and machine-parseable errors from day
  one — not bolted on later.

**Target users:** Network automation teams, IX operators, anyone who
currently drives GoBGP via gRPC and wants memory safety and predictable
performance. Not a replacement for FRR/BIRD in full routing suite roles.

---

## Completed

- [x] MP-BGP (IPv6 unicast) — RFC 4760: `MP_REACH_NLRI` / `MP_UNREACH_NLRI` decode/encode, `Ipv6Prefix` type, `Prefix` enum for AFI-agnostic RIB, AFI/SAFI capability negotiation, dual-stack route exchange, IPv6 route injection via gRPC, FRR dual-stack interop validated
- [x] BGP wire codec — OPEN, UPDATE, NOTIFICATION, KEEPALIVE, NLRI, path attributes, communities, RFC-compliant flag validation, fuzz harness
- [x] RFC 4271 state machine — all 6 states, full transition table, OPEN negotiation, property tests
- [x] Tokio transport — single task per peer, inbound listener, TCP MD5/GTSM, session counters, NLRI batching, TCP collision detection (RFC 4271 §6.8)
- [x] RIB — Adj-RIB-In, Loc-RIB best-path (RFC 4271 §9.1.2 with eBGP preference), Adj-RIB-Out with split horizon, dirty peer resync, route injection, WatchRoutes streaming
- [x] Policy — prefix lists with ge/le matching (IPv4 + IPv6), per-peer import/export, global fallback
- [x] gRPC API — 8 services: Global, Neighbor, Policy, PeerGroup, RIB, Injection, Control, Evpn (all IPv6-capable)
- [x] Dynamic peer management — add, delete, enable, disable neighbors at runtime (IPv4 + IPv6)
- [x] Observability — Prometheus metrics at all RIB mutation points, structured JSON logging
- [x] Operations — coordinated shutdown (ctrl-c + gRPC), gRPC server supervision, metrics server hardening
- [x] Interop validated — FRR 10.3.1 (17/17 IPv4 + 6 dual-stack automated tests), BIRD 2.0.12
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
- [x] 1245 tests — unit, integration, property, fuzz

For detailed milestone build orders, see [docs/milestones.md](docs/milestones.md).

---

## Planned Features

*Ordered by market impact and what unlocks production adoption. Informed by
operator feedback, competitive analysis, and IX/SDN market research (March 2026).*

*For feature parity details, see [docs/gobgp-parity.md](docs/gobgp-parity.md)
and [docs/COMPARISON.md](docs/COMPARISON.md).*

### Release stance

**rustbgpd is staying in v0.x until real-world deployment feedback and a
gRPC security audit close.** Both are non-code gates (see Pre-1.0
Requirements below). The two requirements anchor v1.0; everything else
is production-ready today.

The release cadence is: ship operator-visible polish in v0.11+ / v0.12+
cuts as items below land. v1.0 itself is gated on external validation,
not feature completeness.

### Next Up — Pre-v1.0 Polish (v0.x cuts)

Operator-visible gaps that should land before v1.0. These are real
operator-hit items pulled from KNOWN_ISSUES and the Deferred Hardening
list below; the bullets here are the **active** track, the rest of
this document is reference / long-tail.

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
- [ ] **CI regression tracking for benchmarks** — automated runs of
  the criterion benchmarks with threshold-based alerts on PR. The
  benchmarks exist; the regression gate doesn't.
- [ ] **`rustbgpctl` policy / peer-group / neighbor-set commands** —
  the daemon-side `PolicyService` and `PeerGroupService` gRPC
  surfaces are complete, but the CLI only wraps NeighborService /
  RibService / InjectionService. Operators currently manage policy
  and peer-groups via TOML+SIGHUP (now hot-reloads as of v0.12.0)
  or raw `grpcurl`; neither is friendly. Three command
  classes to add:
    - **Read** — `rustbgpctl policy list/get`, `peer-group list/get`,
      `neighbor-set list/get` (wraps `List*` / `Get*` RPCs).
    - **Write** — `rustbgpctl policy set/delete`, `peer-group set/delete`,
      `neighbor-set set/delete`, plus `policy chain set-global-import/
      export/clear` (wraps `Set*` / `Delete*` / chain RPCs).
    - **Runtime-vs-file diff** — `rustbgpctl policy diff <candidate.toml>`
      compares the daemon's *runtime* state (which may have drifted
      from disk via gRPC mutations) against a candidate file. This is
      genuinely different from `rustbgpd --diff` (file-vs-file dry-run
      of SIGHUP) and pairs naturally with the SIGHUP reconcile work.
      May require a new gRPC RPC that returns the daemon's effective
      runtime config snapshot.
  Pure CLI / proto-wrapping work — no protocol changes. ~800–1500
  LOC across `crates/cli/src/commands/policy.rs` +
  `peer_group.rs` + clap wiring.
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
- [ ] **Tighten test failure-mode coverage.** All four hot-apply
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
- [ ] **RFC 8326 dynamic-peer GShut replay.** Static + collision-
  replaced sessions inherit `advertise_graceful_shutdown` from
  `ManagedPeer` on spawn. Dynamic peers auto-removed when their
  session goes Idle lose the entire `ManagedPeer` record; a fresh
  session at the same address starts with the toggle off. Either
  extend the dead-letter side table from ADR-0042 to track GShut
  state, or document the operator workaround (re-issue
  `rustbgpctl gshut`) as the supported path. ~30 LOC if we extend
  the side table.
- [x] **Resolve open `cargo audit` findings** (v0.13.2) —
  vulnerability cleared in v0.13.1; soundness warning accepted as
  unreachable in v0.13.2:
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
- [x] **EVPN VTEP foundation — declarative EVI/VNI domain model** (v0.13.0) — Gate 7a per `docs/evpn-enablement.md`. New `crates/evpn` exposes the runtime [`EvpnInstance`] / [`EvpnInstanceTable`] types; `[[evpn_instances]]` config block lands the operator-facing TOML surface (VNI, RD, RTs, local VTEP IP, optional bridge, `advertise_svi_mac`); read-only `EvpnService.ListEvpnInstances` + `rustbgpctl evpn instances` surface the resolved table. Wire crate gains `RouteDistinguisher::from_str`. Empty by default — RR-only deployments unchanged. Kernel reconciliation + Type 2/3 origination land in Gate 7b. ADR-0052.
- [x] **Tier-1 post-release cleanup bundle** (v0.13.1) — three small operational items: prometheus 0.13 → 0.14 (clears RUSTSEC-2024-0437; protobuf 3.x API migration in 4 internal/test files); M34 SIGHUP-policy interop test now reads rustbgpd's own `flapCount` + `uptimeSeconds` instead of FRR's `bgpTimerUpEstablishedEpoch` (cross-checked monotonicity catches handle replacement that flapCount alone would miss); EVPN MP_REACH IPv6 next-hop roundtrip + 32-byte rejection tests close the validate-side audit gap from v0.11.0.
- [x] **Tier-2 patch bundle** (v0.13.2) — four operational-debt fixes: dead-letter side table on `PeerManager` so dynamic peers don't lose `pending_refresh` / `pending_export_apply` across `BackToIdle` auto-removal; gRPC `ConfigEvent` → persister bridge no longer holds a stale snapshot across SIGHUP (replacement now routes through the bridge so subsequent gRPC mutations don't overwrite the persisted file with `stale_pre_reload + one_mutation`); `apply_reload_outcome` helper tightens post-reload sync ordering with named failure stages; `reload_config` runs on a dedicated tokio task so SIGINT/SIGTERM observation is no longer blocked by an in-flight reload. Stale RUSTSEC-2024-0437 ignore dropped from `.cargo/audit.toml`.
- [x] **RFC 8326 BGP Graceful Shutdown** (v0.13.3) — well-known `GRACEFUL_SHUTDOWN` community (`65535:0` / `0xFFFF_0000`) end-to-end. Wire constant in `crates/wire`, policy alias on match + set sides, opt-in `[global] honor_graceful_shutdown = true` knob that appends an implicit chain-tail rule (`match GRACEFUL_SHUTDOWN → set local_pref = 0`) to EBGP imports — running at the chain tail rather than head guarantees the demotion wins last-writer accumulation against operator policies that also set `LOCAL_PREF`. Initiator side: gRPC `NeighborService.SetGracefulShutdown` + `rustbgpctl gshut [--peer X] [--clear]` toggle. Desired state lives on `ManagedPeer` and replays into freshly spawned sessions on collision-replace / inbound-accept; new `RibUpdate::RefreshPeerOutbound` forces re-emission of `AdjRibOut` routes so the toggle is visible on the wire immediately. Typed `SetGshutError::PeerNotFound` / `Internal` distinguishes operator-typo from session/RIB failures at the gRPC layer. New `Route.local_pref_attr` proto field surfaces the explicit-vs-default `LOCAL_PREF` distinction. M35 interop validates both legs (FRR → rustbgpd inbound honor + rustbgpd → FRR outbound advertise + clear) end-to-end against FRR 10.3.1. ADR-0053. Confederation gating + cross-restart persistence + dynamic-peer replay tracked as follow-ups.

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
- [ ] **Add-Path explain support** — route explain currently operates on the single Loc-RIB best path only; for Add-Path peers, non-best candidates that are actually advertised are invisible to explain
- [ ] **FlowSpec NLRI length encoding >4095 bytes** — FlowSpec length prefix uses a 12-bit mask; rules exceeding 4095 bytes get a silently truncated length on the wire
- [x] **AS_PATH segment >255 ASN encoding** — long `AS_SEQUENCE`/`AS_SET` segments are now split into multiple wire segments during encode instead of silently truncating via `u8` wrap
- [x] **IPv6 next-hop policy rewrite completeness** — export policy `set_next_hop = "<ipv6>"` is covered end-to-end for MP_REACH exports and route explain; classic IPv4 `NEXT_HOP` handling remains unchanged
- [ ] **LOCAL_PREF/MED policy match implicit defaults** — `match_local_pref_ge/le` and `match_med_ge/le` currently return false when the attribute is absent; decide whether policy matching should use BGP implicit defaults (100 for `LOCAL_PREF`, 0 for `MED`) instead
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
- [x] **Native gRPC mTLS** (v0.11.0) — TCP listeners terminate TLS in-process via tonic + rustls/ring. See "Next Up — Pre-v1.0 Polish" entry above for the config surface and the partial-config rejection rule.
- [ ] **Finer-grained gRPC authorization** — per-service or per-RPC authorization beyond binary listener access
- [ ] **FSM stale timer event handling** — timer events (ConnectRetry/Hold/Keepalive) in states where the timer should already be stopped trigger FSM Error and session teardown instead of being silently ignored
- [x] **Validation snapshot delivery to transport sessions** — `match_rpki_validation` and `match_aspa_validation` now work in import policy. `ValidationSnapshot` (VRP + ASPA tables) delivered to transport sessions via `tokio::sync::watch` channel. Each session borrows the latest immutable snapshot and evaluates import policy against it. RIB-side revalidation remains the correctness backstop. Config rejection for import validation matches removed.
- [ ] **Convergent import validation on cache update** — import `match_rpki_validation` / `match_aspa_validation` is currently best-effort at ingress time; later VRP/ASPA cache updates do not re-run import policy or trigger route refresh for affected peers. Fix: on cache update, trigger `SoftResetIn` for peers whose resolved import policy uses validation-state matches. Infrastructure exists (route refresh, per-peer policy tracking). Not urgent — current semantics match FRR/BIRD behavior and are documented in KNOWN_ISSUES.

### P1 — Core Protocol Gaps

Features that close meaningful protocol gaps vs GoBGP.

- [x] **Extended Messages** (RFC 8654) — raise 4096-byte limit to 65535; capability code 6 (ADR-0032)
- [x] **Add-Path** (RFC 7911) — dual-stack receive + family-aware multi-path send (route server mode); composite RIB keying, multi-candidate best-path, rank-based path IDs (ADR-0033)
- [x] **RPKI validation** — RTR client (RFC 8210) for route origin validation; VRP table, best-path step 0.5, policy matching (ADR-0034)
- [x] **FlowSpec** (RFC 8955/8956) — IPv4 and IPv6 unicast FlowSpec (SAFI 133); all 13 component types, numeric/bitmask operators, FlowSpec actions via extended communities, gRPC injection/query (ADR-0035)

### P2 — High-Impact Parity Gaps

Features that close the most impactful gaps vs GoBGP for the target user base.
Each moves overall parity 3-5% while disproportionately improving real-world usability.

- [x] **Transparent route server mode** — `route_server_client` per neighbor: skip automatic local ASN prepend on eBGP re-advertisement for IX route-server clients, preserve original unicast NEXT_HOP, and apply the same transparent AS_PATH behavior to FlowSpec export (ADR-0039)
- [x] **GR restarting speaker** — minimal honest mode: static peers advertise `R=1` after coordinated restart via persisted marker file; `forwarding_preserved` remains false until FIB integration exists (ADR-0040)
- [x] **Policy chaining + named policies** — named TOML definitions, GoBGP-style chain evaluation (permit=continue, deny=stop), configurable default_action (ADR-0036)
- [x] **Peer groups + peer-aware policy matching** — reusable peer templates with runtime CRUD, neighbor-set matching, route-type matching, exact next-hop matching, and MED / `LOCAL_PREF` comparison in policy; persisted through TOML config snapshots
- [x] **Extended nexthop** (RFC 8950) — capability code 5, automatic dual-stack negotiation, IPv4 unicast over IPv6 next-hop via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` (ADR-0037)
- [x] **CLI tool** — `rustbgpctl` wrapping gRPC with human-readable and JSON output; covers all supported RPCs
- [x] **Admin shutdown communication** (RFC 8203) — human-readable reason text in Cease NOTIFICATION; threaded from gRPC DisableNeighbor through transport
- [x] **Enhanced Route Refresh** (RFC 7313) — BoRR/EoRR demarcation and inbound family replacement semantics for `SoftResetIn`
- [x] **EVPN Route Reflector — Phase 1** (RFC 7432) — L2VPN/EVPN (AFI 25 / SAFI 70) RR role for VXLAN-EVPN DC fabrics. All 5 RFC 7432 route types (EAD per-ES, EAD per-EVI, MAC/IP, IMET, Ethernet Segment, IP Prefix per RFC 9136), MAC mobility best-path per §15.1 with sticky-flag preservation, RFC 4456 reflection applied to EVPN routes, 6 typed extended-community accessors (BGP Encapsulation for VXLAN per RFC 8365/9012, MAC Mobility, ESI Label, ES-Import RT, Router MAC per RFC 9135, Default Gateway). `ListEvpnRoutes` gRPC RPC + `rustbgpctl evpn` CLI. Gates 0-6 closed on `feat/evpn-rr`: capability sanity (M29), real Type 2 MAC reflection with kernel VXLAN (M30), GR/LLGR stale handling, MAC mobility / sticky preservation interop (M31), multi-homing Type 1 EAD-per-EVI + Type 4 ES reflection (M32 — FRR ES on a bond interface), 50k-route scale validation with churn (M33), and controller-driven injection via `AddEvpnRoute` / `DeleteEvpnRoute` gRPC. Includes review correctness fixes: source-peer split horizon, same-peer attribute-change detection, full RFC 4456 tie-break chain (stale → ORIGIN → CLUSTER_LIST → ORIGINATOR_ID), max-prefix counting EVPN keys + FlowSpec rules, EVPN withdrawals propagated through both AS_PATH and CLUSTER_LIST loop branches, EVPN initial dump for late-joining peers, EVPN ERR refresh tracking, Type 5 prefix in policy context, proto3 default-correct `disable_vxlan_encap` field. See ADR-0050 and [docs/evpn-enablement.md](docs/evpn-enablement.md) for the Gate 0-9 ladder.
- [ ] **EVPN Phase 2 — VTEP mode** — local EVI/VRF/VNI state, MAC learning from kernel FDB, local route origination. Required for general-purpose routing; not required for RR-only deployments. Blocked by need for kernel integration design.
- [ ] **EVPN Phase 3 — Multi-homing execution + IRB** — DF election (RFC 7432 §8 + RFC 8584), symmetric IRB semantics (RFC 9135), auto-derived Route Targets (RFC 8365 §5.1.2.1), aliasing / backup-path via Type 1 EAD. Needed for active-active ToR deployments. (Phase 1 already validates that the RR reflects multi-homing Type 1 EAD-per-EVI + Type 4 ES routes correctly so VTEPs can run DF election independently; Phase 3 is rustbgpd-as-VTEP execution.)
- [ ] **EVPN Phase 4 — Adjacent standards** — PBB-EVPN (RFC 7623), EVPN-MVPN integration (RFC 9251, Route Types 6/7/8), MPLS encapsulation, Add-Path for EVPN (RFC 9252). Service-provider EVPN use cases.
- [ ] **EVPN polish + observability gaps** (low-priority, Phase 1 known limitations):
  - [x] Type 5 (IP Prefix) interop test against FRR (M30b, `tests/interop/m30b-evpn-type5-frr.clab.yml`) — single-VTEP origination from FRR vrf1 / L3VNI 100; rustbgpd RR decodes the Type 5 NLRI and surfaces RD, prefix, next-hop, VNI label, RT extended community, and VXLAN encap via `ListEvpnRoutes`. Withdrawal validated. RR-reflection of Type 5 (2-VTEP topology, ORIGINATOR_ID + CLUSTER_LIST asserts) tracked as M30c.
  - [x] **`match_evpn_route_type` policy clause** (v0.11.0) — `match_evpn_route_type: u8` on `PolicyStatement` filters EVPN by RFC 7432/§9136 route type (1-5; non-EVPN never matches). Wired through TOML config, gRPC `PolicyStatement` (proto field 24), and the EVPN evaluation sites in `crates/transport/src/session/inbound.rs` + `crates/rib/src/manager/distribution.rs::stage_evpn_routes`.
  - [x] **EVPN BMP export and MRT dump integration** (v0.11.0) — BMP `RouteMonitoring` already flows for EVPN at the raw-PDU emit site (no AFI/SAFI gate; pinned by `inbound_evpn_update_emits_bmp_route_monitoring` regression test). MRT `TABLE_DUMP_V2` now emits `RIB_GENERIC` (subtype 6, RFC 6396 §4.3.5) records with AFI 25 / SAFI 70 for every Adj-RIB-In EVPN route. Type 2 + Type 5 round-trip tests assert the wire shape. ADR-0044 carries the encoding choice.
  - GR / LLGR interop harness (kill / restart / measure) — unit tests cover the EVPN GR pipeline; FRR-vs-rustbgpd kill-and-recover interop is not in the M29-M33 set.
  - [x] **M33 soak harness** — `tests/soak/run-m33-soak.sh` extends M33 to arbitrary durations (default 24h, `SOAK_SEC` override for sub-hour smokes), samples cgroup RSS + Prometheus gauges every minute into `samples.csv`, and runs a stdlib-only Python analyzer that gates on memory slope, peak RSS, session flaps, drop deltas, gRPC health continuity, and process-restart detection (counter monotonicity). The first runs surfaced ADR-0051 — see "Sustained-churn writer-task split" below — and `tests/soak/runs/20260427T172938Z/` is the post-fix reproducer of record (drops 613→1, slope 58.5→12.6 MB/h, GetHealth always responsive). Still open: a 24h soak with the writer-split build to confirm the +49-min wedge transition is the only saturation event under continuous load.
  - [x] **`EvpnRibRoute` payload + key redundancy** — landed post-v0.10.0. The cached `EvpnRouteKey` field was removed from `EvpnRibRoute`; identity is now derived on demand via `EvpnRibRoute::key()` (one-line wrapper around `EvpnRoute::key()`, which is O(1) and allocation-free). Adding RFC 9251 Route Types 6-8 will only need new arms in `EvpnRoute::key()` rather than parallel synchronization at every construction site.
  - **CI wiring for M29-M33** — interop scripts running cleanly on a developer box but tied into the GitHub Actions matrix. **M29 + M30 done** — `.github/workflows/interop.yml` runs the EVPN cap-negotiation gate (M29) and the Type 2 MAC-reflection gate with kernel VXLAN + bridge (M30) against FRR 10.3.1 on every push and PR. M30 was unblocked by replacing `start_rustbgpd`'s 3 s fixed sleep with a 10 s poll + diagnostic dump on failure (the original probe failed under heavy CI load before the daemon registered in `/proc`). **M30b blocked on hosted runners** — the Azure-tuned kernel on ubuntu-latest (6.17.0-1010-azure) ships without the `vrf` module, so `ip link add ... type vrf` fails inside the FRR container and FRR cannot bind the L3VNI to originate Type 5; verified empirically via a throwaway probe workflow. M31 (MAC mobility with 3 VTEPs), M32 (multi-homing on a bond ES), and M33 (50k-route scale + churn) stay manual until we have a self-hosted runner with the wall-time budget for them. Net effect: M29 + M30 are gated on hosted runners; M30b/M31/M32/M33 stay manual unless we add a self-hosted runner or hosted runners regain `vrf`.

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
- [x] ~~**Built-in looking glass**~~ — replaced by birdwatcher-compatible REST API in "Next Up" section. Market research shows IXPs use external presentation layers (Alice-LG, IXP Manager); a built-in web UI is not a differentiator.
- [ ] **Config snippets / examples in error messages** — when a gRPC call fails validation, include a working example in the error detail: "invalid families value; try: `families: [\"ipv4_unicast\", \"ipv6_unicast\"]`"
- [x] **Neighbor auto-discovery logging** — when an unknown peer connects, the warning includes a suggested `rustbgpctl neighbor <addr> add --asn <ASN>` command to help operators bootstrap new peers.

Deferred explain follow-ups (after best-path explain ships from "Next Up"):
- [ ] **Named policy / statement attribution in explain** — include exact policy and statement identity in explain output
- [ ] **Import explain** — dry-run import policy, RPKI, and inbound acceptance for one received route
- [ ] **Verbose policy trace** — include non-match steps and full decision trace instead of only decisive reasons
- [ ] **Route history / why-changed timeline** — retain explain history across best-path and policy changes
- [ ] **Looking glass integration for explain** — expose explain output via the future read-only HTTP/JSON looking glass

### P3.5 — Scale & Hardening

Prove it works under pressure before 1.0.

- [x] **RIB scale benchmarks** — criterion benchmarks for AdjRibIn insert (10k–500k), best-path comparison, LocRib recompute, full pipeline, route churn
- [x] **Wire codec benchmarks** — criterion benchmarks for NLRI encode/decode, UPDATE build/parse, path attribute codec, validation
- [ ] **Churn benchmarks** — route flap throughput, reconvergence latency under UPDATE storms
- [ ] **CI regression tracking** — automated benchmark runs with threshold-based alerts
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
- [ ] **TCP-AO authentication** (RFC 5925) — modern replacement for TCP MD5; BIRD 3 just added it (April 2025); neither GoBGP nor rustbgpd has it
- [ ] **Real-time BGP observability** — unified event bus (`broadcast::Sender<BgpEvent>`) streaming route_learned, route_withdrawn, best_path_changed, policy_filtered, session_state_change events; in-memory ring buffer for recent event history; gRPC `EventService` with `WatchEvents` streaming RPC and peer/prefix/type filtering; `rustbgpctl events` CLI with `--since`, `--peer`, `--prefix`, `--type` flags; foundation for TUI live event view
- [ ] **Route history** — per-prefix timeline of routing events (learned, withdrawn, best-path changes) queryable via gRPC and `rustbgpctl history <prefix>`; backed by ring buffer with configurable depth
- [ ] **Route dampening** (RFC 2439) — suppress flapping routes with penalty/decay
- [ ] **Scriptable policy engine** — user-defined attribute transformation functions (Lua, Starlark, or WASM plugins) beyond static match/action rules. Policy evaluation is already a pure function `(route, context) -> (action, modifications)` — sandboxing a scripting layer there would be clean. More expressive than FRR's route-maps, simpler than BIRD's filter DSL.
- [ ] **Evaluate buffa for protobuf codegen** — Anthropic's [buffa](https://github.com/anthropics/buffa) is a pure-Rust protobuf implementation with editions-first design, zero-copy views, and `no_std` support. Benchmark against prost/tonic for gRPC message encode/decode performance; evaluate generated type ergonomics (e.g. `MessageField<T>` vs prost `Option<T>`, `EnumValue<T>` vs raw `i32`). Requires tonic integration story (buffa has no gRPC transport layer — would need a tonic codec adapter or wait for upstream support).

### Deprioritized

Features that market research indicates are lower value than originally planned.

- **YANG model / NETCONF** — FRR can't finish their BGP YANG model; gRPC is the modern interface; low ROI
- **Built-in web UI** — IXPs use Alice-LG / IXP Manager; replaced by API-first looking glass approach
- **Kubernetes operator** — adjacent opportunity but premature; nail the IX/SDN use case first

### Interop Test Coverage

27 automated interop scripts cover M1, M3, M4, M10–M33 against FRR 10.3.1,
BIRD 2.0.12, GoBGP 4.3.0, and StayRTR. M0 (FRR, BIRD) are manual smoke
tests.

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

## Pre-1.0 Requirements

Quality gates before tagging 1.0.0. **The two open items below anchor the
v1.0 cut**; everything else is shipped. Code-side polish continues in v0.x
releases (see "Next Up — Pre-v1.0 Polish" above).

- [x] MP-BGP (at least IPv6 unicast)
- [x] Graceful restart
- [x] Extended communities
- [x] Policy actions (match + modify + filter)
- [x] Large communities (RFC 8092)
- [x] ASPA verification — upstream verification with RTR v2 (ADR-0049)
- [ ] **Real-world deployment feedback** *(v1.0 gate)* — at least one
  operator running rustbgpd in a production-shaped environment long
  enough to surface bugs the soak harness can't. The 12 h soak verdict
  + interop coverage establish the production *claim*; this gate
  validates it.
- [x] Wire crate API stability (`rustbgpd-wire` published on crates.io)
- [x] Comprehensive rustdoc for public API (hand-written crates; generated proto stubs excluded)
- [ ] **Security audit of gRPC surface** *(v1.0 gate)* — independent
  review of the gRPC API surface, listener configuration (mTLS pending,
  see Next Up), and authorization model. Native gRPC mTLS lands in v0.x
  before the audit so the audit isn't blocked on a known-missing
  primitive.
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
- [x] Containerlab interop topologies (FRR 10.3.1, BIRD 2.0.12)
- [x] Automated interop test scripts (M1, M3, M4, M10–M33)
- [x] Binary releases (GitHub Releases with cross-compiled linux-amd64/arm64 binaries)
- [ ] Homebrew formula
- [x] crates.io publishing (`rustbgpd-wire` published; other crates remain internal)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style,
and PR process. Issues labeled `good first issue` are good entry points.
