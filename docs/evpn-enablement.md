# EVPN Enablement Roadmap

Last updated: 2026-05-07

Gate-by-gate plan for turning rustbgpd's Phase 1 EVPN Route Reflector into a
production-ready control plane and, eventually, a VTEP-capable daemon.

Each gate below unlocks a concrete capability claim — the thing you can point
an engineer at and say "yes, that works today". Priority is driven by what
**blocks a production deployment** of the RR role in a VXLAN-EVPN DC fabric
(SONiC/FRR leaves, rustbgpd on spine or dedicated RR appliance), not by
implementation fan-out.

See also: [ADR-0050](adr/0050-evpn-route-reflector.md) for the architectural
record, [gobgp-parity.md](gobgp-parity.md) for the cross-daemon comparison.

## TL;DR

- **Gates 0, 1, 2, 3, 4, 5, 6**: done on `feat/evpn-rr`. Capability,
  Type 2 reflection (M30), EVPN GR/LLGR, MAC mobility / sticky
  (M31), multi-homing Type 1 EAD-per-EVI + Type 4 ES reflection
  (M32 — FRR ES on a bond interface; see Gate 4), 50k-route
  scale validation with
  churn (M33), and controller-driven injection via gRPC
  (`AddEvpnRoute` / `DeleteEvpnRoute`). Gates 0-4
  validated against FRR 10.3.1; Gate 5 uses an in-tree iBGP load
  generator (the `bench/evpn-load` crate) so rustbgpd's scale is
  what gets exercised, not a third-party daemon's. The
  "production-ready RR at 10k+ MAC scale, SDN-integratable" bundle
  is now complete.
- **Gate 7a** (declarative EVI/VNI domain), **Gate 7b** (downward
  FDB program reconciler), and **Gate 7b+1** (upward Type 2
  origination from kernel local-MAC observations + Type 3 IMET per
  L2VNI + RTNLGRP_NEIGH subscription) have shipped in v0.13.0,
  v0.14.0, and v0.15.0. Together they close the bidirectional
  single-homed L2VNI VTEP alpha loop.
- **Gates 8-9** expand into active-active multi-homing execution /
  IRB. Big investments gated by market demand, not technical
  readiness.

## Current Position

Phase 1 RR role — control-plane only, all 5 RFC 7432 route types, MAC Mobility
best-path (validated against real FRR), RFC 4456 reflection, VXLAN encap
community (RFC 8365), gRPC + CLI. Real-peer interop via M29 (capability),
M30 (Type 2 reflection), and M31 (MAC mobility / sticky). EVPN GR/LLGR
stale handling shipped. Peer-down and dirty-resync correctness gaps
closed.

**Honest completeness estimates:**

| Scope | Completeness |
|-------|-------------|
| RFC 7432 RR role | ~90-92% |
| Production-ready RR for a SONiC/FRR fabric | ~95-97% |
| Full RFC 7432 daemon (RR + VTEP + multi-homing + IRB) | ~32-36% |

## Gate Ladder

### Gate 0 — Capability negotiation and control-plane integration ✅

Status: **done** (feat/evpn-rr, 2026-04-23)

Unlocks:
- L2VPN/EVPN capability negotiated with real FRR
- gRPC `ListEvpnRoutes` returns a well-formed response
- Control-plane plumbing compiles and doesn't crash on an EVPN session

Evidence: M29 interop test, 1201 workspace tests passing, 30 EVPN-specific
unit tests (wire codec round-trip + MAC mobility tiebreak + peer-down
regression + dirty-resync regression).

Does **not** yet prove: any route actually flows end-to-end through the
RR onto the wire and back into a peer's EVPN RIB.

---

### Gate 1 — Real Type 2 MAC reflection end-to-end ✅

Status: **done** (feat/evpn-rr, M30 harness, 2026-04-24)

Unlocks: the minimum credible "this actually works" claim. Two FRR VTEPs
with kernel VXLAN interfaces + bridge domain; rustbgpd between them as RR;
MAC learned on VTEP-A appears on VTEP-B's `show evpn mac vni N`.

Delivered:

| Task | File / location |
|------|----------------|
| 3-node containerlab topology (rustbgpd RR + 2 VTEPs) | `tests/interop/m30-evpn-type2-frr.clab.yml` |
| Kernel VXLAN + bridge config per VTEP | `tests/interop/configs/frr-bgpd-m30-vtep-{a,b}.conf` |
| FRR VTEP startup shim (`ip link add vxlan`, bridge attach, nolearning) | `tests/interop/scripts/start-frr-vtep.sh` |
| rustbgpd RR config (cluster-id, both VTEPs as RR clients) | `tests/interop/configs/rustbgpd-m30-rr.toml` |
| Test script (7 assertions) | `tests/interop/scripts/test-m30-evpn-type2-frr.sh` |

Validated: next-hop preservation (VTEP loopback, not RR's address), VNI
propagation in the Type 2 label field (or `tunnel_type = 8` via BGP
Encap ext community), RFC 4456 `ORIGINATOR_ID` + `CLUSTER_LIST` on the
reflected UPDATE, attribute pass-through without mutation, clean
withdrawal propagation. MAC injection via `bridge fdb add` → netlink →
FRR zebra → Type 2 origination; data-plane VXLAN packets do not need
to traverse the fabric for this test.

No rustbgpd code changes were needed — the harness exercises the Gate 0
control plane against a real FRR 10.3.1 peer.

---

### Gate 2 — EVPN GR/LLGR stale handling ✅

Status: **done** (feat/evpn-rr, 2026-04-23)

Unlocks: VTEP restart without total EVPN route flap in the rest of the
fabric. Reflected EVPN routes get marked stale during the restart window,
swept on EoR, promoted to LLGR-stale after GR timeout per RFC 9494.

Delivered:

| Task | File / location |
|------|----------------|
| `iter_evpn_mut()` on `AdjRibIn` | `crates/rib/src/adj_rib_in.rs` |
| `mark_stale_evpn`, `clear_stale_evpn`, `sweep_stale_evpn`, `sweep_stale_family_evpn`, `promote_to_llgr_stale_evpn`, `sweep_llgr_stale_evpn`, `clear_llgr_stale_evpn` | `crates/rib/src/adj_rib_in.rs` |
| `evpn_llgr_stale_local_tags: HashSet<EvpnRouteKey>` field | `crates/rib/src/adj_rib_in.rs` |
| `clear_local_llgr_stale_evpn_community` helper using `Arc::make_mut` | `crates/rib/src/adj_rib_in.rs` |
| GR entry, LLGR promotion, non-LLGR sweep, and LLGR timer sweep wired | `crates/rib/src/manager/graceful_restart.rs` |
| EVPN `clear_stale` on EoR (GR + LLGR paths) | `crates/rib/src/manager/route_refresh.rs` |
| `refresh_stale_evpn` tracking for enhanced route refresh; EVPN BoRR/EoRR emission | `crates/rib/src/manager/route_refresh.rs` + `mod.rs` |
| `LocRib::recompute_evpn` fix: detect `is_stale` / `is_llgr_stale` flips so single-peer stale transitions propagate into Loc-RIB | `crates/rib/src/loc_rib.rs` |
| 6 AdjRibIn stale unit tests + 7 RibManager GR/LLGR regression tests | `crates/rib/src/adj_rib_in.rs`, `crates/rib/src/manager/tests.rs` |

Evidence: +13 tests, 1214 workspace total; clippy clean on Rust 1.95.

---

### Gate 3 — MAC mobility end-to-end interop ✅

Status: **done** (feat/evpn-rr, M31 harness, 2026-04-24)

Unlocks: VM / container migration claim. 4-node topology (rustbgpd RR
+ 3 VTEPs) exercising the RFC 7432 §15.1 MAC Mobility semantics
against real FRR 10.3.1.

Delivered:

| Task | File / location |
|------|----------------|
| 4-node topology (RR + 3 VTEPs) | `tests/interop/m31-evpn-mac-mobility-frr.clab.yml` |
| Per-VTEP FRR configs (a, b, c) | `tests/interop/configs/frr-bgpd-m31-vtep-{a,b,c}.conf` |
| rustbgpd RR config with 3 RR clients | `tests/interop/configs/rustbgpd-m31-rr.toml` |
| MAC mobility + sticky test script (10 assertions across 3 phases) | `tests/interop/scripts/test-m31-evpn-mac-mobility-frr.sh` |

Validated:

- **Baseline**: all 3 VTEPs Established, VTEP-B sees Type 3 IMET from
  both A and C through the reflector.
- **Plain MAC reflection**: MAC injected on VTEP-A appears on VTEP-B
  with remote VTEP = VTEP-A.
- **Move**: `bridge fdb add` on VTEP-C + `bridge fdb del` on VTEP-A;
  VTEP-B's best path flips to VTEP-C within 30 s; MAC Mobility
  sequence number on the reflected Type 2 is strictly greater than
  pre-move.
- **Sticky preservation**: sticky MAC on VTEP-A (`bridge fdb add …
  sticky`) is not displaced by a non-sticky advertisement from
  VTEP-C, matching the unit-test semantics in `evpn_tiebreak_simple`.

Reuses the `start-frr-vtep.sh` shim from M30 — no new kernel setup
code. No rustbgpd code changes — the harness validates existing
behavior.

---

### Gate 4 — Multi-homing Type 1 EAD + Type 4 ES reflection ✅

Status: **done** (feat/evpn-rr, M32 harness, 2026-04-26)

Unlocks: active-active ToR fabric reflection. Two VTEPs share an ESI
on a bond ES interface; rustbgpd reflects both Type 1 EAD-per-EVI and
Type 4 ES routes unchanged with correct RFC 4456 attributes; third
VTEP observes the reflected inputs.

The ES is configured on an **LACP bond interface** with a single dummy
slave. FRR EVPN-MH only registers a local ES when the configured
interface is a bond — `show evpn es` is empty for plain dummy or
veth interfaces in FRR 10.3.1, regardless of `evpn mh es-id` /
`es-sys-mac` config. The bond + dummy-slave shape is the minimal
FRR-supported config that produces a local ES without requiring a
real LACP partner, and it triggers EAD-per-EVI origination once the
ES is bound to the EVI.

Delivered:

| Task | File / location |
|------|----------------|
| 4-node topology (RR + 3 VTEPs, 2 sharing an ESI) | `tests/interop/m32-evpn-multihome-frr.clab.yml` |
| Extended VTEP shim with bond ES access interface | `tests/interop/scripts/start-frr-vtep-mh.sh` |
| Per-VTEP FRR configs with `evpn mh es-id` + `es-sys-mac` | `tests/interop/configs/frr-bgpd-m32-vtep-{a,b,c}.conf` |
| rustbgpd RR config with 3 RR clients | `tests/interop/configs/rustbgpd-m32-rr.toml` |
| Test script (6 gated assertions) | `tests/interop/scripts/test-m32-evpn-multihome-frr.sh` |

Gated assertions:

- **Type 4 ES reflection**: VTEP-B receives both VTEP-A's and VTEP-C's
  Type 4 ES routes for the shared ESI.
- **Type 1 EAD-per-EVI reflection**: VTEP-B receives both peers' EAD
  routes for the shared ESI.
- **RFC 4456 attribute pass-through**: ORIGINATOR_ID and CLUSTER_LIST
  correctly set on each reflected ES route.
- **gRPC surface**: `ListEvpnRoutes` shows ≥ 2 Type 4 ES routes and
  ≥ 2 Type 1 EAD routes (one of each per sharing VTEP).
- **DF election input completeness**: VTEP-B's `show evpn es` lists
  both VTEPs as members for the shared ESI.

Rustbgpd does NOT participate in DF election — it reflects the inputs
and the VTEPs run the election independently. This test validates
only the RR's obligation: do not mutate or drop ES / EAD routes.

Reuses the M30 VXLAN shim for all non-MH aspects. Caveat: the FRR
multi-homing config requires kernel features that may vary by host
— if MH routes don't appear in the test's expected output, verify
`evpn mh` is supported by the container's FRR build.

---

### Gate 5 — Scale validation ✅

Status: **done** (feat/evpn-rr, M33 harness, 2026-04-24)

Unlocks: the production-ready claim. 50k Type 2 routes (25k × 2
originating peers) flowed through the RR to a third observer with
60 s of 1000/sec churn layered on top. Assertions cover convergence
time, post-churn route-count fidelity, CPU health, and gRPC stability.

This is where the architectural claims (FlowSpec-pattern parallel
tables, `Arc<Vec<PathAttribute>>` intern, secondary indexing) got
validated for the new family.

Delivered:

| Task | File / location |
|------|----------------|
| `bench/evpn-load` — minimal iBGP peer library | `bench/evpn-load/src/lib.rs` |
| `evpn-tester` — bulk Type 2 generator w/ rate control + churn | `bench/evpn-load/src/bin/tester.rs` |
| `evpn-monitor` — observer emitting a convergence JSON report | `bench/evpn-load/src/bin/monitor.rs` |
| 3-peer containerlab topology (RR + 2 testers + monitor, p2p /30s) | `tests/interop/m33-evpn-scale.clab.yml` |
| rustbgpd RR config (3 RR clients, L2VPN/EVPN) | `tests/interop/configs/rustbgpd-m33-scale.toml` |
| Test script (5 assertions) | `tests/interop/scripts/test-m33-evpn-scale.sh` |
| Benchmarks section | `docs/BENCHMARKS.md` |

Validated (with M33 harness):

- **Bulk convergence**: 50,000 reflected Type 2 routes reached the
  observer under a 60 s ceiling (initial convergence ~5 s on the
  reference hardware).
- **Churn fidelity**: 60 s of 1000/sec withdraw+re-advertise leaves
  the post-churn count within ±tester batch (40) of 50,000, with at
  least ½·`CHURN_RATE`·`CHURN_DURATION` withdrawal events observed
  by the monitor — proving churn fired and the live set tracked it
  rather than riding flat at 50k due to dropped withdrawals. The
  ±batch tolerance absorbs the case where the live-set sample at
  observation end lands mid-cycle.
- **RR health**: gRPC `GetHealth` + `ListEvpnRoutes` stay responsive
  the entire run; the RR never flaps sessions.
- **Dogfooded wire crate**: the tester/monitor dogfood
  `rustbgpd-wire` directly — no third-party daemon is in the
  measurement path.

Notes on methodology:

- Both testers and the monitor run the same `rustbgpd:dev` image.
  Baking the load generator binaries alongside `rustbgpd` keeps the
  harness reproducible from one `docker build` + `containerlab deploy`.
- All routes share a single RD (`65000:1`), ethernet-tag `0`, VNI
  `100`. MAC addresses are deterministic (`02:00:00:XX:YY:ZZ` with
  the low 24 bits = the route index), so a specific harness run is
  exactly repeatable.
- ESI is zeroed in this harness — Gate 4 already validated the
  multi-homing attribute shape. Gate 5 isolates scale of the
  reflection pipeline.

---

### Gate 6 — Controller-injection gRPC ✅

Status: **done** (feat/evpn-rr, 2026-04-24)

Unlocks: SDN controllers / orchestration systems pushing EVPN routes
directly into the RR via `AddEvpnRoute` / `DeleteEvpnRoute` gRPC.
Phase 1 supports Type 2 (MAC/IP) and Type 3 (IMET); Type 5 IP-Prefix
and Type 1/4 multi-homing origination are deferred pending use-case
signal.

Delivered:

| Task | File / location |
|------|----------------|
| `InjectEvpn` / `WithdrawEvpn` `RibUpdate` variants | `crates/rib/src/update.rs` |
| `handle_inject_evpn` / `handle_withdraw_evpn` handlers | `crates/rib/src/manager/distribution.rs` |
| `RouteOrigin::Local` path for EVPN (mirrors FlowSpec) | `crates/api/src/injection_service.rs` |
| Proto: `AddEvpnRoute` / `DeleteEvpnRoute` RPCs | `proto/rustbgpd.proto` |
| `InjectionService` methods + RD / MAC / IP validation | `crates/api/src/injection_service.rs` |
| `rustbgpctl evpn add-mac-ip/add-imet/delete-*` subcommands | `crates/cli/src/commands/evpn.rs` |
| Unit + integration tests | `crates/rib/src/manager/tests.rs`, `crates/api/src/injection_service.rs` |

End-to-end flow:

1. Controller calls `AddEvpnRoute` (Type 2) via gRPC.
2. `InjectionService` parses RD, MAC, IP, label; synthesizes an
   `EvpnRibRoute` with `RouteOrigin::Local`; sends `RibUpdate::InjectEvpn`.
3. `handle_inject_evpn` places the route in the local Adj-RIB-In and
   recomputes/distributes — identical path to FlowSpec injection.
4. All iBGP peers negotiating L2VPN/EVPN receive the reflection.

Validation coverage:

- `inject_evpn_reflects_to_peer` — round-trip through the manager,
  including withdraw.
- `add_evpn_type2_reaches_rib_channel` — gRPC service parses the
  request and forwards an `InjectEvpn` with the expected key.
- `add_evpn_type2_rejects_zero_vni`, `add_evpn_rejects_unsupported_route_type`,
  `add_evpn_rejected_on_read_only_listener`.
- `parse_rd_type0_ibgp`, `parse_rd_type1_ipv4`, `parse_rd_type2_asn32`,
  `parse_rd_rejects_malformed`, `parse_mac_roundtrip`,
  `parse_mac_rejects_malformed`.

---

### Gate 7 — VTEP mode (Phase 2)

Status: Gates 7a / 7b / 7b+1 landed · Alpha-soak and post-Gate follow-ups remain · Blockers: Gates 1-6 (closed)

Unlocks: rustbgpd running on a leaf itself — local EVI/VRF/VNI config,
MAC learning from the kernel FDB (netlink monitor), local route
origination, local withdrawal on MAC aging.

Landed as **three slices** (see ADR-0052 / ADR-0054 / ADR-0055) so the
durable state model locked down before kernel reconciliation and
local-origination semantics landed on top of it:

#### Gate 7a — Foundation: declarative EVI/VNI domain model

Status: landed in v0.13.0

Unlocks the operator-facing surface and the typed runtime model that
later phases consume:

| Task | File / location | Status |
|------|----------------|--------|
| `crates/evpn` — `EvpnInstance`, `EvpnInstanceId`, `RouteTarget`, `EvpnInstanceTable` | new crate | landed (slice) |
| `RouteDistinguisher::from_str` | `crates/wire/src/evpn.rs` | landed (slice) |
| `[[evpn_instances]]` schema + parse + validation | `src/config/schema.rs` + `src/config/mod.rs` | landed (slice) |
| `EvpnService.ListEvpnInstances` (read-only gRPC) | `crates/api/src/evpn_service.rs` | landed (slice) |
| `rustbgpctl evpn instances` CLI | `crates/cli/src/commands/evpn.rs` | landed (slice) |
| Example TOML + ADR | `examples/evpn-vtep-leaf/`, `docs/adr/0052-...` | landed (slice) |

#### Gate 7b — Kernel reconciliation + origination

Status: bidirectional VTEP alpha — Gate 7b (foundation, downward FDB
program) shipped in v0.14.0; Gate 7b+1 (upward Type 2 / Type 3
origination + RTNLGRP_NEIGH subscription) merged in PR #35 on
2026-05-07 and shipped in v0.15.0 · Blockers: Gate 7a (closed)

Why gated on demand: SONiC/FRR leaves do this well today. Rustbgpd
competing with FRR for the VTEP role is a meaningful strategic expansion,
not a tactical feature. Only worth it if there's a specific use case
(pure-Rust leaf, better API story, etc.) that justifies the scope.

**Groundwork (landed):**

| Task | File / location | Status |
|------|----------------|--------|
| Daemon-level integration test booting with `[[evpn_instances]]` and round-tripping through `EvpnService.ListEvpnInstances` + `rustbgpctl evpn instances`. The tripwire that proves config → daemon → gRPC → CLI still works while internals get more dynamic. | `tests/evpn_instances_binary.rs` | landed |
| Dataplane-boundary ADR — what `crates/evpn-linux` consumes from `crates/evpn`, what it observes from the kernel, what it returns. Diff loop semantics (push / pull / reconcile-on-event). Failure surfacing back to the domain layer. | `docs/adr/0054-evpn-linux-dataplane-boundary.md` | landed |
| Runtime mutation surface for the startup-pinned `Arc<EvpnInstanceTable>` (`ArcSwap` or `RwLock`) — small refactor, but mutation *semantics* (delete behavior with active learned MACs, instance redefinition during MAC mobility, etc.) is the real work. | `crates/api/src/evpn_service.rs`, daemon wiring | deferred to alpha-soak / post-v0.15 |

**FDB reconciler (PR #34):**

| Task | File / location | Status |
|------|----------------|--------|
| `crates/evpn-linux` crate skeleton, `Dataplane` trait, `InMemoryDataplane` fake | `crates/evpn-linux/` | landed (PR #34) |
| Diff loop: desired `RemoteMacTable` + `KernelSnapshot` + `OwnedSet` → idempotent `DataplaneOp` plan | `crates/evpn-linux/src/diff.rs` | landed (PR #34) |
| Reconcile actor: per-op-fingerprint permanent-failure suppression, exponential backoff, 60 s periodic full dump, level-triggered re-reconcile | `crates/evpn-linux/src/reconcile.rs` | landed (PR #34) |
| Linux netlink backend: bridge/VXLAN link inventory + bridge FDB dump + `RTM_NEWNEIGH` program/withdraw with `NTF_SELF \| NTF_MASTER \| NTF_EXT_LEARNED` and `NUD_NOARP \| NUD_PERMANENT` (single-message wire shape, verified via strace on iproute2) | `crates/evpn-linux/src/linux/` | landed (PR #34) |
| Errno classification (EPERM/EACCES → `PermissionDenied`; EOPNOTSUPP → `KernelTooOld`; EINVAL → `InvalidArgument`) | `crates/evpn-linux/src/linux/fdb.rs` | landed (PR #34) |
| EVPN supervisor: project RIB EVPN routes → `RemoteMacTable`, publish `DataplaneIntent` only on semantic change (no per-poll generation churn) | `src/evpn_dataplane.rs` | landed (PR #34) |
| M36 containerlab smoke: rustbgpd-as-VTEP + FRR-as-originator (iBGP, AS 65000); verifies bridge-master row + VXLAN-self+dst row both carry `extern_learn`, foreign-static survives, withdraw cleans up. 8/8 PASS. | `tests/interop/scripts/test-m36-evpn-vtep-smoke.sh` | landed (PR #34) |
| Privileged netns dataplane test (gated on `EVPN_LINUX_NETNS=1`, runs nightly outside PR-CI) | `crates/evpn-linux/tests/netns_dataplane.rs` | landed (PR #34) |

**Origination loop (Gate 7b+1, v0.15.0):**

ADR-0055 locks the boundary; the implementation closes the upward
flow that Gate 7b's foundation left as a stub.

| Task | File / location | Status |
|------|----------------|--------|
| `LocalMacOriginator` state machine — pure RFC 7432 §15.1 sequencer with proptest-style monotonic-ratchet invariant | `crates/evpn/src/origination.rs` | landed |
| PMSI Tunnel path attribute (RFC 6514 §5, type 22) — decoder, encoder, `for_evpn_ingress_replication` constructor | `crates/wire/src/pmsi.rs` | landed |
| `EvpnOriginator` daemon actor — `tokio::select!` over local-MAC channel + RIB poll + shutdown-drain; emits `RibUpdate::InjectEvpn` / `WithdrawEvpn` | `src/evpn_originator.rs` | landed |
| Type 3 IMET origination per `EvpnInstance` — startup-inject + shutdown-withdraw helpers carrying PMSI Tunnel + RT extcomms | `src/evpn_imet.rs` | landed |
| Upward `LocalMacObservation` channel — `Dataplane::take_local_mac_rx` trait method + `InMemoryDataplane` test surface | `crates/evpn-linux/src/dataplane.rs`, `crates/evpn-linux/src/in_memory.rs` | landed |
| `RTNLGRP_NEIGH` subscription + classifier — `add_membership` on the rtnetlink socket, pure `classify_neigh` function with bridge-port → VNI lookup, drop on `NTF_EXT_LEARNED` echoes and VXLAN-port ifindexes | `crates/evpn-linux/src/linux/notify.rs` | landed |
| Daemon main wiring — spawn originator alongside the reconciler under the same `[[evpn_instances]]` gate; coordinated-shutdown drain order | `src/main.rs` | landed |
| ADR-0055 — Local-MAC origination boundary (sequence rules, channel surface, deferral list) | `docs/adr/0055-evpn-local-mac-origination.md` | landed |
| M37 containerlab smoke — rustbgpd-as-VTEP originating Type 2 + IMET against FRR consumer | `tests/interop/m37-evpn-local-origination.clab.yml` | landed |

**Post-Gate 7b / 7b+1 / 7b+2 / 7c alpha-soak follow-ups:**

| Task | File / location |
|------|----------------|
| MAC duplication detection (RFC 7432 §15.1 M=180s/N=5 quarantine action) — detection counters shipped; the operator-facing escalation channel and quarantine action are deferred per ADR-0055 §9 | `crates/evpn/src/origination.rs` (extend) |
| Type 5 IP Prefix origination per L3VNI | (deferred to Gate 9 — IP-VRF concept needed) |
| Mutation surface (`AddEvpnInstance` / `DeleteEvpnInstance`) | `crates/api/src/evpn_service.rs` |
| Kernel VXLAN interface config generator? | ops question — maybe not |

**Closed by post-v0.16.0 follow-ups (in `[Unreleased]`):**

| Item | Where it landed |
|------|-----------------|
| `advertise_svi_mac` consumption | `src/evpn_svi.rs` + `InstanceDataplaneStatus.bridge_mac` |
| Sticky-MAC config schema (`sticky_macs`) | ADR-0056, `EvpnInstance.sticky_macs` |
| Sub-second mobility convergence (Gate 7c) | `EvpnRouteEvent` broadcast in `crates/rib`; the 5 s poll stays as `Lagged` / cold-start backstop |
| MAC-with-IP Type 2 origination (Gate 7b+2) | `AF_INET` / `AF_INET6` `RTNLGRP_NEIGH` classifier in `crates/evpn-linux/src/linux/notify.rs`, `LocalMacIpOriginator` state machine in `crates/evpn/src/origination_macip.rs`, daemon correlation under FRR-style replace model in `src/evpn_originator.rs`. Operator prerequisite: bridge `neigh_suppress on`. |

---

### Gate 8 — Multi-homing foundation, observable DF election

Status: ✅ alpha-supported (slice 1+2+3+4) · Tracked: M38 smoke ·
Blockers cleared.

Ships:

- `[[ethernet_segments]]` config block with ESI, non-empty member
  VNI list, `df_preference = 32768`,
  `df_algorithm = "default-modulo"`, and originator IP.
  Single-homed and RR deployments take the empty-config early return
  and pay zero runtime cost.
- Pure DF election state machine (`crates/evpn/src/df_election.rs`)
  — RFC 7432 §8.5 service carving + RFC 8584 §3 algorithm
  negotiation, callable from a unit test.
- Three Type 1/4 origination state machines
  (`crates/evpn/src/origination_es.rs`) — Type 4 ES, Type 1
  EAD-per-ES (with MAX_ET marker), Type 1 EAD-per-EVI. The
  EAD-per-EVI originator tracks per-VNI DF role internally for
  Gate 8b but emits no wire churn on role flips (the Gate 8 wire
  shape is role-independent per RFC 7432 §14).
- Daemon orchestrator (`src/evpn_segment.rs`) wiring all of the
  above off the EVPN best-path broadcast (Gate 7c).
- Observable Prometheus surface — `evpn_df_role{esi,vni,role}`
  gauge and `evpn_df_role_changes_total{esi,vni}` counter.
- ADR-0057 records the observation/enforcement carve-out.

### Gate 8b prep — ES-Import RT + ESI Label origination

Status: ✅ shipped (`[Unreleased]`, follows Gate 8 in the same
release window).

Closes the two control-plane gaps ADR-0057 originally flagged
from Gate 8 — both extcomms had wire-codec support already,
so this was an origination-only change with no wire bump:

- **Type 4 ES route**: auto-derived ES-Import RT extcomm
  (RFC 7432 §7.6) — high-order 6 octets of the ESI Value.
  Peers can now correlate the segment via RT match without
  preconfiguration.
- **Type 1 EAD-per-ES route**: ESI Label extcomm (RFC 7432 §7.5)
  with the synthesized label and `single_active = false`
  (Gate 8 default is all-active). Peers can wire the label into
  their split-horizon filter tables; the dataplane-side drops
  on non-DF receivers stay Gate 8b proper.
- **Type 1 EAD-per-EVI**: unchanged (carries no ESI Label per
  RFC 7432 §14).

### Gate 8b — Multi-homing enforcement

Status: intent foundation landed, kernel enforcement deferred ·
Estimate: ~3-4 weeks · Blockers: Gate 8 + Gate 8b prep (cleared).

The first enforcement-foundation slice is in place:

1. **Observable BUM-enforcement intent** — `src/evpn_segment.rs`
   publishes a complete `(ESI, VNI) -> DfRole` table into the EVPN
   dataplane supervisor. `crates/evpn-linux` resolves each row
   against the current link inventory and reports bridge, VXLAN
   ifindex, CE-facing port ifindexes, and desired action
   (`allow` for DF, `suppress` for Non-DF) through
   `DataplaneReport.bum_enforcement`. No kernel filter mutation yet.

Concrete remaining slices:

1. **Dataplane split-horizon kernel primitive** — consume the
   reported BUM-enforcement plan; on Non-DF for a `(ESI, VNI)`,
   suppress / block CE-facing BUM behavior while preserving remote
   FDB programming and local learning.
   - Candidate primitives to spike before coding: `tc` filter on
     CE-facing bridge ports, nftables bridge-family rules, bridge
     VLAN filtering for VLAN-aware follow-up, or bridge MDB behavior
     if it can cover the relevant multicast-only subset. Do not
     wire any of these directly into the reconciler until a netns
     test proves the primitive blocks CE-facing BUM without
     affecting unicast FDB programming.
2. **Proper ESI label allocator** — replace the deterministic
   ESI-byte-derived synthesizer with a real per-ESI label space
   that survives operator-level configuration churn.
3. **Aliasing / backup paths** (RFC 7432 §14) — multihomed
   remote MACs resolved via Type 1 EAD-per-EVI as alternative
   next-hops.
4. **Mass withdraw on `AS_PATH` change** (RFC 7432 §8.6) — the
   fast-flip primitive that bypasses MP_UNREACH for whole-segment
   withdraw.
5. **DF-role-aware MAC origination** — a non-DF PE under
   enforcement should not advertise MAC routes that aliasing
   peers can't follow back. Couples to slice 1.
6. **Optional import-side ES-Import RT filtering** — apply the
   ES-Import RT origination from Gate 8b prep on the daemon's
   own RIB import path so unrelated segments are filtered before
   they reach LocRib. Currently we *originate* the RT but
   *import* via user-configured RTs only.

**Operator note:** Gate 8 + Gate 8b prep enables peers to
*observe* the segment without enabling segment forwarding. Do not
configure `[[ethernet_segments]]` for production multihoming
until Gate 8b proper ships — segment BUM will duplicate toward
the CE in a 2-PE setup.

---

### Gate 9 — Symmetric IRB (RFC 9135), adjacent standards

Status: after Gate 7 · Estimate: ~2-3 weeks · Blockers: Gate 7

Unlocks: L3 routing between EVPN tenants on the same VTEP. Router MAC
generation, Type 2 + Type 5 coordination, L3VNI mapping. Also
Auto-derived Route Targets (RFC 8365 §5.1.2.1).

Further out on this track:

- **RFC 9251 EVPN-MVPN** (Route Types 6/7/8) — multicast integration
- **RFC 7623 PBB-EVPN** — provider-backbone EVPN for carriers
- **MPLS encapsulation** — SP EVPN deployments beyond VXLAN
- **Add-Path for EVPN (RFC 9252)** — tables already support it, not negotiated

## Priority Ordering

```
Gate 1 (Type 2 interop, M30)    ── ✅ done
Gate 2 (GR/LLGR)                ── ✅ done
Gate 3 (MAC mobility, M31)      ── ✅ done
Gate 4 (multi-homing, M32)      ── ✅ done
Gate 5 (scale, M33)             ── ✅ done
Gate 6 (controller inject)      ── ✅ done   << full Phase 1 RR bundle complete
───────────── decision point ─────────────
Gate 7 (VTEP mode)               ── ✅ done
Gate 8 (multi-homing foundation) ── ✅ done   << observable DF election, M38 smoke
Gate 8b (multi-homing enforcement) ── deferred (split-horizon + ESI Label)
Gate 9 (IRB, MVPN, PBB, MPLS)    ── furthest horizon
```

### Harness reuse

Gates 1 and 3 build on the same containerlab + VXLAN setup: M30 is the
2-VTEP baseline, M31 adds a third VTEP so MAC mobility and sticky-MAC
preservation can be exercised. Gate 4 (multi-homing) extends M31 again
— two VTEPs sharing an ESI, third VTEP observes DF election inputs. No
new kernel infrastructure per gate after M30; the shim script
(`start-frr-vtep.sh`) is reused by every subsequent VTEP.

### Why Gate 6 before Gate 7

Gate 6 is ~1-2 weeks and opens a whole category of deployments (SDN
controllers injecting EVPN). Gate 7 is 4-6 weeks and enters FRR
competition territory. The ROI curve strongly favors Gate 6 first.

## Out of Scope (explicit non-goals for Gates 1-6)

Following ADR-0050's guardrail list. These are only reconsidered after
Gate 7 becomes a real commitment:

- VTEP mode (local EVI/VRF/VNI state, kernel FDB learning, local origination)
- DF election execution
- Symmetric IRB semantics
- Auto-derivation of Route Targets
- PBB-EVPN (RFC 7623)
- EVPN-MVPN (RFC 9251)
- MPLS encapsulation
- `match_evpn_route_type` / `match_vni` / `match_mac` policy clauses
  (Phase 1.5 nicety, not blocking)
- EVPN MRT dump
- EVPN BMP export (wire records already pass through, but no typed
  extraction in BMP message generation)

## Cross-References

- **ADR-0050** — architectural record for Phase 1
- **CHANGELOG.md** — `[Unreleased]` entry for EVPN RR
- **ROADMAP.md** — P2 block with Phase 1-5 breakdown
- **docs/INTEROP.md** — P1.5 "EVPN validation depth" gap list
- **docs/RFC_NOTES.md** — RFC 7432 / 9012 / 9135 implementation notes
- **docs/USE_CASES.md §7** — "VXLAN-EVPN DC Fabric Route Reflector"
- **docs/gobgp-parity.md** — DC fabric RR section, ~85% parity claim
- **examples/rr-evpn-fabric/config.toml** — reference RR config
