# EVPN Enablement Roadmap

For release-by-release feature history, see [CHANGELOG.md](../CHANGELOG.md).

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
- **Gate 8/8b** adds active-active multi-homing alpha execution:
  DF election, Type 1/4 origination, production-default BUM
  suppression with opt-out config, ESI-aware Type 2 origination,
  aliasing projection, and receive-side mass-withdraw filtering.
  **Gate 9** ships symmetric
  Interface-less IRB end-to-end (v0.18.0): `[[evpn_ip_vrfs]]`
  config schema, `IpVrfStatus` readiness probe (seven ADR-0058
  §3 predicates), Linux VRF + L3 VXLAN netlink dumps,
  `Dataplane::probe_ip_vrfs`, per-IP-VRF kernel-route observation
  with conservative classifier, Type 5 origination via
  `RibUpdate::InjectEvpn` gated on readiness, remote Type 5
  import + L3 FIB programming through a transactional
  `L3OwnedState` model, `RTNLGRP_IPV4/IPV6_ROUTE` multicast for
  sub-second withdraw, `ListIpVrfs`/`GetIpVrf` gRPC +
  `rustbgpctl evpn vrfs` CLI. ADR-0059 (v0.19.0) adds
  receive-path aliasing-ECMP via FDB nexthop groups, validated
  against FRR EVPN-MH by the hosted M40 smoke.
  ADR-0087/0090 close the near-term overlay-index ladder through native
  GW-IP origination, ESI origination, single-active receive, and all-active
  receive proofs (M68/M71/M72). Remaining big investments are the remaining
  ADR-0063 runtime convergence exceptions and lower-priority VTEP operability
  gaps such as bridge-ifindex MAC+IP VLAN correlation, true shared-VNI /
  non-zero Ethernet Tag service, and rustbgpd-managed SVD / collect-metadata
  VXLAN plus VRF/L3VXLAN lifecycle creation (managed bridge and fixed-VNI
  VXLAN lifecycle has shipped; VRF/L3VXLAN schema/status has shipped).
  ADR-0088 records the boundary for those operability gaps; ADR-0089's first
  VNI-per-broadcast-domain VLAN-aware bridge slice now validates an explicit
  `bridge_vlan` binding, programs VLAN-scoped remote-MAC FDB rows, attributes
  AF_BRIDGE local-MAC observations by `NDA_VLAN`, and attributes AF_INET /
  AF_INET6 MAC+IP observations that arrive on real VLAN upper devices such as
  `brvlan.10`. M70 adds the FRR cross-vendor receipt for the same-MAC
  two-VNI remote-FDB path on a rustbgpd-owned `vlan_filtering=1` bridge,
  `macip_vlan_attribution` proves same-MAC+IP two-VNI isolation through VLAN
  upper devices, and `svd_fdb_vni` proves SVD / collect-metadata Ready,
  same-MAC two-VNI isolation, and scoped delete on a real kernel. Raw
  bridge-ifindex ARP/ND on `vlan_filtering=1` bridges still fails closed
  because Linux does not report bridge VLAN identity there. Managed bridge and
  fixed-VNI VXLAN creation now ship under ADR-0091's altname-stamp ownership
  model; VRF/L3VXLAN rows now validate, derive ownership stamps, and report
  status, while SVD / collect-metadata VXLAN lifecycle and VRF/L3VXLAN
  lifecycle stay fail-closed until their own ownership/lifecycle proofs land.

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
| Full RFC 7432 daemon (RR + VTEP + multi-homing + IRB) | ~45-50% |

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
Controller injection supports Type 2 (MAC/IP), Type 3 (IMET), and Type 5
(IP Prefix, RFC 9136 — shipped v0.25.0 via `AddEvpnRoute`/`DeleteEvpnRoute`
+ `rustbgpctl evpn add-ip-prefix`, M45 smoke). Type 5 injection accepts the
default interface-less gateway-zero shape and a controller-supplied
overlay-index Gateway Address with ESI still zero. Native Type 1/4
multi-homing origination ships through `[[ethernet_segments]]`, but
controller injection for those route types is not exposed.

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
| Runtime mutation surface for the EVPN model (ADR-0063) — coordinator core + commit gate, with `EvpnService.ApplyEvpnRuntime` and SIGHUP reload wired to daemon-owned candidate parsing, full EVPN table validation, plan summaries, validate-only/no-op behavior, and ordered convergence + rollback. ADR-0063 deliberately rejects a direct `ArcSwap` / `RwLock` table swap. **See the "ADR-0063 runtime convergence contract" subsection below the table for the full shape-by-shape breakdown.** | `crates/evpn/src/runtime.rs`, `crates/api/src/evpn_service.rs`, `src/main.rs`, `src/evpn_runtime_converger.rs`, `src/reload.rs`, `src/evpn_imet.rs`, `src/evpn_originator/`, `src/evpn_svi.rs`, `src/evpn_l3_originator.rs`, `src/evpn_dataplane.rs`, `src/evpn_segment.rs` | single L2VNI add/delete/redefine + IP-VRF add/delete/redefine + ES add/delete/redefine + additive build-up + atomic tenant teardown + `ip_vrf` relink + L2VNI-only add/delete/redefine compositions, including intrinsic IP-VRF link metadata for added/deleted VNIs, landed for RPC and SIGHUP (M47/M48 teardown + M49 preference-DF smokes); L3VNI/device/table IP-VRF identity redefine (restart-required by design) + ES/IP-VRF row mixed edits remain tracked in [#268](https://github.com/lance0/rustbgpd/issues/268) |

**ADR-0063 runtime convergence contract.** The foundation exposes the
committed generation through `GetEvpnRuntime` / `rustbgpctl evpn runtime`
and rejects a direct `ArcSwap` / `RwLock` table swap. A daemon actor
converger commits these shapes **live** through `ApplyEvpnRuntime` and SIGHUP
file-driven reload:

- **Single L2VNI add** — IMET originate + effective-table republish to the
  dataplane supervisor, Type 2 MAC/MAC+IP originator, SVI task, and the
  already-running segment actor's instance view.
- **Single L2VNI delete** (when the VNI is not an Ethernet Segment member,
  including IP-VRF deployments where only derived link metadata changes) —
  IP-VRF metadata + effective-table republish, Type 2 / SVI drain, IMET
  withdraw, segment actor instance view.
- **Single L2VNI redefine** (including ES members when `ip_vrf` link
  metadata is unchanged) — per-VNI Type 3 IMET withdraw-then-re-originate
  plus candidate-instance-table republish to the level-triggered Type 2
  originator, SVI task, dataplane supervisor, and segment actor. ES-member
  redefine also drains/rebuilds Type 4 / EAD-per-ES / EAD-per-EVI while
  preserving the stable ESI label — this makes `apply_aliasing_ecmp`
  runtime-drivable via the dataplane `FdbNhg → SingleDst` transition.
- **Single IP-VRF add** — effective-table republish to the dataplane
  supervisor and Type 5 originator.
- **Single standalone IP-VRF delete** (no L2VNI references it) —
  effective-table republish to the dataplane supervisor and Type 5
  originator.
- **Single IP-VRF redefine** with unchanged L3VNI/device/table identity —
  effective-table republish plus Type 5 drain/replay for changed
  route/policy/egress fields.
- **Single Ethernet Segment add/delete/redefine** — full desired-ES
  snapshot republished to the segment actor, which drains/rebuilds Type 4
  / EAD-per-ES / EAD-per-EVI / BUM state.
- **Atomic tenant teardown** — a delete-only plan dropping an ES-member
  L2VNI together with its Ethernet Segment (delete or member-shrink)
  and/or a linked IP-VRF in one pass, validated for internal consistency
  then converged by withdrawing each deleted L2VNI's Type 3 IMET and
  republishing candidate snapshots to every level-triggered actor with a
  rollback ladder (the segment actor emits Type 1/4 withdraws even for a
  member VNI removed in the same pass).
- **Additive build-up** — a pure add-only multi-row or multi-domain candidate
  such as adding a linked L2VNI, its IP-VRF, and its Ethernet Segment in one
  request. The converger validates that no delete/redefine is present and that
  any `ip_vrf` reference delta belongs only to newly added L2VNIs, then
  originates Type 3 IMET and republishes candidate snapshots to the dataplane,
  Type 2 originator, SVI, segment, and Type 5 originator with rollback.
- **L2VNI mixed composition** — one-or-more L2VNI add/delete/redefine
  change classes in the same candidate. Deleted VNIs cannot be Ethernet
  Segment members, IP-VRF/ES row edits remain rejected, and any `ip_vrf`
  reference delta must belong only to added/deleted VNIs. The converger
  originates added IMET, re-keys redefined IMET, republishes changed IP-VRF
  reference metadata, publishes the candidate L2VNI snapshot, withdraws deleted
  IMET, and rolls back all touched snapshots/IMET state on failure.
- **`ip_vrf` relink** — a dataplane-only republish of the moved link
  reference (the link drives only RFC 9135 overlay-index recursion; RD is
  unchanged, so no Type 3 re-origination).

Convergence is ordered with rollback; the originator / SVI / Type 5 actors
drain removed-or-redefined VNIs/IP-VRFs (including stale duplicate-MAC
move-window state where applicable) before accepting a new model. Because
the segment actor consumes runtime instance snapshots, ES add/redefine can
bind a member VNI added by an earlier live L2VNI add when the actor
already exists.

Shapes that **fail closed** with `FAILED_PRECONDITION` (without advancing
or degrading the committed generation): L3VNI/device/table IP-VRF identity
changes (restart-required by design — kernel VRF lifecycle), ES/IP-VRF row
mixed edits outside the L2VNI-only composer, an ES referencing an unknown member VNI, or an
apply on an RR-only / no-actor daemon.

The apply is **cancellation-shielded** (ADR-0080): the converge + commit
critical section runs on a detached task, so a client that disconnects or
times out mid-apply loses only the response — the mutation still runs to
completion (commit or rollback) and the coordinator generation and SIGHUP
reload baseline advance truthfully. A caller that lost its response should
treat the apply as at-least-once and read `GetEvpnRuntime` /
`rustbgpctl evpn runtime` for the authoritative outcome. Coordinated
shutdown takes the same apply lock before EVPN teardown, so an in-flight
apply finishes before the withdraw-all sweep and a late apply cannot
re-originate routes after it.

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
| `EvpnOriginator` daemon actor — `tokio::select!` over the local-observation channel (MAC-only and MAC+IP events) + RIB poll + shutdown-drain; emits `RibUpdate::InjectEvpn` / `WithdrawEvpn` | `src/evpn_originator/` | landed |
| Type 3 IMET origination per `EvpnInstance` — startup-inject + shutdown-withdraw carrying PMSI Tunnel + RT extcomms, now owned by a controller with per-VNI originate/withdraw methods for ADR-0063 convergence | `src/evpn_imet.rs` | landed; runtime controller primitive added |
| Upward `LocalMacObservation` channel — `Dataplane::take_local_mac_rx` trait method + `InMemoryDataplane` test surface | `crates/evpn-linux/src/dataplane.rs`, `crates/evpn-linux/src/in_memory.rs` | landed |
| `RTNLGRP_NEIGH` subscription + classifier — `add_membership` on the rtnetlink socket, pure `classify_neigh` function with bridge-port → VNI lookup, drop on `NTF_EXT_LEARNED` echoes and VXLAN-port ifindexes | `crates/evpn-linux/src/linux/notify.rs` | landed |
| Daemon main wiring — spawn originator alongside the reconciler under the same `[[evpn_instances]]` gate; coordinated-shutdown drain order | `src/main.rs` | landed |
| ADR-0055 — Local-MAC origination boundary (sequence rules, channel surface, deferral list) | `docs/adr/0055-evpn-local-mac-origination.md` | landed |
| M37 containerlab smoke — rustbgpd-as-VTEP originating Type 2 + IMET against FRR consumer | `tests/interop/m37-evpn-local-origination.clab.yml` | landed |

**Post-Gate 7b / 7b+1 / 7b+2 / 7c alpha-soak follow-ups:**

| Task | File / location |
|------|----------------|
| MAC duplication detection (RFC 7432 §15.1 M=180s/N=5) — ✅ complete (#139): detect-only defaults, opt-in local-origin `suppress_local` action, remote-route processing suppression, receive-side intent filtering, and a manual clear API (`ClearDuplicateMacQuarantine`). Only explicit kernel drop/filter primitives remain optional follow-up. | `crates/evpn/src/duplicate_mac.rs`, `src/evpn_originator/duplicate_mac.rs`, `crates/api/src/evpn_service.rs` |
| Type 5 IP Prefix origination per L3VNI | ✅ Gate 9 slice 6 (v0.18.0) — kernel-route observation, `IpVrfStatus`-gated origination via `RibUpdate::InjectEvpn`, remote import + transactional L3 FIB programming (`L3OwnedState`), Router MAC conflict detection, four-phase apply ordering, foreign-state preservation. `RTNLGRP_IPV4/IPV6_ROUTE` multicast added sub-second withdraw on tenant `ip addr del`. |
| Mutation surface — whole-model `EvpnService.ApplyEvpnRuntime` plus SIGHUP reload (ADR-0063); single L2VNI add/delete/redefine, single IP-VRF add/delete/redefine with unchanged L3VNI/device/table identity, single Ethernet Segment add/delete/redefine, additive build-up, atomic tenant teardown (delete-only ES-member L2VNI + Ethernet Segment and/or linked IP-VRF in one pass), `ip_vrf` relink, and L2VNI-only add/delete/redefine compositions with intrinsic IP-VRF link metadata for added/deleted VNIs commit live; L3VNI/device/table identity changes are restart-required by design and ES/IP-VRF row mixed edits fail closed (#268) | `crates/api/src/evpn_service.rs`, `src/main.rs`, `src/reload.rs`, `src/evpn_runtime_converger.rs`, `src/evpn_segment.rs` |
| Kernel VXLAN interface config generator? | ops question — maybe not |

**Closed in v0.17.0 (post-v0.16.0 follow-ups):**

| Item | Where it landed |
|------|-----------------|
| `advertise_svi_mac` consumption | `src/evpn_svi.rs` + `InstanceDataplaneStatus.bridge_mac` |
| Sticky-MAC config schema (`sticky_macs`) | ADR-0056, `EvpnInstance.sticky_macs` |
| Sub-second mobility convergence (Gate 7c) | `EvpnRouteEvent` broadcast in `crates/rib`; the 5 s poll stays as `Lagged` / cold-start backstop |
| MAC-with-IP Type 2 origination (Gate 7b+2) | `AF_INET` / `AF_INET6` `RTNLGRP_NEIGH` classifier in `crates/evpn-linux/src/linux/notify.rs`, `LocalMacIpOriginator` state machine in `crates/evpn/src/origination_macip.rs`, daemon correlation under FRR-style replace model in `src/evpn_originator/`. Operator prerequisite: bridge `neigh_suppress on`. |

---

### Gate 8 — Multi-homing foundation, observable DF election

Status: ✅ alpha-supported (slice 1+2+3+4) · Tracked: M38 smoke ·
Blockers cleared.

Ships:

- `[[ethernet_segments]]` config block with ESI, non-empty member
  VNI list, `df_preference = 32768`,
  `df_algorithm = "default-modulo"`, `"highest-random-weight"`,
  `"highest-preference"`, or `"lowest-preference"`,
  `redundancy_mode = "all-active"` or `"single-active"`, and
  originator IP.
  Single-homed and RR deployments take the empty-config early return
  and pay zero runtime cost.
- Pure DF election state machine (`crates/evpn/src/df_election.rs`)
  — RFC 7432 §8.5 service carving + RFC 8584 §3.2 Highest Random
  Weight + RFC 9785 Highest-/Lowest-Preference, with fallback to
  default when candidates disagree, callable from a unit test. Local
  Don't-Preempt origination shipped (`df_dont_preempt`); stateful
  non-revertive election remains deferred. Receive-side single-active
  backup-path pre-install is covered by ADR-0083.
- Three Type 1/4 origination state machines
  (`crates/evpn/src/origination_es.rs`) — Type 4 ES, Type 1
  EAD-per-ES with the MAX_ET marker and ESI Label single-active flag,
  and Type 1 EAD-per-EVI. Receiver-side aliasing ECMP is limited to
  all-active remote ES reachability; receive-side single-active
  backup-path pre-install is covered by ADR-0083, with local-PE-side
  L3/symmetric-IRB extension still deferred. The EAD-per-EVI
  originator tracks per-VNI DF role internally for Gate 8b but emits
  no wire churn on role flips (the Gate 8 wire shape is
  role-independent per RFC 7432 §14).
- Daemon orchestrator (`src/evpn_segment.rs`) wiring all of the
  above off the EVPN best-path broadcast (Gate 7c).
- Cloneable runtime owner/control surface for complete desired-ES
  snapshots. This preserves `src/evpn_segment.rs` as the only Type 1/4
  owner and gives ADR-0063 ES commits a single actor boundary.
  `ApplyEvpnRuntime` now commits a **single Ethernet Segment add/delete/redefine**
  through that boundary (republishing the current instance table plus full
  desired-ES snapshot), including member VNIs added by an earlier runtime
  L2VNI add when the segment actor already exists.
- Observable Prometheus surface — `evpn_df_role{esi,vni,role}`
  gauge and `evpn_df_role_changes_total{esi,vni}` counter.
- ADR-0057 records the observation/enforcement carve-out.

### Gate 8b prep — ES-Import RT + ESI Label origination

Status: ✅ shipped in v0.17.0, follows Gate 8 in the same release
window.

Closes the two control-plane gaps ADR-0057 originally flagged
from Gate 8 — both extcomms had wire-codec support already,
so this was an origination-only change with no wire bump:

- **Type 4 ES route**: auto-derived ES-Import RT extcomm
  (RFC 7432 §7.6) — high-order 6 octets of the ESI Value.
  Peers can now correlate the segment via RT match without
  preconfiguration.
- **Type 1 EAD-per-ES route**: ESI Label extcomm (RFC 7432 §7.5)
  with the allocated label and `single_active = false`
  (Gate 8 default is all-active). Peers can wire the label into
  their split-horizon filter tables; rustbgpd's dataplane-side drops
  are now the production default via `apply_bum_enforcement` (true
  since v0.23.0). Note these are *role-based* (DF/non-DF) BUM-port
  drops, not source-conditioned local-bias split-horizon — see the
  Gate 8b note below and ADR-0065.
- **Type 1 EAD-per-EVI**: unchanged (carries no ESI Label per
  RFC 7432 §14).

### Gate 8b — Multi-homing enforcement

Status: ✅ alpha-supported, production-default with opt-out config
(default flipped in v0.23.0 after soak evidence) · Blockers cleared:
Gate 8 + Gate 8b prep.

Shipped pieces:

1. **Observable BUM-enforcement intent** — `src/evpn_segment.rs`
   publishes a complete `(ESI, VNI) -> DfRole` table into the EVPN
   dataplane supervisor. `crates/evpn-linux` resolves each row
   against the current link inventory and reports bridge, VXLAN
   ifindex, CE-facing port ifindexes, and desired action
   (`allow` for DF, `suppress` for Non-DF) through
   `DataplaneReport.bum_enforcement`.
2. **Dataplane DF/non-DF BUM-suppression primitive** — when
   `apply_bum_enforcement = true`, the Linux dataplane applies the
   validated BUM-suppression primitive for Non-DF CE-facing ports.
   This is *role-based* (per-port flood-flag) suppression, **not**
   source-conditioned VXLAN local-bias split-horizon (RFC 8365
   §8.3.1). True local-bias — dropping only BUM whose overlay source
   is an ES-peer VTEP while still flooding other BUM and forwarding
   known unicast — is the **remaining all-active correctness gate**.
   ADR-0065's netns spike confirmed it is not achievable with
   stateless `tc` on the standard bridged-VXLAN softswitch (the
   overlay source is not visible to `tc-flower` at the VXLAN ingress
   hook — the FRR #15400 failure mode); it is ASIC/offload-dependent.
   The Docker netns harness is PR-CI gated; the default flipped to
   `true` in v0.23.0 after the Gate 8b 24 h MAC-churn soak
   (2026-05-16) and the M37 local-origination 24 h MAC-churn soak
   (2026-05-19) both passed clean.
3. **Single-active whole-port AC gate** — the RFC 7432 §14.1.1
   complement to the flood flags: for a single-active ES **with an
   ADR-0085 `interface` binding**, the non-DF PE's bound AC bridge
   port is held in `IFLA_BRPORT_STATE` `disabled` (all traffic
   blocked, known unicast included) and re-opened on DF promotion;
   a drained ES blocks too (maintenance semantic). Rides the same
   `apply_bum_enforcement` knob. Whole-port, not per-VLAN: RFC 8584
   service carving that splits DF roles across member VNIs falls
   back to BUM-only enforcement, surfaced via a warning + the
   `evpn_es_ac_gate` gauge (`blocked` / `forwarding` /
   `mixed-roles`). Unbound segments stay BUM-flood-only — binding
   the AC is what provides the port handle. Do not run kernel STP
   on a bound AC; if the port is observed in an STP-owned state
   (`listening`, `learning`, `blocking`), rustbgpd warns and leaves it
   untouched until STP releases the port state. See
   `docs/evpn-vtep-troubleshooting.md` for the
   triage section; M67 asserts the transitions in CI.
4. **Per-ESI label allocator** — `EsiLabelAllocator` assigns stable
   labels per ESI, avoids deterministic synthesizer collisions, and
   threads the allocated label through both the EAD-per-ES NLRI MPLS
   label field and the ESI Label extended community.
5. **ESI-aware MAC origination** — Type 2 routes originated for MACs
   learned on a VNI in a configured `[[ethernet_segments]]` block
   carry that segment's ESI. Config rejects a VNI shared across
   multiple local segments until learned-port-to-ESI disambiguation
   is plumbed.
6. **Aliasing receive-side projection + FDB-NHG dataplane** — the
   projection layer combines non-zero-ESI Type 2 routes with
   EAD-per-EVI routes and populates `RemoteMacEntry::alias_vtep_ips`
   + `alias_group_key`. ADR-0059 wires the kernel side: multi-homed
   Type 2 entries program an FDB nexthop group via `NDA_NH_ID` /
   `NHA_FDB`, with members keyed by per-VTEP IP and the group
   keyed by `(VNI, ESI, EthernetTag)`. Receive-path ECMP fans out
   across every observed alias VTEP. M40 hosted smoke
   validates the end-to-end path against FRR EVPN-MH 10.3.1.
7. **Mass-withdraw receive-side filter** — every supervisor pass
   snapshots EAD-per-ES routes and drops non-zero-ESI Type 2 routes
   whose `(origin VTEP next-hop, ESI)` is not active. This gives
   level-triggered whole-segment withdrawal within the dataplane
   supervisor poll interval.

Concrete remaining slices:

1. **MAC-churn variant of the 24 h Gate 8b soak** — **PASSED**
   2026-05-16 ([`docs/soak-gate8b-mac-churn-24h.md`](soak-gate8b-mac-churn-24h.md)).
   Synthetic DF flips with concurrent FDB programming via the
   process-restart harness at
   `tests/soak/run-gate8b-mac-churn-soak.sh`. 69 complete flip cycles,
   ~478 K FDB ops, PE1 RSS plateau 17.23–18.93 MB (slope envelope
   0.08 MB/h), 0 FATAL / WARN / drift events. Combined with the M37
   local-origination 24 h MAC-churn soak ([`docs/soak-m37-local-origination-churn-24h.md`](soak-m37-local-origination-churn-24h.md),
   PASSED 2026-05-19; 17 174 churn cycles, 430 400 inject == 430 400
   withdraw, after-warmup RSS slope 0.184 MB/h, 10/10 gates green),
   this cleared the gating evidence for flipping the
   `apply_bum_enforcement` default to `true`. The flip shipped in
   v0.23.0.
2. **Local DF-election ES-Import RT filtering** — rustbgpd applies
   the ES-Import RT it originates in Gate 8b prep at the local Type 4
   candidate projection boundary. Remote Type 4 routes with a missing
   or mismatched ES-Import RT are ignored for DF election, while the
   EVPN Loc-RIB, `ListEvpnRoutes`, and RR reflection remain complete
   for observability and route-reflector use cases.

ADR-0059 slice 3.5 hardening (`apply_aliasing_ecmp` off-switch,
periodic `RTM_GETNEXTHOP` drift recovery, IPv6 alias members)
shipped in v0.20.0 — PRs #91 / #92 / #93 — and is no longer on
the remaining-slices list.

**Operator note:** DF/non-DF BUM suppression and aliasing ECMP are the
production default since v0.23.0. Both `apply_bum_enforcement` and
`apply_aliasing_ecmp` ship as `true` out of the box; new deployments
get role-based kernel BUM-suppression on Non-DF CE-facing ports and FDB
nexthop groups for multi-homed Type 2 routes without additional config.
VXLAN local-bias split-horizon (RFC 8365 §8.3.1) is **not** part of this
and remains the open all-active correctness gate — ASIC/offload-dependent
on the Linux softswitch (ADR-0065).
Operators who need the prior observe-only / single-dst posture can
still opt out explicitly with `apply_bum_enforcement = false` and/or
`apply_aliasing_ecmp = false` on the relevant `[[evpn_instances]]`
entry.

---

### Gate 9 — Symmetric IRB (RFC 9135), adjacent standards

Status: end-to-end shipped in v0.18.0 · auto-derived RTs are now
available as an explicit config opt-in · receive-side overlay-index
Type 5 recursion now resolves non-zero Gateway Address routes through
linked Type 2 MAC/IP state, with unresolved or ambiguous gateways
still fail-closed and counted by Prometheus · native GW-IP and ESI
overlay-index Type 5 origination now ship as explicit opt-in modes

Unlocks: L3 routing between EVPN tenants on the same VTEP under the
RFC 9136 §4.4.2 symmetric Interface-less IRB model (matches FRR's
default). Operator-supplied Router MAC, Type 2 + Type 5 coordination,
L3VNI mapping.

Shipped pieces (v0.18.0):

- `[[evpn_ip_vrfs]]` TOML schema declares IP-VRF / L3VNI tenants
  with name, RD, RT list, local VTEP IP, operator-supplied Router
  MAC, and observe-only `vrf_device` / `l3vxlan_device` / `table_id`.
  Optional `ip_vrf` field on `[[evpn_instances]]` binds an L2VNI to
  a declared IP-VRF by name. ADR-0058 §4 records the deliberate
  decision to not auto-derive the Router MAC.
- Pure-logic `rustbgpd_evpn::ip_vrf::readiness` probe against ADR-
  0058 §3's seven predicates (`vrf_device` exists + UP + matching
  table id; `l3vxlan_device` exists + UP + matching VNI + matching
  local IP + enslaved to the VRF + MAC matches Router MAC).
  `NotReady { reasons }` reports every failing predicate at once.
- Pure-logic `ip_vrf::origination` + `ip_vrf::projection` helpers
  for Type 5 NLRI construction (label = L3VNI, Interface-less
  gateway, RT extcomms, BGP Encap = VXLAN, Router MAC extcomm)
  and RT-keyed import with Router MAC enforcement / self-origin
  filtering.
- Auto-derived Route Targets for both `[[evpn_instances]]` and
  `[[evpn_ip_vrfs]]` via `auto_derive_route_target = true` (2-octet AS
  only; 4-octet-AS deployments keep explicit RTs). The derived form
  differs by VNI scope to match the de-facto vendor wire forms:
  - **L2VNI / MAC-VRF** uses the RFC 8365 §5.1.2.1 opaque form
    (`AS:0x10000000|vni`), which matches FRR only with `autort
    rfc8365-compatible` (FRR's default L2VNI autort is `AS:VNI`).
  - **L3VNI / IP-VRF** uses plain `AS:VNI`, matching FRR's default
    tenant-VRF auto-RT with no extra knob (validated by the M39b
    cross-vendor interop smoke).
  See `docs/CONFIGURATION.md` for the full interop matrix.
- RFC 9135 §9.2 overlay-index Type 5 detection on the receive path:
  non-zero Type 5 Gateway Address routes are no longer treated as
  Interface-less Type 5. The dataplane projection resolves them through
  a Type 2 MAC/IP route from the same RIB snapshot when that Type 2
  route's L2VNI is linked to the matched IP-VRF through
  `[[evpn_instances]].ip_vrf`. Contenders are tie-broken like the Type 2
  path — highest MAC mobility sequence wins, and a single MAC reachable
  through several VTEPs (multi-homing) resolves to a deterministic
  next_hop. Missing links, unresolved gateways, gateways resolving to
  multiple distinct MACs, self-originated rows, quarantined MACs,
  mass-withdraw-filtered Type 2 rows, RT misses, and L3VNI mismatches
  remain fail-closed drops. The daemon publishes the current remote
  Type 5 projection-drop counts through
  `evpn_ip_vrf_remote_prefix_drops{vrf,reason}` with fixed reason
  labels and the `IpVrfState.remote_prefix_drop_counts` API / CLI field, so
  recursive failures are visible without prefix/MAC cardinality in metrics or
  status output.
- ADR-0087 native GW-IP overlay-index origination (v0.39.0): per-IP-VRF
  `overlay_index_mode = "gateway_ip"` originates local Type 5 routes
  with an eligible kernel via in the Gateway Address and no Router-MAC
  extcomm, while routes without an eligible via fall back to the
  interface-less shape. The default stays `"interface_less"`. M68 proves
  FRR consumes this native shape with `enable-resolve-overlay-index`: it
  holds the Type 5 unresolved before the companion Type 2 exists, then
  imports the prefix into the tenant VRF through the Gateway Address
  once the MAC/IP route arrives.
- RFC 9136 §4.3 ESI overlay-index origination: per-IP-VRF
  `overlay_index_mode = "esi"` originates local Type 5 routes with a
  configured non-zero ESI, zero Gateway Address, L3VNI in the label
  slot, and Router MAC extcomm set to `overlay_index_mac`. Config load
  fails closed unless `overlay_index_esi` names a configured
  `[[ethernet_segments]]` ESI, the IP-VRF has at least one linked
  `[[evpn_instances]].ip_vrf` L2VNI, and the selected/implicit
  `overlay_index_l2vni` is a member of that ES.
- RFC 9136 §4.3 single-active ESI overlay-index Type 5 receive:
  receive-side projection preserves non-zero Type 5 ESI and Ethernet Tag
  metadata, scopes protected recursion through EAD-per-EVI state in an
  L2VNI linked to the matched IP-VRF, and imports only the installable v1
  shape: exactly one single-active remote VTEP. Missing scope, missing
  Router MAC, unresolved EAD, dual GW-IP+ESI overlay indexes,
  and ambiguous single-active candidates stay fail-closed and are counted
  through the existing remote-prefix drop surface. M71 proves the single-active
  receive path against a GoBGP route source.
- RFC 9136 §4.3 all-active ESI overlay-index Type 5 receive:
  ADR-0090 defines the all-active receive contract. Projection carries
  deterministic all-active remote-VTEP target sets, the Linux L3 writer installs
  valid two-or-more-member target sets as route-level ECMP over the L3VXLAN with
  per-VTEP L3 neighbors and an L3VXLAN Router-MAC FDB-NHG row, and the actor
  cleans up the route, neighbors, FDB row, and L3-tagged nexthop objects on
  withdraw or all-active-to-single collapse. Crash-leftover all-active rows are
  adopted on restart, including the existing L3 NHID group/member tree, so
  desired state reclaims the prior NHG ID rather than allocating a fresh tree.
  Single-member all-active target
  sets, mixed single-active/all-active signals, family mismatches, and
  incompatible Router-MAC target-set claims stay fail-closed. The
  `l3_all_active_writer` netns selector proves the production writer path
  against a real kernel; M72 proves the real-peer path with two GoBGP PEs:
  unresolved before EAD, then a two-way VRF ECMP route plus Router-MAC `nhid`
  FDB row, then deterministic target-set collapse/re-expand and withdraw
  cleanup.
- Linux `ip_vrf::dump_ip_vrf_observations` (VRF + L3 VXLAN
  rtnetlink dumps), `Dataplane::probe_ip_vrfs` trait method +
  Linux implementation, `IpVrfTable` plumbed through
  `DataplaneIntent`; reconcile actor calls `probe_ip_vrfs` each
  pass and logs `Ready` ↔ `NotReady` transitions via tracing.
  `DataplaneReport.ip_vrf_status` rows propagate the same verdict
  to subscribers, and `rustbgpctl evpn vrfs [NAME]` plus the new
  `EvpnService.ListIpVrfs` / `EvpnService.GetIpVrf` gRPC surfaces
  let operators read the readiness state without scraping logs.

Closed arcs and remaining bounds:

- Overlay-index IRB follow-through is no longer a near-term gap: GW-IP
  receive-side recursive resolution, bounded drop metrics, aggregated per-VRF /
  per-reason drop counts in gRPC / CLI status, native GW-IP origination
  (ADR-0087), ESI origination, single-active ESI receive recursion, the
  FRR consume-side M68 GW-IP proof, the M71 real-peer single-active ESI proof,
  ADR-0090's all-active L3 writer, and the M72 real-peer all-active proof now
  ship. Broader service-provider EVPN route families remain demand-shaped.
- Runtime instance mutation bounds (ADR-0063 / #268): single L2VNI add/delete/
  redefine, single IP-VRF add/delete/redefine with unchanged L3VNI/device/table
  identity, single Ethernet Segment add/delete/redefine, additive build-up,
  atomic tenant teardown (delete-only ES-member L2VNI + Ethernet Segment and/or
  linked IP-VRF in one pass), `ip_vrf` relink, and L2VNI-only add/delete/
  redefine compositions with intrinsic IP-VRF link metadata for added/deleted
  VNIs commit live via `ApplyEvpnRuntime` and SIGHUP reload. L3VNI/device/table
  IP-VRF identity changes are restart-required by design, and ES/IP-VRF row
  mixed edits fail closed with a "split the request" error.

(The hosted `kernel-dataplane` workflow now covers the EVPN dataplane smokes
M36 / M37 / M37+IP / M38 / M39 / M39b / M40 / M46 / M47 / M48 / M49 /
M60 / M61 / M65 / M66 / M67 / M68 / M69 / M70 / M71 / M72 — #130 closed. Non-EVPN kernel
dataplane, BFD, and TCP-AO coverage is catalogued in `INTEROP.md` and
`kernel-dataplane-runner.md`.)

### Standards-tail map

This table separates the remaining EVPN work by fit. It is intentionally not a
promise to chase full service-provider EVPN parity before there is operator
demand.

| Area | Status | First reviewable slice | Proof gate |
|------|--------|------------------------|------------|
| RFC 9136 ESI overlay-index Type 5 origination + single-active receive | Shipped (bounded v1) | RT-5 carries non-zero ESI, zero Gateway Address, L3VNI label, and configured virtual/transit Router MAC; receive-side recursion imports exactly one single-active EAD-per-EVI candidate scoped by linked L2VNI and Ethernet Tag | Pure origination/projection + daemon tests plus M71 GoBGP real-peer receive proof |
| ADR-0090 all-active ESI overlay-index Type 5 receive | Shipped (bounded v1) | Extends the M71 shape to all-active ESI recursion with deterministic remote-VTEP target sets, route-level ECMP, per-VTEP L3 neighbors, and L3VXLAN FDB-NHG for the shared Router MAC. The model distinguishes single-active, all-active, and conflicting EAD redundancy signals; invalid one-member/mixed/family-conflict/Router-MAC-conflict shapes fail closed; valid all-active target sets install through the production L3 writer and reclaim crash-leftover L3 NHID/FDB-NHG state on restart | `l3_all_active_writer` same-host netns proof is CI-gated for both steady-state writer cleanup and abort/restart adoption; M72 real-peer proof is CI-gated with two GoBGP route-source PEs: unresolved before EAD, then VRF ECMP route + `nhid` Router-MAC FDB row, then deterministic target-set collapse/re-expand and withdraw cleanup |
| VLAN-aware bridges | Demand-shaped Linux/VXLAN operability; ADR-0088 boundary accepted; ADR-0089 v1 VNI-per-broadcast-domain slice landed for traditional multi-VXLAN bridges and SVD / collect-metadata VXLAN: `bridge_vlan` schema/status, observed VLAN topology validation, `NDA_VLAN` remote-MAC FDB attribution for fixed-VNI devices, `NDA_SRC_VNI` attribution for SVD devices, AF_BRIDGE local-MAC VLAN attribution, VLAN-upper AF_INET / AF_INET6 MAC+IP attribution, M70 FRR interop proving same-MAC two-VNI isolation on a traditional rustbgpd-owned `vlan_filtering=1` bridge, `dataplane_vlan_fdb` + `macip_vlan_attribution` proving real-kernel VLAN-scoped FDB and MAC+IP isolation, and `svd_fdb_vni` proving SVD Ready + add + same-MAC two-VNI isolation + scoped delete on a real kernel. Ethernet Tag ID stays `0`; unattributable VLAN observations fail closed as normal "not ours" classifier outcomes, downstream observation backpressure is metered, and startup link-cache/probe priming bounds the boot window | Raw bridge-ifindex ARP/ND on `vlan_filtering=1` bridges remains fail-closed unless a future FDB-correlation design proves freshness and ambiguity handling; true VLAN-aware bundle / non-zero Ethernet Tag needs a separate ADR; managed netdev creation stays a separate ergonomics track | Unit tests, hosted/gated local kernel netns tests including `dataplane_vlan_fdb`, `macip_vlan_attribution`, and `svd_fdb_vni`, and hosted M70 FRR containerlab receipt |
| rustbgpd-managed bridge / VXLAN / VRF netdev creation | Demand-shaped operator ergonomics; boundary accepted in ADR-0088 and ADR-0091; bridge and fixed-VNI VXLAN lifecycle landed (`[managed_netdevs]`, derived altname stamps, `EvpnService.ListManagedNetdevs`, `rbgp evpn managed-netdevs`, create -> stamp -> fresh-dump confirm, crash-restart adoption, safe same-owner reap, foreign/unsafe preservation). Fixed-VNI VXLAN rows create traditional one-VNI VXLAN devices on the desired bridge, fail closed on SVD/collect-metadata, `vnifilter`, learning, bridge-attachment, or protected-attribute drift, and the `managed_ready` proof shows the rustbgpd-created bridge + VXLAN topology makes the real EVPN L2 probe Ready. VRF/L3VXLAN schema/status substrate has landed: desired rows validate, derive `vrf` / `l3vxlan` ownership stamps, parse observed protected attributes, and report desired/observed/orphan/foreign/unsafe state through the same surfaces | Add VRF/L3VXLAN lifecycle create/adopt/reap proof. SVD/collect-metadata VXLAN creation and VLAN-upper creation remain separate class-specific gates | Unit + actor tests and hosted/gated local kernel netns tests `managed_bridge`, `managed_vxlan`, and `managed_ready`; fixed-VNI VXLAN status/lifecycle plus VRF/L3VXLAN status substrate are covered by config/API/CLI/link-parser/reconcile unit tests |
| BGP Add-Path for L2VPN EVPN | Demand-shaped control-plane breadth | Negotiate RFC 7911 Add-Path for AFI 25 / SAFI 70 only after EVPN Adj-RIB-In/Out, API, event history, and export paths are path-id-safe | Unit matrix plus FRR/GoBGP interop if a peer supports the shape |
| RFC 9251 Route Types 6/7/8 | Out-of-current-lane / service-provider multicast | Typed route-family slice for SMET and IGMP/MLD sync routes; no Linux dataplane change until multicast ownership is designed | Standards codec tests plus real-peer reflect/withdraw interop |
| RFC 9572 Route Types 9/10/11 | Out-of-current-lane / service-provider BUM segmentation | Typed route-family slice for PMSI/leaf A-D routes | Standards codec tests plus real-peer interop |
| RFC 7623 PBB-EVPN, EVPN-MVPN, VPWS/E-Tree, MPLS/SRv6 service encapsulation | Out-of-niche unless operator demand appears | New ADR before code; keep MPLS dataplane out of scope unless explicitly reversed | Separate design and interop plan |

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
Gate 8b (multi-homing enforcement) ── ✅ alpha, default-on with opt-out
                                       (DF/non-DF BUM + aliasing ECMP;
                                        local-bias SPH ASIC-dep — ADR-0065)
Gate 9 (IRB, Type 5)             ── ✅ symmetric Interface-less IRB end-to-end (v0.18.0)
ADR-0059 (aliasing FDB-NHG)      ── ✅ shipped (slices 1-4); M40 FRR-validated
Gate 9+ (MVPN/PBB/MPLS/BUM ext)  ── furthest horizon
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

## Original Non-Goals for Gates 1-6

Following ADR-0050's guardrail list. Several items below have since
landed in later gates; this section records what Phase 1 deliberately
did not take on:

- VTEP mode (landed across Gates 7a/7b/7b+1/7b+2/7c)
- DF election execution (landed in Gate 8; enforcement alpha in Gate 8b)
- Symmetric Interface-less IRB semantics (Gate 9, v0.18.0 — end-to-end shipped)
- Auto-derivation of Route Targets
- PBB-EVPN (RFC 7623)
- Multicast EVPN / MVPN (including RFC 9251 IGMP/MLD proxy routes)
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
- **docs/gobgp-parity.md** — DC fabric RR section + feature-parity matrix
- **examples/rr-evpn-fabric/config.toml** — reference RR config
