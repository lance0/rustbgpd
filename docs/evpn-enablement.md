# EVPN Enablement Roadmap

Last updated: 2026-04-23

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

- **Gates 0, 1, 2, 3**: done on `feat/evpn-rr`. Capability, real Type 2
  MAC reflection (M30), EVPN GR/LLGR, and MAC mobility / sticky
  preservation (M31) all validated against FRR 10.3.1.
- **Gate 4** (multi-homing Type 1 + Type 4 reflection) is the last
  remaining item for "production-ready RR for a SONiC/FRR fabric".
- **Gate 5** validates scale. Once green, the RR claim is full.
- **Gate 6** unlocks controller-driven deployments; cheap relative to payoff.
- **Gates 7-9** expand into VTEP / active-active multi-homing / IRB. Big
  investments gated by market demand, not technical readiness.

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
| RFC 7432 RR role | ~70-75% |
| Production-ready RR for a SONiC/FRR fabric | ~78-82% |
| Full RFC 7432 daemon (RR + VTEP + multi-homing + IRB) | ~22-26% |

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

### Gate 4 — Multi-homing reflection (Type 1 + Type 4)

Status: after Gate 1 · Estimate: ~3-5 days · Blockers: Gate 1

Unlocks: active-active ToR deployments. Two VTEPs share an ESI
(`es-id type 0 00:11:22:33:44:55:66:77:88:99`); rustbgpd reflects Type 1
EAD-per-ES, EAD-per-EVI, and Type 4 ES routes unchanged; third VTEP runs
its own DF election correctly against the reflected inputs.

Key principle: the RR does not *execute* DF election, it just must not
corrupt the inputs. This makes Gate 4 cheaper than it sounds.

| Task | File / location |
|------|----------------|
| 3-VTEP topology with shared ESI on VTEP-A and VTEP-B | `tests/interop/m32-evpn-multihome-frr.clab.yml` (new) |
| FRR configs with `evpn mh es-id` on two VTEPs | `tests/interop/configs/frr-bgpd-m32-*.conf` (new) |
| Test: verify reflected Type 1 EAD and Type 4 ES are byte-identical | `tests/interop/scripts/test-m32-evpn-multihome-frr.sh` |
| Test: VTEP-C's DF election picks expected DF | (vtysh poll) |

---

### Gate 5 — Scale validation

Status: after Gates 1-4 · Estimate: ~3-5 days · Blockers: Gates 1-4

Unlocks: the production-ready claim. bgperf2-style harness: 50k Type 2
routes (e.g. 10k VNIs × 5 MACs each), 1000/sec churn, 5-minute sustained.
Assertions: CPU < 50% on one core, memory bounded, no dropped messages,
convergence time measurable.

This is where the architectural claims (FlowSpec-pattern parallel tables,
`Arc<Vec<PathAttribute>>` intern, secondary indexing) get validated for
the new family.

| Task | File / location |
|------|----------------|
| bgperf2 EVPN generator (or extend existing) | `bench/bgperf2-evpn/` (new) |
| Scale test harness (50k routes + churn) | `bench/bgperf2-evpn/scenarios/` (new) |
| Publish numbers in BENCHMARKS.md | `docs/BENCHMARKS.md` |
| Fix any hot-path regressions surfaced | tbd |

---

### Gate 6 — Controller-injection gRPC

Status: optional after Gate 5 · Estimate: ~1-2 weeks · Blockers: none

Unlocks: SDN controllers / orchestration systems pushing EVPN routes
directly into the RR via `AddEvpnRoute` / `DeleteEvpnRoute` gRPC.
Relatively cheap once the RR plumbing is solid.

| Task | File / location |
|------|----------------|
| Replace `InjectEvpn` `unimplemented!()` stub in RibUpdate | `crates/rib/src/update.rs` |
| `handle_inject_evpn` / `handle_withdraw_evpn` in RibManager | `crates/rib/src/manager/mod.rs` |
| `RouteOrigin::Local` support for EVPN (mirrors FlowSpec injection) | `crates/rib/src/route.rs` |
| Proto: `AddEvpnRouteRequest` / `DeleteEvpnRouteRequest` + RPCs | `proto/rustbgpd.proto` |
| `InjectionService` methods + validation | `crates/api/src/injection_service.rs` |
| `bgpctl evpn add`/`delete` subcommands | `crates/cli/src/commands/evpn.rs` |
| End-to-end test: inject via gRPC, observe reflection | `crates/rib/src/manager/tests.rs` |

---

### Gate 7 — VTEP mode (Phase 2)

Status: strategic decision · Estimate: ~4-6 weeks · Blockers: Gates 1-5

Unlocks: rustbgpd running on a leaf itself — local EVI/VRF/VNI config,
MAC learning from the kernel FDB (netlink monitor), local route
origination, local withdrawal on MAC aging.

Why gated on demand: SONiC/FRR leaves do this well today. Rustbgpd
competing with FRR for the VTEP role is a meaningful strategic expansion,
not a tactical feature. Only worth it if there's a specific use case
(pure-Rust leaf, better API story, etc.) that justifies the scope.

Scope sketch:

| Task | File / location |
|------|----------------|
| `[[evpn_instances]]` config: EVI ↔ L2VNI ↔ bridge mapping | `src/config/schema.rs` |
| Netlink client for kernel FDB monitoring | new crate? `crates/netlink/` |
| Local MAC table (MAC → next-hop + VNI + sequence) | `crates/rib/src/evpn_local.rs` (new) |
| Type 2 origination on MAC learn | RibManager handler |
| Type 2 withdrawal on MAC age-out | RibManager handler |
| Type 3 IMET origination per L2VNI | — |
| Type 5 IP Prefix origination per L3VNI | — |
| Anti-spoofing, MAC move sequence management | — |
| Kernel VXLAN interface config generator? | ops question — maybe not |

---

### Gate 8 — Multi-homing execution, DF election

Status: after Gate 7 · Estimate: ~3-4 weeks · Blockers: Gate 7

Unlocks: rustbgpd as an active-active VTEP. DF election (RFC 7432 §8 +
RFC 8584), aliasing via Type 1 EAD-per-EVI, split-horizon using the
ESI Label extended community, backup-path selection.

Ties directly into Gate 7 — no value without local VTEP state.

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
Gate 4 (multi-homing)            ── ships "production-ready RR for SONiC/FRR fabric"
Gate 5 (scale)                   ── ships "production-ready at 10k+ MAC scale"
Gate 6 (controller inject)       ── ships "SDN-integratable"
───────────── decision point ─────────────
Gate 7 (VTEP mode)               ── big strategic expansion
Gate 8 (multi-homing execution)  ── depends on Gate 7
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

## Out of Scope (explicit non-goals for Gates 1-5)

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
