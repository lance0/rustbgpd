# Interop Test Results

Tracks interop validation against real BGP implementations. Updated with
every milestone. "Tested" means validated by a documented containerlab
or privileged-netns procedure, not "someone tried it once." CI-gated rows
are called out explicitly.

> For the end-to-end install + lifecycle walkthrough (containerlab
> quick-start with `m0-frr.clab.yml` is in there), see
> [`deployment.md`](deployment.md).

> For the consolidated operator-facing proof index that rolls interop,
> dataplane, benchmark, memory, and soak receipts together, see
> [`OPERATIONAL_PROOF.md`](OPERATIONAL_PROOF.md).

---

## Test Matrix

### CI coverage

The hosted `.github/workflows/interop.yml` path gates the following
foundation interop milestone scenarios on every PR (the rest of the
matrix below runs on the hosted kernel-dataplane workflow or manual gates).

- **Foundation** — wire-protocol + core RIB / refresh / policy: **M1**, **M13**, **M15**.
- **Address-family + topology** — MP-BGP, RR, multi-path, BGP-LS reflection,
  VPNv4 reflection, RT-Constrain filtering, ORR divergent-best: **M10**,
  **M14**, **M17**, **M73**, **M74**, **M75**, **M76**.
- **Operational + security** — BMP, transport security, FlowSpec: **M22**, **M24**, **M25**.
- **BGP Roles + OTC** — RFC 9234 role negotiation and Only-To-Customer leak prevention against an FRR 10.3.1 peer: **M55**.
- **Outbound Route Filtering** — RFC 5291/5292 receive-side prefix ORF against an FRR 10.3.1 peer: **M57**.
- **EVPN + SIGHUP** — control-plane sanity, MAC reflection, policy soft-reset: **M29**, **M30**, **M34**.
- **Graceful Shutdown** — receiver/initiator coverage across unicast, FlowSpec, and EVPN: **M35**, **M35b**, **M35c**.
- **BLACKHOLE FIB discard** — RFC 7999 receiver scoping plus opt-in kernel discard install / withdraw: **M41**.
- **gRPC/gNMI + EVPN injection** — ADR-0064 mTLS tier enforcement, ADR-0070 gNMI / OpenConfig telemetry + Set, gNMI Subscribe ON_CHANGE, and EVPN Type 5 control-plane injection: **M44**, **M54**, **M56**, **M45**.
- **Inbound RIB backpressure** — ADR-0078 hold-timer survival under an artificially stalled RIB: **M63**.
- **IPv6-only peering** — a session with `disable_ipv4_unicast` negotiating only IPv6 unicast against an FRR 10.3.1 peer: **M64**.

Plus one **kernel-primitive** PR-CI gate that lives in `ci.yml`
rather than `interop.yml` (no containerlab — single Docker
container exercises a real Linux bridge inside a netns):

- **EVPN BUM-flood-suppression primitive** — runs the spike
  (`bum_filter_spike_validates_kernel_primitive`) and the Rust
  netlink round-trip (`linux_dataplane_set_bum_port_flags_round_trip`)
  via the harness at `crates/evpn-linux/tests/docker/`. Validates
  the kernel-side `IFLA_BRPORT_*_FLOOD` triplet on every PR so a
  netlink-attribute encoding regression can't slip past
  PR-CI. Runs in roughly 1-2 min warm.

The hosted `kernel-dataplane` workflow adds the privileged Linux
coverage that needs containerlab, kernel modules, or real netns route tables:
**M36**,
**M37**, **M37+IP**, **M38**, **M39**, **M39b**, **M40**, **M42**, **M46**,
**M47**, **M48**, **M49**, **M50**, **M51**, **M52**, **M53**, **M58**, **M60**, **M61**, **M62**, **M65**, **M66**, **M67**, **M68**, **M69**, **M70**, **M71**, **M72**, the conditional
**M43** TCP-AO smoke, and the Docker netns selectors (such as
`fdb_nhg` / `fib_runtime` / `bfd_runtime` / `dataplane_vlan_fdb` /
`svd_fdb_vni` / … — see the `netns` job in `kernel-dataplane.yml` for the full
set). Those jobs run on PRs, pushes to `main`, nightly schedule, and
manual dispatch on GitHub-hosted `ubuntu-latest` runners.
The current hosted runner advertises `CONFIG_TCP_AO=y`, so M43 runs the
real BIRD 3.2.1 TCP-AO topology. The workflow still probes the selected
runner kernel first; a future runner without TCP-AO support reports a warning
and skips only that topology.

#### M-series proof quality contract

A `Tested (Mxx)` receipt is only as strong as the evidence its driver asserts.
Proof-critical checks should be target-scoped to the exact peer, prefix or MAC,
VNI or VLAN, VRF or table, protocol or metric, next hop, or kernel object under
test. Broad text scans are acceptable for diagnostics and liveness checks, but
not as the decisive proof for route, FDB, nexthop, or programming state.

If a row claims kernel dataplane proof, the pass condition must include kernel
evidence such as route, FDB, nexthop, VLAN/VNI, or netns state. It must not
fall back to control-plane-only BGP or gRPC evidence when the receipt claims
kernel programming. Drivers should be rerunnable and cleanup-safe: setup and
teardown must not leave owned routes, FDB rows, nexthops, prober files, or
stale topology state behind. Each proof should include a non-vacuity sentinel:
first show the negative, unresolved, or uniquely injected target state, then
prove the positive state and final withdrawal or cleanup.

The remaining interop scripts are local / manual gates because they
need substantial wall-clock (M11/M16 GR/LLGR, M33 scale soak),
additional fixtures (StayRTR / mock RTR v2 server), or
broader platform-diversity validation (BIRD and non-CI GoBGP cases beyond
the protected BIRD TCP-AO smoke and M73 BGP-LS receipt).

| Peer | Version | Topology | Status | Notes | Known Quirks | NOTIFICATIONs Observed |
|------|---------|----------|--------|-------|--------------|------------------------|
| FRR (bgpd) | 10.3.1 | `tests/interop/m0-frr.clab.yml` | Tested (M0) | All 5 tests pass | Needs `no bgp ebgp-requires-policy` | Cease on `clear bgp *` |
| FRR (bgpd) | 10.3.1 | `tests/interop/m1-frr.clab.yml` | Tested (M1, M2) | UPDATE/RIB + best-path | FRR advertises 3 prefixes via `network` | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m3-frr.clab.yml` | Tested (M3) | 3-node redistribution | 2× FRR peers, route injection | — |
| BIRD | 2.0.12 | `tests/interop/m0-bird.clab.yml` | Tested (M0) | All 5 tests pass | Needs `/run/bird` dir; sends empty UPDATE on establish | Cease/Admin Shutdown + Cease/Admin Reset |
| FRR (bgpd) | 10.3.1 | `tests/interop/m4-frr.clab.yml` | Tested (M4) | 10-peer dynamic mgmt | 8 static + 2 dynamic peers | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m10-frr-ipv6.clab.yml` | Tested (M10) | Dual-stack MP-BGP | IPv4 session, IPv6 via MP_REACH_NLRI | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m11-gr-frr.clab.yml` | Tested (M11) | Graceful Restart (RFC 4724) | Short timers (30s restart, 30s stale) | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m12-ec-frr.clab.yml` | Tested (M12) | Extended Communities (RFC 4360) | RT:65002:100 via route-map | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m13-policy-frr.clab.yml` | Tested (M13) | Policy Engine (chains, actions) | 3-node: import chain + export deny/MED/prepend | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m14-rr-frr.clab.yml` | Tested (M14) | Route Reflector (RFC 4456) | 3-node iBGP: RR + 2 clients | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m15-rr-frr.clab.yml` | Tested (M15) | Route Refresh (RFC 2918) | SoftResetIn via gRPC | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m16-llgr-frr.clab.yml` | Tested (M16) | LLGR (RFC 9494) | GR→LLGR transition, stale clearing | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m17-addpath-frr.clab.yml` | Tested (M17) | Add-Path (RFC 7911) | Multi-path send, distinct path_ids | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m18-extnexthop-frr.clab.yml` | Tested (M18) | Extended Next-Hop (RFC 8950) | Dual-stack, IPv6 NH for IPv4 | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m19-routeserver-frr.clab.yml` | Tested (M19) | Transparent Route Server | No ASN prepend, NH preservation | Needs per-neighbor `no enforce-first-as` |
| FRR (bgpd) | 10.3.1 | `tests/interop/m20-privateas-frr.clab.yml` | Tested (M20) | Private AS Removal | remove/all/replace modes | — |
| FRR + StayRTR | 10.3.1 + latest | `tests/interop/m21-rpki-frr.clab.yml` | Tested (M21) | RPKI origin validation via RTR | StayRTR serves static VRP JSON | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m22-flowspec-frr.clab.yml` | Tested (M22) | FlowSpec inject + distribute + withdraw | FRR receives only (cannot originate) | — |
| GoBGP | 4.3.0 | `tests/interop/m23-gobgp.clab.yml` | Tested (M23) | Bidirectional route exchange | Custom image: `docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop/` | — |
| GoBGP ×2 | 4.6.0 | `tests/interop/m73-bgpls-reflection-gobgp.clab.yml` | Tested (M73) | ADR-0077 BGP-LS reflection/export real-peer receipt | Three-node iBGP topology: GoBGP source -> rustbgpd RR -> GoBGP sink, all negotiating BGP-LS (`AFI 16388 / SAFI 71`). The source injects one deterministic RFC 9552 Node NLRI (`node-name m73-node`) through the GoBGP CLI; the driver asserts rustbgpd exposes it through `rbgp rib bgpls` with non-empty opaque payload and BGP-LS Attribute bytes, the sink receives the reflected route with the Node-name BGP-LS Attribute intact, and source withdrawal removes the route from rustbgpd and the sink. This proves the SAFI 71 reflection and withdrawal path specifically; a real-peer SAFI 72 (BGP-LS VPN) reflection receipt, local topology production, Add-Path, and GR/LLGR stale preservation remain deferred. SAFI 72 reflection shares the SAFI 71 pipeline and is implemented, but is not yet interop-proven. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). | Dedicated image: `docker build -t gobgp:bgpls -f tests/interop/Dockerfile.gobgp-bgpls tests/interop` |
| GoBGP ×2 | 3.37.0 | `tests/interop/m74-vpnv4-reflection-gobgp.clab.yml` | Tested (M74) | ADR-0077 VPNv4 (SAFI 128) route-reflection real-peer receipt | Three-node iBGP topology: GoBGP source -> rustbgpd RR -> GoBGP sink, all negotiating `l3vpn-ipv4-unicast` (AFI 1 / SAFI 128). The source injects two VPNv4 routes with distinct RDs (65000:1 / 65000:2) but the same inner prefix — proving RD-scoped route identity — each with an MPLS label and a Route Target. The driver asserts rustbgpd exposes both through `rbgp rib vpn` with RD / label / RT intact, the sink receives the reflections with **label values, RD, RT, and next-hop (the source address) preserved verbatim** plus correct RFC 4456 ORIGINATOR_ID and CLUSTER_LIST, single-RD withdrawal propagates while the sibling RD survives, and the RR installs nothing into any dataplane (`ip -M route` empty, no VPN-derived kernel routes) per ADR-0077 §6. VPNv6 shares the SAFI-128 pipeline and is implemented but not yet interop-proven; Add-Path and GR/LLGR stale preservation for SAFI 128 remain deferred. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). | Stock `gobgp:interop` image |
| GoBGP ×3 | 3.37.0 | `tests/interop/m75-rtc-vpnv4-filter-gobgp.clab.yml` | Tested (M75) | RFC 4684 RT-Constrain (SAFI 132) VPNv4 reflection-filtering real-peer receipt | Four-node iBGP topology: GoBGP source (VRFs blue RT 65001:100 + red RT 65001:200, one VPNv4 route each) -> rustbgpd RR -> an RTC-negotiating GoBGP sink (VRF blue only) plus a second sink WITHOUT the `rtc` family. The driver asserts both RTC peers **accept the RR's self-originated default RTC NLRI into adj-in** (the wire pin that it carries the mandatory empty AS_PATH — without it GoBGP treat-as-withdraws the UPDATE and PEs suppress their VPN routes toward the RR), the RR consequently receives both VPN routes, `rbgp rib rtc` exposes the local default plus the clients' /96 membership NLRIs (Loc-RIB best-path-only view), RTC NLRIs themselves reflect between clients with ORIGINATOR_ID, **strict filtering** (the RTC sink receives exactly the blue route and never red), the non-RTC sink receives BOTH routes unfiltered (SAFI 132 not negotiated ⇒ no filtering), widening / narrowing the sink's membership delivers / withdraws the red route with **zero session flaps**, an injected default RTC NLRI matches all RTs and its withdrawal narrows back, the RR installs nothing into any dataplane, and the RR's UPDATE counters stay quiet after convergence (no GoBGP-#1630-style RTC reflection storm). iBGP-only on purpose (GoBGP's eBGP RTC is broken upstream, gobgp #2427); membership churn drives `gobgp global rib add/del -a rtc` because GoBGP 3.37.0 segfaults on `vrf del` while a default RTC NLRI sits in its table. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). | Stock `gobgp:interop` image |
| GoBGP ×5 | 4.6.0 | `tests/interop/m76-orr-divergent-best-gobgp.clab.yml` | Tested (M76) | RFC 9107 Optimal Route Reflection divergent-best real-peer receipt | Six-node iBGP topology: a **linkstate-only** GoBGP source, two GoBGP PEs, and two GoBGP clients around a rustbgpd RR. The source injects a four-link BGP-LS square (A→X=1, A→Y=10, B→X=10, B→Y=1) via `gobgp global rib add -a ls link` with byte-identical node-descriptor tuples so both links into a node intern to one graph node; the PEs announce the SAME prefix with next-hops that resolve to X and Y; the clients are pinned to vantages A / B via `orr_vantage`. The driver asserts `rbgp topology` exposes the square (4 nodes / 4 links) and `rbgp orr` resolves both vantages with their bound peers; **the divergence** — for one prefix, c1's best carries NEXT_HOP 10.0.9.1 / ORIGINATOR_ID pe1 while c2's carries 10.0.9.2 / pe2; a topology-driven flip (re-adding A→X at metric 100) moves ONLY c1 with **zero session flaps and zero UPDATEs toward the unaffected client** (quiet-counter pin); withdrawing all four links unresolves both vantages and BOTH clients converge to the identical standard best (deterministic lowest-peer-address PE); re-injecting the square restores the divergence; the RR installs nothing into any dataplane; and the linkstate-only source session **never flaps across the run** — the wire-level regression pin for the implicit-IPv4 negotiation fix (#632), which this topology exposed (classic-NLRI IPv4 UPDATEs leaked to an ls-only peer hard-reset the GoBGP session). **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). | Dedicated image: `docker build -t gobgp:bgpls -f tests/interop/Dockerfile.gobgp-bgpls tests/interop` |
| FRR + BMP receiver | 10.3.1 | `tests/interop/m24-bmp-frr.clab.yml` | Tested (M24) | BMP Initiation, PeerUp, RouteMonitoring | Python TCP receiver validates message types and ordering | — |
| FRR (2x) | 10.3.1 | `tests/interop/m25-md5-gtsm-frr.clab.yml` | Tested (M25) | TCP MD5 + GTSM / TTL security | Two peers: MD5 auth + GTSM separately | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m26-cease-frr.clab.yml` | Tested (M26) | Cease/Max-Prefixes subcode 1 | max_prefixes=2, FRR sends 3 | Cease/Maximum Number of Prefixes Reached |
| FRR (2x) + RTR v2 | 10.3.1 | `tests/interop/m27-aspa-rtr2.clab.yml` | Tested (M27) | ASPA/RTR v2: validation states, best-path preference | Python RTR v2 mock server (StayRTR lacks ASPA); 2 FRR peers for best-path tiebreak | — |
| FRR + RTR v2 | 10.3.1 | `tests/interop/m59-aspa-roles-rtr2.clab.yml` | Tested (M59) | Role-aware ASPA: downstream (customer-cone) verification (draft-ietf-sidrops-aspa-verification-25 §5.5, ADR-0049) | rustbgpd (AS 65001) configures a local BGP Role of `customer` toward the FRR peer (AS 65003, its provider), so routes received from it are verified with the **downstream** procedure rather than upstream (M27 covers the roleless/upstream half). FRR advertises two prefixes with crafted AS_PATHs and the Python RTR v2 mock feeds ASPA records that make one downstream-Valid and one downstream-Invalid: `192.168.20.0/24` `[65003, 65011, 65010]` → an unbroken up-ramp ⇒ `aspaState = valid`; `192.168.21.0/24` `[65003, 65007, 65008]` → neither up- nor down-ramp covers (65008 and 65003 each attest only 65099) ⇒ `aspaState = invalid`. Driver asserts both verdicts via `RibService/ListReceivedRoutes`. Local-only, like M21/M27 (RTR-cache-dependent; not in hosted CI). | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m28-dynamic-frr.clab.yml` | Tested (M28) | Dynamic prefix-based neighbors | No static neighbor — FRR auto-accepted via `[[dynamic_neighbors]]`; auto-removed on disconnect | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m29-evpn-rr-frr.clab.yml` | Tested (M29) | EVPN Route Reflector capability sanity (RFC 7432) | L2VPN/EVPN capability + session + gRPC `ListEvpnRoutes`. | — |
| FRR (bgpd, 2×) | 10.3.1 | `tests/interop/m30-evpn-type2-frr.clab.yml` | Tested (M30) | EVPN Type 2 MAC reflection end-to-end (RFC 7432 §7.2) | 3-node topology with kernel VXLAN + bridge per VTEP; MAC injected via `bridge fdb add` on VTEP-A propagates through rustbgpd RR to VTEP-B within ~30 s; asserts ORIGINATOR_ID + CLUSTER_LIST on reflected UPDATE, next-hop preservation, VXLAN encap community, and withdrawal propagation | CI-gated alongside M29 (`.github/workflows/interop.yml`) |
| FRR (bgpd) | 10.3.1 | `tests/interop/m30b-evpn-type5-frr.clab.yml` | Tested (M30b) | EVPN Type 5 IP Prefix Route origination (RFC 9136) | Single-VTEP topology with kernel VRF + L3VNI + bridge + SVI + VXLAN. FRR's `vrf1` (L3VNI 100) advertises 192.0.2.1/32 as a Type 5 NLRI with explicit RD/RT 65000:100; rustbgpd's gRPC `ListEvpnRoutes` surfaces the route with correct RD, prefix, next-hop, VNI label, RT extended community, and VXLAN encap (`tunnel_type=8`); `ip addr del` on the VRF loopback propagates as a withdrawal. RR-reflection of Type 5 (2-VTEP variant) tracked as M30c follow-up. | Manual only — Azure kernel 6.17.0-1010-azure on ubuntu-latest ships without the `vrf` module, so L3VNI binding fails on hosted runners |
| FRR (bgpd, 3×) | 10.3.1 | `tests/interop/m31-evpn-mac-mobility-frr.clab.yml` | Tested (M31) | EVPN MAC mobility + sticky preservation (RFC 7432 §15.1, §7.7) | 4-node topology (RR + 3 VTEPs). MAC moved from VTEP-A to VTEP-C; VTEP-B's best path flips and Mobility sequence strictly increments. Sticky MAC on VTEP-A is not displaced by non-sticky on VTEP-C. | — |
| FRR (bgpd, 3×) | 10.3.1 | `tests/interop/m32-evpn-multihome-frr.clab.yml` | Tested (M32) | EVPN multi-homing Type 1 EAD + Type 4 ES reflection (RFC 7432 §8) | VTEP-A and VTEP-C share an ESI on a bond ES interface (same `evpn mh es-id` + `es-sys-mac`); VTEP-B observer sees both VTEPs' Type 4 ES + Type 1 EAD-per-EVI routes through the RR with correct RFC 4456 attributes (ORIGINATOR_ID + CLUSTER_LIST). RR does not execute DF election — just reflects inputs. | — |
| (synthetic) | — | `tests/interop/m32b-evpn-ead-synthetic.clab.yml` | Tested (M32b) | EVPN Type 1 EAD-per-EVI reflection with synthetic ESI (no kernel bond) | Manual-only sibling to M32. Uses synthetic EAD-per-EVI advertisements injected via gRPC instead of FRR's bond ES, so it runs without the bond-ES kernel module CI lacks. | — |
| In-tree evpn-load (2 testers + 1 monitor) | in-tree HEAD | `tests/interop/m33-evpn-scale.clab.yml` | Tested (M33) | EVPN RR scale validation — 50k Type 2 routes + 60 s of 1000/sec churn | 2 synthetic iBGP testers originate 25k Type 2 each via the in-tree `bench/evpn-load` generator; monitor counts reflected UPDATEs and asserts initial convergence < 60 s, post-churn count within ±tester-batch (40) of 50,000, observed withdrawal events ≥ ½·`CHURN_RATE`·`CHURN_DURATION` (proves churn actually fired), tester peers stay Established without flaps, and gRPC health survives. No third-party daemon in the measurement path. | — |
| FRR (bgpd) | 10.3.1 | `tests/interop/m34-policy-soft-reset-frr.clab.yml` | Tested (M34) | SIGHUP policy soft-reset auto-fire | Single-peer plain BGP topology. FRR advertises 3 prefixes; rustbgpd starts with permit-all named policy + chain. Test SIGHUPs a config that adds `deny 192.168.1.0/24` to the same definition and asserts (a) the session stays Established (no flap — auto-refresh path issues a Route Refresh, not a session reset), and (b) 192.168.1.0/24 is removed from the RIB while the other two prefixes remain. Guards the auto-fire inside `PeerManager::update_runtime_policies` — a permit→deny edit on an established peer's effective import chain previously silently left forbidden routes flowing. | CI-gated alongside M29/M30 (`.github/workflows/interop.yml`) |
| FRR (bgpd) | 10.3.1 | `tests/interop/m35-graceful-shutdown-frr.clab.yml` | Tested (M35) | RFC 8326 BGP Graceful Shutdown — both legs end-to-end | Single-peer topology. **Receiver leg**: FRR's outbound route-map tags `192.168.1.0/24` with the `GRACEFUL_SHUTDOWN` community (`65535:0`); rustbgpd's `[global] honor_graceful_shutdown = true` appends an implicit chain-tail rule that demotes `local_pref` to 0. Test asserts (a) the tagged prefix carries the community in `ListReceivedRoutes`, (b) the untagged prefix doesn't, (c) the tagged prefix has `local_pref_attr = 0` (explicit attribute, proving the implicit rule fired — distinguishing from EBGP's no-LOCAL_PREF default), and (d) the untagged prefix has no `local_pref_attr`. **Initiator leg**: test injects `172.16.0.0/24` *first* (steady state, no community), then toggles `NeighborService.SetGracefulShutdown { enabled: true }` via gRPC with no route churn; FRR's `show ip bgp ... json` must show the now-existing path with `community.list ⊇ ["gracefulShutdown"]` (or numeric `65535:0`). This proves `RibUpdate::RefreshPeerOutbound` actually force-emits routes already in `AdjRibOut` (bypasses the equality suppression). **Clear leg**: toggle off via the same gRPC path, again no delete+re-add; FRR no longer sees the community. Defends both RFC 8326 §4 receiver behavior and §3 initiator behavior on the wire, including the runtime toggle-after-advertise path. | CI-gated alongside M29/M30/M34 (`.github/workflows/interop.yml`) |
| FRR (bgpd) | 10.3.1 | `tests/interop/m35b-graceful-shutdown-flowspec-frr.clab.yml` | Tested (M35b) | RFC 8326 initiator leg on FlowSpec | Single-peer FlowSpec topology. Test injects an IPv4 FlowSpec rule first, verifies FRR receives it in steady state, toggles `NeighborService.SetGracefulShutdown { enabled: true }` without delete+re-add, then captures the BGP UPDATEs on the wire inside the FRR container and asserts the existing rule is re-emitted with the GRACEFUL_SHUTDOWN community (`0xffff0000`). Toggle-off captures the clear-side re-emit and asserts the community is gone. Pins the FlowSpec outbound advertise site for `attach_graceful_shutdown_if_enabled`. The on-the-wire approach is necessary because FRR 10.3.1's FlowSpec JSON/text views do not expose standard communities; the capture is a per-(src,sport,dst,dport) TCP-stream-reassembling Python parser (`AF_PACKET` raw socket on `eth1`) that buffers each flow's payload and only counts complete BGP UPDATEs from the head of the buffer, so a community attribute that lands across a TCP segment boundary doesn't cause the test to flake under CI load. | CI-gated alongside M29/M30/M34/M35 (`.github/workflows/interop.yml`) |
| FRR (bgpd) | 10.3.1 | `tests/interop/m35c-graceful-shutdown-evpn-frr.clab.yml` | Tested (M35c) | RFC 8326 initiator leg on EVPN | Single-peer L2VPN/EVPN topology. Test injects an EVPN Type 2 route first, verifies FRR receives it in steady state, toggles `NeighborService.SetGracefulShutdown { enabled: true }` without delete+re-add, then captures the BGP UPDATEs on the wire inside the FRR container and asserts the existing Type 2 route is re-emitted with the GRACEFUL_SHUTDOWN community (`0xffff0000`). Toggle-off captures the clear-side re-emit and asserts the community is gone. Pins the EVPN outbound advertise site for `attach_graceful_shutdown_if_enabled`. Uses the same per-flow TCP-stream-reassembling Python capture as M35b — FRR's L2VPN EVPN JSON view likewise does not expose standard communities, so packet capture (with TCP reassembly so a community split across segments still parses cleanly) is the only reliable wire-level check. | CI-gated alongside M29/M30/M34/M35 (`.github/workflows/interop.yml`) |
| FRR (bgpd) | 10.3.1 | `tests/interop/m41-blackhole-frr.clab.yml` | Tested (M41) | RFC 7999 BLACKHOLE receiver scoping + opt-in FIB discard | Single-peer EBGP topology. FRR's outbound route-map tags `203.0.113.66/32` and `198.51.100.0/24` with the `BLACKHOLE` community (`65535:666`) and leaves `203.0.113.67/32` untagged. rustbgpd runs with `[global] honor_blackhole = true` and `[global] install_blackhole_discard = true`; the driver asserts tagged routes in `ListReceivedRoutes` carry both `BLACKHOLE` and `NO_ADVERTISE`, the untagged route carries neither, `ListBlackholeDiscards` reports the host route as `installed`, the broad prefix as `rejected/broad_prefix`, the rustbgpd container FIB has a kernel `blackhole 203.0.113.66` route, the untagged and broad prefixes do not install, and FRR withdrawal removes the kernel discard. **In CI** on every push and PR via `.github/workflows/interop.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m42-fib-runtime-frr.clab.yml` | Tested (M42) | ADR-0061 opt-in general unicast Linux FIB runtime | Single-peer EBGP topology. FRR advertises `203.0.113.42/32` and `198.51.100.0/24`; rustbgpd runs with `[[fib_tables]] name="edge", table_id=1000, metric=200, families=["ipv4_unicast"]`. The driver asserts `ListFibRoutes` reports the selected host route as `installed/owned`, the rustbgpd container's table 1000 has `203.0.113.42 via 10.0.0.2 proto bgp metric 200`, an existing `proto static` table-1000 row for `198.51.100.0/24` is preserved and reported as `rejected/foreign_route_exists`, FRR withdrawal removes only the daemon-owned route, and SIGTERM-triggered coordinated shutdown drains the owned route while preserving the foreign row. The privileged netns selector covers the companion drift case: external replacement of an owned row is reported as `owned_route_drifted`, ownership is released, and a later withdraw does not delete the replacement. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml` on PRs, pushes to `main`, nightly schedule, and manual dispatch on GitHub-hosted `ubuntu-latest` runners. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m58-fib-table-crud-frr.clab.yml` | Tested (M58) | ADR-0061 runtime `[[fib_tables]]` CRUD over gRPC / CLI | Companion to M42's startup-configured table path. The driver starts with one configured table, then drives `SetFibTable`, `DeleteFibTable`, and `ListFibTables` against a real kernel through `rbgp fib-table`: add a second table and observe back-fill, change the table key (`table_id` / `metric`) and observe old rows withdraw plus new rows install, restart and prove the persisted table survives, delete a table and prove only that table's daemon-owned rows withdraw, and assert `NOT_FOUND` for deleting a missing name. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m57-orf-frr.clab.yml` | Tested (M57) | ADR-0075 receive-side Address-Prefix ORF (RFC 5291/5292) | rustbgpd (AS 65001) is the route server with `prefix_orf_receive = true` for the FRR neighbor; three prefixes are injected into its Loc-RIB via `InjectionService.AddPath`. FRR (AS 65002) negotiates `capability orf prefix-list both` and has an inbound `prefix-list ORF-IN in` permitting only `10.10.1.0/24`, which it pushes to rustbgpd as an ORF. **Phase 1:** the driver asserts FRR receives *only* `10.10.1.0/24` — the other two prefixes are filtered out by the ORF before being advertised (and the RFC 5291 §6 gate held the family until FRR's ORF arrived). **Phase 2:** the prefix-list is widened to permit-all and the ORF re-sent via `clear bgp 10.0.0.1 in prefix-filter`; the driver asserts FRR then receives all three prefixes (re-expansion / REMOVE-ALL + ADD). Validates implicit-deny semantics and type-64 negotiation against FRR. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). |
| FRR (bgpd) | 10.3.1 | tests/interop/m64-ipv6-only.clab.yml | Tested (M64) | IPv6-only peering — session with disable_ipv4_unicast negotiating only IPv6 unicast | rustbgpd peers with an FRR 10.3.1 peer over an IPv6-only session; only IPv6 unicast is negotiated (no IPv4 AFI/SAFI). **Hosted CI** in .github/workflows/interop.yml. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m63-stalled-rib-hold-timer.clab.yml` | Tested (M63) | ADR-0078 inbound transport→RIB backpressure — hold-timer survival under a stalled RIB | Single-peer EBGP topology with hold_time 9 s (keepalive 3 s) on both sides. rustbgpd starts with two test-only fault-injection envs: `RUSTBGPD_TEST_RIB_INGEST_STALL_MS=12000` (the RIB manager sleeps 12 s before handling each `RoutesReceived` batch) and `RUSTBGPD_TEST_RIB_CHANNEL_CAPACITY=2` (shrinks the transport→RIB channel so a modest flood saturates it). FRR floods 4000 /32 Null0 statics in 8 waves of 500 spaced 2 s apart — the wave spacing lower-bounds the UPDATE batch count regardless of NLRI packing, so the guaranteed stall (≥ 96 s) dwarfs 2× the negotiated hold time and ≥ 4 batches overflow the 2-slot channel, parking the session task on the blocking delivery for longer than the hold time per batch. The driver asserts: the session stays Established on both ends at 1 s grain through a 40 s survival window inside the stall (FRR via vtysh, capture-only-on-success; rustbgpd via `GetNeighborState`, where `stale=true` readings — the parked session task can't answer the bounded QueryState round-trip — count as unknowns, not verdicts); `bgp_inbound_rib_backpressure_total` > 0 (the channel really filled and the block-never-drop path ran); after the drain the RIB holds **exactly** 4000 routes (the never-drop receipt); and zero flaps from both vantage points (`flap_count`, `bgp_session_flaps_total`, FRR `connectionsEstablished`/`connectionsDropped`). `bgp_hold_timer_rearmed_pending_input_total` is logged informationally only — expected 0 in this shape, because the FSM restarts the hold timer when each parked delivery completes, so the select loop never observes an expired deadline; the pending-input re-arm path stays pinned by the transport unit tests. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). |
| FRR (bgpd) ×2 | 10.3.1 | `tests/interop/m50-fib-ecmp-frr.clab.yml` | Tested (M50) | ADR-0066 unicast multipath/ECMP FIB install | Two FRR peers in the same AS (65002), one per point-to-point link, each originate `203.0.113.50/32` with an identical `AS_PATH`. rustbgpd (AS 65001) runs with `[[fib_tables]] table_id=1000, metric=200, maximum_paths=2`. The driver asserts the rustbgpd container's table 1000 holds `203.0.113.50/32` as a kernel multipath route with both `nexthop via 10.0.0.2` and `nexthop via 10.0.1.2` (proto bgp, metric 200) and that `ListFibRoutes` reports two `next_hops`; then withdraws one FRR's prefix and asserts the route collapses to the single surviving gateway (one `next_hop`, no `nexthop` stanzas); then re-advertises and asserts the two-way ECMP returns. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) ×2 | 10.3.1 | `tests/interop/m52-fib-ecmp-relax-frr.clab.yml` | Tested (M52) | ADR-0066 multipath-relax (`[global].multipath_relax`) | Two FRR peers in **different** ASes (frr1 AS 65002, frr2 AS 65003) each originate `203.0.113.52/32`, so as seen by rustbgpd the paths have equal `AS_PATH` *length* (1) but different ASNs — exact-`AS_PATH` grouping would not bundle them. rustbgpd (AS 65001) runs with `maximum_paths=2` and `[global] multipath_relax=true`. The driver asserts the prefix installs into table 1000 as a kernel two-way ECMP route with both `nexthop via 10.0.0.2` and `nexthop via 10.0.1.2` (proving relax groups the different-AS paths) and that `ListFibRoutes` reports two `next_hops`; then withdraws frr2 (AS 65003) and asserts collapse to the frr1 survivor; then re-advertises and asserts the relaxed two-way ECMP returns. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) ×2 | 10.3.1 | `tests/interop/m53-bgp-unnumbered-frr.clab.yml` | Tested (M53) | ADR-0069 BGP unnumbered / IPv6 link-local peering | rustbgpd (AS 65001) peers with two FRR interface neighbors over IPv6 link-local only: no IPv4 addresses are present on the fabric links. Both FRR peers advertise `198.51.100.53/32` using RFC 8950 Extended Next Hop over separate link-local sessions. The driver asserts rustbgpd's neighbor status carries both scoped identities, `ListReceivedRoutes` sees two paths, the Linux table 1000 route installs as ECMP via `fe80::2 dev eth1` and `fe80::3 dev eth2`, and `ListFibRoutes` reports two next-hops; then it withdraws frr2 and asserts the route collapses to the eth1 survivor, re-advertises and asserts two-way ECMP returns. It also injects `192.0.2.53/32` through rustbgpd and asserts both FRR peers receive it with a link-local next-hop, proving outbound unnumbered MP_REACH. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) ×2 | 10.3.1 | `tests/interop/m53-bgp-unnumbered-spike.clab.yml` | Tested (M53 spike) | ADR-0069 BGP unnumbered target-behavior observation | FRR interface peers establish over IPv6 link-local only with no IPv4 addresses on the fabric link, exchange IPv4 unicast routes whose visible next-hop is `fe80::/10`, and expose RFC 8950 Extended Next Hop in neighbor state. The spike captures IPv4 MP_REACH with a 32-byte IPv6 next-hop and does not observe Link-Local Next Hop capability 77. This is retained as target-behavior evidence; the production rustbgpd↔FRR gate is M53 above. |
| FRR (bgpd + bfdd) | 10.3.1 | `tests/interop/m51-bfd-frr.clab.yml` | Tested (M51) | ADR-0067 single-hop BFD + RFC 5882 BGP coupling | Single-peer EBGP topology with BFD enabled on both sides (FRR `bfdd`, fast profile: 300 ms × 3 ≈ 900 ms detection; BGP hold timer 90 s). rustbgpd (AS 65001) configures the neighbor with `bfd = { profile = "fast" }` (non-strict coupling); FRR (AS 65002) uses `neighbor … bfd profile fast`. The driver asserts BGP reaches Established **and** BFD reaches Up from both sides (`BfdService.GetBfdSessions` reports `BFD_SESSION_STATE_UP` and FRR `show bfd peers json` reports `status: up`), then kills FRR's `bfdd` (`killall -9 bfdd`, briefly re-killed so the down window is observable) and asserts rustbgpd's BFD goes Down and the RFC 5882 coupling tears the BGP session out of Established within a few detection windows — far faster than the 90 s hold timer, proving the coupling rather than a hold-timer expiry. `watchfrr` then restarts `bfdd`, and the driver asserts BFD + BGP both recover. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| BIRD | 3.2.1 | `tests/interop/m43-tcp-ao-bird.clab.yml` | Tested (M43) | ADR-0062 static-neighbor TCP-AO protected session | Single-peer EBGP topology. rustbgpd (AS 65001, 10.0.43.1) configures a static neighbor with `tcp_ao = { key = "interop-secret-m43", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }`; BIRD 3.2.1 (AS 65043, 10.0.43.2) uses `authentication ao` with the matching key and advertises `203.0.113.43/32`. The driver asserts BIRD reaches Established, rustbgpd receives the advertised route through `RibService.ListReceivedRoutes`, then restarts BIRD with a mismatched TCP-AO secret and asserts the route withdraws and the session does not re-establish within the fail-closed window. **Hosted kernel-dataplane CI** includes M43; the current hosted runner advertises `CONFIG_TCP_AO=y` and runs the topology, while the workflow keeps a warning-only skip guard for future runner kernels without TCP-AO support. |
| grpcurl (mTLS client) | n/a | `tests/interop/m44-grpc-tier-authz.clab.yml` | Tested (M44) | ADR-0064 gRPC tier authorization over native mTLS | Single rustbgpd node, no BGP peer — exercises the gRPC authorization boundary, not a routing session. `tests/interop/scripts/gen-m44-certs.sh` builds a CA, a server cert (`DNS:rustbgpd.local`), and four client certs whose `rustbgpd://` URI SANs map to roles via `[security.grpc.roles]` (`observer`, `automation`, `operator`, plus an unmapped `intruder`). The daemon runs `enforcement = "tier"` (the v0.24.0 default) with an mTLS gRPC listener. The driver presents each client cert to `grpcurl` (verifying the server cert against `-servername rustbgpd.local`) and asserts the per-tier contract: observer can `ListReceivedRoutes` but not `AddNeighbor`; automation can `AddNeighbor` but not `TriggerMrtDump`; operator can `TriggerMrtDump`; the unmapped principal is denied any RPC; and `bgp_grpc_authz_decisions_total` records the `role_tier_denied` / `principal_unmapped` labels. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). |
| gnmic (mTLS client) | 0.46.0 | `tests/interop/m54-gnmi-openconfig.clab.yml` | Tested (M54) | ADR-0070 gNMI / OpenConfig telemetry + Set over native mTLS | Single rustbgpd node, no BGP peer — exercises the collector-facing and operator-facing gNMI surface through the real `gnmic` client. The daemon serves `gnmi.gNMI` only on an mTLS-configured TCP listener; the driver presents the operator client certificate generated by `tests/interop/scripts/gen-m54-certs.sh`, verifies `Capabilities` reports gNMI `0.10.0`, the OpenConfig BGP modules, and `JSON` / `JSON_IETF`, reads the supported OpenConfig BGP global and neighbor `state` paths with `Get`, proves static numbered-neighbor `Set` add/delete plus peer-group and dynamic-neighbor-prefix Set persistence, asserts an undefined dynamic-neighbor peer-group is rejected with `InvalidArgument`, proves commit-confirmed confirm/cancel, asserts read-tier `Set` is denied and unsupported leaves return `Unimplemented`, and proves `Subscribe STREAM/SAMPLE` emits repeated snapshots for `global/state/router-id`. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). |
| gnmic (mTLS client) + FRR (bgpd) | 0.46.0 / 10.3.1 | `tests/interop/m56-gnmi-onchange-frr.clab.yml` | Tested (M56) | ADR-0070 deferral resolved / ADR-0072 follow-up — gNMI `Subscribe ON_CHANGE` (session-state only) | Two-node topology (rustbgpd ↔ FRR) with `[event_history].enabled = true`. After the peering reaches Established, the driver first asserts that `STREAM ON_CHANGE` on an unsupported leaf (`state/peer-as`) is rejected with `Unimplemented`. It then runs a short subscribe with no flap to validate the initial-snapshot scope: the captured log must contain `ESTABLISHED` for the configured peer and the `sync_response` marker (sync_response detection is informational because gnmic versions render it inconsistently). A second subscribe opens in the background, the driver `clear bgp` on the FRR side to flap, and the driver asserts a non-ESTABLISHED state appears in the post-flap log (which can only come from the flap transition — the initial snapshot already showed ESTABLISHED). Finally, the driver opens a third subscription and asserts that reconnect yields a fresh initial snapshot (no replay of disconnected-window transitions — the v1 contract is that historical replay belongs to `SubscribeFromEvent`, not gNMI). Full re-ESTABLISHED inside the test window is informational because FRR reconverge time is timing-sensitive. Reuses the M54 mTLS PKI for the gNMI listener. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). |
| FRR (bgpd) ×5 + raw-BGP fixture | 10.3.1 | `tests/interop/m55-bgp-roles-otc-frr.clab.yml` | Tested (M55) | ADR-0071 BGP Roles + Only-to-Customer (RFC 9234) | rustbgpd (AS 65001) peers with FRR nodes for the three compatible role pairs (Provider↔Customer, RS↔RS-Client, Peer↔Peer), one incompatible Provider↔Provider session, and one strict-role peer where FRR advertises no Role. The driver asserts compatible sessions reach Established and `ListNeighbors` reports local/remote role negotiation, while the mismatch and strict-no-role sessions fail before Established with a sent NOTIFICATION. It then injects `192.0.2.55/32` through rustbgpd and asserts FRR Customer sees OTC=65001 on the received route. A tiny raw-BGP Customer fixture sends the cases compliant FRR will not emit: a Customer route carrying OTC (I1 leak) and a malformed-length OTC UPDATE that also withdraws a previously accepted route. The driver asserts the bad announcements are absent, the withdrawal still applies, the raw session remains Established, and `bgp_otc_routes_blocked_total` ticks `ingress_from_customer_rsclient` and `malformed_length`. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). |
| FRR (bgpd) | 10.3.1 | `tests/interop/m45-evpn-type5-injection.clab.yml` | Tested (M45) | EVPN Type 5 (IP Prefix) control-plane injection via gRPC (RFC 9136) | rustbgpd injects an interface-less Type 5 IP-Prefix route through `InjectionService.AddEvpnRoute` (`rbgp evpn add-ip-prefix`) with ESI 0, the L3VNI in the label, and a Router MAC extended community; the driver asserts FRR receives the injected Type 5 with the correct next-hop and Route Target, then deletes it and asserts withdrawal. **Hosted CI** in `.github/workflows/interop.yml` (no kernel features required). |
| FRR (bgpd) | 10.3.1 | `tests/interop/m36-evpn-vtep-smoke.clab.yml` | Tested (M36) | EVPN VXLAN VTEP dataplane (Linux FDB reconciler) real-VTEP smoke — rustbgpd as VTEP, FRR as originator | iBGP/AS65000 single-peer topology. rustbgpd container pre-creates `br100` + `vxlan100` (nolearning, local 10.0.0.1) plus a foreign-static FDB entry (`02:99:99:99:99:99 → 10.0.0.99`); FRR injects MAC `02:aa:bb:cc:dd:01` on its dummy bridge port to trigger Type 2 origination. Test asserts rustbgpd's `bridge fdb show dev vxlan100` produces both required kernel rows (the `master <bridge>` row carrying `extern_learn`, and the `self`/`dst <remote>` row also carrying `extern_learn`), then withdraws and asserts cleanup, and verifies the foreign-static entry survives both cycles (validates ADR-0054 §5/§7 foreign-entry preservation against a real Linux 6.17 kernel). 8/8 PASS locally. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`; the complementary privileged netns test at `crates/evpn-linux/tests/netns_dataplane.rs` (gated on `EVPN_LINUX_NETNS=1`) covers the same FDB programming path under direct cargo control. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m60-evpn-adoption-sweep.clab.yml` | Tested (M60) | ADR-0079 single-dst FDB adoption sweep kill-and-restart — stale-state reaping + still-desired re-adoption against a real kernel | Same iBGP/AS65000 VTEP shape as M36. FRR advertises Type 2 MACs A (`02:aa:bb:cc:dd:01`) and B (`02:aa:bb:cc:dd:02`); rustbgpd programs both as `extern_learn` single-dst rows, the driver plants a foreign-static row (no marker) while the daemon runs, then `kill -9`s the rustbgpd process — the container's netns and its FDB rows survive (crash-leftover premise, asserted). While the daemon is down FRR withdraws B's binding. Restart with `RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=5` and assert: row A stays present with `extern_learn` continuously across the reap window (adopted + re-claimed, polled at 1 s grain); row B is reaped after the deferral (bounded by the 60 s periodic-dump cadence); both foreign rows survive untouched; Prometheus reports `evpn_fdb_single_dst_adopted_total >= 2` and `evpn_fdb_single_dst_reaped_total == 1` for the restarted process. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m61-evpn-l3-adoption-sweep.clab.yml` | Tested (M61) | ADR-0079 EVPN L3 adoption sweep kill-and-restart — VRF routes, L3 neighbors, and L3VXLAN FDB rows against a real kernel | The L3 companion to M60, over the M48 symmetric Interface-less IRB topology (vrf1 / L3VNI 100, kernel devices via `start-rustbgpd-m39-pe1.sh`). FRR originates Type 5 prefixes A (`198.51.100.0/24`, start-script tenant address) and B (`203.0.113.0/24`, driver-injected on `lo-vrf1`); rustbgpd imports both into vrf1's kernel table as `via 10.0.0.2 dev l3vxlan100 proto bgp ... onlink` rows plus the shared resolution rows — the `PERMANENT` + `extern_learn` L3 neighbor (FRR's VTEP IP → router MAC) and the `extern_learn` + `self` L3VXLAN FDB row (A and B share FRR's single VTEP IP / router MAC, so one neighbor + one FDB row serve both). The driver plants a foreign `proto static` route, a permanent non-`extern_learn` neighbor, (ADR-0082) an `extern_learn` + permanent neighbor stamped `protocol zebra` — foreign by stamp despite carrying the full legacy marker pair — and (ADR-0082 strict flip) an `extern_learn` + permanent neighbor with NO protocol stamp, the exact shape a pre-stamp rustbgpd left behind, which the post-v0.38.0 strict default must refuse (`RUSTBGPD_EVPN_ADOPTION_ACCEPT_LEGACY` deliberately unset) — while the daemon runs, then `kill -9`s the rustbgpd process — the container's netns and every kernel row survive (crash-leftover premise, asserted). While the daemon is down FRR withdraws B. Restart with `RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=5` and assert: route A and the shared resolution rows stay fully marked continuously across the reap window (adopted + re-claimed, polled at 1 s grain); route B is reaped after the deferral (its resolution rows are A's, so they must not be reaped — the route-before-resolution reap order is pinned by the reconcile unit tests, not observable here); all four foreign rows survive untouched (the stamp-less one still stampless — the pre-flip stamp-or-legacy rule would have adopted and reaped it) and the re-claimed neighbor row shows the ADR-0082 `NDA_PROTOCOL` ownership stamp (`proto bgp` in `ip neigh show`); Prometheus reports `evpn_l3_route_adopted_total == 2`, `evpn_l3_route_reaped_total == 1`, and neighbor/FDB adopted `== 1` / reaped `== 0` for the restarted process. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m62-blackhole-adoption-sweep.clab.yml` | Tested (M62) | ADR-0079 blackhole discard adoption sweep kill-and-restart — stale-discard reaping + still-desired re-adoption against a real kernel | The RFC 7999 companion to M60/M61, over the M41 single-peer EBGP shape. FRR's outbound route-map tags host routes A (`203.0.113.66/32`) and B (`203.0.113.68/32`) with `BLACKHOLE` (`65535:666`); rustbgpd (with `[global] honor_blackhole = true` + `install_blackhole_discard = true`) installs both as kernel `RTN_BLACKHOLE` + `RTPROT_BGP` rows in the main table, the driver plants a foreign `proto static` blackhole row (no marker) while the daemon runs, then `kill -9`s the rustbgpd process — the container's netns and both discard rows survive (crash-leftover premise, asserted). While the daemon is down FRR withdraws B (`no network`). Restart with `RUSTBGPD_BLACKHOLE_ADOPTION_REAP_DEFERRAL_SECS=5` and assert: row A stays present with the `proto bgp` marker continuously across the reap window (adopted + re-claimed, polled at 1 s grain; `ListBlackholeDiscards` reads `installed` with reason `adopted`/`owned`); row B surfaces as `installed/adopted_pending_reap` while it waits, is reaped only after the deferral (bounded by the 30 s periodic reconcile), and drops off the status surface; the foreign row survives untouched and never gets a status row; Prometheus reports `bgp_blackhole_discard_adopted_total >= 2` and `bgp_blackhole_discard_reaped_total == 1` for the restarted process. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| GoBGP ×2 (PE1 + PE2) | 3.37.0 (image builds latest v3) | `tests/interop/m65-evpn-single-active-failover.clab.yml` | Tested (M65) | ADR-0083 single-active failover blackout measurement — pre-installed backup path, one-message swap, ordered teardown against a real kernel | rustbgpd is the remote VTEP (receive side, the device under test); two GoBGP-driven PEs over plain kernel bridge/VXLAN dataplanes share single-active ES `00:00:00:00:00:00:00:00:00:01` for VNI 100, and a host behind the DUT pings the dual-homed CE (a bridge over both attachment circuits) at a 100 ms grain. GoBGP — not a second rustbgpd or FRR — because the failure injection must be the RFC 7432 §8.2 mass-withdraw wire shape (EAD-per-ES withdrawn while the MAC routes stay advertised): rustbgpd can originate the Single-Active flag but has no AC binding, and its SIGHUP ES-removal drains + synchronously re-keys the VNI's Type 2 routes, destroying the swap window; FRR's EVPN multihoming is all-active only. The driver injects EAD-per-ES (Single-Active ESI Label flag) + EAD-per-EVI from both PEs and the CE MAC's ESI-attached Type 2 from pe1, asserts the slice-2 pre-install (`NDA_NH_ID` row behind a one-member group, member = pe1's per-VTEP NH, pe2's NH pre-created as standby but NOT a member), then downs pe1's CE leg and withdraws only its EAD-per-ES. Hard asserts: the same group id is retargeted to the pre-created backup NH in one membership replace (new member id == the pre-install standby id — the swap allocates nothing), the MAC row's nhid is held continuously (never flushed), the withdrawn PE's NH is GC'd, `evpn_single_active_backup_swaps_total == 1` / gauge `== 1`, traffic flows again via pe2; then pe2's EAD-per-ES withdrawal (eligible set empty, pe1's MAC route still advertised) drives the ordered teardown — rows flushed, group + NHs gone, `evpn_single_active_teardowns_total == 1`, gauge back to 0, pings hard-dead (no Type 3 routes are ever injected, so no flood entries exist anywhere: known-unicast via the NHG row is the only fabric path and the swap is the only restoration mechanism). Foreign FDB rows (pre-loaded + driver-planted) and a driver-planted untagged fdb nexthop survive untouched. The blackout window is measured informationally from the ping stream (max consecutive missed-probe run): ~4.5 s on local hardware, dominated by the dataplane supervisor's 5 s RIB-poll cadence (the swap itself is a single `NLM_F_REPLACE`); one generous hard bound (< 30 s) separates the poll-driven event path from the ≤60 s periodic-reconcile backstop. Node failure (hard PE kill) is scoped out by construction: the dead PE's session carries its MAC routes down with its EAD-per-ES, so no swap window exists — that path is detection-bounded flush + relearn (M36/M60 semantics). **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| rustbgpd ×3 (VTEP/RR + PE1 + PE2) | in-tree HEAD | `tests/interop/m66-evpn-es-drain-handover.clab.yml` | Tested (M66) | ADR-0084 Ethernet Segment drain service handover — rustbgpd on both sides (origination PEs + receive-side VTEP) against a real kernel | The proof M65 couldn't be: M65 needed GoBGP PEs because rustbgpd had no deliberate origination-side withdrawal stimulus; the ADR-0084 runtime drain (`rbgp evpn es drain <esi>`) is that stimulus now, so all three BGP speakers are rustbgpd — two full-dataplane single-active segment PEs (ES `00:00:00:00:00:00:00:00:00:01`, VNI 100, RFC 9785 highest-preference DF: pe1 200 > pe2 100) and the M65-shape remote VTEP doubling as iBGP RR so the PEs see each other's Type 4 routes. A host behind the VTEP pings the dual-homed CE at a 100 ms grain across the cycle. Unlike M65, the flood path is present (Type 3 IMET asserted from both PEs; since rustbgpd does not yet program kernel flood entries from received IMET, the topology pre-installs the equivalent static all-zero VXLAN FDB rows) so the surviving PE's MAC-learning gap is bridged after the drain. Hard asserts: steady state carries Type 4 + EAD-per-ES + EAD-per-EVI from both PEs and the CE MAC's ESI-attached Type 2 from the DF only, behind the ADR-0083 one-member NHG with the backup NH pre-created; the drain RPC is operator_only (observer principal over a UDS listener → PermissionDenied, unknown ESI → NotFound — rbgp against tier-enforced bearer-token/UDS listeners); draining pe1 reports `drained=true changed=true member_vni_count=1` (repeat → `changed=false`), withdraws all four route classes from the VTEP while pe2's stay intact, drops pe1's `evpn_df_role` df gauge to 0 and promotes pe2 to DF; the service hands over — pe2 learns the CE MAC through the now-open flood path, originates its own Type 2, and the VTEP's CE MAC FDB row re-resolves toward pe2's VTEP IP; a SIGHUP reload WHILE DRAINED that keeps the ES configured (made non-trivial by live-adding a bridge-less L2VNI, forcing a real EVPN runtime apply) does not resurrect the routes (ADR-0084 decision 3); undrain restores Type 4 + both EAD classes immediately and pe1 re-wins DF (revertive preference); after one CE maintenance-exit ARP broadcast the CE-MAC Type 2 from pe1 and end-to-end service are asserted back — the broadcast is required by two pre-existing daemon gaps the proof surfaces and documents in the topology header (no same-ESI local bias in the PE remote-MAC projection, so the drained PE's local AC row is usurped by the peer's Type 2; and no local-delete observation for that in-place port move, so the undrain replays the cached claim). The receive-side backup-swap counter may fire transiently during the drain (ordering-dependent) — logged, never asserted. Blackout measured informationally with one generous < 30 s bound; the BUM-flood-only enforcement limit (a drained/non-DF AC does not block known unicast — ROADMAP "single-active non-DF full AC blocking") typically keeps the observed gap near zero while the control-plane handover completes behind it. Foreign FDB state (pre-loaded row + the static flood rows) survives untouched. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| rustbgpd ×3 (VTEP/RR + PE1 + PE2) | in-tree HEAD | `tests/interop/m67-evpn-link-drain-failover.clab.yml` | Tested (M67) | ADR-0085 link-driven Ethernet Segment drain failover and held-off recovery — a real AC failure, not an RPC, drives the drain end-to-end | The M66 sibling with the production trigger (ADR-0085 decisions 1–3, the close of the origination-side withdrawal-stimulus arc: RPC drain proven by M66, link-driven drain here). Same five-node topology — two full-dataplane rustbgpd single-active segment PEs (RFC 9785 highest-preference DF: pe1 200 > pe2 100) behind a rustbgpd VTEP/RR, a host pinging the dual-homed CE at a 100 ms grain — but the PEs bind their CE-facing attachment circuit (`interface = "eth2"`, `recovery_delay_secs = 5`). The failure injection is `ip link set eth2 down` INSIDE pe1: the binding watches pe1's own ifindex carrier (`IFF_LOWER_UP`), and on a containerlab veth pair the CE leg drops carrier too — cable-pull semantics, admin-down and cable pull deliberately the same signal. Hard asserts: pe1's carrier monitor demonstrably armed (log line) and every `evpn_es_drained{esi, reason}` gauge 0 before the failure; on AC loss the `link` reason gauge goes 1 with NO operator involvement (operator gauge stays 0, coordinator log line present), pe1's df gauge drops, all four route classes (Type 4 + EAD-per-ES + EAD-per-EVI + Type 2) withdraw from the VTEP — the RFC 7432 §8.2 mass-withdraw shape — while pe2's survive, pe2 promotes to DF, and the VTEP's CE-MAC FDB row re-resolves toward exactly pe2; on `ip link set eth2 up` the gauge must still read 1 on every sub-second sample through up+3 s (the recovery hold-off, RFC 8584 §3 damping — the one strict-ish timing assert, framed as "still held at t+3 s" against the 5 s window) before releasing (~5.5 s observed), then pe1's routes return and pe1 re-wins DF revertively; a down-up-down-up flap inside the hold-off keeps the gauge at 1 past the FIRST up's would-be deadline (proving the re-arm cancelled it) with routes still withdrawn, and recovery completes only after the LAST up + hold-off; operator/link reason composition (decision 2): an operator drain plus a full link down/up cycle leaves the ES withdrawn (the operator reason survives link recovery), and only the operator undrain restores origination. Blackout measured informationally (100–300 ms local — unlike M66's RPC drain the AC is really dead, so this is the genuine failover) with a generous < 30 s bound; the recovered DF's Type 2 returns after the M66-established CE maintenance-exit broadcast. Foreign FDB state survives; the script is re-runnable (a prior cycle's shared-ESI co-advertisement — legitimate RFC 7432 aliasing once the CE has spoken on both legs — downgrades the two fresh-bring-up-only pins to informational). Since the single-active whole-port AC gate landed (the bound AC is the port handle), the script also asserts the RFC 7432 non-DF full-AC blocking transitions: pe2's bound AC bridge port reads `state disabled` at steady state (NonDF), opens to `state forwarding` on DF promotion (a prerequisite for the flood-path relearn), and re-blocks after the revertive failback. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m37-evpn-local-origination.clab.yml` | Tested (M37) | EVPN local MAC origination (Type-2 + Type-3 IMET) smoke — rustbgpd as VTEP originator, FRR as consumer | Inverts M36's roles to validate the upward EVPN flow added with EVPN local MAC origination. iBGP/AS65000 single-peer topology. rustbgpd container pre-creates `br100` + `vxlan100` + a non-VXLAN bridge port (`veth100a` enslaved to `br100`); the daemon subscribes to `RTNLGRP_NEIGH` (enum group id `3`, **not** the legacy bitmask `RTMGRP_NEIGH = 4`) on the rtnetlink socket and runs the `notify::classify_neigh` classifier on every `RTM_NEWNEIGH AF_BRIDGE` message. Test asserts (1) FRR sees a Type 3 IMET originated by rustbgpd at startup with PMSI Tunnel = Ingress Replication, label = raw 24-bit VNI per RFC 8365 §5.1.3, originator = 10.0.0.1; (2) `bridge fdb add 02:aa:bb:cc:dd:01 dev veth100a master static` triggers a Type 2 origination visible on FRR within ~15s with originator = 10.0.0.1; (3) `bridge fdb del` triggers a Type 2 withdraw within ~15s; (4) `docker stop` on rustbgpd causes the Type 3 IMET to drain (shutdown emits the Withdraw before the daemon exits). 4/4 PASS locally against Linux 6.17 + FRR 10.3.1. Validates ADR-0055 §1-§6 end-to-end. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m37-evpn-mac-ip-origination.clab.yml` | Tested (M37+IP) | EVPN MAC-with-IP Type-2 origination smoke — FRR-style replace model | iBGP/AS65000 single-peer topology. Same rustbgpd-as-VTEP / FRR-as-consumer shape as M37 but exercises the upward flow extended by MAC-with-IP origination: `bridge fdb add MAC` originates a MAC-only Type 2; `ip neigh add IP lladdr MAC dev br100 nud reachable` causes the daemon to withdraw the MAC-only and emit a MAC+IP Type 2 (replace invariant — never both at once). Withdrawing the neighbour pulls the MAC+IP and the MAC-only path re-originates. Operator prerequisite: `neigh_suppress on` on every VXLAN port so the kernel routes ARP/ND bindings into the bridge's neighbour table. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| rustbgpd ×2 (PE1 + PE2) | in-tree HEAD | `tests/interop/m38-evpn-df-election.clab.yml` | Tested (M38) | EVPN multi-homing (ESI, Type-1/Type-4) observable DF election + Type 1/4 origination | Two rustbgpd PEs share an ESI on a non-zero `[[ethernet_segments]]` entry; each originates Type 4 ES + Type 1 EAD-per-ES + Type 1 EAD-per-EVI per RFC 7432 §8.5 (default-modulo carving), with RFC 8584 HRW available as a configured algorithm in the control-plane state machine. Asserts (1) PE1 reports DF=1 and PE2 reports DF=0 for `(esi, vni)` within ~30 s via `evpn_df_role`; (2) after PE1 shuts down, PE2 promotes to DF and `evpn_df_role_changes_total{esi,vni}` increments; (3) the reflected Type 4 ES route carries the ES-Import RT extcomm (RFC 7432 §7.6, BUM-flood-suppression prep) and Type 1 EAD-per-ES carries the ESI Label extcomm (RFC 7432 §7.5). **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`; the EVPN BUM-flood-suppression kernel primitive validation continues to live on the parallel Docker harness gated in `ci.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m39-evpn-type5-symmetric-irb.clab.yml` | Tested (M39) | EVPN symmetric IRB (Type-5 / L3VNI) bidirectional, Interface-less (RFC 9136 §4.4.2) | Two-VTEP topology with rustbgpd PE1 (10.0.0.1, AS 65000) directly peered to FRR PE2 (10.0.0.2, AS 65000) — no Route Reflector. Both PEs run vrf1/L3VNI 100 with the L3VXLAN device enslaved directly to the VRF (no bridge, per ADR-0058 §3 Interface-less shape). PE1 tenant `192.0.2.1/32` lives on `lo-vrf1` (rustbgpd observes via the Type 5 origination + import path and originates as Type 5); PE2 tenant `192.0.2.2/32` lives on FRR's loopback (FRR originates via `advertise ipv4 unicast`). Asserts: (1) BGP Established within ~30 s; (2) FRR sees PE1's Type 5; (3) rustbgpd sees PE2's Type 5; (4) PE1 kernel route for 192.0.2.2/32 via 10.0.0.2 dev l3vxlan100 in table 100 (RTPROT_BGP + RTNH_F_ONLINK); (5) PE1 neighbor row `10.0.0.2 lladdr <PE2 router_mac> dev l3vxlan100 PERMANENT extern_learn`; (6) PE1 FDB row `<PE2 router_mac> dev l3vxlan100 dst 10.0.0.2 self extern_learn`; (7) gRPC `IpVrfState.installed_routes_count == 1`; (8) bidirectional ping over the L3VNI VXLAN tunnel via `ip vrf exec vrf1 ping`; (9) `ip addr del` on PE1's tenant dummy → FRR drops the Type 5 within 30 s. Operator-supplied Router MAC on the rustbgpd side (`router_mac = "02:00:00:00:01:01"` in PE1 TOML) — the startup script writes the value onto the L3VXLAN device so the IP-VRF readiness probe passes. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml` because hosted runners do not reliably expose the `vrf` module. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m39b-evpn-auto-rt-frr.clab.yml` | Tested (M39b) | EVPN auto-derived Route Targets, cross-vendor (RFC 8365 §5.1.2.1 / `AS:VNI`) | Two-node rustbgpd↔FRR L3VNI topology with `auto_derive_route_target = true`. Proves bidirectional Type 5 import via auto-derived RT, validating that rustbgpd's L3VNI auto-RT uses the plain `AS:VNI` form FRR's tenant-VRF auto-RT expects (FRR's `autort rfc8365-compatible` is MAC-VRF/L2VNI-only, so the RFC 8365 opaque form does not import cross-vendor for L3VNIs). **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m40-evpn-aliasing-ecmp-frr.clab.yml` | Tested (M40) | ADR-0059 EVPN aliasing dataplane ECMP via FDB nexthop groups against FRR EVPN-MH | Three-node topology with rustbgpd as VTEP observer (10.0.0.1, AS 65000) directly peered to two FRR VTEPs (pe-a at 10.0.0.2 and pe-c at 10.0.1.2) that share ES1 via the bond shape FRR EVPN-MH requires (`es-id 1`, `es-sys-mac aa:bb:cc:dd:ee:ff`; FRR EVPN-MH only registers a local ES when the carrier is a bond device — `start-frr-vtep-mh.sh` builds a `bond` + dummy-slave + bridge attachment per RFC 7432 §5 ESI Type 3 derivation). Asserts: (1) both FRR peers Established to rustbgpd; (2) both FRR nodes show local ES1 in `show evpn es` with the `L` flag; (3) injecting test MAC `02:aa:bb:cc:dd:40` on pe-a's `esdummy` bond originates a Type 2 with ESI=ES1; (4) rustbgpd's bridge FDB shows a row with decimal `nhid N`; (5) `ip nexthop show` shows the matching group `id N group X/Y ... fdb` whose two members resolve to pe-a's and pe-c's VTEP IPs under the `NHG_TAG | n` / `VTEP_NH_TAG | n` tag scheme; (6) `docker stop pe-c` collapses the entry to single-dst (the projection invariant `empty alias_vtep_ips ⇔ alias_group_key.is_none()` forces N=2 → N=1 to fall back); (7) `bridge fdb del` removes the row and any stale FDB nexthops. 16/16 PASS first-shot against Linux 6.17 + FRR 10.3.1. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| rustbgpd ×2 (PE1 + PE2) | in-tree HEAD | `tests/interop/m46-evpn-df-hrw.clab.yml` | Tested (M46) | RFC 8584 §3.2 Highest Random Weight DF election | Two rustbgpd PEs share an ESI for VNI 200, both configured `df_algorithm = "highest-random-weight"`. The HRW weights elect the higher-IP PE (PE2, 10.0.0.2) as DF, whereas default service carving (`200 mod 2` = slot 0) would elect PE1 — so asserting PE2 is DF is a positive proof that HRW (negotiated unanimously over the DF Election Extended Community on Type 4 ES routes) drives the election rather than modulo. Asserts: (1) both PEs exchange both Type 4 ES candidates; (2) PE2 reports `evpn_df_role{...,role="df"} 1` and NonDF=0; (3) PE1 reports DF=0 / NonDF=1; (4) stopping PE2 (the DF) promotes PE1 to DF and increments `evpn_df_role_changes_total{...,vni="200"}`. Byte-exact cross-vendor HRW conformance is locked separately by the `hrw_weight_matches_rfc8584_known_answer` unit test (independent CRC-32 + LCG known-answer); FRR cannot host the peer side because it implements RFC 9785 preference-DF, not HRW. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m47-evpn-tenant-teardown.clab.yml` | Tested (M47) | ADR-0063 / #210 runtime EVPN tenant teardown via `EvpnService.ApplyEvpnRuntime` | First interop smoke to drive `ApplyEvpnRuntime`. rustbgpd boots a tenant — L2VNI 100 plus Ethernet Segment `00:00:00:00:00:00:00:00:00:01` over member VNI 100 — and advertises its Type 3 (IMET) and Type 1/4 (EAD / ES) routes to a directly-peered FRR receiver (no Route Reflector). Pure control-plane: no kernel bridge / VXLAN / VRF, so the tenant routes (all under RD 65000:100) live in FRR's global `show bgp l2vpn evpn`. Asserts: (1) BGP Established; (2) FRR receives RD 65000:100; (3) rustbgpd's `ListEvpnRoutes` shows the local Type 3 + Type 4; (4) `grpcurl … EvpnService/ApplyEvpnRuntime` with a candidate that drops the whole tenant returns `EVPN_RUNTIME_APPLY_COMMITTED` with L2VNI 100 in the deleted plan (the daemon converges the L2VNI + ES delete through the atomic tenant-teardown path); (5) FRR withdraws RD 65000:100; (6) rustbgpd's `ListEvpnRoutes` no longer shows the tenant's Type 3 / Type 4. The linked-IP-VRF + kernel-L3 teardown datapath is covered by **M48**. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m48-evpn-tenant-teardown-datapath.clab.yml` | Tested (M48) | ADR-0063 / #210 runtime EVPN tenant teardown over the kernel L3 datapath | The datapath companion to M47: drives `ApplyEvpnRuntime` to drop a *linked* IP-VRF together with its L2VNI in one pass, proving the Type 5 withdraw + kernel L3 drain that M47 (control-plane) cannot reach. Builds on the M39 symmetric Interface-less IRB datapath — PE1 boots vrf1 / L3VNI 100 (kernel devices via `start-rustbgpd-m39-pe1.sh`) plus a bridge-less L2VNI 10 linked to vrf1. Asserts the tenant comes up (FRR sees PE1's Type 5 192.0.2.0/24 + Type 3 IMET under RD 65000:10; PE1 imports FRR's Type 5 198.51.100.0/24 into vrf1's kernel table), then `grpcurl … EvpnService/ApplyEvpnRuntime` with a candidate that drops the whole tenant returns `EVPN_RUNTIME_APPLY_COMMITTED` with L2VNI 10 + IP-VRF vrf1 in the deleted plan (converged through the atomic tenant-teardown path because vrf1 is referenced by L2VNI 10), and finally that FRR withdraws PE1's Type 5 + IMET and PE1's imported kernel L3 route drains from the vrf1 table. Requires the `vrf`/`vxlan` kernel modules. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| rustbgpd ×2 (PE1 + PE2) | in-tree HEAD | `tests/interop/m49-evpn-preference-df.clab.yml` | Tested (M49) | RFC 9785 Highest-Preference DF election (+ Don't-Preempt origination) | Two rustbgpd PEs share an ESI for VNI 200, both `df_algorithm = "highest-preference"`; PE1 `df_preference` 100, PE2 `df_preference` 200 with `df_dont_preempt = true`. Highest-Preference elects PE2 (preference 200 > 100), whereas default service carving (`200 mod 2` = slot 0) would elect PE1 — so asserting PE2 is DF is positive proof preference-DF drives the election rather than a silent fall-back to modulo. Asserts: (1) both PEs exchange both Type 4 ES candidates; (2) PE2 reports `evpn_df_role{...,role="df"} 1` / NonDF=0; (3) PE1 reports DF=0 / NonDF=1; (4) stopping PE2 (the DF) promotes PE1 and increments `evpn_df_role_changes_total{...,vni="200"}`. NOT cross-vendor (both PEs rustbgpd; M69 covers FRR interop). The byte-exact DF Election extcomm incl. the RFC 9785 Don't-Preempt bit is locked separately by the `preference_df_election_extcomm_*` unit test. Validated locally 8/8; also runs in **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m69-evpn-preference-df-frr.clab.yml` | Tested (M69) | RFC 9785 Highest-Preference DF election, cross-vendor | Two-node rustbgpd↔FRR Ethernet Segment for VNI 200. rustbgpd advertises Highest-Preference with `df_preference = 100`; FRR advertises `evpn mh es-df-pref 200` on its bond-backed ES. Default service carving would elect rustbgpd (`200 mod 2` = slot 0 -> lower IP), so asserting rustbgpd NonDF and FRR DF proves the preference-DF wire signal drives the cross-vendor election rather than modulo. Asserts: (1) both peers exchange Type 4 ES routes; (2) rustbgpd's ListEvpnRoutes exposes FRR's DF Election extended community as Highest-Preference / preference 200; (3) rustbgpd reports `evpn_df_role{role="nondf"} 1` and DF=0; (4) FRR `show evpn es detail` reports local DF with preference 200 and the remote rustbgpd candidate at preference 100. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m70-evpn-vlan-aware-bridge-frr.clab.yml` | Tested (M70) | ADR-0089 VLAN-aware bridge FDB attribution, cross-vendor | Two-node rustbgpd↔FRR topology for ADR-0089's v1 Linux shape. rustbgpd owns one `vlan_filtering=1` bridge (`brvlan`) with explicit `bridge_vlan` bindings: VLAN10/VNI100 and VLAN20/VNI200, each backed by a traditional non-external VXLAN device. FRR deliberately stays on the proven traditional side, one bridge/VXLAN per VNI, and originates the same MAC in VNI100 and VNI200. Asserts: (1) BGP Established; (2) FRR discovers and originates Type 3 IMET for both VNIs; (3) FRR advertises the same MAC with RT 65000:100 and RT 65000:200; (4) rustbgpd programs `NDA_VLAN`-scoped remote FDB rows on `vxlan100 vlan 10 dst 10.0.0.2` and `vxlan200 vlan 20 dst 10.0.0.2`; (5) withdrawing the VNI100 MAC removes only the VLAN10 row while the VLAN20 row survives, then the VNI200 withdraw removes the remaining row. This is VNI-per-broadcast-domain service with Ethernet Tag ID 0; SVD / collect-metadata VXLAN, managed netdev creation, and RFC VLAN-Aware Bundle service remain out of scope. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| FRR (bgpd) | 10.3.1 | `tests/interop/m68-evpn-type5-gwip-overlay-index-frr.clab.yml` | Tested (M68) | ADR-0087 native GW-IP overlay-index Type 5 origination — FRR consume-side recursive resolution | Two-node rustbgpd→FRR topology with L3VNI 100 / vrf1 and linked L2VNI 10 on both PEs. rustbgpd runs `overlay_index_mode = "gateway_ip"` and originates a Type 5 for `203.0.113.0/24` from a static VRF route via Gateway Address `10.1.1.5`; FRR has `enable-resolve-overlay-index`. The driver first adds the static route before any companion Type 2 exists and asserts FRR receives the Type 5 but keeps it out of vrf1, using target-scoped FRR/kernel route JSON checks so the unresolved proof cannot be satisfied by an unrelated route. It then originates the gateway MAC/IP Type 2 on L2VNI 10 and asserts FRR imports `203.0.113.0/24` into vrf1 via `10.1.1.5` (BGP RIB and kernel route), proving cross-vendor recursive overlay-index resolution. Finally it withdraws the static route and asserts FRR drops both the Type 5 and the imported VRF route. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| GoBGP | 3.37.0 (image builds latest v3) | `tests/interop/m71-evpn-esi-overlay-type5-receive-gobgp.clab.yml` | Tested (M71) | RFC 9136 §4.3 ESI overlay-index Type 5 single-active recursion — rustbgpd receive-side (PR #541) | Two-node GoBGP→rustbgpd topology; rustbgpd is the receive-side DUT with a full L3 datapath (vrf1 / L3VNI 100 + linked L2VNI 10), GoBGP is the route source. GoBGP injects an ESI overlay-index Type 5 for `203.0.113.0/24` (non-zero ESI `00:..:01`, Router-MAC extcomm, Gateway Address `0.0.0.0`, RT 65000:100) plus the Type 1 EAD-per-ES / EAD-per-EVI rows that resolve it. GoBGP — not FRR — because the proof needs byte-exact, independent control over the EAD-per-ES Single-Active vs All-Active ESI Label flag (FRR's EVPN multi-homing is all-active only). Phases: (1) Type 5 alone is held unresolved (`evpn_ip_vrf_remote_prefix_drops{vrf="vrf1",reason="unresolved_esi_overlay_index"}` ≥ 1, no kernel route); (2) adding the single-active EAD-per-ES + EAD-per-EVI imports the prefix into vrf1 (kernel route `via 10.0.0.2 dev l3vxlan100 proto bgp onlink`, the unresolved drop gauge falls to 0); (3) advertising the same EAD-per-ES without the Single-Active flag withdraws the import and fails closed as a one-candidate all-active target set (`...{reason="unsupported_all_active_target_set"}` ≥ 1, route gone); (4) withdrawing the Type 5 leaves vrf1 clean. M72 proves the route ECMP + L3VXLAN FDB-NHG success path with two all-active PEs. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| GoBGP ×2 (PE1 + PE2) | 3.37.0 (image builds latest v3) | `tests/interop/m72-evpn-esi-overlay-type5-all-active-gobgp.clab.yml` | Tested (M72) | RFC 9136 §4.3 ESI overlay-index Type 5 all-active recursion — rustbgpd receive-side | Three-node GoBGP×2→rustbgpd topology; rustbgpd is the receive-side DUT with vrf1 / L3VNI 100 + linked L2VNI 10, pe1 injects the ESI overlay-index Type 5 for `203.0.113.0/24`, and pe1 + pe2 inject all-active EAD-per-ES / EAD-per-EVI rows with distinct RDs so the target set has two remote VTEPs. Phases: (1) Type 5 alone is held unresolved (`evpn_ip_vrf_remote_prefix_drops{vrf="vrf1",reason="unresolved_esi_overlay_index"}` ≥ 1, no kernel route); (2) adding both all-active EAD candidates imports the prefix into vrf1 as a route-level ECMP route over `l3vxlan100` with both `nexthop via 10.0.1.2` and `nexthop via 10.0.2.2`, per-VTEP L3 neighbors, a Router-MAC FDB row carrying `nhid`, and an FDB nexthop group whose members resolve to both PE VTEPs; (3) withdrawing pe2's EAD state collapses below the all-active minimum and removes the route/FDB-NHG state, then re-adding pe2 restores two-way ECMP; (4) withdrawing the Type 5 cleans the VRF route, Router-MAC FDB row, L3 NHG/member nexthops, and L3 neighbors. **Hosted kernel-dataplane CI** via `.github/workflows/kernel-dataplane.yml`. |
| Junos vMX | — | — | Stretch | Lab only, not CI | — | — |
| Arista cEOS | — | — | Stretch | Lab only, not CI | — | — |
| Cisco IOS-XE | — | — | Stretch | If available | — | — |

---

## Running Interop Tests

### Prerequisites

- Docker installed and running
- containerlab installed
- `rustbgpd:dev` Docker image built: `docker build -t rustbgpd:dev .`
- `bird:2-bookworm` Docker image built: `docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop/`
- `bird:3.2.1-tcpao` Docker image built for M43:
  `docker build -t bird:3.2.1-tcpao -f tests/interop/Dockerfile.bird3 tests/interop/`

### FRR (M0)

```sh
# Deploy topology
sudo containerlab deploy -t tests/interop/m0-frr.clab.yml

# Start rustbgpd
sudo docker exec -d clab-m0-frr-rustbgpd /usr/local/bin/start-rustbgpd.sh

# Watch logs
sudo docker logs -f clab-m0-frr-rustbgpd

# Check FRR session state
sudo docker exec clab-m0-frr-frr vtysh -c "show bgp summary"

# Check Prometheus metrics
sudo docker exec clab-m0-frr-rustbgpd curl -s http://127.0.0.1:9179/metrics

# Tear down
sudo containerlab destroy -t tests/interop/m0-frr.clab.yml
```

### BIRD (M0)

```sh
# Build BIRD image (one-time)
docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop/

# Deploy topology
containerlab deploy -t tests/interop/m0-bird.clab.yml

# Start BIRD (create run dir first)
docker exec clab-m0-bird-bird mkdir -p /run/bird
docker exec -d clab-m0-bird-bird bird -c /etc/bird/bird.conf

# Start rustbgpd
docker exec -d clab-m0-bird-rustbgpd /usr/local/bin/start-rustbgpd.sh

# Check BIRD session state
docker exec clab-m0-bird-bird birdc show protocols rustbgpd

# Check Prometheus metrics (via management IP)
curl -s http://<rustbgpd-mgmt-ip>:9179/metrics

# Tear down
containerlab destroy -t tests/interop/m0-bird.clab.yml
```

### BIRD TCP-AO (M43)

M43 validates ADR-0062 static-neighbor TCP-AO against BIRD 3.2.1 on a
Linux kernel with `CONFIG_TCP_AO=y`:

```sh
docker build -t bird:3.2.1-tcpao -f tests/interop/Dockerfile.bird3 tests/interop/
docker build -t rustbgpd:dev .
containerlab deploy -t tests/interop/m43-tcp-ao-bird.clab.yml
bash tests/interop/scripts/test-m43-tcp-ao-bird.sh
containerlab destroy -t tests/interop/m43-tcp-ao-bird.clab.yml --cleanup
```

The driver first proves a matching-key session establishes and imports
`203.0.113.43/32`, then restarts BIRD with a wrong secret and asserts the
route withdraws and the session remains down. This is a fail-closed transport
security check, not key-rotation coverage.

### Network Layouts

```
FRR:  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR  (10.0.0.2/24, AS 65002)
BIRD: rustbgpd (10.0.1.1/24, AS 65001) ── eth1 ─── eth1 ── BIRD (10.0.1.2/24, AS 65003)
```

IP assignment is done via `exec` commands in the topology YAML. Containerlab
`kind: linux` does not auto-assign IPs.

---

## M0 Test Procedures

### Test 1: Session Establishment

Wait for `"session established"` in rustbgpd logs and `Established` in
FRR's `show bgp summary`. Should complete within 10 seconds.

**Pass criteria:** Both sides report Established. Prometheus
`bgp_session_established_total` >= 1.

### Test 2: Metrics Endpoint

```sh
sudo docker exec clab-m0-frr-rustbgpd curl -s http://127.0.0.1:9179/metrics
```

**Pass criteria:** Endpoint responds with Prometheus text format.
`bgp_session_state_transitions_total` shows the full path:
Idle → Connect → OpenSent → OpenConfirm → Established.

### Test 3: Peer Restart Recovery

```sh
sudo docker exec clab-m0-frr-frr pkill bgpd
sudo docker exec clab-m0-frr-frr /usr/lib/frr/bgpd -d -f /etc/frr/frr.conf
# Wait ~15s
sudo docker exec clab-m0-frr-frr vtysh -c "show bgp summary"
```

**Pass criteria:** Session re-establishes automatically.
`bgp_session_established_total` increments. The auto-reconnect logic in
`PeerSession` injects `ManualStart` when the FSM falls to Idle without an
operator-initiated stop.

### Test 4: TCP Reset Recovery

```sh
sudo docker exec clab-m0-frr-frr vtysh -c "clear bgp *"
# Wait ~15s
sudo docker exec clab-m0-frr-frr vtysh -c "show bgp summary"
```

**Pass criteria:** Session re-establishes. `bgp_notifications_received_total`
shows Cease notifications from FRR.

### Test 5: Full Metrics Verification

After tests 1–4, dump metrics and verify consistency:

- `bgp_session_established_total` = number of establishments (expect 3)
- `bgp_session_flaps_total` = transitions away from Established (expect 2)
- `bgp_session_state_transitions_total` covers all visited FSM states
- `bgp_messages_sent_total` and `bgp_messages_received_total` have open,
  keepalive, and notification counters

---

## FRR Test Results (2026-02-27, FRR 10.3.1)

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established in <10s |
| Metrics endpoint | PASS | Full FSM path in `state_transitions_total` |
| Peer restart recovery | PASS | Auto-reconnect, `established_total`=2 |
| TCP reset recovery | PASS | Cease NOTIFICATIONs received, `established_total`=3 |
| Full metrics dump | PASS | 3 establishments, 2 flaps, all counters consistent |
| **30-min soak** | **PASS** | **35 min, 35/35 checks, 73 keepalives, 0 flaps** |

## BIRD Test Results (2026-02-27, BIRD 2.0.12)

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established in <1s |
| Metrics endpoint | PASS | Full FSM path in `state_transitions_total` |
| Peer restart recovery | PASS | Auto-reconnect after `birdc down`, `established_total`=2 |
| TCP reset recovery | PASS | `birdc restart`, Cease NOTIFICATIONs received, `established_total`=3 |
| Full metrics dump | PASS | 3 establishments, 2 flaps, Cease subcodes 2+4 |
| **30-min soak** | **PASS** | **35 min, 35/35 checks, 0 flaps** |

---

## Per-Peer Notes

### FRR

- Primary CI target. Must not break.
- FRR 10.3.1 used for M0 validation.
- Requires `no bgp ebgp-requires-policy` in config (rustbgpd has no policy
  engine in M0, so FRR would reject the session without this).
- FRR sends Cease NOTIFICATION on `clear bgp *` (good for testing TCP reset
  recovery path).
- `kind: linux` in containerlab — IP addresses assigned via `exec` post-deploy.

### BIRD

- Primary CI target. Must not break.
- BIRD 2.0.12 (Debian bookworm package) used for M0 validation.
- Custom Docker image built from `tests/interop/Dockerfile.bird` (Debian bookworm + bird2).
- `/run/bird` directory must be created before starting bird (not present in
  the base image; bird needs it for `bird.ctl` socket).
- BIRD sends an empty UPDATE immediately after session establishment (since
  `export none` is configured). rustbgpd receives this as a valid update.
- BIRD sends Cease/Administrative Shutdown (subcode 2) on `birdc down` and
  Cease/Administrative Reset (subcode 4) on `birdc restart`.
- `kind: linux` in containerlab — IP addresses assigned via `exec` post-deploy.

### GoBGP

- Secondary CI target. Failures investigated, not gating.
- Used as a peer, not as reference implementation.

---

## Malformed OPEN Test Results (2026-02-27, FRR 10.3.1)

Config: `tests/interop/configs/rustbgpd-frr-badopen.toml` — rustbgpd expects
`remote_asn=65099` but FRR sends AS 65002.

| Check | Result | Details |
|-------|--------|---------|
| NOTIFICATION sent | PASS | Code 2 (Open Message), Subcode 2 (Bad Peer AS) |
| TCP closed after NOTIFICATION | PASS | Connection torn down immediately |
| No hot reconnect loop | PASS | Deferred reconnect timer (`connect_retry_secs`, default 5s) prevents rapid cycling |
| Reconnect fires on schedule | PASS | Second attempt follows `connect_retry_secs` after first rejection |

Previously this scenario caused a hot loop (29K+ cycles / 10s) because
auto-reconnect injected `ManualStart` synchronously. Fixed by adding a
`reconnect_timer` to `PeerSession` that defers reconnection by
`connect_retry_secs`. This malformed-OPEN path uses the fixed Idle reconnect
guard; TCP-level connection refusals use the separate fast-retry /
exponential-backoff path.

---

## Cease Subcode Compatibility

rustbgpd sends Cease/1 (Maximum Number of Prefixes Reached) when a
per-peer `max_prefixes` limit is exceeded. `OUT_OF_RESOURCES` (subcode 8)
is defined but not currently sent by any code path.

| Peer | Accepts Cease/1 (Max Prefixes) | Clean Teardown | Notes |
|------|-------------------------------|----------------|-------|
| FRR 10.3.1 | Yes | Yes | Reports "Cease/Maximum Number of Prefixes Reached", session re-establishes (M26) |
| BIRD | TBD | TBD | — |
| GoBGP | TBD | TBD | — |

---

## M1 Test Procedures

### Prerequisites (in addition to M0)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m1-frr.clab.yml`

### Network Layout

```
M1 FRR: rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

FRR advertises: 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16 via `network` statements.

### Test 1: Routes Appear in RIB

After session reaches Established, wait for UPDATEs to propagate (typically <5s).
Query via gRPC:

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"neighbor_address": "10.0.0.2"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListReceivedRoutes
```

**Pass criteria:** Response contains 3 routes with prefixes 192.168.1.0,
192.168.2.0, and 10.10.0.0.

### Test 2: Route Attributes Correct

From the same gRPC response, verify:
- `origin` = 0 (IGP) — FRR `network` statements produce IGP origin
- `as_path` contains 65002
- `next_hop` = "10.0.0.2"

### Test 3: Route Withdrawal

Remove a network from FRR:

```sh
docker exec clab-m1-frr-frr vtysh -c "conf t" -c "router bgp 65002" \
  -c "address-family ipv4 unicast" -c "no network 192.168.2.0/24" -c "end"
```

Wait ~5s, then query again.

**Pass criteria:** 192.168.2.0/24 is no longer in the response. Other routes remain.

### Test 4: Peer Restart — RIB Cleared and Repopulated

Kill FRR's bgpd, wait for session teardown, restart bgpd.

**Pass criteria:** RIB is empty after peer down, then repopulated with 3 routes
after session re-establishes.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m1-frr.sh
```

Runs all 4 tests automatically. Requires containerlab topology deployed and
`grpcurl` on the host.

---

## M1 FRR Test Results (2026-02-27, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m1-frr.sh` — **15 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (3/3) | PASS | 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16 |
| ORIGIN attribute | PASS | IGP (proto3 default zero) |
| AS_PATH attribute | PASS | Contains 65002 |
| NEXT_HOP attribute | PASS | 10.0.0.2 |
| totalCount field | PASS | Present in gRPC response |
| Route withdrawal | PASS | 192.168.2.0/24 removed after `no network` |
| Remaining routes after withdrawal | PASS | 192.168.1.0/24 still present |
| RIB cleared on peer down | PASS | Empty after bgpd killed |
| Peer restart recovery | PASS | Session re-established (~33s, watchfrr + reconnect timer) |
| RIB repopulated after restart | PASS | 3/3 routes restored |

Note: Test 4 (peer restart) relies on watchfrr auto-restarting bgpd after
`killall -9`. rustbgpd reconnects after `connect_retry_secs` (default 5s);
repeated TCP-level connection refusals use the separate fast-retry /
exponential-backoff path.

---

## M2 Test Procedures

M2 reuses the M1 containerlab topology (`m1-frr.clab.yml`) — FRR advertising
3 prefixes to rustbgpd. With a single peer, the Loc-RIB best routes should
match the Adj-RIB-In received routes, with `best: true` set.

### Test 1: ListBestRoutes Returns Correct Routes

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListBestRoutes
```

**Pass criteria:** Response contains 3 routes with `best: true`, correct
`peerAddress` (10.0.0.2), and matching prefixes/attributes.

### Test 2: ListBestRoutes Pagination

```sh
# Page 1 (size 2)
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"page_size": 2}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListBestRoutes

# Page 2
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"page_size": 2, "page_token": "2"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListBestRoutes
```

**Pass criteria:** Page 1 returns 2 routes with `nextPageToken: "2"`,
page 2 returns 1 route with empty `nextPageToken`.

### Test 3: M1 Regression (all existing tests still pass)

```sh
bash tests/interop/scripts/test-m1-frr.sh
```

**Pass criteria:** 15/15 tests pass — route receipt, attributes, withdrawal,
peer restart recovery all unaffected by M2 changes.

---

## M2 FRR Test Results (2026-02-27, FRR 10.3.1)

| Test | Result | Details |
|------|--------|---------|
| M1 regression (15 tests) | PASS | All 15 automated tests pass |
| ListBestRoutes — 3 routes | PASS | All 3 prefixes with `best: true` |
| ListBestRoutes — peerAddress | PASS | `10.0.0.2` from `route.peer` field |
| ListBestRoutes — attributes | PASS | AS_PATH=[65002], NEXT_HOP=10.0.0.2 |
| ListBestRoutes — pagination (page 1) | PASS | 2 routes, nextPageToken="2" |
| ListBestRoutes — pagination (page 2) | PASS | 1 route, no nextPageToken |

---

## M3 Test Procedures

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m3-frr.clab.yml`

### Network Layout

```
M3 FRR (3-node):

  rustbgpd (AS 65001)
  eth1: 10.0.0.1/24        eth2: 10.0.1.1/24
       │                         │
       │                         │
  eth1: 10.0.0.2/24        eth1: 10.0.1.2/24
  FRR-A (AS 65002)          FRR-B (AS 65003)
```

FRR-A advertises: 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16 via `network` statements.
FRR-B receives only (no route advertisements).

### Test 1: Route Redistribution

After sessions reach Established, FRR-A's routes should propagate through
rustbgpd to FRR-B.

```sh
docker exec clab-m3-frr-frrb vtysh -c "show bgp ipv4 unicast"
```

**Pass criteria:** FRR-B sees 3 routes from FRR-A with AS_PATH `65001 65002`.

### Test 2: Split Horizon

FRR-A should NOT receive its own routes back from rustbgpd.

```sh
docker exec clab-m3-frr-frra vtysh -c "show bgp ipv4 unicast"
```

**Pass criteria:** FRR-A sees only its own locally-originated routes, not
routes reflected back through rustbgpd.

### Test 3: Route Injection

Inject a route via gRPC and verify both peers receive it.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "10.99.0.0", "prefix_length": 24, "next_hop": "10.0.0.1"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.InjectionService/AddPath

docker exec clab-m3-frr-frra vtysh -c "show bgp ipv4 unicast 10.99.0.0/24"
docker exec clab-m3-frr-frrb vtysh -c "show bgp ipv4 unicast 10.99.0.0/24"
```

**Pass criteria:** Both FRR-A and FRR-B see 10.99.0.0/24 with AS_PATH `65001`.

### Test 4: Withdrawal Propagation

Remove a network from FRR-A and verify FRR-B sees the withdrawal.

```sh
docker exec clab-m3-frr-frra vtysh -c "conf t" -c "router bgp 65002" \
  -c "address-family ipv4 unicast" -c "no network 192.168.2.0/24" -c "end"
```

**Pass criteria:** FRR-B no longer sees 192.168.2.0/24.

### Test 5: DeletePath

Withdraw the injected route via gRPC.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "10.99.0.0", "prefix_length": 24}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.InjectionService/DeletePath
```

**Pass criteria:** Both FRR-A and FRR-B no longer see 10.99.0.0/24.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m3-frr.sh
```

Runs all 5 tests automatically. Requires containerlab topology deployed and
`grpcurl` on the host.

---

## M3 FRR Test Results (2026-02-27, FRR 10.3.1)

| Test | Result | Details |
|------|--------|---------|
| Route redistribution (A→B) | PASS | FRR-B sees 3 routes with AS_PATH 65001 65002 |
| Split horizon | PASS | FRR-A does not receive its own routes back |
| Route injection | PASS | Both peers see 10.99.0.0/24 after AddPath |
| Withdrawal propagation | PASS | FRR-B drops 192.168.2.0/24 after FRR-A withdraws |
| DeletePath | PASS | Both peers drop 10.99.0.0/24 after DeletePath |

---

## M4 Test Procedures

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m4-frr.clab.yml`

### Network Layout

```
M4 FRR (10-node):

                        rustbgpd (AS 65001)
        eth1: 10.0.10.1   ...   eth10: 10.0.19.1
             │                        │
     10.0.10.2/24              10.0.19.2/24
     FRR-01 (AS 65010)   ...  FRR-10 (AS 65019)
```

8 FRR peers are statically configured (FRR-01 through FRR-08).
FRR-09 and FRR-10 are present in the topology but added dynamically via gRPC.
Each FRR peer advertises 2 prefixes (172.16.x0.0/24, 172.16.x1.0/24).
FRR-01 has a per-peer export policy: deny 10.0.0.0/8 le 32.

### Test 1: All 8 Static Sessions Establish

Wait for all 8 FRR peers to report `Established` via `show bgp neighbors`.

**Pass criteria:** All 8 sessions reach Established within 90s.

### Test 2: ListNeighbors Returns 8 Peers

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/ListNeighbors
```

**Pass criteria:** Response contains 8 neighbors with `SESSION_STATE_ESTABLISHED`.

### Test 3: Received Routes from All Peers

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.RibService/ListReceivedRoutes
```

**Pass criteria:** At least 16 routes received (2 per peer × 8 peers).
In practice, routes redistributed between peers may increase the total.

### Test 4: Per-Peer Export Policy

Inject 10.99.0.0/24 via `AddPath`. FRR-01 (with deny 10.0.0.0/8 le 32
export policy) should NOT see it. FRR-02 (no per-peer policy) should see it.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"prefix": "10.99.0.0", "prefix_length": 24, "next_hop": "10.0.10.1"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.InjectionService/AddPath

docker exec clab-m4-frr-frr-01 vtysh -c "show bgp ipv4 unicast 10.99.0.0/24 json"
docker exec clab-m4-frr-frr-02 vtysh -c "show bgp ipv4 unicast 10.99.0.0/24 json"
```

**Pass criteria:** FRR-01 does not have 10.99.0.0/24. FRR-02 does.

### Test 5: Dynamic AddNeighbor

Add FRR-09 (AS 65018) via gRPC. Verify session establishes and ListNeighbors
returns 9.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"config": {"address": "10.0.18.2", "remote_asn": 65018, "description": "frr-09-dynamic"}}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/AddNeighbor
```

**Pass criteria:** FRR-09 session reaches Established. ListNeighbors returns 9.

### Test 6: Dynamic DeleteNeighbor

Delete FRR-09 via gRPC. Verify ListNeighbors returns 8 again.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.18.2"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/DeleteNeighbor
```

**Pass criteria:** ListNeighbors returns 8.

### Test 7: Enable/Disable Neighbor

Disable FRR-01 via `DisableNeighbor`, verify session drops. Re-enable via
`EnableNeighbor`, verify session re-establishes.

```sh
grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.10.2", "reason": "test"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/DisableNeighbor

# Wait 5s, verify FRR-01 is not Established

grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
  -d '{"address": "10.0.10.2"}' \
  <rustbgpd-mgmt-ip>:50051 rustbgpd.v1.NeighborService/EnableNeighbor
```

**Pass criteria:** FRR-01 drops to Active/Idle after disable, then
re-establishes after enable.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m4-frr.sh
```

Runs all 7 tests automatically. Requires containerlab topology deployed,
rustbgpd started, and `grpcurl` on the host.

---

## M4 FRR Test Results (2026-02-27, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m4-frr.sh` — **17 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Static sessions (8/8) | PASS | All 8 sessions established on first attempt |
| ListNeighbors count | PASS | Returned 8 peers with SESSION_STATE_ESTABLISHED |
| Received routes | PASS | 30 routes received (>= 16 expected) |
| Per-peer export policy (FRR-01 deny) | PASS | FRR-01 correctly denied 10.99.0.0/24 |
| Per-peer export policy (FRR-02 allow) | PASS | FRR-02 received 10.99.0.0/24 |
| Dynamic AddNeighbor (FRR-09) | PASS | Session established, ListNeighbors returned 9 |
| Dynamic DeleteNeighbor (FRR-09) | PASS | ListNeighbors returned 8 after deletion |
| DisableNeighbor (FRR-01) | PASS | Session dropped to Active state |
| EnableNeighbor (FRR-01) | PASS | Session re-established on first attempt |

---

## M10 Test Procedures (MP-BGP / IPv6 Unicast)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m10-frr-ipv6.clab.yml`

### Network Layout

```
M10 FRR (dual-stack):

  rustbgpd (AS 65001)               FRR (AS 65002)
  eth1: 10.0.0.1/24                 eth1: 10.0.0.2/24
  eth1: fd00::1/64                  eth1: fd00::2/64
       │                                 │
       └─────────── eth1 ────────────────┘
```

BGP session over IPv4 (10.0.0.1 ↔ 10.0.0.2) with MP-BGP IPv6 unicast negotiated.

FRR advertises:
- IPv4: 192.168.1.0/24, 10.10.0.0/16
- IPv6: 2001:db8:1::/48, 2001:db8:2::/48

### Test 1: Session with IPv6 AFI/SAFI Capability

Wait for session to reach Established. Verify FRR sees IPv6 unicast AFI/SAFI
negotiated in the neighbor capabilities.

**Pass criteria:** `ipv6Unicast` appears in FRR's `show bgp neighbors` JSON.

### Test 2: IPv4 Routes Received (backward compat)

Query received routes via gRPC and verify IPv4 prefixes are present.

**Pass criteria:** 192.168.1.0 and 10.10.0.0 in Adj-RIB-In.

### Test 3: IPv6 Routes Received via MP_REACH_NLRI

Query received routes and verify IPv6 prefixes are present.

**Pass criteria:** 2001:db8:1:: and 2001:db8:2:: in Adj-RIB-In.

### Test 4: IPv6 Routes in Best Routes (Loc-RIB)

Query best routes and verify IPv6 prefixes appear.

**Pass criteria:** 2001:db8:1:: and 2001:db8:2:: in Loc-RIB.

### Test 5: IPv6 Route Withdrawal

Withdraw 2001:db8:2::/48 from FRR, verify it disappears from rustbgpd's RIB.
Other routes (IPv4 + remaining IPv6) must still be present.

**Pass criteria:** 2001:db8:2:: withdrawn; 2001:db8:1:: and 192.168.1.0 still present.

### Test 6: IPv6 Route Injection via gRPC

Inject 2001:db8:ff::/48 via `AddPath`, verify it appears in best routes.
Clean up via `DeletePath`.

**Pass criteria:** Injected prefix appears in Loc-RIB.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m10-frr-ipv6.sh
```

Runs all 6 tests automatically. Requires containerlab topology deployed and
`grpcurl` on the host.

---

## M11 Test Procedures (Graceful Restart — RFC 4724)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m11-gr-frr.clab.yml`

### Network Layout

```
M11 GR FRR:
  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

FRR has `bgp graceful-restart` with `restart-time 30`. rustbgpd has
`gr_restart_time = 30`, `gr_stale_routes_time = 30`. Short timers keep tests fast.

FRR advertises: 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16.

### Test 1: GR Capability Negotiated

After session reaches Established, verify FRR reports GR capability in
`show bgp neighbors` JSON. Verify `bgp_gr_stale_routes` = 0 in steady state.

**Pass criteria:** FRR sees GR capability. No stale routes in steady state.

### Test 2: Peer Restart Preserves Routes (Stale Marking)

Kill FRR's bgpd (`killall -9 bgpd`). Wait for rustbgpd to detect session down.
Query metrics to verify GR is active and routes are preserved as stale.

**Pass criteria:** `bgp_gr_active_peers` >= 1, `bgp_gr_stale_routes` >= 3,
routes still present in RIB.

### Test 3: End-of-RIB Clears Stale Flag

watchfrr restarts bgpd automatically. Wait for session re-establishment.
After FRR sends its routes + EoR, stale flags should be cleared.

**Pass criteria:** `bgp_gr_stale_routes` = 0, `bgp_gr_active_peers` = 0,
routes still present and valid.

### Test 4: GR Timer Expiry Sweeps Stale Routes

Kill FRR's bgpd AND watchfrr (prevent restart). Wait for GR restart timer
to expire (30s). Stale routes should be swept from the RIB.

**Pass criteria:** `bgp_gr_stale_routes` = 0, peer routes removed from RIB,
`bgp_gr_timer_expired_total` >= 1.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m11-gr-frr.sh
```

Runs all 4 tests automatically. Tests 1–3 run sequentially (test 2 kills bgpd,
test 3 waits for watchfrr to restart it). Test 4 kills both bgpd and watchfrr
to force timer expiry.

---

## M11 GR FRR Test Results (2026-03-01, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m11-gr-frr.sh` — **17 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (3/3) | PASS | All 3 prefixes in RIB on first attempt |
| GR capability in FRR neighbor state | PASS | `gracefulRestart` present in JSON |
| No stale routes in steady state | PASS | `bgp_gr_stale_routes` = 0 |
| GR active after peer kill | PASS | `bgp_gr_active_peers` = 1 |
| Routes preserved as stale | PASS | 3 stale routes during GR |
| Routes in RIB during GR | PASS | 3 routes still present |
| Session re-established after bgpd restart | PASS | watchfrr restarted bgpd, established on attempt 5 |
| Stale cleared after EoR | PASS | `bgp_gr_stale_routes` = 0 |
| GR completed after EoR | PASS | `bgp_gr_active_peers` = 0 |
| Routes valid after GR | PASS | 3 routes still present |
| GR active after kill (no watchfrr) | PASS | `bgp_gr_active_peers` = 1 |
| Routes stale during timer wait | PASS | 3 stale routes |
| Stale swept after timer expiry | PASS | `bgp_gr_stale_routes` = 0 |
| RIB cleared after sweep | PASS | 0 routes from peer |
| Timer expired counter | PASS | `bgp_gr_timer_expired_total` = 1 |
| GR completed after expiry | PASS | `bgp_gr_active_peers` = 0 |

---

## M12 Test Procedures (Extended Communities — RFC 4360)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m12-ec-frr.clab.yml`

### Network Layout

```
M12 EC FRR:
  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

FRR has a route-map `EC_OUT` that applies `set extcommunity rt 65002:100` to
all outbound routes. FRR advertises: 192.168.1.0/24, 192.168.2.0/24.

### Test 1: Routes Received with Extended Communities

After session reaches Established, verify routes have the `extendedCommunities`
field populated in the gRPC response.

**Pass criteria:** Both prefixes present, `extendedCommunities` field non-empty.

### Test 2: Extended Community Values Correct

Verify the raw uint64 value matches the expected encoding for RT:65002:100
(2-octet AS specific, type 0x00, subtype 0x02).

**Pass criteria:** Decimal value `842131417596004` (= `0x0002FDEA00000064`)
appears in the route data. Both routes carry the EC.

### Test 3: Inject Route with Extended Community

Inject 10.99.0.0/24 via `AddPath` with RT:65001:42. Verify the injected route
appears in best routes with the correct EC value.

**Pass criteria:** Injected route in Loc-RIB with EC value `842127122628650`.

### Test 4: Extended Communities in Best Routes

Verify FRR-originated routes also carry extended communities in ListBestRoutes
(not just ListReceivedRoutes).

**Pass criteria:** RT:65002:100 present in best routes for FRR prefixes.

### Test 5: Delete Injected Route

Delete 10.99.0.0/24 via `DeletePath`. Verify removal. FRR routes must remain.

**Pass criteria:** Injected route removed, FRR routes still present.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m12-ec-frr.sh
```

Runs all 5 tests automatically. Requires containerlab topology deployed and
`grpcurl` on the host.

---

## M12 EC FRR Test Results (2026-03-01, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m12-ec-frr.sh` — **14 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on attempt 30 |
| Routes received (2/2) | PASS | Both prefixes in RIB |
| extendedCommunities field present | PASS | Field populated in gRPC response |
| RT:65002:100 value correct | PASS | Decimal 842131417596004 matches |
| Both routes have ECs | PASS | 2 routes with extendedCommunities |
| AddPath with EC accepted | PASS | 10.99.0.0/24 injected with RT:65001:42 |
| Injected route in best routes | PASS | Present in Loc-RIB |
| Injected EC value correct | PASS | Decimal 842127122628650 matches |
| FRR route in best routes | PASS | 192.168.1.0/24 present |
| RT:65002:100 in best routes | PASS | EC preserved through best-path selection |
| DeletePath removes injected route | PASS | 10.99.0.0/24 removed |
| FRR routes survive deletion | PASS | 192.168.1.0/24 still present |

---

## M13 Test Procedures (Policy Engine)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m13-policy-frr.clab.yml`

### Network Layout

```
M13 Policy (3-node):

  FRR-A (AS 65002)          rustbgpd (AS 65001)          FRR-B (AS 65003)
  eth1: 10.0.0.2/24  ────  eth1: 10.0.0.1/24
                            eth2: 10.0.1.1/24  ────  eth1: 10.0.1.2/24
```

FRR-A advertises: 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16.
FRR-B receives only (no route advertisements).

rustbgpd import chain (named policies, GoBGP-style accumulation):
1. `deny-long-prefixes` — deny /25 and longer
2. `tag-internal` — add community 65001:100 to 10.0.0.0/8 le 16
3. `set-lp-upstream` — set LOCAL_PREF 200 for AS_PATH matching `_65002_`

rustbgpd export policy (inline first-match):
1. Deny 10.10.0.0/16
2. Permit all with MED 50 + AS_PATH prepend 65001 ×2

### Test 1: Import LOCAL_PREF

Verify 192.168.1.0/24 has LOCAL_PREF 200 (AS_PATH regex match).

### Test 2: Import Community Add

Verify 10.10.0.0/16 has standard community 65001:100 (prefix match via chain accumulation).

### Test 3: Export Deny

Verify 10.10.0.0/16 is NOT present on FRR-B. Other prefixes must be present.

### Test 4: Export MED

Verify 192.168.1.0/24 has MED 50 on FRR-B.

### Test 5: Export AS_PATH Prepend

Verify AS_PATH on FRR-B has 3× 65001 (1 natural eBGP + 2 prepended) followed by 65002.

### Test 6: Import LOCAL_PREF All Routes

Verify all 3 routes from AS 65002 have LOCAL_PREF 200.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m13-policy-frr.sh
```

---

## M13 Policy FRR Test Results (2026-03-06, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m13-policy-frr.sh` — **15 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (FRR-A) | PASS | Established on first attempt |
| Session establishment (FRR-B) | PASS | Established on first attempt |
| Routes received (3/3) | PASS | All 3 prefixes in RIB |
| FRR-B routes (2/2) | PASS | 10.10.0.0/16 correctly denied |
| Import LOCAL_PREF 200 | PASS | 192.168.1.0/24 has LOCAL_PREF 200 |
| Import community 65001:100 | PASS | 10.10.0.0/16 has community via chain accumulation |
| LOCAL_PREF all routes | PASS | All 3 routes from AS 65002 have LOCAL_PREF 200 |
| Export deny 10.10.0.0/16 | PASS | Not present on FRR-B |
| Export permit 192.168.x.0 | PASS | Both /24 prefixes on FRR-B |
| Export MED 50 | PASS | 192.168.1.0/24 MED=50 on FRR-B |
| Export AS_PATH prepend | PASS | 3× 65001 (1 natural + 2 prepended) |
| AS_PATH origin AS | PASS | 65002 present in AS_PATH |

---

## M14 Test Procedures (Route Reflector — RFC 4456)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m14-rr-frr.clab.yml`

### Network Layout

```
M14 Route Reflector (3-node iBGP):

  FRR-Client1 (AS 65001)          rustbgpd RR (AS 65001)          FRR-Client2 (AS 65001)
  eth1: 10.0.0.2/24  ────────  eth1: 10.0.0.1/24
  router-id: 10.0.0.2            cluster_id: 10.0.0.1
                                  eth2: 10.0.1.1/24  ────────  eth1: 10.0.1.2/24
                                                                 router-id: 10.0.1.2
```

rustbgpd is the route reflector with `cluster_id = "10.0.0.1"` and both neighbors
marked `route_reflector_client = true`.

Client1 advertises: 192.168.10.0/24, 192.168.11.0/24.
Client2 advertises: 192.168.20.0/24.

### Test 1: Client1 Routes Reflected to Client2

Verify FRR-Client2 receives 192.168.10.0/24 and 192.168.11.0/24.

### Test 2: Client2 Routes Reflected to Client1

Verify FRR-Client1 receives 192.168.20.0/24.

### Test 3: ORIGINATOR_ID Set Correctly

Verify reflected routes carry ORIGINATOR_ID matching the originator's router-id.

### Test 4: CLUSTER_LIST Contains RR Cluster ID

Verify reflected routes carry CLUSTER_LIST containing 10.0.0.1.

### Test 5: RR RIB Has All Routes

Verify rustbgpd's Loc-RIB has all 3 routes.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m14-rr-frr.sh
```

---

## M14 RR FRR Test Results (2026-03-06, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m14-rr-frr.sh` — **14 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (Client1) | PASS | Established on first attempt |
| Session establishment (Client2) | PASS | Established on first attempt |
| Routes received (3/3) | PASS | All 3 prefixes in RIB |
| Client2 has Client1 routes | PASS | 192.168.10.0/24, 192.168.11.0/24 reflected |
| Client1 has Client2 routes | PASS | 192.168.20.0/24 reflected |
| RR RIB complete | PASS | All 3 routes in Loc-RIB |
| Client1→Client2 reflection | PASS | Both /24 prefixes reflected |
| Client2→Client1 reflection | PASS | 192.168.20.0/24 reflected |
| ORIGINATOR_ID (Client1) | PASS | 10.0.0.2 (Client1's router-id) |
| ORIGINATOR_ID (Client2) | PASS | 10.0.1.2 (Client2's router-id) |
| CLUSTER_LIST | PASS | 10.0.0.1 present in route attributes |

---

## M15 Test Procedures (Route Refresh — RFC 2918 + RFC 7313)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m15-rr-frr.clab.yml`

### Network Layout

```
M15 Route Refresh:
  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

rustbgpd has an import policy setting LOCAL_PREF 150. FRR advertises 192.168.1.0/24
and 192.168.2.0/24. A third route (10.99.0.0/24) is added dynamically by FRR during
the test.

### Test 1: Initial Routes with Import Policy

Verify routes arrive with LOCAL_PREF 150 from the import policy.

### Test 2: SoftResetIn Triggers Re-advertisement

Trigger `SoftResetIn` via gRPC. Verify the session remains Established (no flap)
and all routes are still present.

### Test 3: Import Policy After SoftResetIn

Verify LOCAL_PREF 150 is still applied after the soft reset.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m15-rr-frr.sh
```

---

## M15 Route Refresh FRR Test Results (2026-03-06, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m15-rr-frr.sh` — **10 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (2/2) | PASS | Both prefixes in RIB |
| 192.168.1.0/24 present | PASS | In received routes |
| 192.168.2.0/24 present | PASS | In received routes |
| LOCAL_PREF = 150 on import | PASS | Import policy applied |
| New route received | PASS | 10.99.0.0/24 via normal UPDATE |
| SoftResetIn RPC completed | PASS | gRPC call succeeded |
| Session stable after SoftResetIn | PASS | Established, no flap |
| All routes after SoftResetIn | PASS | 3 routes still present |
| LOCAL_PREF after SoftResetIn | PASS | 150 still applied |

---

## M16 Test Procedures (LLGR — RFC 9494)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m16-llgr-frr.clab.yml`

### Network Layout

```
M16 LLGR:
  rustbgpd (10.0.0.1/24, AS 65001) ── eth1 ─── eth1 ── FRR (10.0.0.2/24, AS 65002)
```

rustbgpd has `graceful_restart = true`, `gr_restart_time = 15`, `llgr_stale_time = 60`.
FRR has `bgp graceful-restart` and `bgp long-lived-graceful-restart stale-time 60`.

### Test 1: Initial Routes Received

Verify routes arrive normally.

### Test 2: GR → LLGR Transition

Kill FRR's bgpd. Wait for GR timer (15s) to expire. Routes should still be present
(LLGR preserves them beyond the GR timer).

### Test 3: Reconnect Clears LLGR-Stale

watchfrr restarts bgpd. After session re-establishment and EoR, LLGR-stale state
should be cleared and routes remain valid.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m16-llgr-frr.sh
```

---

## M16 LLGR FRR Test Results (2026-03-06, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m16-llgr-frr.sh` — **8 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (2/2) | PASS | Both prefixes in RIB |
| 192.168.1.0/24 present | PASS | In received routes |
| 192.168.2.0/24 present | PASS | In received routes |
| Routes preserved after GR timer | PASS | 2 routes still present (LLGR active) |
| Session re-established | PASS | watchfrr restarted bgpd |
| Routes present after reconnect | PASS | 2 routes still present |
| LLGR-stale cleared | PASS | No stale routes after EoR |

---

## M17 Test Procedures (Add-Path — RFC 7911)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m17-addpath-frr.clab.yml`

### Network Layout

```
M17 Add-Path (4-node):

  FRR-A (AS 65002)            rustbgpd (AS 65001)             FRR-Client (AS 65004)
  eth1: 10.0.0.2/24  ────  eth1: 10.0.0.1/24                 add_path send=true
                             eth2: 10.0.1.1/24  ────  ...       send_max=4
  FRR-B (AS 65003)           eth3: 10.0.2.1/24  ────  eth1: 10.0.2.2/24
  eth1: 10.0.1.2/24  ────
```

FRR-A and FRR-B both advertise 192.168.10.0/24 (shared prefix with different AS_PATHs).
FRR-A also advertises 192.168.1.0/24; FRR-B also advertises 192.168.2.0/24.

FRR-Client has `neighbor X addpath-rx-all-paths` to accept multiple paths.

### Test 1: Routes from Both Source Peers

Verify all 4 routes appear in Adj-RIB-In (2 from FRR-A, 2 from FRR-B).

### Test 2: Multi-path on Client

Verify FRR-Client receives 2 paths for 192.168.10.0/24.

### Test 3: Distinct Path IDs

Verify the 2 advertised routes for 192.168.10.0/24 have distinct `path_id` values.

### Test 4: Unique Prefixes Forwarded

Verify unique prefixes (192.168.1.0/24, 192.168.2.0/24) are advertised to the client.

### Test 5: Different AS_PATHs

Verify the two paths for 192.168.10.0/24 on FRR-Client have different AS_PATHs
(one via AS 65002, one via AS 65003). Note: eBGP next-hop-self means both paths
share the same next-hop (rustbgpd's address), so AS_PATH is the correct differentiator.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m17-addpath-frr.sh
```

---

## M17 Add-Path FRR Test Results (2026-03-07, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m17-addpath-frr.sh` — **15 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (FRR-A) | PASS | Established on first attempt |
| Session establishment (FRR-B) | PASS | Established |
| Session establishment (FRR-Client) | PASS | Established |
| Routes received (4/4) | PASS | All 4 routes in RIB |
| FRR-A 192.168.10.0 present | PASS | Shared prefix from source A |
| FRR-A 192.168.1.0 present | PASS | Unique prefix from source A |
| FRR-B 192.168.10.0 present | PASS | Shared prefix from source B |
| FRR-B 192.168.2.0 present | PASS | Unique prefix from source B |
| Multi-path on client (2 paths) | PASS | FRR-Client has 2 paths for 192.168.10.0/24 |
| Distinct path_ids | PASS | 2 unique path IDs for shared prefix |
| 192.168.1.0/24 forwarded | PASS | Unique prefix advertised to client |
| 192.168.2.0/24 forwarded | PASS | Unique prefix advertised to client |
| Path via AS 65002 | PASS | AS_PATH differentiation correct |
| Path via AS 65003 | PASS | AS_PATH differentiation correct |

---

## M18 Test Procedures (Extended Next-Hop — RFC 8950)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m18-extnexthop-frr.clab.yml`

### Network Layout

```
M18 Extended Next-Hop (dual-stack):

  rustbgpd (AS 65001)               FRR (AS 65002)
  eth1: 10.0.0.1/24                 eth1: 10.0.0.2/24
  eth1: fd00::1/64                  eth1: fd00::2/64
       │                                 │
       └─────────── eth1 ────────────────┘
```

Both sides negotiate Extended Next-Hop capability. rustbgpd has
`families = ["ipv4_unicast", "ipv6_unicast"]` and `local_ipv6_nexthop = "fd00::1"`.

FRR has `capability extended-nexthop` and advertises:
- IPv4: 192.168.1.0/24, 192.168.2.0/24
- IPv6: 2001:db8:1::/48

### Test 1: Session with Extended Next-Hop Capability

Verify session reaches Established and Extended Next-Hop capability is negotiated.

### Test 2: IPv4 Routes Received

Verify both IPv4 prefixes are received.

### Test 3: IPv6 Routes Received

Verify the IPv6 prefix is received via MP_REACH_NLRI.

### Test 4: Injected Route Reaches FRR

Inject 10.99.0.0/24 via gRPC `AddPath` and verify FRR receives it.

### Test 5: Extended Next-Hop Negotiation Succeeded

Verify FRR receives the injected route (proves outbound encoding works with
Extended Next-Hop negotiated).

### Automated Test Script

```sh
bash tests/interop/scripts/test-m18-extnexthop-frr.sh
```

---

## M18 Extended Next-Hop FRR Test Results (2026-03-07, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m18-extnexthop-frr.sh` — **9 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment | PASS | Established on first attempt |
| Routes received (3/3) | PASS | All 3 routes in RIB |
| Session Established state | PASS | Via FRR neighbor JSON |
| Extended Next-Hop capability | PASS | Present in neighbor capabilities |
| IPv4 192.168.1.0 received | PASS | Standard IPv4 route |
| IPv4 192.168.2.0 received | PASS | Standard IPv4 route |
| IPv6 2001:db8:1:: received | PASS | Via MP_REACH_NLRI |
| Injected route reaches FRR | PASS | 10.99.0.0/24 via AddPath |
| Extended NH negotiation works | PASS | Route received with valid next-hop |

---

## M19 Test Procedures (Transparent Route Server)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m19-routeserver-frr.clab.yml`

### Network Layout

```
M19 Transparent Route Server (3-node):

  FRR-A (AS 65002)       rustbgpd RS (AS 65001)       FRR-B (AS 65003)
  eth1: 10.0.0.2/24  ──  eth1: 10.0.0.1/24
  route_server_client     eth2: 10.0.1.1/24  ──  eth1: 10.0.1.2/24
                          ip_forward=1                 route_server_client
```

FRR-A advertises: 192.168.1.0/24, 192.168.2.0/24.
FRR-B advertises: 192.168.3.0/24.

Both peers are `route_server_client = true` on rustbgpd.

### Route Server Nuances

**Cross-subnet next-hop reachability:** Peers are on separate /24 subnets
(containerlab point-to-point links). Because `route_server_client` preserves
the original NEXT_HOP, FRR-B receives routes with NH=10.0.0.2 (a different
subnet). Each FRR peer needs a static route to the other's subnet via
rustbgpd, and rustbgpd needs `ip_forward=1`.

**FRR enforce-first-as (critical):** FRR 10.x enables `enforce-first-as` by
default. When rustbgpd (AS 65001) transparently forwards a route with
AS_PATH `[65002]`, FRR-B rejects it with `"incorrect first AS (must be 65001)"`.
The fix is `no neighbor X.X.X.X enforce-first-as` **per-neighbor** in each FRR
config. The global `no bgp enforce-first-as` alone is insufficient in FRR 10.3.1.

### Test 1: No ASN Prepend on FRR-B

Verify routes from FRR-A arrive at FRR-B with AS_PATH `[65002]` (no 65001 inserted).

### Test 2: NEXT_HOP Preserved on FRR-B

Verify routes show NEXT_HOP = 10.0.0.2 (FRR-A's original address).

### Test 3: No ASN Prepend on FRR-A

Verify routes from FRR-B arrive at FRR-A with AS_PATH `[65003]`.

### Test 4: NEXT_HOP Preserved on FRR-A

Verify routes show NEXT_HOP = 10.0.1.2 (FRR-B's original address).

### Test 5: All Prefixes Forwarded

Verify both FRR-A prefixes (192.168.1.0/24, 192.168.2.0/24) are present on FRR-B.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m19-routeserver-frr.sh
```

---

## M19 Route Server FRR Test Results (2026-03-07, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m19-routeserver-frr.sh` — **13 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (FRR-A) | PASS | Established on first attempt |
| Session establishment (FRR-B) | PASS | Established on first attempt |
| Routes in RIB (3/3) | PASS | All routes from both peers |
| FRR-B routes (3 total) | PASS | 1 local + 2 from FRR-A |
| FRR-A routes (3 total) | PASS | 2 local + 1 from FRR-B |
| AS_PATH on FRR-B contains 65002 | PASS | Origin AS preserved |
| AS_PATH on FRR-B no 65001 | PASS | Route server ASN not prepended |
| NEXT_HOP on FRR-B = 10.0.0.2 | PASS | FRR-A's original NH preserved |
| AS_PATH on FRR-A contains 65003 | PASS | Origin AS preserved |
| AS_PATH on FRR-A no 65001 | PASS | Route server ASN not prepended |
| NEXT_HOP on FRR-A = 10.0.1.2 | PASS | FRR-B's original NH preserved |
| 192.168.1.0/24 on FRR-B | PASS | Prefix forwarded |
| 192.168.2.0/24 on FRR-B | PASS | Prefix forwarded |

---

## M20 Test Procedures (Private AS Removal)

### Prerequisites (in addition to M1)

- `grpcurl` installed on the host
- Topology deployed: `containerlab deploy -t tests/interop/m20-privateas-frr.clab.yml`

### Network Layout

```
M20 Private AS Removal (5-node):

  FRR-Source (AS 64512)  ──  rustbgpd (AS 65001)  ──  FRR-Remove  (AS 65002)
  private AS, advertises       │                       remove_private_as = "remove"
  192.168.1.0/24 [64512]       │
  192.168.2.0/24 [64512,64000] ├──  FRR-All     (AS 65003)
  (route-map prepend)          │    remove_private_as = "all"
                               │
                               └──  FRR-Replace (AS 65004)
                                    remove_private_as = "replace"
```

FRR-Source (AS 64512, private) advertises two prefixes:
- 192.168.1.0/24 with AS_PATH `[64512]` (all-private)
- 192.168.2.0/24 with AS_PATH `[64512, 64000]` (mixed — 64000 is public, prepended via route-map)

Three observer peers each use a different `remove_private_as` mode:
- **remove**: Strip private ASNs only when the ENTIRE original path is private.
- **all**: Strip all private ASNs unconditionally.
- **replace**: Replace each private ASN with the local ASN (65001).

### Expected AS_PATHs (after rustbgpd prepends its own AS 65001)

| Prefix | Loc-RIB | remove outbound | all outbound | replace outbound |
|--------|---------|-----------------|--------------|------------------|
| 192.168.1.0/24 | `[64512]` | `[65001]` | `[65001]` | `[65001, 65001]` |
| 192.168.2.0/24 | `[64512, 64000]` | `[65001, 64512, 64000]` | `[65001, 64000]` | `[65001, 65001, 64000]` |

Note: The public ASN in the mixed path must NOT be in the 64512-65534 or
4200000000-4294967294 ranges (RFC 6996 private ASN ranges). The test uses
64000 which is below the private range threshold.

### Test 1: Source Routes Received

Verify both prefixes arrive in rustbgpd's Adj-RIB-In.

### Test 2: Remove Mode

Verify 192.168.1.0/24 has private ASNs removed (all-private path) and
192.168.2.0/24 retains private ASN 64512 (mixed path, not stripped in "remove" mode).

### Test 3: All Mode

Verify both prefixes have all private ASNs stripped. Public ASN 64000 preserved.

### Test 4: Replace Mode

Verify private ASNs are replaced with the local ASN (65001). Public ASN preserved.

### Automated Test Script

```sh
bash tests/interop/scripts/test-m20-privateas-frr.sh
```

---

## M20 Private AS Removal FRR Test Results (2026-03-07, FRR 10.3.1)

Automated test: `bash tests/interop/scripts/test-m20-privateas-frr.sh` — **22 passed, 0 failed.**

| Test | Result | Details |
|------|--------|---------|
| Session establishment (Source) | PASS | Established |
| Session establishment (Remove) | PASS | Established |
| Session establishment (All) | PASS | Established |
| Session establishment (Replace) | PASS | Established |
| Routes in RIB (2/2) | PASS | Both prefixes from source |
| Observer routes (Remove) | PASS | 2 routes received |
| Observer routes (All) | PASS | 2 routes received |
| Observer routes (Replace) | PASS | 2 routes received |
| Source: 192.168.1.0 present | PASS | All-private path |
| Source: 192.168.2.0 present | PASS | Mixed path |
| Remove: 192.168.1.0 AS_PATH=[65001] | PASS | Private ASN removed |
| Remove: 192.168.2.0 private preserved | PASS | Mixed path, not all-private |
| Remove: 192.168.2.0 public 64000 present | PASS | Public ASN preserved |
| All: 192.168.1.0 AS_PATH=[65001] | PASS | Private stripped |
| All: 192.168.2.0 private removed | PASS | 64512 stripped |
| All: 192.168.2.0 public 64000 preserved | PASS | Public ASN kept |
| All: 192.168.2.0 local ASN prepended | PASS | 65001 present |
| Replace: 192.168.1.0 2× 65001 | PASS | 1 replaced + 1 prepended |
| Replace: 192.168.1.0 no 64512 | PASS | Private ASN replaced |
| Replace: 192.168.2.0 2× 65001 | PASS | 1 replaced + 1 prepended |
| Replace: 192.168.2.0 public 64000 preserved | PASS | Public ASN kept |
| Replace: 192.168.2.0 no 64512 | PASS | Private ASN replaced |

---

## Troubleshooting

- **Docker network overlap:** Containerlab's default management network
  (172.20.20.0/24) can conflict with other Docker networks. Stop conflicting
  containers or use `containerlab deploy --reconfigure`.
- **FRR bgpd won't peer:** Ensure `-f /etc/frr/frr.conf` is passed when
  restarting bgpd manually. Without it, bgpd starts with no config.
- **No auto-reconnect:** If rustbgpd session stays in Idle after a peer
  failure, verify `stop_requested` isn't set. Only `Stop` and `Shutdown`
  commands set it.
- **Large Docker build context:** Ensure `.dockerignore` includes `target/`.
  Without it, the build context exceeds 2 GB.
- **BIRD "Cannot create control socket":** Run `mkdir -p /run/bird` inside the
  container before starting bird. The Debian package expects this directory.
- **FRR "incorrect first AS" with route server:** FRR 10.x enables
  `enforce-first-as` by default. For transparent route server setups where
  the AS_PATH doesn't start with the route server's ASN, you must add
  `no neighbor X.X.X.X enforce-first-as` per-neighbor in each FRR client
  config. The global `no bgp enforce-first-as` is insufficient in FRR 10.3.1.
- **Route server routes "0 accepted prefixes":** If FRR shows `PfxRcd=0` but
  rustbgpd reports routes sent, check `enforce-first-as` (above) and also
  verify cross-subnet next-hop reachability — preserved next-hops on different
  subnets need static routes through the route server.
- **BIRD shows "Active / Connection refused":** BIRD is trying outbound to
  rustbgpd's port 179, but rustbgpd only connects outbound in M0 (no listener).
  This is normal — rustbgpd's outbound connect will establish the session.
  If it persists, check the connect-retry timer interval.

---

## M21 Test Results (2026-03-15, FRR 10.3.1 + StayRTR v0.6.2)

RPKI origin validation via RTR cache. Surfaced an RTR v2→v1 version-
negotiation race in StayRTR/GoRTR (server disconnects without sending the
RFC 8210 §10 Error Report on unsupported protocol version); rustbgpd's
RTR client falls back to v1 on connection close, and the upstream race
was fixed in [bgp/stayrtr#167](https://github.com/bgp/stayrtr/pull/167).

| Test | Result | Details |
|------|--------|---------|
| gRPC endpoint ready | PASS | First attempt |
| BGP session established | PASS | First attempt |
| RPKI validation states populated | PASS | First attempt |
| StayRTR container running | PASS | Management network reachable |
| RPKI metrics present | PASS | Prometheus output includes rpki counters |
| 192.168.1.0/24 = Valid | PASS | VRP covers AS 65002, max /24 |
| 192.168.2.0/24 = Invalid | PASS | VRP says AS 65099, origin is AS 65002 |
| 10.10.0.0/16 = NotFound | PASS | No VRP covers this prefix |
| Valid route in best routes | PASS | validation_state=valid in Loc-RIB |
| Invalid route in best routes | PASS | validation_state=invalid (only candidate) |
| Health shows 3 routes | PASS | totalRoutes >= 3 |
| **Total** | **12/12** | |

---

## M22 Test Results (2026-04-30, FRR 10.3.1)

FlowSpec injection via gRPC → distribution to FRR → withdrawal
propagation. Rewritten in v0.12.2 to use **direct convergence
signals** (`show bgp ipv4 flowspec json` parsed with `jq` for state
queries; `show bgp summary json` for `connectionsDropped` flap
detection) after a session-tearing wire-level bug (rejected
RFC-compliant FlowSpec `NEXT_HOP=0.0.0.0`) hid behind a slow text-
display path. Per-step `assert_no_flap` surfaces any session reset
at the operation that caused it instead of letting an eventual
re-establish mask the failure.

| Test | Result | Details |
|------|--------|---------|
| gRPC endpoint ready | PASS | First attempt |
| BGP session established | PASS | Initial Established + initial `connectionsDropped` snapshot captured for flap-detection baseline |
| FlowSpec capability negotiated | PASS | AFI 1 / SAFI 133 visible in `show bgp neighbors` output |
| Rule 1 in rustbgpd Loc-RIB | PASS | gRPC `ListFlowSpecRoutes`: dest=192.168.1.0/24, proto==6, dst-port==80, action=drop |
| Session no flap after rule 1 inject | PASS | `connectionsDropped` unchanged |
| FRR received rule 1 | PASS | `show bgp ipv4 flowspec json` totalRoutes ≥ 1 with `192.168.1.0/24` substring in routes-map keys (~30 s window) |
| Both rules in rustbgpd Loc-RIB | PASS | gRPC: count == 2 |
| Session no flap after rule 2 inject | PASS | `connectionsDropped` unchanged |
| FRR received both rules | PASS | totalRoutes ≥ 2 with both prefixes in routes-map (~30 s window) |
| Rule 1 withdrawn from rustbgpd | PASS | gRPC `DeleteFlowSpec` succeeds; Loc-RIB shows count == 1 |
| Session no flap after withdraw | PASS | `connectionsDropped` unchanged |
| Post-withdrawal convergence | PASS | rule 1 absent + rule 2 present + totalRoutes == 1 in single converged check (~30 s window) |
| **Total** | **12/12** | |

---

## M23 Test Results (2026-03-15, GoBGP 4.3.0)

Bidirectional route exchange with GoBGP. Custom Docker image with iproute2.

| Test | Result | Details |
|------|--------|---------|
| gRPC endpoint ready | PASS | First attempt |
| BGP session established | PASS | First attempt |
| rustbgpd received 3 routes | PASS | 192.168.1.0, 192.168.2.0, 10.10.0.0 from GoBGP |
| Prefix 192.168.1.0 present | PASS | |
| Prefix 192.168.2.0 present | PASS | |
| Prefix 10.10.0.0 present | PASS | |
| AS_PATH contains 65002 | PASS | GoBGP's ASN in path |
| NEXT_HOP = 10.0.0.2 | PASS | GoBGP's address |
| GoBGP received 203.0.113.0/24 | PASS | rustbgpd → GoBGP via gRPC injection |
| 192.168.2.0/24 withdrawn | PASS | GoBGP withdrawal propagated to rustbgpd |
| 192.168.1.0/24 still present | PASS | Survived withdrawal of sibling |
| GoBGP no longer has 203.0.113.0/24 | PASS | rustbgpd withdrawal propagated to GoBGP |
| **Total** | **12/12** | |

---

## M24 Test Results (2026-03-15, FRR 10.3.1 + Python BMP receiver)

BMP collector integration. Python TCP receiver validates RFC 7854 message
types and ordering.

| Test | Result | Details |
|------|--------|---------|
| gRPC endpoint ready | PASS | First attempt |
| BGP session established | PASS | First attempt |
| BMP Initiation received | PASS | First message from rustbgpd |
| BMP PeerUp received | PASS | After FRR session establishes |
| BMP RouteMonitoring received | PASS | count=2 (one per FRR prefix) |
| Initiation before PeerUp | PASS | Correct RFC 7854 ordering |
| Message summary | PASS | 4 total: 1 Initiation + 1 PeerUp + 2 RouteMonitoring |
| **Total** | **7/7** | |

---

## M25 Test Results (2026-03-15, FRR 10.3.1)

TCP MD5 authentication (RFC 2385) and GTSM / TTL security (RFC 5082)
with two separate FRR peers.

| Test | Result | Details |
|------|--------|---------|
| gRPC endpoint ready | PASS | First attempt |
| MD5 session established | PASS | password "interop-secret-m25" on both sides |
| Route received over MD5 session | PASS | 192.168.1.0/24 from FRR-A |
| GTSM session established | PASS | ttl-security hops 1 on FRR-B |
| Route received over GTSM session | PASS | 172.16.0.0/16 from FRR-B |
| Both peers active | PASS | activePeers=2 |
| Routes from both peers | PASS | totalRoutes=2 |
| **Total** | **7/7** | |

---

## M26 Test Results (2026-03-15, FRR 10.3.1)

Cease subcode compatibility. rustbgpd sends Cease/1 (Max Prefixes) when
`max_prefixes=2` is exceeded by FRR's 3 prefixes.

| Test | Result | Details |
|------|--------|---------|
| gRPC endpoint ready | PASS | First attempt |
| Session established (then bounced) | PASS | Established before prefix limit triggers |
| FRR received Cease NOTIFICATION | PASS | "Cease/Maximum Number of Prefixes Reached" |
| max_prefix_exceeded metric | PASS | Prometheus counter present |
| Session flapped | PASS | flapCount=1, cycle through Established |
| FRR still operational | PASS | vtysh responds after Cease |
| **Total** | **6/6** | |

---

## M34 Test Procedures (SIGHUP policy soft-reset auto-fire)

Validates the automatic Route Refresh path inside
`PeerManager::update_runtime_policies` introduced in v0.12.0. A
permit→deny edit on an established peer's effective import chain
must (a) not tear the BGP session, and (b) cause the affected prefix
to drop from rustbgpd's RIB while other prefixes from the same peer
remain.

**Topology:** `tests/interop/m34-policy-soft-reset-frr.clab.yml` —
single-peer plain BGP, FRR advertises three prefixes
(192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16). rustbgpd starts with
a permit-all named policy attached as the global import chain. No
kernel features required.

**Sequence:**

1. Wait for the rustbgpd↔FRR session to reach Established and all
   three FRR-originated prefixes to appear in rustbgpd's Loc-RIB.
2. Capture FRR's `bgpTimerUpEstablishedEpoch` for flap detection.
3. Replace the running config with a deny variant (same chain,
   same `[[neighbors]]`, but the named policy gains a deny rule
   for 192.168.1.0/24) via `docker cp`, then SIGHUP the daemon.
4. Wait ~6 s for SIGHUP processing + Route Refresh + re-import.
5. Assertions: post-SIGHUP epoch matches pre-SIGHUP (no flap),
   192.168.1.0/24 absent from RIB, both other prefixes still
   present.

CI-gated alongside M29 / M30 (`.github/workflows/interop.yml`).

## M34 Test Results (2026-04-30, FRR 10.3.1)

| Test | Result | Details |
|------|--------|---------|
| Session reached Established | PASS | FRR side reports Established |
| All 3 prefixes in RIB | PASS | 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16 |
| Pre-SIGHUP epoch captured | PASS | `bgpTimerUpEstablishedEpoch` from FRR |
| Config swap + SIGHUP delivered | PASS | docker cp, then `kill -HUP $pid` |
| Session stayed Established | PASS | post-SIGHUP epoch matches pre-SIGHUP |
| 192.168.1.0/24 dropped | PASS | auto Route Refresh re-imported under deny rule |
| 192.168.2.0/24 still present | PASS | not matched by deny rule |
| 10.10.0.0/16 still present | PASS | not matched by deny rule |
| **Total** | **8/8** | |

---

## Missing Interop Coverage

Tracked gaps where code and unit tests exist but real-system interop validation
is missing. Prioritized by risk.

### P0 — High value, should validate before stable release

| Gap | What exists today | What's missing |
|-----|-------------------|----------------|
| ~~**RPKI/RTR cache**~~ | ~~Done (M21)~~ | ~~StayRTR interop validated: RTR session, v2→v1 fallback, VRP delivery, origin validation (Valid/Invalid/NotFound). Underlying server-side race fixed upstream in [bgp/stayrtr#167](https://github.com/bgp/stayrtr/pull/167).~~ |
| ~~**ASPA/RTR v2 cache**~~ | ~~Done (M27)~~ | ~~Python RTR v2 mock server interop validated: v2 negotiation, ASPA record delivery, validation states (valid/invalid/unknown), best-path preference (step 0.7), ROA+ASPA coexistence.~~ |
| ~~**FlowSpec peer**~~ | ~~Done (M22)~~ | ~~FRR interop validated: gRPC injection, eBGP distribution, withdrawal propagation. FRR receives but cannot originate.~~ |

### P1 — Important for broader adoption

| Gap | What exists today | What's missing |
|-----|-------------------|----------------|
| ~~**GoBGP as peer**~~ | ~~Done (M23)~~ | ~~GoBGP 4.3.0 interop validated: session, bidirectional route exchange, attributes, withdrawal.~~ |
| ~~**BMP collector**~~ | ~~Done (M24)~~ | ~~Python BMP receiver validates Initiation, PeerUp, RouteMonitoring messages and ordering.~~ |
| ~~**TCP MD5 / GTSM**~~ | ~~Done (M25)~~ | ~~Two-peer scenario: MD5-authenticated session + GTSM-secured session, routes exchanged over both.~~ |
| ~~**Cease subcode compat**~~ | ~~Done (M26)~~ | ~~FRR accepts Cease/1 (Max Prefixes) cleanly. Table updated. BIRD/GoBGP still TBD.~~ |

### P1.5 — EVPN Route Reflector validation depth

| Gap | What exists today | What's missing |
|-----|-------------------|----------------|
| **EVPN capability + session** | Done (M29) — L2VPN/EVPN capability negotiated with FRR 10.3.1, session Established, `ListEvpnRoutes` RPC well-formed. | — |
| **EVPN Type 2 MAC reflection** | Done (M30). Real FRR 10.3.1 VTEPs with kernel VXLAN + bridge per VTEP; MAC injected via `bridge fdb add` on VTEP-A propagates through rustbgpd RR to VTEP-B; assertions cover ORIGINATOR_ID + CLUSTER_LIST (RFC 4456), next-hop preservation, VXLAN encap community, and withdrawal path. | — |
| **EVPN Type 1 + Type 4 multi-homing reflection** | Done (M32). 4-node containerlab harness: two FRR VTEPs share an ESI on a bond ES interface (same `evpn mh es-id` + `es-sys-mac`); rustbgpd RR reflects both VTEPs' Type 4 ES + Type 1 EAD-per-EVI routes to a third observing VTEP unchanged with correct RFC 4456 attributes (ORIGINATOR_ID + CLUSTER_LIST). The RR does not run DF election — VTEPs do — and the harness asserts the observer receives the inputs DF election needs. | — |
| **EVPN MAC mobility end-to-end** | Done (M31). 4-node containerlab harness validates: MAC move from VTEP-A → VTEP-C flips VTEP-B's best path and increments the MAC Mobility sequence on the reflected Type 2; sticky MAC on VTEP-A is not displaced by non-sticky takeover from VTEP-C (RFC 7432 §7.7). | — |
| **EVPN GR / LLGR stale** | Wired end-to-end (RFC 4724 + RFC 9494, graceful restart / LLGR). `mark_stale_evpn` / `promote_to_llgr_stale_evpn` / EoR clear paths validated by 13 unit + integration tests covering stale marking, LLGR promotion with `LLGR_STALE` community injection via `Arc::make_mut`, peer-originated community preservation, `NO_LLGR` drop on promotion, GR / LLGR timer sweep, and ERR `refresh_stale_evpn` tracking. | Live FRR VTEP flap against a rustbgpd RR with tcpdump capture of the reflected `LLGR_STALE` community during the restart window — the unit + integration depth is in place, the lab capture is the one piece still tracked as a follow-up. |
| **EVPN scale** | Done (M33). 50,000 Type 2 routes reflected from two originating peers to a third observer + 60 s of 1000/sec withdraw + re-advertise churn; initial convergence < 60 s, post-churn count within ±tester batch (40 routes) of 50,000, ≥½·`CHURN_RATE`·`CHURN_DURATION` withdrawal events observed (proves churn fired), tester peers stay Established without flaps, gRPC `GetHealth` / `ListEvpnRoutes` stay responsive. Load generator is the in-tree `bench/evpn-load` crate built on `rustbgpd-wire` — no third-party daemon in the measurement path. | — |
| **EVPN controller injection** | Done (controller injection, 2026-04-24). `InjectionService::AddEvpnRoute` / `DeleteEvpnRoute` cover Type 2 MAC/IP and Type 3 IMET, with display-form RD parsing (`65000:100`, `10.0.0.1:100`, `4200000000:100`); injected routes flow through the same reflection pipeline as iBGP-learned ones. CLI: `rbgp evpn add-mac-ip / add-imet / delete-mac-ip / delete-imet`. | Type 5 IP-Prefix injection is deferred pending use-case signal. Native Type 1/4 multi-homing origination ships through `[[ethernet_segments]]`; controller injection for those route types is not exposed. |

### P1.5 — EVPN VTEP-mode validation depth

| Gap | What exists today | What's missing |
|-----|-------------------|----------------|
| **VTEP FDB program (Linux FDB reconciler)** | Done (M36). rustbgpd-as-VTEP + FRR-as-originator; received Type 2 routes land both the bridge-master `extern_learn` row and the `self`/`dst` row, foreign-static entries survive, withdraw cleans up. Pairs with the privileged netns test gated on `EVPN_LINUX_NETNS=1`. | Hosted `kernel-dataplane` CI now covers the M36 containerlab smoke. |
| **VTEP local MAC origination (Type-2 + Type-3 IMET)** | Done (M37). rustbgpd-as-originator + FRR-as-consumer; `bridge fdb add` triggers Type 2 origination, `bridge fdb del` triggers withdrawal, daemon shutdown drains Type 3 IMET before peer down. | Hosted `kernel-dataplane` CI covers the M37 smoke. The M37 24 h MAC-churn soak completed and is archived at `docs/soak-m37-local-origination-churn-24h.md` plus `docs/artifacts/soak/m37-local-origination-20260518T015056Z/`, confirming the originator retention model plateaus under sustained churn. |
| **VTEP MAC-with-IP origination** | Done (M37+IP). FRR-style replace model: at most one of MAC-only / MAC+IP advertising for a MAC at any time. Operator prerequisite: `neigh_suppress on` per VXLAN port. | Hosted `kernel-dataplane` CI now covers the M37+IP smoke. |
| **VTEP Type 5 origination + import (symmetric IRB / L3VNI)** | Pure-logic helpers landed in v0.18.0 (`ip_vrf::origination` / `ip_vrf::projection`); `[[evpn_ip_vrfs]]` config, readiness probe, the `probe_ip_vrfs` plumbing through `DataplaneIntent`, and the operator-visibility surface (`DataplaneReport.ip_vrf_status` rows + `EvpnService.ListIpVrfs` / `GetIpVrf` gRPC + `rbgp evpn vrfs [NAME]` CLI) are in place. The daemon-side origination (#77) wires the per-IP-VRF kernel-route dump on every reconcile pass + conservative classifier, watch channel publication, L3 originator task with a level-triggered diff loop that gates on readiness, `IpVrfState.originated_routes_count` surfaced via gRPC/CLI. The dataplane-side import (#78) wires: best-path subscription, `project_ip_prefix_routes()` driving a transactional L3 ownership model with value-aware drift detection (kernel route + L3 neighbor + L3VXLAN FDB programmed atomically in a four-phase route-remove → resolution-add → route-add → resolution-remove ordering), foreign-state preservation, Router MAC conflict detection, and `IpVrfState.installed_routes_count` surfaced via gRPC/CLI. Two privileged netns tests at `crates/evpn-linux/tests/netns_l3_install.rs` (gated on `EVPN_LINUX_NETNS=1`) validate the kernel programming end-to-end against Linux 6.17, including foreign-preservation across an install/withdraw cycle. M30b validates Type 5 *receive* against FRR (manual-only, hosted Azure runner lacks `vrf` module). M39 covers the bidirectional smoke and now runs in the hosted kernel-dataplane workflow. | Earlier M30b remains manual on hosted runners because of the missing `vrf` module; M39 is CI-gated on the hosted kernel-dataplane runner. |
| **EVPN DF election (multi-homing)** | Done (M38 default-modulo, M46 HRW, M49 rustbgpd×rustbgpd preference-DF, M69 FRR preference-DF, RFC 9785 preference-DF + single-active unit coverage). Two-PE rustbgpd Ethernet Segment exercises RFC 7432 §8.5 default-modulo carving (M38) and RFC 8584 §3.2 Highest Random Weight (M46, over a VNI where the HRW winner differs from the modulo winner so the test proves HRW is in effect), with unanimous-or-default algorithm negotiation; `evpn_df_role` Prometheus gauge + `evpn_df_role_changes_total` counter; reflected Type 4 ES carries ES-Import RT extcomm and Type 1 EAD-per-ES carries ESI Label extcomm (BUM-flood-suppression prep). Byte-exact HRW conformance is locked by a known-answer unit test, RFC 9785 Highest-/Lowest-Preference election is covered by pure election + Type 4 DF Election extcomm tests, and M69 proves FRR's `evpn mh es-df-pref` Type 4 signal elects the FRR side cross-vendor when modulo would pick rustbgpd. The single-active ESI Label flag and receiver-side suppression of all-active alias ECMP for remote single-active reachability are unit-tested. | Cross-vendor HRW interop is not available (FRR implements RFC 9785 preference-DF, not HRW). `evpn_bum_filter_kernel` continues to cover the BUM-suppression kernel primitive on every PR. |
| **EVPN BUM-enforcement (BUM-flood suppression + DF election)** | Kernel primitive validated on every PR via the Docker harness at `crates/evpn-linux/tests/docker/` (`evpn_bum_filter_kernel` job). Enabled by default since v0.23.0 after the Gate 8b 24 h MAC-churn soak and M37 24 h local-origination soak both passed. The Gate 8b BUM-state soak, 1 h MAC-churn dry run, and 24 h MAC-churn gate are archived under `docs/soak-gate8b-*.md` plus `docs/artifacts/soak/`. | — |
