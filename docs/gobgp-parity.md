# rustbgpd vs GoBGP Feature Parity

Last updated: 2026-05-27 (v0.30.0, adding ADR-0071 RFC 9234 BGP Roles + Only-to-Customer route-leak prevention, ADR-0072 durable event history with `SubscribeFromEvent` cursor replay + gNMI `Subscribe ON_CHANGE` v1 for neighbor session-state, and PR #294 ASPA algorithm fidelity / §6.2 per-AFI/SAFI gate; on top of ADR-0067 BFD, ADR-0066/0068 unicast multipath / ECMP FIB, ADR-0069 BGP unnumbered, and ADR-0070 read-only gNMI / OpenConfig telemetry from the prior release window)

## Address Families

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| IPv4 Unicast | Yes | Yes | |
| IPv6 Unicast | Yes | Yes | MP-BGP (RFC 4760) |
| IPv4 Multicast | Yes | No | |
| IPv6 Multicast | Yes | No | |
| IPv4 Labeled Unicast (RFC 8277) | Yes | No | |
| IPv6 Labeled Unicast | Yes | No | |
| VPNv4 / VPNv6 (RFC 4364) | Yes | No | |
| L2VPN VPLS (RFC 4761) | Yes | No | |
| L2VPN EVPN (RFC 7432) | Yes | Partial (RR + bidirectional VTEP, MAC-only and MAC+IP) | Route types 1-5 in RR mode with controller-injection gRPC for Type 2/3/5 (controller injection, ADR-0050). Bidirectional VTEP shipped across the declarative instance schema, FDB reconciler, local MAC + MAC+IP origination, and VTEP convergence (v0.13.0 onward, ADR-0052/0054/0055/0056): declarative `[[evpn_instances]]` schema; Linux kernel FDB programming from received Type 2 routes (downward); MAC-only and MAC+IP local origination via `RTNLGRP_NEIGH` subscription with RFC 7432 §15.1 mobility sequencing under the FRR-style replace model (one Type 2 per MAC at any time — `IpAdded` upgrades from MAC-only to MAC+IP, last `IpRemoved` downgrades back; requires `bridge neigh_suppress on`); Type 3 IMET per L2VNI carrying PMSI Tunnel (RFC 6514 §5); `advertise_svi_mac` SVI-MAC origination; `sticky_macs` (ADR-0056) for RFC 7432 §15.4 sticky bit; sub-second mobility convergence via push notification (EVPN VTEP convergence). Note that GoBGP's "Yes" here is the wire codec — GoBGP itself does not own kernel-side VTEP integration (it relies on FRR/SDN injection), so on the VTEP-mode dimension rustbgpd has functional parity-plus. Multi-homing foundation shipped in v0.17.0 (EVPN multi-homing (ESI, Type-1/Type-4), ADR-0057): observable DF election, Type 1/4 origination, and Prometheus `evpn_df_role` surface, validated by M38. EVPN BUM-flood-suppression + DF-election alpha follow-ups add ESI Label / ES-Import RT origination, production-default kernel BUM-port enforcement with opt-out config (RFC 7432 §8.5), DF-role-aware Type 2 ESI attachment, RFC 7432 §14 aliasing receive-side projection, and RFC 7432 §8.4 receive-side EAD-per-ES mass-withdraw filtering. EVPN symmetric IRB (Type-5 / L3VNI), Interface-less, shipped end-to-end in v0.18.0 (`[[evpn_ip_vrfs]]` schema, pure-logic Type 5 origination + projection, IP-VRF readiness probe, Linux netlink dumps, `Dataplane::probe_ip_vrfs`, Type 5 origination via `RibUpdate::InjectEvpn`, remote import + L3 FIB programming through the transactional `L3OwnedState` model with four-phase apply ordering, `RTNLGRP_IPV4/IPV6_ROUTE` multicast for sub-second withdraw, `ListIpVrfs`/`GetIpVrf` gRPC + `rustbgpctl evpn vrfs` CLI, M39 hosted smoke). ADR-0059 (v0.19.0) adds receive-path aliasing-ECMP via FDB nexthop groups, FRR-validated by M40. Auto-derived Route Targets (RFC 8365 §5.1.2.1 for L2VNI / AS:VNI for L3VNI), Type 5 gRPC injection including non-zero Gateway Address, receive-side RFC 9135 overlay-index recursion, and duplicate-MAC remote-route suppression + manual clear all shipped; BUM-port enforcement defaults on since v0.23.0. Remaining EVPN items: native overlay-index local origination / recursion-path interop, the two remaining ADR-0063 runtime shapes (L3VNI/device/table IP-VRF identity redefine is restart-required by design; non-teardown mixed edits fail closed — single/teardown/`ip_vrf`-relink shapes all commit live, M47/M48/M49), single-active backup-path pre-install, optional import-side ES-Import RT filtering, EVPN over MPLS/PBB, and EVPN route types 6-11 |
| IPv4/IPv6 FlowSpec (RFC 8955) | Yes | Yes | SAFI 133, all 13 component types |
| VPN FlowSpec | Yes | No | |
| BGP-LS (RFC 7752) | Yes | No | |
| SR Policy | Yes | No | |
| SRv6 MUP | Yes | No | |
| Route Target Constraints | Yes | No | |

## Core Protocol

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| RFC 4271 FSM (all 6 states) | Yes | Yes | |
| 4-byte ASN (RFC 6793) | Yes | Yes | AS_TRANS mapping |
| Capability negotiation (RFC 5492) | Yes | Yes | |
| TCP collision detection (RFC 4271 §6.8) | Yes | Yes | |
| Graceful Restart (RFC 4724) | Yes | Yes | Helper mode + restarting-speaker `R=1`; `forwarding_preserved=false` (no FIB ownership — same as GoBGP default) |
| Long-Lived GR (RFC 9494) | Yes | Yes | Two-phase timer, three-tier best-path demotion, `LLGR_STALE`/`NO_LLGR` communities, per-AFI family scoping |
| Notification GR (RFC 8538) | Yes | Yes | N-bit (RFC 8538 §2), Cease/Hard Reset bypass |
| Route Refresh (RFC 2918) | Yes | Yes | |
| Enhanced Route Refresh (RFC 7313) | Yes | Yes | `BoRR` / `EoRR` demarcation; inbound replacement semantics on `SoftResetIn` |
| Add-Path (RFC 7911) | Yes | Yes | Dual-stack receive + multi-path send (route server mode) |
| Route Reflector (RFC 4456) | Yes | Yes | |
| Confederation (RFC 5065) | Yes | No | |
| Extended Messages (RFC 8654) | No | Yes | rustbgpd supports it; GoBGP does not |
| Extended Nexthop (RFC 8950) | Yes | Yes | IPv4 unicast over IPv6 next hop |
| BGP unnumbered (interface-scoped IPv6 link-local) | Yes | Yes | Both carry IPv4 unicast over RFC 8950 on link-local interface neighbors. GoBGP uses interface autodiscovery (`neighbor-interface`, derives the peer from the link-local); rustbgpd v1 uses static `address` + `interface` (FRR-style autodiscovery deferred) and additionally installs the scoped Linux FIB next-hop with the egress `dev`. M53 validates rustbgpd against FRR. ADR-0069 |
| Admin Shutdown Comm (RFC 8203) | Yes | Yes | Reason text in NOTIFICATION |
| BGP Roles + Only-to-Customer (RFC 9234) | Partial | Yes | rustbgpd negotiates the OPEN Role capability, applies §5 strict-mode rejection on mismatch, and enforces OTC ingress / egress rules per §6 with a structured `OtcRouteBlockedEvent` payload on `SubscribeFromEvent` alongside the `bgp_otc_routes_blocked_total{peer, reason}` counter and per-peer scalar. GoBGP has draft-era support without OTC enforcement parity at last check. ADR-0071, M55. |

## Path Attributes

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| ORIGIN / AS_PATH / NEXT_HOP | Yes | Yes | |
| MED / LOCAL_PREF | Yes | Yes | |
| ATOMIC_AGGREGATE / AGGREGATOR | Yes | Yes | |
| Standard Communities (RFC 1997) | Yes | Yes | |
| Extended Communities (RFC 4360) | Yes | Yes | RT, RO, 4-byte AS |
| Large Communities (RFC 8092) | Yes | Yes | Wire, RIB, API, policy |
| ORIGINATOR_ID / CLUSTER_LIST | Yes | Yes | RR support |
| MP_REACH / MP_UNREACH (RFC 4760) | Yes | Yes | |
| AIGP (type 26) | Yes | No | |
| PMSI_TUNNEL (type 22) | Yes | Yes | RFC 6514 §5; originated on Type 3 IMET for ingress-replication BUM |
| Only-to-Customer (type 35, RFC 9234) | Partial | Yes | Codec + ingress/egress enforcement (see Core Protocol row above). |
| TUNNEL_ENCAP (type 23) | Yes | No | |
| PREFIX_SID (type 40) | Yes | No | |
| Unknown attribute passthrough | Yes | Yes | Partial bit on re-advert |

## Policy Engine

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| Prefix matching (ge/le) | Yes | Yes | IPv4 + IPv6 |
| Standard community matching | Yes | Yes | ASN:VALUE + well-known names |
| Extended community matching | Yes | Yes | RT/RO encoding-agnostic |
| Large community matching | Yes | Yes | LC:global:local1:local2 |
| AS_PATH regex | Yes | Yes | Cisco/Quagga `_` convention |
| AS_PATH length match | Yes | Yes | `match_as_path_length_ge` / `match_as_path_length_le` |
| Neighbor set matching | Yes | Yes | Address / ASN / peer-group based |
| RPKI validation result match | Yes | Yes | `match_rpki_validation` in policy |
| Route type match (int/ext/local) | Yes | Yes | `match_route_type` |
| MED / LOCAL_PREF comparison | Yes | Yes | Inclusive `match_med_*` / `match_local_pref_*` |
| Next-hop matching | Yes | Yes | Exact IPv4/IPv6 equality for unicast routes |
| Community add/remove/replace | Yes | Yes | Standard, extended, large |
| MED manipulation | Yes | Yes | set_med |
| LOCAL_PREF set | Yes | Yes | set_local_pref |
| AS_PATH prepend | Yes | Yes | set_as_path_prepend |
| Next-hop set/self | Yes | Yes | set_next_hop = "self" or IP |
| Named policy definitions | Yes | Yes | TOML definitions with configurable default_action |
| Policy chaining | Yes | Yes | GoBGP-style: permit=continue, deny=stop, implicit permit |

## gRPC API

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| Total RPCs | ~55 | 78 | 74 `rustbgpd.v1` RPCs plus 4 `gnmi.gNMI` RPCs |
| Peer CRUD | Yes | Yes | Add/Delete/List/Enable/Disable |
| Peer groups | Yes | Yes | `PeerGroupService` + neighbor membership RPCs |
| Dynamic neighbors (prefix-based) | Yes | Yes | `[[dynamic_neighbors]]` config + `ListDynamicNeighbors` (M28); runtime Add/Delete RPCs defined but stubbed |
| Path add/delete | Yes | Yes | IPv4 + IPv6 |
| Streaming path injection | Yes | No | AddPathStream |
| List paths (Adj-In/Loc/Adj-Out) | Yes | Yes | |
| Watch events (streaming) | Yes | Yes | WatchRoutes |
| gNMI / OpenConfig telemetry | No | Partial | Read-only `Capabilities` / `Get` / `Subscribe` (ONCE / POLL / STREAM SAMPLE, plus STREAM ON_CHANGE v1 for neighbor `session-state` when `[event_history]` is enabled) on a strict OpenConfig BGP state subset; `Set` returns `Unimplemented`. ADR-0070 / M54; ON_CHANGE wired in ADR-0072 / M56. |
| Table statistics | Yes | Partial | Health endpoint |
| VRF management | Yes | No | |
| Policy CRUD via API | Yes | Yes | Named policy definition CRUD plus global/per-neighbor chain assignment |
| Import-policy explain | No | Yes | `ExplainImportPolicy` RPC + `rustbgpctl policy explain` — per-prefix PERMIT/DENY/WITHDRAWN/EVICTED/STALE/NOT_SEEN decision trace at the transport eval site, IPv4/IPv6 unicast (ADR-0073) |
| RPKI management | Yes | Partial | VRP/cache status via metrics; no gRPC RPKI CRUD |
| BMP management | Yes | Partial | Config-file only; no runtime gRPC add/remove |
| MRT control | Yes | Yes | `TriggerMrtDump` RPC |
| Zebra/FRR integration | Yes | No | |
| Runtime log level | Yes | Partial | Per-peer log level via config; no global runtime gRPC toggle |
| Global config get/set | Partial | Partial | Get only on both |
| Soft reset (in/out) | Yes | Yes | SoftResetIn RPC |
| Graceful shutdown RPC | Yes | Yes | |

## Monitoring & Observability

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| Prometheus metrics | Yes | Yes | rustbgpd has more granular RIB metrics |
| Structured logging | No | Yes | JSON via tracing-subscriber |
| BMP exporter (RFC 7854) | Yes | Yes | Per-collector TCP client, Initiation/PeerUp/PeerDown/RouteMonitoring/StatsReport/Termination |
| MRT dump (RFC 6396) | Yes | Yes | `TABLE_DUMP_V2` periodic + on-demand; gzip optional (ADR-0044) |
| WatchEvent streaming | Yes | Yes | `WatchRoutes` + `WatchEvents` (legacy broadcast) plus `SubscribeFromEvent` with a durable monotonic-`event_id` cursor that survives daemon restart and post-incident reconnect; backed by the SQLite-WAL event outbox (ADR-0072). `rustbgpctl events watch --from-event-id N` and the `examples/event-bridge` reference binary consume the cursor. |
| Durable event history / cursor replay | No | Yes | ADR-0072: producers across RIB, EVPN, PeerManager session lifecycle, policy, BFD, and dataplane FIB / blackhole all enqueue durable events; the `[event_history]` config block controls retention by count + bytes. `bgp_event_outbox_cursor_gap_total` counts subscribe requests where the requested cursor was older than the retention floor. |
| gNMI / OpenConfig telemetry | No | Yes | Read-only `gnmi.gNMI` target for a strict OpenConfig BGP state subset (`Capabilities`, `Get`, `Subscribe` ONCE / POLL / STREAM SAMPLE, plus STREAM ON_CHANGE v1 for neighbor `session-state` when `[event_history]` is enabled; `Set` returns `Unimplemented`). Served on mTLS TCP or local UDS; M54 + M56 validate with `gnmic` |
| Sentry integration | Yes | No | |

## Security

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| TCP MD5 (RFC 2385) | Yes | Yes | |
| TCP-AO (RFC 5925) | No | Static startup | rustbgpd applies static-neighbor TCP-AO keys on Linux startup active-open and passive-listener sockets; dynamic neighbors, live rotation, and multi-key rollover remain follow-ups |
| GTSM / TTL Security (RFC 5082) | Yes | Yes | |
| BFD (RFC 5880/5881/5882) | No | Yes | Single-hop async BFD with IPv4 + IPv6 global static neighbors, `[[bfd_profiles]]` / `[neighbors.bfd]`, `GetBfdSessions`, `rustbgpctl bfd`, Prometheus/events, and RFC 5882 strict + non-strict BGP coupling. M51 validates non-strict failover/recovery against FRR `bfdd`. Deferred: multihop, echo/demand, auth, dynamic-neighbor BFD, and IPv6 link-local / unnumbered |
| RPKI/RTR (RFC 6811/8210) | Yes | Yes | Persistent RTR session with `SerialNotify`, fallback serial polling, and enforced expiry |
| Private AS removal | Yes | Yes | Three modes: `remove`, `all`, `replace` (ADR-0045) |
| LLGR_STALE stripping (RFC 9494 §4.6) | N/A | Yes | Strip `LLGR_STALE` from exports to non-LLGR peers |

## Operations

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| Config formats | TOML/YAML/JSON/HCL | TOML | |
| Config reload (SIGHUP) | Yes | Yes | Neighbor diff + reconcile; global changes require restart |
| Config persistence | No | Yes | gRPC mutations atomically persisted to TOML |
| Prefix limits | Yes | Yes | Cease/1 enforcement |
| Embeddable library | Yes (Go) | No | Wire crate is standalone |
| CLI tool | Yes (gobgp) | Yes | `rustbgpctl` wraps gRPC API |
| Live TUI dashboard | No | Yes | `rustbgpctl top` — sessions, prefix counts, message rates, route events |
| Rustc-style config errors | No | Yes | Source-line spans with column markers on validation errors |
| Docker image | Yes | Yes | |
| Route server client mode | Yes | Yes | Transparent eBGP export for unicast plus FlowSpec AS_PATH transparency |
| Fuzz testing | No | Yes | Wire decoder fuzzing |
| Interop test suite | No | Yes | Containerlab + FRR/BIRD |

## Best-Path Selection

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| LOCAL_PREF | Yes | Yes | |
| AS_PATH length | Yes | Yes | |
| ORIGIN | Yes | Yes | |
| MED | Yes | Yes | Always-compare (deterministic) |
| eBGP over iBGP | Yes | Yes | |
| CLUSTER_LIST length | Yes | Yes | RFC 4456 §9 |
| ORIGINATOR_ID | Yes | Yes | RFC 4456 §9 |
| Lowest peer tiebreaker | Yes | Yes | |
| Stale route demotion | Yes | Yes | GR step 0 |
| RPKI preference | Yes | Yes | Step 0.5: Valid > NotFound > Invalid |
| AIGP | Yes | No | |
| Multipath/ECMP | Yes | Yes | Classic unicast FIB ECMP ships via ADR-0066: `[[fib_tables]].maximum_paths`, per-class `maximum_paths_ebgp` / `maximum_paths_ibgp`, homogeneous eBGP or iBGP groups, and kernel `RTA_MULTIPATH` install. `[global].multipath_relax` provides FRR-style AS_PATH-length grouping; ADR-0068 adds Link Bandwidth weighted multipath. Add-Path multi-path send and EVPN aliasing ECMP also ship |

## Summary

| Category | GoBGP | rustbgpd | Parity |
|----------|:-----:|:--------:|:------:|
| Address families | 15 | 4 | ~27% |
| Core protocol | 14 | 14 | 100% |
| Path attributes | 13 | 9 | ~69% |
| Policy engine | 18 | 18 | 100% |
| gRPC RPCs | ~55 | 78 | 100%+ (broader surface, including read-only gNMI) |
| Monitoring | 5 | 6 | 100%+ |
| Security | 4 | 5 | 100%+ |
| Best-path steps | 11 | 11 | 100% except AIGP |

## Weighted Parity Estimates

### IX Route Server Use Case (~100% parity)

A first-class target deployment. Weighted toward what matters:

- **Address families:** only need IPv4+IPv6 unicast + FlowSpec = 100% parity
- **Best-path:** 100% for the IX path; AIGP remains the only missing listed best-path step and is rarely used at IXes
- **Core protocol:** 100% — GR helper + restarting speaker, LLGR, Notification GR, Enhanced RR, Add-Path, Extended Nexthop all landed
- **Policy:** 100%; covers peer-aware matching (neighbor sets, route type, MED/`LOCAL_PREF` comparison, exact next-hop match), community match/set, and AS_PATH regex/prepend
- **Add-Path send:** critical for route servers, fully implemented with multi-path
- **Route server client mode:** transparent eBGP with unicast NEXT_HOP preservation and FlowSpec AS_PATH transparency
- **BMP exporter:** RFC 7854 streaming to collectors, reconnect replay, periodic Stats Report
- **MRT dump:** RFC 6396 TABLE_DUMP_V2 periodic + on-demand with gzip
- **LLGR (RFC 9494):** two-phase timer, three-tier best-path demotion, per-AFI — critical for large IXes
- **Config persistence + SIGHUP reload:** gRPC mutations survive restart; live neighbor reconciliation
- **Operator packaging (v0.4.2):** systemd unit, example configs, operations guide, release checklist, container image CI

**Remaining gaps for IX RS parity:** no material control-plane gaps remain for the target deployment. Remaining work is operator polish: CLI integration tests and other non-protocol hardening.

### General-Purpose BGP Speaker (~87% parity)

Competing head-to-head with GoBGP for all use cases:

- EVPN RR + bidirectional VTEP shipped (Phase 1 ADR-0050; Phase 2 ADR-0052/0054/0055/0056 — MAC-only Type 2 + Type 3 IMET in v0.15.0, MAC+IP Type 2 via ARP/ND suppression in v0.16.0 under the FRR replace model). EVPN multi-homing (ESI, Type-1/Type-4) plus BUM-flood suppression + DF election (v0.17.0+) add alpha multi-homing execution: DF election, Type 1/4 origination, production-default kernel BUM-port enforcement with opt-out config (RFC 7432 §8.5), ESI-aware Type 2 origination, RFC 7432 §14 aliasing receive-side projection, and RFC 7432 §8.4 mass-withdraw filtering. EVPN symmetric IRB (Type-5 / L3VNI), Interface-less, shipped end-to-end in v0.18.0 (IP-VRF schema, Type 5 origination + remote import + L3 FIB programming with four-phase apply ordering, sub-second `RTNLGRP_IPV4/IPV6_ROUTE` withdraw, `rustbgpctl evpn vrfs` CLI + `ListIpVrfs`/`GetIpVrf` gRPC, M39 smoke). ADR-0059 aliasing dataplane ECMP shipped via FDB nexthop groups, M40 FRR smoke. Auto-derived RTs, Type 5 gRPC injection including non-zero Gateway Address, receive-side RFC 9135 overlay-index recursion, duplicate-MAC remote suppression + manual clear, and production-default DF/non-DF BUM suppression + aliasing ECMP all shipped. Still missing: VXLAN local-bias split-horizon (ASIC/offload-dependent on the Linux softswitch — ADR-0065, the remaining all-active correctness gate), native overlay-index local origination / recursion-path interop, the two remaining ADR-0063 runtime shapes (L3VNI/device/table IP-VRF identity redefine — restart-required by design; non-teardown mixed edits — fail closed; relink + teardown + single shapes all commit live), single-active backup-path pre-install, EVPN over MPLS/PBB, and EVPN route types 6-11
- VPNv4/v6 and labeled unicast missing
- No confederation support limits SP deployments
- gRPC API exposes a broader operator surface than GoBGP's raw API count, shaped differently: BFD inspection via `GetBfdSessions`, EVPN IP-VRF visibility via `ListIpVrfs` / `GetIpVrf`, dynamic-neighbor query via `ListDynamicNeighbors`, and a read-only OpenConfig/gNMI target for existing telemetry collectors
- Linux FIB integration is scoped and opt-in: RFC 7999 discard routes and ADR-0061 configured-table unicast installs exist, and ADR-0066/0068 now cover unicast multipath / ECMP FIB including per-class caps, `multipath_relax`, and Link Bandwidth weighted multipath. It is still not a Zebra-compatible full routing-suite backend or redistribution manager

## Advantages Over GoBGP

- **Extended Messages (RFC 8654)** — rustbgpd has it, GoBGP doesn't
- **Zero unsafe in application logic** — `deny(unsafe_code)` per-crate
- **Fuzz testing + property testing** — GoBGP has neither
- **Interop test suite** — Containerlab + FRR/BIRD shipped; GoBGP doesn't ship one
- **Structured logging** — tracing-subscriber JSON vs GoBGP's unstructured logs
- **RPKI integrated into best-path** — clean architecture vs GoBGP's bolt-on
- **ASPA upstream path verification** — RTR v2, best-path step 0.7, export policy matching; GoBGP has no ASPA support
- **BFD integration (RFC 5880/5881/5882)** — rustbgpd has in-process single-hop async BFD with strict and non-strict RFC 5882 BGP coupling; GoBGP has no BFD integration
- **Unicast FIB ECMP beyond Add-Path** — rustbgpd installs kernel `RTA_MULTIPATH` routes with `maximum_paths`, per-class eBGP/iBGP caps, `multipath_relax`, and Link Bandwidth weighted multipath
- **Read-only gNMI / OpenConfig telemetry** — rustbgpd exposes a native `gnmi.gNMI` service for OpenConfig BGP operational state (`Capabilities`, `Get`, `Subscribe` SAMPLE/POLL/ONCE, plus STREAM ON_CHANGE v1 for neighbor `session-state`), verified with `gnmic`; GoBGP exposes its own gRPC API but not an OpenConfig/gNMI target
- **Import-policy explain** — `ExplainImportPolicy` RPC + `rustbgpctl policy explain` answer "why didn't this prefix come in?" from a per-session import-decision cache that records both permits and denies at the transport eval site (ADR-0073); GoBGP has no per-prefix import-decision diagnostic
- **Config persistence** — gRPC mutations atomically persisted to TOML; GoBGP doesn't persist runtime changes
- **Operator packaging** — systemd unit, example configs, operations guide, release checklist, container image CI out of the box
- **Secure-by-default gRPC** — UDS default listener, optional token auth per listener, read-only/read-write split; GoBGP defaults to open TCP
- **Rustc-style config diagnostics** — validation errors show TOML source lines with column markers; GoBGP prints plain-text errors
- **Live TUI dashboard** — `rustbgpctl top` with session table, prefix counts, message rates, and route events; GoBGP has no built-in TUI
- **EVPN RR + bidirectional VTEP via API-first + kernel-integrated model** — Phase 1 RR (ADR-0050) covers RFC 7432 Types 1-5 with MAC Mobility best-path, VXLAN encap community, gRPC `ListEvpnRoutes`, and controller-driven `AddEvpnRoute` / `DeleteEvpnRoute` injection (Type 2/3); validated end-to-end against FRR 10.3.1 and at 50k-route scale with churn (M30-M33). Phase 2 (declarative instance schema, FDB reconciler, local MAC + MAC+IP origination, VTEP convergence; ADR-0052/0054/0055/0056) adds the **bidirectional VTEP loop**: kernel FDB programming from received Type 2 routes (M36), local MAC/MAC+IP origination via `RTNLGRP_NEIGH` with RFC 7432 §15.1 mobility sequencing, Type 3 IMET per L2VNI (M37), SVI MAC origination, sticky MAC config, and sub-second mobility wakeups. EVPN multi-homing (ESI, Type-1/Type-4) plus BUM-flood suppression + DF election (v0.17.0+) add alpha multi-homing execution: DF election (M38), Type 1/4 origination, opt-in kernel BUM-port enforcement (RFC 7432 §8.5), ESI-aware Type 2 origination, RFC 7432 §14 aliasing receive-side projection, and RFC 7432 §8.4 mass-withdraw filtering. EVPN symmetric IRB (Type-5 / L3VNI), Interface-less, shipped end-to-end in v0.18.0 (`[[evpn_ip_vrfs]]`, Type 5 origination + remote import + L3 FIB programming, `Dataplane::probe_ip_vrfs`, sub-second route-event subscription, `rustbgpctl evpn vrfs`, M39 hosted smoke against FRR 10.3.1). ADR-0059 aliasing dataplane ECMP shipped in v0.19.0 (M40 FRR smoke). On the VTEP-mode dimension this is functional parity-plus over GoBGP — GoBGP exposes the EVPN wire codec but does not own kernel-side FDB integration. GoBGP retains an edge on remaining overlay-index local origination / recursion-path interop and mature production multi-homing soak time-in-deployment. rustbgpd's operational model stays API-first throughout

## Top Gaps by Use Case

### IX Route Server (~99% parity)

The one remaining IX-relevant control-plane gap is **ORF / Outbound Route
Filtering (RFC 5291)** — FRR and GoBGP let a peer push a prefix-filter so the
route server suppresses unwanted routes before sending them; rustbgpd does not
negotiate ORF yet (tracked under ROADMAP "Next"). Otherwise no material
control-plane gaps remain; remaining work is operator polish: CLI integration
tests, bulk policy-edit ergonomics, and production packaging hardening rather
than missing protocol capability.

### DC Fabric / Whitebox BGP Speaker (~95% parity)

BGP unnumbered, scoped link-local FIB installs, ECMP / weighted multipath, BFD,
read-only gNMI, and EVPN RR / VTEP work make this a first-class deployment
target. Remaining gaps are narrower:

1. **BGP unnumbered autodiscovery** — rustbgpd v1 requires static
   `address` + `interface`; FRR-style `neighbor IFACE interface remote-as
   external` remains deferred.
2. **IPv6 link-local BFD for unnumbered peers** — follows naturally from the
   scoped peer identity in ADR-0069, but ADR-0067 intentionally shipped global
   IPv4 / IPv6 single-hop first.
3. **Config transaction / diff UX** — required before any serious gNMI `Set`
   or broader remote-mutation story.
4. ~~**Durable event replay**~~ — *shipped in v0.30.0 (ADR-0072 + ADR-0072
   follow-up sprint).* `SubscribeFromEvent` with monotonic-`event_id` cursor
   carries the post-incident debugging story; gNMI `ON_CHANGE` v1 for
   neighbor `session-state` consumes the same in-process broadcast.

### General-Purpose BGP Speaker (~87% parity)

The remaining broad-market gaps are mostly service-provider or full-router
scope:

1. **VPNv4/v6 and labeled unicast** — enterprise/SP VPN deployments.
2. **Confederation (RFC 5065)** — service-provider deployments.
3. **Full Zebra/FIB integration and redistribution** — ADR-0061/0066/0068/0069
   add configured-table kernel route installation with scoped next-hop identity,
   per-table caps, ECMP, per-class caps, `multipath_relax`, Link Bandwidth
   weighted multipath, and link-local gateway support, but rustbgpd is still not
   a full routing-suite backend or redistribution manager.
4. **EVPN standards tail** — native overlay-index local origination,
   recursion-path interop, single-active backup-path pre-install, EVPN over
   MPLS/PBB, and route types 6-11.
5. **Operational policy features** — ORF / Outbound Route Filtering (RFC 5291;
   route-server-relevant, tracked under ROADMAP "Next") and conditional
   advertisement (advertise-if-present / advertise-if-absent; demand-shaped).
   Both are carried by FRR and GoBGP.

## Pre-1.0 Tech Debt

| Priority | Item | Impact |
|----------|------|--------|
| ~~HIGH~~ | ~~manager.rs at ~8,318 lines~~ | Done — split into 7 submodules (mod.rs, distribution.rs, peer_lifecycle.rs, route_refresh.rs, graceful_restart.rs, helpers.rs, tests.rs) |
| ~~HIGH~~ | ~~`config.rs` at 3,118 lines~~ | Done — split into `src/config/` submodules for schema, parsing, validation, and tests |
| ~~HIGH~~ | ~~`transport/session.rs` at 3,967 lines~~ | Done — split into `crates/transport/src/session/` submodules for core loop, FSM, I/O, inbound, outbound, commands, and tests |
| ~~MEDIUM~~ | ~~Refactor policy `evaluate()` to take a `RouteContext` struct~~ | Done — `RouteContext<'a>` replaces 7+ params; `#[expect(clippy::too_many_arguments)]` removed from all production policy code |
| ~~MEDIUM~~ | ~~`RibManager::handle_update()` at 615 lines~~ | Done — thin dispatcher in mod.rs delegates to focused handlers in distribution, peer_lifecycle, route_refresh, graceful_restart |
| ~~MEDIUM~~ | ~~Policy engine tests concentrated in one file~~ | Done — split into 8 focused test modules: prefix, community, large_community, aspath_regex, as_path_length, modifications, chain, rpki |
| ~~MEDIUM~~ | ~~No FlowSpec fuzz target~~ | Done — `decode_flowspec` target added |
| ~~MEDIUM~~ | ~~RTR expire_interval not enforced~~ | Done — stale VRPs now expire and are withdrawn if no fresh EndOfData arrives before the effective expiry timer |
| MEDIUM | Unknown FlowSpec component types rejected | Should be preserved/skipped for forward compatibility with future RFCs |
| ~~LOW~~ | ~~`timer.rs:118` production `panic!()`~~ | Done — removed |
| ~~LOW~~ | ~~CLI `.unwrap()` on JSON serialization~~ | Done — only test code uses `.unwrap()` now |
| ~~LOW~~ | ~~RTR client polling-only~~ | Done — RTR sessions stay connected and honor Serial Notify |
