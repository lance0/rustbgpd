# rustbgpd vs GoBGP Feature Parity

Last updated: 2026-03-12

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
| L2VPN EVPN (RFC 7432) | Yes | No | Route types 1-5, 9 |
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
| Admin Shutdown Comm (RFC 8203) | Yes | Yes | Reason text in NOTIFICATION |

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
| PMSI_TUNNEL (type 22) | Yes | No | |
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
| Total RPCs | ~55 | 47 | |
| Peer CRUD | Yes | Yes | Add/Delete/List/Enable/Disable |
| Peer groups | Yes | Yes | `PeerGroupService` + neighbor membership RPCs |
| Dynamic neighbors (prefix-based) | Yes | No | |
| Path add/delete | Yes | Yes | IPv4 + IPv6 |
| Streaming path injection | Yes | No | AddPathStream |
| List paths (Adj-In/Loc/Adj-Out) | Yes | Yes | |
| Watch events (streaming) | Yes | Yes | WatchRoutes |
| Table statistics | Yes | Partial | Health endpoint |
| VRF management | Yes | No | |
| Policy CRUD via API | Yes | Yes | Named policy definition CRUD plus global/per-neighbor chain assignment |
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
| WatchEvent streaming | Yes | Yes | WatchRoutes |
| Sentry integration | Yes | No | |

## Security

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| TCP MD5 (RFC 2385) | Yes | Yes | |
| TCP-AO (RFC 5925) | No | No | Neither; on rustbgpd roadmap |
| GTSM / TTL Security (RFC 5082) | Yes | Yes | |
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
| Multipath/ECMP | Yes | Partial | Add-Path multi-path send; no FIB ECMP |

## Summary

| Category | GoBGP | rustbgpd | Parity |
|----------|:-----:|:--------:|:------:|
| Address families | 15 | 4 | ~27% |
| Core protocol | 14 | 14 | 100% |
| Path attributes | 13 | 9 | ~69% |
| Policy engine | 18 | 18 | 100% |
| gRPC RPCs | ~55 | 47 | ~85% |
| Monitoring | 5 | 5 | 100% |
| Security | 4 | 4 | 100% |
| Best-path steps | 11 | 10.5 | ~95% |

## Weighted Parity Estimates

### IX Route Server Use Case (~100% parity)

The primary target deployment. Weighted toward what matters:

- **Address families:** only need IPv4+IPv6 unicast + FlowSpec = 100% parity
- **Best-path:** 95%, missing piece (AIGP) rarely used at IXes
- **Core protocol:** 100% — GR helper + restarting speaker, LLGR, Notification GR, Enhanced RR, Add-Path, Extended Nexthop all landed
- **Policy:** 100%; covers peer-aware matching (neighbor sets, route type, MED/`LOCAL_PREF` comparison, exact next-hop match), community match/set, and AS_PATH regex/prepend
- **Add-Path send:** critical for route servers, fully implemented with multi-path
- **Route server client mode:** transparent eBGP with unicast NEXT_HOP preservation and FlowSpec AS_PATH transparency
- **BMP exporter:** RFC 7854 streaming to collectors, reconnect replay, periodic Stats Report
- **MRT dump:** RFC 6396 TABLE_DUMP_V2 periodic + on-demand with gzip
- **LLGR (RFC 9494):** two-phase timer, three-tier best-path demotion, per-AFI — critical for large IXes
- **Config persistence + SIGHUP reload:** gRPC mutations survive restart; live neighbor reconciliation
- **Operator packaging (v0.4.2):** systemd unit, example configs, operations guide, release checklist, container image CI

**Remaining gaps for IX RS parity:** no material control-plane gaps remain for the target deployment. Remaining work is operator polish: CLI integration tests, listener authorization split, and other non-protocol hardening.

### General-Purpose BGP Speaker (~73% parity)

Competing head-to-head with GoBGP for all use cases:

- Missing address families hurt badly (EVPN, VPN, labeled unicast)
- No confederation support limits SP deployments
- gRPC API covers ~86% of GoBGP's RPC surface (no VRF; dynamic-neighbor query via `ListDynamicNeighbors`, runtime Add/Delete deferred)
- No Zebra/FIB integration — cannot install routes into the kernel

## Advantages Over GoBGP

- **Extended Messages (RFC 8654)** — rustbgpd has it, GoBGP doesn't
- **Zero unsafe in application logic** — `deny(unsafe_code)` per-crate
- **Fuzz testing + property testing** — GoBGP has neither
- **Interop test suite** — Containerlab + FRR/BIRD shipped; GoBGP doesn't ship one
- **Structured logging** — tracing-subscriber JSON vs GoBGP's unstructured logs
- **RPKI integrated into best-path** — clean architecture vs GoBGP's bolt-on
- **ASPA upstream path verification** — RTR v2, best-path step 0.7, export policy matching; GoBGP has no ASPA support
- **Config persistence** — gRPC mutations atomically persisted to TOML; GoBGP doesn't persist runtime changes
- **Operator packaging** — systemd unit, example configs, operations guide, release checklist, container image CI out of the box
- **Secure-by-default gRPC** — UDS default listener, optional token auth per listener, read-only/read-write split; GoBGP defaults to open TCP
- **Rustc-style config diagnostics** — validation errors show TOML source lines with column markers; GoBGP prints plain-text errors
- **Live TUI dashboard** — `rustbgpctl top` with session table, prefix counts, message rates, and route events; GoBGP has no built-in TUI

## Top Gaps by Use Case

### IX Route Server (current target, ~100% parity)

No material protocol gaps remain. Remaining work is operator polish:

1. **CLI integration tests** — operator-quality hardening, not protocol parity.
2. **Policy UX polish** — bulk editing / richer ergonomics rather than missing
   route-server capability.
3. ~~**Built-in looking glass**~~ — shipped as birdwatcher-compatible REST API.

### General-Purpose BGP Speaker (~73% parity)

These close the biggest gaps for broader adoption but are out of scope for
the current alpha:

1. **Confederation (RFC 5065)** — required for service provider deployments
2. **EVPN (RFC 7432)** — most-requested address family after unicast + FlowSpec
3. **VPNv4/v6 (RFC 4364)** — enterprise/SP VPN deployments
4. ~~**Dynamic neighbors (prefix-based)**~~ — shipped: `[[dynamic_neighbors]]` with peer group inheritance, `remote_asn=0`, auto-accept/remove
5. **Zebra/FIB integration** — kernel route installation

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
