# rustbgpd vs GoBGP Feature Parity

Last updated: 2026-03-04

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
| Graceful Restart (RFC 4724) | Yes | Partial | Receiving speaker only; GoBGP does both + restarting |
| Long-Lived GR (RFC 9494) | Yes | No | Per-AFI timers |
| Notification GR (RFC 8538) | Yes | No | |
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
| AS_PATH length match | Yes | No | |
| Neighbor set matching | Yes | No | |
| RPKI validation result match | Yes | Yes | `match_rpki_validation` in policy |
| Route type match (int/ext/local) | Yes | No | |
| MED / LOCAL_PREF comparison | Yes | No | |
| Next-hop matching | Yes | No | |
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
| Total RPCs | ~55 | ~20 | |
| Peer CRUD | Yes | Yes | Add/Delete/List/Enable/Disable |
| Peer groups | Yes | No | |
| Dynamic neighbors (prefix-based) | Yes | No | |
| Path add/delete | Yes | Yes | IPv4 + IPv6 |
| Streaming path injection | Yes | No | AddPathStream |
| List paths (Adj-In/Loc/Adj-Out) | Yes | Yes | |
| Watch events (streaming) | Yes | Yes | WatchRoutes |
| Table statistics | Yes | Partial | Health endpoint |
| VRF management | Yes | No | |
| Policy CRUD via API | Yes | No | Config-file only |
| RPKI management | Yes | Partial | VRP/cache status via metrics; no gRPC RPKI CRUD |
| BMP management | Yes | No | |
| MRT control | Yes | No | |
| Zebra/FRR integration | Yes | No | |
| Runtime log level | Yes | No | |
| Global config get/set | Partial | Partial | Get only on both |
| Soft reset (in/out) | Yes | Yes | SoftResetIn RPC |
| Graceful shutdown RPC | Yes | Yes | |

## Monitoring & Observability

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| Prometheus metrics | Yes | Yes | rustbgpd has more granular RIB metrics |
| Structured logging | No | Yes | JSON via tracing-subscriber |
| BMP exporter (RFC 7854) | Yes | No | On roadmap |
| MRT dump (RFC 6396) | Yes | No | On roadmap |
| WatchEvent streaming | Yes | Yes | WatchRoutes |
| Sentry integration | Yes | No | |

## Security

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| TCP MD5 (RFC 2385) | Yes | Yes | |
| TCP-AO (RFC 5925) | No | No | Neither; on rustbgpd roadmap |
| GTSM / TTL Security (RFC 5082) | Yes | Yes | |
| RPKI/RTR (RFC 6811/8210) | Yes | Partial | Poll-based RTR client; Serial Notify + expiry deferred |
| Private AS removal | Yes | No | |

## Operations

| Feature | GoBGP | rustbgpd | Notes |
|---------|:-----:|:--------:|-------|
| Config formats | TOML/YAML/JSON/HCL | TOML | |
| Config reload (SIGHUP) | Yes | No | |
| Config persistence | No | No | On rustbgpd roadmap |
| Prefix limits | Yes | Yes | Cease/1 enforcement |
| Embeddable library | Yes (Go) | No | Wire crate is standalone |
| CLI tool | Yes (gobgp) | No | grpcurl works |
| Docker image | Yes | Yes | |
| Route server client mode | Yes | Partial | Transparent eBGP unicast mode via `route_server_client`; FlowSpec transparency deferred |
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
| Core protocol | 14 | 9 | ~64% |
| Path attributes | 13 | 9 | ~69% |
| Policy engine | 18 | 13 | ~72% |
| gRPC RPCs | ~55 | ~20 | ~36% |
| Monitoring | 5 | 3 | 60% |
| Security | 4 | 2.5 | ~63% |
| Best-path steps | 11 | 10 | ~91% |

## Weighted Parity Estimates

### IX Route Server Use Case (~70-75% parity)

The primary target deployment. Weighted toward what matters:

- **Address families:** only need IPv4+IPv6 unicast + FlowSpec = 100% parity
- **Best-path:** 91%, missing piece (AIGP) rarely used at IXes
- **Policy:** 72% with named definitions and chaining; covers common operations (prefix match, community match/set, AS_PATH regex/prepend, next-hop self)
- **Core protocol:** GR receiving-only covers the IX route server case well
- **Add-Path send:** critical for route servers, fully implemented with multi-path

### General-Purpose BGP Speaker (~45-50% parity)

Competing head-to-head with GoBGP for all use cases:

- Missing address families hurt badly (EVPN, VPN)
- No confederation support limits SP deployments
- GR restarting speaker needed for router role
- No CLI tool limits adoption by network engineers

## Advantages Over GoBGP

- **Extended Messages (RFC 8654)** — rustbgpd has it, GoBGP doesn't
- **Zero unsafe in application logic** — `deny(unsafe_code)` per-crate
- **Fuzz testing + property testing** — GoBGP has neither
- **Interop test suite** — Containerlab + FRR/BIRD shipped; GoBGP doesn't ship one
- **Structured logging** — tracing-subscriber JSON vs GoBGP's unstructured logs
- **RPKI integrated into best-path** — clean architecture vs GoBGP's bolt-on

## Top 5 Gaps for Maximum Parity Gain

1. **GR restarting speaker** — core protocol 64% → 71%, unlocks router deployments
2. ~~**Policy chaining + named policies**~~ — done
3. ~~**Extended nexthop (RFC 8950)**~~ — done
4. **CLI tool** — practical usability; grpcurl is a poor substitute for `gobgp` CLI
5. **BMP exporter (RFC 7854)** — standard route monitoring export for visibility and external collectors

Each moves the needle 3-5% on overall parity while disproportionately improving real-world usability.

## Pre-1.0 Tech Debt

| Priority | Item | Impact |
|----------|------|--------|
| HIGH | manager.rs at ~7,100 lines | Hardest file to review; split into distribution.rs, flowspec.rs, revalidation.rs, graceful_restart.rs |
| HIGH | Policy engine has 0 unit tests | 57 tests exist but all indirect through engine.rs; needs dedicated test module |
| ~~MEDIUM~~ | ~~No FlowSpec fuzz target~~ | Done — `decode_flowspec` target added |
| MEDIUM | RTR expire_interval not enforced | Stale VRPs persist indefinitely if cache goes silent without disconnecting |
| MEDIUM | Unknown FlowSpec component types rejected | Should be preserved/skipped for forward compatibility with future RFCs |
| LOW | RTR client polling-only | No Serial Notify; deferred by design |
