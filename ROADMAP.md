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

## Completed (v0.2.0)

- [x] MP-BGP (IPv6 unicast) — RFC 4760: `MP_REACH_NLRI` / `MP_UNREACH_NLRI` decode/encode, `Ipv6Prefix` type, `Prefix` enum for AFI-agnostic RIB, AFI/SAFI capability negotiation, dual-stack route exchange, IPv6 route injection via gRPC, FRR dual-stack interop validated
- [x] BGP wire codec — OPEN, UPDATE, NOTIFICATION, KEEPALIVE, NLRI, path attributes, communities, RFC-compliant flag validation, fuzz harness
- [x] RFC 4271 state machine — all 6 states, full transition table, OPEN negotiation, property tests
- [x] Tokio transport — single task per peer, inbound listener, TCP MD5/GTSM, session counters, NLRI batching, TCP collision detection (RFC 4271 §6.8)
- [x] RIB — Adj-RIB-In, Loc-RIB best-path (RFC 4271 §9.1.2 with eBGP preference), Adj-RIB-Out with split horizon, dirty peer resync, route injection, WatchRoutes streaming
- [x] Policy — prefix lists with ge/le matching (IPv4 + IPv6), per-peer import/export, global fallback
- [x] gRPC API — 5 services: Global, Neighbor, RIB, Injection, Control (all IPv6-capable)
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
- [x] Large Communities (RFC 8092) — 12-byte wire codec, RIB accessor, gRPC API, policy matching and set/delete actions (ADR-0031)
- [x] Review hardening: IPv4 NEXT_HOP wire path, RT/RO ASN validation, AS_PATH regex AS_SET braces, zero-length LC rejection, EC logical add/remove equivalence, AS_SEQUENCE overflow guard
- [x] Extended Messages (RFC 8654) — raise 4096-byte BGP message limit to 65535 bytes; capability code 6, unconditional advertisement, dynamic buffer sizing (ADR-0032)
- [x] Add-Path (RFC 7911) — dual-stack receive + multi-path send (route server mode); capability code 69, NlriEntry composite keying, RIB re-keying with (Prefix, path_id), multi-candidate best-path selection, rank-based path ID assignment, per-candidate export policy, gRPC path_id fields (ADR-0033)
- [x] Extended nexthop (RFC 8950) — capability code 5; automatic dual-stack capability advertisement, IPv4 unicast NLRI over IPv6 next hop via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` (ADR-0037)
- [x] RPKI origin validation (RFC 6811 + RFC 8210) — RTR client, VRP table, best-path integration, policy `match_rpki_validation`, new rpki crate (ADR-0034)
- [x] 850 tests — unit, integration, property, fuzz

For detailed milestone build orders, see [docs/milestones.md](docs/milestones.md).

---

## Planned Features

*Ordered by what unlocks production use. The policy engine is the critical
path — without route manipulation, rustbgpd is observation-only.*

*For GoBGP feature parity details, see [docs/gobgp-parity.md](docs/gobgp-parity.md).*

### P0 — Production Blockers (Complete)

All P0 features shipped. See Completed section above.

- [x] **Policy actions** — route modification on import/export (ADR-0030)
- [x] **AS_PATH regex matching** — Cisco/Quagga-style patterns in policy (ADR-0030)
- [x] **Large communities** (RFC 8092) — full feature track (ADR-0031)

### Deferred Hardening

Items identified during review that are not correctness bugs but improve strictness.

- [ ] **Unknown FlowSpec component forward compatibility** — component types >13 currently cause hard decode errors; should skip unknown types to allow future RFC extensions without breaking interop
- [x] **FlowSpec fuzz target** — `decode_flowspec` fuzz target added for direct FlowSpec NLRI decoding coverage
- [ ] **Policy engine unit tests** — 57 tests exist but all indirect via engine.rs integration tests; needs dedicated test module with isolated unit tests per match/action type
- [ ] **Large community duplicate normalization** — received UPDATEs with duplicate large communities are stored and re-advertised unchanged; strict RFC 8092 behavior would dedup on receipt and before encode
- [ ] **RTR persistent session + Serial Notify** — RTR client currently disconnects after each EndOfData and reconnects after refresh_interval; keeping the TCP session open would allow receiving Serial Notify for faster cache-change propagation (RFC 8210 §8)
- [ ] **RTR expire_interval enforcement** — config and server-advertised expire timers are accepted but not enforced; VRPs should be cleared if no fresh EndOfData arrives within the expiry window
- [ ] **ERR metrics** — no gauge for active enhanced route refresh windows or pending refresh-stale route count; would improve operational visibility during soft resets
- [ ] **Inbound BoRR/EoRR retry on channel-full** — inbound BoRR/EoRR markers are silently dropped (with warning) when the RIB channel is full; unlike outbound responses which have `pending_refresh` retry, inbound markers have no recovery path

### P1 — Core Protocol Gaps

Features that close meaningful protocol gaps vs GoBGP.

- [x] **Extended Messages** (RFC 8654) — raise 4096-byte limit to 65535; capability code 6 (ADR-0032)
- [x] **Add-Path** (RFC 7911) — dual-stack receive + family-aware multi-path send (route server mode); composite RIB keying, multi-candidate best-path, rank-based path IDs (ADR-0033)
- [x] **RPKI validation** — RTR client (RFC 8210) for route origin validation; VRP table, best-path step 0.5, policy matching (ADR-0034)
- [x] **FlowSpec** (RFC 8955/8956) — IPv4 and IPv6 unicast FlowSpec (SAFI 133); all 13 component types, numeric/bitmask operators, FlowSpec actions via extended communities, gRPC injection/query (ADR-0035)

### P2 — High-Impact Parity Gaps

Features that close the most impactful gaps vs GoBGP for the target user base.
Each moves overall parity 3-5% while disproportionately improving real-world usability.

- [x] **Transparent route server mode** — `route_server_client` per neighbor: skip automatic local ASN prepend, preserve original NEXT_HOP on eBGP unicast re-advertisement for IX route-server clients; FlowSpec transparency remains deferred (ADR-0039)
- [x] **GR restarting speaker** — minimal honest mode: static peers advertise `R=1` after coordinated restart via persisted marker file; `forwarding_preserved` remains false until FIB integration exists (ADR-0040)
- [x] **Policy chaining + named policies** — named TOML definitions, GoBGP-style chain evaluation (permit=continue, deny=stop), configurable default_action (ADR-0036)
- [x] **Extended nexthop** (RFC 8950) — capability code 5, automatic dual-stack negotiation, IPv4 unicast over IPv6 next-hop via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` (ADR-0037)
- [ ] **CLI tool** — `rustbgpctl` wrapping gRPC; grpcurl is a poor substitute for `gobgp` CLI; TUI mode as a follow-on
- [x] **Admin shutdown communication** (RFC 8203) — human-readable reason text in Cease NOTIFICATION; threaded from gRPC DisableNeighbor through transport
- [x] **Enhanced Route Refresh** (RFC 7313) — BoRR/EoRR demarcation and inbound family replacement semantics for `SoftResetIn`

### P2.5 — Operational Polish

Features that improve day-to-day operations.

- [ ] **Config persistence** — write gRPC mutations (AddNeighbor, etc.) back to TOML so they survive restarts
- [ ] **BMP exporter** (RFC 7854) — stream route monitoring data to collectors (OpenBMP, pmacct); standard for visibility into BGP state
- [ ] **MRT dump export** (RFC 6396) — TABLE_DUMP_V2 for offline analysis and archival

### P3 — Scale & Hardening

Prove it works under pressure before 1.0.

- [ ] **RIB scale benchmarks** — large table import/export (100k+ prefixes), memory profiling, best-path convergence time
- [ ] **Churn benchmarks** — route flap throughput, reconvergence latency under UPDATE storms
- [ ] **CI regression tracking** — automated benchmark runs with threshold-based alerts
- [ ] **Peer flap storms** — repeated session up/down under load; verify no resource leaks
- [ ] **gRPC churn** — concurrent AddNeighbor/DeleteNeighbor/SoftResetIn calls; verify no deadlocks or panics
- [ ] **Repeated GR recovery** — back-to-back graceful restart cycles; verify stale sweep correctness
- [ ] **Long-duration stability** — multi-hour runs with active route exchange; monitor memory and fd usage

### P4 — Nice to Have

Valuable but not blocking production use or 1.0.

- [ ] **TCP-AO authentication** (RFC 5925) — modern replacement for TCP MD5 (GoBGP doesn't have it either)
- [ ] **Route dampening** (RFC 2439) — suppress flapping routes with penalty/decay
- [ ] **TUI mode** for `rustbgpctl` — interactive terminal UI for monitoring and management; follow-on to CLI
- [ ] **YANG model / NETCONF** — alternative management interface for traditional NOC tooling

### Interop Test Hardening

Ongoing improvements to the test infrastructure.

- [ ] **`trap cleanup EXIT`** — auto-destroy topology on failure; guard with a `--deploy` flag so manual workflows aren't disrupted
- [ ] **EoR detection by polling** — replace `sleep 10` in M11 test 3 with a `wait_eor()` loop that polls `bgp_gr_stale_routes` until 0
- [ ] **Timestamps in log output** — `date +%H:%M:%S` in `log()`/`ok()`/`fail()` across all 5 scripts; especially useful for GR timing
- [ ] **Pre-flight checks** — verify `grpcurl`, `docker`, `containerlab` exist before running any tests

---

## Pre-1.0 Requirements

Quality gates before tagging 1.0.0:

- [x] MP-BGP (at least IPv6 unicast)
- [x] Graceful restart
- [x] Extended communities
- [x] Policy actions (match + modify + filter)
- [x] Large communities (RFC 8092)
- [ ] Real-world deployment feedback
- [ ] Wire crate API stability (`rustbgpd-wire` publishable as 1.0)
- [ ] Comprehensive rustdoc for public API
- [ ] Security audit of gRPC surface
- [ ] **manager.rs split** — currently ~7,700 lines; split into distribution.rs, revalidation.rs, graceful_restart.rs submodules for reviewability
- [ ] **RTR expire_interval enforcement** — VRPs should be cleared if no fresh EndOfData arrives within the expiry window; currently accepted but not enforced

---

## Competitive Landscape

| | FRR / BIRD | GoBGP | rustbgpd |
|---|---|---|---|
| **Primary interface** | CLI | gRPC | gRPC |
| **Runtime** | C | Go (GC) | Rust (no GC) |
| **Scope** | Full routing suite | BGP-only | BGP-only |
| **Dynamic peers** | Config reload | gRPC | gRPC |
| **Real-time events** | Log parsing | BMP/MRT | gRPC streaming |
| **Observability** | SNMP, CLI | Prometheus | Prometheus + structured logs |
| **Wire codec reuse** | No | No | `rustbgpd-wire` standalone crate |

---

## Scope Creep / Non-Goals

rustbgpd is an **API-first BGP daemon**. The following are explicitly out of scope:

- **Full routing suite.** No OSPF, IS-IS, LDP, MPLS, PIM. This is a BGP daemon.
- **CLI-first operation.** The CLI is a convenience wrapper around gRPC,
  not the primary interface. If you want rich CLI, use `grpcurl` or write
  a client.
- **GoBGP proto compatibility.** Our protos are our own. A compat adapter
  can exist as a separate project if anyone wants it.
- **Windows support.** Linux is the target. macOS for dev builds only.
- **Web UI / dashboard.** Grafana + Prometheus is the monitoring story.
  We export metrics, not render dashboards.
- **Plugin system in v1.** Policy is built-in and minimal. WASM/DSL
  plugins are post-v1 if the core is stable enough to warrant them.

If you need these features, combine rustbgpd with purpose-built tools.

---

## Infrastructure

- [x] GitHub Actions CI (fmt, clippy, test on every push/PR)
- [x] Nightly fuzz CI (wire decoder fuzzing)
- [x] Docker image (multi-stage Dockerfile)
- [x] Containerlab interop topologies (FRR 10.3.1, BIRD 2.0.12)
- [x] Automated interop test scripts (M1, M3, M4, M10, M11, M12)
- [ ] Binary releases (GitHub Releases with cross-compiled binaries)
- [ ] Homebrew formula
- [ ] crates.io publishing (`rustbgpd-wire` first, then workspace)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style,
and PR process. Issues labeled `good first issue` are good entry points.
