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
- [x] gRPC API — 7 services: Global, Neighbor, Policy, PeerGroup, RIB, Injection, Control (all IPv6-capable)
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
- [x] 946+ tests — unit, integration, property, fuzz

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
- [x] **gRPC UDS + bearer auth hardening** — gRPC now defaults to a local Unix domain socket, TCP listeners are explicit opt-in, and per-listener bearer-token auth is available via `token_file`
- [x] **FlowSpec fuzz target** — `decode_flowspec` fuzz target added for direct FlowSpec NLRI decoding coverage
- [x] **Policy engine test modularization** — extracted the `merge_from` + `PolicyChain` test cluster into `engine/tests/chain.rs` to reduce monolithic test sprawl while preserving behavior
- [ ] **Large community duplicate normalization** — received UPDATEs with duplicate large communities are stored and re-advertised unchanged; strict RFC 8092 behavior would dedup on receipt and before encode
- [x] **RTR persistent session + Serial Notify** — RTR client now keeps the TCP session open after EndOfData, honors Serial Notify for immediate updates, and uses refresh_interval as a fallback serial-poll timer (RFC 8210 §8)
- [x] **RTR expire_interval enforcement** — config and server-advertised expire timers are now enforced; VRPs are cleared if no fresh EndOfData arrives before the expiry window
- [ ] **ERR metrics** — no gauge for active enhanced route refresh windows or pending refresh-stale route count; would improve operational visibility during soft resets
- [ ] **Inbound BoRR/EoRR retry on channel-full** — inbound BoRR/EoRR markers are silently dropped (with warning) when the RIB channel is full; unlike outbound responses which have `pending_refresh` retry, inbound markers have no recovery path
- [x] **BMP collector reconnect replay** — `BmpManager` caches live Peer Up state and replays it only to the collector that just reconnected
- [x] **BMP periodic Stats Report** — `PeerManager` now emits per-peer periodic BMP Stats Report messages (type 7: Adj-RIB-In routes) every 60 seconds
- [x] **BMP Termination on daemon shutdown** — coordinated shutdown now signals `BmpManager` explicitly, then drains manager/client tasks with bounded waits so connected collectors receive Termination before process exit
- [ ] **BMP event-drop counters** — BMP send paths currently log dropped events on channel-full but do not expose a Prometheus counter for replay/stats/route-monitoring drop rates
- [ ] **BMP transport integration tests** — codec and manager are covered, but session-to-BMP emission paths (PeerUp/PeerDown/RouteMonitoring) still lack end-to-end tests
- [ ] **BMP periodic stats scalability** — `emit_periodic_bmp_stats` serializes `query_state().await` per peer; at hundreds of peers this could stall the PeerManager select! loop; consider concurrent queries or cached counts
- [ ] **BMP client connect-loop shutdown** — client stuck in TCP connect-backoff cannot observe channel close until next `rx.recv()`; mitigated by abort timeout but prevents clean Termination to unreachable collectors
- [ ] **Duplicate BMP collector address detection** — two collectors with the same address are accepted without warning, resulting in duplicate data streams
- [ ] **CLI gRPC integration tests** — `rustbgpctl` has parser/format tests but no mock-server integration tests for command-to-RPC behavior
- [ ] **SIGHUP reconcile rollback semantics** — reload now reports structured per-peer failures and keeps the prior config snapshot, but does not roll back already-applied runtime peer changes from earlier reconcile steps
- [ ] **MRT snapshot encode allocation pressure** — `TABLE_DUMP_V2` encode path currently builds grouped route vectors and clones attributes per entry; correct but allocation-heavy on very large dumps (optimize if MRT CPU/latency becomes material)
- [ ] **gRPC listener split** — separate read-only and mutating RPC listeners / bind addresses so monitoring can be exposed without exposing control-plane writes
- [ ] **Native gRPC mTLS** — terminate TLS inside the daemon for operators who do not want an Envoy/nginx sidecar
- [ ] **Finer-grained gRPC authorization** — per-service or per-RPC authorization beyond binary listener access

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

- [ ] **Rust-compiler-style config errors** — show the actual TOML with line numbers, underline the bad field, and suggest corrections ("did you mean `ipv4_unicast`?"). Every Rust developer will feel at home. Use `miette` or `ariadne` for rendering.
- [x] **`rustbgpd --check config.toml`** — validate config without starting the daemon. Print structured errors or "config OK". Operators run this before every reload and deploy.
- [x] **Startup banner with topology summary** — on boot, print a clean tree showing ASN, router-id, peer count by type, named policies, neighbor sets, listener endpoints, optional subsystems (RPKI caches, BMP collectors, MRT output). First thing an operator sees after starting the daemon.
- [x] **Shell completions** — `rustbgpctl completions {bash,zsh,fish}` generates completions from clap derives. Pre-generated files shipped in `examples/completions/`.

#### CLI Polish

- [ ] **Colored, tabular CLI output** — aligned tables, colored session states (green=Established, yellow=OpenSent, red=Idle/Active), human-readable uptime ("2d 4h 12m" not seconds), prefix counts with delta indicators. Make `rustbgpctl neighbor` look as good as a Grafana panel in a terminal.
- [ ] **Route filtering in CLI** — `rustbgpctl rib best --prefix 10.0.0.0/8 --longer --community 65001:100 --from 10.0.0.2`. Server-side filtering via gRPC, not client-side grep. This is what operators do 50 times a day.
- [x] **`--version` flag** — both `rustbgpd --version` and `rustbgpctl --version`.
- [ ] **`rustbgpctl diff`** — show what a pending config reload (SIGHUP) would change: peers added/removed/modified, policy changes, timer changes. Dry-run for config changes.

#### Debugging & Observability

- [ ] **Policy trace / route explain** — `rustbgpctl route explain 203.0.113.0/24`: show the route's full journey — which peer announced it, import policy evaluation step-by-step (which statement matched, what modifications applied), best-path selection with ranked candidates and tie-break reasons, then per-peer export policy evaluation showing why it was or wasn't advertised to each neighbor. No BGP daemon does this well. This is the flagship feature.
- [ ] **Config diff on SIGHUP** — log exactly what changed on reload: "neighbor 10.0.0.2: hold_time 90->45, added to peer-group rs-clients". Currently operators have to guess what a reload did.
- [ ] **Per-peer log filtering** — `rustbgpctl logs --peer 10.0.0.2` or structured log field `peer=10.0.0.2` that makes grep/jq filtering trivial. Currently all peers log to the same stream.
- [ ] **Route diff on policy change** — after hot-applying an export policy change, log a summary: "export policy changed: 12 routes newly advertised to 10.0.0.2, 3 routes withdrawn". Currently operators see the recomputation but not the outcome.

#### Advanced UX

- [ ] **Live TUI dashboard** — `rustbgpctl top`: a terminal UI (ratatui) showing sessions, prefix counts, message rates per peer, memory usage, RPKI cache status, all updating live via WatchRoutes + metrics streams. Think `htop` for BGP. Nothing else in the BGP world has this.
- [ ] **Built-in looking glass** — `rustbgpd --looking-glass :8080`: read-only HTTP/JSON API for NOC dashboards and public looking glass pages. Single binary, zero config. IXes would love this for member-facing route queries.
- [ ] **Config snippets / examples in error messages** — when a gRPC call fails validation, include a working example in the error detail: "invalid families value; try: `families: [\"ipv4_unicast\", \"ipv6_unicast\"]`"
- [ ] **Neighbor auto-discovery logging** — when a peer connects that isn't configured, log it clearly with suggested config: "unknown peer 10.0.0.5 AS 65005 connected; to accept: `rustbgpctl neighbor 10.0.0.5 add --asn 65005`". Helps operators bootstrap new peers.

### P3.5 — Scale & Hardening

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
- [ ] **YANG model / NETCONF** — alternative management interface for traditional NOC tooling

### Interop Test Coverage

Existing tests (M1, M3, M4, M10, M11, M12) cover IPv4/IPv6 unicast, route
injection, dynamic peers, GR helper mode, and extended communities. The
following tests close the remaining coverage gaps for features shipped
post-M12.

**Must-test (high signal, high risk):**

- [x] **M13: Policy engine** — FRR ↔ rustbgpd: `set_local_pref`, `set_med`, community add, AS_PATH prepend, AS_PATH regex match, export deny, policy chain accumulation (15/15)
- [x] **M14: Route Reflector** (RFC 4456) — iBGP client/non-client reflection, ORIGINATOR_ID/CLUSTER_LIST, 3-node topology (14/14)
- [x] **M15: Route Refresh** (RFC 2918 + 7313) — `SoftResetIn` via gRPC, session stability, import policy reapplication (10/10)
- [x] **M16: LLGR** (RFC 9494) — GR → LLGR-stale promotion, reconnect clears stale (8/8)

**Should-test (important, lower blast radius):**

- [ ] **M17: Add-Path multi-path send** (RFC 7911) — rank-based path IDs, multiple candidates advertised to FRR
- [ ] **M18: Extended next-hop** (RFC 8950) — IPv4 unicast over IPv6 next-hop via `MP_REACH_NLRI`
- [ ] **M19: Transparent route server** — skip ASN prepend, preserve original NEXT_HOP on eBGP re-advertisement
- [ ] **M20: Private AS removal** — all three modes (`remove`, `all`, `replace`) validated against FRR

**Deferred (hard to interop-test or low wire-level risk):**

- RPKI (needs running validator), FlowSpec (limited FRR support), BMP (needs collector), MRT (offline format), config persistence/SIGHUP (daemon-internal), Notification GR, Admin Shutdown, Extended Messages (capability negotiation only), gRPC security (not wire protocol)

### Interop Test Infrastructure

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
- [x] Comprehensive rustdoc for public API (hand-written crates; generated proto stubs excluded)
- [ ] Security audit of gRPC surface
- [x] **RibManager submodule split** — 8,318-line manager.rs split into 7 submodules (mod.rs, distribution.rs, peer_lifecycle.rs, route_refresh.rs, graceful_restart.rs, helpers.rs, tests.rs)
- [x] **RTR expire_interval enforcement** — VRPs are now cleared if no fresh EndOfData arrives before the expiry window

---

## Competitive Landscape

| | FRR / BIRD | GoBGP | rustbgpd |
|---|---|---|---|
| **Primary interface** | CLI | gRPC | gRPC |
| **Runtime** | C | Go (GC) | Rust (no GC) |
| **Scope** | Full routing suite | BGP-only | BGP-only |
| **Dynamic peers** | Config reload | gRPC | gRPC |
| **Real-time events** | Log parsing | BMP/MRT | gRPC streaming + BMP + MRT |
| **Observability** | SNMP, CLI | Prometheus | Prometheus + structured logs |
| **Wire codec reuse** | No | No | `rustbgpd-wire` standalone crate |

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
- [x] Automated interop test scripts (M1, M3, M4, M10, M11, M12)
- [ ] Binary releases (GitHub Releases with cross-compiled binaries)
- [ ] Homebrew formula
- [ ] crates.io publishing (`rustbgpd-wire` first, then workspace)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style,
and PR process. Issues labeled `good first issue` are good entry points.
