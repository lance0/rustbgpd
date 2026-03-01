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
- [x] Graceful Restart — receiving speaker (RFC 4724): capability negotiation, stale route demotion, End-of-RIB detection/sending, timer-based stale sweep
- [x] 445 tests — unit, integration, property, fuzz

For detailed milestone build orders, see [docs/milestones.md](docs/milestones.md).

---

## Planned Features

### Next — Extended Communities (RFC 4360)

**Why this matters:** Route targets, traffic engineering, and VPN signaling all use extended communities. Required for any IX or transit use case that tags routes with operational metadata.

- [ ] Wire: Extended Communities attribute (type 16) decode/encode
- [ ] Wire: common subtypes (route target, route origin, 4-byte AS)
- [ ] RIB: store and expose in route data
- [ ] API: extended communities in proto Route message and AddPath
- [ ] Policy: match on extended community values in prefix lists

---

## Future Ideas

*Prioritized by effort vs user impact. Quick wins first, then bigger lifts.*

### Quick Wins (low effort, high impact)

- [ ] **Extended message support** (RFC 8654) — raise 4096-byte limit for large UPDATE messages; mainly a wire codec change
- [ ] **Config persistence** — write gRPC mutations (AddNeighbor, etc.) back to TOML so they survive restarts
- [ ] **TCP-AO authentication** (RFC 5925) — modern replacement for TCP MD5; `setsockopt` change similar to existing MD5 code
- [ ] **Route refresh** (RFC 2918) — request peer to re-advertise all routes; useful after policy changes

### Medium Effort (moderate effort, high impact)

- [ ] **BMP exporter** (RFC 7854) — stream route monitoring data to collectors (OpenBMP, pmacct); standard for visibility into BGP state
- [ ] **RPKI validation** — RTR client (RFC 8210) for route origin validation; growing regulatory requirement
- [ ] **Large communities** (RFC 8092) — 12-byte communities for 4-byte ASN operators; increasingly common at IXPs

### Larger Projects (high effort, high impact)

- [ ] **FlowSpec speaker mode** (RFC 5575) — programmatic traffic filtering rules distributed via BGP
- [ ] **Add-Path** (RFC 7911) — advertise multiple paths per prefix; essential for route servers
- [ ] **Route dampening** (RFC 2439) — suppress flapping routes with penalty/decay

### Nice to Have

- [ ] **CLI client** wrapping gRPC — convenience tool, not the primary interface
- [ ] **MRT dump export** (RFC 6396) — TABLE_DUMP_V2 for offline analysis and archival
- [ ] **YANG model / NETCONF** — alternative management interface for traditional NOC tooling

---

## Pre-1.0 Requirements

Quality gates before tagging 1.0.0:

- [x] MP-BGP (at least IPv6 unicast)
- [x] Graceful restart
- [ ] Extended communities
- [ ] Real-world deployment feedback
- [ ] Wire crate API stability (`rustbgpd-wire` publishable as 1.0)
- [ ] Comprehensive rustdoc for public API
- [ ] Security audit of gRPC surface

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
- [x] Automated interop test scripts (M1, M3, M4)
- [ ] Binary releases (GitHub Releases with cross-compiled binaries)
- [ ] Homebrew formula
- [ ] crates.io publishing (`rustbgpd-wire` first, then workspace)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style,
and PR process. Issues labeled `good first issue` are good entry points.
