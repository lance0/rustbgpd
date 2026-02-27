# Roadmap

Build order and milestone plan for rustbgpd. Each milestone is a tagged
release with passing CI, updated interop matrix, and changelog entry.

---

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

## Completed

1. **rustbgpd-wire** — BGP message codec (OPEN, KEEPALIVE, NOTIFICATION,
   UPDATE encode/decode, capability parsing, property tests)
2. **rustbgpd-fsm** — RFC 4271 finite state machine (all 6 states, full
   transition table, OPEN negotiation, exponential backoff, property tests)
3. **rustbgpd-telemetry** — Prometheus metrics (8 metrics: state transitions,
   flaps, established, notifications, messages, RIB stubs) + JSON logging
4. **rustbgpd-transport** — Tokio TCP session runtime (single task per peer,
   length-delimited framing, timer management, PeerHandle API, telemetry
   integration, 18 tests including mock-peer integration)
5. **Daemon entrypoint** — TOML config loading with validation, peer session
   spawning, Prometheus `/metrics` HTTP endpoint, graceful SIGTERM shutdown
6. **CI workflow** — GitHub Actions: `cargo fmt --check`, `cargo clippy`,
   `cargo test --workspace` on every push and PR

---

## M0 — "Establish" `[complete]`

Session establishment and stability. The daemon connects to peers,
completes OPEN/KEEPALIVE exchange, and holds Established state.

### Build Order

1. ~~**rustbgpd-wire** — OPEN, KEEPALIVE, NOTIFICATION encode/decode~~ **Done**
   - BGP header (marker, length, type) parsing with 4096-byte enforcement
   - OPEN message: version, ASN, hold time, router ID, capabilities
   - Capability TLV parsing: 4-byte ASN (code 65), MP-BGP (code 1)
   - KEEPALIVE message (header only, no body)
   - NOTIFICATION message: error code, subcode, data
   - Property tests: `encode(decode(x)) == x` roundtrip
   - Fuzz harness: message decode from arbitrary bytes

2. ~~**rustbgpd-fsm** — Pure RFC 4271 state machine~~ **Done**
   - Six states: Idle, Connect, Active, OpenSent, OpenConfirm, Established
   - Input events: message received, timer fired, TCP connected/disconnected
   - Output actions: send message, start/stop timer, connect, disconnect
   - OPEN negotiation: hold time, capabilities, ASN validation
   - Negotiation result struct: agreed caps, AFI/SAFI set, peer ASN, peer ID
   - No tokio imports, no I/O — pure function from (State, Event) → (State, Actions)

3. ~~**rustbgpd-telemetry** — Metrics and structured logging~~ **Done**
   - Prometheus counters: session state transitions, flaps, NOTIFICATIONs
   - RIB metric stubs (exist at zero): update latency, backpressure, drops
   - Structured JSON events for FSM transitions

4. ~~**rustbgpd-transport** — Tokio TCP glue~~ **Done**
   - Single-task-per-peer session runtime with `tokio::select!`
   - Read loop: bytes → `peek_message_length` → `decode_message` → FSM event
   - Write loop: FSM action → `encode_message` → TCP write
   - Timer management: `Option<Pin<Box<Sleep>>>` with freestanding `poll_timer`
   - `PeerHandle` / `PeerCommand` API for external control (Start, Stop, Shutdown)
   - Iterative action loop avoids async recursion
   - Full telemetry integration (state transitions, messages, notifications)

5. ~~**Daemon entrypoint** — Config, metrics, peer wiring, shutdown~~ **Done**
   - TOML config loading and validation (`src/config.rs`)
   - Prometheus `/metrics` HTTP endpoint (`src/metrics_server.rs`)
   - CLI arg parsing, telemetry init, peer spawn, SIGTERM shutdown (`src/main.rs`)
   - CI workflow: fmt, clippy, test (`.github/workflows/ci.yml`)

6. ~~**Interop validation** — FRR and BIRD~~ **Done**
   - ~~Containerlab topology: rustbgpd ↔ FRR (10.3.1)~~ **Pass**
   - ~~Containerlab topology: rustbgpd ↔ BIRD (2.0.12)~~ **Pass**
   - ~~Test: session establishment~~ **Pass** (both peers)
   - ~~Test: peer restart recovery~~ **Pass** (both peers)
   - ~~Test: TCP reset recovery~~ **Pass** (both peers)
   - ~~Test: establish, hold 30+ minutes, verify keepalives~~ **Pass** (FRR 35min/73 KAs, BIRD 35min)
   - ~~Test: malformed OPEN → correct NOTIFICATION~~ **Pass** (Bad Peer AS → code 2/subcode 2)

### Exit Criteria

- Establish and hold 30+ minutes with FRR and BIRD
- Survive peer restart and TCP reset
- Correct NOTIFICATION on malformed OPEN
- Prometheus metrics capture all state transitions
- Structured log events for every FSM transition

---

## M1 — "Hear"

Decode UPDATEs. Store in Adj-RIB-In. Expose via gRPC.

- UPDATE decode: IPv4 unicast NLRI, withdrawn routes
- Path attributes: ORIGIN, AS_PATH (2-byte + 4-byte), NEXT_HOP, LOCAL_PREF, MED
- Unknown transitive attribute pass-through (Partial bit policy)
- Adj-RIB-In per neighbor
- `ListReceivedRoutes` gRPC endpoint
- Attribute validation matrix (all checks from DESIGN.md)
- Fuzz harness for UPDATE decoder
- Interop: RIB dump matches peer's advertised routes

## M2 — "Decide"

Loc-RIB best-path selection.

- Best-path comparison: LOCAL_PREF → AS_PATH length → ORIGIN → MED → eBGP/iBGP → router-id → peer address
- Total ordering property tests (no ties for distinct paths)
- `ListBestRoutes` gRPC endpoint
- Structured events for best-path changes

## M3 — "Speak"

Route injection, advertisement, and policy.

- `AddPath` / `DeletePath` gRPC endpoints
- Adj-RIB-Out computation per neighbor
- UPDATE encoding and advertisement
- Import/export allow/deny policy
- Max-prefix enforcement (NOTIFICATION Cease on exceed)
- TCP MD5 authentication (Linux only)
- GTSM / TTL security

## M4 — "Route Server Mode"

Scale to many peers with per-peer policy.

- 50+ peers in containerlab, stable under churn
- Per-peer import/export filters
- Communities pass-through (optional)
- RIB scaling evaluation
- `WatchRoutes` streaming gRPC endpoint

---

## Post-v1

- MP-BGP (IPv6 unicast)
- Communities and extended communities
- FlowSpec speaker mode (prefixd lineage)
- BMP exporter
- RPKI validation (RTR client)
- Graceful restart
- TCP-AO authentication
- Config persistence (gRPC → TOML writeback)
- Extended message support (RFC 8654)

---

## Non-Goals

These are explicitly out of scope. Not "maybe later" — out of scope.

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
