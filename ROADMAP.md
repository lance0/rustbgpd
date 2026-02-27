# Roadmap

Build order and milestone plan for rustbgpd. Each milestone is a tagged
release with passing CI, updated interop matrix, and changelog entry.

---

## M0 — "Establish" `[current]`

Session establishment and stability. The daemon connects to peers,
completes OPEN/KEEPALIVE exchange, and holds Established state.

### Build Order

1. **rustbgpd-wire** — OPEN, KEEPALIVE, NOTIFICATION encode/decode
   - BGP header (marker, length, type) parsing with 4096-byte enforcement
   - OPEN message: version, ASN, hold time, router ID, capabilities
   - Capability TLV parsing: 4-byte ASN (code 65), MP-BGP (code 1)
   - KEEPALIVE message (header only, no body)
   - NOTIFICATION message: error code, subcode, data
   - Property tests: `encode(decode(x)) == x` roundtrip
   - Fuzz harness: message decode from arbitrary bytes

2. **rustbgpd-fsm** — Pure RFC 4271 state machine
   - Six states: Idle, Connect, Active, OpenSent, OpenConfirm, Established
   - Input events: message received, timer fired, TCP connected/disconnected
   - Output actions: send message, start/stop timer, connect, disconnect
   - OPEN negotiation: hold time, capabilities, ASN validation
   - Negotiation result struct: agreed caps, AFI/SAFI set, peer ASN, peer ID
   - No tokio imports, no I/O — pure function from (State, Event) → (State, Actions)

3. **rustbgpd-telemetry** — Metrics and structured logging
   - Prometheus counters: session state transitions, flaps, NOTIFICATIONs
   - RIB metric stubs (exist at zero): update latency, backpressure, drops
   - Structured JSON events for FSM transitions

4. **rustbgpd-transport** — Tokio TCP glue
   - TCP listener and outbound connection management
   - Read loop: bytes → wire::decode → FSM input
   - Write loop: FSM output → wire::encode → bytes
   - Bounded channels between reader/writer/FSM
   - Session lifecycle: connect, established, teardown
   - Integration with telemetry counters

5. **Interop validation**
   - Containerlab topology: rustbgpd ↔ FRR
   - Containerlab topology: rustbgpd ↔ BIRD
   - Test: establish, hold 30+ minutes, verify keepalives
   - Test: peer restart recovery
   - Test: TCP reset recovery
   - Test: malformed OPEN → correct NOTIFICATION

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
- FlowSpec speaker mode
- BMP exporter
- RPKI validation (RTR client)
- Graceful restart
- TCP-AO authentication
- Config persistence (gRPC → TOML writeback)
- Extended message support (RFC 8654)
