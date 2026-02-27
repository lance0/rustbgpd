# Changelog

All notable changes to rustbgpd will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses milestone-based versioning aligned with the design
document (M0–M4).

---

## [Unreleased]

### Added

- Workspace with 7 crates: wire, fsm, transport, rib, policy, api, telemetry
- gRPC proto skeleton (`rustbgpd.v1` package, all 5 services)
- Containerlab interop topologies for FRR 10.x and BIRD 2.x
- Design document, RFC notes, interop matrix template
- Roadmap with market context and milestone plan (M0–M4)
- `rustbgpd-wire`: OPEN, KEEPALIVE, NOTIFICATION, UPDATE encode/decode
- `rustbgpd-wire`: Capability parsing (4-byte ASN, MP-BGP, unknown pass-through)
- `rustbgpd-wire`: Strict 4096-byte message size enforcement
- `rustbgpd-wire`: `DecodeError::to_notification()` mapping for protocol errors
- `rustbgpd-wire`: Property tests (`encode(decode(x)) == x` roundtrip)
- `rustbgpd-fsm`: RFC 4271 §8 state machine (all 6 states, full transition table)
- `rustbgpd-fsm`: Timer management as input events / output actions
- `rustbgpd-fsm`: OPEN validation and capability negotiation
- `rustbgpd-fsm`: Exponential backoff on connect retry (30s–300s)
- `rustbgpd-fsm`: Property tests (no panics on arbitrary event sequences)
- `rustbgpd-telemetry`: Prometheus metrics (state transitions, flaps, notifications, messages)
- `rustbgpd-telemetry`: RIB metric stubs (registered at zero for M1)
- `rustbgpd-telemetry`: Structured JSON logging via tracing-subscriber with env-filter
- `rustbgpd-transport`: Single-task-per-peer Tokio TCP session runtime
- `rustbgpd-transport`: Length-delimited framing with `peek_message_length`
- `rustbgpd-transport`: Timer management with `poll_timer` future for `select!` compatibility
- `rustbgpd-transport`: `PeerHandle` / `PeerCommand` API for spawning and controlling sessions
- `rustbgpd-transport`: Full OPEN/KEEPALIVE handshake, reconnection, and teardown
- `rustbgpd-transport`: Telemetry integration (state transitions, messages, notifications)

---

## [0.0.1] — Unreleased

Target: **M0 — "Establish"**

### Done

- `rustbgpd-wire`: OPEN, KEEPALIVE, NOTIFICATION encode/decode
- `rustbgpd-wire`: Capability parsing (4-byte ASN, MP-BGP)
- `rustbgpd-wire`: Strict 4096-byte message size enforcement
- `rustbgpd-fsm`: RFC 4271 state machine (all 6 states)
- `rustbgpd-fsm`: Timer inputs (ConnectRetry, Hold, Keepalive)
- `rustbgpd-fsm`: OPEN negotiation and capability exchange
- `rustbgpd-telemetry`: Prometheus metric stubs (8 metrics, all counters at zero)
- `rustbgpd-telemetry`: Structured JSON log events via tracing-subscriber
- `rustbgpd-transport`: Single-task-per-peer TCP session runtime
- `rustbgpd-transport`: Framing, timers, connect/disconnect lifecycle
- `rustbgpd-transport`: 18 tests (12 unit + 6 integration with mock peer)

### Remaining

- Fuzz harness stubs for wire decoder
- Interop validation with FRR and BIRD

### Exit Criteria

- Establish and hold 30+ minutes with FRR and BIRD
- Survive peer restart and TCP reset
- Correct NOTIFICATION on malformed OPEN
- Prometheus metrics capture all state transitions
- Structured log events for every FSM transition
