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

---

## [0.0.1] — Unreleased

Target: **M0 — "Establish"**

### Planned

- `rustbgpd-wire`: OPEN, KEEPALIVE, NOTIFICATION encode/decode
- `rustbgpd-wire`: Capability parsing (4-byte ASN, MP-BGP)
- `rustbgpd-wire`: Strict 4096-byte message size enforcement
- `rustbgpd-fsm`: RFC 4271 state machine (all 6 states)
- `rustbgpd-fsm`: Timer inputs (ConnectRetry, Hold, Keepalive)
- `rustbgpd-fsm`: OPEN negotiation and capability exchange
- `rustbgpd-transport`: Tokio TCP session management
- `rustbgpd-transport`: Bounded channels with backpressure
- `rustbgpd-telemetry`: Prometheus metric stubs (counters at zero)
- `rustbgpd-telemetry`: Structured JSON log events
- Fuzz harness stubs for wire decoder

### Exit Criteria

- Establish and hold 30+ minutes with FRR and BIRD
- Survive peer restart and TCP reset
- Correct NOTIFICATION on malformed OPEN
- Prometheus metrics capture all state transitions
- Structured log events for every FSM transition
