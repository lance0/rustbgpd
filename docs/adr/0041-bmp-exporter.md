# ADR-0041: BMP Exporter (RFC 7854)

**Status:** Accepted
**Date:** 2026-03-04

## Context

BMP (BGP Monitoring Protocol) is the standard way to stream BGP state to
external collectors (OpenBMP, pmacct, Wireshark). It is a unidirectional
protocol: the router initiates TCP to each collector and sends BMP messages
wrapping raw BGP PDUs. This was the #1 gap in gobgp-parity.md.

Key RFC 7854 design points:
- Router initiates TCP to collector (active client, not server)
- Unidirectional — router to collector only, no responses
- 7 message types: Initiation, Peer Up, Peer Down, Route Monitoring,
  Stats Report, Termination, Route Mirroring
- Per-peer header (42 bytes) on most messages
- Route Monitoring wraps raw UPDATE PDUs (needs original wire bytes)
- Peer Up includes raw OPEN PDUs from both sides

## Decision

### New crate: `crates/bmp/`

Four modules following the RPKI crate pattern:

- **`types.rs`** — `BmpEvent` enum (PeerUp/PeerDown/RouteMonitoring),
  `BmpPeerInfo`, `PeerDownReason`, `BmpClientConfig`
- **`codec.rs`** — All BMP message encoding functions (Initiation, Peer Up,
  Peer Down, Route Monitoring, Stats Report, Termination) plus per-peer
  header encoding
- **`client.rs`** — Per-collector async TCP client with exponential backoff
  reconnect; sends Initiation on connect, streams pre-encoded messages
- **`manager.rs`** — Fan-out manager: receives `BmpEvent` from transport,
  encodes to BMP wire format, distributes to all collector channels

### Data flow

```
PeerSession (transport)
  ├── SessionEstablished → BmpEvent::PeerUp
  ├── SessionDown        → BmpEvent::PeerDown
  └── inbound UPDATE     → BmpEvent::RouteMonitoring
         │
         ▼
  mpsc::Sender<BmpEvent>  (optional, only when BMP configured)
         │
         ▼
  BmpManager → encodes → fans out to N BmpClient tasks
```

### Raw PDU capture

`ReadBuffer::try_decode()` changed to return `(Message, Bytes)` — the decoded
message plus the original raw frame bytes. This enables byte-perfect Route
Monitoring (raw UPDATE) and Peer Up (raw OPEN) messages.

OPEN PDU capture: outbound OPEN cached from `encode_message()`, inbound OPEN
captured from raw bytes in `process_read_buffer`.

### Threading

`Option<mpsc::Sender<BmpEvent>>` threaded through main.rs → PeerManager →
PeerHandle::spawn() → PeerSession. When BMP is not configured, all fields are
`None` with minimal overhead (`Bytes` refcount clone only on decode path).

### Config

```toml
[bmp]
sys_name = "rustbgpd"
sys_descr = ""

[[bmp.collectors]]
address = "10.0.0.100:11019"
reconnect_interval = 30
```

## Consequences

### Positive

- Standard RFC 7854 monitoring — collectors like OpenBMP and pmacct work
  out of the box
- Raw PDU capture enables byte-perfect BMP Route Monitoring without
  re-encoding
- Near-zero overhead when BMP is not configured (`Bytes` refcount clones,
  no message-data copies)
- Fan-out architecture supports multiple collectors with independent
  reconnect
- Collector reconnect replay for currently Established peers (targeted to the
  collector that reconnected)
- Periodic per-peer Stats Report export (type 7, Adj-RIB-In route count)

### Negative

- `try_decode()` now clones the frame buffer for raw bytes — minor
  allocation overhead on every inbound message (only the `Bytes` ref-count
  bump when BMP is not configured, since clone is deferred)
- `PeerSession::new()` gains another parameter (mitigated by
  `#[expect(clippy::too_many_arguments)]`)

### Deferred

- Adj-RIB-Out monitoring (RFC 7854 §5, flag `O=1`)
- Route Mirroring (Type 6)
- Post-policy Route Monitoring
- gRPC BMP management (runtime add/remove collectors)
- TLS for collector connections
