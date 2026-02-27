# RFC Implementation Notes

Notes keyed to RFC sections. Documents interpretations, deviations, and
implementation choices made during development.

---

## Milestone 0 — RFC 4271 Sections

### §4.2 — OPEN Message

- **Hold Time negotiation:** Use the minimum of local and remote proposed
  hold times. If the negotiated value is non-zero and less than 3 seconds,
  send NOTIFICATION (2, 6) — Unacceptable Hold Time. Zero means no
  keepalives (supported but discouraged in config docs).
- **BGP Identifier:** Validated as a valid IPv4 address (non-zero,
  non-multicast). Collision detection per §6.8.
- **Version:** Only BGP-4 (version 4). Any other version gets
  NOTIFICATION (2, 1) — Unsupported Version Number, with data field
  containing the supported version (4).
- **My AS:** 4-byte ASN support via RFC 6793 capability. If the peer
  does not advertise 4-byte ASN capability, we use 2-byte AS in OPEN
  and set AS_TRANS (23456) if our ASN > 65535.

### §4.3 — UPDATE Message

- Wire-level decode implemented in M0. Full processing (NLRI, path
  attributes, validation, RIB population) implemented in M1.
- NLRI uses prefix-length encoding: 1 byte prefix length + ceil(len/8)
  bytes of address. Host bits are masked off on decode.
- Path attribute TLV: flags(1) + type(1) + length(1 or 2) + value.
  Extended Length flag (0x10) controls 2-byte length field.
- 2-byte vs 4-byte AS_PATH encoding controlled by `four_octet_as`
  capability negotiated in OPEN.
- Structural decode (can I read these bytes?) separated from semantic
  validation (is the attribute set RFC-compliant?). See ADR-0012.

### §4.4 — KEEPALIVE Message

- Sent at negotiated hold_time / 3 interval.
- If hold_time is 0, no KEEPALIVEs are sent or expected.

### §4.5 — NOTIFICATION Message

- All error codes and subcodes per RFC 4271 Table 9 are defined as
  typed enums, not raw integers.
- On send: log structured event, then close the TCP connection.
- On receive: log structured event, transition FSM to Idle.

### §6.8 — BGP Identifier Collision

- If an OPEN is received from a peer with the same BGP Identifier as
  an existing session, the collision resolution procedure applies:
  compare local and remote BGP Identifiers as unsigned 32-bit integers.
  The connection initiated by the higher ID is kept.

### §8 — Finite State Machine

- All six states implemented: Idle, Connect, Active, OpenSent,
  OpenConfirm, Established.
- All timers modeled as inputs (not spawned internally): ConnectRetry,
  Hold, Keepalive.
- DelayOpen timer: not implemented in v1 (RFC 4271 §8 optional).
- Exponential backoff on connect retry: `base * 2^counter`, capped at
  300s, reset on ManualStart or reaching Established.
- Initial hold timer before OPEN negotiation: 240s (RFC 4271 "large
  value"), replaced by negotiated value once OPEN exchange completes.
- `handle_event` never returns `Result` — every (State, Event) pair
  produces a well-defined output. Invalid events in any state produce a
  NOTIFICATION (FSM Error) and transition to Idle.
- `SessionDown` action only emitted when leaving Established state.
  Failed handshakes are not surfaced as session-down events.
- `StateChanged` action emitted on every state transition for telemetry.

### §8.2 — Timers (transport implementation)

- Timers are `Option<Pin<Box<Sleep>>>` in the transport layer. `None`
  means the timer is stopped; `Some` means it is running.
- A freestanding `poll_timer` future is used in `tokio::select!` to
  avoid `&mut self` borrow conflicts with other select branches.
- When a timer fires, the transport clears the slot (`= None`) before
  feeding the event to the FSM. The FSM may restart the timer via a
  `StartTimer` action in the same event cycle.

### §8.2 — TCP Connection Management (transport implementation)

- Transport uses `Option<TcpStream>` for connection state. `None` when
  disconnected; the TCP read branch of `select!` is disabled via a
  guard (`if stream.is_some()`).
- `InitiateTcpConnection` action triggers `TcpStream::connect` with a
  configurable timeout. The result is returned as a follow-up FSM event
  (`TcpConnectionConfirmed` or `TcpConnectionFails`).
- Send failures (OPEN, KEEPALIVE) are treated as TCP failures: the
  stream is dropped and `TcpConnectionFails` is queued.
- `CloseTcpConnection` drops the stream and clears the read buffer.

### §10 — Error Handling

- Every error condition maps to a specific NOTIFICATION code/subcode.
- No generic error paths. Each failure has a unique structured event.

---

## RFC 6793 — 4-Byte ASN Support

### Capability Advertisement

- Capability code 65, length 4, containing our 4-byte ASN.
- If peer advertises this capability, 4-byte AS_PATH segments are used.
- If peer does not advertise it, 2-byte AS encoding is used with
  AS_TRANS (23456) substitution where necessary.

### AS_TRANS Handling

- When encoding for a 2-byte-only peer: replace any ASN > 65535 with
  AS_TRANS in AS_PATH, and include AS4_PATH for the full path.
- When decoding from a 2-byte-only peer: if AS4_PATH is present,
  reconstruct the true path per RFC 6793 §4.2.3.

---

## Interpretation Decisions

These are deliberate choices where the RFC is ambiguous or permits
multiple behaviors. Each is documented here for auditability.

### Partial Bit Policy

When re-advertising an unrecognized optional transitive attribute,
rustbgpd OR's the Partial bit (flag 0x20). All other flags and the
attribute bytes are preserved unchanged. This is not configurable in v1.

**Rationale:** rustbgpd has not validated the semantics of the
attribute. Marking it Partial is the correct conservative signal to
downstream peers. Matches behavior of FRR, BIRD, and most production
implementations.

### Cease Subcode Fallback

When tearing down a session due to resource exhaustion (e.g., global
route limit exceeded), rustbgpd sends NOTIFICATION Cease with subcode 4
(Out of Resources) per RFC 4486 §3.

**Fallback:** If interop testing reveals a peer that rejects unknown
Cease subcodes, the fallback is generic Cease (code 6, subcode 0).
Documented per-peer in INTEROP.md.

### Strict 4096-Byte Maximum Message Size

RFC 4271 §4.1 specifies a maximum message size of 4096 bytes. rustbgpd
enforces this strictly:

- **Inbound:** Any message with a length field > 4096 is rejected with
  NOTIFICATION (1, 2) — Bad Message Length. The raw length value is
  included in the NOTIFICATION data field.
- **Outbound:** Any attempt to encode a message > 4096 bytes is an
  internal error (not a protocol error). This is caught at encode time
  and produces a structured error event. The message is not sent.
- **No extended message support in v1.** RFC 8654 (Extended Message
  Support) is a post-v1 roadmap item. Until then, 4096 is a hard limit.

### Hold Time Floor

If the negotiated hold time is non-zero and less than 3 seconds,
rustbgpd sends NOTIFICATION (2, 6) — Unacceptable Hold Time. This
prevents pathologically short hold times that would cause false flaps.
RFC 4271 recommends a minimum of 3 seconds; we enforce it.

---

## Milestone 1 — RFC 4271 Sections

### §5.1.1 — ORIGIN Attribute

- Decoded from 1-byte value: 0=IGP, 1=EGP, 2=INCOMPLETE.
- Well-known mandatory. Flags must be Optional=0, Transitive=1.

### §5.1.2 — AS_PATH Attribute

- Segments decoded as type(1) + count(1) + ASNs(2 or 4 bytes each).
- Segment types: AS_SEQUENCE (2), AS_SET (1).
- Empty segments (count=0) are rejected as malformed (NOTIFICATION 3,11).
- 4-byte ASN encoding used when `four_octet_as` capability is negotiated.

### §5.1.3 — NEXT_HOP Attribute

- 4 bytes decoded as IPv4 address.
- Validated: 0.0.0.0, 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 are
  all rejected with NOTIFICATION (3, 8) — Invalid NEXT_HOP Attribute.
- Mandatory for eBGP with NLRI. Not required for iBGP (may be omitted
  or set by the transport layer).

### §5.1.4 — MULTI_EXIT_DISC (MED) Attribute

- 4 bytes decoded as u32.
- Optional non-transitive. Decoded and stored but not yet used in
  best-path comparison (M2 scope).

### §5.1.5 — LOCAL_PREF Attribute

- 4 bytes decoded as u32.
- Well-known mandatory (iBGP scope). Decoded and stored but not yet
  used in best-path comparison (M2 scope).

### §6.3 — UPDATE Message Error Handling

- All validation checks produce specific NOTIFICATION subcodes:
  - (3,1) Malformed Attribute List — duplicate type codes
  - (3,2) Unrecognized Well-known Attribute — Optional=0 + unknown type
  - (3,3) Missing Well-known Attribute — ORIGIN, AS_PATH, NEXT_HOP (eBGP)
  - (3,4) Attribute Flags Error — well-known with wrong Optional/Transitive
  - (3,8) Invalid NEXT_HOP Attribute — reserved/multicast/loopback address
  - (3,11) Malformed AS_PATH — empty segment
- Validation is separate from decode (ADR-0012). Withdrawal-only UPDATEs
  (zero attributes) pass decode fine and skip validation.

### §9.1 — Adj-RIB-In

- Per-peer `AdjRibIn` stores routes keyed by `Ipv4Prefix`.
- Insert replaces existing route for the same prefix.
- Withdraw removes by prefix, returns whether the route existed.
- PeerDown clears all routes for that peer.
- Single `RibManager` tokio task owns all Adj-RIB-In state (ADR-0013).

---

## Interpretation Decisions

### Attribute Ordering

RFC 4271 §4.3 states well-known attributes should appear before optional
attributes. rustbgpd accepts out-of-order attributes but emits a
structured warning event. A future `strict_attribute_order` config option
may reject them, but this is not v1 scope.
