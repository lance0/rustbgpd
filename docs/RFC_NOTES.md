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

---

## RFC 4760 — Multiprotocol Extensions for BGP-4

### §3 — MP_REACH_NLRI (Type 14)

Wire layout:

```
AFI (2 bytes) | SAFI (1) | NH-Len (1) | Next Hop (variable) | Reserved (1) | NLRI (variable)
```

- Flags: Optional + Transitive (0xC0).
- AFI 2 (IPv6), SAFI 1 (Unicast) is the only supported combination beyond
  IPv4 unicast.
- Next-hop length: 16 bytes (global IPv6 address) or 32 bytes (global +
  link-local). When 32 bytes, rustbgpd takes the first 16 (global address)
  and discards the link-local.
- NLRI: same prefix-length encoding as IPv4, but up to 128 bits (16 bytes
  of address data).
- When `MP_REACH_NLRI` is present in an UPDATE, the body NEXT_HOP attribute
  (type 3) is not required — the next-hop is carried inside the MP attribute.
  `validate_update_attributes()` relaxes the NEXT_HOP mandatory check when
  `has_mp_nlri` is true.

### §3 — MP_UNREACH_NLRI (Type 15)

Wire layout:

```
AFI (2 bytes) | SAFI (1) | Withdrawn Routes (variable)
```

- Flags: Optional + Non-Transitive (0x80).
- Withdrawn routes use the same prefix-length encoding as announced NLRI.

### AFI/SAFI Negotiation

- MP-BGP capabilities are advertised in OPEN via `Capability::MultiProtocol`.
- `intersect_families()` computes the intersection of locally configured
  families (from `PeerConfig.families`) and the peer's advertised
  `MultiProtocol` capabilities. Only negotiated families are processed.
- Result stored in `NegotiatedSession.negotiated_families`.
- If neither side advertises IPv4 unicast MP-BGP capability, IPv4 unicast
  is still implicitly supported (RFC 4760 §8 backward compat: body NLRI
  is always IPv4).

### IPv6 NLRI Encoding

- Same wire format as IPv4: 1 byte prefix length + ceil(len/8) bytes of
  address. Maximum prefix length is 128 (vs 32 for IPv4).
- Host bits are masked off on decode (same as `Ipv4Prefix::new()`).
- `Ipv6Prefix` type mirrors `Ipv4Prefix`: public fields `addr: Ipv6Addr`
  and `len: u8`.

### Outbound UPDATE Splitting

- IPv4 routes use body NLRI (WITHDRAWN + NLRI fields in the UPDATE body).
- IPv6 routes use `MP_REACH_NLRI` / `MP_UNREACH_NLRI` in the path
  attributes with empty body NLRI.
- A single UPDATE carries only one address family.
- `MpReachNlri` and `MpUnreachNlri` are not stored on `Route.attributes` —
  they are per-UPDATE framing, rebuilt on each outbound send.

### eBGP NEXT_HOP for IPv6

- eBGP next-hop rewrite: `MpReachNlri.next_hop` is set to the local socket's
  IPv6 address (same pattern as IPv4 eBGP next-hop rewrite).
- iBGP: next-hop passed through unchanged.

---

## Interpretation Decisions

### Attribute Ordering

RFC 4271 §4.3 states well-known attributes should appear before optional
attributes. rustbgpd accepts out-of-order attributes but emits a
structured warning event. A future `strict_attribute_order` config option
may reject them, but this is not v1 scope.

---

## RFC 4724 — Graceful Restart Mechanism for BGP

rustbgpd implements the **receiving speaker** role only. When a peer that
previously advertised the Graceful Restart capability goes down, rustbgpd
preserves that peer's routes as stale rather than immediately withdrawing
them.

### §3 — Graceful Restart Capability

- Capability code 64. Wire format: 2-byte flags/time + N × 4-byte
  per-family entries.
- `restart_state` (R-bit): indicates the sender has restarted and may
  have preserved forwarding state. 12-bit `restart_time` field.
- Per-family: AFI (2) + SAFI (1) + flags (1). Bit 0x80 =
  `forwarding_preserved`.
- Receiving speaker advertises `restart_state: false` and
  `forwarding_preserved: false` for all configured families.
- If a peer sends multiple GR capabilities (malformed OPEN), only the
  first is used. A warning is logged.
- Capability decode is bounded to the enclosing optional-parameter slice
  — a malformed capability length cannot consume beyond the parameter.

### §4.1 — Procedures for the Restarting Speaker

Not implemented. rustbgpd does not advertise R=1 or preserve its own
forwarding state on restart. This requires FIB integration and is deferred.

### §4.2 — Procedures for the Receiving Speaker

**GR trigger:** On `SessionDown`, GR is entered when the peer previously
advertised GR capability (`peer_gr_capable`) AND local config has
`graceful_restart = true`. The R-bit is NOT checked — it indicates
restart state in the NEW OPEN after reconnection, not in the dying session.

**Family handling:** ALL families from the peer's GR capability are retained
as stale (not just those with `forwarding_preserved=true`). The
`forwarding_preserved` flag affects forwarding decisions, not route
retention. Routes for negotiated families NOT in the peer's GR capability
are withdrawn immediately.

**Stale route demotion:** `Route.is_stale` flag. Best-path step 0 (before
LOCAL_PREF) prefers non-stale over stale. This is more aggressive than the
RFC suggestion (step 7 or later) but matches GoBGP and FRR behavior.

**Two-phase timer:**
1. Initial timer = `restart_time` (peer's advertised value). This is the
   window for the peer to re-establish the TCP session.
2. On `PeerUp` during GR, timer resets to `stale_routes_time` (local
   config, default 360s). This is the window for the peer to send
   End-of-RIB markers.

**PeerUp during GR:** Routes are NOT cleared of stale flags. The timer is
reset. Outbound state is re-registered. Stale flags are cleared only by
per-family End-of-RIB, not by session re-establishment.

**End-of-RIB:** Clears stale flag for the indicated address family.
Recomputes best paths (previously-demoted routes may now win). If all
families have received EoR, GR completes and state is cleaned up.

**Timer expiry:** Remaining stale routes are swept as withdrawals. GR
state is cleaned up. `bgp_gr_timer_expired_total` metric incremented.

### End-of-RIB Detection

- IPv4: empty UPDATE (no NLRI, no withdrawn, no attributes)
- IPv6: UPDATE with only empty `MP_UNREACH_NLRI`

### End-of-RIB Sending

After sending the initial table to a new peer, EoR markers are sent for
each negotiated family via `OutboundRouteUpdate.end_of_rib`.

### Metrics

- `bgp_gr_active_peers` — gauge, set on GR entry, cleared on completion
  or timer expiry
- `bgp_gr_stale_routes` — gauge per peer, updated on GR entry, per-family
  EoR, and completion/expiry
- `bgp_gr_timer_expired_total` — counter, incremented on timer expiry

---

## Interpretation Decisions (RFC 4724)

### Stale Demotion Placement

RFC 4724 suggests demotion "in its decision process" without specifying
where. rustbgpd places it at step 0 (before LOCAL_PREF), meaning a stale
route always loses to any non-stale alternative regardless of other
attributes. This matches GoBGP and FRR and is the safest behavior for a
receiving speaker.

### All GR Families Retained

RFC 4724 §4.2: "the receiving speaker MUST retain the routes received from
the restarting speaker for all the address families that were previously
received in the Graceful Restart Capability." The `forwarding_preserved`
flag does NOT gate route retention — it indicates whether the data plane
was preserved for forwarding decisions.

### gr_stale_routes_time Cap

`gr_stale_routes_time` is capped at 3600 seconds (1 hour). This is an
implementation safety limit, not an RFC constraint. A misconfigured value
should not keep stale routes for days.

### Receiving Speaker Only

Restarting speaker mode (advertising R=1, preserving forwarding state)
requires FIB integration that does not exist. Deferred per ADR-0024.
