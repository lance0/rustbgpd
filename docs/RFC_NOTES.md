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
route limit exceeded), rustbgpd sends NOTIFICATION Cease with subcode 8
(Out of Resources) per RFC 4486 §3.

**Fallback:** If interop testing reveals a peer that rejects unknown
Cease subcodes, the fallback is generic Cease (code 6, subcode 0).
Documented per-peer in INTEROP.md.

### Message Size Limits (RFC 4271 + RFC 8654)

RFC 4271 §4.1 defines a 4096-byte maximum unless Extended Messages
(RFC 8654) are negotiated. rustbgpd enforces negotiated limits:

- **Inbound:** Message length > negotiated max is rejected with
  NOTIFICATION (1, 2) — Bad Message Length. The raw length value is
  included in the NOTIFICATION data field.
- **Outbound:** Encode attempts beyond the negotiated max return an
  internal encode error and the message is not sent.
- **Negotiation behavior:** Sessions start at 4096-byte framing. If both
  peers advertise capability code 6, max message length is raised to
  65535 for that session; on session-down it resets to 4096.

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
- Optional non-transitive. Used in best-path step 4 (deterministic
  always-compare mode).

### §5.1.5 — LOCAL_PREF Attribute

- 4 bytes decoded as u32.
- Well-known mandatory (iBGP scope). Used in best-path step 1 (highest
  wins, default 100).

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

- Per-peer `AdjRibIn` stores routes keyed by `(Prefix, u32)` (prefix + path_id for Add-Path support).
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

Minimal restarting-speaker mode implemented (ADR-0040). After a coordinated
shutdown, a marker file is written to `runtime_state_dir`. On startup, if the
marker is present and not expired, static peers from config are offered R=1 in
OPEN. `forwarding_preserved` remains false because rustbgpd does not own or
verify the FIB. Dynamic gRPC-added peers always get R=0.

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

Full restarting speaker mode with forwarding-state preservation requires
FIB integration. Minimal honest mode (R=1 without forwarding claims) is
implemented per ADR-0040.

---

## RFC 2918 — Route Refresh Capability

- Capability code 2, unconditionally advertised.
- Inbound: on receiving ROUTE-REFRESH, re-advertise the requested family
  from Adj-RIB-Out.
- Outbound: `SoftResetIn` gRPC RPC sends ROUTE-REFRESH to the peer.
- See ADR-0027.

---

## RFC 7313 — Enhanced Route Refresh

- Capability code 70, unconditionally advertised.
- BoRR/EoRR markers demarcate the refresh window.
- Inbound BoRR marks existing routes as refresh-stale; EoRR sweeps
  unreplaced routes. 5-minute timeout on the refresh window.
- Outbound: Enhanced peers get BoRR → routes → EoRR; legacy peers get
  routes → EoR.
- See ADR-0038.

---

## RFC 4360 — Extended Communities

- Type code 16. Two-octet AS (subtypes 0x02 RT, 0x03 RO) and four-octet
  AS (subtypes 0x02 RT, 0x03 RO) encodings.
- Policy matching uses logical RT/RO equivalence across encodings.
- See ADR-0025, ADR-0026.

---

## RFC 8092 — Large Communities

- Type code 32. 12 bytes: Global Administrator (4) + Local Data Part 1 (4) +
  Local Data Part 2 (4).
- Zero-length Large Communities attribute rejected at wire decode.
- Policy: `LC:G:L1:L2` format in `match_community`, `set_community_add`,
  `set_community_remove`.
- See ADR-0031.

---

## RFC 8654 — Extended Message Support

- Capability code 6, unconditionally advertised.
- When both peers advertise, max message length is raised from 4096 to
  65535 bytes for that session. Resets to 4096 on session-down.
- `ReadBuffer.set_max_message_len()` dynamically resizes on negotiation.
- See ADR-0032.

---

## RFC 7911 — Add-Path

- Capability code 69. Per-family Send/Receive/Both modes.
- Adj-RIB-In/Out keyed by `(Prefix, u32)` for multi-path storage.
- Multi-path send: rank-based path IDs (best=1, second=2, ...).
- `send_max` caps paths per prefix per peer.
- Both IPv4 body NLRI and IPv6 MP_REACH/MP_UNREACH supported.
- See ADR-0033.

---

## RFC 8950 — Extended Next Hop

- Capability code 5. Advertised automatically when both `ipv4_unicast` and
  `ipv6_unicast` are configured.
- Negotiation: exact 6-byte tuple matching (NLRI AFI, NLRI SAFI, NH AFI).
- When negotiated, IPv4 unicast uses `MP_REACH_NLRI` / `MP_UNREACH_NLRI`
  with IPv6 next hop instead of body NLRI.
- See ADR-0037.

---

## RFC 6811 — RPKI Origin Validation + RFC 8210 — RTR

- VRP table with sorted-Vec binary search for prefix containment.
- `Arc<VrpTable>` snapshot pattern for lock-free reads.
- RTR codec: RFC 8210 v1 only. Serial/Reset queries, Serial Notify,
  expire enforcement.
- Best-path step 0.5: Valid > NotFound > Invalid (between stale demotion
  and LOCAL_PREF).
- `match_rpki_validation` in policy.
- See ADR-0034.

---

## RFC 8955/8956 — FlowSpec

- SAFI 133. IPv4 and IPv6 unicast FlowSpec.
- 13 match component types (destination/source prefix, protocol, ports,
  ICMP, TCP flags, packet length, DSCP, fragment, flow label).
- Actions via extended communities: traffic-rate, traffic-action,
  traffic-marking, redirect.
- NH length = 0 in MP_REACH_NLRI for FlowSpec.
- See ADR-0035.

---

## RFC 7854 — BMP

- BMP exporter (router-initiated). All 6 message types encoded.
- Per-collector TCP client with reconnect/backoff.
- Peer Up replay on collector reconnect.
- Periodic Stats Report (type 7: Adj-RIB-In route count, 60s interval).
- Coordinated Termination on daemon shutdown.
- Raw UPDATE PDU capture via `Bytes` refcount clone (zero overhead when
  unconfigured).
- See ADR-0041.

---

## RFC 8203 — Admin Shutdown Communication

- Cease NOTIFICATION subcode 2 (Administrative Shutdown) carries a
  UTF-8 reason string.
- Reason threaded from gRPC `DisableNeighbor` through transport to the
  NOTIFICATION data field.

---

## RFC 7432 — EVPN (Phase 1: Route Reflector + Phase 2: Bidirectional VTEP)

- AFI 25 (L2VPN) / SAFI 70 (EVPN). Enum variants added to `Afi` and
  `Safi`; capability negotiation works automatically.
- Wire codec for all 5 RFC 7432 route types:
  - **Type 1 EAD** (per-ES when `ethernet_tag == MAX_ET (0xFFFFFFFF)`,
    per-EVI otherwise). Distinct `EvpnRouteKey` variants prevent
    semantic collapse.
  - **Type 2 MAC/IP Advertisement.** IP Addr Length is in **bits**
    (0 / 32 / 128). Label2 is optional — either 0 or 3 trailing bytes
    after the primary label.
  - **Type 3 IMET.** IP length is in bits (32 / 128).
  - **Type 4 ES.** IP length in bits.
  - **Type 5 IP Prefix (RFC 9136).** Fixed total length disambiguates
    IPv4 (34 bytes) from IPv6 (58 bytes) — prefix-length byte alone
    cannot distinguish since 32 is valid for both.
- Route Distinguisher (RFC 4364) displays as `<asn16>:<u32>` (Type 0),
  `<ipv4>:<u16>` (Type 1), `<asn32>:<u16>` (Type 2). Unknown RD types
  fall back to hex.
- `EvpnRoute` carries full wire payload (for reflection); `EvpnRouteKey`
  is the hashable identity used as RIB key.
- **Best-path §15.1:** Type 2 routes run a MAC Mobility head (sticky
  preserved against displacement by non-sticky; higher sequence wins)
  before the standard BGP preference chain. Absence of the MAC Mobility
  community → `(sticky=false, seq=0)` per §7.7.
- **Route reflection:** RFC 4456 rules (`ORIGINATOR_ID`, `CLUSTER_LIST`,
  split-horizon) reuse the existing unicast `should_suppress_ibgp_inner`
  via a synthetic `Route` probe — no EVPN-specific reflection logic.
  Split horizon is keyed on the **source peer**, not the route's
  next-hop, so a reflector with one client behind a NAT or a different
  loopback still suppresses correctly. AS_PATH and RR cluster-loop
  branches emit a proper EVPN withdrawal toward the looping peer
  (rather than silently dropping the route in the Adj-RIB-Out), so a
  client that previously received the route observes a clean retract.
- **Best-path tie-break:** the EVPN best-path chain runs the full
  RFC 4456 ordering after the BGP body — stale flag → ORIGIN →
  shortest CLUSTER_LIST → lowest ORIGINATOR_ID — matching the unicast
  decision process so a reflector with multiple equal-AS paths
  converges deterministically.
- **Initial dump on session up:** when an iBGP EVPN session reaches
  Established, the existing Adj-RIB-In is replayed to the new peer
  through the same Adj-RIB-Out path that handles steady-state
  reflection — no separate "fast-path" code that could skip RFC 4456
  attribute attachment. EoR is emitted per family after the dump.
- **Enhanced Route Refresh tracking** (RFC 7313): `refresh_stale_evpn`
  records EVPN keys present in Adj-RIB-In at BoRR time; any key not
  re-advertised before EoRR is withdrawn at sweep, mirroring the
  unicast `refresh_stale` path.
- **Max-prefix accounting** counts EVPN keys alongside unicast
  prefixes in the per-peer prefix counter, so `max_prefixes` triggers
  Cease/1 (Maximum Number of Prefixes Reached) when a misbehaving
  VTEP floods Type 2 routes.
- **Policy context:** EVPN routes pass through the policy engine with
  attribute / community / RT visibility (placeholder `0.0.0.0/0`
  prefix matches FlowSpec's pattern); Type 5 IP-Prefix routes
  additionally surface their actual prefix in `RouteContext`, so a
  prefix-based clause filters Type 5 routes by the IP prefix carried
  in the NLRI.
- **GR / LLGR stale handling** (RFC 4724 + RFC 9494, Gate 2): EVPN
  routes participate in the stale-route pipeline alongside unicast
  and FlowSpec. On `PeerGracefulRestart`, `mark_stale_evpn((L2Vpn,
  Evpn))` flags routes; on GR timer expiry with LLGR-negotiated,
  `promote_to_llgr_stale_evpn` injects `COMMUNITY_LLGR_STALE` via
  `Arc::make_mut` and records the route key in
  `evpn_llgr_stale_local_tags` so `clear_stale_evpn` /
  `clear_llgr_stale_evpn` on EoR later strip only the
  locally-injected communities (peer-originated ones are preserved).
  Routes carrying `COMMUNITY_NO_LLGR` are dropped on GR expiry rather
  than promoted, per RFC 9494 §4.7. Enhanced Route Refresh (RFC 7313)
  tracks unreplaced EVPN keys in `refresh_stale_evpn` and withdraws
  them on BoRR/EoRR completion.
- **Type 2 MAC/IP Advertisement interop**: validated end-to-end
  against FRR 10.3.1 via the M30 containerlab suite
  (`tests/interop/m30-evpn-type2-frr.clab.yml`). Real kernel VXLAN +
  bridge per VTEP; MAC injection on one VTEP via `bridge fdb add`
  propagates through the rustbgpd RR to the second VTEP and appears
  in its EVPN MAC table. Assertions cover RFC 4456 `ORIGINATOR_ID`
  + `CLUSTER_LIST`, next-hop preservation (VTEP loopback, not RR),
  VXLAN encap community surfaced through gRPC, and withdrawal
  propagation on FDB delete.
- **MAC Mobility + sticky-MAC preservation interop** (RFC 7432 §15.1,
  §7.7): validated via the M31 4-node harness
  (`tests/interop/m31-evpn-mac-mobility-frr.clab.yml`). MAC moved
  between two originating VTEPs through the RR increments the
  Mobility sequence on the reflected Type 2 and flips the observing
  VTEP's best path. Sticky MAC on the first VTEP is not displaced by
  a non-sticky advertisement from the second VTEP.
- **Scale validation** (Gate 5, M33, 2026-04-24): the RR sustains
  50,000 Type 2 MAC/IP routes reflected from two originating peers
  to a third observer, followed by 60 s of 1,000 rps withdraw +
  re-advertise churn, with no route loss and no session flap. The
  load generator is the in-tree `bench/evpn-load` crate, built
  directly on `rustbgpd-wire` — no third-party daemon sits in the
  measurement path. See `tests/interop/m33-evpn-scale.clab.yml`
  and `docs/BENCHMARKS.md` § "EVPN RR Scale (M33)".
- **Controller-driven injection** (Gate 6, 2026-04-24): Type 2
  MAC/IP and Type 3 IMET routes can be injected via gRPC
  (`InjectionService::AddEvpnRoute`) and withdrawn via
  `DeleteEvpnRoute`. The service accepts display-form RDs
  (`65000:100`, `10.0.0.1:100`, `4200000000:100`), parses MAC
  addresses and host IPs, and assembles an `EvpnRibRoute` with
  `RouteOrigin::Local` that flows through the same reflection
  pipeline as iBGP-learned routes. `rustbgpctl evpn add-mac-ip /
  add-imet / delete-mac-ip / delete-imet` CLI subcommands cover
  the operator-facing surface. Type 5 IP-Prefix and Type 1/4
  multi-homing origination are deferred pending use-case signal.
- **Multi-homing Type 1 EAD + Type 4 ES reflection interop** (RFC 7432 §8):
  validated via the M32 4-node harness
  (`tests/interop/m32-evpn-multihome-frr.clab.yml`). Two FRR VTEPs
  share an Ethernet Segment on a bond ES interface (same `es-id` +
  `es-sys-mac` → identical 10-byte ESI); both originate Type 4 ES
  + Type 1 EAD-per-EVI routes that the rustbgpd RR reflects to a
  third observing VTEP. Gated assertions cover that both ESI-sharing
  peers' Type 1 EAD + Type 4 ES routes reach the observer with
  correct `ORIGINATOR_ID` + `CLUSTER_LIST` and that gRPC
  `ListEvpnRoutes` surfaces both Route Type 1 and Route Type 4
  entries. DF election itself runs on the VTEPs; the RR is
  path-transparent.
- See ADR-0050.

### Phase 2: Bidirectional VTEP (Gates 7a, 7b, 7b+1)

- **Gate 7a (v0.13.0, ADR-0052):** declarative local-VTEP domain in
  `crates/evpn` — `EvpnInstanceTable` + `[[evpn_instances]]` TOML
  schema + read-only `EvpnService.ListEvpnInstances`. Empty by
  default; RR-only deployments unchanged.
- **Gate 7b (v0.14.0, ADR-0054):** Linux kernel reconciliation in
  the new `crates/evpn-linux` crate. The `ReconcileActor<D: Dataplane>`
  consumes a `tokio::sync::watch<Arc<DataplaneIntent>>` from a
  daemon-side projection of the RIB's best-path Type 2 routes, and
  programs/withdraws remote-MAC FDB entries via rtnetlink (single
  combined-flag `RTM_NEWNEIGH` with `NTF_SELF | NTF_MASTER |
  NTF_EXT_LEARNED` and `NUD_NOARP | NUD_PERMANENT`). Foreign-entry
  preservation is structural — the delete pass iterates `OwnedSet`
  (rustbgpd-programmed keys), never the kernel snapshot, so
  kernel-learned local MACs and operator-static FDB entries cannot
  be deleted by the algorithm.
- **Gate 7b+1 (v0.15.0, ADR-0055):** local-MAC origination
  closes the upward flow. New `crates/evpn/src/origination.rs` ships
  the pure deterministic `LocalMacOriginator` state machine encoding
  RFC 7432 §15.1 sequence rules: first-Learned-no-contender ⇒ seq=0
  with no extcomm; first-Learned-vs-contender at R ⇒ R+1 with
  extcomm; remote announces M ≥ N ⇒ bump to `max(M, N) + 1`;
  aged-then-relearn preserves the seq ratchet so a stale peer never
  wins contention. Local-port move on a previously-advertised MAC
  bumps the seq AND wakes up the extcomm even without a contender,
  so peers see the bumped seq on the wire (otherwise a later stale
  remote at seq=0 would tie our hidden seq=1). The
  `crates/evpn-linux/src/linux/notify.rs` classifier subscribes to
  `RTNLGRP_NEIGH` (enum group id `3`, **not** the legacy bitmask
  `RTMGRP_NEIGH = 4` — `Socket::add_membership` takes the enum
  value), drops `NTF_EXT_LEARNED` echoes (we programmed those) and
  VXLAN-port ifindexes (those are remote-MAC echoes), and resolves
  bridge-port → VNI via a new `LinkCache::bridge_port_to_vni` map.
  The daemon-side `src/evpn_originator.rs` actor mirrors the
  dataplane supervisor on the upward flow and emits
  `RibUpdate::InjectEvpn` / `WithdrawEvpn`. Self-NH routes are
  filtered before reaching the state machine via the existing
  `project_evpn_routes`, so the originator never sees its own
  re-Inject as a contender.
- **Type 3 IMET origination per L2VNI (Gate 7b+1):** `src/evpn_imet.rs`
  emits one Type 3 per `EvpnInstance` at startup, withdrawn at
  coordinated-shutdown. Lifecycle is decoupled from kernel
  Ready/NotReady — IMET expresses BGP-level VNI membership, not
  data-plane programmability. Carries the **PMSI Tunnel attribute**
  (RFC 6514 §5, path attribute type 22) for ingress replication.
- **PMSI Tunnel codec (RFC 6514 §5):** new `crates/wire/src/pmsi.rs`
  defines `PathAttribute::PmsiTunnel(PmsiTunnel)` with typed
  `PmsiTunnelType` (preserves unknown values for forward-compat per
  RFC 7385) and `PmsiTunnelIdentifier` (Empty / Ipv4 / Ipv6 / Raw).
  Wire layout: flags(1) | type(1) | label(3) | tunnel id(variable).
  The `for_evpn_ingress_replication(vni, ip)` constructor encodes
  the label field as the **raw 24-bit VNI per RFC 8365 §5.1.3** —
  RFC 8365 redefines the field semantics for EVPN-VXLAN so the full
  24 bits are the VNI, **not** the MPLS-style high-20-bits shift.
  Matches FRR/Cumulus on the wire and stays consistent with
  `EvpnMacIp.label1`. Tunnel identifier carries the originator IP.
- **Coordinated shutdown ordering (Gate 7b+1):** the daemon drains
  the EVPN originator (emits Type 2 Withdraws) and withdraws the
  IMET keys **before** sending `PeerManagerCommand::Shutdown` so
  Type 2 / Type 3 Withdraws ride still-open BGP sessions. The
  dataplane reconciler drains afterward (FDB teardown doesn't need
  active BGP).
- **Bidirectional VTEP interop (M37):** validated end-to-end against
  Linux 6.17 + FRR 10.3.1 via
  `tests/interop/m37-evpn-local-origination.clab.yml`. rustbgpd as
  VTEP originator, FRR as consumer. 4/4 PASS: Type 3 IMET originated
  at startup, Type 2 originated within ~3 s of `bridge fdb add`,
  Type 2 withdrawn within ~3 s of `bridge fdb del`, Type 3 IMET
  drained on shutdown. Local-only / privileged smoke (not in
  PR-CI); the Gate 7b downward path retains its M36 coverage.
- **Closed in `[Unreleased]` post-v0.16.0:** `advertise_svi_mac`
  consumption (origination of the bridge's own MAC on
  instance-Ready via `InstanceDataplaneStatus.bridge_mac`),
  `sticky_macs` config schema (ADR-0056 — listed MACs originated
  with the RFC 7432 §15.4 sticky bit), and sub-second mobility
  convergence (Gate 7c — EVPN-keyed `EvpnRouteEvent` broadcast in
  `crates/rib`; the 5 s poll stays as `Lagged` / cold-start
  backstop).
- **Deferred (tracked in ADR-0055 §7 / §9 + `docs/evpn-alpha-soak.md`):**
  MAC-with-IP origination via ARP/ND suppression (Gate 7b+2) and
  RFC 7432 §15.1 duplicate-MAC quarantine action (M=180 s/N=5;
  detection counters shipped — the operator-facing escalation
  channel is the deferred half).

---

## RFC 9012 / RFC 8365 — BGP Encapsulation Ext Community + VXLAN-EVPN

- The BGP Encapsulation extended community (Type 0x03, Subtype 0x0C)
  uses the widely-deployed **RFC 5512 layout** (4 bytes reserved +
  2-byte Tunnel Type). RFC 9012 §4.1 specifies a different layout
  (1-byte Tunnel Type + 5-byte Flags) but FRR, BIRD, Juniper, and
  Cisco all emit the RFC 5512 form, so interop compatibility wins.
- Tunnel Type values: 7 = NVGRE, 8 = VXLAN, 11 = MPLS-over-GRE.
  `as_bgp_encapsulation()` returns the u16 tunnel type.
- rustbgpd does not yet **negotiate** a preferred encap. VXLAN is
  assumed; non-VXLAN values are passed through untouched.

---

## RFC 9135 — Symmetric IRB (wire support, semantics deferred)

- Type 2 MAC/IP routes with a second MPLS label (Label2) and the
  Router MAC ext community (Type 0x06, Subtype 0x03) are decoded and
  reflected unchanged. rustbgpd does not yet interpret IRB pairings.
- The Router MAC ext community accessor returns the 6-byte MAC.

---

## EVPN Extended Communities — typed accessors (RFC 7432 §7.5-§7.8)

Subtypes with typed accessors on `ExtendedCommunity` (others pass
through as opaque u64):

| Type/Subtype | Name | Payload |
|---|---|---|
| 0x03 / 0x0C | BGP Encapsulation | u16 tunnel type |
| 0x03 / 0x0D | Default Gateway | flag-only (value = 0) |
| 0x06 / 0x00 | MAC Mobility | (sticky: bool, sequence: u32) |
| 0x06 / 0x01 | ESI Label | (single_active: bool, label: u32) |
| 0x06 / 0x02 | ES-Import RT | 6-byte MAC target |
| 0x06 / 0x03 | Router MAC | 6-byte MAC |

- RFC 8214 Layer 2 Attributes (Type 0x06 / Subtype 0x04) deferred —
  encoding is complex and not needed for Phase 1 RR flow.
