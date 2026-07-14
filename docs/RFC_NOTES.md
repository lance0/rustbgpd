# RFC Implementation Notes

Notes keyed to RFC sections. Documents interpretations, deviations, and
implementation choices made during development.

---

## Supported standards at a glance

Consolidated map of the RFCs, SAFIs, and features rustbgpd implements. The
per-RFC sections below carry the conformance detail, interpretations, and
deviations; [docs/INTEROP.md](INTEROP.md) has the interop matrix,
[docs/RECEIPTS.md](RECEIPTS.md) the receipts index, and
[docs/LIMITATIONS.md](LIMITATIONS.md) the boundaries and non-goals.

| Area | Standards | Scope |
|------|-----------|-------|
| Core BGP | RFC 4271, RFC 6793 (4-byte ASN) | FSM + UPDATE validation, dual-stack IPv4/IPv6 unicast (SAFI 1) |
| MP-BGP + extensions | RFC 4760, RFC 7911 (Add-Path), RFC 8654 (Extended Messages), RFC 8950 (Extended Next Hop) | Multiprotocol negotiation and modern capability set |
| Route refresh / filtering | RFC 2918, RFC 7313 (Enhanced RR), RFC 5291/5292 (ORF) | Receive-side Address-Prefix ORF |
| Communities | RFC 4360 (Extended), RFC 8092 (Large) | Match plus policy set/remove |
| Route reflection | RFC 4456, RFC 9107 (ORR, ADR-0095) | Per-client best paths via BGP-LS-sourced SPF |
| Graceful restart | RFC 4724 (GR helper), RFC 9494 (LLGR) | Stale retention across all RR families; no forwarding-state preservation |
| VPN / MPLS families (RR / controller-feed only, ADR-0077) | RFC 4364/4659 VPNv4/v6 (SAFI 128), RFC 4684 RT-Constrain (SAFI 132), RFC 8277 labeled-unicast (SAFI 4), RFC 9552 BGP-LS (SAFI 71/72) | RD/label/next-hop/RT preserved verbatim; no VRF import, no MPLS FIB, no local BGP-LS production |
| EVPN (Linux/VXLAN alpha) | RFC 7432, RFC 9135/9136 (symmetric IRB), RFC 9012/8365 (VXLAN encap) | Route types 1-5; RR + VTEP + multi-homing building blocks |
| Origin / path security | RFC 6811 + RFC 8210 (RPKI/RTR), ASPA, RFC 9234 (Roles + OTC, ADR-0071) | Origin validation, AS-path verification, leak prevention |
| Transport security | RFC 5925 (TCP-AO), TCP MD5, RFC 5082 (GTSM) | TCP-AO: static-neighbor and direct dynamic-prefix keyrings on Linux; add-only successor installation on SIGHUP |
| FlowSpec / blackhole | RFC 8955/8956 (FlowSpec, SAFI 133), RFC 7999 (BLACKHOLE) | Receiver scoping + opt-in Linux FIB discard |
| Liveness | RFC 5880/5881/5882 (BFD), RFC 9687 (Send Hold Timer) | Single-hop async BFD for static neighbors |
| Maintenance | RFC 8326 (Graceful Shutdown), RFC 8203 (Admin Shutdown Communication) | Receiver gating + initiator toggle |
| Monitoring | RFC 7854/8671/9069 (BMP trio), RFC 6396 (MRT TABLE_DUMP_V2), RFC 7951 (gNMI/OpenConfig JSON) | Pre-policy / post-policy / Loc-RIB BMP views |

---

## RFC 9552 and RFC 9107 — ORR topology scope

- ORR builds only the default BGP-LS topology. Link and Prefix NLRIs use a
  single descriptor MT-ID; Node membership comes only from Multi-Topology TLV
  263 inside BGP-LS Attribute 29. IS-IS interprets the lower 12 bits, while
  OSPF requires the reserved high bits clear and a value in `0..=127`.
- Absent MT-ID is default. A Node list containing zero is default even when it
  also advertises non-zero memberships. Valid non-zero-only objects are
  excluded; duplicate, wrongly placed, structurally invalid, or
  protocol-uninterpretable topology data is excluded fail-closed before graph
  insertion.
- Flex-Algorithm definition/prefix inputs and Flex Prefix-SID/SR-Algorithm
  values do not select another SPF. They are reported as ignored aggregate
  input while the valid base default object and classic IGP/Prefix Metric stay
  active.

---

## RFC 9234 — Roles and Only-to-Customer

- The configured local Role is session-stamped into the RIB before `PeerUp`,
  so the first Adj-RIB-Out build and every subsequent export use the same
  RFC 9234 relationship semantics. Update-group identity includes that role;
  peers with different OTC egress behavior cannot share advertised state.
- E2 suppression for IPv4/IPv6 unicast happens after export-policy
  modifications but before grouped or private Adj-RIB-Out commit. This covers
  single-best, ORR, Add-Path, and per-client-best selection. A route that was
  previously advertised and becomes OTC-blocked is withdrawn and removed from
  logical advertised state; a newly blocked route is never committed.
- Transport retains the E2 check as a defense-in-depth encoder guard and owns
  the established `bgp_otc_routes_blocked_total` / `OTC_ROUTE_BLOCKED`
  diagnostic publication. The RIB passes rejected route context explicitly,
  so metrics/events and export-explain reflect the same pre-commit decision.
  Backpressured grouped peers retain at most one pending diagnostic per route;
  resync rebuilds that residue from current denials so withdrawn sources do
  not leak stale events into an unrelated later update.
- RFC 9234 section 5 applies only to IPv4/IPv6 unicast SAFI 1 here. FlowSpec,
  EVPN, VPN, labeled-unicast, RTC, and BGP-LS are not subject to the OTC gate.

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
- Outbound IPv4/IPv6 unicast and IPv4/IPv6 FlowSpec announcements and
  withdrawals are chunked by the peer's negotiated 4096/65535-byte message
  limit. MP chunking starts with at most 1,024 entries, grows through exactly
  built and size-checked candidates up to a 4,096-entry probe ceiling, and
  retains successful/failed bounds; it does not promise to fill every Extended
  Message. Structured FlowSpec construction is fallible; an individually
  unencodable NLRI fails the session rather than partially committing a batch.
- EVPN MP_REACH/MP_UNREACH is likewise chunked to the negotiated ceiling. A
  single announcement or withdrawal that still cannot fit invokes the
  Cease/8 outbound-saturation teardown, preventing a live session from
  retaining logical Adj-RIB-Out state that never reached the wire.
- Before any announcement enters Adj-RIB-Out, the RIB probes its exact
  one-route wire form through an immutable snapshot of that session's live
  encoder and negotiated 4096/65535-byte ceiling. This post-policy check covers
  unicast, FlowSpec, EVPN, BGP-LS, VPN, labeled-unicast, and RT-Constrain. A
  failure is rejected before commit; if the identity was previously
  advertised, the same transition emits its withdrawal. Grouped peers keep a
  sparse per-member rejection overlay, so peers with different negotiated
  ceilings retain exact individual advertised views while sharing the staged
  group table. Recompute/resync retries rejected routes, and a source
  withdrawal retires the rejection without a redundant wire withdrawal.
  Transport's Cease/8 path remains the final defense if a route-bearing
  envelope lacks the matching snapshot or a live encoder still finds an
  impossible single-route UPDATE.
- FlowSpec identity is `(AFI, rule)` throughout Adj-RIB-In, Loc-RIB,
  Adj-RIB-Out, recompute, distribution, and withdrawal. AFI is never inferred
  from an optional destination-prefix component: legal destination-less IPv4
  and IPv6 rules remain distinct.

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
  link-local). When 32 bytes, rustbgpd takes the first 16 as the primary
  next-hop and preserves the trailing 16 in `link_local_next_hop`
  (round-tripped through wire / RIB / MRT since v0.11.0); ADR-0069 resolves a
  link-local next-hop as a scoped next-hop for unnumbered IPv4-over-IPv6 and
  Linux FIB `dev`.
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

rustbgpd implements the **receiving speaker** role and a planned-restart
**restarting speaker** role. As a receiver, when a peer that previously
advertised the Graceful Restart capability goes down, rustbgpd preserves that
peer's routes as stale rather than immediately withdrawing them. The bounded
restarting-speaker behavior is described in §4.1 and ADR-0040.

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

Restarting-speaker mode is implemented (ADR-0040). After a coordinated
shutdown, a marker file is written to `runtime_state_dir`. On startup, if the
marker is present and not expired, static peers from config are offered R=1 in
OPEN. `forwarding_preserved` remains false because rustbgpd does not own or
verify the FIB. Dynamic gRPC-added peers always get R=0. Before sessions start,
the RIB freezes the resolved static GR peer/family roster. Per-family Loc-RIB
selection and outbound initial table/EoR are held until current-session EoRs
arrive from every eligible waiter or the marker-bounded selection timer
expires. Peer Restart State and absent GR families exclude that peer/family;
superseded-session EoRs are rejected.

When `warm_cache_checkpoint_on_shutdown = true`, a successful bounded
checkpoint publication binds its generation into the restart marker
(ADR-0104). Linux marker v3 also binds the expiry to a complete boot and time
namespace `CLOCK_BOOTTIME` domain; wall-only v1/v2 remain compatibility
fallbacks when that domain is unavailable. Checkpoint failure retains a
generationless marker. This does not extend RFC 4724 semantics: startup never
restores or advertises cached routes, and `forwarding_preserved` remains false.

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

Full restarting speaker mode with forwarding-state preservation requires a
verified restore/adoption design. Minimal honest mode (R=1 without forwarding
claims) is implemented per ADR-0040; ADR-0104's publication-only checkpoint
does not change that boundary.

---

## RFC 2918 — Route Refresh Capability

- Capability code 2, unconditionally advertised.
- Inbound: on receiving ROUTE-REFRESH, re-advertise the requested family
  from Adj-RIB-Out.
- Outbound: `SoftResetIn` gRPC RPC sends ROUTE-REFRESH to the peer.
- See ADR-0027.

---

## RFC 5291 / RFC 5292 — Outbound Route Filtering, Address-Prefix ORF

- Capability code 3, Address-Prefix ORF-Type 64.
- rustbgpd implements the receive side: per-neighbor / peer-group
  `prefix_orf_receive = true` advertises willingness to receive Address-Prefix
  ORF entries and applies the peer-pushed filter before export policy.
- ORF filters use prefix-list semantics: sequence order, first match wins,
  implicit deny on a non-empty list, permit-all when empty.
- The initial advertisement for an ORF-negotiated family is gated until the
  peer's first ROUTE-REFRESH; `DEFER` installs state and waits for a later
  immediate or plain refresh to sweep advertisements and withdrawals.
- Unknown `When-to-refresh` values are invalid control input: rustbgpd resets
  the negotiated Address-Prefix ORF list for that family/type and forces a safe
  resync instead of treating the value as defer-like state.
- Address-Prefix ORF entries are decoded only for IPv4/IPv6 unicast. L2VPN and
  unknown future SAFIs are preserved as raw ORF groups until their family-specific
  prefix encodings and export semantics are implemented.
- See ADR-0075.

---

## RFC 7313 — Enhanced Route Refresh

- Capability code 70, unconditionally advertised.
- BoRR/EoRR markers demarcate the refresh window.
- Inbound BoRR marks existing routes as refresh-stale; EoRR sweeps
  unreplaced routes. 5-minute timeout on the refresh window.
- Outbound: Enhanced peers get BoRR → routes → EoRR; legacy peers get
  routes → EoR.
- Joint behavior with GR/LLGR retention (LAN-187): routes flagged
  GR-stale or LLGR-stale are NOT snapshotted at BoRR, so EoRR (or the
  window timeout) never purges them. A restarting peer's refresh replay
  is not authoritative while it is still converging — RFC 4724 §4.1
  retains stale paths until End-of-RIB or the restart timer, RFC 9494
  §4.2 until the LLGR timer; those remain the only removal points. A
  re-advertisement inside the window still clears both staleness kinds
  via implicit replace. The reverse ordering (GR entry during an open
  window) is a session-down, which drops all refresh windows for the
  peer. Combination matrix in `handle_begin_route_refresh`.
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

### Experimental Paths-Limit

Capability code 76 implements the tuple format from the expired
`draft-abraitis-idr-addpath-paths-limit-04`. Each AFI/SAFI receiver preference
is applied only to the matching negotiated Add-Path send direction. This is an
experimental interoperability feature, not an adopted IETF standard.
Neighbor output orders rows by numeric AFI/SAFI and carries an optional
normalized limit whose presence distinguishes active unlimited from inactive,
while retaining the legacy raw unlimited sentinel for rolling compatibility.

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
- RTR codec: RFC 8210 v1 plus the 8210bis v2 ASPA PDU. Serial/Reset
  queries, Serial Notify, expire enforcement. Router Key PDUs (BGPsec)
  and RTR transport security (TLS/SSH) are not implemented.
- Cache state is one per-cache epoch `(version, session ID, serial)`,
  advanced only at a validated End of Data. Identity mismatches (session
  ID, RFC 1982 serial regression) force a Reset Query resync — never a
  splice. Validated data is retained through reconnect/Cache Reset until
  replaced or expired. Transactions are bounded by deadline and
  record/byte budgets.
- ASPA over RTR v2 uses 8210bis replacement semantics: announce replaces
  the customer's provider set; withdraw removes the customer ASN.
- Strict acceptance limits (8210bis-26): per-PDU length is capped at
  65,535 octets (§5 — an over-limit length field is corrupt framing,
  Error Report code 0); End of Data timers are bounded to the §6 legal
  ranges (zeros mean "not provided"; above-maximum values clamp down
  with a warning; an expire below the 600 s minimum is honored as-is,
  since expiring early is safe; a refresh/retry not below the expire is
  lowered under it per the §6 relationship rule); ASPA PDUs must be
  well-shaped per §5.12 (announce: at least one provider, strictly
  increasing, no AS 0 among multiple; withdraw: no provider list, PDU
  length exactly 12) — violations get Error Report code 9.
- Deviation: Duplicate Announcement Received (Error Code 7) and
  Withdrawal of Unknown Record (Error Code 6) are not detected. The RTR
  client does not hold the per-cache active record set during a
  transaction — the VRP manager applies updates by normalizing
  announce/withdraw merges — so detecting either would require a
  parallel active-record index in the client. Duplicate announcements
  and withdrawals of unknown records are normalized silently instead of
  failing the session.
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
- Per-collector view selection: `monitor = ["rib_in_pre",
  "rib_out_post", "loc_rib"]` (default `["rib_in_pre"]`). The full
  monitoring trio (7854 + 8671 + 9069) ships on one exporter; M81
  receipt.
- See ADR-0041 and ADR-0097.

---

## RFC 8671 — BMP Adj-RIB-Out Monitoring

- Post-policy Adj-RIB-Out Route Monitoring, tapped at the transport's
  outbound byte funnel (`enqueue_bulk`): the BMP message wraps the exact
  PDU sent on the wire, after transport stamping
  (ORIGINATOR_ID/CLUSTER_LIST, GShut, LLGR §4.6) — byte-exact by
  construction, test-pinned for VPN and EVPN.
- O-flag 0x10 on Route Monitoring; L=post-policy under O=1; peer
  identity stays the remote peer's; PeerUp/Down/Stats remain O=0.
- Stats types 15 and 17 (post-policy Adj-RIB-Out counts) from one
  batched AdjRibOut query per stats tick; unavailable counts are
  omitted, never a false zero.
- Live-only (no rib-out table dump): AdjRibOut stores routes
  pre-transport-stamping, so a synthesized dump would not be
  byte-faithful. Pre-policy rib-out deliberately skipped.
- Saturation semantics: "mirror what was actually sent" is enforced in
  both directions. An UPDATE that fails to enqueue on the saturated
  writer is never mirrored (it never reached the wire; the `Cease/8`
  teardown ends in a reliably delivered, correctly ordered Peer Down and
  the re-established session re-floods the view). Conversely, a mirror
  event dropped on a full BMP channel after the wire send succeeded
  forces a synthetic Peer Down/Peer Up peer-state reset on the stream
  (reason 2, FSM code 0) so the divergence is collector-detectable —
  live-only views can never silently under-report. Per-peer Peer
  Up/Peer Down delivery to the BMP manager is reliable (never
  try_send-dropped).
- See ADR-0097 (Decisions 1, 3 incl. the saturation amendment).

---

## RFC 9069 — BMP Local RIB Monitoring

- Loc-RIB Route Monitoring synthesized at the RIB recompute commit
  seams (`crates/rib/src/bmp_sync.rs`); announcement PDUs rebuild
  MP_REACH the same way the MRT exporter does.
- Emulated instance peer per §5.2.1: peer type 3, peer flags forced to
  zero (its own registry — never V, even for v6), fabricated sent-OPEN
  advertising exactly the streamed capability set, VRF/Table Name
  `"global"`, Peer Down reason 6, stats types 8/10.
- V1 family scope: IPv4/IPv6 unicast + VPNv4/VPNv6; the fabricated OPEN
  only promises families that actually stream.
- Collector-connect table sync: chunked non-blocking dump (256-message
  chunks drained by a per-collector forwarder task with a send
  timeout) → one End-of-RIB per family → live. Dump/live overlap is the
  standard BMP initial-sync race, accepted.
- See ADR-0097 (Decisions 1, 2).

---

## draft-ietf-grow-bmp-tlv-20 — BMPv4 TLV framing (pre-IANA)

- Per-collector `version = 3 | 4`, default 3; v3 output byte-identical
  to prior releases (golden-bytes pinned).
- v4: common-header version 4 on every message; Route Monitoring wraps
  the UPDATE in the mandatory BGP Message TLV (type 7, index 0, §5.2);
  Stats Reports wrap in the Stats TLV (code 1, §5.4); the
  TLV-provisioned message types change only their version byte.
- Indexed-TLV (§4.3: 2-byte index after length, excluded from the
  length value, G-bit) and Group TLV (type 4) encoding infrastructure.
- All draft code points live in `crates/bmp/src/tlv.rs` with a renumber
  note — an IANA renumber at RFC publication is a single-file change.
  The draft's Appendix A contradicts its normative §5.2.1 on the Group
  TLV type; we follow the normative text.
- See ADR-0097 (Decision 4).

---

## draft-ietf-grow-bmp-path-marking-tlv-05 — Path Marking (pre-IANA)

- Path Marking TLV on Loc-RIB Route Monitoring toward BMPv4 collectors
  (an RM TLV — v4-gated by construction; v3 output is byte-identical
  with or without it).
- Status bits limited to what an RR can attest: Best + Stale (from the
  GR/LLGR machinery). FIB/damping/filter bits are never fabricated.
- Reason Code (§3.2) on live unicast announces: re-derived
  best-vs-runner-up through the `best_path_cmp_with_reason` explain
  ladder over the same candidate pool the recompute used; sole
  candidate → no reason; decisive steps without a registered draft code
  are omitted rather than mislabeled. VPN and dump entries carry bits
  only.
- Known collision: the draft self-assigns RM TLV type 5, which tlv-20
  §9 has since taken for VRF/Table Name; rustbgpd never emits the
  latter, and the constant carries a renumber note.
- See ADR-0097 (Decision 5).

---

## RFC 8203 — Admin Shutdown Communication

- Cease NOTIFICATION subcode 2 (Administrative Shutdown) carries a
  UTF-8 reason string.
- Reason threaded from gRPC `DisableNeighbor` through transport to the
  NOTIFICATION data field.

---

## RFC 9687 — Send Hold Timer

- A peer that stops draining its TCP socket can no longer wedge a
  session forever: each `write_all + flush` in the per-peer writer task
  is bounded by the configured `SendHoldTime`
  (`crates/transport/src/session/writer.rs`).
- **Detection shape (documented deviation from §4.3's letter):** the
  RFC models a free-running timer restarted on every sent message; we
  run a per-write deadline that only ticks while a write is pending.
  The trigger condition is equivalent — a wedged peer stalls the
  pending write, which times out — and the variant cannot fire on an
  idle session, so the §4.3 "stop when negotiated HoldTime is zero"
  rule is unnecessary and protection stays active with keepalives
  disabled. FRR's SendQ-progress check is the same shape.
- **Expiry actions (§4.3, Event 29 §4.2):** teardown reuses the
  TCP-failure path — session down, TCP close, `ConnectRetryCounter`
  increment, transition to Idle — **without** sending a NOTIFICATION.
  §4.3 makes the NOTIFICATION optional ("if … doing so will not delay"
  the teardown); the socket is by definition not draining, and a
  cancelled `write_all` may have left a partial PDU on the wire, so
  injecting one could corrupt framing. FRR/OpenBGPd attempt a
  best-effort code-8 NOTIFICATION here; we deliberately do not.
- **Local reporting (§4.3 required log, §5/§9 error code):** `warn` log
  with peer + duration, `bgp_send_hold_expirations_total{peer}`
  counter, an operator event-history record carrying error code 8 /
  subcode 0 ("Send Hold Timer Expired"), and a BMP Peer Down reason 2
  (local close, no NOTIFICATION) with FSM event code 29
  (`SendHoldTimer_Expires`). `NotificationCode::SendHoldTimerExpired`
  (8) decodes/logs if a peer ever sends it to us.
- **Default (§6):** enabled by default at
  `max(480, 2 × configured hold_time)` seconds. §6 recommends
  max(8 min, 2 × *negotiated* hold time); the negotiated value is
  unknowable at config time but never exceeds the configured one, so
  the derived default is always ≥ the RFC's recommendation and always
  satisfies the §4.4 `SendHoldTime > HoldTime` MUST. Precedent: FRR
  uses 2 × hold time (not configurable); OpenBGPd uses
  max(negotiated hold time, 90 s) (not configurable). Per-neighbor +
  peer-group `send_hold_time` knob (§6 MAY); 0 disables; non-zero
  values ≤ the effective hold time are rejected at config load (§4.4).
  Also settable over gRPC (`AddNeighbor` / `PeerGroupDefinition`, same
  validation) and via `rbgp neighbor <addr> add --send-hold-time`.

---

## RFC 7432 — EVPN (Phase 1: Route Reflector + Phase 2: Bidirectional VTEP + Phase 3: Multi-homing + Phase 4: IRB foundation)

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
  pipeline as iBGP-learned routes. `rbgp evpn add-mac-ip /
  add-imet / delete-mac-ip / delete-imet` CLI subcommands cover
  the operator-facing surface. Type 5 IP-Prefix injection is
  deferred pending use-case signal. Native Type 1/4 multi-homing
  origination ships through `[[ethernet_segments]]`; controller
  injection for those route types is not exposed.
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
- **Closed after v0.16.0 (v0.17.0 follow-ups):** `advertise_svi_mac`
  consumption (origination of the bridge's own MAC on
  instance-Ready via `InstanceDataplaneStatus.bridge_mac`),
  `sticky_macs` config schema (ADR-0056 — listed MACs originated
  with the RFC 7432 §15.4 sticky bit), sub-second mobility
  convergence (Gate 7c — EVPN-keyed `EvpnRouteEvent` broadcast in
  `crates/rib`; the 5 s poll stays as `Lagged` / cold-start
  backstop), and MAC-with-IP Type 2 origination via ARP/ND
  suppression (Gate 7b+2 — `AF_INET` / `AF_INET6` classifier in
  `crates/evpn-linux`, `LocalMacIpOriginator` in `crates/evpn`,
  daemon correlation under the FRR-style replace model per
  RFC 9135 §7.2.3 in `src/evpn_originator.rs`. Operator
  prerequisite: bridge `neigh_suppress on`).
- **Partially shipped (tracked in ADR-0055 §9 +
  `docs/evpn-alpha-soak.md`):** RFC 7432 §15.1 duplicate-MAC M/N
  detection defaults to M=180 s / N=5 and can opt into local-origin
  `suppress_local` recovery. Remote-route processing and dataplane
  loop-protection remain deferred.

### Phase 3: Multi-homing foundation (Gate 8, ADR-0057)

- **Gate 8 (v0.17.0, ADR-0057):** observable DF election +
  Type 1/4 origination. New `crates/evpn/src/segment.rs` carries
  the `EthernetSegment` domain type (ESI, member VNIs, DF
  preference, algorithm, originator IP). New
  `crates/evpn/src/df_election.rs` ships the pure
  `(state, event) → roles` state machine — RFC 7432 §8.5 service
  carving (sort candidates by originator IP ascending; `vni mod n`
  picks the slot) plus RFC 8584 §3 algorithm negotiation (lowest
  algorithm-id wins; `DefaultModulo` is the universal floor). New
  `crates/evpn/src/origination_es.rs` ships three deterministic
  Type 1/4 originators: `LocalEsOriginator` (Type 4 ES),
  `LocalEadPerEsOriginator` (Type 1 EAD-per-ES with MAX_ET
  marker), `LocalEadPerEviOriginator` (Type 1 EAD-per-EVI,
  role-aware via `on_vni_role_changed`). Daemon orchestrator at
  `src/evpn_segment.rs` subscribes to the EVPN best-path
  broadcast (Gate 7c), re-runs election on every Type 4 event,
  and updates the Prometheus surface
  (`evpn_df_role{esi,vni,role}` gauge,
  `evpn_df_role_changes_total{esi,vni}` counter).
- **Gate 8 scope was observation only; Gate 8b is now alpha and default-on
  with explicit opt-out flags.**
  The follow-up Gate 8b slices add ESI Label / ES-Import RT
  origination, DF-role-aware Type 2 ESI attachment, the
  BUM-suppression kernel primitive behind `apply_bum_enforcement`,
  aliasing projection, and a receive-side EAD-per-ES mass-withdraw
  filter. The 24 h MAC-churn soak passed 2026-05-16
  ([`docs/soaks/soak-gate8b-mac-churn-24h.md`](soaks/soak-gate8b-mac-churn-24h.md)),
  which unblocks the production-default flip, and the flip landed:
  `apply_bum_enforcement` / `apply_aliasing_ecmp` default to `true`
  since v0.23.0, with explicit `= false` as the documented opt-out.
- **M38 smoke** (`tests/interop/m38-evpn-df-election.clab.yml`):
  2-PE rustbgpd segment, asserts (1) PE1 elected DF, (2) PE2
  elected NonDF, (3) PE2 promotes to DF after PE1 shutdown,
  (4) `evpn_df_role_changes_total` advances on the promotion.

### Phase 4: Symmetric Interface-less IRB end-to-end (Gate 9, ADR-0058)

- **Gate 9 shipped end-to-end in v0.18.0:** `[[evpn_ip_vrfs]]` TOML
  schema (parsed in `src/config/schema.rs` as `EvpnIpVrfConfig`),
  `[[evpn_instances]].ip_vrf` binding, `IpVrf` / `IpVrfTable`
  domain types under `crates/evpn/src/ip_vrf/`, `IpVrfStatus`
  readiness probe (seven ADR-0058 §3 predicates),
  `LinuxDataplane::probe_ip_vrfs` + IP-VRF / L3 VXLAN device
  dumps. Slice 6 PR A (#77) added per-IP-VRF kernel-route
  observation + Type 5 origination via `RibUpdate::InjectEvpn`.
  Slice 6 PR B (#78) added remote Type 5 import + L3 FIB
  programming through the transactional `L3OwnedState` model
  (per-prefix install state + shared kernel-neighbor / L3VXLAN-FDB
  refcount, value-aware drift detection, four-phase apply
  ordering: route-remove → resolution-add → route-add →
  resolution-remove, Router MAC conflict detection,
  foreign-state preservation). PR #79 adds
  `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` multicast for
  sub-second tenant `ip addr del` withdraw. `DataplaneReport.ip_vrf_status`
  + `DataplaneReport.ip_vrf_installed_routes` propagate the
  verdict to subscribers; `rbgp evpn vrfs [NAME]` +
  `EvpnService.ListIpVrfs` / `EvpnService.GetIpVrf` gRPC
  surfaces let operators read it without scraping logs.
  **M39 hosted kernel-dataplane CI** validates the
  bidirectional Type 5 path against FRR 10.3.1.
- **Shipped since Gate 9:** auto-derived Route Targets (RFC 8365
  §5.1.2.1 for L2VNI / AS:VNI for L3VNI, v0.25.0, M39b cross-vendor
  smoke) and Type 5 gRPC injection (v0.25.0, M45). Hosted
  kernel-dataplane CI gates M36–M43 incl. M39b.
- **Shipped after Gate 9:** receive-side overlay-index recursion for imported
  Type 5 routes, native GW-IP + ESI overlay-index Type 5 origination
  (ADR-0087), single-active ESI overlay-index Type 5 receive, and
  all-active ESI overlay-index Type 5 receive with route-level ECMP plus
  L3VXLAN FDB-NHG programming. Remaining EVPN work is outside the core
  overlay-index shape: runtime mixed-edit tails, Linux softswitch local-bias
  limits, true shared-VNI / non-zero Ethernet Tag service, managed netdev
  ergonomics, and service-provider route families.

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

## RFC 9135 / RFC 9136 — Symmetric Interface-less IRB (Gate 9 end-to-end, v0.18.0)

- Type 2 MAC/IP routes with a second MPLS label (Label2) and the
  Router MAC ext community (Type 0x06, Subtype 0x03) are decoded
  and reflected unchanged. The Router MAC ext community accessor
  returns the 6-byte MAC. Slice 6 PR B interprets both: `label2`
  carries the L3VNI on Type 5 origination, and the Router MAC
  drives the kernel L3 neighbor + L3VXLAN FDB rows on remote
  Type 5 import.
- **Gate 9 (ADR-0058)** adopts the RFC 9136 §4.4.2 symmetric
  Interface-less IP-VRF-to-IP-VRF model as the only IRB mode
  rustbgpd supports. Asymmetric IRB (RFC 9135 §4.1) and the
  Interface-ful IP-VRF-to-IP-VRF model (RFC 9136 §4.4.1) are
  explicit non-goals.
- The `[[evpn_ip_vrfs]]` config block declares per-tenant IP-VRF /
  L3VNI state (RD, RTs, VTEP source IP, Router MAC, observed
  Linux VRF + L3 VXLAN device names, VRF table id).
  `[[evpn_instances]]` gains an optional `ip_vrf = "..."` field
  binding an L2VNI to one IP-VRF tenant.
- A pure-logic IP-VRF readiness probe (`rustbgpd-evpn` crate)
  maps a portable kernel snapshot against the configured `IpVrf`
  and returns an `IpVrfStatus` verdict; every failing predicate
  is enumerated.
- **Shipped in v0.18.0:** per-IP-VRF kernel-route observation,
  Type 5 origination via `RibUpdate::InjectEvpn` gated on
  readiness, remote Type 5 import + L3 FIB programming through
  the transactional `L3OwnedState` model with four-phase apply
  ordering, Router MAC conflict detection, sub-second withdraw
  via `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` multicast,
  `rbgp evpn vrfs` CLI + `ListIpVrfs`/`GetIpVrf` gRPC,
  M39 hosted smoke against FRR 10.3.1.
- **Shipped after Gate 9:** receive-side overlay-index recursion,
  auto-derived Route Targets per RFC 8365 §5.1.2.1, native GW-IP +
  ESI overlay-index Type 5 origination (ADR-0087), single-active ESI
  overlay-index Type 5 receive, and all-active ESI overlay-index Type 5
  receive with route-level ECMP plus L3VXLAN FDB-NHG programming. Remaining
  EVPN work is outside the core overlay-index shape: runtime mixed-edit
  tails, Linux softswitch local-bias limits, true shared-VNI / non-zero
  Ethernet Tag service, managed netdev ergonomics, and service-provider
  route families.

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
