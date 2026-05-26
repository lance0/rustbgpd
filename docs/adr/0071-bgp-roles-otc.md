# ADR-0071: BGP Roles and Only to Customer (RFC 9234)

**Status:** Accepted
**Date:** 2026-05-26

## Context

Route leaks — Provider/Peer routes mistakenly re-advertised to other
Providers/Peers — remain a persistent inter-AS hazard despite RPKI / ASPA and
operator prefix filters. RFC 9234 attacks the problem in-band: each speaker
advertises a configured Role in OPEN, both peers fail-closed on a role mismatch,
and an Only-To-Customer (OTC) path attribute on UPDATEs marks routes that must
never leave the customer cone.

rustbgpd targets IX route-server, MANRS-credible deployments, and DC fabrics, so
Roles + OTC is the highest-value remaining route-leak gap on the roadmap (P1).
It complements ASPA (path validation against upstream) and prefix policy
(operator-curated); Roles + OTC are the cheapest mechanical leak defense to add
— a fixed-shape capability + a typed attribute + small ingress/egress rules.

Current state of the art: FRR has had `neighbor … local-role …` for several
releases; BIRD supports Roles + OTC; OpenBGPd ships Roles without OTC; GoBGP has
an open issue tracking RFC 9234 but no implementation. Shipping Roles + OTC in
full, with FRR interop, closes the strongest remaining route-server /
MANRS-credibility gap on rustbgpd's roadmap.

### What the RFC fixes for us

**Roles (RFC 9234 §4).** Capability **code 9**, length 1, value ∈ {**0=Provider,
1=RS, 2=RS-Client, 3=Customer, 4=Peer**}. Compatibility matrix (RFC Table 2):
**Provider↔Customer, RS↔RS-Client, Peer↔Peer**. Any other pair ⇒ reject the OPEN
with **NOTIFICATION code 2 (OPEN Message Error), subcode 11 (Role Mismatch)**. A
**"strict mode"** extends the rejection to "I advertised a Role but the peer
didn't" — operator opt-in for environments that mandate Roles end-to-end. The
default behaviour for a missing-on-the-other-side Role is to ignore the absence
and proceed: the session establishes and **the §5 OTC procedures still fire**
driven by the local role (Provider implies the peer is a Customer, RS implies
RS-Client, Peer implies Peer, and vice versa). The peer's advertised Role is
needed only for the OPEN-time compatibility check and the strict-mode
rejection — not for classifying the peer's relationship to apply §5.

**OTC (RFC 9234 §5).** Path attribute **type code 35**, **Optional + Transitive**
(flags `0xC0`), length 4, value = a 32-bit ASN. Four rules — two egress, three
ingress (the RFC numbers them under one heading; we list five for clarity):

- **E1.** Sending to Customer / Peer / RS-Client and OTC not present ⇒ add
  OTC = local AS.
- **E2.** Route already has OTC ⇒ MUST NOT propagate to Provider / Peer / RS.
- **I1.** Receive from Customer / RS-Client with OTC present ⇒ leak. Ineligible.
- **I2.** Receive from Peer with OTC present AND OTC value ≠ peer's AS ⇒ leak.
  Ineligible.
- **I3.** Receive from Provider / Peer / RS without OTC ⇒ add OTC = remote AS
  (so downstream egress sees the marker).

### What rustbgpd already gives us

- **Capability dispatch is well-trodden:** 4-byte AS (RFC 6793), MP-BGP, Add-Path
  (RFC 7911), Extended Nexthop (RFC 8950), Extended Messages (RFC 8654),
  Graceful Restart (RFC 4724), Long-Lived GR (RFC 9494), Notification GR (RFC
  8538). Role is one more capability code following the same pattern.
- **`PathAttribute`** is the typed-or-`Unknown` hybrid enum (`AsPath`,
  `NextHop`, `MpReachNlri`, communities, `PmsiTunnel`, …) — `OnlyToCustomer(u32)`
  slots in as a new typed variant.
- **FSM OPEN-error paths** already produce a `NOTIFICATION` + transition to
  Idle for things like Bad Peer AS / Unsupported Capability; Role Mismatch
  (subcode 11) plugs into the same shape.
- **`prepare_outbound_attributes()`** is the documented seam for per-peer
  outbound attribute massaging — AS_PATH prepend, NEXT_HOP rewrite, private AS
  removal. OTC egress (E1/E2) belongs here.
- **Inbound UPDATE processing** already supports import-policy filtering and
  per-attribute validation. OTC ingress leak rejection (I1/I2) follows the
  same precedent: ineligible at import + structured event.
- **Per-neighbor config + peer-group inheritance** is established (ADR-0036); a
  new `role` + `strict_role` field follows the existing enum-field pattern
  (e.g. `redundancy_mode`, `df_algorithm`).

## Decision

Implement RFC 9234 in full for static eBGP neighbors. Per-neighbor `role` config
drives both the OPEN Role capability and the egress/ingress OTC rules. Optional
`strict_role` enforces "both sides MUST advertise" at OPEN time. Leak
detections are structured events + Prometheus counters, never silent.

### Role capability (§4)

- Advertise OPEN Capability **code 9** (length 1) whenever
  `[[neighbors]].role` is configured. The 1-byte value is the enum code from
  {Provider=0, RS=1, RS-Client=2, Customer=3, Peer=4}.
- After OPEN exchange, the FSM checks the compatibility matrix
  (Provider↔Customer, RS↔RS-Client, Peer↔Peer). Any other pair ⇒ send
  **NOTIFICATION code 2 / subcode 11 (Role Mismatch)** and transition to Idle.
- **Default (non-strict):** if the local advertised Role but the peer didn't,
  the session **establishes** (per the RFC §4.2 SHOULD). The **§5 OTC
  procedures still fire**, driven by the **local** role — Provider implies
  the peer is a Customer, RS implies RS-Client, Peer implies Peer, and vice
  versa. The peer's advertised role is needed only for the compatibility
  verification and strict-mode rejection; it is NOT required for the §5
  set/check rules to apply.
- **Strict mode** (`[[neighbors]].strict_role = true`, default `false`): if the
  local advertised Role and the peer didn't, reject with NOTIFICATION 2/11.
  Operator opt-in for fabrics / IXes that require Roles end-to-end.
- **Duplicate Role capabilities** (the RFC says don't advertise multiple): on
  receive, identical duplicates are coalesced into one Role capability.
  Multiple Role capabilities carrying **different role values** in the same
  OPEN are rejected with **NOTIFICATION 2/11 (Role Mismatch)** — the sender
  has emitted contradictory role declarations.
- The configured local role and any advertised peer role are both recorded on
  `NegotiatedSession` for observability; transport's §5 procedures read the
  LOCAL role (config-side) to drive set/check.
- iBGP sessions ignore Roles entirely (eBGP-only per spec).

### OTC path attribute (§5)

- New `PathAttribute::OnlyToCustomer(u32)` variant. **Type code 35**, **flags
  `0xC0`** (Optional + Transitive — NOT Partial), **length 4**, value = the
  32-bit ASN that initially set OTC.
- **Scope: IPv4 unicast and IPv6 unicast only.** RFC 9234 §5 explicitly
  scopes the procedures to AFI 1 / AFI 2, SAFI 1. v1 does NOT apply OTC to
  FlowSpec, EVPN, or any other AFI/SAFI — only the unicast egress path
  (`crates/transport/src/session/outbound.rs:1004`
  `prepare_outbound_attributes`) gets the OTC hook; the FlowSpec and EVPN
  siblings are deliberately untouched.
- **Preserve-existing-OTC invariant.** A valid OTC already present on a
  route is preserved unchanged through E1 and I3 — those rules only ADD
  when OTC is absent, never overwrite. The only paths that suppress an
  OTC-carrying route from the import view are I1 / I2 (semantic
  ineligibility, ingress) and E2 (egress suppression to non-
  Customer/Peer/RS-Client destinations).
- **Egress** (in `prepare_outbound_attributes()`, unicast only). Driven by
  the **local** role:
  - **E1:** If our local role is Provider / Peer / RS (i.e. the peer's
    implied role is Customer / Peer / RS-Client), and OTC is not already
    present on the route, ADD OTC = local AS.
  - **E2:** If the route already carries OTC, suppress the route from
    outbound advertisements when the peer's implied role is Provider /
    Peer / RS (i.e. our local role is Customer / Peer / RS-Client). The
    suppression is observable via the structured event + counter; it is
    not a silent drop.
- **Ingress — semantic leak detection** (in `process_update`). Driven by
  the **local** role. **This is RFC 9234 §5 semantic ineligibility, NOT
  RFC 7606 treat-as-withdraw** — the route is "ineligible for the Adj-
  RIB-In and Loc-RIB" per the RFC. We reuse the AS_PATH-loop / RR-loop
  transport-layer mechanics (drop announcements, process withdrawals,
  structured event + counter, session stays Established) because that's
  the only "drop announces, keep withdrawals" primitive in the codebase
  today — but the metric labels and events make the RFC justification
  explicit:
  - **I1:** From a peer whose implied role is Customer or RS-Client, with
    OTC present ⇒ leak. UPDATE announcements dropped, withdrawals
    processed, `bgp_otc_routes_blocked_total{reason="ingress_from_customer_rsclient"}`
    + structured event fire. Session NOT torn down.
  - **I2:** From a peer whose implied role is Peer, with OTC present AND
    OTC value ≠ remote AS ⇒ leak. Same semantic ineligibility +
    `reason="ingress_peer_mismatch"`.
  - **I3:** From a peer whose implied role is Provider / Peer / RS, with
    no OTC present ⇒ ADD OTC = remote AS on import (so downstream egress
    sees the marker and E1 doesn't re-set it with the wrong AS). If an
    OTC is already present (any value), preserve it unchanged per the
    invariant above — I3 does NOT overwrite.
- **Malformed OTC length (length ≠ 4 octets)** ⇒ **RFC 7606 treat-as-
  withdraw** (RFC 9234 §5 explicitly cites RFC 7606 for malformed OTC).
  **The wire crate MUST preserve a malformed OTC as a recoverable
  marker, not raise a fatal decode error** — otherwise `update.parse(…)`
  in `process_update` would short-circuit into the FSM error path and
  kill the session, which is precisely what RFC 7606 forbids for this
  case. v1 carries the malformed OTC through as
  `PathAttribute::Unknown(RawAttribute)` with the OTC type code retained
  on the raw bytes; the transport ingress branch inspects the parsed
  attribute set, sees a raw attribute with type 35 and length ≠ 4, and
  applies the same transport-layer mechanics as I1/I2 (drop
  announcements, process withdrawals, session stays Established) but
  with a distinct counter label:
  `bgp_otc_routes_blocked_total{reason="malformed_length"}`. Same event
  type as I1/I2 (see below) with `reason="malformed_length"`. This is a
  syntactic error, not a semantic leak; the reason label makes the
  distinction observable.
- Roles + OTC procedures fire whenever the **local** `[[neighbors]].role`
  is configured (eBGP only). They do NOT require the peer to advertise
  Role — the local role determines the peer's implied relationship per
  the RFC 9234 §4 compatibility matrix.
- iBGP sessions ignore Roles + OTC entirely.

### Config (`src/config/schema.rs`)

```toml
[[neighbors]]
address     = "203.0.113.1"
remote_asn  = 65002
role        = "provider"   # provider | rs | rs-client | customer | peer
strict_role = true         # optional, default false
```

Validation:

- `role` (if set) must be a valid enum value.
- `strict_role = true` is only meaningful when `role` is set; validation
  rejects `strict_role` without `role`.
- `role` is rejected on an **iBGP** session (eBGP-only per RFC) and on an
  **AS-Confederation sub-AS** session (RFC NOT RECOMMENDED).
- Per-neighbor and peer-group inheritance follow ADR-0036 chain semantics.

### What v1 does **not** cover (aligned with RFC 9234 carve-outs)

- **Complex peering on a single eBGP session** (one session that is Peer for
  some prefixes and Customer for others). RFC 9234: "Roles MUST NOT be
  configured on an eBGP session with a Complex peering relationship."
  Operators with mixed relationships split into multiple sessions. Config
  validation accepts a single role per neighbor; no per-prefix role.
- **AS Confederation** sub-AS sessions. RFC: NOT RECOMMENDED; validation
  rejects `role` on a confederation-internal session. **Future caveat:**
  if confederation support later exports OTC across the confederation
  boundary, the OTC ASN MUST be the **Confederation Identifier** — not a
  member AS (RFC 9234 §5).
- **Private-AS** interactions. The RFC explicitly leaves this outside its
  scope; rustbgpd treats private ASNs identically to public for Roles
  purposes (no special handling).
- **iBGP Roles.** Roles are eBGP-only per the spec.
- **Dynamic role change without session restart.** A role change on an
  established session requires the peer to bounce (announced as
  restart-required on SIGHUP, like other capability changes). Lifting this
  needs a Route-Refresh-plus-revalidation pass — a separate future ADR if
  demand appears.

### Observability

- gRPC `NeighborState` gains:
  - `local_role` (string — the configured local role; empty when unset),
  - `remote_role` (string — the role the peer advertised in OPEN; empty
    when the peer did not advertise Role),
  - `role_negotiated` (bool — true iff *both* sides advertised compatible
    roles),
  - `otc_routes_blocked` (uint64 — per-peer running total spanning all
    reason labels; cheap operator sanity-check on top of the labelled
    Prometheus counter).
- Prometheus counters:
  - `bgp_otc_routes_blocked_total{peer, reason}` with `reason ∈
    {ingress_from_customer_rsclient, ingress_peer_mismatch,
    malformed_length, egress_to_upstream_via_otc}`.
  - `bgp_role_mismatch_total{peer, local_role, remote_role}` incremented
    on OPEN-time rejection.
- New `BgpEventType::OtcRouteBlocked` event carrying peer, prefix,
  observed OTC value (or raw bytes for the malformed case), AS_PATH
  context, and the `reason` (`I1` / `I2` / `E2` / `malformed_length`).
  Named "blocked" rather than "leak" because malformed-length is not
  semantically a leak — one event type with a discriminating reason is
  simpler than splitting "leak" and "malformed" into two.

### Interop gate

**M55** — Roles + OTC against FRR 10.3.1, which has shipped
`neighbor … local-role …` for several releases. **FRR's role keyword
spelling diverges from the RFC** (`rs-server`, `rs-client`, `provider`,
`customer`, `peer` — note `rs-server` vs RFC `RS`), so the topology config
pins FRR's spelling and the test assertions compare against `vtysh`
output, not the RFC text. Strict mode in FRR is the `strict-mode` suffix
on the `local-role` line. The FRR doc reference is pinned to
[stable-10.3](https://docs.frrouting.org/en/stable-10.3/bgp.html) — not
`latest` — so the syntax matches the in-test FRR image.

1. **Pair establishment.** rustbgpd ↔ FRR for each compatible pair
   (Provider↔Customer, RS↔RS-Client, Peer↔Peer): assert Established + the
   negotiated `local_role` / `remote_role` in `ListNeighbors`.
2. **Mismatch.** rustbgpd Provider ↔ FRR Provider: assert OPEN rejected
   with **NOTIFICATION 2 / 11** visible in both directions.
3. **OTC egress set.** rustbgpd Provider advertises to FRR Customer:
   assert FRR sees the route carrying OTC = rustbgpd's AS.
4. **OTC ingress leak (deliberate injection).** A compliant FRR will not
   naturally emit an OTC-carrying route from a Customer-role session, so
   the test must inject the leak: either via a **raw-BGP fixture** (a
   small scapy / exabgp speaker that opens with Customer role and sends
   an UPDATE carrying OTC), or via FRR's debug injection path, or by
   peering through an intermediate that re-emits the route with OTC.
   Assertion: rustbgpd marks the route ineligible (not installed,
   `bgp_otc_routes_blocked_total{reason="ingress_from_customer_rsclient"}`
   increments, structured event emitted, session stays Established).
5. **Strict mode.** rustbgpd with `strict_role = true` peers against a
   FRR config without `local-role`: assert NOTIFICATION 2/11.
6. **Malformed OTC length.** A raw-BGP fixture sends an UPDATE with an
   OTC attribute of length 3 (or 5). Assert the announcement is dropped,
   `bgp_otc_routes_blocked_total{reason="malformed_length"}` ticks, and
   the session stays Established (RFC 7606 treat-as-withdraw, distinct
   from the semantic-leak reason label).

## Slicing

| PR | Scope | Verification |
|----|-------|--------------|
| **PR1** | `crates/wire`: Role capability (code 9, 1-byte enum encode/decode) + OTC path attribute (type 35, 4-byte AS encode/decode) + their public re-exports. **Malformed OTC length (≠ 4) is preserved as `PathAttribute::Unknown(RawAttribute)` carrying the OTC type code — NOT a fatal `DecodeError`** so transport can apply RFC 7606 treat-as-withdraw without killing the session. Pure crate; unit tests + fuzz-target update if applicable. | `cargo test -p rustbgpd-wire`; new tests cover all five role values, the `0xC0` flag encoding, round-trips, **malformed-length stored as recoverable `Unknown` (verified non-fatal)**, and the `expected_flags()` rejection path for bad flags. |
| **PR2** | `crates/fsm` role compatibility + NOTIFICATION 2/11 + strict-mode gating + duplicate-role-cap rejection, and recording the configured local role + advertised peer role on `NegotiatedSession`; `crates/transport` ingress (I1/I2 semantic leak + malformed-OTC-length treat-as-withdraw + I3 set) + egress (E1/E2 unicast only — FlowSpec/EVPN siblings NOT touched) wired through `prepare_outbound_attributes` and the inbound UPDATE path; `src/config` schema + validation for `role` / `strict_role` (mirroring the `remove_private_as` precedent); structured event + Prometheus counters with distinct `reason` labels for `ingress_from_customer_rsclient` / `ingress_peer_mismatch` / `malformed_length` / `egress_to_upstream_via_otc`. | `cargo test --workspace`; unit tests cover each ingress/egress rule, the duplicate-cap behaviour, the malformed-length treat-as-withdraw, the preserve-existing-OTC invariant, and the strict / non-strict paths; FSM table covers the compatibility matrix. |
| **PR3** | `proto/rustbgpd.proto` + `crates/api/src/neighbor_service.rs`: surface `local_role` / `remote_role` / `role_negotiated` on `NeighborState`; `crates/cli` renders them in `rustbgpctl neighbor show`. Additive — no new authz-matrix entries. | `cargo test -p rustbgpd-api`; `rustbgpctl neighbor show` smoke. |
| **PR4** | FRR interop topology + driver under `tests/interop/`, wired into `kernel-dataplane.yml`. Covers the six interop scenarios above (pair establishment, mismatch, OTC egress set, OTC ingress leak via deliberate injection, strict mode, malformed-length treat-as-withdraw). | M-series CI green against FRR 10.3.1. |

## Implementation status

| Slice | Status |
|-------|--------|
| PR1 — wire codec (Role capability + OTC attribute) | Planned |
| PR2 — FSM mismatch + transport ingress/egress + config | Planned |
| PR3 — gRPC `NeighborState` + CLI | Planned |
| PR4 — FRR interop | Planned |

## Repo seams (grounded)

- **Wire constants:** `crates/wire/src/constants.rs:61` (`capability_code`
  module — add `BGP_ROLE = 9`), `:83` (`attr_type` — add
  `ONLY_TO_CUSTOMER = 35`), and `crates/wire/src/notification.rs:80`
  (`open_subcode` — add `ROLE_MISMATCH = 11`; description row in
  `description()` at `notification.rs:180`).
- **Capability codec:** `Capability` enum at `crates/wire/src/capability.rs:135`
  with a lossless `Unknown { code, data }` fallback at `:173`. Add a
  `Capability::Role { role: BgpRole }` variant and arms in `decode` (`:190`,
  match at `:212`), `encode` (`:440`), `code()` (`:575`), `encoded_len()`
  (`:592`). Tests follow the existing pattern (`capability.rs:703-1407`):
  decode + roundtrip + bad-length-stored-as-Unknown + invalid-role-as-Unknown,
  mirroring `extended_message_bad_length_stored_as_unknown` (`:1148`).
- **OPEN optional-parameter parser:** `decode_optional_parameters`
  (`capability.rs:612`) already iterates capability TLVs in a bounded
  sub-buffer — no change needed.
- **Path attribute:** `PathAttribute` enum at `crates/wire/src/attribute.rs:608`
  with `Unknown(RawAttribute)` fallback at `:637`. Add a
  `PathAttribute::OnlyToCustomer(u32)` variant + arms in
  `decode_attribute_value` (`:773`, match at `:797`), `encode_path_attributes`
  (`:1405`), `type_code()` (`:643`), `flags()` (`:664`). Critically, add an
  `expected_flags()` row at `attribute.rs:1369` for
  `attr_type::ONLY_TO_CUSTOMER => Some(OPTIONAL | TRANSITIVE)` — this gives
  malformed-flags rejection (subcode 4 `ATTRIBUTE_FLAGS_ERROR`) for free,
  same path the COMMUNITIES family uses. Encode body is one
  `extend_from_slice(&value.to_be_bytes())`, modelled on `Med`/`LocalPref`
  (`attribute.rs:1432-1441`).
- **`NegotiatedSession`:** `crates/fsm/src/action.rs:26`. The pattern is a
  named scalar field per capability (e.g. `peer_gr_capable: bool` at `:42`,
  `peer_extended_message: bool` at `:54`). Add `peer_role: Option<BgpRole>`
  following this convention.
- **OPEN validation + role mismatch:** `validate_open()` at
  `crates/fsm/src/negotiation.rs:32` is the single seam. Existing error
  branches return `Err(NotificationMessage::new(NotificationCode::OpenMessage,
  <subcode>, <data>))` at `:37-44` (UNSUPPORTED_VERSION), `:47-53`
  (UNACCEPTABLE_HOLD_TIME), `:56-62` (BAD_BGP_IDENTIFIER), `:69-75`
  (BAD_PEER_AS). Insert the role-compatibility check after the existing
  capability extractions (around `:172`, before constructing
  `NegotiatedSession` at `:175`). The OPEN handler at
  `crates/fsm/src/session.rs:208` already turns `Err(notification)` into
  `Action::SendNotification` + close + → Idle (`:248`) — no change there.
- **Local capability emission:** `PeerConfig::local_capabilities()` at
  `crates/fsm/src/config.rs:41` builds the outgoing OPEN cap list. Append
  `Capability::Role { role }` gated on `config.role.is_some()`, mirroring
  the GR / Add-Path push pattern.
- **Transport — egress OTC set (E1/E2), unicast only.** Function is
  `prepare_outbound_attributes` at `crates/transport/src/session/
  outbound.rs:1004`; the hook itself lands just before
  `attach_graceful_shutdown_if_enabled` (around `:1170`). The "OTC not
  already present" guard mirrors the LOCAL_PREF backfill at
  `outbound.rs:1079-1085`. **Do NOT add the hook to**
  `prepare_outbound_attributes_flowspec` (`:1182`) or
  `prepare_outbound_attributes_evpn` (`:1286`) — RFC 9234 §5 scopes the
  procedures to AFI 1/2 SAFI 1; non-unicast SAFIs are explicitly out of
  v1 scope.
- **Transport — ingress OTC check (I1/I2 semantic leak + malformed-
  length treat-as-withdraw):** new branch modelled on the AS_PATH-loop
  branch at `crates/transport/src/session/inbound.rs:216` (the branch
  body spans `:219-292`, with the keep-withdrawals fallthrough at
  `:250-289`). Insert after the RR-loop branch (after `:369`). The
  branch inspects `parsed.attributes` for **two** cases: (a) a typed
  `PathAttribute::OnlyToCustomer(value)` (I1/I2 semantic check), and (b)
  a `PathAttribute::Unknown(raw)` where `raw.type_code ==
  attr_type::ONLY_TO_CUSTOMER` (malformed length — the wire crate
  preserves it as Unknown rather than raising `DecodeError`, see PR1).
  All three cases drop announcements, process withdrawals, bump
  `bgp_otc_routes_blocked_total{reason=…}` with the right label, and
  emit `BgpEventType::OtcRouteBlocked`. No NOTIFICATION; session stays
  Established. `process_update` entry is `inbound.rs:74`.
- **Config schema:** `Neighbor` struct at `src/config/schema.rs:459` —
  add `role: Option<String>` + `strict_role: Option<bool>` following the
  `Option<T>`-with-string-enum pattern. Mirror fields on `PeerGroupConfig`
  at `:567`. The right precedent is **`remove_private_as`** (string in
  TOML → enum on the way into `PeerConfig`): validation at
  `src/config/validation.rs:350-373` (match arm at `:355`). NOT the
  `df_algorithm` / `redundancy_mode` precedent — those resolve at
  use-site, which is the wrong shape here.
- **`PeerConfig` (FSM):** `crates/fsm/src/config.rs:13` — add
  `role: Option<BgpRole>` + `role_strict: bool` so `local_capabilities()`
  can emit Role and `validate_open` can drive the compatibility check.
- **gRPC `NeighborState`:** `proto/rustbgpd.proto:187` (currently 13
  fields; add tag 14+ for `local_role` (string), `remote_role` (string),
  `role_negotiated` (bool), `otc_routes_blocked` (uint64) — matching the
  field names listed in the Observability section). Mapper at
  `crates/api/src/neighbor_service.rs:145` (`peer_info_to_proto`).
  `PeerInfo` at `crates/api/src/peer_types.rs:906` gets the four new
  fields; `build_peer_info` at `src/peer_manager/snapshot.rs:17-50`
  populates them.
- **`PeerSessionState`** (live session, populated on transition to
  Established): `crates/transport/src/handle.rs:227`. Add
  `local_role: Option<BgpRole>`, `remote_role: Option<BgpRole>`,
  `role_negotiated: bool` (mirror `negotiated_hold_time: Option<u16>` at
  `:235`) and `otc_routes_blocked: u64` (mirror `notifications_received:
  u64` at `:245`).
- **Metrics:** mirror the AS_PATH-loop counter pattern exactly —
  declaration at `crates/telemetry/src/metrics.rs:65`
  (`as_path_loop_detected: IntCounterVec`), registration at `:358-365`,
  recorder `record_as_path_loop_detected` at `:1098-1102`. Add
  `bgp_otc_routes_blocked_total{peer, reason}` and
  `bgp_role_mismatch_total{peer, local_role, remote_role}` following the
  same shape.
- **Interop precedent:** capability-negotiation topologies to mirror —
  M11 (Graceful Restart, `tests/interop/m11-gr-frr.clab.yml`), M17
  (Add-Path), M18 (Extended Next Hop). Next free slot is **M55** (M54 is
  the gNMI interop, paired with ADR-0070).
- **ADR index:** `docs/adr/README.md:81` is the last row (ADR-0070). Add
  the ADR-0071 row directly below, before the `## Template` section.

## Consequences

- rustbgpd ships a real, RFC-conformant Roles + OTC implementation — the
  strongest remaining route-server / MANRS-credibility gap closes. A genuine
  edge over GoBGP (open issue, not implemented) and over OpenBGPd (Roles
  without OTC).
- **Architectural constraint — OTC ingress uses the loop-detection
  "drop announces, keep withdrawals" mechanism for two semantically
  distinct cases.** rustbgpd has **no general RFC 7606 treat-as-withdraw
  infrastructure** today: `crates/wire/src/validate.rs` is binary (ok or
  NOTIFICATION + session reset), and the only "drop announcements
  without tearing the session" primitives are the AS_PATH-loop branch at
  `inbound.rs:216-292` and the RR-loop branch at `:301-369`. The ADR
  reuses that mechanism for two cases that the RFC frames very
  differently:
  - **I1 / I2 — RFC 9234 §5 semantic ineligibility.** The route is
    "ineligible for the Adj-RIB-In and Loc-RIB." Not a malformed UPDATE.
    Distinct `reason` labels (`ingress_from_customer_rsclient`,
    `ingress_peer_mismatch`) and distinct structured events keep the RFC
    justification explicit even though the transport mechanism is shared.
  - **Malformed OTC length (≠ 4 octets) — RFC 7606 treat-as-withdraw.**
    Genuinely a syntactic error. Same transport mechanism, different
    `reason` label (`malformed_length`).
  Lifting either case to per-prefix `RouteEvent::PolicyFiltered` (so the
  RIB sees the rejected prefix) is a deliberate follow-up, matching the
  AS_PATH-loop precedent's transport-layer short-circuit.
- Strictly opt-in via `[[neighbors]].role`; existing configs are unchanged.
  Non-role sessions behave identically to today's eBGP.
- The OTC ingress path adds a small per-route check: one attribute lookup +
  one ASN comparison. Performance impact is negligible.
- Operators who want full leak prevention combine Roles + OTC with existing
  ASPA / RPKI / prefix filters — they are complementary, not redundant.
  Document this in CONFIGURATION.md and the user-facing release notes.
- Pulls on one small future item: a Route-Refresh-plus-revalidation path so an
  in-place role flip can revalidate ingress without bouncing the session.
  Deferred; current behaviour is restart-required on role change.

## Deferred

- **Complex peering** on a single eBGP session (RFC: MUST NOT configure).
- **AS Confederation sub-AS** Roles (RFC: NOT RECOMMENDED).
- **iBGP Roles** (eBGP-only per RFC).
- **Dynamic role change without session restart** — needs a Route-Refresh +
  revalidation pass; future ADR if demand appears.
- **Operator override of OTC behaviour** (e.g. forced strip on egress for
  asymmetric leak protection) — deliberately not exposed in v1.

## References

- RFC 9234, *Route Leak Prevention and Detection Using Roles in UPDATE and OPEN
  Messages*:
  <https://www.rfc-editor.org/rfc/rfc9234.html>
- FRR BGP role documentation (pinned to stable-10.3 — matches the
  in-test FRR image; "latest" can diverge):
  <https://docs.frrouting.org/en/stable-10.3/bgp.html>
- APNIC blog, *BGP route leak prevention and detection with the help of RFC
  9234*:
  <https://blog.apnic.net/2023/05/10/bgp-route-leak-prevention-and-detection-with-the-help-of-rfc-9234/>
- APNIC blog, *RFC 9234 observed in the wild*:
  <https://blog.apnic.net/2023/05/16/rfc-9234-observed-in-the-wild/>
- GoBGP issue #3244 (tracking, not implemented):
  <https://github.com/osrg/gobgp/issues/3244>
- ADR-0036 — policy chaining + per-neighbor inheritance.
- ADR-0064 — gRPC tier authorization; a future Roles config-write would be
  `Mutating` / `OperatorOnly`.
- `ROADMAP.md` P1 entry "BGP Roles + OTC (RFC 9234)" — this ADR closes the
  exit condition.
