# ADR-0050: EVPN Route Reflector (RFC 7432 Phase 1)

**Status:** Accepted
**Date:** 2026-04-23

## Context

VXLAN-EVPN is the de-facto control plane for GPU / multi-tenant data
center fabrics. Prior roadmap framing deprioritized EVPN as "not needed
for IX route server or SDN controller use cases" — that read the market
wrong: DC fabrics where an API-first route reflector is the natural
deployment shape are a first-class use case, not a tangent. EVPN is now
being treated as P2.

Phase 1 scope is deliberately narrowed to **route reflector role**:

- Reflect all 5 RFC 7432 route types between VTEP peers per RFC 4456
- No local EVI/VRF/VNI state, no MAC learning, no data-plane forwarding
- VXLAN encapsulation only (RFC 8365)
- All VTEPs handle their own DF election, IRB semantics, and kernel FDB

VTEP mode, IRB semantics (RFC 9135), DF election (RFC 8584), PBB-EVPN
(RFC 7623), and EVPN-MVPN (RFC 9251) are explicit future-phase work.
Controller-injection gRPC was originally listed here as future work but
shipped inside the Phase 1 RR bundle (Gate 6, 2026-04-24).

The existing FlowSpec implementation (ADR-0035) established the pattern
for non-prefix NLRI: parallel tables in Adj-RIB-In / Loc-RIB /
Adj-RIB-Out keyed by a non-prefix identifier, separate decode/encode
path, dedicated match clauses, dedicated gRPC endpoints. EVPN follows
this pattern throughout.

## Decision

### Wire codec in its own module (not extending `Prefix`)

`crates/wire/src/evpn.rs` holds an `EvpnRoute` enum (6 variants: Type 1
EAD per-ES, Type 1 EAD per-EVI, Type 2 MAC/IP, Type 3 IMET, Type 4 ES,
Type 5 IP Prefix) and primitives — `RouteDistinguisher`,
`EthernetSegmentIdentifier`, `MacAddress`, `EthernetTagId`, `MplsLabel`,
`EvpnIpPrefixValue`.

Extending `Prefix` was considered and rejected:

- `Prefix` is `Copy` (20 bytes max). EVPN routes are variable-length and
  cannot be `Copy` without breaking the existing `HashMap<(Prefix, u32),
  Route>` storage shape.
- `Prefix` participates in longest-prefix-match concepts (`prefix_len()`);
  EVPN routes don't have prefix length (except Type 5, which carries it
  internally).
- FlowSpec had the same shape mismatch and chose a parallel table — EVPN
  follows.

Trade-off: every RIB method that handles prefixes needs a parallel EVPN
method. The compiler enforces completeness; FlowSpec already proved the
pattern scales.

### Split payload from identity: `EvpnRoute` vs `EvpnRouteKey`

`EvpnRoute` carries the full RFC 7432 wire payload — needed for round-
tripping routes through a route reflector without losing label / gateway
/ ethernet-tag information.

`EvpnRouteKey` carries only the identifying fields per route type and is
`Copy + Eq + Hash` — suitable as the RIB's `HashMap` key.

EAD per-ES and EAD per-EVI share a wire format (discriminated by
`EthernetTagId::MAX_ET`) but get separate `EvpnRouteKey` variants so the
RIB never collapses two semantically distinct routes that happen to
share the wire layout.

### Per-type encoding gotchas that the codec handles

- **Type 2 IP address length field** is in **bits** (0/32/128), not
  bytes. Wire encoding carries 0/4/16 bytes of IP data after the length.
- **Type 2 optional Label2** — 0 or 3 trailing bytes after the primary
  label, never both. The decoder accepts either and round-trips
  faithfully; encoders emit Label2 only when present.
- **Type 5 IPv4 vs IPv6 discrimination** — RFC 9136 makes the IPv4 form
  34 bytes total and the IPv6 form 58 bytes. The decoder uses total
  payload length to pick the variant; the prefix-length byte cannot
  disambiguate alone because 32 is a valid IPv6 prefix length.
- **Route Distinguisher display** — three RFC 4364 encodings (Type 0:
  `<asn16>:<u32>`; Type 1: `<ipv4>:<u16>`; Type 2: `<asn32>:<u16>`).
  Unknown types hex-dump fall back.

### Parallel RIB tables, reusing the FlowSpec shape

`AdjRibIn`, `AdjRibOut`, and `LocRib` each gain
`HashMap<EvpnRouteKey, EvpnRibRoute>` alongside their existing
`flowspec_routes` tables. `EvpnRibRoute` mirrors `FlowSpecRoute`'s
attribute-accessor surface (`origin()`, `as_path()`, `local_pref()`,
`communities()`, etc.) and reuses the existing attribute-intern table
in `AdjRibIn` so identical attribute sets share a single `Arc` across
unicast, FlowSpec, and EVPN routes.

### Best-path: type-specific head + shared BGP body

`evpn_tiebreak_simple` (in `loc_rib.rs`) runs a Type-2-specific head
for MAC Mobility per RFC 7432 §15.1, then falls through to the standard
BGP preference chain:

```
Type 2 head (if both routes are Type 2):
  sticky_flag  (sticky wins regardless of sequence)
  sequence     (higher wins)
Shared BGP body:
  local_pref   (higher wins)
  as_path len  (shorter wins)
  med          (lower wins)
  ebgp > ibgp
  peer address (lower wins — deterministic)
```

Absence of the MAC Mobility community is treated as `(sticky=false,
seq=0)` per RFC 7432 §7.7, so the head is a pure extension — existing
MAC/IP routes without the community fall through to the same ordering
they'd have had before.

Type 1/4 DF-election tiebreaks are not implemented in Phase 1 because
the RR does not run DF election — downstream VTEPs do. Route Types 3
and 5 have no type-specific head.

Not forked into its own function: keeping a single `evpn_tiebreak_simple`
with a dispatch head is cheaper to maintain than a per-route-type
function tree.

### 6 typed extended-community accessors

Added to `ExtendedCommunity`:

| Subtype | Purpose | RFC |
|---|---|---|
| 0x03 / 0x0C | BGP Encapsulation (distinguish VXLAN=8) | RFC 9012 / 8365 |
| 0x03 / 0x0D | Default Gateway (flag-only) | RFC 4761 / 7432 |
| 0x06 / 0x00 | MAC Mobility (sticky + sequence) | RFC 7432 §7.7 |
| 0x06 / 0x01 | ESI Label (single-active + label) | RFC 7432 §7.5 |
| 0x06 / 0x02 | ES-Import Route Target | RFC 7432 §7.6 |
| 0x06 / 0x03 | Router MAC | RFC 9135 §4.1 |

The opaque `u64` passthrough handles any other subtype losslessly.
RFC 8214 Layer 2 Attributes is deferred — its encoding is complex and
not needed for Phase 1 RR flow.

BGP Encapsulation uses the widely-deployed RFC 5512-style layout
(4 bytes reserved + 2-byte Tunnel Type), not the RFC 9012 §4.1 layout
(1-byte Tunnel Type + 5-byte Flags). The deployed code in FRR, BIRD,
Juniper, and Cisco emits the RFC 5512 format and interop compatibility
outweighs strict RFC 9012 adherence.

### Capability negotiation and config plumbing

`Afi::L2Vpn = 25` and `Safi::Evpn = 70` extend the existing enums.
`parse_families()` accepts `"l2vpn_evpn"`. GR, LLGR, Add-Path, and
Extended Next-Hop capability construction is already data-driven from
the configured family list, so EVPN flows through naturally — Add-Path
and Extended Next-Hop remain unicast-only by construction (filtered by
`safi == Unicast`).

No new `[evpn]` config section in Phase 1. The RR operates entirely
through per-neighbor `families = ["l2vpn_evpn"]` + `route_reflector_client`.

### Transport integration

Inbound (`crates/transport/src/session/inbound.rs`):
- New `mp.safi == Evpn` branch after the FlowSpec branch
- Policy context for Types 1-4 uses a placeholder `0.0.0.0/0` prefix
  (same trick FlowSpec uses) — RT / community / AS_PATH matching works
  naturally; for Type 5 (RFC 9136 IP Prefix) the actual NLRI prefix is
  surfaced in the `RouteContext` so prefix-based policy clauses match
  the real destination
- Builds `EvpnRibRoute`s and sends through `RibUpdate::RoutesReceived`
- MP EoR detection extended to require `mp.evpn_withdrawn.is_empty()`

Outbound (`crates/transport/src/session/outbound.rs`):
- EVPN withdrawals emit a single `MP_UNREACH_NLRI` per update; the
  `evpn_route_from_key` helper reconstructs a minimal `EvpnRoute` with
  zero-valued labels and `EthernetSegmentIdentifier::ZERO` since the
  receiver identifies routes by key only
- EVPN announces group routes by `(next_hop, attrs)` and emit one
  `MP_REACH_NLRI` per group. Next-hop is the originating VTEP's loopback
  (preserved from ingress) so downstream VTEPs can build correct VXLAN
  tunnels
- `prepare_outbound_attributes_evpn` mirrors `_flowspec`: strips
  legacy `NEXT_HOP`, prepends local ASN on eBGP, adds ORIGINATOR_ID +
  CLUSTER_LIST on RFC 4456 reflection

### Policy: no new fields in Phase 1

The existing `RouteContext` (extended communities, communities, AS_PATH,
peer metadata, route_type) is exactly what an RR needs to filter EVPN
routes. RT filtering works through the existing `match_community`
clause against `RT:<asn>:<value>` extended communities. A
`match_evpn_route_type` clause is a Phase 1.5 follow-up if operators
need it in production.

The placeholder-prefix trick for Types 1-4 means a `match prefix =
"0.0.0.0/0"` clause will match those route types — operators with
prefix-based policy chains should scope them by family tag if they
care. Type 5 (IP Prefix) bypasses the placeholder and matches against
its actual NLRI prefix, so prefix-based policy filters Type 5 EVPN
routes the same way they filter unicast.

### gRPC surface

New `ADDRESS_FAMILY_L2VPN_EVPN = 5` variant. New `EvpnRouteEntry`
message carries route_type, rd, esi, ethernet_tag, mac, ip, prefix,
gateway, label, label2, next_hop, peer_address, as_path, communities,
extended_communities, and a **decoded `tunnel_type`** field populated
from the BGP Encapsulation ext community (VXLAN=8 for RFC 8365 fabrics).

`ListEvpnRoutes(ListEvpnRequest) returns (ListEvpnResponse)` on
`RibService`. Filters by route_type, peer, and RD. The proto surface
intentionally exposes fields as display-formatted strings rather than
re-encoding the wire payload — gRPC is the operator-facing surface, not
a wire round-trip path, and display strings are easier to work with.

`AddEvpnRoute` / `DeleteEvpnRoute` controller-injection RPCs shipped
inside Phase 1 (Gate 6, 2026-04-24). The service accepts display-form
RDs (`65000:100`, `10.0.0.1:100`, `4200000000:100`), parses MAC + IP +
label, and assembles an `EvpnRibRoute` with `RouteOrigin::Local` that
flows through the same reflection pipeline as iBGP-learned routes.
Phase 1 covers Type 2 MAC/IP and Type 3 IMET; Type 5 IP-Prefix
injection is deferred pending use-case signal. Native Type 1/4
multi-homing origination later shipped through `[[ethernet_segments]]`,
but the injection service still does not expose those route types.

### CLI

`rustbgpctl evpn [--route-type N] [--peer IP] [--rd STR]` — JSON output
via `--json`. Human output groups fields conditionally per route type
(MAC/IP routes show MAC + IP but not prefix; Type 5 shows prefix +
gateway but not MAC). VXLAN encap is surfaced as `encap=vxlan` for
easy operator identification.

## Consequences

- rustbgpd becomes viable as the control plane for VXLAN-EVPN DC
  fabrics where VTEPs run their own MAC learning and DF election
  (SONiC + FRR leaves, for example).
- The wire crate gains ~800 LoC of EVPN codec and 8 new public types.
  SemVer bump for `rustbgpd-wire` on next release.
- `RibUpdate::RoutesReceived` and `OutboundRouteUpdate` have new fields
  — all 156 existing struct-literal call sites were updated.
- EVPN routes are covered by GR/LLGR stale handling per RFC 9494
  (Gate 2, 2026-04-23): `mark_stale_evpn` / `clear_stale_evpn` /
  `promote_to_llgr_stale_evpn` / `sweep_{stale,llgr_stale}_evpn` on
  `AdjRibIn`, wired through `graceful_restart.rs` and
  `route_refresh.rs` at every unicast + FlowSpec call site. LLGR
  promotion injects `LLGR_STALE` via `Arc::make_mut` and tracks
  locally-injected communities in `evpn_llgr_stale_local_tags` so
  peer-originated communities are preserved across EoR.
- Policy match clauses don't yet recognize route-type / VNI / ESI —
  operators get RT-based filtering via extended communities. A
  `match_evpn_route_type` clause is Phase 1.5.
- The EVPN interop surface now spans M29 (capability + session sanity)
  through M33 (50k-route scale + churn): M30 covers real Type 2 MAC
  reflection through kernel VXLAN against FRR 10.3.1; M31 covers MAC
  mobility + sticky preservation; M32 gates on Type 1 EAD-per-EVI
  + Type 4 ES reflection for multi-homing (FRR ES on a bond interface);
  M33 dogfoods `rustbgpd-wire` from the
  in-tree `bench/evpn-load` crate. See INTEROP.md § P1.5 for the full
  matrix.
- Controller-injection (`AddEvpnRoute` / `DeleteEvpnRoute`) is exposed
  for Type 2 MAC/IP and Type 3 IMET (Gate 6). Type 5 IP-Prefix
  injection remains deferred pending use-case signal. Native Type 1/4
  multi-homing origination later shipped through `[[ethernet_segments]]`;
  only the injection-service surface is still gated.
- MPLS encapsulation is not wired — the BGP Encapsulation ext community
  decoder handles any tunnel type value losslessly but rustbgpd does
  not negotiate an encap preference. VXLAN is the deployed case.

See [docs/evpn-enablement.md](../evpn-enablement.md) for the gate-by-gate
plan. Gates 0-6 (capability, Type 2 reflection, GR/LLGR, MAC mobility,
multi-homing reflection, scale validation, controller injection) shipped
on `feat/evpn-rr`; Gates 7-9 (VTEP mode, multi-homing execution / DF
election, IRB / MVPN / PBB / MPLS) remain a strategic decision point.
