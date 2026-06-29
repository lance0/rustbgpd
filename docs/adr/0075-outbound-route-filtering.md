# ADR-0075: Receive-side Address-Prefix Outbound Route Filtering (ORF)

**Status:** Accepted
**Date:** 2026-06-03

## Context

Outbound Route Filtering (ORF, RFC 5291) lets a BGP peer push a filter to its
neighbor; the neighbor applies that filter to the routes it advertises *back*.
With the Address-Prefix ORF-Type (RFC 5292) the filter is a prefix-list. This is
a standard route-server feature — a client constrains what it receives without
the server pre-configuring a per-client export policy — and the one
IX-route-server control-plane gap rustbgpd had versus FRR. It was the next
parity item on the ROADMAP after the v0.34.0 RPKI/index work.

rustbgpd already had a Route Refresh codec (RFC 2918 + 7313), capability
negotiation, and a per-peer Adj-RIB-Out export path, so ORF slots in as: a wire
codec, a capability advertised at OPEN, a per-peer prefix filter in the RIB, and
an inbound Route Refresh handler that installs it.

## Decisions

1. **Receive-side only.** rustbgpd advertises the ORF capability with the
   **Receive** role and applies received filters to its own outbound. It never
   sends ORF to upstreams (the Send role / client side is out of scope).
   Negotiation succeeds for an `(AFI, SAFI)` when *local Receive* ∩ *peer Send*.
2. **Address-Prefix ORF-Type 64; legacy 128 decoded but not negotiated.** We
   advertise and apply only the IANA standard type 64 (matching FRR's default).
   The wire codec *decodes* the pre-standard Cisco type 128 so we don't choke,
   but type-128 entries arrive un-negotiated and are ignored — keeping us inside
   the capability-intersection model. Advertising/negotiating 128 is a possible
   interop follow-up.
3. **Minlen/Maxlen: 0 = unspecified, prefix-list `ge`/`le` semantics**
   (RFC 5292 §4/§6). An entry `P/L` matches route `Q` iff `P` contains `Q` and:
   both 0 ⇒ exact (`route_len == L`); otherwise `max(L, minlen) ≤ route_len ≤
   (maxlen == 0 ? family_max : maxlen)`.
4. **Filter evaluation = prefix-list semantics (FRR-compatible).** Entries are
   ordered by `Sequence`; first match wins; no match on a non-empty list ⇒ deny
   (implicit deny). An empty filter ⇒ no constraint (permit-all).
5. **Initial-advertisement gate (RFC 5291 §6).** When ORF-Receive is negotiated
   for a family, the initial table dump for that family is suppressed (only the
   End-of-RIB is sent — an honest "empty table so far") until the peer's first
   ROUTE-REFRESH lifts the gate; the filtered table is then flooded. Without the
   gate we would flood the full table before the client's filter arrives,
   defeating ORF's purpose. The gate also holds for best-path churn during the
   gated window.
6. **DEFER defers the sweep, not the state.** ORF entries install immediately.
   `IMMEDIATE` (or a malformed-field reset) additionally re-runs the
   re-advertisement sweep now; `DEFER` installs only — the filter stays live for
   subsequent outbound churn and is swept on a later IMMEDIATE/plain refresh. A
   plain (non-ORF) ROUTE-REFRESH always re-advertises now and explicitly
   withdraws routes that the deferred filter now denies.
7. **Unsupported type vs malformed field (RFC 5291 §5.2).** An un-negotiated ORF
   type (128, unknown) is ignored. A structurally-framed but semantically
   invalid entry of a *negotiated* type (`minlen > maxlen`, length beyond the
   family) removes the previously installed list of that type (reset to
   permit-all) rather than tearing the session down — the wire codec surfaces
   such a group as `OrfEntries::Malformed` and the transport emits a REMOVE-ALL.
   A negotiated ORF message with an unknown `When-to-refresh` value is treated
   the same way at the RIB boundary: the installed list for that family/type is
   reset and a safe outbound resync runs, instead of installing the peer's
   entries with defer-like timing. Genuine BGP-framing truncation remains a
   `DecodeError`.
8. **ORF is an additional filter, applied before export policy, tracked
   separately.** In the distribution hot path the ORF check sits after the
   sendable-family check and before export-policy evaluation. An ORF-denied
   prefix is a silent withdraw — *not* a policy denial — so it is deliberately
   excluded from the export-policy-filtered set and counters. ORF filters the
   prefix, not Add-Path path-ids (the whole prefix is gated once).
9. **Config knob `prefix_orf_receive`** (per-neighbor and per-peer-group, TOML
   `prefix_orf_receive`) — direction-explicit so operators can't invert it. ORF
   is opt-in and off by default. It is configured via the static TOML surface
   only; the dynamic-neighbor gRPC surface is unchanged (no new method or field),
   so gRPC-added neighbors default to off.
10. **Only IPv4/IPv6 unicast Address-Prefix entries are parsed today.** The
    Route Refresh ORF codec keys Address-Prefix decoding on the resolved
    `(AFI, SAFI)` pair and only parses `(IPv4, Unicast)` / `(IPv6, Unicast)`.
    Known non-IP families (for example L2VPN/EVPN) and unknown future SAFIs
    remain `Raw` ORF groups, not malformed Address-Prefix entries. This avoids
    baking plain-IP prefix semantics into future L2VPN, VPNv4/v6, labeled-unicast,
    or MPLS-family work before those prefix encodings and policy semantics are
    implemented.

## Consequences

- A new `orf` module in `rustbgpd-wire` (capability + Route Refresh ORF codec);
  `RouteRefreshMessage` gains an optional `orf` field and loses `Copy`. This is a
  breaking change to the published `rustbgpd-wire` crate (→ next minor bump).
- `crates/rib` gains `OrfFilterSet` and two per-peer manager maps
  (`peer_orf_filters`, `peer_orf_pending`); the distribution functions take an
  `orf_filter` parameter. No `best_path` change.
- No new gRPC/authz surface — the authz tier matrix is unaffected.
- Behavior is covered by unit/integration tests across all five crates (wire
  codec round-trips, capability negotiation, filter semantics, the gate, and
  IMMEDIATE/DEFER sweep behavior), plus the **M57** containerlab interop lab
  (`tests/interop/m57-orf-frr.clab.yml`): a real FRR 10.3.1 client negotiates
  `capability orf prefix-list both` and pushes a `prefix-list NAME in`, and the
  driver asserts rustbgpd's advertised set is constrained to the permitted
  prefix and then re-expands when the filter is widened and the ORF re-sent.
  FRR is the reference for the one point of ecosystem variance (implicit-deny on
  a non-empty list).

See also ADR-0071 (capability negotiation patterns) and the Route Refresh codec
(RFC 2918/7313).
