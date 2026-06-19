# ADR-0092: EVPN VLAN-Aware Bundle service (non-zero Ethernet Tag)

**Status:** Proposed
**Date:** 2026-06-19

> Draft / stub. Frames the problem, the proposed decision shape, and the open
> questions for the service-model work ADR-0089 deferred. Decisions marked
> *(proposed)* are not final until this moves to Accepted.

## Context

ADR-0089 shipped the **VLAN-Based** service interface (RFC 7432 §6.1 /
RFC 8365 §5.1.3): one broadcast domain per EVI, Ethernet Tag ID fixed at `0`,
on a Linux `vlan_filtering=1` bridge. ADR-0089 Decision 6 explicitly deferred
the **VLAN-Aware Bundle** service — where one MAC-VRF / EVI carries *multiple*
VLANs and the **Ethernet Tag ID identifies the VLAN within the bundle** — to a
separate ADR. This is that ADR.

The VLAN-Aware Bundle model is the operationally common shape on FRRouting and
NVIDIA-style fabrics (one EVI, many VLANs, Ethernet-Tag-scoped routes), and is
the parity gap behind "true VLAN-aware bridge support." It is a control-plane
**and** dataplane lift: the EVPN route key gains Ethernet-Tag significance, the
RIB/import semantics become per-`(EVI, Ethernet Tag)`, and the Linux mapping
becomes `(EVI, Ethernet Tag) → (bridge VLAN, VXLAN VNI)`.

The wire codec already carries the Ethernet Tag field on Type 1/2/3/5; what
changes is its **semantics** (non-zero = VLAN-within-bundle) and everything
that keys on it.

## Decision

### 1. New config-selected service-interface mode *(proposed)*

Per EVI, the operator selects VLAN-Based (today's Tag-0 model, ADR-0089) or
VLAN-Aware Bundle (this ADR). Both modes coexist; the Tag-0 path is unchanged
and stays the default.

### 2. Ethernet-Tag-scoped route semantics *(proposed)*

In bundle mode, Type 2 (MAC / MAC+IP), Type 3 (IMET), and Type 1 (EAD-per-EVI)
carry a **non-zero Ethernet Tag = VLAN ID**; import/export, RT scoping, and the
EVPN RIB key become per-`(EVI, Ethernet Tag)`. Type 5 / L3 semantics per
RFC 9136 are revisited for the bundle case. The codec field exists; the change
is making the Tag load-bearing in the key and the dataplane mapping.

### 3. Linux dataplane mapping *(open)*

`(EVI, Ethernet Tag)` ⇒ `(bridge VLAN, VXLAN VNI)` on a VLAN-aware bridge whose
VXLAN member(s) carry per-VLAN VNI bindings. Reconcile remote MAC / MAC+IP into
the correct VLAN-scoped FDB row (extends the `NDA_VLAN` work from ADR-0089).

### 4. Multi-homing is Ethernet-Tag-scoped *(open)*

ADR-0088 already noted single-active / all-active multi-homing depend on
Ethernet-Tag scoping. EAD-per-EVI, DF election, and aliasing must be evaluated
per `(ESI, EVI, Ethernet Tag)` in bundle mode. This is the subtlest part and
needs its own decisions (possibly a follow-on ADR).

## Open questions

- Config schema for a bundle EVI and its VLAN→VNI map.
- The EVPN RIB key change (Ethernet Tag becomes significant) and its blast
  radius across import, export, event history, API, and Add-Path safety.
- Migration / coexistence story from a Tag-0 deployment.
- Whether bundle-mode multi-homing is in-scope here or a separate ADR.

## Consequences

- Closes the "true VLAN-aware bridge / non-zero Ethernet Tag" parity gap with
  FRR/NVIDIA VLAN-aware fabrics.
- Largest of the EVPN tail items: touches `crates/wire` semantics,
  `crates/evpn` keying/import/export, and `crates/evpn-linux` mapping.
- Likely spans multiple slices; the multi-homing scoping (Decision 4) may spin
  out into its own ADR.

## Dependencies and relationships

- **Builds on:** ADR-0089 (VLAN-Based foundation, `NDA_VLAN` FDB), and the
  existing Ethernet Tag wire field.
- **Independent of:** ADR-0091 (managed netdev) and ADR-0093 (MAC+IP
  correlation), though managed netdev would create the VLAN-aware bridge
  topology this consumes.

## Rejected Alternatives

- **Assume VLAN == VNI on a `vlan_filtering=1` bridge** — rejected in ADR-0088;
  forces the daemon to guess the EVI/Tag mapping.
- **Reuse the Tag-0 key and ignore the Ethernet Tag** — cannot express multiple
  VLANs in one EVI; defeats the bundle model.

## Test Obligations

- Wire round-trip for non-zero Ethernet Tag on Type 1/2/3/5.
- Per-`(EVI, Tag)` import/export isolation (two VLANs in one EVI do not bleed).
- Real-kernel VLAN-aware-bundle FDB programming; cross-vendor receipt vs FRR
  VLAN-aware bundle.
- Multi-homing scoping proofs (when in-scope).
