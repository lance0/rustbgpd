# ADR-0052: EVPN VTEP Foundation — Local EVI/VNI Domain Model

**Status:** Accepted
**Date:** 2026-05-01

## Context

ADR-0050 deliberately narrowed Phase 1 EVPN scope to the route
reflector role — no local EVI/VRF/VNI state, no MAC learning, no
dataplane integration. That kept the surface small enough to validate
RFC 7432 reflection semantics against FRR end-to-end (gates 0–6,
shipped through v0.11.x).

`docs/evpn-enablement.md` Gate 7 (VTEP mode) is the natural follow-on:
rustbgpd running on a leaf with local EVIs, kernel FDB integration,
and Type 2/3/5 origination. Gate 7 is broad — netlink monitoring,
local MAC table, origination paths, anti-spoofing, MAC mobility
sequencing. Landing it in one slice would mean reviewing a kernel
integration bolted onto a domain model that hasn't been exercised yet.

This ADR records the decision to land Gate 7 as **two separable
slices**, with the durable state model first:

1. **Foundation (this ADR):** declarative
   `[[evpn_instances]]` config, runtime [`EvpnInstanceTable`], read-only
   gRPC visibility. No kernel work, no origination.
2. **Kernel reconciliation:** netlink FDB monitor, local MAC table,
   Type 2/3 origination, withdrawal-on-age.

Slice 1 lets every later phase consume a stable typed model instead
of bolting kernel state onto whatever shape the schema took. It also
lets ADR-0050's RR-only invariant ("no local EVI state") flip into
"local EVI state allowed, but the foundation slice itself does not yet
drive origination" without a second config-shape break.

## Decision

### Declarative model, not GoBGP-implicit

`GoBGP`'s EVPN surface has *no* declarative `[evpn_instances]` block —
operators add individual routes via `gobgp global rib add` and the
route attributes (RD, RT, VNI) carry all the state. That works for a
route reflector or transit AS but not for a VTEP, where the daemon
needs to know **which VNIs are local, where to source VXLAN encap
from, and which bridge ↔ VNI mappings count as "ours" before any
route exists**. FRR / Cumulus / SONiC all take the declarative path;
rustbgpd does too.

### New crate: `crates/evpn`

Sibling pattern to `crates/rpki` — a service-domain crate that the
daemon (`src/`) and the gRPC layer (`crates/api`) depend on. Not a
`crates/rib` submodule: rib is RIB tables and best-path; EVPN domain
config is upstream of route origination, and rib can stay
unaware of it until origination lands.

Three modules:

- `route_target.rs` — typed [`RouteTarget`] (RFC 4360 / RFC 5668)
  enum covering all three RT subtype encodings, with
  `FromStr` / `Display`. Models RTs as a domain enum rather than
  reusing the wire crate's opaque `ExtendedCommunity` 8-byte
  container so operator input either parses or rejects, never
  half-formed.
- `instance.rs` — [`EvpnInstanceId`] (validated 24-bit VNI),
  [`EvpnInstance`] (resolved per-EVI state), and
  [`EvpnInstanceTable`] (uniqueness-enforcing collection with
  parallel VNI and RD indexes).
- `lib.rs` — re-exports.

### Wire-side: `RouteDistinguisher::from_str` lives in `crates/wire`

The wire crate's existing `RouteDistinguisher` (8 bytes, RFC 4364
§4.2) had `Display` but no parser. Adding `FromStr` here keeps the
parsing alongside the type definition — independently useful for any
future caller that needs to round-trip RD strings without pulling in
the EVPN domain crate.

Disambiguation between RD types follows the FRR / Cisco / Junos
convention: `asn:val` → Type 0 if `asn ≤ 65535`, else Type 2;
`ipv4:val` → Type 1.

### Schema: `[[evpn_instances]]` blocks

Operator-facing TOML shape:

```toml
[[evpn_instances]]
vni = 100
rd = "10.0.0.10:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.10"
bridge = "br100"            # optional
advertise_svi_mac = false   # optional
```

Defaults to empty — RR-only deployments leave this list empty and
nothing in the daemon changes shape.

### Single bidirectional `route_targets` field

Most operators set import RTs equal to export RTs. The schema models
RTs as one bidirectional list to keep the common case ergonomic.
Splitting into separate `import_route_targets` / `export_route_targets`
is a non-breaking schema addition if a future use case requires it.

### Route-target type modeled as an enum, identity includes the variant

`RouteTarget::TwoOctetAs { 65000, 100 }` and a `RouteTarget` parsed
as a 4-octet AS form happen to share the same `(global, local)`
tuple but live at different RT subtypes on the wire and are *not*
the same RT. The enum makes that distinction part of identity, not
something downstream code has to track separately.

### Defer L3VNI / IP-VRF to a follow-on ADR

The brief covers the L2VNI shape — vlan/bridge-bound EVIs, Type 2
origination ergonomics. L3VNIs need an IP-VRF concept (per-VRF
routing, RouterMAC, RFC 9135 symmetric IRB). FRR ties L3VNI to a
`vrf <name>` stanza which rustbgpd does not have. Adding that here
would conflate two phases; it lands in Gate 9 territory, not Gate 7.

### gRPC surface: read-only `EvpnService.ListEvpnInstances`

One RPC, returning the resolved [`EvpnInstanceTable`] sorted by VNI.
No mutation in this slice — the daemon's instance table is built
once at startup from `Config::resolve_evpn_instances` and shared via
`Arc<EvpnInstanceTable>` across listeners.

Mutation was deliberately deferred out of this per-row surface. ADR-0063 later
superseded any `AddEvpnInstance` / `DeleteEvpnInstance` plan with the
full-model `EvpnService.ApplyEvpnRuntime` coordinator: callers submit a
candidate EVPN runtime model, the daemon reuses config validation, computes a
plan, converges the affected actors, and commits a new generation only after the
live shape succeeds.

### CLI: `rustbgpctl evpn instances`

Pure proto-wrapping of the gRPC surface. Mirrors the existing
`evpn list` route-listing command's output style.

## Boundaries — what `crates/evpn` is and isn't

The crate is the **local VTEP / EVPN domain model**, not "the place
where every EVPN-related thing lives." Three guardrails hold the
shape across phases:

### `crates/evpn` does *not* absorb existing EVPN machinery

EVPN code that lives elsewhere today stays where it is. Specifically
**not** moving into `crates/evpn`:

- Wire codec (`crates/wire/src/evpn.rs`) — `EvpnRoute`,
  `EvpnRouteKey`, RD/ESI/MAC/MPLS-label primitives, NLRI
  encode/decode, capability bytes. Protocol concepts, not local
  state.
- RIB state (`crates/rib`) — `EvpnRibRoute`, EVPN Loc-RIB,
  Adj-RIB-In/Out, best-path, reflection rules, stale handling. RR
  behavior is a RIB concern.
- Session glue (`crates/transport/src/session/`) — inbound
  `MP_REACH` consumption, outbound EVPN announcement grouping,
  capability checks. Knows peer state, negotiated families,
  next-hop context.
- Controller injection (`InjectionService.{Add,Delete}EvpnRoute`,
  `RibService.ListEvpnRoutes`) — controller-style route mutation
  on the RR/transit path. Stays under the existing services.

The load-bearing test of this invariant is the
`rr-evpn-fabric` example: it must continue to run with
`crates/evpn` essentially unused. RR-only deployments don't have
local EVIs and don't need the domain crate's surface.

### Domain types describe desired state, never program the kernel

`EvpnInstance` / `EvpnInstanceTable` express *intent*, not
behavior. No `inst.create_vxlan_device()`, no `table.program_fdb()`
methods. The Linux dataplane crate, `crates/evpn-linux`, owns kernel
observation, diff, and netlink/FDB programming. It consumes
`EvpnInstanceTable` as input — it never produces or mutates the
desired-state model.

This split has to land *before* much Linux logic is written. Once
kernel-side methods start hanging off `EvpnInstance`, the boundary
is gone, and the next contributor has to either accept the
conflation or tear it apart later.

### Dependency direction stays one-way

```
crates/wire ← crates/transport → crates/rib
                    │
                    ▼
              crates/evpn (local VTEP only)
                    │
                    ▼
            crates/evpn-linux  (dataplane)
```

`crates/evpn` may depend on `crates/wire` (already does, for
`RouteDistinguisher`). It must **not** depend on `crates/rib` or
`crates/transport`. The dataplane crate will depend on
`crates/evpn` and the OS, nothing else.

`crates/transport` and `crates/rib` may consume *local-VTEP*
services from `crates/evpn` once Type 2/3 origination lands —
e.g. "is there a local EVI for this VNI? what's its source
VTEP IP?" — but plain RR / route-reflection behavior must keep
working without taking that dependency. The clean test: building
the daemon with `[[evpn_instances]]` empty must not exercise any
new code paths that didn't exist pre-Phase-2.

### Future shape — local MAC ownership and mobility

Local-MAC tables (MAC → VNI + sequence number, peer-learned remote
MACs, mobility state per RFC 7432 §15) belong in `crates/evpn` as
**separate domain types**, not by overloading
`rustbgpd_wire::EvpnRoute`. Wire types describe what comes off the
wire; domain types describe what the local VTEP owns. Two
crossings: the wire-decode path lifts an inbound Type 2 into a
local domain MAC entry; the origination path lowers a local MAC
entry into an outbound `EvpnRoute`. Both crossings live at the
boundary between `crates/transport` and `crates/evpn`.

### `RouteTarget` placement

`RouteTarget` is in `crates/evpn` today because its only use is
config / domain RT lists. If it later becomes the canonical typed
representation of *any* RT extended community in the codebase
(policy match, controller injection, MRT export), the conversion
helpers between this domain enum and
`rustbgpd_wire::ExtendedCommunity` may belong closer to
`crates/wire`. Reassess at that point; do not preemptively move.

## Consequences

### Positive

- **Stable model anchors later work.** Type 2/3 origination,
  netlink reconciliation, MAC mobility — all consume the same
  typed [`EvpnInstance`]. Schema breaks across phases are confined
  to additive fields.
- **Validation surface today, behavior tomorrow.** Operators can
  write the leaf config and run `rustbgpd --check` /
  `rustbgpctl evpn instances` against it before any kernel
  integration ships. That's the same workflow they get with FRR's
  `vtysh` validation pass.
- **No regression for RR-only deployments.** Empty
  `[[evpn_instances]]` is the default; the route-reflector example
  TOML is unchanged. ADR-0050's invariants hold.
- **Wire crate gains a useful primitive.** `RouteDistinguisher::from_str`
  is independently useful — anything in the codebase that wants to
  round-trip RD strings (gRPC injection, MRT export, future BMP
  inspection tools) can use it without the EVPN domain crate.

### Negative

- **A field on the public schema with no behavior yet.**
  `advertise_svi_mac` parses today but doesn't drive Type 2
  origination until that path lands. Documented inline; the
  alternative — adding the field later — would force a schema
  break for every operator who wants to ramp the SVI flag at the
  same time the origination ships.
- **Two indexes maintained in lock-step.** `EvpnInstanceTable`
  carries both a VNI map and an RD map; insert is all-or-nothing.
  Cheap at expected sizes (dozens to hundreds of EVIs per leaf)
  and explicit in the type, but worth flagging.

### Neutral

- **VLAN-Aware Bundle service interface deferred.** RFC 7432 also
  defines a many-tags-per-EVI shape. The wire codec already round-
  trips Ethernet-Tag in every route type. ADR-0089 later supplied the
  VNI-per-broadcast-domain `bridge_vlan` attribution path, but true
  shared-VNI / non-zero Ethernet Tag service still needs a separate
  domain-model expansion.
- **No per-row persistence path.** Runtime mutation later landed through
  ADR-0063's full-model `ApplyEvpnRuntime` / SIGHUP convergence model rather
  than through per-row `AddEvpnInstance` / `DeleteEvpnInstance` RPCs.

## Follow-on architectural work

The Gate 7b (kernel-reconciliation) branch defined the dataplane boundary
**before** writing much Linux logic. ADR-0054 landed at the start of that branch
and covers:

- The `crates/evpn-linux` crate's surface — what it
  consumes from `crates/evpn`, what it observes from the kernel,
  what it returns up.
- The desired-vs-actual diff loop semantics (push, pull, or
  reconcile-on-event).
- How netlink failures surface back to the domain layer (does the
  domain crate know its intent failed to apply, or does only
  telemetry see it?).

That ADR is intentionally separate from this foundation record: the boundary
above kept the foundation slice from leaking kernel concerns, and ADR-0054 then
anchored the real `crates/evpn-linux` implementation.

## Cross-References

- ADR-0050 — EVPN Route Reflector (RFC 7432 Phase 1)
- ADR-0054 — EVPN Linux Dataplane Boundary
- `docs/evpn-enablement.md` Gate 7 — VTEP mode roadmap
- RFC 7432 §7 — EVPN routes and MAC-VRF identification
- RFC 7432 §15 — MAC mobility (referenced by future-shape section)
- RFC 4364 §4.2 — VPN-IPv4 / Route Distinguisher encodings
- RFC 4360 §4 / RFC 5668 §2 — Route Target extended communities
- RFC 8365 §5 — VXLAN VNI semantics
- RFC 9135 §6.1 — SVI MAC origination (referenced by `advertise_svi_mac`)
