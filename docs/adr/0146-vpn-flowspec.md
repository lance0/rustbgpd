# ADR-0146: IPv4 VPN FlowSpec origination (AFI 1 / SAFI 134)

**Status:** Accepted (2026-11-03); implementation follows the slices below.
**Date:** 2026-11-03
**Update (2026-11-08):** v0.82.0 is the release floor named in the
[API reference](../reference/api.md#vpn-flowspec-controller-api); it carries
IPv4 and IPv6 VPN FlowSpec origination. The decision text below is unchanged.
**Amends:** The "No VPN FlowSpec (SAFI 134)" decision in
[ADR-0035](0035-flowspec.md), for local origination only. ADR-0035's other
decisions, [ADR-0135](0135-flowspec-feasibility.md),
[ADR-0139](0139-flowspec-controller-contract.md),
[ADR-0141](0141-injection-owner-lease.md),
[ADR-0143](0143-flowspec-direct-ip-actions.md) and
[ADR-0144](0144-guarded-flowspec-mutations.md) remain in force.

## Context

An operator runs a mitigation controller that sends FlowSpec rules into a VRF
with GoBGP: a GoBGP VRF named `TRANSIT` with RD `44407:40` and import/export
RT `44407:777`, and both `ipv4-flowspec` and `l3vpn-ipv4-flowspec` enabled
toward a router. They asked whether rustbgpd can take GoBGP's place.

ADR-0035 excluded SAFI 134 because rustbgpd has no VRF infrastructure. That
reason applies to *receiving* VPN FlowSpec into a VRF and enforcing it. It
does not apply to a controller that only *originates* VPN FlowSpec to a PE,
which owns the VRF and the dataplane.

### The standard

[RFC 8955 §8](https://www.rfc-editor.org/rfc/rfc8955.html#section-8) defines
AFI 1 / SAFI 134. Its NLRI is the §4.1 length (one octet below 240, otherwise
`0xfnnn`), an 8-octet Route Distinguisher, and the §4.2 component list. The
length covers the RD, so a rule's components are limited to 4087 octets.
Propagation into VRFs is controlled by Route Target extended communities
matched against VRF import policy, as in
[RFC 4364](https://www.rfc-editor.org/rfc/rfc4364.html). A rule applies only to
traffic in the VRFs that import it; by default, traffic that a PE receives from
the MPLS core is not filtered. §6 validates SAFI 134 against SAFI 128 routes,
not the default unicast table. §7 actions are the same as for SAFI 133.

### What receivers do

- **GoBGP** has two ways to originate SAFI 134. You can add a path to the global
  RIB with an explicit `rd` and optional `rt` (`gobgp global rib add -a
  ipv4-l3vpn-flowspec rd ... rt ... match ... then ...`). Or you can add a path
  to a VRF, which converts it to SAFI 134 with the VRF's RD and export RTs. A
  neighbor that is *bound* to a VRF gets the route converted back to SAFI 133
  with its RTs removed
  ([`server.go`](https://github.com/osrg/gobgp/blob/v4.11.0/pkg/server/server.go),
  [`path.go`](https://github.com/osrg/gobgp/blob/v4.11.0/internal/pkg/table/path.go)).
  Releases before v4.11.0 get the two-octet FlowSpec length wrong. The
  decoder does not mask the `0xf` nibble, and the encoder switches to the
  two-octet form one octet early, then writes it over the payload. Rules whose
  payload, including the RD, is 239 octets or more are therefore not exchanged
  correctly. v4.11.0 masks and sets the length as §4.1 requires.
- **IOS XR** enables `vpnv4 flowspec` under BGP. Each VRF has an `ipv4
  flowspec` address family whose import RTs select the rules it takes. `show
  bgp vpnv4 flowspec vrf <name>` and `show flowspec vrf <name>` verify the result
  ([Cisco: BGP FlowSpec VRF to VRF](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xr-software/223122-configure-bgp-flowspec-vrf-to-vrf.html)).
- **Junos** carries VPN flow routes with `family inet-vpn flow` in the master
  instance. Its documentation states that VPN flow routes are not validated
  automatically
  ([`flow`](https://www.juniper.net/documentation/en_US/junos12.3/topics/reference/configuration-statement/flow-edit-protocols-bgp.html)).
- **FRR** has no SAFI 134 at all: its IANA SAFI table ends at 133, and its
  FlowSpec guide says FlowSpec can be configured only on the default VRF
  ([`flowspec.rst`](https://github.com/FRRouting/frr/blob/master/doc/user/flowspec.rst)).
  An FRR peer therefore never negotiates SAFI 134 and cannot be the VPN target.

### What rustbgpd has

- FlowSpec SAFI 133 is keyed by `FlowSpecKey { afi, rule }`.
- Local intent is held in the Adj-RIB-In of the synthetic peer `0.0.0.0`. That
  intent is managed through the inventoried controller RPCs, leases and guarded
  mutations.
- VPN unicast (SAFI 128) is reflected but never originated.
- RD text parsing and lossless rendering already exist (`parse_rd`,
  `format_rd`), and so does Route Target text parsing (`parse_route_target`,
  plus the asdot+ form in `FlowSpecRedirect`).
- On every FlowSpec-key path, `InjectionService` refuses an unknown
  `afi_safi` with `INVALID_ARGUMENT` before any mutation
  (`parse_flowspec_afi`), and so does `ListFlowSpecRoutes`
  (`validate_flowspec_afi_safi`).

## Decision summary

| # | Decision | Change after v1 |
|---|----------|-----------------|
| 1 | Explicit wire scope in the API: `afi_safi` + RD identify the rule; RTs are attributes. No VRF objects in the daemon. | Costly |
| 2 | Identity is `(family, RD, components)`. RD types 0, 1, 2 only; RTs use the existing RT grammar. An RT-only change follows the existing upsert and guarded rules for the key; an RD change is a different rule. The RD scopes keys and revisions, not lease deadlines. | Costly |
| 3 | Additive API: one new `AddressFamily` value plus `rd`/`route_targets` fields on the existing FlowSpec messages. `UNSPECIFIED` keeps meaning SAFI 133 only. Support is published as a release floor plus a read-only probe. | Costly |
| 4 | Names: config `l3vpn_ipv4_flowspec`, rpol `vpnv4-flowspec`, metric family `l3vpn_ipv4_flowspec`, enum `ADDRESS_FAMILY_L3VPN_IPV4_FLOWSPEC = 13`. | Costly |
| 5 | Originate only. Received SAFI 134 is decoded, then discarded and counted: never stored, reflected or validated. No RT-Constrain gating. | Cheap (additive) |
| 6 | Per-neighbor family enablement, no new config objects; a published example equivalent to `TRANSIT`. | Cheap |
| 7 | Six ordered slices, with GoBGP interop last; outside the v1 inventory until that evidence exists. | — |

The first four decisions fix names, numbers and meanings that controllers will
persist. They are listed first because they cannot be changed after v1 without
a deprecation. The rest can be extended additively in 1.x.

## Decisions that are costly to change after v1

### 1. Scope is explicit wire identity, not a named VRF

A VPN rule is named by its wire identity: the family, the RD and the
components. Its RTs are path attributes supplied with each add. The daemon
stores no VRF names, VRF tables or RD/RT bindings, and creates no kernel VRF.

A named VRF binding (`[[vrfs]] name/rd/import/export`, with `vrf = "TRANSIT"`
in requests) was rejected for this slice:

- **Rename and edit.** A daemon-side name would need rules for renaming,
  reloads that change a VRF's RD while it holds live rules, and how to clean
  them up. With explicit identity the key cannot be moved by a config edit, so
  a delete never reaches a different VPN. The controller's persisted record
  already carries the RD.
- **Mutation surface.** It adds a config object, reload and transaction
  semantics, and a resolution step on every mutation, for no wire behavior an
  explicit RD lacks.
- **Precedent.** GoBGP's global-RIB form (`rd`/`rt` on the path) is the same
  model. A VRF is only a source of defaults for it.

A later version can add a named binding as configuration that *resolves at
admission* to `(rd, route_targets)`. It must never be stored as the key.

### 2. Identity, RD and RT encodings

**Identity.** The rule key is `(family, rd, components)`. Global SAFI 133
keys have no RD; SAFI 134 keys always have one. The same components can
exist in global scope and in any number of RDs at once. Each key is added,
replaced, fenced by its own admission revision and deleted on its own.

The RD isolates rule identity, not lease deadlines. Under ADR-0141, one owner
holds one lease, and its deadline covers every key that owner holds across
RDs and families. When one owner's lease expires, all of its keys are
withdrawn in one batch, whatever their RDs. A controller that needs
independent deadlines per VPN uses a separate owner per VPN.

**RD.** RFC 4364 §4.2 Types 0, 1 and 2, in the text the API already
accepts. The structured forms are `asn16:u32`, `a.b.c.d:u16` and `asn32:u16`,
and `0x` plus 16 hexadecimal digits gives the raw form. Read-back uses the
existing lossless rendering, so a small-ASN Type 2 RD reads as raw hex and
re-injects unchanged. Other RD types return `INVALID_ARGUMENT` for origination.
On receive, the wire codec keeps them as raw bytes, as `RouteDistinguisher`
already does.

**RT.** At least one Route Target is required. It can be typed in
`route_targets` or raw in `extended_communities`. A VPN rule with no RT cannot be
imported by any VRF, so it is refused (`INVALID_ARGUMENT`) rather than
silently advertised. Typed RTs use the `FlowSpecRedirect.route_target` grammar:

| Text | Encoding |
|------|----------|
| `ASN:value`, ASN up to 65535, 32-bit value | type `0x00`, sub-type `0x02` |
| `a.b.c.d:value`, 16-bit value | type `0x01`, sub-type `0x02` |
| `ASN:value`, ASN above 65535, 16-bit value | type `0x02`, sub-type `0x02` |
| `high.low:value` (RFC 5396 asdot+), 16-bit value | type `0x02`, sub-type `0x02` |

Read-back renders a 4-octet-AS RT whose ASN fits in 16 bits as `0.ASN:value`,
so it re-injects with the same encoding. A typed RT that is repeated, or
also supplied raw, returns `INVALID_ARGUMENT`, following ADR-0143's rule for
typed and raw ambiguity.

Read-back shows each RT twice: typed in `route_targets` and raw in
`extended_communities`. A controller that re-injects a read-back row must use
one form for the RTs: either the typed `route_targets` with those communities
removed from the raw list, or the raw list with `route_targets` left empty.
Copying both lists is a deliberate duplicate and fails validation.

**RT versus redirect.** A scope RT (sub-type `0x02`) controls VRF import.
The RFC 8955 §7.4 / RFC 7674 redirect-to-VRF action (types `0x80`–`0x82`,
sub-type `0x08`) stays an action in `actions` and is never counted as a scope
RT. The existing EVPN `parse_route_target` grammar lacks the asdot+ form, so
the FlowSpec RT parser is shared with the redirect parser, not the EVPN one.

**Changes.**

- **RT-only change, plain or leased.** The same key with different RTs is the
  existing upsert path. A plain add, or a leased add by the owner that holds
  the key, returns `REPLACED` and creates no stale duplicate. While export
  policy still permits the rule toward a peer, that peer gets one UPDATE whose
  attributes implicitly replace the old ones, with no withdrawal. An RT change
  can also make the rule ineligible: an export policy can match on RTs, for
  example. A peer that was sent the rule before but is no longer eligible gets
  a withdrawal.
- **RT-only change, guarded.** Guarded rules keep ADR-0144 §3. A changed
  payload under the held revision is `REVISION_MISMATCH`, so the controller
  deletes the old revision and adds the new RTs under a new revision. Between
  those two steps, the rule is withdrawn.
- **RD change.** A different RD is a different key. The controller adds the
  new identity and deletes the old one. The daemon does not infer a move, so a
  partial failure leaves two explicit keys rather than a hidden one.

### 3. API shape

All changes are additive. They use the next free numbers at the time of
writing; the implementing change rechecks them.

| Message | New field |
|---------|-----------|
| `AddressFamily` | `ADDRESS_FAMILY_L3VPN_IPV4_FLOWSPEC = 13` |
| `AddFlowSpecRequest` (also wrapped by the leased and guarded adds) | `string rd = 7`, `repeated string route_targets = 8` |
| `DeleteFlowSpecRequest` | `string rd = 6` |
| `DeleteGuardedFlowSpecRequest` | `string rd = 5` |
| `LeasedFlowSpecKey` | `string rd = 3` |
| `ListFlowSpecExportDispositionsRequest` | `string rd = 6` |
| `FlowSpecRouteEntry` | `string rd = 13`, `repeated string route_targets = 14` |

No new RPCs are needed. The existing add, delete, leased, guarded, lease
listing, export-disposition and list RPCs cover the scoped lifecycle.

**Validation.** Every check below runs before any mutation, and a failure
leaves the RIB, the lease table and the wire unchanged:

- The VPN family requires a valid `rd`. Any other family with a non-empty `rd`
  or `route_targets` returns `INVALID_ARGUMENT`.
- A VPN add requires at least one RT. Components use the IPv4 grammar, so
  type 13 is rejected. The encoded rule, including the 8-octet RD, must fit
  in 4095 octets.
- Actions are the IPv4 FlowSpec set; none is added or removed for VPN.
- Raw RTs stay legal on global rules, as they are today. Typed
  `route_targets` on a global rule is refused, so a controller cannot attach
  RTs to a global rule and treat it as VPN support.

**Reads.**

- **Unscoped listing.** `afi_safi = UNSPECIFIED` in `ListFlowSpecRoutes` keeps
  meaning "IPv4 and IPv6 FlowSpec (SAFI 133)" in every view: selected, local
  intent, received and advertised. VPN rows are returned only to an explicit
  `ADDRESS_FAMILY_L3VPN_IPV4_FLOWSPEC`. Rows carry `rd` and typed
  `route_targets`, and RTs stay in the raw `extended_communities` too.
  `route_targets` is populated only on VPN rows.
- **Lease listing.** `ListLeasedKeys` orders FlowSpec keys by family, then RD,
  then rule. Its page cursor encodes the SAFI and the RD with the rule, so a
  walk resumes at the exact scoped key. It returns `rd` for VPN keys. VPN keys
  count against the existing per-owner cap of 16,384 keys and share the
  owner's single lease.
- **Export dispositions.** `ListFlowSpecExportDispositions` is keyed by
  `(afi_safi, rd, components)`. A peer that did not negotiate (1, 134) reads
  `WITHHELD` `family_not_negotiated`, the existing reason. So a missing
  negotiation shows as non-export, not as success.

**Old clients and old daemons.**

- An old client never sends value 13, and `UNSPECIFIED` excludes VPN rows,
  so its reads and writes are unchanged.
- An old client might echo a VPN key from `ListLeasedKeys` without `rd`
  because it does not know the field. That request has the VPN family and no
  RD, so it is refused. It cannot delete a different scope.
- An older daemon refuses every request carrying value 13 with
  `INVALID_ARGUMENT` before mutation. Source inspection at the time of writing
  confirmed this for every FlowSpec-key path: the shared add builder (used by
  the plain, leased and guarded adds), `DeleteFlowSpec`,
  `DeleteGuardedFlowSpec`, `ListFlowSpecExportDispositions` and
  `ListFlowSpecRoutes`. The implementation pins it at runtime with the existing
  rollback qualification against the previous release.
- A new client must never send `rd` with a SAFI 133 family. An older daemon
  would drop the field and act on the global rule. A new daemon refuses it.
- A controller never retries a refused VPN request as a global one.

**Capability floor.** There is no new capability RPC or feature vocabulary.
Support is published in two ways:

1. **Release floor.** The first release that carries the feature is stated
   in the API reference and changelog, and `HealthResponse.daemon_version`
   reports it.
2. **Runtime probe.** `ListFlowSpecRoutes(afi_safi =
   L3VPN_IPV4_FLOWSPEC, received_peer_address = "0.0.0.0")` is read-only. A
   supporting daemon answers with `received_view = true`; an older one answers
   `INVALID_ARGUMENT`. The probe exercises the scoped surface itself, not an
   unrelated RPC.

**v1 classification.** The new enum value and fields start outside the v1
inventory: they go in the unstable or excluded lists, so the stable digests do
not change. They are promoted by a later amendment once qualification exists,
as ADR-0144 was. Two meanings are pinned in the maintained contract
immediately, because they protect today's controllers even before VPN rows
exist:

- `UNSPECIFIED` selects SAFI 133 only.
- A FlowSpec-key request whose family needs an RD is refused without one.

### 4. Names

| Surface | Name |
|---------|------|
| Config `families` / `required_families` | `l3vpn_ipv4_flowspec` (matches `l3vpn_ipv4_unicast`; GoBGP: `l3vpn-ipv4-flowspec`) |
| rpol `route.family` | `vpnv4-flowspec` (matches `vpnv4`, `ipv4-flowspec`) |
| Metric `family` label | `l3vpn_ipv4_flowspec` |
| Proto | `ADDRESS_FAMILY_L3VPN_IPV4_FLOWSPEC = 13` |
| Wire | `Safi::FlowSpecVpn = 134` (`Safi` is `#[non_exhaustive]`) |

The existing `ipv4-flowspec` rpol value keeps matching SAFI 133 only. An
existing export policy that denies `ipv4-flowspec` therefore does not deny VPN
rules. The configuration and policy references must say so where the family
is enabled.

IPv6 VPN FlowSpec (AFI 2 / SAFI 134) gets no name, enum value or decode path
in this slice. It stays an unsupported family.

## Decisions that can change later

### 5. Receive, reflection, validation and RT-Constrain

**Originate only.** The daemon has no VRF tables against which to apply §6,
and the controller use case needs no receive path. Received (1, 134) is
handled as follows:

- **Decode.** NLRIs are decoded fully, so framing and malformed-input
  handling are exact. A malformed SAFI 134 NLRI takes the existing SAFI 133
  malformed-NLRI path.
- **Discard.** NLRIs are then discarded before Adj-RIB-In and counted in
  `bgp_vpn_flowspec_nlri_discarded_total{peer}`, with a `debug` log line. They
  are never stored, selected, reflected or validated.
- **End-of-RIB.** A peer's End-of-RIB for (1, 134) is accepted and ignored.
- **Route refresh.** A peer's ROUTE-REFRESH for (1, 134) replays the
  Adj-RIB-Out. The daemon never asks a peer to refresh (1, 134); an inbound
  soft reset of that family has nothing to replay.
- **Reads.** The received view of a remote peer for this family is empty
  with `received_view = true`. The discard counter explains why.

Discarding is the same as an import policy that denies everything, which BGP
permits. Storing and reflecting received rules later is additive, with no API
change.

**Feasibility validation.** `[flowspec] validation = "rfc9117"` keeps
covering SAFI 133 only, as ADR-0135 states. Local VPN rules report the same
local status as local SAFI 133 rules. The validation dependency index skips
scoped keys as defense in depth; a test pins that a VPN rule with no covering
unicast route is still advertised in `rfc9117` mode. Nothing in SAFI 134 is
ever checked against the default unicast table.

**RT-Constrain.** (1, 134) is not added to the RFC 4684 outbound gate or its
End-of-RIB hold. Every peer that negotiated the family receives the rule,
subject to export policy, and the PE's VRF import filters it. Three reasons:

- RFC 4684 §6 says "should", not "must".
- Controller-to-PE fan-out is small.
- The gate would need membership-change re-evaluation of the FlowSpec
  Adj-RIB-Out.

A test pins this, so a later change to gate SAFI 134 is deliberate. Gating
belongs with reflection, where RT-Constrain does its work.

**Other paths.**

- **Add-Path.** Never advertised for (1, 134); the existing family filter
  already omits FlowSpec, and a test pins it.
- **GR and LLGR.** (1, 134) is treated like (1, 133) in capability
  construction from slice 2, which adds the family's stale-retention
  lifecycle; slice 1 leaves it out of the GR and LLGR families, because it
  stores nothing to retain. It is not guaranteed, as for all FlowSpec.
  ADR-0144's residual risk applies: a peer with GR or LLGR for the family
  keeps a rule after the daemon crashes, until its stale timers run out.
- **Export policy.** Ordinary export policy, `NO_ADVERTISE`/`NO_EXPORT`, and
  ignoring `set_next_hop` all apply unchanged. Export policy can strip a
  rule's RTs; the documentation names that as the operator's choice, not
  something the daemon prevents.
- **BMP and MRT.** No VPN FlowSpec output in this slice.

**Enforcement.** Following §8, a PE applies the rule only to traffic in VRFs
that import its RTs. That is normally traffic arriving on the VRF's attachment
circuits, not traffic arriving from the MPLS core. A rule meant for upstream
transit links in a VRF fits that model. The daemon makes no installation or
forwarding claim (ADR-0139, ADR-0143).

### 6. Configuration and the `TRANSIT` example

Enabling the family is per neighbor, through the existing `families` (and
optionally `required_families`) lists. No default includes it. There is:

- no VRF table and no RD/RT config;
- no per-family max-prefix knob, because received rules are discarded and
  consume nothing.

Adding or removing the family follows the existing reload rules for a
`families` change.

Equivalent of the GoBGP `TRANSIT` setup:

```toml
[global]
asn = 44407
router_id = "192.0.2.1"

[[neighbors]]
address = "192.0.2.21"
remote_asn = 44407
description = "pe-transit"
families = ["ipv4_flowspec", "l3vpn_ipv4_flowspec"]
# Optional: refuse the session if the PE does not negotiate VPN FlowSpec.
required_families = ["l3vpn_ipv4_flowspec"]
```

The controller supplies the VRF's identity with each rule. It uses the RD
`44407:40` and the export RT `44407:777`. The import half of GoBGP's "both"
RT has no meaning for an originator:

```json
{
  "afiSafi": "ADDRESS_FAMILY_L3VPN_IPV4_FLOWSPEC",
  "rd": "44407:40",
  "routeTargets": ["44407:777"],
  "components": [
    {"type": 1, "prefix": "203.0.113.10/32"},
    {"type": 3, "value": "=17"}
  ],
  "actions": [{"trafficRate": {"rate": 0}}]
}
```

The same body goes to `AddFlowSpec`. It goes as `rule` to `AddLeasedFlowSpec`
or `AddGuardedFlowSpec`. Delete and list use the same
`(afi_safi, rd, components)`.

## Implementation plan

Each slice merges on its own, keeps global FlowSpec unchanged, and adds a
changelog fragment where users can see the change. Sizes are rough line
counts, tests included.

| Slice | Contents | Depends on | Size |
|-------|----------|------------|------|
| 1 | Wire codec, negotiation, receive-and-discard | — | M, ~900 |
| 2 | Scoped RIB identity and distribution | 1 | L, ~2,000 |
| 3 | Policy and telemetry | 2 | S, ~400 |
| 4 | Controller API | 2 (3 in parallel) | M–L, ~1,500 |
| 5 | Operator surface | 4 | M, ~700, mostly docs |
| 6 | Qualification | 4 | M |

### Slice 1: wire codec, negotiation and receive-and-discard

**Files:**

- `crates/wire/src/capability.rs`: `Safi::FlowSpecVpn` and the
  `CONFIGURED_FAMILIES` row.
- `crates/wire/src/flowspec.rs`: an RD-plus-rule NLRI type, its decode and
  encode, and the 4095-octet bound including the RD.
- `crates/wire/src/attribute.rs`: the family classification;
  `MP_REACH`/`MP_UNREACH` fields; NH-Len 0 on both directions.
- `crates/wire/src/lib.rs`: re-exports.
- `crates/wire/tests/flowspec_vpn.rs`.
- The `decode_flowspec` fuzz target and its seeds.
- `crates/transport/src/session/inbound.rs`: decode, discard and count.
- `crates/telemetry/src/metrics.rs`.
- The config family label.
- `docs/reference/operations.md`: the metric row.

**Crate release.** `MpReachNlri` and `MpUnreachNlri` gain public fields,
which is a breaking change for `rustbgpd-wire` 0.x. The published crates
move together:

- `rustbgpd-wire` 0.28;
- `rustbgpd-fsm` 0.15;
- `rustbgpd-rpki` 0.10.

FSM and RPKI re-export wire types, so a wire compatibility-line move is a
minor bump for each of them (see the
[embedding guide](../reference/embedding.md#4-which-crate-to-publish-next-and-why)).
They are published in the existing order: wire, then fsm, then rpki. Each
crate's changelog, the README usage snippets, the embedding guide examples
and the root pins follow the published-crate release procedure.

**Tests:**

- Golden vectors for RD Types 0, 1 and 2, plus a raw unknown RD type on
  decode.
- One-octet and extended lengths at the RD-inclusive boundary. A 239-octet
  payload uses the one-octet length `0xef`, and a 240-octet payload uses
  `0xf0f0`. One case crosses 240 octets only because of the RD. The 4095 bound
  includes the RD.
- Malformed input: a length below 8; an RD with no components; truncated input;
  a length that overruns. A malformed second NLRI must not misframe the first.
- Non-zero NH-Len rejected. An `MP_UNREACH` withdrawal, and End-of-RIB as an
  empty `MP_UNREACH`.
- The OPEN advertises (1, 134) only when configured, never with Add-Path.
- Received rules are counted and never reach the RIB. (2, 134) stays
  unsupported. A proptest round trip.

### Slice 2: scoped RIB identity and distribution

This slice gets an independent maximum-effort review before it is pushed.

**Files:**

- `crates/rib/src/route.rs`: `rd: Option<RouteDistinguisher>` on
  `FlowSpecRoute`, `FlowSpecKey` and `FlowSpecRouteKey`, and a `family()`
  that derives SAFI 133 or 134.
- In `crates/rib/src`: `adj_rib_in.rs`, `loc_rib.rs`, `adj_rib_out.rs`,
  `update.rs` and `injection_lease.rs`.
- In `crates/rib/src/manager/`: `distribution/flowspec.rs`,
  `route_refresh.rs`, `graceful_restart.rs`, `selection_deferral.rs`,
  `peer_lifecycle.rs`, `lease_expiry.rs`, `queries.rs` and
  `flowspec_validation.rs`.
- In `crates/transport/src/session/`: `outbound.rs`, `export.rs`,
  `refresh_accounting.rs` and `family_limits.rs`.

**Sweep.** The compiler finds struct literals, but not the roughly 70
`(afi, Safi::FlowSpec)` tuples. The PR lists every `Safi::FlowSpec` site and
what happened to it.

**Tests:**

- **Coexistence.** Identical components in global scope, RD A and RD B
  coexist. Replace, delete and a guarded revision mismatch on one key never
  touch the others. Rules held by different owners in different RDs expire
  independently. When a single owner's lease expires, all of that owner's
  keys in every RD are withdrawn together, as ADR-0141 specifies.
- **RT changes.**
  - A plain or leased RT-only replace emits one announcement and no
    withdrawal toward a peer that stays eligible, and the advertised view
    shows only the new RTs.
  - A replace that makes the rule ineligible under export policy withdraws
    it from the peers that had it.
  - A guarded RT change with the same revision is `REVISION_MISMATCH`. Delete
    and re-add under a new revision succeeds.
- **RD change.** An RD change leaves the old key until it is deleted.
- **Negotiation.** A peer without (1, 134) receives nothing, and End-of-RIB is
  sent per negotiated family. No UPDATE mixes SAFI 133 and 134.
- **Refresh and recovery.** ROUTE-REFRESH for (1, 134) replays VPN rules only.
  Reconnect re-advertises. Local VPN rules are eligible during selection
  deferral, as local SAFI 133 rules are.
- **Validation.** `rfc9117` never indexes a VPN key.
- **Bounded work.** An expiry batch across many RDs stays within the existing
  paced-cleanup bounds and readiness checkpoints.

### Slice 3: policy and telemetry

**Files:**

- The rpol family vocabulary.
- `crates/rib/src/manager/helpers.rs` for family labels, and the Loc-RIB and
  Adj-RIB-In metric families in `crates/telemetry`.
- `docs/reference/rpol-language.md` and `docs/reference/operations.md`.

**Tests:**

- `vpnv4-flowspec` matches and denies VPN rules, and `ipv4-flowspec` does not
  match them.
- Export policy can add and strip RTs.
- `NO_ADVERTISE` is honored.
- The `0.0.0.0` series is reported per family.

### Slice 4: controller API

**Files:**

- `proto/rustbgpd.proto`.
- `crates/api/src/injection_service.rs`, `rib_service.rs` and
  `route_distinguisher.rs`; the RT parser is shared with `parse_redirect`.
- In `docs/reference/`: `api.md`, `v1-stable-surface.json` (outside-v1 lists),
  `v1-stable-contract.md` (the two pinned meanings) and
  `grpc-method-inventory.md`.

**Tests:**

- **Round trip.** Each RPC round-trips the scope: add, leased add, guarded
  add and delete, delete, list in each view, `ListLeasedKeys` and export
  dispositions.
- **Refusals.** The matrix covers:
  - a missing RD, an RD on a global rule, and an unknown RD type;
  - typed RTs on a global rule, no RT, and a duplicate or typed-plus-raw RT;
  - components over 4087 octets, and a type 13 component.
- **Old clients.** `UNSPECIFIED` excludes VPN rows in every view. An old
  client's echoed VPN key without `rd` is refused.
- **Re-injection.** Re-injecting a read-back row with its typed RTs, or with
  only their raw equivalents, is `UNCHANGED`. Copying both forms is
  `INVALID_ARGUMENT`. The API reference documents the rule.
- **Guarded and leased.** Admission revisions are per scoped key. One owner's
  lease spans its keys in every RD and family; separate owners give separate
  deadlines.
- **Lease pagination.** A `ListLeasedKeys` walk whose page boundary falls
  between identical components in global scope, RD A and RD B resumes without
  skipping or repeating a key. The cursor carries the SAFI and the RD.
- **Export dispositions.** `family_not_negotiated` is reported per peer.
- **Old daemons.** Each VPN path gets a non-OK reply with no state change
  against the previous release, using the existing rollback qualification
  script.
- Stable-surface and protobuf compatibility checks, and
  `cargo test --workspace`.

### Slice 5: operator surface

**Files:**

- `crates/cli/src/commands/flowspec.rs` and the CLI argument definitions:
  `--rd` and `--route-target` on add, delete and list, plus rendering.
- `examples/vpn-flowspec-controller/config.toml`, the `TRANSIT` equivalent
  above.
- Under `docs/`:
  - `reference/configuration.md`: the families list and the policy caveat;
  - `explanation/gobgp-parity.md`: the VPN FlowSpec row, which becomes
    "IPv4 origination only";
  - `reference/rfc-notes.md` and `reference/stability.md`.

**Tests:** CLI parse and render, and a strict check of the example config.

### Slice 6: qualification

**Files:**

- A containerlab leg pinned to GoBGP v4.11.0. Earlier releases get the
  two-octet length wrong.
- Its driver script.
- A receipt under `docs/artifacts/interop/`.

**GoBGP checks:**

- The OPEN negotiates (1, 134).
- GoBGP's `ipv4-l3vpn-flowspec` RIB shows RD `44407:40`, RT `44407:777` and
  the discard action.
- **Length boundary.** Rules with RD-inclusive payloads of 239 and 240
  octets arrive intact, with the one-octet and two-octet lengths. Releases
  before v4.11.0 mishandle both.
- **Scope.** One VPN rule and a global rule with identical components
  coexist. A second RD acts as a negative control: its rule and its deletion
  never affect the first RD's rule.
- **RT changes.** A plain RT-only replace arrives as one replacement. A
  guarded RT change goes through delete and re-add under a new revision.
- **Negotiation.** A peer without the family receives nothing and reads
  `family_not_negotiated`.
- **Restart.** After a daemon restart, re-injection restores the rules.
- **Capture.** A packet capture shows AFI 1 / SAFI 134 with the expected RD
  and RT, and no SAFI 133 leak of a VPN rule.

**IOS XR receipt.** The router receipt uses IOS XR, the requesting
operator's platform. The sequence is an ASR 9901 proof of concept, then ASR
9906 edge routers, then later the Cisco 8000 series (8201).

Each step runs on one VRF, with a second RD as the negative control. The
receipt records the router model and software release. It must show, for each
action:

- the rule received in the VPN table;
- the rule installed only in the intended VRF;
- the effect on traffic;
- withdrawal restoring traffic.

The actions are:

- discard (traffic-rate 0);
- rate limiting in bytes and in packets;
- DSCP marking;
- redirect-to-VRF;
- redirect-to-IP.

There are three cases besides the actions:

- **Negative controls.** A rule with the wrong RT, and an unrelated VRF.
- **Source-only match.** A rule whose only component is a source prefix
  (type 2), dropping traffic from remote addresses.
- **Validation.** RFC 8955 §6 rule (a), unchanged by RFC 9117, makes a rule
  without a destination prefix infeasible unless the receiver relaxes it by
  explicit configuration. §8 applies the same validation to VPN routes. The
  receipt records the XR validation setting for the controller session. It
  shows the source-only rule installed under that setting, or records the
  refusal. A refusal is the receiver's validation, not a rustbgpd defect.

Support claims rise only to the level each step proves. Cisco 8000 import of
SAFI 134 into a VRF, and its enforcement of each action, stay unverified until
router output from that platform exists. Junos and other receivers are not
targets of this slice.

**Release placement.** Slices 1–5 are feature work for the current v1 window.
Slice 6 and the v1 inventory amendment can follow. Until then the surface
ships outside v1, as ADR-0144's methods did before their amendment.

## Operator answers and remaining questions

The requesting operator answered the scoping questions:

| Question | Answer |
|----------|--------|
| Which router imports SAFI 134? | IOS XR only. The sequence is an ASR 9901 proof of concept, ASR 9906 edge routers, and later the Cisco 8000 series (8201). The FRR peer in the original sample cannot be the target, because FRR has no SAFI 134. |
| How are rules injected? | A controller using the scoped API: `AddFlowSpec`, or its leased and guarded variants, with an explicit RD and RTs. |
| Which actions? | All of them: discard, rate limiting in bytes and packets, marking, redirect-to-VRF and redirect-to-IP. A source-prefix-only match is required. |
| How many VRFs? | One VRF, with one RD. Qualification adds a second RD as a negative control; the API itself has no RD limit. |

These remain open, each with the default used until the answer changes it:

1. **Does the PE negotiate RT-Constrain with the controller?** *Default:* no
   gating of SAFI 134 (decision 5).
2. **Is Graceful Restart negotiated on the FlowSpec session?** *Default:*
   the neighbor's existing GR setting applies to the family. Disable it where
   a rule must not outlive the daemon (ADR-0144).
3. **Must rustbgpd also receive or reflect VPN FlowSpec?** *Default:* no.
   Received rules are discarded and counted.
4. **What is the XR FlowSpec validation setting for the controller session?**
   *Default:* the receipt records the setting in use. The source-only case
   shows whether that setting installs a rule without a destination prefix.

## Consequences

**What changes:**

- **Origination.** A controller can originate IPv4 VPN FlowSpec through the
  existing FlowSpec RPCs, and the daemon holds no VRF state. Keys and
  admission revisions are scoped by RD. Lease deadlines stay per owner across
  RDs and families, and guarded rules keep the delete-then-re-add rule for any
  payload change.
- **Compatibility.** Old clients and the inventoried global contract are
  unchanged. An older daemon refuses VPN requests before mutation.
- **Receive.** Received VPN FlowSpec is deliberately not supported. It is
  decoded so framing stays correct, then discarded and counted so the
  omission can be seen. Adding receive, reflection or RT-Constrain gating
  later is additive.
- **Crate releases.** `rustbgpd-wire` 0.28, `rustbgpd-fsm` 0.15 and
  `rustbgpd-rpki` 0.10 are released together.
- **Vocabularies.** The new family label, rpol value and metric label join
  closed vocabularies.

**What is not claimed:** this adds no VRF import, IPv6 VPN FlowSpec, Linux
dataplane enforcement, remote acceptance, installation or forwarding. Only the
slice 6 router receipts can support a claim about a specific router, and only
for the platform, release and action each one shows.
