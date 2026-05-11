# ADR-0058: EVPN Gate 9 — symmetric IRB, L3VNI, Type 5 dataplane

**Status:** Accepted; rollout slices 1–6 shipped on main
(PRs #66, #67, #72, #73, #74, #75); slices 7–8 pending
**Date:** 2026-05-10

## Context

Through Gate 8b (ADRs 0054–0057), rustbgpd is a fully bidirectional
L2 EVPN VTEP — it learns local MACs, originates RT-2 / RT-3 / RT-4 /
RT-1, observes DF election, enforces BUM split-horizon in the kernel,
and consumes the receive side (Type 2 / Type 3 / Type 4 / EAD-per-EVI
mass-withdraw + aliasing). The Type 5 wire codec round-trips, but
nothing originates a Type 5, nothing installs a remote Type 5 into a
kernel FIB, and the daemon has no concept of an IP-VRF / L3VNI domain
object.

Gate 9 closes that gap. The shape of "EVPN IRB" the industry has
converged on is the **symmetric Interface-less IP-VRF-to-IP-VRF
Model** of RFC 9136 §4.4.2 — same one FRR implements, same one
Cumulus / NVIDIA documents, same one Juniper and Arista interop
against in EANTC. We adopt that as the only IRB mode rustbgpd will
support in this gate; asymmetric IRB (RFC 9135 §4.1) and the
Interface-ful IP-VRF-to-IP-VRF model (RFC 9136 §4.4.1) are explicit
non-goals and stay out of the data structures' shape until somebody
asks for them.

This ADR pins the architecture so the code slices that follow
(config schema, Linux probe/readiness, pure projection / origination
helpers, CLI visibility, M39 interop smoke) have a single contract
to converge on.

## Decision

### 1. New first-class config object: `[[evpn_ip_vrfs]]`

L3 EVPN introduces a domain object that doesn't exist in the
current schema: the IP-VRF. It's the tenant boundary for Type 5 —
RT-imported routes go into its FIB, Type 5 originations come out of
its FIB, and the L3VNI is what wraps frames between PEs.

We add `[[evpn_ip_vrfs]]` as a top-level TOML array, parallel to
`[[evpn_instances]]` and `[[ethernet_segments]]`. Each entry binds
one IP-VRF tenant:

```toml
[[evpn_ip_vrfs]]
name = "tenant-blue"             # operator-facing handle
vni = 5000                       # L3VNI
rd = "65000:5000"                # Route Distinguisher
route_targets = ["65000:5000"]   # required import + export RTs
local_vtep_ip = "10.0.0.1"       # required source IP for L3VXLAN encap
router_mac = "02:00:00:00:00:01" # local Router MAC extcomm value
                                 # advertised on every Type 5; same
                                 # MAC the kernel uses as the inner
                                 # dst when peers send frames to us
vrf_device = "vrf-blue"          # Linux VRF device name (observe-only)
l3vxlan_device = "vni5000"       # Linux L3VXLAN device name (observe-only)
table_id = 5000                  # VRF route table id (observe-only,
                                 # cross-checked against vrf_device)
```

`[[evpn_instances]]` (the existing L2VNI surface) gains an optional
`ip_vrf = "tenant-blue"` field that binds the L2VNI to an IP-VRF by
name. The link is name-based so `[[evpn_ip_vrfs]]` and
`[[evpn_instances]]` can be reordered freely in the file.

Validation, at config-load time:

- IP-VRF `name` is unique and matches `^[a-zA-Z][a-zA-Z0-9_-]*$`.
- `vni` is unique across both `[[evpn_ip_vrfs]]` and `[[evpn_instances]]`
  (an L3VNI and an L2VNI can't share a number).
- `rd` parses (`asn:value` or `ip:value`).
- `route_targets` is non-empty and every entry parses. Auto-RT
  derivation is deliberately out of scope for this gate.
- `local_vtep_ip` is required and parses as IPv4 or IPv6. Sharing
  a daemon-wide VTEP IP may come later as an explicit defaulting
  feature, not as implicit schema behavior.
- `router_mac` is a valid unicast non-zero MAC. Not auto-derived; see
  §3 below.
- Every `[[evpn_instances]].ip_vrf` resolves to a declared IP-VRF.
- Soft-reload semantics: same as `[[evpn_instances]]` today —
  restart-required for now. Promoting to SIGHUP rides with the
  same future `[[evpn_instances]]` mutation surface (deferred,
  evpn-alpha-soak.md tracks).

### 2. Symmetric Interface-less IRB only

The dataplane contract pinned for this gate:

- **Outbound (origination).** For each `[[evpn_ip_vrfs]]` entry,
  the daemon watches the VRF's Linux route table (`table_id`). On
  every relevant `RTM_NEWROUTE` / `RTM_DELROUTE` for a route in
  that table whose nexthop is *not* via the L3VXLAN device (i.e.,
  it's a local kernel-attached or kernel-installed route, not a
  route we ourselves programmed), the daemon originates a Type 5
  carrying:
  - `prefix` from the route key
  - `gateway = 0.0.0.0` / `::` (Interface-less model — gateway is
    unused; the resolution happens via Router MAC extcomm)
  - `label = vni`
  - `esi = 0`, `ethernet_tag = 0`
  - Path attrs: `NEXT_HOP = local_vtep_ip`, RT extcomms from the
    `[[evpn_ip_vrfs]].route_targets`, **Router MAC extcomm**
    (subtype 0x03 of opaque type 0x06, RFC 9135 §4.2) = the
    configured `router_mac`, **Encap extcomm** = VXLAN (8).

- **Inbound (FIB install).** A received Type 5 whose RD is not
  ours, whose RTs match some local `[[evpn_ip_vrfs]].route_targets`,
  becomes an `RTM_NEWROUTE` in that VRF's `table_id` with:
  - `dst = prefix`
  - `oif = l3vxlan_device`
  - `nexthop = NEXT_HOP from path attrs` (the originator's VTEP)
  - `proto = RTPROT_BGP`
  - Linux's `bridge fdb append <router_mac> dst <vtep> dev <l3vxlan>
    vni <l3vni>` for the inner-MAC resolution.
  Withdrawal: the matching `RTM_DELROUTE` + reverse FDB del.

- **No asymmetric IRB.** The daemon will not consume MAC/IP RT-2
  to install routes for remote hosts in the IP-VRF — RT-5 is the
  only route-installing source.

### 3. Linux device lifecycle: observe-only

We do not create or destroy Linux VRF devices, L3VXLAN devices,
or modify their VNI/table-id bindings. The operator pre-creates
them as part of system bring-up (matching the way M30b / M37 / M38
already work for L2VNI bridges and VXLAN devices today).

At reconcile time, before programming any FIB entry, the readiness
probe must observe:

1. The configured `vrf_device` exists and is `state UP`.
2. `vrf_device`'s `IFLA_VRF_TABLE` matches the configured `table_id`.
3. The configured `l3vxlan_device` exists and is `state UP`.
4. `l3vxlan_device`'s `IFLA_VXLAN_ID` matches the configured `vni`.
5. `l3vxlan_device`'s `IFLA_VXLAN_LOCAL` (IPv4) or `IFLA_VXLAN_LOCAL6`
   (IPv6) matches the configured `local_vtep_ip`.
6. `l3vxlan_device` is enslaved to `vrf_device`
   (`IFLA_MASTER == vrf_device.ifindex`).
7. `l3vxlan_device.address` (MAC) matches the configured
   `router_mac`. **This is the deliberate non-auto-derivation
   contract** — see §5.

Any check failure produces a `Status::NotReady` for that IP-VRF and
the daemon does not originate Type 5 from it and does not install
remote Type 5 into it. The check re-runs every reconcile pass; the
daemon flips `NotReady → Ready` on its own without operator
intervention as soon as bring-up completes.

The same observe-only contract already governs L2 — `[[evpn_instances]]`
expects a pre-created bridge + VXLAN. This keeps the L3 surface
consistent with that pattern and avoids the rabbit-hole of "what if
the daemon creates a VRF and then the operator's other config
changes its table id?"

### 4. Router MAC is operator-supplied, not auto-derived

The Router MAC extcomm value the daemon attaches to outbound Type 5
must match the MAC the kernel will use as the inner destination
MAC when peers send frames back to us — otherwise peers do recursive
lookup, the inner MAC doesn't match our L3VXLAN device's MAC, and
frames get black-holed.

The "obvious" approach is to read `l3vxlan_device.address` and
auto-populate the Router MAC. We deliberately don't do this:

- It ties the order of operations to "VXLAN device must exist before
  the daemon can start originating Type 5", which collides with
  reconcile-loops where the daemon is restarted ahead of network
  bring-up. The current evpn_instances surface already takes this
  pain by waiting for `state Ready`; auto-derivation makes the same
  problem also affect the *advertised value*, not just the *gating
  predicate*.
- The MAC is an externally-visible interop value. An operator might
  legitimately want it stable across L3VXLAN device recreates (e.g.
  ifindex change should not change the Router MAC peers see), or
  match a value their orchestrator has committed to in advance.

So the config-declared `router_mac` is the source of truth on the
wire, and the readiness probe asserts the kernel matches it. Mismatch
is a hard NotReady — the daemon will not originate Type 5 with a
value that doesn't match what's actually being used to decapsulate.

### 5. Type 5 wire shape — single label, Interface-less

The Type 5 codec already round-trips (`EvpnIpPrefixRoute` in
`crates/wire/src/evpn.rs:453`) and carries one MPLS label slot.
RFC 9136 §4.4.2 mandates the Interface-less model uses that single
label as the L3VNI and `gateway = 0.0.0.0 / ::`.

This ADR therefore does **not** introduce a "label2" concept for
Type 5. The structural `label2` field that appears on RT-2 for
RFC 9135 IRB-with-MAC-IP routes stays scoped to RT-2 and is unused
in Gate 9.

### 6. Domain layout

```
crates/evpn/src/ip_vrf/mod.rs           NEW: IpVrf, IpVrfId, IpVrfTable
crates/evpn/src/ip_vrf/origination.rs   NEW: kernel route → Type 5 builder
crates/evpn/src/ip_vrf/projection.rs    NEW: Type 5 → RemoteIpPrefix
crates/evpn/src/ip_vrf/readiness.rs     NEW: pure-logic readiness probe
src/config/schema.rs                  + EvpnIpVrfConfig serde shape
src/config/mod.rs                     + parse_evpn_ip_vrf, validation
src/evpn_ip_vrf.rs                    NEW: per-vrf supervisor task (slice 8)
crates/evpn-linux/src/linux/ip_vrf.rs NEW: IpVrfObservations + snapshot_for
crates/evpn-linux/src/dataplane.rs    + Dataplane::probe_ip_vrfs trait method
crates/evpn-linux/src/reconcile.rs    + IP-VRF readiness probe wiring
crates/evpn-linux/src/...             + FIB install/withdraw ops (slice 8)
```

The pure-logic split mirrors the L2 side:

- `crates/evpn/src/ip_vrf/projection.rs` is the read-only,
  side-effect-free Type 5 → `RemoteIpPrefix` mapper. Has no Linux
  dependency. Unit-tested with synthetic input.
- `crates/evpn/src/ip_vrf/origination.rs` is the read-only kernel
  route → `EvpnIpPrefixRoute` builder. No tokio, no I/O.
- `src/evpn_ip_vrf.rs` is the per-vrf supervisor task that owns
  state, subscribes to the dataplane report broadcast, drives the
  RIB inject/withdraw, and applies the FIB ops via the dataplane
  channel.

### 7. Linux probe shape (Step 3)

`IpVrfStatus` lives in `crates/evpn/src/ip_vrf/readiness.rs`
(re-exported via `crates/evpn/src/ip_vrf/mod.rs`). The actual
shape that landed — with the observed value attached to every
mismatch variant so a future `--json` view can render the
delta without re-querying the kernel:

```rust
pub enum IpVrfStatus {
    /// All seven §3 predicates hold; we may originate / install.
    Ready {
        vrf_ifindex: u32,
        l3vxlan_ifindex: u32,
        table_id: u32,
        router_mac: MacAddress,
    },
    /// At least one predicate failed. Every failing predicate is
    /// reported so an operator's `--json` view can render the full
    /// list, not just the first one tripped.
    NotReady { reasons: Vec<IpVrfNotReady> },
}

pub enum IpVrfNotReady {
    VrfDeviceMissing,
    VrfDeviceDown,
    VrfTableIdMismatch  { observed: u32, configured: u32 },
    L3VxlanMissing,
    L3VxlanDown,
    L3VxlanVniMismatch  { observed: u32, configured: u32 },
    L3VxlanLocalMismatch{ observed: Option<IpAddr>, configured: IpAddr },
    L3VxlanNotInVrf     { observed_master: Option<u32>, expected_master: u32 },
    RouterMacMismatch   { observed: Option<MacAddress>, configured: MacAddress },
}
```

The probe itself —
`probe(&IpVrf, &IpVrfKernelSnapshot) -> IpVrfStatus` — is pure
and takes a portable [`IpVrfKernelSnapshot`] built by the
`crates/evpn-linux` reconciler from rtnetlink in a follow-on
slice. Keeps the seven predicates unit-testable against
synthesized snapshots — no privileged runners.

The reconciler populates this for every configured IP-VRF on every
pass and includes it in `DataplaneReport.ip_vrf_status` (new field).
The supervisor consumes the broadcast as it already does for
`InstanceDataplaneStatus`.

### 8. CLI visibility (Step 5 preview)

A new `rustbgpctl evpn vrfs` subcommand prints:

```
NAME         VNI    STATUS       VRF        L3VXLAN     ROUTER_MAC          ORIGINATED  RECEIVED
tenant-blue  5000   Ready        vrf-blue   vni5000     02:00:00:00:00:01           3        12
tenant-red   5001   NotReady(2)  vrf-red    vni5001     —                           0         0
```

Backed by a new `ListEvpnIpVrfs` gRPC RPC. Originated / Received
counts are wire-level Type 5 counts attributed to the VRF via RT
matching. The `NotReady(2)` cell reads "2 readiness predicates
failed" — `--json` or `evpn vrfs get <name>` expand the list.

## Out of scope

- **Asymmetric IRB.** Symmetric Interface-less only.
- **Interface-ful IRB** (RFC 9136 §4.4.1).
- **ARP / ND suppression** (RFC 9135 §6). The kernel handles ARP on
  the L2VNI bridge directly; we don't proxy.
- **Type 5 ESI != 0** advertisements. The daemon will reject non-zero
  ESI on Type 5 at config validation if it's ever requested. Multi-
  homed IP-VRF + ESI is a Gate 9b scope question.
- **Mobility-keyed Type 5.** RFC 9721 extends mobility procedures to
  IRB; that's a follow-on after Gate 9 lands and we have base
  Type 5 traffic.
- **`[[evpn_ip_vrfs]]` mutation at runtime.** Same restart-required
  story as the L2 side. Mutation surface rides with the existing
  evpn-alpha-soak.md item.
- **Dynamic Router MAC**, auto-RD, auto-RT. Operator-supplied only
  in this gate.
- **Forwarding-plane ECMP across multiple egress PEs for the same
  prefix.** Interface-less semantics let us do this in principle;
  in this gate we install one nexthop per (prefix, VRF) and let the
  RIB's best-path step pick it. ECMP is a follow-on.

## Alternatives considered

- **Auto-derive Router MAC from kernel.** Rejected per §4 — couples
  daemon startup ordering to network device bring-up and removes the
  operator's ability to pin a stable wire-visible value.
- **Use the existing `[[evpn_instances]]` table for L3VNIs too,
  distinguished by a `type = "l3"` field.** Rejected — the two
  object types have very different lifecycles (L2 binds a bridge,
  L3 binds a VRF), different status semantics (L2 has BUM
  enforcement, L3 has FIB programming), and different operational
  audiences. Keeping them separate matches every other
  implementation we surveyed.
- **Manage VRF / L3VXLAN device lifecycle from the daemon.**
  Rejected per §3 — consistent with the observe-only contract that
  L2 already follows, avoids ownership tangles with `systemd-networkd`
  / `NetworkManager` / cloud-init orchestrators.
- **Asymmetric IRB instead of symmetric.** Rejected — asymmetric
  scales poorly (every PE has to host every MAC for every IP-VRF
  it serves), is what Junos / Arista deprecated by default, and
  doesn't interoperate cleanly with FRR's symmetric default.

## Rollout

The work splits into eight shippable slices. The original plan
called for six; the readiness step grew its own pure-logic /
netlink-dump / trait-impl / report-wiring sub-slices so each piece
stays small enough to review against its own test surface. Final
shape as actually merged:

1. **This ADR + config schema** — pure doc + `EvpnIpVrfConfig`
   parse / validation / diff. Operators can declare IP-VRFs at this
   stage; the daemon parses + logs but does nothing with them yet.
   *Shipped in #66.*
2. **Pure-logic Type 5 helpers** —
   `crates/evpn/src/ip_vrf/{origination,projection}.rs` with full
   unit-test coverage against synthetic input. No wiring into the
   supervisor yet. *Shipped in #67.*
3. **Pure-logic readiness probe** — `IpVrfKernelSnapshot` +
   `probe(&IpVrf, &snapshot) -> IpVrfStatus` in
   `crates/evpn/src/ip_vrf/readiness.rs`. Kernel-free; takes a
   portable snapshot and runs the seven §3 predicates. No netlink,
   no tokio. *Shipped in #72 (originally #68 against a stacked
   base).*
4. **Linux netlink dumps (4a).** `crates/evpn-linux/src/linux/ip_vrf.rs`
   builds `IpVrfObservations` from one `RTM_GETLINK` pass; the
   `snapshot_for` helper composes the per-IP-VRF `IpVrfKernelSnapshot`
   the readiness probe consumes. *PR #73.*
5. **`Dataplane::probe_ip_vrfs` trait + Linux impl (4b).** Abstract
   probe surface with an empty default for non-Linux / fake impls;
   `LinuxDataplane` overrides it by running the dump and calling
   `probe()` per configured VRF. Short-circuits when the
   `IpVrfTable` is empty so L2-only and RR-only deployments incur
   zero added netlink cost.
6. **Intent plumbing + reconcile call (4c).** `DataplaneIntent`
   gains `ip_vrfs: Arc<IpVrfTable>`; the daemon populates it once
   at startup from config; the reconcile actor calls
   `probe_ip_vrfs` on every pass and emits one
   `tracing::info!` per Ready transition and one `tracing::warn!`
   per NotReady transition. Steady-state is silent — operators get
   edge-triggered output, not a 5 s spam loop.
7. **CLI / report visibility slice.** Adds `IpVrfStatus` rows to
   `DataplaneReport`, a `ListIpVrfs` / `GetIpVrf` gRPC RPC, and the
   `rustbgpctl evpn vrfs [get NAME]` command. Surfaces IP-VRF
   readiness so the operator can see it before any FIB programming
   ships.
8. **End-to-end wiring + M39 interop smoke.** Supervisor consumes
   `DataplaneReport.ip_vrf_status`, drives Type 5 RIB
   inject/withdraw on local IP-route changes, installs remote
   Type 5 into the kernel VRF. M39 manual containerlab harness
   validates FRR ↔ rustbgpd bidirectional Type 5 against a small
   symmetric IRB topology.

Slices 4–6 (the readiness path) deliberately separate "decide" from
"observe" from "wire" so each PR's test surface is its own:
slice 3 unit-tests against synthesized snapshots, slice 4 unit-tests
against synthesized `LinkMessage` instances, slice 5 has only
trait-shape glue, slice 6 has only intent + log plumbing. None of
them need privileged runners.

## References

- RFC 9136 — IP Prefix Advertisement in EVPN
- RFC 9135 — Integrated Routing and Bridging in EVPN
- RFC 7432 §15.4 — sticky bit (mobility carryover)
- RFC 9721 — Extended Mobility Procedures for EVPN-IRB (deferred)
- ADR-0052 — EVPN VTEP foundation (Gate 7)
- ADR-0054 — EVPN Linux dataplane boundary
- ADR-0055 — Local-MAC origination boundary
- ADR-0057 — Gate 8 observable DF election
- FRR EVPN docs (Interface-less, symmetric default)
- Juniper / Arista interop confirmation (EANTC 2024)
