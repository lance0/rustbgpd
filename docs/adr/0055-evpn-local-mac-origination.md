# ADR-0055: EVPN Local-MAC Origination Boundary

**Status:** Accepted; implemented in PR #35 and merged on 2026-05-07
**Date:** 2026-05-06

## Context

ADR-0054 closed the **downward** EVPN dataplane flow in Gate 7b:
RIB best-path → `crates/evpn` projection → `Arc<DataplaneIntent>`
watch → `crates/evpn-linux` reconciler → kernel FDB. Remote MACs land
in the Linux bridge tagged `extern_learn`. The **upward** flow (kernel
local-MAC observations turning into BGP EVPN Type 2 originations) was
left as a stub: `LocalMacObservation { Learned, Aged }` was defined
in `crates/evpn/src/mac.rs`, the `KernelEvent::LocalMacObservation`
variant existed in the dataplane crate, the reconcile actor explicitly
dropped it, and `LinuxDataplane::next_event` returned `pending()`.

Gate 7b+1 closes that loop: rustbgpd-as-VTEP becomes **bidirectional**.
This ADR locks the boundary between the kernel observation feed and
the BGP origination engine before the implementation lands, in the
same spirit ADR-0054 locked the downward boundary.

The relevant source constraints are:

- **RFC 7432 §7.2** — Type 2 MAC/IP Advertisement route format.
- **RFC 7432 §7.3** — Type 3 Inclusive Multicast Ethernet Tag (IMET)
  route format.
- **RFC 7432 §7.7** — MAC Mobility extended community shape and
  semantics; "absent extcomm" is semantically `seq=0, sticky=false`.
- **RFC 7432 §15.1** — Sequence-number rules for MAC mobility:
  - First advertisement, no contender ever observed: no extcomm.
  - First advertisement vs contender at seq=R: emit at R+1.
  - Contender announces seq=M ≥ our N: bump to `max(M, N) + 1`.
- **RFC 7432 §15.4** — Sticky bit semantics. Operator-facing
  per-MAC sticky configuration is **explicitly out of scope** for this
  ADR; the sticky field is plumbed end-to-end (state machine →
  Inject action → wire codec) but always `false` on the daemon side
  until a follow-up ADR defines the config schema.
- **RFC 6514 §5** — PMSI Tunnel attribute (path attribute type 22),
  required on Type 3 IMET to advertise ingress-replication BUM.
- **RFC 8365 §5.1.3** — VXLAN-EVPN encap convention; redefines the
  PMSI Tunnel "MPLS Label" field semantics so the **full 24-bit field
  is the VNI** (no high-20-bits MPLS shift). Matches `EvpnMacIp.label1`
  for Type 2 routes.
- **Linux RTNLGRP_NEIGH** (`<linux/rtnetlink.h>`, enum group id `3` —
  third entry in `enum rtnetlink_groups`, **not** the legacy bitmask
  `RTMGRP_NEIGH = 4`) — the multicast group whose unsolicited
  `RTM_NEWNEIGH` / `RTM_DELNEIGH` messages surface bridge FDB learn/age
  events. `Socket::add_membership` takes the enum group id directly.

The constraints from ADR-0054 carry over unchanged:

- `crates/evpn-linux` may not depend on `crates/rib` or `crates/transport`.
- `crates/evpn` must remain portable to non-Linux dev builds (no
  netlink, no tokio, no I/O).
- Route-reflector deployments with empty `[[evpn_instances]]` must
  spawn no background tasks.

## Decision

### 1. Domain types stay in `crates/evpn`; no new RIB pathway

The local-MAC origination state machine —
`LocalMacOriginator`, `LocalMacOriginationState`, `RemoteMacView`,
`OriginationAction` — lives in `crates/evpn/src/origination.rs`. The
shape is symmetric to ADR-0054's placement of `DataplaneIntent` /
`RemoteMacTable`: pure domain logic in the portable crate, daemon-side
glue in the binary.

The daemon-side adapter `src/evpn_originator.rs` is the only place
that translates `OriginationAction`s into `RibUpdate::InjectEvpn` /
`RibUpdate::WithdrawEvpn`. The RIB inject/withdraw entry points were
already present (used by the gRPC injection service and by the
existing route reflector tests); no new RIB pathway is added.

The `EvpnRouteKey` of every Inject is **stored** on the per-MAC
state, not reconstructed at withdraw time, so withdraws are
byte-identical to the originally-announced NLRI even if instance
config rotates mid-flight.

### 2. Sequence rules encoded structurally

The `LocalMacOriginator` state machine encodes RFC 7432 §15.1
explicitly:

- A `last_seen_remote_seq: Option<u32>` on each per-MAC entry tracks
  the highest remote sequence ever observed. `None` ⇒ "no contender
  has ever appeared," in which case the rendered Inject action carries
  `mobility_seq: None` (the daemon omits the extcomm on the wire).
- `our_seq: u32` ratchets monotonically per `(VNI, MAC)` across the
  entry's entire lifetime. Aged-then-Re-Learn does **not** reset the
  ratchet — the prior sequence is preserved so a peer that still
  remembers our advertisement cannot win a stale contention.
- `originated_key: Option<EvpnRouteKey>` distinguishes "currently
  advertising" from "withdrawn or never advertised." The state entry
  is kept after withdraw so the ratchet survives.

A pure-function shape (`on_local_learned`, `on_local_aged`,
`on_remote_changed` each return `Vec<OriginationAction>` and never
touch I/O) keeps the sequencer testable on macOS dev builds with no
tokio or RIB scaffolding. The proptest invariant in
`crates/evpn/src/origination.rs#tests` exercises the monotonic
ratchet across mixed-handler sequences.

### 3. Upward channel surface is deliberately separate from `next_event`

The dataplane trait grows one method:

```rust
fn take_local_mac_rx(&mut self) -> Option<mpsc::Receiver<LocalMacObservation>> {
    None
}
```

with a default implementation returning `None`. The daemon calls this
once at construction and hands the receiver to the originator's
`tokio::select!` loop.

A dedicated channel was chosen over routing observations through the
existing `KernelEvent::LocalMacObservation` variant in
`Dataplane::next_event`. Going through `next_event` would require the
reconcile actor to forward observations to a daemon-owned channel,
coupling the actor's lifetime and channel layout to the originator's
and forcing the actor to outlive the originator. Keeping the two
upward flows independent at the trait boundary preserves ADR-0054 §1's
"narrow upward interface" rule.

### 4. Self-origination filter at the daemon, not the state machine

The originator's RIB-poll diff feeds `RemoteMacView`s into
`on_remote_changed`. The daemon filters self-NH routes (those whose
next-hop is the local instance's `local_vtep_ip`) **before** building
the view; the state machine never sees its own re-Inject as a
contender. Filtering structurally at the projection layer (via
`project_evpn_routes`, which already drops self-NH routes for the
downward dataplane flow per Gate 7b) reuses the existing rule rather
than duplicating it.

### 5. Polling, not broadcast subscription

The originator polls the RIB on the same fixed cadence the dataplane
supervisor uses (5 s default). The existing `RouteEvent` broadcast at
`crates/rib/src/event.rs` is keyed by `Prefix` and is therefore
unicast-only — EVPN best-path changes do not surface there. Adding an
EVPN-specific broadcast is tracked as a Gate 7c convergence
optimization in `docs/evpn-enablement.md`; it is **not** required for
correctness because mobility races are bounded by the polling cadence
and the level-triggered re-evaluation in `on_remote_changed`.

### 6. Type 3 IMET origination is lifecycle-decoupled from kernel readiness

One Type 3 IMET route is originated per configured `EvpnInstance` at
daemon startup and withdrawn at coordinated-shutdown time. IMET is
**not** conditioned on dataplane Ready/NotReady — the route expresses
BGP-level VNI membership, not kernel programmability. Peers care
whether we want to receive BUM, not whether our kernel is ready to
forward it.

The IMET originator (`src/evpn_imet.rs`) is a free function pair
(`originate_all` / `withdraw_all`) rather than a long-lived actor
because the Gate 7a config schema pins the `EvpnInstanceTable` at
startup. When dynamic `[[evpn_instances]]` mutation lands post-v1.0,
the function shape can grow into a full reconciler; for now an actor
would buy nothing.

The PMSI Tunnel attribute (path attribute type 22, RFC 6514 §5) is
the only new wire-format addition. Its codec is in
`crates/wire/src/pmsi.rs`. For ingress replication over VXLAN, the
constructor `PmsiTunnel::for_evpn_ingress_replication(vni, ip)`
encodes the label field as the **raw 24-bit VNI** per RFC 8365 §5.1.3
(no MPLS-style shift) and the Tunnel Identifier as the unicast
originator IP.

### 7. Origination of MAC-with-IP Type 2 is deferred

`LocalMacObservation::Learned` carries no host IP because
`RTM_NEWNEIGH AF_BRIDGE` (the kernel's bridge FDB feed) is L2-only.
Carrying ARP/ND-suppression observations requires a separate
`AF_INET` / `AF_INET6` `RTNLGRP_NEIGH` subscription correlated by
MAC, which is its own design problem. Gate 7b+1 originates the
**IP-less** Type 2 ("MAC-only") form exclusively. The wire codec
already supports the MAC+IP form; only the consumer is deferred.

### 8. Sticky / static MAC anti-spoof config is deferred

The wire-side codec for the sticky bit (RFC 7432 §15.4) is in scope —
`OriginationAction::Inject` carries a `sticky: bool` field, the state
machine plumbs it through, and the daemon encodes it in the MAC
Mobility extended community when set. The **operator-facing** config
field (e.g., a `static_macs: BTreeSet<MacAddress>` on
`EvpnInstance`) is **out of scope** for this ADR. Schema questions
(per-MAC vs per-port? imported from sysctl? gRPC mutation?) deserve
their own follow-up. Until that schema lands, the daemon always
passes `sticky = false`.

### 9. MAC duplication detection is deferred

RFC 7432 §15.1 also defines a "5 moves in 180s ⇒ duplicate"
quarantine heuristic. Detection counters can land in a follow-up
without changing this ADR; quarantine action requires operator-facing
escalation channels (gRPC + metrics + log) and is therefore deferred.

## Consequences

### Positive

- The originator and the dataplane reconciler are **independent
  actors** sharing only `Arc<EvpnInstanceTable>` and the daemon's
  `rib_tx`. A crash in either is structurally isolated.
- Sequence-rule logic is unit-testable with no kernel, no RIB, and no
  tokio. The state machine's 17 in-module tests cover every RFC §15.1
  branch including a proptest-style monotonic ratchet invariant.
- macOS dev builds still build the originator (the channel is a
  `crates/evpn-linux` trait method that returns `None` on macOS-bound
  fake impls; the originator's `spawn` path returns `None` too,
  cleanly skipping the actor).
- RR-only deployments still spawn no background tasks. The empty
  `[[evpn_instances]]` gate covers both the dataplane reconciler
  (Gate 7b) and the originator (Gate 7b+1).

### Negative

- The poll cadence (5 s default) is a convergence floor for
  mobility-driven sequence bumps. RFC 7432 doesn't impose a tighter
  bound, but operators with sub-second move requirements will see
  this as a gap. Tracked in `docs/evpn-enablement.md` as Gate 7c.
- The MAC-only Type 2 origination is operationally narrower than
  FRR's behavior (FRR snoops ARP/ND too). Documented as a deferred
  item; v1.0 readiness is not blocked but full FRR parity is.
- Real-kernel verification requires `EVPN_LINUX_NETNS=1` and
  `CAP_NET_ADMIN`. PR-CI runners cannot exercise it; a privileged
  runner job is a separate follow-up.

### Neutral

- The IMET-always-on lifecycle differs from the dataplane's
  Ready/NotReady gating. This is a deliberate split — the BGP-side
  membership advertisement is independent of the data-plane-side
  programming readiness. Documented above (§6).

## Alternatives considered

**Routing observations through `KernelEvent::LocalMacObservation` + the
reconcile actor.** Rejected (§3) — couples the actor's lifetime to
the originator and forces the reconcile select! loop to forward
observations to a daemon channel.

**A long-lived actor for IMET origination.** Rejected (§6) — adds
state for no functional gain because the instance table is
startup-pinned. The free-function shape is symmetric to other
"originated at boot, withdrawn at shutdown" patterns in the daemon
(e.g., the gRPC injection service's static-route bulk inject).

**Adding an EVPN-specific `RouteEvent` broadcast.** Tracked as Gate
7c in `docs/evpn-enablement.md`. Polling is the right correctness
floor; the broadcast is a convergence-latency optimization that does
not need to ship before v1.0.

## Implementation references

- `crates/evpn/src/origination.rs` — state machine
- `crates/wire/src/pmsi.rs` — PMSI Tunnel codec
- `src/evpn_originator.rs` — daemon actor
- `src/evpn_imet.rs` — Type 3 IMET originate/withdraw helpers
- `crates/evpn-linux/src/linux/notify.rs` — `RTNLGRP_NEIGH`
  subscription + classifier
- `crates/evpn-linux/src/dataplane.rs` — `take_local_mac_rx` trait
  method
- `tests/interop/m37-evpn-local-origination.clab.yml` — interop
  smoke (Phase G)
