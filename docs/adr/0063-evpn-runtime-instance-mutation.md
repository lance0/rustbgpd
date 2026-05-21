# ADR-0063: EVPN runtime instance mutation semantics

**Status:** Accepted; partially implemented — single L2VNI add, single L2VNI
delete when the VNI is not an Ethernet Segment member, single IP-VRF add,
single standalone IP-VRF delete, and single Ethernet Segment add commit live
via `EvpnService.ApplyEvpnRuntime`; redefine / mixed / multi-element edits,
linked IP-VRF delete, and ES-aware delete shapes still fail closed (remaining shapes tracked in
[#210](https://github.com/lance0/rustbgpd/issues/210)). The segment actor reads
a startup-pinned instance table, so an ES whose member VNI was added at runtime
is rejected (restart-required), not silently dropped — full instances-watch
convergence is also #210.
**Date:** 2026-05-17 (implementation in progress through v0.25.0)

## Context

`[[evpn_instances]]`, `[[evpn_ip_vrfs]]`, and `[[ethernet_segments]]`
are startup-pinned today. `reload_config` logs restart-required drift
and pins the in-memory snapshot back to the live values so repeated
SIGHUPs keep surfacing the mismatch. `EvpnService` is read-only and is
backed by an `Arc<EvpnInstanceTable>` built during daemon startup.

That was a safe boundary for Gate 7a, but the local EVPN table now feeds
more than a read surface:

- Type 3 IMET origination per L2VNI (RFC 7432 §7.3).
- Type 2 MAC-only, MAC+IP, SVI MAC, sticky-MAC, and duplicate-MAC local
  origination state.
- Linux FDB reconciliation for single-homed and multi-homed remote Type 2
  routes.
- Gate 8 Ethernet Segment / DF state and Type 1/4 origination.
- Gate 9 Type 5 origination and L3 FIB programming for linked IP-VRFs
  (RFC 9136 §4.4).

Issue #133 asks for explicit delete/redefine semantics before any gRPC
or SIGHUP runtime mutation path lands. A table swap alone would make the
API view change before the originators, DF/segment orchestrator, and
dataplane reconciler have drained or replayed their derived state.

## Decision

Runtime EVPN instance mutation must be command-driven through one EVPN
runtime coordinator. The coordinator owns a generationed runtime model
covering the resolved L2VNI instances, IP-VRFs, and Ethernet Segment
bindings, and serializes every add, delete, or redefine operation. The
first implementation must not mutate the shared `Arc<EvpnInstanceTable>`
directly with `ArcSwap`, `RwLock`, or ad hoc per-service locks.

The coordinator is the only component allowed to publish a new effective
EVPN runtime generation. Per-feature actors consume coordinator commands
or generation snapshots and report completion/failure back to the
coordinator. `EvpnService` and CLI surfaces expose the committed
generation, plus any in-progress or failed operation state once that
status surface exists.

### Add semantics

Adding an L2VNI instance is a validation-first operation:

1. Validate the full candidate runtime model, not only the new row:
   VNI/RD uniqueness, Route Target syntax, bridge/readiness references,
   IP-VRF links, Ethernet Segment `member_vnis`, and no conflict with a
   pending delete/redefine for the same VNI.
2. Allocate the next generation and publish the instance as
   `activating`, not silently `active`, if any derived actor still needs
   to converge.
3. Prime derived subsystems in dependency order:
   IMET Type 3 membership, local observation subscriptions, local Type 2
   replay, SVI MAC origination, DF/ES bindings and Type 1/4 origination,
   remote Type 2 dataplane intent, and linked IP-VRF/Type 5
   re-evaluation.
4. Mark the instance `active` only after the coordinator has queued every
   required idempotent reconcile action. Kernel Ready/NotReady remains a
   dataplane status, not a reason to reject the config row.

Validation failures reject the mutation without publishing a new
generation.

### Delete semantics

Deleting an L2VNI instance is a drain operation:

1. Stop accepting new local observations for that VNI.
2. Remove the VNI from desired dataplane intent so owned remote FDB /
   BUM / FDB-NHG state drains through the existing reconciler rules.
3. Withdraw every locally originated route bound to the instance:
   MAC-only Type 2, MAC+IP Type 2, SVI Type 2, Type 3 IMET, and any
   Type 1 EAD-per-EVI state for segments that include the VNI.
4. Re-evaluate linked IP-VRF state; if the deleted L2VNI was the IP-VRF's
   required local EVPN binding, the Type 5 originator and L3 dataplane
   path must withdraw or mark that IP-VRF NotReady.
5. Drop per-instance mobility ratchets, duplicate-MAC detector state,
   pending local observations, and originated-key caches only after the
   withdraw/drain plan has been queued.

Delete is best-effort and retryable. If a subsystem channel or kernel
operation fails transiently, the coordinator keeps the instance in a
`deleting` / degraded state and retries through the subsystem's existing
level-triggered model. It must not claim the instance is gone while owned
routes or kernel state remain queued for cleanup.

### Redefine semantics

The first runtime mutation surface treats instance redefinition as
delete-old plus add-new. This applies to any field that changes route
identity, import/export policy, kernel ownership, or local origination:
`vni`, `rd`, `route_targets`, `local_vtep_ip`, `bridge`,
`advertise_svi_mac`, `sticky_macs`, `duplicate_mac_detection`, `ip_vrf`,
and `apply_aliasing_ecmp`.

A future implementation may allow narrower in-place updates only when
the affected subsystem supplies a pure, tested converge plan that does
not mix old and new route keys. Until then, redefine drains the old
generation first, then activates the new generation. Mobility sequence
ratchets are not carried across redefine unless the future converge plan
explicitly proves the route identity is unchanged and safe to retain.

### API shape

This ADR does not add protobuf methods. Future mutating RPCs should be
coordinator commands rather than direct table writes. They may expose
add/delete/redefine as separate RPCs or a whole-model replace, but they
must preserve the validation-first, generationed, idempotent drain model
above.

SIGHUP keeps its current restart-required behavior until the coordinator
exists. Reload may parse and validate the new file, but it must not
silently advance the live EVPN runtime model.

## Consequences

- SIGHUP file-driven EVPN edits keep the current safe behavior: they remain
  restart-required, and repeated SIGHUPs keep surfacing the drift.
- The runtime mutation implementation is larger than a shared-table swap, but
  it avoids split-brain between gRPC, BGP-originated routes, DF/ES state, and
  Linux owned state. The first increments — single L2VNI add, single L2VNI
  delete when the VNI is not an Ethernet Segment member, single IP-VRF add,
  single standalone IP-VRF delete, and single Ethernet Segment add — now commit
  live through the daemon actor converger. L2VNI delete also republishes derived
  IP-VRF reference metadata to the dataplane when the deleted VNI was linked to
  a still-present IP-VRF; IP-VRF row delete/redefine and mixed tenant teardown
  still fail closed.
- The Ethernet Segment actor owns a cloneable runtime control surface for
  complete desired-ES snapshots and remains the sole Type 1/4 owner. A single ES
  add now commits live by republishing the full desired-ES snapshot through that
  owner (it drains/rebuilds Type 4, EAD-per-ES, EAD-per-EVI, and BUM enforcement
  state internally). The actor's instance view is startup-pinned, so an ES whose
  member VNI was added by a prior runtime L2VNI add is rejected
  (restart-required) by the converger rather than silently dropped; the
  full instances-watch convergence and delete/redefine remain in #210.
- Redefine, mixed / multi-element edits, linked IP-VRF delete / tenant teardown,
  ES-aware L2VNI delete, ES delete/redefine, and runtime-added-member-VNI ES
  convergence are still validated as pure fail-closed plans; their live
  convergence is the remaining work in
  [#210](https://github.com/lance0/rustbgpd/issues/210).
- Issue #133 (design) is resolved and closed; the remaining implementation is
  tracked in #210.

## Non-goals

- No per-instance `AddEvpnInstance` / `DeleteEvpnInstance` protobuf surface;
  mutation is a whole-model apply via `EvpnService.ApplyEvpnRuntime`.
- No hot SIGHUP apply for `[[evpn_instances]]`, `[[evpn_ip_vrfs]]`, or
  `[[ethernet_segments]]`.
- No automatic Linux bridge, VXLAN, VRF, or Ethernet Segment netdev
  creation.
- No change to EVPN dataplane defaults such as `apply_bum_enforcement` or
  `apply_aliasing_ecmp`.
- No durable persistence of EVPN originator ratchets across daemon restart.
