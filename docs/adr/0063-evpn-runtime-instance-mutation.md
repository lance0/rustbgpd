# ADR-0063: EVPN runtime instance mutation semantics

**Status:** Accepted; **alpha-complete** — single L2VNI add, single L2VNI
delete when the VNI is not an Ethernet Segment member, single L2VNI redefine
including Ethernet Segment members when `ip_vrf` link metadata is unchanged,
single IP-VRF add, single standalone IP-VRF delete, single IP-VRF redefine with
unchanged L3VNI/device/table identity, single Ethernet Segment
add/delete/redefine, atomic tenant teardown (a delete-only plan that drops an
ES-member L2VNI together with its Ethernet Segment (delete or member-shrink)
and/or a linked IP-VRF in one pass), additive multi-domain build-up (pure
add-only L2VNI/IP-VRF/ES candidates), and `ip_vrf` relink (an L2VNI re-homed to
a different IP-VRF), and standalone L2VNI swaps (one-or-more clean L2VNI adds
plus one-or-more clean standalone L2VNI deletes, with no ES membership,
IP-VRF reference, redefine, or row-shape changes) commit live via
`EvpnService.ApplyEvpnRuntime` and SIGHUP file-driven reload; ES add/redefine
can bind member VNIs added by a prior live L2VNI add when the segment actor
already exists. Two shapes remain non-live, by design: **L3VNI/device/table
IP-VRF identity changes** are restart-required (kernel VRF lifecycle —
`router_mac` is still live-redefinable), and **broader generic mixed
add/delete/redefine edits** fail closed with a "split the request" error
pending a generalized converge-to-candidate follow-up
([#268](https://github.com/lance0/rustbgpd/issues/268)).
**Date:** 2026-05-17 (implementation completed through v0.27.0)

## Context

`[[evpn_instances]]`, `[[evpn_ip_vrfs]]`, and `[[ethernet_segments]]`
now feed a daemon-owned runtime coordinator. `EvpnService.ApplyEvpnRuntime`
and SIGHUP file-driven reload both submit a fully resolved candidate through
that coordinator for supported live shapes. Unsupported shapes, missing EVPN
actors, and actor convergence failures fail closed: `reload_config` logs the
failure and pins the in-memory snapshot back to the committed runtime values so
repeated SIGHUPs keep surfacing the mismatch.

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

Issue #133 asked for explicit delete/redefine semantics before a runtime
mutation path could safely land. The design is now resolved and the
`ApplyEvpnRuntime` full-candidate RPC plus SIGHUP reload commit the supported
shapes, while remaining unsupported shapes still fail closed under #268. A
table swap alone would make the API view change before the originators,
DF/segment orchestrator, and dataplane reconciler have drained or replayed
their derived state.

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

The implemented L2VNI redefine slice realizes this delete-old-plus-add-new
contract per consumer: the level-triggered watch consumers (Type 2 originator,
SVI, dataplane, segment) classify a content-changed VNI as a
drain-and-re-derive, and the per-VNI Type 3 IMET controller — the lone explicit
consumer — withdraws the committed route before originating the candidate one
(a bare re-originate would no-op against the still-tracked key). The slice is
scoped to instances with an unchanged `ip_vrf` link. If the redefined VNI is an
Ethernet Segment member, the segment actor drains and rebuilds Type 4,
EAD-per-ES, and EAD-per-EVI routes under the candidate route identity while
retaining the stable ESI label. An `ip_vrf` relink (the link itself moving) is a
separate, dataplane-only shape — see below.

### `ip_vrf` relink

Moving an L2VNI's `ip_vrf` link to a different IP-VRF (or adding/removing it)
edits no IP-VRF/L2VNI/Ethernet-Segment row — the link lives only in the IP-VRF
table's reference metadata (`referenced_l2vnis`). So a pure relink produces empty
row changesets; the plan carries a dedicated `ip_vrf_references_changed` signal
(also surfaced in `ApplyEvpnRuntimeResponse.plan`, so the apply does not read as
an empty no-op) that the coordinator's `is_noop` check honors. The link drives
only the dataplane's RFC 9135 §9.2 overlay-index recursion gateway resolution, so
convergence is dataplane-only: republish the candidate IP-VRF table to the
dataplane. The RD is unchanged, so there is no Type 3 re-origination; the Type 2
originator / SVI / segment do not read the link. A relink *combined* with a row
redefine in one request stays fail-closed.

### API shape

This ADR does not add protobuf methods. Future mutating RPCs should be
coordinator commands rather than direct table writes. They may expose
add/delete/redefine as separate RPCs or a whole-model replace, but they
must preserve the validation-first, generationed, idempotent drain model
above.

SIGHUP reload is another coordinator client, not a separate mutation
implementation. Reload may parse and validate the new file, but it must only
advance the live EVPN runtime model after the coordinator and daemon actor
converger accept the candidate. If the coordinator is unavailable, the runtime
actors are missing, or the candidate is outside the supported shape set, reload
must pin the runtime snapshot to the committed model and keep surfacing drift.

## Consequences

- SIGHUP file-driven EVPN edits now reuse the ADR-0063 coordinator for the
  same supported live shapes as `ApplyEvpnRuntime`. Unsupported shapes,
  unavailable actors, and convergence failures keep the safe behavior: reload
  pins the EVPN runtime fields back to the committed model, logs the rejected
  candidate, and repeated SIGHUPs keep surfacing the drift.
- The runtime mutation implementation is larger than a shared-table swap, but
  it avoids split-brain between gRPC, BGP-originated routes, DF/ES state, and
  Linux owned state. The first increments — single L2VNI add, single L2VNI
  delete when the VNI is not an Ethernet Segment member, single L2VNI redefine
  including Ethernet Segment members when `ip_vrf` link metadata is unchanged,
  single IP-VRF add, single standalone IP-VRF delete, single IP-VRF redefine
  with unchanged L3VNI/device/table identity, and single Ethernet Segment
  add/delete/redefine — now commit live through the
  daemon actor converger. L2VNI delete also republishes derived IP-VRF
  reference metadata to the dataplane when the deleted VNI was linked to a
  still-present IP-VRF; tearing down the referenced IP-VRF (or the L2VNI's
  Ethernet Segment) is covered by the tenant-teardown path below rather than the
  single-delete path. L2VNI redefine re-originates the per-VNI Type 3
  IMET (the lone explicit consumer — withdraw the committed route, then
  originate the candidate one) and republishes the candidate instance table to
  the level-triggered watch consumers (Type 2 originator, SVI, dataplane,
  segment), which each drain and re-derive the content-changed VNI. Because the
  dataplane diff reads every per-VNI field, redefine is the surface that finally
  makes `apply_aliasing_ecmp` runtime-drivable via the standard
  `FdbNhg → SingleDst` transition. A standalone `ip_vrf` relink commits live on
  its own dataplane-only path (see above); a relink combined with a redefine in
  one request stays fail closed.
- IP-VRF redefine republishes the candidate IP-VRF table to the dataplane
  supervisor and Type 5 originator when the operator changes route/policy/egress
  fields (`rd`, `route_targets`, `local_vtep_ip`, `router_mac`) but keeps the
  same name, L3VNI, `vrf_device`, `l3vxlan_device`, and `table_id`. The Type 5
  originator drains local prefixes for removed or redefined IP-VRFs before
  reconciling the candidate table, so existing local Type 5 routes are withdrawn
  under the old key and replayed with the new route attributes. Changing the
  L3VNI, device names, table id, or L2VNI links remains fail closed.
- The Ethernet Segment actor owns a cloneable runtime control surface for
  complete desired-ES snapshots and current EVPN instance snapshots, and
  remains the sole Type 1/4 owner. A single ES add, delete, or redefine now
  commits live by republishing the full desired-ES snapshot through that owner
  (it drains/rebuilds Type 4, EAD-per-ES, EAD-per-EVI, and BUM enforcement
  state internally). L2VNI add/delete convergence also republishes the
  candidate instance table to an already-running segment actor, so a later ES
  add/redefine can bind a member VNI added at runtime. When an ES member VNI is
  redefined, the same instance-watch path drains/rebuilds Type 4, EAD-per-ES,
  EAD-per-EVI, and BUM enforcement state from the updated instance snapshot. ES
  add/redefine still fails closed if no segment actor was spawned at startup or
  if a member VNI is absent from the candidate runtime instance table.
- Atomic tenant teardown commits a delete-only plan that spans more than one
  resource (or deletes an ES-member L2VNI, or deletes a referenced IP-VRF) in a
  single pass. The converger validates internal consistency (no surviving L2VNI
  may dangle on a deleted IP-VRF; no candidate Ethernet Segment may still list a
  deleted member VNI — ES redefines are accepted only as a member-shrink), then
  withdraws each deleted L2VNI's Type 3 IMET and republishes the candidate
  snapshots to every level-triggered actor (dataplane instances + IP-VRF
  metadata, SVI, Type 2 originator, segment instances + segments, Type 5
  originator). A rollback ladder republishes the committed snapshots and
  re-originates IMET on any failed publish, escalating the error when an IMET
  restore itself fails. The drains reuse the existing level-triggered consumers;
  the only added primitive is the segment actor emitting Type 1/4 withdraws for a
  member VNI whose instance has already been removed (a withdraw needs only the
  route key, not the reference instance's path attributes).
- Additive build-up commits a pure add-only multi-row or multi-domain candidate
  (for example, adding a linked L2VNI, its IP-VRF, and its Ethernet Segment in
  one request). The converger validates that no delete/redefine is present, that
  any `ip_vrf` reference delta belongs only to newly added L2VNIs, and that
  added ES member VNIs exist in the candidate model. It then originates Type 3
  IMET for each added L2VNI and republishes candidate snapshots to the same
  level-triggered consumers as the single-add paths: dataplane instances and
  IP-VRF metadata, Type 2 originator, SVI, segment instances and segments, and
  Type 5 originator. Rollback republishes the committed snapshots and withdraws
  speculative IMET on any failed publish.
- Standalone L2VNI swaps commit a conservative add+delete composition live:
  one-or-more newly added L2VNIs plus one-or-more deleted L2VNIs, provided the
  deleted VNIs are not Ethernet Segment members, no `ip_vrf` reference/link
  metadata changes, and no IP-VRF/ES rows or L2VNI redefines are mixed into the
  same candidate. The converger originates IMET for added VNIs, publishes the
  candidate L2VNI table to level-triggered consumers, withdraws IMET for deleted
  VNIs, and rolls back by republishing the committed table, withdrawing
  speculative IMET, and restoring deleted IMET if any step fails.
- `ip_vrf` relink now commits live (dataplane-only, see above). The two shapes
  that remain non-live are by design: **L3VNI/device/table IP-VRF identity
  changes** stay restart-required (a kernel VRF lifecycle operation — a runtime
  drain/recreate would risk a dual-state window; `router_mac` is still
  live-redefinable), and **broader generic mixed add/delete/redefine edits**
  fail closed with an operator-actionable "split the request or apply the
  standalone L2VNI swap separately" error, pending a generalized
  converge-to-candidate follow-up ([#268](https://github.com/lance0/rustbgpd/issues/268)).
- Issue #133 (design) is resolved and closed; the remaining implementation is
  tracked in #268.

## Non-goals

- No per-instance `AddEvpnInstance` / `DeleteEvpnInstance` protobuf surface;
  mutation is a whole-model apply via `EvpnService.ApplyEvpnRuntime`.
- No hot SIGHUP apply outside the ADR-0063 supported shape set. In particular,
  L3VNI/device/table IP-VRF identity changes, broader generic mixed
  add/delete/redefine edits beyond standalone L2VNI swaps, and runtime applies
  on daemons without the required EVPN actors remain fail-closed.
- No automatic Linux bridge, VXLAN, VRF, or Ethernet Segment netdev
  creation.
- No change to EVPN dataplane defaults such as `apply_bum_enforcement` or
  `apply_aliasing_ecmp`.
- No durable persistence of EVPN originator ratchets across daemon restart.
