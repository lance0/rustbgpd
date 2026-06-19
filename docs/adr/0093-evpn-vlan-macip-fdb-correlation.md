# ADR-0093: VLAN MAC+IP attribution via FDB correlation on raw bridge ifindexes

**Status:** Proposed
**Date:** 2026-06-19

## Context

ADR-0089 shipped local MAC+IP (ARP/ND) VLAN attribution through VLAN upper
devices such as `brvlan.10`. A neighbor event on a VLAN upper ifindex carries
an unambiguous local VLAN identity because the upper device itself represents
exactly one `(bridge, VLAN)` pair. rustbgpd maps that upper ifindex to one
configured `bridge_vlan` / VNI and can safely originate Type 2 MAC+IP.

ARP/ND neighbor events that arrive on the raw `vlan_filtering=1` bridge
ifindex are different. The AF_INET / AF_INET6 neighbor message does not carry
the bridge VLAN. rustbgpd therefore fails closed today: no local Type 2
MAC+IP observation is emitted for raw bridge-ifindex neighbor events on
VLAN-aware bridges.

The bridge FDB does carry VLAN information for MAC rows (`NDA_VLAN`), so in
principle the daemon could correlate `(IP, MAC)` from the neighbor event with
`(MAC, VLAN)` from the bridge FDB. The risk is event ordering: a current FDB
row does not by itself prove it was learned for the same ARP/ND edge, and
misattributing a host to the wrong tenant is worse than dropping the
observation.

This ADR records the candidate design and the guardrails. It does **not**
accept implementation yet.

## Current Decision

### 1. Keep the raw bridge path fail-closed by default

The shipped behavior remains correct:

- VLAN upper devices can emit MAC+IP observations.
- Raw `vlan_filtering=1` bridge-ifindex ARP/ND remains unattributed and is
  dropped.
- Drops are normal "not ours / not attributable" classifier outcomes, not
  dataplane errors.

### 2. Defer this feature behind managed VLAN-upper creation

ADR-0091 managed netdev creation can create VLAN upper devices for operators
who want rustbgpd to own the Linux topology. That path uses the already-proven
MAC+IP attribution model and avoids this race-sensitive correlation problem.

Raw bridge FDB correlation is therefore lower priority and demand-shaped. It
matters only for hand-built raw `vlan_filtering=1` bridge deployments where
the operator does not use VLAN uppers and still needs MAC+IP origination.

## Candidate Design If Later Accepted

### 1. Use event-cache freshness plus on-demand validation

On-demand FDB lookup alone is insufficient. It can show that a MAC currently
has a VLAN-scoped FDB row, but it cannot prove that the row was learned for
the same neighbor event.

A future implementation must combine:

- an in-memory FDB event ledger built from AF_BRIDGE RTNLGRP_NEIGH events; and
- an on-demand AF_BRIDGE FDB validation at the raw bridge neighbor event.

Seeded dump rows are not fresh. They can initialize state for deletes or
diagnostics, but they cannot authorize a new MAC+IP origination.

### 2. Attribute only one fresh, configured, local candidate

For a raw bridge AF_INET / AF_INET6 neighbor add, a future implementation may
emit only when all of the following hold:

- the neighbor event has a valid NUD state and advertisable host IP;
- the MAC has exactly one fresh FDB-event candidate on an eligible non-VXLAN
  local bridge port;
- that candidate VLAN maps to exactly one configured `bridge_vlan` / VNI;
- an on-demand FDB validation confirms exactly one current eligible row for
  the same bridge and MAC;
- the row is not a VXLAN, `extern_learn`, remote, or otherwise non-local row;
- the freshness window is satisfied.

Any miss, duplicate VLAN, unconfigured VLAN, stale event, seeded-only row,
VXLAN/remote row, dump error, or neighbor-before-FDB ordering drops.

### 3. Deletes use only prior add-cache state

Neighbor delete events must not newly infer VLAN from the FDB. A delete may
withdraw only if a prior accepted add cached the exact `(ifindex, IP) ->
(MAC, VNI)` attribution. If no accepted add exists, the delete drops.

### 4. The freshness window must be calibrated before implementation

The ADR does not choose a concrete freshness window. That value needs a
kernel/netns calibration proof under realistic event ordering. The window
must be strict enough to prevent MAC-move and duplicate-VLAN misattribution,
even if that means the feature drops more often on busy systems.

## Consequences

### Positive

- Documents the last raw bridge-ifindex MAC+IP attribution gap.
- Preserves the tenant-isolation posture: ambiguity drops.
- Leaves a plausible implementation path if operator demand appears.

### Negative

- Adds a race-sensitive inference path if implemented later.
- Requires more state than the VLAN-upper path: FDB event ledger,
  freshness timestamps, on-demand FDB validation, and prior-add delete cache.
- Even a conservative implementation may be too strict for some busy systems.

## Dependencies and relationships

- **Builds on:** ADR-0089 (VLAN-aware bridge model, `NDA_VLAN` FDB parsing,
  VLAN upper attribution).
- **Deferred behind:** ADR-0091 managed netdev creation, because managed VLAN
  uppers cover the common safe path.
- **Independent of:** ADR-0092 true VLAN-Aware Bundle service.

## Rejected Alternatives

### Attribute to the default or untagged VLAN

Rejected. The raw bridge neighbor message does not carry that identity, and
guessing would create cross-tenant leakage.

### Use on-demand FDB lookup alone

Rejected. It proves current state, not event ordering or freshness.

### Treat seeded dump rows as fresh

Rejected. A startup dump can contain old FDB rows unrelated to a later
neighbor event.

### Emit unattributed MAC+IP and let policy sort it out

Rejected. The Type 2 route needs the correct EVPN instance/VNI before policy
can safely reason about it.

## Test Obligations If Accepted Later

- Unit tests:
  - one fresh local VLAN candidate emits;
  - duplicate VLAN candidates drop;
  - unconfigured VLAN drops;
  - seeded-only FDB row drops;
  - neighbor-before-FDB drops;
  - VXLAN/extern-learn/remote FDB rows drop;
  - delete withdraws only from prior accepted add-cache state.
- netns tests:
  - raw bridge neighbor + fresh FDB row in VLAN 10 emits VNI 100 only when
    freshness is satisfied;
  - same MAC in VLAN 10 and VLAN 20 drops;
  - stale FDB plus fresh neighbor drops;
  - VLAN-upper behavior remains unchanged.

## References

- Linux neighbor UAPI, including `NDA_VLAN` and NUD state.
  <https://github.com/torvalds/linux/blob/master/include/uapi/linux/neighbour.h>
- Linux bridge FDB implementation, keyed by MAC and VLAN and emitting
  `NDA_VLAN` / `NDA_CACHEINFO`.
  <https://github.com/torvalds/linux/blob/master/net/bridge/br_fdb.c>
- iproute2 `bridge fdb` support for `vlan VID`.
  <https://github.com/iproute2/iproute2/blob/main/bridge/fdb.c>
- ADR-0089 local MAC+IP VLAN-upper attribution proof.
