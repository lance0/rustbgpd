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

## Decision

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

Concretely, the demand may approach **zero** once ADR-0091 ships VLAN-upper
creation: operators who let rustbgpd own the topology get MAC+IP attribution for
free via the proven upper-device path. This ADR may therefore be **retired
without implementation** if ADR-0091 VLAN-upper adoption is high. It stays
Proposed precisely so that retirement is a deliberate call, not an implicit one.

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

### 2. Bound the FDB event ledger

The FDB event ledger must never grow without limit. A future implementation
must define both:

- a **TTL bound** for event entries; and
- a **hard size bound** (global and/or per bridge).

The TTL must be at least as long as the freshness window, and may be longer if
needed for move/delete diagnostics. Eviction is fail-closed: an evicted or
expired ledger entry cannot authorize correlation. Under size pressure, evict
the oldest event-time / least-recently-used entries first, increment an
eviction/drop reason, and let the later raw bridge neighbor event fall through
the normal "not attributable" path. A VM migration storm, STP reconvergence, or
port flap must not turn this optional feature into unbounded memory growth.

### 3. Attribute only one fresh, configured, local candidate

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
VXLAN/remote row, dump error, evicted ledger row, or neighbor-before-FDB
ordering drops.

### 4. Deletes and moves use prior add-cache state

Neighbor delete events must not newly infer VLAN from the FDB. A delete may
withdraw only if a prior accepted add cached the exact `(ifindex, IP) ->
(MAC, VNI)` attribution. If no accepted add exists, the delete drops.

A **move is not just an add.** A neighbor add that overwrites a prior
`(ifindex, IP)` attribution with a *different* `(MAC, VNI)` — a host that moved
VLANs, e.g. VLAN 10 -> VLAN 20 — must **withdraw the prior `(MAC, VNI)` Type 2
from the old EVI** as well as originate the new one. The add-cache must
therefore retain the prior attribution so the overwrite drives that withdrawal.
Without it, a moved host leaves a stale Type 2 in the old VNI until it ages out
or remote peers apply MAC-mobility sequencing — the local daemon would never
withdraw it. The original ADR-0089 VLAN-upper path does not have this gap
because the upper-device ifindex carries the VLAN directly.

### 5. The freshness window is a heuristic and must be calibrated before implementation

The kernel provides **no ordering guarantee** across the AF_INET / AF_INET6 and
AF_BRIDGE `RTNLGRP_NEIGH` multicast groups: the ARP/ND event can arrive before,
after, or concurrently with the corresponding FDB event. The freshness window
is therefore a **heuristic, not a proof** — it bounds the race, it does not
eliminate it. The ADR does not choose a value; calibration must **measure the
worst-case inter-arrival skew under load and set the window to roughly 2-3× it**.
On a busy system that may land in **seconds, not milliseconds**, which makes the
feature even more conservative (more drops). The window must still be strict
enough to prevent MAC-move and duplicate-VLAN misattribution.

### 6. Dropped correlations must be observable, distinct from "host has no IP"

Because every condition in Decision 3's list must hold simultaneously, any FDB
churn (VM migration, STP topology change, port flap) makes the feature drop a
meaningful fraction of MAC+IP observations on a busy system. The operator then
sees a Type 2 MAC route with **no** corresponding MAC+IP route for some hosts,
and cannot tell "correlation dropped" from "the host genuinely has no IP." A
future implementation must expose a **per-reason drop counter / observation
status** (ambiguous-vlan, unconfigured-vlan, stale-event, seeded-only,
ordering-miss, …) in the EVPN status surface so the gap is diagnosable, not
silent — the same "fail-closed must be observable" principle as ADR-0091
Decision 6.

## Consequences

### Positive

- Documents the last raw bridge-ifindex MAC+IP attribution gap.
- Preserves the tenant-isolation posture: ambiguity drops.
- Leaves a plausible implementation path if operator demand appears.

### Negative

- Adds a race-sensitive inference path if implemented later.
- Requires more state than the VLAN-upper path: FDB event ledger,
  freshness timestamps, on-demand FDB validation, size/TTL eviction, and a
  prior-add cache that also drives move-withdrawals (Decision 4).
- Even a conservative implementation may be too strict for some busy systems;
  misses are easily confused with "host has no IP" without the per-reason drop
  surface (Decision 6).

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
  - TTL-expired and size-evicted FDB ledger rows drop and increment an
    observable eviction/drop reason;
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
