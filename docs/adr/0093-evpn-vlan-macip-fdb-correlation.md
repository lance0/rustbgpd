# ADR-0093: VLAN MAC+IP attribution via FDB correlation on raw bridge ifindexes

**Status:** Proposed
**Date:** 2026-06-19

> Draft / stub. Frames the problem and the proposed correlation design.
> Lower priority than [ADR-0091](0091-evpn-managed-netdev-creation.md) — see
> "Priority" below. Decisions marked *(proposed)* are not final.

## Context

ADR-0089 shipped local MAC+IP (ARP/ND) VLAN attribution **via VLAN upper
devices** (e.g. `brvlan.10`): the upper's ifindex encodes exactly one VLAN, so
an AF_INET/AF_INET6 neighbor event on it attributes cleanly to a VNI. ARP/ND
neighbor events that arrive on the **raw `vlan_filtering=1` bridge ifindex**
carry no VLAN identity (Linux does not report bridge VLAN on the neighbour
message there), so they **fail closed** — no local Type 2 MAC+IP observation is
emitted. ADR-0089 left lifting that gap to "a future FDB-correlation design
that proves freshness and ambiguity handling." This ADR proposes that design.

The bridge **FDB** *does* carry the VLAN for a MAC (`NDA_VLAN`). So in principle
the VLAN for a MAC+IP neighbour can be recovered by correlating the neighbour's
MAC against the FDB. The risk is doing this without misattributing a host to
the wrong tenant under races or ambiguity.

## Decision

### 1. Infer VLAN by correlating the MAC+IP neighbour with the bridge FDB *(proposed)*

For an ARP/ND event on a raw `vlan_filtering=1` bridge ifindex, look up the
neighbour's MAC in the bridge FDB; if the MAC resolves to exactly one VLAN that
maps to a configured `bridge_vlan`/VNI, attribute the MAC+IP to that VNI.

### 2. Ambiguity ⇒ fail closed *(proposed)*

If the MAC is present in **more than one** VLAN in the FDB (or maps to no
configured VLAN), drop the observation. Never guess.

### 3. Freshness ⇒ fail closed *(proposed, the hard part)*

The neighbour event and the FDB learn race. The correlation must only fire when
the FDB entry is **consistent and fresh** relative to the neighbour event;
define a freshness window / ordering rule (and the handling for "neighbour seen
before the MAC is in the FDB"). A stale or racing correlation must drop, not
emit.

### 4. Preserve the fail-closed default *(proposed)*

Any miss, ambiguity, or freshness failure keeps today's behavior (drop /
"not ours"), preserving the "wrong tenant is worse than no import" posture.
This path only ever *adds* attributions it can prove.

## Open questions

- The freshness window and the neigh-before-FDB-learn ordering rule.
- On-demand FDB query per neighbour event vs. maintaining a correlated cache.
- Interaction with managed netdev (ADR-0091): if rustbgpd creates VLAN **upper**
  devices, the already-working upper-device path covers these deployments and
  this ADR becomes largely unnecessary.

## Priority

**Lower than ADR-0091.** The common deployment is covered two ways already: VLAN
upper devices (shipped, ADR-0089) and — once ADR-0091 lands — rustbgpd creating
those uppers itself. This ADR matters only for **operator-built raw
`vlan_filtering=1` bridges** where the operator chose not to use VLAN upper
devices *and* needs MAC+IP origination. Worth designing so the gap is closed and
documented, but it is a narrow-audience refinement, not a blocker.

## Consequences

- Closes the last raw-bridge-ifindex MAC+IP fail-closed gap for hand-built
  VLAN-aware bridges.
- Adds a race-sensitive correlation path; the freshness/ambiguity rules carry
  the correctness weight, hence the fail-closed default.

## Dependencies and relationships

- **Builds on:** ADR-0089 (VLAN model, `NDA_VLAN` FDB, the VLAN-upper path).
- **Eased / possibly obviated by:** ADR-0091 (managed VLAN-upper creation).
- **Independent of:** ADR-0092.

## Rejected Alternatives

- **Attribute to the default/untagged VLAN** — silent misattribution; rejected
  for the same reason ADR-0088 rejected "program only the untagged VLAN."
- **Emit unattributed and let policy sort it out** — breaks tenant isolation.

## Test Obligations

- Unambiguous single-VLAN MAC ⇒ correct VNI attribution.
- Same MAC in two VLANs ⇒ fail closed.
- Neighbour-before-FDB-learn race ⇒ fail closed (no misattribution).
- Regression: VLAN-upper-device path and the raw-ifindex default-fail-closed
  behavior are unchanged when correlation does not fire.
