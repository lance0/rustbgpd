# ADR-0085: Ethernet Segment interface binding — link-driven drain and same-ESI local bias

**Status:** Accepted
**Date:** 2026-06-12

## Context

ADR-0084 shipped the manual ES drain: an operator can withdraw exactly
one Ethernet Segment's origination state (Type 4, EAD-per-ES,
EAD-per-EVI, local Type 2s) and restore it, with the drained set fanned
out to both origination actors. That primitive was deliberately built
trigger-agnostic — the RPC is one trigger; the production trigger is
the access circuit itself.

Today an ES is pure configuration: `[[ethernet_segments]]` carries an
ESI, member VNIs, and DF-election inputs, but no notion of *which
local interface is the attachment circuit*. Consequences, all observed
in practice:

1. **AC failure produces no withdrawal.** When the access circuit
   dies, the daemon keeps originating the full ES route set; remote
   PEs keep forwarding into a black hole until BGP/hold-timer churn
   discovers the problem some other way. Every production EVPN-MH
   implementation is link-driven here (FRR binds `es-id` to the
   interface; Cumulus documents uplink/link-state tracking driving
   EAD-ES withdrawal), and RFC 8584 §3 explicitly models
   AC-influenced DF candidacy.
2. **No same-ESI local bias in the remote-MAC projection.** The M66
   proof (PR #460) showed a received Type 2 from the peer PE being
   programmed over this PE's own kernel-learned local AC row — an
   in-place FDB port move toward the fabric. Per RFC 7432 §15.1, a
   MAC reachable on a shared ES is *not* a mobility event between the
   member PEs; usurping the local row is wrong while the local AC is
   healthy. A principled bias needs exactly the signal this ADR adds:
   "is the local AC for that ESI up?" (The cache-honesty half — the
   originator observing the port move — is fixed independently; the
   bias removes the usurpation at its root.)
3. **The link inventory is poll-only** (`links.rs` walks
   `LinkHandle::get`); the ROADMAP already tracks `RTNLGRP_LINK`
   eventing. Link-driven drain wants edge-triggered carrier
   transitions with the poll as a backstop — the same event-driven +
   backstop shape the dataplane intent recompute and segment
   re-election already use.

## Decision 1 — `interface` binding on `[[ethernet_segments]]`

Add two optional keys to `[[ethernet_segments]]`:
`interface = "<linkname>"` (the binding) and `recovery_delay_secs`
(the Decision 3 hold-off; meaningful only with `interface` set).
Binding semantics:

- The named link is the ES's attachment circuit. AC health =
  **carrier**: the `IFF_LOWER_UP` bit in the rtnetlink link flags
  (`ifi_flags`) — not `IFLA_OPERSTATE`, which is a separate attribute
  with different semantics, and not admin state: an
  operator running `ip link set ... down` gets the same drain a cable
  pull gets, which is the correct forwarding answer in both cases.
- Unbound segments (no `interface`) behave exactly as today —
  config-driven origination, drain only via the ADR-0084 RPC. The
  binding is opt-in per ES.
- A bound interface that does not exist at startup (or disappears at
  runtime) counts as **down** — fail-closed toward drain, never
  toward originating reachability we cannot serve. Resolution is by
  name on every transition (ifindex can be reused; names are the
  operator contract).
- SIGHUP/runtime config may add, change, or remove the binding;
  changing it re-evaluates health against the new link immediately.

## Decision 2 — drain reasons: operator and link drains compose

The ADR-0084 drained set becomes **reason-keyed**:
`drained: Map<ESI, Set<DrainReason>>` with `DrainReason::Operator`
and `DrainReason::Link`. An ES is drained while the set is non-empty.

- Link down → add `Link`; link up (after the Decision 3 hold-off) →
  remove `Link`.
- `SetEthernetSegmentDrain(drained=true/false)` adds/removes
  `Operator` only.
- **An operator undrain does not override a dead link**, and **link
  recovery does not override an operator drain.** Maintenance flows
  need exactly this: drain manually, do the cable work (link flaps
  freely, changing nothing), undrain manually — origination returns
  only when the link is also healthy.
- The RPC response and the runtime/metrics surface report the reason
  set, so "why is this ES drained" is always answerable
  (`evpn_es_drained{esi, reason}` gauge per reason).
- Actor-facing fanout is unchanged: both actors keep consuming the
  flat drained-ESI set; reasons live only in the coordinator. ADR-0084
  GC (`retain_configured`) drops all reasons with the ES.

## Decision 3 — recovery hold-off on link up

A down→up transition does not undrain immediately. Per-ES
`recovery_delay_secs` (default **30**, range 0–3600) holds the `Link`
reason for that long after carrier returns:

- Rationale: RFC 8584's AC-influenced DF model (§3) and its DF-wait
  behavior exist precisely so a recovering attachment circuit does
  not attract traffic before the segment has re-converged (bridge
  port re-learning, DF re-election propagation). FRR ships the same
  concept as its EVPN-MH startup/recovery delay. A flapping
  circuit also gets natural damping: the timer re-arms on every up
  edge, so an unstable link stays drained until it holds carrier for
  the full window.
- Down is always immediate — only recovery is delayed.
- Startup is **not** held: the first link probe's state applies
  directly (an ES whose AC is up at boot originates immediately, as
  today). A FRR-style global startup delay is explicitly out of scope
  (see Out of scope) — recovery delay arms on observed transitions
  only.

## Decision 4 — `RTNLGRP_LINK` subscription with poll backstop

A daemon-side link monitor subscribes to `RTNLGRP_LINK` and projects
carrier state for the bound link names into a watch channel the drain
coordinator consumes; the existing poll-based inventory walk doubles
as the backstop/initial-state source (subscription gap or missed
message heals at the next poll). The parser keeps the established
discipline: scalars out of `LinkMessage`, no enum round-tripping. This
lands the ROADMAP "`RTNLGRP_LINK` eventing" item for the attributes
this feature needs (ifindex, name, link flags / carrier); the wider
inventory stays poll-based until something else needs eventing.

## Decision 5 — same-ESI local bias in the remote-MAC projection

The binding feeds a per-`(ESI, VNI)` **bias-eligibility** snapshot to
the dataplane supervisor, published by the segment actor alongside the
existing BUM-enforcement flow. Projection rule (`project_one`):

- A remote MAC/MAC-IP route whose ESI is **locally attached, healthy,
  not drained — and for which this PE is entitled to forward** does
  not program a remote FDB row: the local AC is then the correct
  egress, and RFC 7432 §15.1 says same-ES reachability is not
  mobility. "Entitled to forward" is redundancy-mode-aware:
  **all-active** — always (every member PE forwards); **single-active
  — only when this PE is the DF for that `(ESI, VNI)`**. A healthy
  single-active *backup* keeps the remote row toward the active PE —
  its own AC is non-forwarding by definition, and biasing there would
  become a blackhole the moment the non-DF all-traffic AC blocking
  gap is closed. The bias-eligibility snapshot is therefore published
  by the **segment actor** (the one owner of both redundancy mode and
  the per-`(ESI, VNI)` DF role), composed with link health, rather
  than derived from link state alone.
- The bias lifts the moment the attachment is unhealthy **or
  drained**: remote rows program and the peer PE takes over — which
  is exactly the M66 takeover behavior, now by design instead of by
  usurpation.
- Unbound segments get no bias (health unknowable) — today's behavior
  is preserved, and the port-move observation fix keeps the
  originator's cache honest in that configuration.

## Consequences

- An AC failure on a bound ES now produces the RFC 7432 §8.2
  mass-withdraw wire shape automatically, end-to-end with ADR-0083's
  receive-side swap: link down → drain → EAD withdrawal → remote
  backup swap. The M66 job gains a sibling phase (or M67) where the
  stimulus is `ip link set ... down` on the PE instead of the RPC.
- The ADR-0084 "restart clears drain" caveat softens for bound
  segments: link state is re-read at startup, so a dead AC re-drains
  on boot without any persisted state.
- Reason-keyed drain changes the `SetEthernetSegmentDrain` response
  semantics slightly (`drained` reflects the composed state; `changed`
  reflects the operator reason). The CLI renders the reason set.
- The non-DF full-AC-blocking gap (tracked on the ROADMAP) is *not*
  closed by this ADR, but the binding provides the port handle a
  per-role traffic gate needs; that work can follow without new
  config surface.

## Out of scope

- **Persisted drain across restarts** (ADR-0084 deferral stands;
  bound segments now self-correct, which removes most of the demand).
- **Global startup delay** (FRR-style "don't originate anything for N
  minutes after boot"). Different problem (whole-PE readiness), wants
  its own knob if operators ask.
- **Bond/team member-level tracking** — the binding watches one named
  link; if the AC is a bond, bind the bond device (its carrier
  already aggregates member health).
- **Non-DF all-traffic AC blocking** — separate ROADMAP item, as
  above.

## Cross-references

- ADR-0083 (single-active backup path — the receive-side repair this
  trigger feeds), ADR-0084 (drain primitive + two-actor fanout),
  ADR-0057 (DF election + Gate 8b BUM enforcement), ADR-0054 (kernel
  ownership discipline).
- RFC 7432 §8.2/§8.2.1/§15.1, RFC 8584 §3.
- M66 (`tests/interop/m66-evpn-es-drain-handover.clab.yml`) — the
  proof that motivated Decision 5 and will regression-pin Decisions
  1–3.
