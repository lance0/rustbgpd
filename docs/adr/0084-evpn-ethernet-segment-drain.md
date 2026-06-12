# ADR-0084: Runtime Ethernet Segment drain

**Status:** Accepted
**Date:** 2026-06-12

## Context

ADR-0083 gave remote PEs a fast repair path for a single-active
Ethernet Segment: when the active PE's EAD-per-ES withdraws, every
remote VTEP atomically retargets the segment's MACs at the pre-created
backup PE. What rustbgpd could not do until now is *produce* that
stimulus deliberately. An operator planning access-circuit maintenance
on a multi-homed CE had two bad options: take the circuit down and let
the remote side discover it through hold-timer/BGP churn, or restart
the daemon with the ES removed from config (which tears down far more
than the one segment).

The missing primitive is a **manual ES drain**: withdraw exactly the
origination state tied to one Ethernet Segment — gracefully, before
the maintenance — and restore it afterwards without re-learning from
scratch. The same stimulus shape is what RFC 7432's fast-convergence
model expects (§8.2: EAD withdrawal with MAC routes converging via
backup paths), and it is also the building block a future
interface-bound automation trigger needs (ROADMAP "origination-side
withdrawal stimulus": an ES has no AC/interface binding today, so the
daemon cannot emit the mass-withdraw shape on its own when the access
circuit fails).

### Why drain state must be visible to both actors

Two independent actors originate per-ES state:

- the **segment actor** (`src/evpn_segment.rs`) owns the ES's own
  route classes — Type 4 (ES), Type 1 EAD-per-ES, Type 1 EAD-per-EVI —
  plus DF election and the BUM enforcement snapshot;
- the **local Type 2 originator** (`src/evpn_originator/`) stamps the
  ES's ESI onto local MAC / MAC+IP routes for the member VNIs and
  re-originates them from kernel events and cached state.

A drain that lived only in the segment actor would withdraw the Type
4/EAD routes but leave the member VNIs' local Type 2 routes advertised
— remote PEs would keep forwarding unicast at the drained PE. Worse,
the originator's *replay machinery actively fights a one-sided drain*:
`apply_runtime_model` (`src/evpn_originator/lifecycle.rs`)
unconditionally replays cached local MACs after any model change that
drains a VNI's routes (`replay_local_mac_after_recovery`), and fresh
kernel FDB events re-originate withdrawn MACs within one poll
interval. The drain therefore has to be a first-class input to both
actors: the originator needs a **drain-without-replay** mode that the
existing redefine/ESI-change paths deliberately do not have.

### Why Type 4 is withdrawn too

Draining only the EAD routes would leave this PE in peers' DF
candidate sets (Type 4 is the election membership signal, RFC 7432
§8.5). A drained PE that remains DF-electable can win BUM forwarding
duty for a segment whose access circuit is about to go down. With-
drawing the Type 4 exits DF election cleanly; remote PEs re-elect
among the remaining candidates while the drained PE's own election is
suppressed locally.

## Decision

**Add a runtime-only, in-memory ES drain primitive, owned by the
daemon coordinator and pushed to both origination actors, exposed via
`EvpnService.SetEthernetSegmentDrain` (gRPC) and
`rustbgpctl evpn es drain|undrain <esi>` (CLI).**

### Numbered decisions

1. **Drain semantics (RFC 7432 fast-convergence shape).** Draining an
   ESI: (a) the segment actor withdraws that ES's Type 4, EAD-per-ES,
   and all EAD-per-EVI routes, keeping its `SegmentState` so undrain
   can re-originate; (b) the local originator withdraws the member
   VNIs' local Type 2 MAC and MAC+IP routes WITHOUT clearing the local
   observation caches, and suppresses new local-MAC originations for
   those VNIs while drained (kernel events keep updating the caches so
   undrain replays the latest state, not a stale snapshot). Undrain
   re-originates Type 4 + EADs, re-runs DF election, republishes the
   BUM enforcement snapshot, and replays the cached local MAC/IP state
   through the existing quarantine-respecting replay primitive.
2. **One owner, two consumers.** The drained-ESI set lives in a single
   coordinator-owned structure (`src/evpn_es_drain.rs`). Mutations are
   serialized by the same EVPN runtime apply lock that ADR-0063
   applies and SIGHUP reloads take, then pushed to the segment actor
   (a third watch input alongside its instance and segment snapshots)
   and to the originator (a field on its runtime model, so
   `apply_runtime_model` classifies drain transitions exactly like
   instance/ESI-map changes).
3. **Drain survives snapshot republish; config removal GCs it.** A
   SIGHUP or runtime apply that keeps a drained ES configured must not
   resurrect its routes: the segment actor skips drained ESIs in
   startup/election/snapshot-reapply, and the originator model carries
   the drained set on every publish. If a runtime apply *removes* a
   drained ES from config, the coordinator drops its drain entry on
   segment-set replace — a later re-add of the same ESI starts
   undrained, never silently suppressed by a stale entry.
4. **Runtime-only, in-memory (v1).** Restart clears the drain and
   replays configured state. This is deliberate: the primitive guards
   a planned maintenance window on a *running* daemon. Persisting
   drain state would add a second persisted-intent surface (and its
   crash-consistency questions, see ADR-0079) for a state that an
   operator re-applies in seconds. Persisted drain is explicitly
   deferred until operator demand shows restart-spanning windows.
5. **Idempotent, validated RPC.** One RPC covers both directions
   (`drained: true|false`). Unknown/unconfigured ESIs return
   `NOT_FOUND`. Repeating the current state is an idempotent no-op
   (`changed = false`). The RPC is `operator_only` (ADR-0064): a drain
   redirects live customer traffic onto remote PEs' backup paths —
   traffic-impacting origination control, a step above the per-key,
   restorative duplicate-MAC clear.
6. **SVI-MAC routes are out of scope.** The SVI actor's Type 2 (the
   gateway bridge MAC, RFC 9135 §6.1) stays advertised while drained:
   it advertises the IRB gateway function, which is not tied to the
   drained access circuit.

## Options considered

- **Drain via config edit (remove the ES + reapply).** Works today via
  ADR-0063, but conflates "maintenance pause" with "deprovision": the
  ESI label is released, EAD/Type 4 state is rebuilt from scratch on
  re-add, and the originator replays under a changed ESI map rather
  than restoring identical state. Rejected as the operator workflow.
- **Drain state inside the segment actor only.** Rejected — see
  Context; the originator's replay machinery and kernel-event
  origination resurrect the member VNIs' Type 2 routes.
- **Persisted drain (survive restart).** Deferred (Decision 4).
- **Interface-bound automatic drain.** The right end state for AC
  failure (the daemon observes the access interface and emits the
  mass-withdraw shape itself), but it needs an ES↔interface binding
  model that does not exist yet. This ADR ships the shared
  "drain ESI without replay" primitive that trigger will reuse
  (`apply_ethernet_segment_drain` is deliberately separate from the
  RPC hook); the binding + trigger gets its own ADR.

## Consequences

- Operators get a graceful pre-maintenance drain whose remote-side
  repair is the already-proven ADR-0083 backup swap (M65).
- The originator gains a genuine drain-without-replay mode; the
  drain/undrain transitions ride the same model-diff classification as
  removes/redefines/ESI-map changes, so rollback paths in the runtime
  converger publish drained state consistently.
- A failed runtime apply that GC'd a drain entry does not restore it
  on rollback. This is deliberate and conservative: a lost drain means
  routes re-advertise (operator re-drains); restoring one could
  silently re-suppress an ES the operator believes undrained.
- Duplicate-MAC quarantines and the drain compose: undrain replays are
  quarantine-respecting, and quarantine recovery while drained keeps
  the MAC withdrawn until undrain.
- An interop M-job proving the drain against a remote PE's backup swap
  is a planned follow-up (the M65 topology already exercises the
  receive side of the same wire shape).

## References

- RFC 7432 §8.2 (mass withdrawal), §8.5 (DF election membership),
  §14 (aliasing / EAD routes)
- ADR-0063 (EVPN runtime mutation coordinator), ADR-0064 (gRPC
  authorization tiers), ADR-0079 (persisted-state posture),
  ADR-0083 (single-active backup-path pre-install)
- `src/evpn_es_drain.rs`, `src/evpn_segment.rs`,
  `src/evpn_originator/lifecycle.rs`
