# ADR-0106: Warm checkpoint restore under planned-restart GR

**Status:** Proposed (recommendation: reject ordinary restore)
**Date:** 2026-07-14

## Context

ADR-0104 publishes a bounded, private warm bundle at coordinated shutdown.
The bundle contains eligible Adj-RIB-In views, an MRT artifact, and exact
configuration, resolved import-policy, peer, family, and session-profile
identity. `load_warm_bundle` validates those fields, freshness, artifact
integrity, and MRT semantics, but has no daemon caller. Startup therefore
always converges from an empty RIB.

The apparent next step was to restore the cached routes at boot and select them
before peers finished replaying their tables. That could look like a cheap warm
restart for a route reflector or route server because the publication and
validation machinery already exists.

Source inspection resolved one important semantic question. The checkpoint is
**post-import-policy**:

- transport evaluates import policy and sends only permitted, modified routes
  to RibManager;
- the checkpoint query clones those routes from per-peer Adj-RIB-In, not from
  raw wire input or Loc-RIB;
- `WarmBundleViewKindV1::AdjRibInPostImportPolicy` now names the view correctly;
- the resolved import-policy digest binds identity but does not instruct the
  reader to apply policy again.

Reapplying import policy during any future reader would therefore be wrong.
Non-idempotent actions such as AS-path prepend or MED modification would run
twice. ADR-0040's older pre-policy wording is corrected with this decision.

That verification did not establish a safe convergence win. rustbgpd's
marker-backed startup implements the restarting-speaker procedure in RFC 4724
section 4.1: route selection is deferred until the eligible peers have sent
End-of-RIB, are excluded by the protocol rules, or the bounded
`Selection_Deferral_Timer` expires. The timer deadline is the remaining
planned-restart marker lifetime.

## Decision

### 1. Do not wire V1 warm-bundle routes into startup

Reject ordinary planned-restart route restore on the current protocol and
artifact contract. Keep ADR-0104 as publication and validation infrastructure;
do not add a boot caller that inserts, selects, installs, or advertises its
routes.

The reason is structural, not an implementation inconvenience:

1. Cached routes may be decoded or prepared while selection deferral is active,
   but RFC 4724 does not permit the restarting speaker to select them early.
2. Current-session announces received before EoR are authoritative fresh input
   and replace matching cached identities.
3. When the matching current session sends EoR, every cached identity not
   replayed by that peer must be swept before the EoR can count toward
   convergence. Otherwise a withdrawn route from before restart can survive.
4. When the last eligible EoR releases selection, the cache is therefore either
   replaced by fresh routes or removed. It contributes no selected route that
   the peer replay did not already provide.
5. If EoR does not arrive, the selection-deferral timeout is the marker expiry.
   Retaining unreplayed cache entries beyond that boundary would turn an
   expired planned-restart artifact into an unbounded routing source. They must
   be swept before timer release as well.

A concurrently restarting peer is the one narrow exception to that ordinary
shape: a current OPEN with the Restart State (`R`) bit set excludes that
peer/family from the EoR waiter set. The V1 manifest does not bind the current
`R` or Forwarding State (`F`) bits, and rustbgpd's current waiter projection
does not retain `F`. Cached identities for such a peer could survive the legal
selection point, but that unmeasured concurrent-restart edge is not a safe
basis for this capability. A future proposal must reject current `R=1`
sessions or independently bind both current flags and prove the edge's value
and stale-route safety.

The necessary EoR preparation fence further removes the apparent shortcut.
Downstream EoR cannot be emitted merely because cached bytes were parsed. It
must remain behind the completed inbound reconciliation, route selection, and
ordinary outbound route-payload staging. Exact-export precommit, update-group
handling, writer-channel results, and route-before-EoR ordering remain
authoritative.

An early Loc-RIB recompute or downstream advertisement from cached routes is
explicitly rejected. It would make the implementation faster by weakening the
selection-deferral guarantee that ADR-0040 and RFC 4724 rely on. A conservative
stall is load-bearing here; removing it recreates the class of premature
convergence bug fixed in collision failback.

### 2. Preserve the honest forwarding claim

`forwarding_preserved` remains false for every family. The bundle records BGP
control-plane input; it does not prove that the complete forwarding plane
survived the daemon restart. Neither publication nor a future reader may set
the RFC 4724 Forwarding State bit to true on that evidence.

### 3. Record prerequisites for any future reconsideration

This no-go does not claim that every possible checkpoint use is impossible. It
records the minimum correctness work that a materially different proposal
would still need:

- **Protocol benefit first.** Demonstrate, with an RFC-compliant state machine,
  how the cache shortens a measured RR/route-server convergence path while
  route selection remains deferred until eligible EoRs or timer expiry and
  unreplayed entries are swept before release. A design that requires early
  selection fails this gate.
- **Post-policy semantics.** Reinject already modified routes without import
  policy evaluation or import-policy counter changes. A non-idempotent policy
  fixture must prove exactly one AS-path/MED modification.
- **Distinct recovery state.** Restored-cache identity must not reuse one
  ambiguous stale bit. Conventional RFC 4724 helper stale state, LLGR stale
  state and the `LLGR_STALE` community, refresh-stale state, and a hypothetical
  boot-cache candidate have different creation and sweep rules.
- **Validation identity.** V1 MRT decoding reconstructs unicast routes with
  RPKI `NotFound`, ASPA `Unknown`, and an empty ASPA context. The bundle neither
  binds the VRP/ASPA dataset nor recovers routes that validation-dependent
  import policy denied. RPKI/ASPA-enabled restore remains unsafe until a later
  format binds sufficient dataset and per-route context.
- **Exact admission.** Marker generation and clock domain, boot identity,
  effective configuration, resolved import policy, current session generation,
  peer ASN/router ID, family, Add-Path profile, and current GR restart/forwarding
  flags must match independently of manifest-authored values. Any mismatch is
  cold start, not partial adoption.
- **Pinned streaming input.** A future two-pass reader must retain and rewind
  one descriptor-pinned artifact, hash the exact second-pass decode stream,
  and keep every prepared effect invisible until that digest and the semantic
  counts verify. Both passes must share one monotonic deadline, retain the
  existing manifest/artifact caps, use fallible allocation, and avoid the
  current whole-artifact `Vec<u8>` plus a second unbounded decoded copy.
- **Fresh-wins rollback.** If a future use ever prepares route state, current-
  session announces and withdrawals must win, rollback must remove only cache-
  owned state, and no downstream EoR may cross a failed preparation.

The manifest-JSON fuzz target remains a prerequisite before any daemon boot
path reads the bundle. Fuzzing makes the parser safer; it does not by itself
solve the protocol no-go.

### 4. Recommend OSS-Fuzz submission as the next tranche

Recommend OSS-Fuzz integration instead of warm restore or RIB sharding for the
next bounded hardening tranche. It strengthens existing untrusted-input
boundaries without changing routing semantics and turns the repository's local
fuzz investment into continuous external coverage.

The work should remain small and independently reviewable:

1. **Local readiness.** Land and stabilize the manifest-JSON target, retain the
   wire, policy, EVPN, and MRT target inventory, seed minimal valid corpora,
   and prove sanitizer builds and bounded target execution locally. Each
   parser guard added during this phase needs a mutation that makes its
   regression test or corpus gate fail red when the guard is removed.
2. **Upstream integration.** Submit the staged Dockerfile, build script,
   project metadata, target list, and corpora under an upstream
   `projects/rustbgpd` entry. The receipt pins the public source revision used
   for local `build_fuzzers`, `check_build`, and target runs; the accepted
   integration continues tracking the repository rather than freezing that
   revision. Do not add daemon behavior or a release change.
3. **Operational handoff.** Document reproducer download, local minimization,
   disclosure/triage ownership, and which target owns each input boundary.
   Treat upstream acceptance plus the first successful hosted build as the
   completion gate. OSS-Fuzz eligibility is externally decided; a rejection
   based on project adoption is a truthful stop receipt, not permission to
   inflate scope.

This is hardening, not a headline routing capability. Its value is that it is
correctly scoped, immediately actionable, and prerequisite work for any future
live warm-bundle reader.

### 5. Keep RIB sharding measurement-gated

ADR-0100 already measured the cheap data-parallel hot-loop proposal below its
go threshold. Prefix-range sharding could raise the ceiling, but it changes
nearly every single-owner, lifecycle, query, dirty-resync, and EoR barrier in
RibManager. It needs a named workload that current main demonstrably misses and
a new architecture gate. RIB sharding is not this week's capability.

## Warm-restore reconsideration gate

Do not reopen implementation from `load_warm_bundle` merely because it has zero
callers. Reconsider only when a proposal supplies all of the following:

1. a protocol transcript showing RFC 4724-compliant selection and EoR ordering;
2. a real-daemon cold control and candidate measurement on a disclosed
   RR/route-server fleet shape;
3. a material convergence benefit that survives full EoR and timer fencing;
4. explicit answers for unreplayed-route sweep, validation identity, pinned
   input, bounded memory/time, fresh-wins rollback, and `F=false`;
5. mutation-proven tests for every new gate.

Without that evidence the answer remains no. Publication can continue to serve
forensics, format validation, and future research without forcing a route
restore consumer.

## Consequences

- Startup retains the current RFC 4724 selection-deferral behavior and cannot
  advertise a prior snapshot as converged routing state.
- ADR-0104 remains useful, bounded infrastructure, but its zero-caller loader
  is not treated as proof that a safe capability is one wiring change away.
- The post-import-policy label is verified and documented; any future consumer
  must not double-apply policy.
- RPKI/ASPA validation identity, stale-state separation, streaming/pinning, and
  fresh-input rollback remain explicit blockers rather than hidden follow-up.
- `forwarding_preserved = false` remains truthful.
- The next recommendation is the smaller OSS-Fuzz submission, with RIB
  sharding deferred behind measurement and warm restore behind a new
  RFC-compliant benefit proof.

## References

- RFC 4724, *Graceful Restart Mechanism for BGP*, sections 2 and 4.1:
  <https://www.rfc-editor.org/rfc/rfc4724.html>
- [ADR-0040](0040-gr-restarting-speaker.md), minimal restarting-speaker mode
- [ADR-0100](0100-parallel-rib-manager.md), measured parallel-RIB blueprint
- [ADR-0104](0104-shutdown-warm-checkpoint-publication.md), bounded publication
