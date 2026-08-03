# ADR-0123: ASPA draft-v27 mitigation requires lossless retention

**Status:** Proposed (behavior activation NO-GO until retention gates pass)
**Date:** 2026-08-03

## Context

ADR-0049 ships ASPA verification for eligible IPv4/IPv6-unicast edge-ingress
routes. The verifier produces `Valid`, `Unknown`, or `Invalid`; import policy
can match those states; admitted routes are revalidated when the ASPA dataset
changes.

The mitigation recommendation changed after the original decision. Section
5.6 of `draft-ietf-sidrops-aspa-verification-27` couples three requirements:

- an Invalid route should be ineligible for route selection;
- that route must remain in Adj-RIB-In for later re-evaluation; and
- Valid and Unknown routes should have equal preference.

The retention clause points to RFC 9324. Its Sections 4 and 5 require a BGP
speaker applying RPKI-based drop policy to keep a full Adj-RIB-In or at least
the dropped routes, and explain that local retention avoids imposing Route
Refresh work on neighbors when validation data change. RFC 9324 names ASPA as
the same future policy class. A diagnostic record that cannot reproduce the
route is not the retained route those documents describe.

### Shipped boundary

The current implementation deliberately does not claim that contract:

- `crates/rib/src/best_path.rs` (`aspa_preference`, `cmp_chain`) ranks
  `Valid > Unknown > Invalid`. Invalid remains eligible and can win when no
  better candidate exists. Valid and Unknown do not have parity.
- `crates/transport/src/session/inbound.rs` evaluates ASPA before import
  policy, but only permitted, policy-modified routes are sent to the RIB. An
  explicit `match_aspa_validation = "invalid"` deny therefore discards the
  route from locally selectable route state.
- `crates/rib/src/manager/distribution/unicast.rs`
  (`process_announce_chunk`) retains admitted routes, and
  `crates/rib/src/manager/graceful_restart.rs`
  (`handle_aspa_cache_update`) revalidates that admitted set. This does not
  recover a route rejected before RIB insertion.
- `src/peer_manager/policy.rs`
  (`soft_reset_import_validation_dependents`) requests inbound Route Refresh
  from established peers whose import policy depends on ASPA after a dataset
  update. Failure or lack of Route Refresh capability leaves no local source
  from which to reconstruct a rejected route.
- `crates/transport/src/session/rejected_routes.rs` is an optional per-session
  diagnostic LRU. It evicts by entry count, truncates the rendered AS_PATH and
  detail, caps community vectors, and resets with the session. It is useful for
  `ListRejectedRoutes`; it is not a lossless, locally re-evaluable Adj-RIB-In.

This ADR changes no routing behavior. In particular, it does not amend the
shipped ASPA ranking or make Invalid implicitly ineligible.

## Decision

### Accept the target, defer activation

The target behavior for the ADR-0049 applicability scope is draft-v27 §5.6:

1. `Invalid` is excluded from route selection and multipath candidate sets.
2. `Valid` and `Unknown` have identical selection preference; ordinary BGP
   attributes decide between them.
3. The validation state remains visible to policy, telemetry, and diagnostics.
   Operators may still apply stricter explicit import or export policy.

Do not implement either selection change until lossless local retention is in
place. Valid/Unknown parity and Invalid ineligibility activate together; an
intermediate ranking would create another behavior epoch without satisfying
the draft's complete mitigation.

### Retention contract required first

The prerequisite is a pre-import-policy Adj-RIB-In view sufficient to replay
the local decision without another UPDATE from the peer. It must:

- retain every eligible eBGP IPv4/IPv6-unicast route identity, including
  Add-Path ID, original decoded path attributes and next-hop identity, ASPA
  verification context, peer/session generation, and the inputs needed to run
  the effective import policy again;
- preserve the input before policy modifications. Re-evaluating a route whose
  AS_PATH or attributes were already rewritten can produce a different answer;
- represent announcements, replacements, explicit withdrawals, route-refresh
  epochs, End-of-RIB, session replacement, and GR/LLGR lifecycle without stale
  session work resurrecting withdrawn routes;
- re-run ASPA verification and ASPA-dependent import policy locally when the
  ASPA snapshot changes, then reconcile admitted routes and best path from one
  generation-fenced result;
- retain complete route semantics. Entry-count eviction, truncated attributes,
  summaries, logs, BMP events, or persistence that cannot reproduce the route
  do not satisfy the gate; and
- be enabled and disabled only through a global operation. A per-peer switch
  would create the inconsistent behavior RFC 9324 Section 4 rejects.

The existing rejected-route LRU remains separate and bounded for operator
diagnostics. It may point at retained state, but it must not become the
authoritative replay store or inherit an unbounded observability surface.

### Staged adoption and rollback

1. **Current behavior:** retain the shipped ladder and Route Refresh fallback.
   Documentation may name the draft-v27 target but must not claim mitigation
   conformance.
2. **Retention shadow:** populate and lifecycle-test the lossless view with no
   change to import admission, best path, export, or refresh behavior. Compare
   local replay results with live processing and measure memory and refresh
   cost on disclosed full-table and route-server shapes.
3. **Opt-in mitigation:** behind one global control, require retention to be
   healthy, stop ASPA-cache-driven Route Refresh, and atomically apply Invalid
   ineligibility plus Valid/Unknown parity. The control must not allow
   mitigation while retention is absent or incomplete.
4. **Release-boundary default decision:** only after the opt-in receipts pass,
   decide in a separate ADR or release decision whether a future release makes
   mitigation the default. The opt-in implementation does not authorize that
   flip; memory, convergence, and rollback evidence must be reviewed first.

Rollback from either activation stage returns to the shadow stage: keep the
retained view, restore the current three-level ladder, locally re-run admission
and selection, and reconcile exports. Rollback must not require peer Route
Refresh or a daemon restart. Deleting retained state is a later, explicit
operation after the rollback has converged.

### Go / no-go gate for behavior

The future behavior-activation change is **GO** only when all of the following
are proved:

1. Lossless replay covers IPv4/IPv6 unicast, Add-Path, policy modification,
   withdraw/replace, refresh, flap, and GR/LLGR lifecycle with generation
   fencing. Each lifecycle guard has a mutation-proven red test.
2. An ASPA `Invalid -> Valid`, `Valid -> Invalid`, and `Unknown` transition
   converges admitted and previously ineligible routes without emitting Route
   Refresh. A peer that did not negotiate Route Refresh passes the same proof.
3. Every best-path, ORR, multipath, per-client-best, advertised-RIB, and explain
   path excludes Invalid and treats Valid/Unknown equally. Partial activation
   is impossible.
4. A disclosed full-table and route-server receipt measures steady-state
   retained bytes per path, peak dataset-swap memory, replay CPU, actor
   responsiveness, and convergence time against immediately preceding main.
5. The global enable, disable, incomplete-retention refusal, and local rollback
   paths converge without route resurrection, hidden peer dependency, or
   mixed per-peer semantics.

The answer remains **NO-GO** if the candidate relies on the diagnostic LRU,
attribute truncation, peer replay, an eviction cap that can discard an
authoritative route, or an unmeasured assumption that full-table duplication is
affordable.

## Consequences

- rustbgpd keeps its shipped ASPA ranking until the data needed for safe
  re-evaluation exists; this ADR is not a release behavior claim.
- The eventual mitigation aligns Invalid handling and Valid/Unknown preference
  with draft-v27 §5.6 as one observable change.
- Lossless pre-policy retention adds material memory, ownership, lifecycle, and
  dataset-swap CPU cost. Attribute sharing and bounded work batches may reduce
  that cost, but cannot weaken replay completeness.
- ASPA-cache convergence stops depending on a neighbor's Route Refresh support
  once mitigation activates. Ordinary operator policy changes remain outside
  this ADR unless the retained view is deliberately reused for them later.
- The bounded rejected-route surface remains cheap and lossy by design; it
  answers diagnostic queries but never proves retention conformance.

## Current validation gate

Executable mitigation proof is N/A for this docs-only Proposed ADR. The current
gate is source-path verification of the shipped boundary, primary-source link
validation, Markdown checks, and a diff proving no behavior, schema, tests,
release notes, or roadmap changed.

## References

- `draft-ietf-sidrops-aspa-verification-27`,
  [Section 5.6, Mitigation Policy](https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-verification-27#section-5.6)
- RFC 9324, [Section 4, Keeping Partial Adj-RIB-In Data](https://www.rfc-editor.org/rfc/rfc9324.html#section-4)
  and [Section 5, Operational Recommendations](https://www.rfc-editor.org/rfc/rfc9324.html#section-5)
- [ADR-0049](0049-aspa-verification.md), ASPA path verification and the
  currently shipped selection policy
