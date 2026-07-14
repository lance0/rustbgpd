# ADR-0104: Shutdown warm-checkpoint publication without boot restore

**Status:** Accepted
**Date:** 2026-07-13

## Context

ADR-0040's planned-restart marker lets rustbgpd honestly advertise Graceful
Restart `R=1`, with `forwarding_preserved = false`, while routing state is
relearned from peers. Future warm-start work needs a durable input that is
bound to the exact live session, configuration, and policy identity at clean
shutdown. Publishing that input is useful independently; adopting it on boot
would require a separate fail-closed selection and reconciliation design.

The artifact contains sensitive, potentially large post-import-policy routing
data.
Publication must therefore be private, bounded, transactional, and unable to
weaken the existing generationless restart-marker path.

## Decision

1. `global.warm_cache_checkpoint_on_shutdown` is default-off and
   restart-required. When enabled, coordinated shutdown attempts one
   checkpoint after closing the availability gate and fencing runtime config
   and EVPN applies.
2. One peer-manager capture binds the live local ASN/router ID, redacted
   effective configuration, resolved import-policy identities, and current
   static numbered sessions. The RIB supplies only eligible post-import-policy
   Adj-RIB-In views for negotiated Graceful Restart families. V1 supports IPv4
   and IPv6 unicast, plus EVPN without Add-Path receive.
3. Encoding, validation, hashing, and storage share a 30-second monotonic
   deadline, cancellation token, and 512 MiB snapshot cap. The manifest is
   capped at 8 MiB. Any ambiguity, timeout, unsupported view, or partial
   failure rejects the complete checkpoint.
4. The fixed `<runtime_state_dir>/warm-bundle-v1` directory is owner-verified
   and descriptor-pinned. Filesystem operations reject symlinks and unsafe
   ownership/modes. A content-addressed MRT artifact is durably committed
   before atomic `manifest.json` replacement; any failure through the manifest
   rename and parent-directory fsync restores the prior committed directory
   image. Only after that commit point, a descriptor-relative sweep removes
   superseded `snapshot-<sha256>.mrt` files and recognizable atomic temporary
   files. It never selects `manifest.json` or the exact snapshot named by the
   current manifest. Cleanup failure is warned and leaves the new generation
   committed; no background collector or directory-size policy is introduced.
   Startup reuses the bounded cleanup engine before publication is armed. A
   missing manifest permits canonical orphan cleanup; a structurally valid,
   byte-stable manifest protects its exact selected snapshot; and a corrupt,
   unsafe, oversized, or changed manifest deletes nothing. Entry-local unlink
   failures are aggregated without suppressing later candidates, while scan,
   guard, bound, and durability failures abort the pass.
5. A successful publication binds the exact checkpoint generation into the
   restart marker. Marker v3 normally carries that binding plus a complete
   Linux boottime clock domain; if clock-domain sampling or representation is
   unavailable, the same generation is retained in wall-only marker v2.
   Checkpoint failure publishes a generationless marker (normally v3, or
   wall-only v1 when the clock domain is unavailable). Marker and bundle
   operations remain independently fail-closed.
6. This decision stops at publication and validation. The daemon has no boot
   call site that loads the bundle. No cached route is inserted into Adj-RIB-In
   or Loc-RIB, selected, installed, or advertised, and
   `forwarding_preserved` remains false. Restore/adoption requires a separate
   decision and implementation.

## Consequences

- Operators can opt into a durable, identity-bound shutdown artifact without
  changing current restart convergence or forwarding claims.
- The checkpoint contains post-import-policy routing and topology data and must
  be protected as sensitive daemon state.
- Shutdown may spend up to 30 seconds attempting publication. Failure is
  visible in logs but preserves the normal generationless Graceful Restart
  marker fallback.
- A successful checkpoint normally leaves one manifest and its one current
  snapshot. Unknown files are not garbage-collected. A post-commit cleanup
  warning means the new checkpoint remains committed but stale private bundle
  entries may need operator inspection or removal.
- The V1 format intentionally excludes dynamic/scoped peers, ambiguous static
  addresses, unsupported families, and EVPN Add-Path receive rather than
  serializing an incomplete or ambiguous view.
- Restore, adoption, route selection, and forwarding-state validation remain
  deferred; the presence of a valid bundle is not evidence that any route will
  be used after restart.
- Every concurrently running daemon requires a distinct `runtime_state_dir`.
  Cross-process sharing is unsupported for the marker, warm bundle, FIB
  receipt, and Unix socket as a whole; this decision does not add a misleading
  warm-only lock.
