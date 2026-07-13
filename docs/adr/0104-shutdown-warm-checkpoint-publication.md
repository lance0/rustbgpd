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

The artifact contains sensitive, potentially large pre-policy routing data.
Publication must therefore be private, bounded, transactional, and unable to
weaken the existing marker-v1 restart path.

## Decision

1. `global.warm_cache_checkpoint_on_shutdown` is default-off and
   restart-required. When enabled, coordinated shutdown attempts one
   checkpoint after closing the availability gate and fencing runtime config
   and EVPN applies.
2. One peer-manager capture binds the live local ASN/router ID, redacted
   effective configuration, resolved import-policy identities, and current
   static numbered sessions. The RIB supplies only eligible pre-policy
   Adj-RIB-In views for negotiated Graceful Restart families. V1 supports IPv4
   and IPv6 unicast, plus EVPN without Add-Path receive.
3. Encoding, validation, hashing, and storage share a 30-second monotonic
   deadline, cancellation token, and 512 MiB snapshot cap. The manifest is
   capped at 8 MiB. Any ambiguity, timeout, unsupported view, or partial
   failure rejects the complete checkpoint.
4. The fixed `<runtime_state_dir>/warm-bundle-v1` directory is owner-verified
   and descriptor-pinned. Filesystem operations reject symlinks and unsafe
   ownership/modes. A content-addressed MRT artifact is durably committed
   before atomic `manifest.json` replacement; failure restores the prior
   committed directory image.
5. A successful publication writes restart marker v2 with the exact checkpoint
   generation. Failure writes the established marker-v1 form instead. Marker
   and bundle operations remain independently fail-closed.
6. This decision stops at publication and validation. The daemon has no boot
   call site that loads the bundle. No cached route is inserted into Adj-RIB-In
   or Loc-RIB, selected, installed, or advertised, and
   `forwarding_preserved` remains false. Restore/adoption requires a separate
   decision and implementation.

## Consequences

- Operators can opt into a durable, identity-bound shutdown artifact without
  changing current restart convergence or forwarding claims.
- The checkpoint contains pre-policy routing and topology data and must be
  protected as sensitive daemon state.
- Shutdown may spend up to 30 seconds attempting publication. Failure is
  visible in logs but preserves the normal Graceful Restart marker fallback.
- The V1 format intentionally excludes dynamic/scoped peers, ambiguous static
  addresses, unsupported families, and EVPN Add-Path receive rather than
  serializing an incomplete or ambiguous view.
- Restore, adoption, route selection, and forwarding-state validation remain
  deferred; the presence of a valid bundle is not evidence that any route will
  be used after restart.
