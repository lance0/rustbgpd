# ADR-0081: Atomic peer-group session reshapes on the targeted RPC path

**Status:** Accepted
**Date:** 2026-06-10

## Context

Two code paths reshape live BGP sessions when peer-group configuration
changes, and they have different atomicity guarantees.

The **targeted catalog RPCs** — `SetPeerGroup`, `SetPeerGroupPreserveMd5`,
`SetNeighborPeerGroup`, `ClearNeighborPeerGroup` (peer-manager command arms
in `src/peer_manager/mod.rs:838-895`) — all funnel into
`apply_peer_group_change` (`src/peer_manager/policy.rs:1089`). That function
reshapes each affected static member with delete-then-re-add **in a loop**,
and every step short-circuits with `?` and no rollback
(`policy.rs:1126,1135,1139,1145`). A mid-loop failure leaves:

- members reshaped *before* the failure running sessions built from the
  next config;
- the failing member possibly **deleted entirely** — the error path between
  `delete_peer_for_reconfigure` (`policy.rs:1133`) and
  `add_peer_with_admin_state` (`policy.rs:1143`) returns without restoring
  the peer it just tore down;
- members *after* the failure untouched;
- `self.current_config` never advanced (`policy.rs:1150`), so the manager's
  config snapshot disagrees with the sessions it is actually running, and
  nothing was persisted. The gRPC service layer's rollback
  (`crates/api/src/peer_group_service.rs:389-410`) only fires on *persist*
  failure, never on a partial *apply* failure.

One concrete in-tree trigger: a targeted peer-group/member edit can include
a TCP-AO-protected static member in the reshape set. `tcp_ao` is
static-neighbor-only (not inherited from peer groups), but the current loop
only discovers a restart-required TCP-AO delta when it reaches that member's
`delete_peer_checked` guard — *per member, mid-loop* — after earlier members
may already have been bounced.

The **0.37.0 catalog-policy fix is precedent but not coverage.** The 12
policy / neighbor-set / policy-chain mutators got an atomic fan-out:
`apply_policy_change` now resolves every affected peer's chains first, then
commits the whole set through the capturing ADR-0076 primitive
`ApplyResolvedPolicySnapshot`, restoring captured priors on mid-fanout
failure (`src/peer_manager/policy.rs:760-820`, CHANGELOG 0.37.0 "Catalog
policy mutations apply to peers atomically"). But restoring a policy chain
is a pointer swap plus a best-effort Route Refresh; a session **reshape**
is a different blast radius: rollback must rebuild a session from a
captured prior config, the peer can reconnect mid-rollback, and the prior
config carries credential material.

The **ADR-0076 transaction path already has the cure.** Static
peer-group/session reshape transactions commit through
`commit_peer_session_reshape_locked`
(`src/config_transaction_control.rs:1357-1399`), which sends one
`ApplyPeerReshapeSnapshot` command. The peer-manager primitive
`apply_peer_reshape_snapshot` (`src/peer_manager/lifecycle.rs:319-369`):

1. **preflights every target before touching any peer** — duplicate-target,
   TCP-AO-change → RestartRequired, dynamic-peer rejection
   (`lifecycle.rs:323-349`), so classification failures reject with zero
   peers touched;
2. reconfigures one peer at a time via `reconfigure_peer`, **capturing each
   prior `PeerManagerNeighborConfig`**;
3. on a mid-loop failure, replays the captured priors **in reverse order**
   (`restore_peer_reshape_priors`, `lifecycle.rs:371-388`), re-reading live
   enabled / graceful-shutdown state so rollback preserves current admin
   intent rather than resurrecting a stale toggle;
4. surfaces a rollback-of-rollback failure as a compound `Internal` error
   (`lifecycle.rs:361-363`) — never silently.

Persist failure after a successful live reshape rolls back both the live
peers and the staged snapshot (`rollback_peer_reshape_and_snapshot`,
`src/config_transaction_control.rs:1652-1671`).

Prior art (source-verified):

- **GoBGP** has the same gap shape as our targeted path:
  `updatePeerGroup` mutates the stored group conf, then loops members
  calling `updateNeighbor`; a member error returns immediately with no
  restore of already-updated members (`pkg/server/server.go:3702-3719`).
  Its per-member classifier is instructive: OPEN/transport-affecting
  changes (`NeedsResendOpenMessage`) are applied as delete + re-add — a
  session bounce — while policy changes hot-apply and report
  `needs_soft_reset_in` to the caller
  (`UpdatePeerGroupRequest.do_soft_reset_in`).
- **FRR** applies peer-group edits to live members through value
  inheritance inside one bgpd process; session-affecting changes flap
  members, and the long tail of partial-application inconsistencies is
  documented by users (FRR issue #7975). FRR's model is "the CLI is the
  transaction"; there is no per-RPC atomicity contract to point at.
- **NETCONF** makes single-RPC atomicity *optional*: `<edit-config>`
  defaults to `stop-on-error`, which explicitly leaves prior changes
  applied; all-or-nothing requires the `:rollback-on-error` capability
  (RFC 6241 §7.2, §8.5).
- **gNMI** makes it *mandatory*: all operations in a `SetRequest` are one
  transaction — "either all modifications within the request are applied,
  or the target MUST rollback the state changes to reflect its state
  before any changes were applied" (gNMI spec §3.4.3). Our gNMI Set
  already inherits this by bridging onto the ADR-0076 controller; the
  native targeted RPCs are now the *only* mutation surface without the
  guarantee.

## Decision

**Make the targeted peer-group RPCs commit their member fan-out through
the existing captured-prior reshape primitive** — option B below, the same
move the 0.37.0 policy-chain fix made with `ApplyResolvedPolicySnapshot`.
One reshape engine, two front doors.

### Options considered

- **A: route targeted RPCs through the `ConfigTransactionController`
  internally** (the gNMI-Set precedent). Strongest unification on paper —
  one commit path, automatic snapshot-token staging, persistence, and
  confirmed-transaction fencing. Rejected for v1: the catalog RPCs are
  definition-shaped, not candidate-TOML-shaped, so each RPC would need a
  synthesize-candidate-TOML bridge like `src/gnmi_set_bridge.rs`; the
  controller's single-family planner and snapshot-token semantics would
  leak into RPCs whose contract is "edit this one object"; and the
  targeted mutators are already fenced while a confirmed transaction is
  pending, so the fencing benefit is already in place. This stays the
  long-term direction if the catalog surface ever grows transactional
  features (it is how gNMI got them for free), but it is a large adapter
  for a rollback bug.
- **B (chosen): commit the member fan-out through
  `apply_peer_reshape_snapshot` inside `apply_peer_group_change`.** The
  primitive already lives in the same peer-manager actor, already
  preflights, captures priors, restores in reverse order, and reports
  compound rollback failures. The RPC contract, authorization tier, and
  persistence flow are unchanged.
- **C: reject multi-member reshapes on the targeted path with
  `FAILED_PRECONDITION` pointing at the transaction API.** Honest and
  tiny, but a capability regression (today's single-member happy path is
  the common case and works), inconsistent with the just-shipped atomic
  policy fan-out, and it would still leave the *single*-member
  delete-without-restore tear-down hazard in place.

### Numbered decisions

1. **Two-phase fan-out.** `apply_peer_group_change` resolves every
   affected member's next `PeerManagerNeighborConfig` from `next_config`
   first (resolution failure = rejected with zero peers touched), then
   commits the whole set through `apply_peer_reshape_snapshot`. The
   existing per-member delete/re-add loop in `policy.rs:1113-1148` is
   deleted, not wrapped.
2. **Preflight before mutation.** The primitive's guards now cover the
   targeted path by construction: a reshape target that changes
   static-neighbor TCP-AO returns `RestartRequired` *before* any member is
   bounced instead of mid-loop; duplicate and dynamic targets are rejected
   up front.
3. **Rollback corner cases are part of the contract:**
   - *Member reconnects mid-rollback.* Rollback replays
     `reconfigure_peer`, which is itself delete + re-add: a member that
     re-established between apply and rollback is bounced a second time.
     That is accepted — the invariant is config-correctness, not
     flap-minimization. Inbound collisions during the window are handled
     by the normal lifecycle (`delete_peer_checked` shuts down
     `pending_inbound`, `lifecycle.rs:472-475`), and rollback re-reads
     live enabled/GShut state so admin intent set during the window
     survives.
   - *Persist failure after a successful reshape.* The service layer's
     existing definition-level rollback (`peer_group_service.rs:389-410`)
     re-applies the prior definition through the same (now atomic)
     fan-out. This double-bounces members — apply forward, roll back —
     which is correct but noisy; folding persistence into the
     peer-manager command (the transaction path's
     `rollback_peer_reshape_and_snapshot` shape) is the follow-up that
     removes the second bounce. Not required for correctness.
   - *Secret capture.* Captured priors are full
     `PeerManagerNeighborConfig`s including `md5_password` and `tcp_ao`
     (`policy.rs:1056-1087`) — deliberately. Precedent: the service layer
     already captures the **unredacted** stored definition (secret
     included) as its persist-rollback token, while the `GetPeerGroup`
     *wire response* redacts (`md5_password: None`,
     `peer_group_service.rs:144-146,348-355`). Same rule here: priors
     live in process memory only, are never logged (audit summaries
     carry has-password booleans only), and are dropped on completion.
   - *Rollback failure.* Compound `Internal` error carrying both the
     original failure and the restore failure (ADR-0076: "silent rollback
     failure is not an acceptable transaction outcome"). The error must
     name which members were left in which shape.
4. **Dynamic-range peer-group field reshapes stay deferred.** The
   primitive rejects dynamic targets and that is unchanged: an accepted
   dynamic peer keeps its running session config until it reconnects;
   only its resolved policy chains hot-apply (the 0.37.0 fan-out resolves
   dynamic peers through their accepted peer group). The targeted path
   shares ADR-0076's deferral — a rollback-capable dynamic-range reshape
   executor (delete/re-add is wrong for ephemeral peers) is its own
   future ADR, and `apply_peer_group_change` must not silently bounce
   dynamic members in the meantime.
5. **`DeletePeerGroup` keeps its still-referenced guard**
   (`policy.rs:1094-1103`) and therefore never reshapes members; it is
   out of scope beyond inheriting the same code path.

## Operational hazards recorded (not solved here)

- A reshape is a session bounce even when atomic; operators editing a
  peer group with many Established members take a full-group flap on the
  targeted path, with no equivalent of the transaction planner's diff
  preview. `rustbgpctl config plan` remains the "show me the blast
  radius first" tool.
- The persist-rollback double-bounce (decision 3) stays until
  persistence moves into the peer-manager command.
- Rollback rebuilds sessions from captured configs; it cannot restore
  *session state* (learned routes re-converge through normal
  re-establishment, GR where negotiated).

## Consequences

- A mid-fanout failure on the targeted path becomes a clean rejection:
  all members back on their prior configs, no member left deleted, config
  snapshot and live sessions agree, nothing persisted.
- The targeted path and the transaction path share one reshape engine and
  therefore one set of guards; future reshape features (e.g. per-member
  progress reporting) land once.
- `SetPeerGroup` on a group with an unreshapeable member (TCP-AO change)
  becomes a clean up-front `RestartRequired` instead of a mid-loop
  partial apply — a strict improvement, but a behavior change clients
  may observe (errors arrive before any session flaps, not after some).
- Tests must cover: mid-fanout failure restores earlier members
  (existing transaction-path tests are the template), tcp_ao preflight
  rejection with zero bounces, rollback preserving admin-disabled and
  GShut state, and the compound-error shape on rollback failure.

## References

- GoBGP `updatePeerGroup` / `updateNeighbor`:
  <https://github.com/osrg/gobgp/blob/master/pkg/server/server.go>
- GoBGP peer-group API (`do_soft_reset_in`):
  <https://github.com/osrg/gobgp/blob/master/docs/sources/peer-group.md>
- FRR peer-group partial-application inconsistencies:
  <https://github.com/FRRouting/frr/issues/7975>
- FRR BGP documentation (peer-group inheritance, listen-range):
  <https://docs.frrouting.org/en/latest/bgp.html>
- RFC 6241 §7.2 (`error-option`, default `stop-on-error`), §8.5
  (`:rollback-on-error` capability):
  <https://www.rfc-editor.org/rfc/rfc6241.html>
- gNMI specification §3.4.3 (SetRequest transactionality):
  <https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md>

See also ADR-0076 (config transaction model; decision 5 and the
session-reshape executor), ADR-0080 (cancellation-shielded applies — the
reshape fan-out runs inside the peer-manager actor, not the request
future, so it is already shielded by construction).
