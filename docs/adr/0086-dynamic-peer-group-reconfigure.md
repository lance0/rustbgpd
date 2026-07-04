# ADR-0086: Peer-group field edits reach live dynamic sessions via post-persist graceful reset

**Status:** Accepted
**Date:** 2026-06-12

## Context

ADR-0081 decision 4 deferred dynamic-range peer-group field reshapes: the
static reshape primitive's delete/re-add semantics are wrong for an
ephemeral accepted peer, `apply_peer_reshape_snapshot` rejects dynamic
targets (`src/peer_manager/lifecycle.rs`), and `delete_peer_checked` rejects
them too (the #416 slot-leak fix). The remaining gap: a peer-group field
edit affecting a `[[dynamic_neighbors]]` range classified as
`SessionReshape` + `is_dynamic_range` and landed in
`unsupported_sections` ("effective neighbor inheritance impact") — the
transaction (and therefore gNMI Set) path rejected it outright, while SIGHUP
and the targeted RPCs applied the catalog change but deliberately skipped
live dynamic members (`apply_peer_group_change`,
`src/peer_manager/policy.rs`), leaving their sessions on the old config
until a natural reconnect.

### Field taxonomy (what a peer-group edit can mean for a live session)

Built from `PeerGroupConfig` (`src/config/schema.rs`) against the transport
session's mutation surface (`PeerCommand`, `crates/transport/src/handle.rs`):

- **(a) Live-swappable today:** resolved import/export policy chains only.
  The dynamic-range live-policy executor (0.37.0,
  `ApplyPolicyImpactSnapshot`) already hot-applies these to accepted dynamic
  sessions by accepted-range attribution. Nothing else qualifies: a session
  task owns an immutable `TransportConfig` snapshot, and the only runtime
  mutation commands are `UpdateImportPolicy`, `UpdateExportPolicy`, and
  `UpdateGracefulShutdown`.
- **(b) Session-resetting by protocol necessity:** `hold_time` (OPEN
  negotiation), `families` / `disable_ipv4_unicast` (MP capabilities),
  `graceful_restart` / `gr_restart_time` / `llgr_stale_time` (GR/LLGR
  capabilities), `add_path` (capability), `role` / `strict_role` (RFC 9234
  capability), `prefix_orf_receive` (ORF capability), `md5_password` (TCP
  MD5 option), `ttl_security` (socket-level GTSM). `bfd` is restart-required
  for everyone; `tcp_ao` is static-neighbor-only and restart-required.
- **(c) In between** (no wire renegotiation, but trapped in the immutable
  per-session snapshot): `max_prefixes`, `remove_private_as`,
  `local_ipv6_nexthop`, `gr_stale_routes_time`, `route_reflector_client` /
  `route_server_client` (these two also change RIB/export semantics).

Category (c) is treated as (b). That matches the static-neighbor semantics
exactly — static members are delete/re-add bounced for the same fields —
and matches FRR/GoBGP behavior (session-affecting peer-group changes flap
members; GoBGP applies `NeedsResendOpenMessage` changes as delete + re-add).
Per-field hot-apply transport commands for (c) would be a transport-crate
surface expansion (new `PeerCommand` variants, FSM plumbing, and lockstep
updates of the manager's cached `ManagedPeer.transport_config` — the #416
parity-drift hazard) for fields that are rarely edited live; not worth it
while the honest alternative (a graceful reset) exists.

### The seams that make a dynamic-safe reset clean

1. `StageConfigSnapshot` advances the peer manager's `current_config` and
   rebuilds the dynamic accept matcher *before* persist
   (`src/peer_manager/mod.rs`), and `handle_inbound` resolves an accepted
   dynamic peer's config from `current_config` at accept time
   (`src/peer_manager/inbound.rs`) — so any reconnect after staging is
   already re-accepted under the candidate config.
2. Any FSM transition to Idle emits `BackToIdle`
   (`crates/transport/src/session/fsm.rs`), and the manager's `BackToIdle`
   handler owns the entire dynamic teardown: `ManagedPeer` removal,
   `dynamic_peer_count` decrement, dead-letter carry-over of unfired policy
   intent, and metric reaping (`src/peer_manager/notifications.rs`).
3. `PeerHandle::stop(Some(reason))` sends a Cease NOTIFICATION with an
   RFC 8203 shutdown communication without touching admin state.

A graceful stop with `enabled` left true therefore composes the full
dynamic "reshape" from existing, separately-tested behavior: stop → Cease →
Idle → `BackToIdle` reap (slot freed) → remote redials → re-accepted under
the committed config. No new lifecycle state, no manual slot accounting, no
delete/re-add.

## Decision

**Commit dynamic-range peer-group field reshapes on the transaction path by
gracefully resetting the affected live dynamic sessions after persist.**

1. **Classifier** (`session_reshape_transaction`, `src/config/mod.rs`): a
   transaction whose effective impacts are all `SessionReshape` is
   committable by the reshape family even when some impacts are dynamic
   ranges — but only when `[[dynamic_neighbors]]` records themselves are
   unchanged. A range peer-group *reassignment* (or range add/remove) stays
   out: it is the dynamic-neighbor executor's family, and sessions accepted
   under the old group cannot be live-reassigned (the live-policy executor
   has the same constraint — it expands ranges by *accepted* peer group).
   Mixed `PolicyChain` + `SessionReshape` impacts remain rejected.
2. **Executor** (`commit_peer_session_reshape_locked`,
   `src/config_transaction_control.rs`): resolve static reshape targets and
   dynamic bounce ranges up front; stage; reconfigure static members through
   the existing captured-prior primitive (rollback-capable, unchanged);
   persist; **then** send `BounceDynamicRangePeers`. Ordering is the
   contract:
   - *A failed transaction never flaps a dynamic peer.* Stage/reshape/persist
     failures roll back exactly as before, with zero dynamic sessions
     signaled (pinned by test).
   - *The reset is post-persist and best-effort.* Once the transaction is
     durable, a per-peer signaling failure degrades to the previously
     documented semantics — the session keeps its running config until it
     reconnects — and is reported in the apply response and the outcome's
     failure list, never silently swallowed and never failing the committed
     transaction (returning an error after persist would misreport a
     committed transaction as failed).
3. **Peer-manager primitive** (`bounce_dynamic_peers_for_ranges`,
   `src/peer_manager/lifecycle.rs`): expand ranges against live peers by
   stored accepted-range attribution (same matching as the live-policy
   executor), send `stop` with shutdown communication
   `"peer-group configuration change"`, leave `enabled`/state machine alone.
   Skips admin-disabled dynamic peers: they run no session, and `BackToIdle`
   deliberately keeps a disabled dynamic peer un-reaped.
4. **Commit-confirmed compatibility for free:** an abort/timer revert
   re-applies the pre-commit snapshot through the same executor, producing
   the reverse reshape — dynamic sessions are reset again and re-accept
   under the restored config.
5. **SIGHUP and the targeted peer-group RPCs split by impact.** Policy-only
   peer-group edits hot-apply to live dynamic sessions through the same
   resolved-policy fanout as named-policy catalog changes. Session-shaping
   peer-group edits keep their skip semantics on these no-preview paths:
   live dynamic sessions keep their running config until reconnect. Bouncing
   customers as a side effect of a reload or a single-object RPC — with no
   plan preview — is an operator surprise; the transaction path is the one
   with `PlanConfigTransaction`/`rbgp config plan` showing the blast
   radius first, and gNMI Set inherits it by bridging onto the same
   controller. Upgrading the targeted path to the same reset is a follow-up
   decision, not blocked by anything here (the primitive is path-agnostic).

### Rollback semantics, stated honestly

A graceful reset is one-way per session: rollback cannot restore a session
that already dropped, only the config it will re-accept under. This is the
same stance ADR-0081 took for static reshapes ("the invariant is
config-correctness, not flap-minimization") — and the dynamic case is
strictly gentler than the static delete/re-add, because nothing is deleted:
a peer the reset never reached simply keeps running until its natural
reconnect converges it. The race where a remote redials between stop and
`BackToIdle` is pre-existing dynamic-flap behavior (the pending inbound is
dropped with the reaped peer; the remote retries and is accepted fresh).

## Consequences

- `rbgp config apply` / gNMI Set can now commit a peer-group field
  edit (e.g. `hold_time`) for a group serving `[[dynamic_neighbors]]`
  ranges — alone or mixed with static members — instead of `REJECTED`. The
  response reports reconfigured static sessions and signaled dynamic
  sessions separately, plus any signaling failures.
- An operator editing a peer group behind a busy IX range takes a
  full-range flap on commit. `rbgp config plan` shows the impacted
  ranges (with reasons) before apply; this is the deliberate trade against
  silently running sessions whose config disagrees with the committed one.
- A known pre-existing wrinkle is unchanged: an admin-disabled dynamic peer
  keeps its stale `ManagedPeer.transport_config` and would re-enable with
  it; the reset skips disabled peers rather than papering over that.
- Tests pin: classifier flips (field reshape committable, reassignment still
  rejected), bounce targeting (range+group attribution, static and
  admin-disabled peers untouched, slot count and admin state untouched),
  per-peer failure reporting without stopping the sweep, post-persist
  ordering (persist failure ⇒ zero resets), and the mixed static+dynamic
  commit.

## References

- ADR-0076 (config transaction model), ADR-0081 (atomic peer-group
  reshapes; decision 4 is the deferral this ADR closes).
- GoBGP peer-group update semantics (`NeedsResendOpenMessage` ⇒ delete +
  re-add): <https://github.com/osrg/gobgp/blob/master/pkg/server/server.go>
- FRR peer-group inheritance / listen-range:
  <https://docs.frrouting.org/en/latest/bgp.html>
- RFC 8203 (BGP Administrative Shutdown Communication), RFC 4271 §6.8.
