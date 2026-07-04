# ADR-0053: RFC 8326 BGP Graceful Shutdown

**Status:** Accepted
**Date:** 2026-05-04

## Context

RFC 8326 standardizes the well-known `GRACEFUL_SHUTDOWN` community
(`65535:0` / `0xFFFF_0000`) for draining traffic ahead of planned BGP
maintenance. Operators tag outbound paths on the session being shut
down; receivers honor the community by setting `LOCAL_PREF` to a low
value so the path becomes a backup. When the session actually closes,
traffic has already shifted off it — packet loss during the cutover is
minimized.

Before this work, operators on rustbgpd had two choices:

1. **Hand-write the policy.** `match_community = "65535:0"` plus
   `set_local_pref = 0` for the receiver side. Workable but verbose
   and error-prone (every operator deploys it differently).
2. **No way to advertise GShut at all.** rustbgpd had no surface for
   attaching a community to outbound updates as a runtime, per-peer
   action — the only way to attach was via export policy, which is a
   config-level edit that doesn't roll back when maintenance ends.

The deferred ROADMAP item called for a **four-part landing**:
wire constant, policy alias, opt-in receiver knob, and an outbound
runtime toggle. This ADR records the architectural shape we picked
across those four pieces and the trade-offs that drove each.

## Decisions

### 1. Wire constant lives in the wire crate, not the policy crate

`pub const COMMUNITY_GRACEFUL_SHUTDOWN: u32 = 0xFFFF_0000` sits in
`crates/wire/src/lib.rs` next to `COMMUNITY_LLGR_STALE` /
`COMMUNITY_NO_LLGR`. The wire crate is the single source of truth for
spec-mandated wire values; centralizing the constant prevents drift
between the policy alias, the transport attach helper, and the
receiver implicit rule.

A pin test (`well_known_community_values_match_specs`) asserts the
spec values directly, so a refactor that accidentally renames the
constant cannot silently change its value.

### 2. Policy alias is one parser, two surfaces

`parse_community_match` in `crates/policy/src/engine.rs` accepts
`"GRACEFUL_SHUTDOWN"` as a community name, mirroring the existing
RFC 1997 aliases (`NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`).
The set-side parser `parse_community_values` in `src/config/parse.rs`
already routes through `parse_community_match`, so the alias works
in both `match_community` and `set_community_add` /
`set_community_remove` positions without a second registration.

### 3. Receiver behavior: implicit chain-tail rule, EBGP-only, opt-in

`[global] honor_graceful_shutdown = true` enables RFC 8326 §4 receiver
behavior. When on, `effective_policy_chains_for_neighbor` appends an
implicit policy to the resolved import chain on every EBGP peer:

```
match community = GRACEFUL_SHUTDOWN → permit, set local_pref = 0
```

Three sub-decisions inside this:

**Tail, not head.** `PolicyChain::evaluate` short-circuits on `Deny`
but accumulates modifications across `Permit` matches with
last-writer-wins on scalar fields. If the implicit rule ran at index
0 and a later operator policy set `local_pref = 200`, the operator's
value would silently overwrite the GShut demotion — defeating the RFC
guarantee. Running at the tail makes the implicit `set_local_pref =
0` win over any earlier operator modification. Operator denies still
short-circuit (no demotion needed if the route is dropped).

**EBGP-only.** `LOCAL_PREF` is non-transitive across EBGP (RFC 4271
§5.1.5); receivers default it to 100 internally. iBGP peers
*propagate* the LOCAL_PREF the EBGP edge already set. Re-applying the
demotion per iBGP hop would clobber values set legitimately at the
upstream EBGP edge — that's why the gate is `neighbor.remote_asn !=
self.global.asn`.

When confederations land the gate needs to key off an explicit
`is_external_neighbor()` helper that knows about confederation sub-AS
topology rather than the simple ASN comparison. This is tracked in
ROADMAP under "RFC 8326 confederation gating" and is a documented
known-limitation in `KNOWN_ISSUES.md`.

**Opt-in by default.** RFC 8326 §4 says receivers SHOULD apply the
demotion, not MUST. Operators who deliberately don't want the
implicit rule (e.g. they're already running it at a different layer
like a route server) can leave the knob off and the resolved chain
stays untouched.

**Hot-applied via SIGHUP (v0.13.4).** Originally `[global]
honor_graceful_shutdown` required a daemon restart for a flip to
take effect — the field was read once at startup and not re-checked
on reload. v0.13.4 closes that limitation: SIGHUP routes the new
value through `PeerManagerCommand::SetHonorGracefulShutdown`, which
recomputes every EBGP peer's effective import chain against the new
snapshot and fans the resolved chains through the existing
`update_runtime_policies` path. The hot-apply is best-effort —
`PeerManager::current_config` (and the daemon's mirrored
`working_config`) advance unconditionally; per-peer failures
aggregate into an `Err` that the reload path logs as a `warn!`
rather than halting. Failed peers retry on their next policy edit
via the existing `pending_refresh` / `pending_export_apply`
bail-and-carry plumbing, so partial application converges rather
than drifts. See `PeerManager::set_honor_graceful_shutdown` and the
SIGHUP step in `src/main.rs`.

### 4. Initiator behavior: operator-runtime toggle, not policy

The runtime side is a per-peer **bool**, not a policy edit:

- gRPC: `NeighborService.SetGracefulShutdown { address, enabled }`
  (empty `address` = all peers, for whole-router maintenance).
- CLI: `rbgp gshut [--peer X] [--clear]` (top-level — the
  `shutdown` verb is already taken by the daemon-shutdown RPC).
- Persistence: the toggle is **runtime-only** by design. RFC 8326 is
  a maintenance-window action; operators clear it when the work is
  done. Promoting it to config would invert the lifecycle and
  encourage leaving it set.

### 5. Desired state lives on `ManagedPeer`, mirrored to the session

The toggle is stored on `ManagedPeer` in `PeerManager` (the
authoritative runtime state for each peer) and **mirrored** to the
per-`PeerSession` bool. Three reasons this matters:

- **Survives session restart.** A peer that flaps mid-maintenance
  comes back up with the toggle still on, because every
  `PeerSession::new` / `new_inbound` constructor takes the toggle as
  an argument and the call sites pass `managed.advertise_graceful_shutdown`.
- **Survives collision-replace.** When an inbound TCP collision wins
  and the existing session is replaced, `replace_with_inbound`
  passes the existing `ManagedPeer`'s toggle into the new session.
- **Survives dynamic-peer auto-removal.** Dynamic peers are tracked
  separately: `BackToIdle` drops the whole `ManagedPeer`, so the
  toggle would be lost across the auto-remove / re-establish cycle
  if it lived only on `ManagedPeer`. v0.13.4 closes this by
  extending the per-IP dead-letter side table on `PeerManager` (the
  same one that already carries `pending_refresh` /
  `pending_export_apply` across `BackToIdle`) with an
  `advertise_graceful_shutdown` field. `dead_letter_pending_for`
  captures the toggle before `peers.remove`; the inbound handler
  for the same address replays it via `restore_dead_lettered_pending`
  before the new session is wired up. Operators no longer need to
  re-issue `rbgp gshut` after a dynamic-peer flap during a
  maintenance window. The replay is covered by
  `dead_lettered_pending_survives_dynamic_peer_auto_removal_and_re_establish`.

### 6. Toggle triggers a dedicated RIB refresh, not a no-op policy

The session bool only affects new outbound advertisements; it doesn't
re-evaluate routes already in `AdjRibOut`. To make the toggle
observable on the wire immediately, `set_graceful_shutdown` issues
`RibUpdate::RefreshPeerOutbound` after flipping the bool.

The RIB handler marks the peer dirty and runs `distribute_changes`,
which re-emits all currently-advertised routes to that peer. The new
emissions go through the outbound pipeline, hit
`attach_graceful_shutdown_if_enabled`, and carry (or stop carrying)
the community on the wire.

`RefreshPeerOutbound` is a new variant rather than reusing
`ReplacePeerExportPolicy` with a no-op policy update because:

- The intent is different and should be self-documenting in the
  RIB-side dispatch.
- Future outbound-attribute toggles (e.g. RFC 7999 BLACKHOLE) will
  use the same variant.
- Keeping policy-replacement and outbound-refresh distinct makes the
  metrics and logs cleaner.

### 7. Typed error from `set_graceful_shutdown`

`PeerManagerCommand::SetGracefulShutdown` replies via
`oneshot::Sender<Result<(), SetGshutError>>` rather than `Result<(),
String>`. The two variants are `PeerNotFound(IpAddr)` (operator typo
— maps to gRPC `NOT_FOUND`) and `Internal(String)` (session/RIB
dispatch failure or aggregated broadcast partial — maps to gRPC
`INTERNAL`). The handler can map directly without parsing strings.

## What we rejected

- **Persistent GShut as TOML config.** Conflates maintenance-window
  state with steady-state config. Operators would forget to clear
  it.
- **Implicit GShut rule at chain head.** Real correctness bug —
  operator policies that set `local_pref` would overwrite the
  demotion silently.
- **Policy-only outbound advertise.** Forces operators to edit
  config to start a maintenance drain. Doesn't compose with `--all`
  semantics.
- **Stringly-typed `Result<(), String>` from the command handler.**
  Loses the structural distinction between "peer not found"
  (operator error, retry useless) and "session failure" (transient,
  desired-state stored, will apply on next session). Mapping all
  errors to `NOT_FOUND` is misleading at the gRPC layer.
- **Reuse `ReplacePeerExportPolicy` with the current policy** for
  the refresh. Works mechanically but conflates two different
  intents in metrics and logs; no longer captures the "policy
  unchanged, just re-emit" semantic.

## Cross-references

- `proto/rustbgpd.proto` — `NeighborService.SetGracefulShutdown`,
  `Route.local_pref_attr`.
- `crates/wire/src/lib.rs` — `COMMUNITY_GRACEFUL_SHUTDOWN`.
- `crates/policy/src/engine.rs` — `parse_community_match`.
- `src/config/mod.rs` — `effective_policy_chains_for_neighbor` +
  `build_implicit_gshut_policy`.
- `src/config/schema.rs` — `Global.honor_graceful_shutdown`.
- `src/peer_manager.rs` — `ManagedPeer.advertise_graceful_shutdown`,
  `PeerManager::set_graceful_shutdown`,
  `PeerManager::set_honor_graceful_shutdown` (v0.13.4 hot-apply
  fan-out), `DeadLetteredPending` (v0.13.4 carries
  `graceful_shutdown` alongside `refresh` / `export_apply`),
  `dead_letter_pending_for` / `restore_dead_lettered_pending`.
- `crates/api/src/peer_types.rs` — `SetGshutError`,
  `PeerManagerCommand::SetHonorGracefulShutdown` (v0.13.4).
- `src/main.rs` — SIGHUP reload step that hot-applies
  `[global] honor_graceful_shutdown` via
  `PeerManagerCommand::SetHonorGracefulShutdown` (v0.13.4).
- `crates/api/src/neighbor_service.rs` — `set_graceful_shutdown` gRPC
  handler.
- `crates/transport/src/handle.rs`,
  `crates/transport/src/session/mod.rs`,
  `crates/transport/src/session/commands.rs`,
  `crates/transport/src/session/outbound.rs` — session-side state +
  attach helper.
- `crates/rib/src/update.rs` + `crates/rib/src/manager/distribution.rs`
  — `RibUpdate::RefreshPeerOutbound`.
- `crates/cli/src/main.rs` + `crates/cli/src/commands/neighbor.rs` —
  `rbgp gshut` command.
- `tests/interop/m35-graceful-shutdown-frr.clab.yml` +
  `tests/interop/scripts/test-m35-graceful-shutdown-frr.sh` — both
  legs against FRR 10.3.1.
- v0.13.4 M35b (FlowSpec) + M35c (EVPN) interop tests — assert the
  GShut attach helper fires on FlowSpec and EVPN outbound advertise
  sites. The capture parser does per-flow TCP stream reassembly so
  BGP messages split across TCP segments are recovered before
  attribute scan.

## References

- RFC 8326 — Graceful BGP Session Shutdown.
- RFC 4271 §5.1.5 — `LOCAL_PREF` non-transitive across EBGP.
- RFC 1997 — Standard communities (well-known names).
- BGP Filter Guide — Graceful Shutdown
  (`https://bgpfilterguide.nlnog.net/guides/graceful_shutdown/`).
