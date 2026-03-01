# ADR-0024: Graceful Restart — Receiving Speaker (RFC 4724)

**Status:** Accepted
**Date:** 2026-03-01

## Context

Without graceful restart, every daemon restart or TCP session reset causes
immediate withdrawal of all routes from the restarting peer, triggering
route flaps across the network. RFC 4724 defines a mechanism to preserve a
restarting peer's routes during the restart window.

rustbgpd needs GR as a pre-1.0 feature because production deployments
require planned maintenance without route churn.

Key constraints:

1. **Receiving speaker only.** When a *peer* restarts, we preserve their
   routes. Restarting speaker mode (advertising `R=1` and preserving our
   own forwarding state) is deferred — it requires FIB integration that
   doesn't exist yet.
2. **Single-task RIB ownership** (ADR-0013). GR timers and stale state
   must live inside `RibManager`, not in transport or FSM.
3. **Stale route demotion** must be visible in best-path selection so
   non-stale alternatives are preferred during the restart window.
4. **End-of-RIB markers** are the signal that a restarting peer has
   finished resending its routing table.

## Decision

### Capability (Wire)

Capability code 64 with `GracefulRestart` variant on `Capability` enum.
Fields: `restart_state` (R-bit), `restart_time` (12-bit seconds),
`families` (per-AFI/SAFI with forwarding-preserved flag).

Receiving speaker advertises `restart_state: false` and
`forwarding_preserved: false` for all configured families.

### Stale Route Demotion

`Route.is_stale: bool` field. Best-path comparison (step 0, before
LOCAL_PREF) prefers non-stale over stale. This is stronger than RFC 4724's
suggestion (which places it after step 6) but matches common implementations
(GoBGP, FRR) that aggressively demote stale routes.

### GR Trigger (Transport)

On `SessionDown`, GR is triggered when `peer_gr_capable && config.graceful_restart`.
The R-bit (`peer_restart_state`) is NOT checked — it indicates restart state
in the *new* OPEN after reconnection, not in the dying session.

### State Machine (RibManager)

- `gr_peers: HashMap<IpAddr, HashSet<(Afi, Safi)>>` — families awaiting EoR
- `gr_stale_deadlines: HashMap<IpAddr, tokio::time::Instant>` — sweep deadlines
- `gr_stale_routes_time: HashMap<IpAddr, u64>` — per-peer EoR timer config

**PeerGracefulRestart:** Mark routes stale for ALL families in the peer's
GR capability (not just forwarding-preserved ones). Withdraw routes for
negotiated families NOT in the GR capability. Clean up outbound state.
Set initial timer = `restart_time` (window for session re-establishment).

**EndOfRib:** Clear stale flag for that family, recompute best-path.
If all families done, remove GR state.

**Timer expiry:** Sweep remaining stale routes as withdrawals.

**PeerUp during GR:** Keep routes stale. Reset timer from `restart_time`
to `stale_routes_time` (window for EoR). Re-register outbound channel and
send initial table. Stale flags are cleared by EoR per-family, not by
PeerUp.

**PeerDown during GR:** Abort — clear all routes immediately (existing
PeerDown logic).

### End-of-RIB Detection (Transport)

- IPv4: empty UPDATE (no NLRI, no withdrawn, no attributes)
- IPv6: UPDATE with only empty `MP_UNREACH_NLRI`

### End-of-RIB Sending

After initial table dump to a new peer, send EoR markers for each
negotiated family via `OutboundRouteUpdate.end_of_rib`.

### Timer Placement

GR timers live in `RibManager::run()` select! loop alongside the existing
dirty-peer resync timer. This keeps all RIB mutation in one task and avoids
cross-task synchronization.

## Alternatives Considered

### Timers in Transport

Each peer session could own its GR timer. Rejected because the stale sweep
mutates Adj-RIB-In and triggers best-path recomputation, which must happen
inside RibManager. Sending a message from transport to RIB on timer expiry
adds latency and complexity for no benefit.

### Stale Demotion After All Steps

RFC 4724 allows stale demotion at any point. Placing it last (step 7) would
mean a stale route could win over a non-stale route with worse attributes.
Step 0 (before LOCAL_PREF) ensures non-stale routes always win, which is
the safest behavior during a restart window.

## Consequences

- Receiving speaker works immediately — peers running GoBGP, FRR, or BIRD
  with GR enabled will have their routes preserved during restarts.
- Restarting speaker deferred — rustbgpd itself will still cause route flaps
  when it restarts. This requires FIB preservation which is out of scope.
- Default enabled (`graceful_restart = true`) — matches operator expectations
  for production use.
