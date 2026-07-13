# ADR-0040: Graceful Restart — Minimal Restarting Speaker Mode

**Status:** Accepted
**Date:** 2026-03-04

## Context

rustbgpd already implements Graceful Restart helper mode (ADR-0024), so it
can preserve a restarting peer's routes. That still leaves a production gap:
when **rustbgpd itself** restarts, peers immediately withdraw its routes
unless we advertise restarting-speaker state (`R=1`) in our next OPEN.

The codebase does **not** own or verify the complete forwarding plane:

1. Opt-in unicast FIB integration exists, but it does not cover or prove the
   complete forwarding plane across every advertised family.
2. An optional shutdown checkpoint may persist eligible pre-policy
   Adj-RIB-In views, but startup does not restore or adopt them (ADR-0104).
3. There is no crash-safe journal.

So a full RFC 4724 “forwarding state preserved” implementation would be
misleading today.

## Decision

Implement an honest restarting-speaker mode:

1. On coordinated daemon shutdown, rustbgpd writes a small restart marker
   file under `global.runtime_state_dir`.
2. On the next startup, if the marker is still valid, static peers restored
   from config advertise Graceful Restart with:
   - `restart_state = true`
   - `forwarding_preserved = false` for all families
3. The restart window is process-wide and expires at:
   - `now + max(gr_restart_time)` across GR-enabled static neighbors
4. Dynamic peers added later via gRPC do **not** participate in that window.
5. Once the window expires, subsequent reconnects revert to normal
   `restart_state = false`.
6. On a marker-backed startup, freeze the complete GR-enabled static-peer
   roster before any session starts. Route selection is deferred separately
   for every locally supported family until all roster peers are either:
   - bound to a current session that sends that family's End-of-RIB;
   - excluded because its OPEN omitted GR/the family or carried Restart State;
   - or the marker-bounded `Selection_Deferral_Timer` expires.
7. Adj-RIB-In continues ingesting while a family is gated, but Loc-RIB
   selection, initial outbound table data, route-refresh responses, and EoR
   remain withheld. On release, deferred route identities (withdrawals
   included) are selected and advertised before EoR.
8. Waiters are transport-generation stamped. A replacement or failed-over
   session re-arms its frozen roster entry, and an EoR from a predecessor or
   collision loser cannot release the gate.

This mode helps peers retain our routes briefly during a planned restart,
but makes **no claim** that rustbgpd preserved dataplane continuity.

ADR-0104 extends coordinated shutdown with an optional generation-bound
checkpoint publication. It deliberately does not change the startup behavior
or the `forwarding_preserved = false` contract defined here.

## Consequences

- Planned restarts are less disruptive for operators running rustbgpd as a
  router or route server.
- The implementation is honest: peers see `R=1`, but never
  `forwarding_preserved = true`.
- Crashes and `SIGKILL` still behave like cold starts because no marker is
  written.
- `global.runtime_state_dir` creates a small, reusable home for future
  daemon-owned runtime state.
- This does **not** replace the helper-mode state machine in ADR-0024; it
  complements it.
- The current `Selection_Deferral_Timer` upper bound is the remaining
  coordinated-restart marker lifetime, derived from the maximum effective
  `gr_restart_time` across resolved static peers. This reuses the existing
  configurable planned-restart window rather than introducing a second
  startup-only duration knob.
- `rbgp neighbor <peer>` and its JSON output expose per-family active/released
  state, the queried peer's stamped waiter state, blocking waiter count,
  remaining time, and release reason. Prometheus exposes the same family gate
  and waiter gauges plus bounded release-reason and timeout counters.
