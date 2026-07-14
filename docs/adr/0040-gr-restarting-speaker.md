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
   Marker v3 records this deadline against Linux `CLOCK_BOOTTIME`, together
   with the boot ID and current time-namespace identity/offset needed to
   prove that the next process is reading the same clock domain. It also
   retains a wall-clock deadline as a bounded compatibility fallback.
4. Dynamic peers added later via gRPC do **not** participate in that window.
5. Once the window expires, subsequent reconnects revert to normal
   `restart_state = false`.
6. On a marker-backed startup, freeze the complete GR-enabled static-peer
   roster before any session starts. Route selection is deferred separately
   for every locally supported family while a roster peer is still awaiting a
   session or its initial End-of-RIB. A family remains under a convergence/EoR
   hold until all roster peers are either:
   - bound to a current session that sends that family's End-of-RIB;
   - excluded because its OPEN omitted GR/the family or carried Restart State;
   - a collision-failback survivor whose post-failback enhanced refresh reaches
     its associated EoRR;
   - or the marker-bounded `Selection_Deferral_Timer` expires.
7. Adj-RIB-In continues ingesting while route selection is deferred. If only
   an `awaiting_refresh` collision survivor remains, rustbgpd stages the current
   Loc-RIB and permits route payloads, while route-refresh responses and EoR
   remain held. Ordinary release selects deferred route identities
   (withdrawals included) before EoR; the timer fallback recomputes an already
   staged collision-failback family before releasing its EoR.
8. Waiters are transport-generation stamped. An ordinary replacement re-arms
   its frozen roster entry, and an EoR from a predecessor or collision loser
   cannot release the gate. If collision resolution instead fails the
   registration back to the exact nonzero, unambiguous surviving session, that
   survivor enters `awaiting_refresh`: its EoR may already have been discarded
   while it was superseded, so an ordinary EoR cannot release it. Once the
   ordinary waiters finish, rustbgpd stages the complete current Loc-RIB but
   withholds downstream EoR and route-refresh responses. A post-failback BoRR
   arms the survivor waiter; only the matching peer EoRR declares convergence
   and releases the held markers. A local refresh timeout sweeps refresh-stale
   routes but is not peer completion. Peers without Enhanced Route Refresh use
   the original `Selection_Deferral_Timer` as the bounded fallback. Every other
   real waiter continues to gate the family.

This mode helps peers retain our routes briefly during a planned restart,
but makes **no claim** that rustbgpd preserved dataplane continuity.

ADR-0104 extends coordinated shutdown with an optional generation-bound
checkpoint publication. It deliberately does not change the startup behavior
or the `forwarding_preserved = false` contract defined here.

Marker v1 is wall-only and generationless; v2 is wall-only and
generation-bound; v3 carries a complete boottime clock domain and permits an
optional checkpoint generation. On Linux, coordinated shutdown publishes v3
when the complete domain can be sampled and represented. Sampling, checked
arithmetic, or serialization-domain failure publishes a complete v1/v2 marker
instead. Startup uses boottime only when the boot ID, current time-namespace
device/inode, and signed seconds plus nanoseconds offset all match. Legacy
markers, a missing live sample, or any mismatch use the wall deadline, always
clamped to the current configured maximum. Equal or past deadlines are
expired. After that one-time resolution the live timer remains process-local
`Instant` time; this decision does not claim suspend-inclusive behavior while
the new daemon is running.

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
