# ADR-0040: Graceful Restart — Minimal Restarting Speaker Mode

**Status:** Accepted
**Date:** 2026-03-04

## Context

rustbgpd already implements Graceful Restart helper mode (ADR-0024), so it
can preserve a restarting peer's routes. That still leaves a production gap:
when **rustbgpd itself** restarts, peers immediately withdraw its routes
unless we advertise restarting-speaker state (`R=1`) in our next OPEN.

The codebase does **not** own or verify the forwarding plane:

1. There is no FIB integration.
2. There is no persisted RIB snapshot across process restart.
3. There is no crash-safe journal.

So a full RFC 4724 “forwarding state preserved” implementation would be
misleading today.

## Decision

Implement a **minimal, honest restarting-speaker mode**:

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

This mode helps peers retain our routes briefly during a planned restart,
but makes **no claim** that rustbgpd preserved dataplane continuity.

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
