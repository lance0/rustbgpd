# ADR-0009: Iterative action loop to avoid async recursion

**Status:** Accepted
**Date:** 2026-02-27

## Context

The transport layer's `drive_fsm` method feeds an event to the FSM and
executes the resulting actions. Some actions produce follow-up FSM events:

- `InitiateTcpConnection` → `TcpConnectionConfirmed` or `TcpConnectionFails`
- Send failure (OPEN/KEEPALIVE write error) → `TcpConnectionFails`

If `execute_actions` called `drive_fsm` directly, this creates async
recursion (`drive_fsm` → `execute_actions` → `drive_fsm`), which Rust's
async system rejects because the future size would be infinite.

Options:
1. **Box::pin the recursive call** — works but adds heap allocation per
   recursion and makes the code harder to follow.
2. **Return follow-up events from `execute_actions`** — the caller loops
   until no more events remain. No recursion, no boxing.

## Decision

`execute_actions` returns `Vec<Event>` of follow-up events. `drive_fsm`
runs an iterative loop:

```rust
async fn drive_fsm(&mut self, initial_event: Event) {
    let mut pending = vec![initial_event];
    while let Some(event) = pending.pop() {
        let actions = self.fsm.handle_event(event);
        let follow_up = self.execute_actions(actions).await;
        pending.extend(follow_up);
    }
}
```

## Consequences

- **Positive:** No async recursion, no `Box::pin`, no heap allocation
  per event cycle.
- **Positive:** Clear data flow — follow-up events are explicit return
  values, not hidden recursive calls.
- **Positive:** Bounded depth in practice — TCP connect produces at most
  one follow-up event, which may produce actions but not further TCP
  connects. The loop terminates quickly.
- **Negative:** Slightly more verbose than a direct recursive call. The
  `Vec<Event>` return type is an extra allocation, but it's typically
  0–1 elements.
