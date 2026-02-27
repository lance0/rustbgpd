# ADR-0005: Pure state machine FSM with no Result return

**Status:** Accepted
**Date:** 2026-02-27

## Context

The BGP finite state machine (RFC 4271 §8) must handle every possible
combination of state and event. The transport layer will feed events
into the FSM and execute the resulting actions. Two designs were
considered:

1. `handle_event` returns `Result<Vec<Action>, FsmError>` — errors for
   invalid combinations.
2. `handle_event` returns `Vec<Action>` — every input produces a
   well-defined output, including transitions to Idle with NOTIFICATION.

## Decision

`handle_event` returns `Vec<Action>` and never fails. Invalid or
unexpected events in any state produce a NOTIFICATION (FSM Error, code
5) and transition to Idle, matching the RFC 4271 §8 fallback behavior.

The FSM mutates state in place and emits a `StateChanged` action on
every transition for telemetry. `SessionDown` is only emitted when
leaving the Established state — failed handshakes do not produce
session-down events.

## Consequences

- **Positive:** The transport layer needs no error-handling path for FSM
  calls. Every event produces actions to execute.
- **Positive:** Protocol-level errors (invalid OPEN, hold timer expiry)
  are handled uniformly through the action mechanism rather than a
  separate error channel.
- **Positive:** Property testing is straightforward — any sequence of
  events is valid input, and the only invariant is "no panics."
- **Negative:** The caller cannot distinguish "this event was expected"
  from "this event triggered an FSM error" without inspecting the
  returned actions. Acceptable because the transport layer executes
  actions regardless.
