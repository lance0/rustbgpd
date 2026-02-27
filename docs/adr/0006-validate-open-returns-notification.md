# ADR-0006: validate_open returns Result<NegotiatedSession, NotificationMessage>

**Status:** Accepted
**Date:** 2026-02-27

## Context

When the FSM receives an OPEN message from a peer, it must validate
the message against local configuration (version, ASN, hold time, BGP
identifier) and negotiate session parameters. Validation failure
requires sending a specific NOTIFICATION message to the peer.

Two approaches were considered:

1. Return `Result<NegotiatedSession, FsmError>` and map errors to
   NOTIFICATION elsewhere.
2. Return `Result<NegotiatedSession, NotificationMessage>` so the
   failed validation directly produces the exact message to send.

## Decision

`validate_open` returns `Result<NegotiatedSession, NotificationMessage>`.
On failure, the returned NOTIFICATION contains the correct error code,
subcode, and data field per RFC 4271 §6.2, ready to be sent on the wire.

## Consequences

- **Positive:** The FSM handler for `OpenReceived` is simple — on `Err`,
  emit `SendNotification(notification)` and transition to Idle.
- **Positive:** NOTIFICATION construction is co-located with validation
  logic, so the error code/subcode pairing is always correct.
- **Positive:** No intermediate error type needed between validation and
  wire encoding.
- **Negative:** `NotificationMessage` (a wire type) appears in the FSM's
  negotiation module. Acceptable because the FSM already depends on
  `rustbgpd-wire` for `OpenMessage`.
