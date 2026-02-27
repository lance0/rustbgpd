# ADR-0003: NOTIFICATION Subcodes as Constants, Not Enums

**Status:** Accepted
**Date:** 2026-02-27

## Context

BGP NOTIFICATION messages carry an error code and subcode. There are 6+
error code families, each with a different set of subcodes defined across
multiple RFCs (4271, 4486, 5492, 8538). We need a typed representation
that is correct, extensible, and doesn't create a combinatorial explosion.

We considered:
1. **Nested enums** — one subcode enum per error code family
2. **Flat enum** — single enum with all (code, subcode) pairs
3. **Typed code enum + raw u8 subcode** with constant modules

## Decision

`NotificationCode` is a typed enum. Subcodes are `u8` with named
constants organized in modules per error code family:

```rust
pub enum NotificationCode {
    MessageHeader = 1,
    OpenMessage = 2,
    UpdateMessage = 3,
    HoldTimerExpired = 4,
    FsmError = 5,
    Cease = 6,
}

pub mod open_subcode {
    pub const UNSUPPORTED_VERSION: u8 = 1;
    pub const BAD_PEER_AS: u8 = 2;
    pub const UNACCEPTABLE_HOLD_TIME: u8 = 6;
    // ...
}
```

## Consequences

- **Positive:** No combinatorial enum hierarchy. Adding a subcode from
  a new RFC is one `pub const` line, not a new enum variant.
- **Positive:** Received NOTIFICATIONs with unknown subcodes are handled
  naturally — they're just `u8` values.
- **Positive:** The FSM constructs specific (code, subcode) pairs and
  knows exactly what they mean. Type safety at the code level is
  sufficient.
- **Negative:** No compile-time exhaustiveness check on subcodes. This
  is acceptable — subcodes are open-ended by design.
- **See also:** ADR-0011 extends this philosophy to error codes with
  `NotificationCode::Unknown(u8)` for unrecognized code bytes.
