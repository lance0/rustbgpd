# ADR-0011: Unknown Variant for NOTIFICATION Error Codes

**Status:** Accepted
**Date:** 2026-02-27

## Context

BGP NOTIFICATION messages carry an error code byte (RFC 4271 §4.5).
The wire crate's `NotificationCode` enum had named variants for codes
1–6. When decoding a NOTIFICATION with an unrecognized code byte (e.g.,
a future RFC extension), the decoder silently mapped it to `Cease`:

```rust
let code = NotificationCode::from_u8(code_byte)
    .unwrap_or(NotificationCode::Cease);
```

This lost the original byte value, which is a protocol correctness bug:
- Logging and metrics report the wrong error code.
- Re-encoding the NOTIFICATION would produce a different byte on the wire.
- Operators cannot diagnose what the peer actually sent.

The design principle from ADR-0003 (subcodes as raw `u8`) already
handled the open-ended subcode space correctly. The error code enum
needed the same treatment.

## Decision

Add an `Unknown(u8)` variant to `NotificationCode`:

```rust
pub enum NotificationCode {
    MessageHeader,
    OpenMessage,
    UpdateMessage,
    HoldTimerExpired,
    FsmError,
    Cease,
    Unknown(u8),
}
```

`from_u8` is now total (returns `Self`, not `Option<Self>`). Unknown
code bytes are preserved in the `Unknown` variant. `as_u8()` returns
the original byte for all variants.

The `#[repr(u8)]` attribute was removed since `Unknown(u8)` carries
data and cannot use a simple discriminant representation.

## Consequences

- **Positive:** Wire-level fidelity — the original code byte is never
  lost. Decode then encode produces identical bytes for all inputs.
- **Positive:** Logging and metrics report the actual code value, even
  for codes not yet defined in the crate.
- **Positive:** `from_u8` is total, eliminating the need for `unwrap`
  or fallback logic at every call site.
- **Positive:** Property tests now generate `Unknown` codes, covering
  roundtrip correctness for the full `u8` range.
- **Negative:** Pattern matches on `NotificationCode` must handle the
  `Unknown` variant. In practice, this is always a wildcard arm (the
  FSM never constructs `Unknown` — it only appears from the wire).
- **Neutral:** Consistent with the ADR-0003 philosophy that protocol
  values from the wire are open-ended and must not be silently coerced.
