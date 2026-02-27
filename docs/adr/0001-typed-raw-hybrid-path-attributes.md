# ADR-0001: Typed + Raw Hybrid Model for Path Attributes

**Status:** Accepted
**Date:** 2026-02-27

## Context

BGP path attributes are extensible — new attribute types are defined by
new RFCs regularly. A BGP speaker that drops unrecognized optional
transitive attributes breaks interop with peers running newer extensions.
RFC 4271 §5 requires that unrecognized optional transitive attributes be
passed through with the Partial bit set.

We need a representation that gives us type safety for known attributes
while preserving unknown attributes byte-for-byte.

## Decision

Use a hybrid enum model:

```rust
enum PathAttribute {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(Ipv4Addr),
    LocalPref(u32),
    Med(u32),
    Unknown(RawAttribute),
}

struct RawAttribute {
    flags: u8,
    type_code: u8,
    data: Bytes,
}
```

Known attributes are decoded into typed variants. Unknown attributes are
preserved as `RawAttribute` with the original flags, type code, and raw
bytes. On re-advertisement, `RawAttribute` is emitted unchanged except
the Partial bit (0x20) is OR'd into flags.

## Consequences

- **Positive:** Type safety for known attributes. Pattern matching in
  best-path selection. Unknown attributes preserved for interop.
- **Positive:** The Partial bit policy is enforced at a single point
  (encode of `RawAttribute`), not scattered across the codebase.
- **Negative:** Adding a new known attribute type requires extending
  the enum and decode logic. This is acceptable — new attributes are
  infrequent and require careful implementation regardless.
- **Neutral:** ASN values in `AsPath` are always `u32` internally.
  2-byte vs 4-byte encoding is handled at the wire boundary.
