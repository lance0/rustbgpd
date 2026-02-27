# ADR-0012: Separate structural decode from semantic validation for UPDATEs

**Status:** Accepted
**Date:** 2026-02-27

## Context

UPDATE processing involves two distinct concerns:

1. **Structural decode** — Can the bytes be read? Is the TLV format valid?
   Are lengths consistent? This is the codec layer's job.
2. **Semantic validation** — Is the attribute set RFC-compliant? Are mandatory
   attributes present? Are flags correct? Is the NEXT_HOP valid?

These could be combined into a single `decode_and_validate()` function, or
kept as separate passes. The key tension: withdrawal-only UPDATEs carry zero
path attributes, which is structurally valid but would fail semantic checks
(missing mandatory ORIGIN, AS_PATH). Combining the passes would require
special-casing this.

## Decision

Decode and validation are separate functions in separate modules:

- `decode_path_attributes()` in `crates/wire/src/attribute.rs` — structural
- `validate_update_attributes()` in `crates/wire/src/validate.rs` — semantic

The transport layer calls decode first, then conditionally calls validation
only when the UPDATE carries NLRI (announced prefixes). Withdrawal-only
UPDATEs skip validation entirely.

```
UpdateMessage::parse()          → ParsedUpdate (structural)
validate_update_attributes()    → Result<(), UpdateError> (semantic, if has_nlri)
```

## Consequences

**Positive:**
- Withdrawal-only UPDATEs work naturally without special-case logic.
- Each layer has a single responsibility and is independently testable.
- Error types are distinct: `DecodeError` (structural) vs `UpdateError`
  (semantic with NOTIFICATION subcode).
- The validation module can be extended with new checks without touching
  the codec.

**Negative:**
- Two passes over the attribute list instead of one. Negligible cost for
  typical UPDATE sizes (<50 attributes).

**Neutral:**
- The transport layer is responsible for orchestrating the two-step
  pipeline. This is consistent with the transport's existing role as
  the adapter between wire format and domain logic.
