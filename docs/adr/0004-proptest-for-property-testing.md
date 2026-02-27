# ADR-0004: Proptest for Property-Based Testing

**Status:** Accepted
**Date:** 2026-02-27

## Context

The wire crate's core invariant is `decode(encode(x)) == x` for all
valid messages. We need property-based testing to verify this across
the input space rather than relying on hand-picked examples.

Options: `proptest` or `quickcheck`.

## Decision

Use `proptest` as a dev-dependency for property-based testing.

## Consequences

- **Positive:** Better shrinking than quickcheck — when a test fails,
  proptest finds a minimal failing case automatically.
- **Positive:** More ergonomic strategy combinators for building
  arbitrary BGP messages.
- **Positive:** Dominant property testing library in the Rust ecosystem.
- **Neutral:** Slightly longer compile times for dev builds due to
  proc macro overhead. Only affects `cargo test`, not release builds.
