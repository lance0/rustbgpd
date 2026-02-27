# Architecture Decision Records

Records of significant architectural decisions made during rustbgpd
development. Each record captures the context, decision, and
consequences so future contributors understand *why*, not just *what*.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [0001](0001-typed-raw-hybrid-path-attributes.md) | Typed + raw hybrid model for path attributes | Accepted | 2026-02-27 |
| [0002](0002-inherent-methods-not-traits-for-codec.md) | Inherent methods, not traits, for codec API | Accepted | 2026-02-27 |
| [0003](0003-subcodes-as-constants-not-enums.md) | NOTIFICATION subcodes as constants, not enums | Accepted | 2026-02-27 |
| [0004](0004-proptest-for-property-testing.md) | Proptest for property-based testing | Accepted | 2026-02-27 |
| [0005](0005-fsm-pure-state-machine.md) | Pure state machine FSM with no Result return | Accepted | 2026-02-27 |
| [0006](0006-validate-open-returns-notification.md) | validate_open returns Result\<NegotiatedSession, NotificationMessage\> | Accepted | 2026-02-27 |
| [0007](0007-explicit-prometheus-registry.md) | Explicit Prometheus registry, not global default | Accepted | 2026-02-27 |

## Template

New ADRs should follow this format:

```markdown
# ADR-NNNN: Title

**Status:** Proposed | Accepted | Deprecated | Superseded by ADR-XXXX
**Date:** YYYY-MM-DD

## Context

What is the issue or question being addressed?

## Decision

What was decided?

## Consequences

What are the results — positive, negative, and neutral?
```
