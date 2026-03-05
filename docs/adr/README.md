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
| [0008](0008-single-task-per-peer.md) | Single tokio task per peer for M0 | Accepted | 2026-02-27 |
| [0009](0009-iterative-action-loop.md) | Iterative action loop to avoid async recursion | Accepted | 2026-02-27 |
| [0010](0010-minimal-metrics-server.md) | Minimal TCP metrics server, no HTTP framework | Accepted | 2026-02-27 |
| [0011](0011-unknown-notification-code-variant.md) | Unknown variant for NOTIFICATION error codes | Accepted | 2026-02-27 |
| [0012](0012-separate-decode-from-validation.md) | Separate structural decode from semantic validation for UPDATEs | Accepted | 2026-02-27 |
| [0013](0013-single-task-rib-manager.md) | Single-task RIB manager with channel-based ownership | Accepted | 2026-02-27 |
| [0014](0014-best-path-standalone-function-deterministic-med.md) | Best-path comparison as standalone function with deterministic MED | Accepted | 2026-02-27 |
| [0015](0015-adj-rib-out-inside-rib-manager.md) | Adj-RIB-Out inside RibManager with per-peer outbound channels | Accepted | 2026-02-27 |
| [0016](0016-socket2-for-md5-gtsm.md) | socket2 for TCP MD5 and GTSM socket options | Accepted | 2026-02-27 |
| [0017](0017-peer-manager-channel-based-ownership.md) | PeerManager — channel-based single-task ownership | Accepted | 2026-02-27 |
| [0018](0018-broadcast-channel-for-watch-routes.md) | Broadcast channel for WatchRoutes streaming | Accepted | 2026-02-27 |
| [0019](0019-inbound-tcp-listener.md) | Inbound TCP listener for passive peering | Accepted | 2026-02-27 |
| [0020](0020-global-control-services-coordinated-shutdown.md) | GlobalService, ControlService, and coordinated shutdown | Accepted | 2026-02-27 |
| [0021](0021-tcp-collision-detection.md) | TCP collision detection via PeerManager coordination | Accepted | 2026-02-28 |
| [0022](0022-grpc-server-supervision.md) | gRPC server supervision — unexpected exit triggers shutdown | Accepted | 2026-02-28 |
| [0023](0023-prefix-enum-afi-agnostic-rib.md) | Prefix enum and AFI-agnostic RIB for MP-BGP | Accepted | 2026-02-28 |
| [0024](0024-graceful-restart.md) | Graceful Restart — Receiving Speaker (RFC 4724) | Accepted | 2026-03-01 |
| [0025](0025-extended-communities.md) | Extended Communities (RFC 4360) | Accepted | 2026-03-01 |
| [0026](0026-extended-community-policy.md) | Extended Community Policy Matching | Accepted | 2026-03-01 |
| [0027](0027-route-refresh.md) | Route Refresh (RFC 2918) | Accepted | 2026-03-02 |
| [0028](0028-standard-community-policy.md) | Standard Community Policy Matching (RFC 1997) | Accepted | 2026-03-02 |
| [0029](0029-route-reflector.md) | Route Reflector (RFC 4456) | Accepted | 2026-03-02 |
| [0030](0030-policy-actions.md) | Policy Actions and AS_PATH Regex | Accepted | 2026-03-02 |
| [0031](0031-large-communities.md) | Large Communities (RFC 8092) | Accepted | 2026-03-02 |
| [0032](0032-extended-messages.md) | Extended Messages (RFC 8654) | Accepted | 2026-03-02 |
| [0033](0033-add-path.md) | Add-Path (RFC 7911) | Accepted | 2026-03-02 |
| [0034](0034-rpki-origin-validation.md) | RPKI Origin Validation (RFC 6811 + RFC 8210) | Accepted | 2026-03-03 |
| [0035](0035-flowspec.md) | FlowSpec (RFC 8955 / RFC 8956) | Accepted | 2026-03-03 |
| [0036](0036-policy-chaining.md) | Policy Chaining + Named Policies | Accepted | 2026-03-04 |
| [0037](0037-extended-nexthop.md) | Extended Next Hop Encoding (RFC 8950) | Accepted | 2026-03-04 |
| [0038](0038-enhanced-route-refresh.md) | Enhanced Route Refresh (RFC 7313) | Accepted | 2026-03-04 |
| [0039](0039-transparent-route-server.md) | Transparent Route Server Mode | Accepted | 2026-03-04 |
| [0040](0040-gr-restarting-speaker.md) | Graceful Restart — Minimal Restarting Speaker Mode | Accepted | 2026-03-04 |
| [0041](0041-bmp-exporter.md) | BMP Exporter (RFC 7854) | Accepted | 2026-03-04 |
| [0042](0042-llgr.md) | Long-Lived Graceful Restart (RFC 9494) | Accepted | 2026-03-05 |
| [0043](0043-config-persistence.md) | Config Persistence and SIGHUP Reload | Accepted | 2026-03-05 |
| [0044](0044-mrt-dump-export.md) | MRT Dump Export (RFC 6396) | Accepted | 2026-03-05 |
| [0045](0045-private-as-removal.md) | Private AS Removal | Accepted | 2026-03-05 |

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
