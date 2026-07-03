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
| [0046](0046-notification-gr.md) | Notification GR (RFC 8538) | Accepted | 2026-03-05 |
| [0047](0047-grpc-security-hardening.md) | gRPC Security Hardening | Accepted | 2026-03-06 |
| [0048](0048-rib-memory-optimizations.md) | RIB Memory Optimizations | Accepted | 2026-03-08 |
| [0049](0049-aspa-verification.md) | ASPA Upstream Path Verification | Accepted | 2026-03-13 |
| [0050](0050-evpn-route-reflector.md) | EVPN Route Reflector (RFC 7432 Phase 1) | Accepted | 2026-04-23 |
| [0051](0051-per-peer-outbound-writer-task.md) | Per-peer outbound writer task | Accepted | 2026-04-27 |
| [0052](0052-evpn-vtep-foundation.md) | EVPN VTEP Foundation — Local EVI/VNI Domain Model | Accepted | 2026-05-01 |
| [0053](0053-rfc-8326-graceful-shutdown.md) | RFC 8326 BGP Graceful Shutdown | Accepted | 2026-05-04 |
| [0054](0054-evpn-linux-dataplane-boundary.md) | EVPN Linux Dataplane Boundary | Accepted | 2026-05-04 |
| [0055](0055-evpn-local-mac-origination.md) | EVPN Local-MAC Origination Boundary | Accepted | 2026-05-06 |
| [0056](0056-evpn-sticky-macs.md) | EVPN sticky-MAC operator config | Accepted | 2026-05-08 |
| [0057](0057-evpn-gate-8-observable-df-election.md) | EVPN Gate 8 — observable DF election without forwarding enforcement | Accepted | 2026-05-09 |
| [0058](0058-evpn-gate-9-irb-l3vni.md) | EVPN Gate 9 — symmetric IRB, L3VNI, Type 5 dataplane | Accepted | 2026-05-10 |
| [0059](0059-evpn-aliasing-fdb-nexthop-groups.md) | EVPN aliasing dataplane via FDB nexthop groups | Accepted | 2026-05-12 |
| [0060](0060-rfc-7999-blackhole.md) | RFC 7999 BLACKHOLE receiver scoping and opt-in FIB discard | Accepted | 2026-05-13 |
| [0061](0061-opt-in-unicast-linux-fib-integration.md) | Opt-in unicast Linux FIB integration | Accepted | 2026-05-14 |
| [0062](0062-tcp-ao-foundation.md) | TCP-AO foundation | Accepted | 2026-05-16 |
| [0063](0063-evpn-runtime-instance-mutation.md) | EVPN runtime instance mutation semantics | Accepted | 2026-05-17 |
| [0064](0064-grpc-authorization.md) | gRPC per-method authorization | Accepted | 2026-05-18 |
| [0064-annex](0064-threat-model.md) | gRPC management-plane threat model (ADR-0064 external-review annex) | Draft audit packet | 2026-05-18 |
| [0065](0065-evpn-localbias-split-horizon.md) | EVPN VXLAN local-bias split-horizon (spike-gated) | Accepted | 2026-05-22 |
| [0066](0066-unicast-multipath-ecmp-fib.md) | Unicast multipath / ECMP FIB install | Accepted | 2026-05-24 |
| [0067](0067-bfd-single-hop.md) | Single-hop asynchronous BFD for BGP | Accepted | 2026-05-24 |
| [0068](0068-weighted-multipath.md) | Weighted (unequal-cost) multipath via Link Bandwidth | Accepted | 2026-05-24 |
| [0069](0069-bgp-unnumbered.md) | BGP unnumbered and IPv6 link-local peering | Accepted | 2026-05-25 |
| [0070](0070-gnmi-openconfig-telemetry.md) | gNMI / OpenConfig telemetry and Set adapter | Accepted | 2026-05-25 |
| [0071](0071-bgp-roles-otc.md) | BGP Roles and Only-to-Customer (RFC 9234) | Accepted | 2026-05-26 |
| [0072](0072-durable-event-history.md) | Durable event history (local outbox) | Accepted | 2026-05-26 |
| [0073](0073-import-policy-explain.md) | Import policy explain via per-session decision cache | Accepted | 2026-05-28 |
| [0074](0074-fib-table-crud-authz-tier.md) | Runtime FIB-table CRUD authorization tier | Accepted | 2026-06-01 |
| [0075](0075-outbound-route-filtering.md) | Receive-side Address-Prefix Outbound Route Filtering (ORF) | Accepted | 2026-06-03 |
| [0076](0076-config-transaction-model.md) | Config transaction model foundation | Accepted | 2026-06-03 |
| [0077](0077-mpls-vpn-bgpls-address-family-boundary.md) | MPLS, VPN, and BGP-LS address-family boundary | Accepted | 2026-06-08 |
| [0078](0078-inbound-rib-backpressure.md) | Inbound transport→RIB backpressure — block, never drop | Accepted | 2026-06-10 |
| [0079](0079-kernel-state-crash-restart-reconciliation.md) | Kernel-state crash-restart reconciliation via adoption sweeps | Accepted | 2026-06-10 |
| [0080](0080-cancellation-shielded-runtime-applies.md) | Cancellation-shielded runtime mutation applies | Accepted | 2026-06-10 |
| [0081](0081-atomic-peer-group-reshape.md) | Atomic peer-group session reshapes on the targeted RPC path | Accepted | 2026-06-10 |
| [0082](0082-nda-protocol-ownership-stamp.md) | NDA_PROTOCOL ownership stamping for EVPN FDB/neighbor state | Accepted | 2026-06-10 |
| [0083](0083-evpn-single-active-backup-path.md) | EVPN single-active backup-path pre-install | Accepted | 2026-06-11 |
| [0084](0084-evpn-ethernet-segment-drain.md) | Runtime Ethernet Segment drain | Accepted | 2026-06-12 |
| [0085](0085-evpn-es-interface-binding.md) | Ethernet Segment interface binding — link-driven drain and same-ESI local bias | Accepted | 2026-06-12 |
| [0086](0086-dynamic-peer-group-reconfigure.md) | Peer-group field edits reach live dynamic sessions via post-persist graceful reset | Accepted | 2026-06-12 |
| [0087](0087-evpn-type5-gateway-ip-overlay-index-origination.md) | Native GW-IP overlay-index Type 5 origination (RFC 9136) | Accepted | 2026-06-12 |
| [0088](0088-evpn-vlan-aware-bridge-managed-netdev-boundary.md) | EVPN VLAN-aware bridge and managed netdev boundary | Accepted | 2026-06-15 |
| [0089](0089-evpn-vni-per-bd-vlan-aware-bridge-support.md) | EVPN VNI-per-BD VLAN-aware bridge support | Accepted | 2026-06-15 |
| [0090](0090-evpn-all-active-esi-overlay-index-type5-receive.md) | All-active ESI overlay-index Type 5 receive | Accepted | 2026-06-17 |
| [0091](0091-evpn-managed-netdev-creation.md) | rustbgpd-managed netdev creation | Accepted | 2026-06-19 |
| [0092](0092-evpn-vlan-aware-bundle-service.md) | EVPN VLAN-Aware Bundle service (non-zero Ethernet Tag) | Accepted | 2026-06-19 |
| [0093](0093-evpn-vlan-macip-fdb-correlation.md) | VLAN MAC+IP attribution via FDB correlation on raw bridge ifindexes | Proposed | 2026-06-19 |
| [0094](0094-evpn-vxlan-nondf-filtering-l2miss.md) | EVPN VXLAN all-active BUM filtering via kernel l2_miss (revisits ADR-0065) | Accepted (negative result) | 2026-06-29 |
| [0095](0095-optimal-route-reflection.md) | Optimal Route Reflection via BGP-LS-sourced SPF (RFC 9107) | Accepted | 2026-07-02 |
| [0096](0096-policy-language.md) | A typed, compiled policy language (`.rpol`) | Accepted | 2026-07-02 |
| [0097](0097-bmp-monitoring.md) | BMP monitoring — the trio, BMPv4 framing, and path marking | Accepted | 2026-07-03 |
| [0098](0098-update-groups.md) | RIB-level update groups — shared outbound staging | Accepted | 2026-07-03 |
| [0099](0099-update-groups-v2.md) | Update groups v2 — per-family keying and RT-aware VPN emit | Accepted | 2026-07-03 |
| [0100](0100-parallel-rib-manager.md) | Parallelizing the RibManager (research blueprint) | Proposed | 2026-07-03 |

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
