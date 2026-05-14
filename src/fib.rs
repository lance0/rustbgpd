//! Pure ADR-0061 general unicast FIB projection and diff model.
//!
//! This module intentionally keeps policy and ownership decisions separate from
//! Linux netlink I/O. It translates configured `[[fib_tables]]` plus Loc-RIB
//! best routes into desired kernel route intent, then compares that intent with
//! daemon-owned and observed kernel state. The runtime actor consumes the same
//! `FibPlan` shape without deciding ownership or foreign-route policy inline.

#![allow(
    dead_code,
    reason = "ADR-0061 keeps the pure FIB model usable from focused tests and runtime code"
)]

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::IpAddr;

use rustbgpd_rib::{Route, RouteOrigin};
use rustbgpd_wire::Prefix;

use crate::config::FibTableConfig;

/// Desired general unicast FIB state derived from config and best routes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FibIntent {
    /// Desired daemon-owned route rows, keyed by table / metric / prefix.
    pub routes: BTreeMap<FibRouteKey, FibRoute>,
    /// Routes suppressed during projection with explicit reasons.
    pub drops: Vec<FibDrop>,
}

/// Kernel route identity for ADR-0061-owned routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FibRouteKey {
    /// Linux route table id.
    pub table_id: u32,
    /// Kernel route metric / priority.
    pub metric: u32,
    /// Destination prefix.
    pub prefix: Prefix,
}

impl Ord for FibRouteKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.table_id
            .cmp(&other.table_id)
            .then_with(|| self.metric.cmp(&other.metric))
            .then_with(|| cmp_prefix(self.prefix, other.prefix))
    }
}

impl PartialOrd for FibRouteKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One desired daemon-owned kernel route plus status metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FibRoute {
    /// Operator-facing table name from `[[fib_tables]]`.
    pub table_name: String,
    /// Linux route identity.
    pub key: FibRouteKey,
    /// Kernel forwarding value.
    pub target: FibRouteTarget,
    /// Peer that supplied the Loc-RIB best route.
    pub peer: IpAddr,
    /// How the Loc-RIB best route was learned.
    pub origin_type: RouteOrigin,
    /// Add-Path path identifier from the selected best route.
    pub path_id: u32,
}

/// Kernel forwarding value for a route row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FibRouteTarget {
    /// Gateway / next-hop address.
    pub next_hop: IpAddr,
}

/// Daemon-owned route state. Updated only after successful future apply ops.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FibOwnedState {
    /// Routes rustbgpd believes it owns.
    pub routes: BTreeMap<FibRouteKey, FibRoute>,
}

/// Observed kernel route snapshot for the future Linux FIB actor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FibKernelSnapshot {
    /// Kernel rows matching route identities relevant to this actor.
    pub routes: BTreeMap<FibRouteKey, FibKernelRoute>,
}

/// Observed kernel route value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FibKernelRoute {
    /// Kernel forwarding value.
    pub target: FibRouteTarget,
    /// Kernel route protocol marker.
    pub protocol: FibKernelProtocol,
}

/// Route protocol marker needed for foreign-route preservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FibKernelProtocol {
    /// `RTPROT_BGP`.
    Bgp,
    /// Any non-BGP protocol.
    Other,
}

/// Suppression or conflict reason produced by projection / diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FibDrop {
    /// The route's next-hop family is not supported for this first tranche.
    NextHopFamilyUnsupported {
        /// Table that would have received the route.
        table_name: String,
        /// Destination prefix.
        prefix: Prefix,
        /// Unsupported next-hop.
        next_hop: IpAddr,
    },
    /// A desired route key already exists in the kernel but is not daemon-owned.
    ForeignRouteExists {
        /// Conflicting key.
        key: FibRouteKey,
    },
}

/// Pure route operation plan for a future Linux apply actor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FibPlan {
    /// Ordered route operations.
    pub ops: Vec<FibOp>,
    /// Conflicts or projection drops that suppressed an operation.
    pub drops: Vec<FibDrop>,
}

/// One pure FIB operation. No netlink is performed in this slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FibOp {
    /// Add a missing daemon-owned route.
    Add(FibRoute),
    /// Adopt an already-present `RTPROT_BGP` route at the configured
    /// table / metric / prefix identity after an ungraceful restart.
    Adopt(FibRoute),
    /// Replace an owned route whose kernel forwarding value drifted.
    Replace {
        /// Previously-owned route identity / metadata.
        previous: FibRoute,
        /// Desired replacement route.
        desired: FibRoute,
    },
    /// Remove a daemon-owned route no longer present in desired state.
    Remove(FibRoute),
}

/// Project configured FIB tables and Loc-RIB best routes into desired state.
#[must_use]
pub(crate) fn project_fib_intent(tables: &[FibTableConfig], routes: &[Route]) -> FibIntent {
    let mut intent = FibIntent::default();

    for route in routes {
        for table in tables {
            if !table_allows_prefix(table, route.prefix) {
                continue;
            }
            if !prefix_and_nexthop_same_family(route.prefix, route.next_hop) {
                intent.drops.push(FibDrop::NextHopFamilyUnsupported {
                    table_name: table.name.clone(),
                    prefix: route.prefix,
                    next_hop: route.next_hop,
                });
                continue;
            }

            let key = FibRouteKey {
                table_id: table.table_id,
                metric: table.metric,
                prefix: route.prefix,
            };
            let projected = FibRoute {
                table_name: table.name.clone(),
                key,
                target: FibRouteTarget {
                    next_hop: route.next_hop,
                },
                peer: route.peer,
                origin_type: route.origin_type,
                path_id: route.path_id,
            };
            intent.routes.insert(key, projected);
        }
    }

    intent
}

/// Compute the route operations needed to converge owned state to intent.
#[must_use]
pub(crate) fn compute_fib_diff(
    intent: &FibIntent,
    owned: &FibOwnedState,
    kernel: &FibKernelSnapshot,
) -> FibPlan {
    let mut plan = FibPlan {
        ops: Vec::new(),
        drops: intent.drops.clone(),
    };

    for (key, owned_route) in &owned.routes {
        if intent.routes.contains_key(key) {
            continue;
        }
        match kernel.routes.get(key) {
            Some(route) if route.protocol == FibKernelProtocol::Other => {
                plan.drops.push(FibDrop::ForeignRouteExists { key: *key });
            }
            _ => plan.ops.push(FibOp::Remove(owned_route.clone())),
        }
    }

    for (key, desired) in &intent.routes {
        match (owned.routes.get(key), kernel.routes.get(key)) {
            (None | Some(_), None) => plan.ops.push(FibOp::Add(desired.clone())),
            (None, Some(kernel_route)) if kernel_route.protocol == FibKernelProtocol::Bgp => {
                if kernel_route.target == desired.target {
                    plan.ops.push(FibOp::Adopt(desired.clone()));
                } else {
                    let mut previous = desired.clone();
                    previous.target = kernel_route.target;
                    plan.ops.push(FibOp::Replace {
                        previous,
                        desired: desired.clone(),
                    });
                }
            }
            (None, Some(_)) => {
                plan.drops.push(FibDrop::ForeignRouteExists { key: *key });
            }
            (Some(_), Some(kernel_route)) if kernel_route.protocol == FibKernelProtocol::Other => {
                plan.drops.push(FibDrop::ForeignRouteExists { key: *key });
            }
            (Some(previous), Some(kernel_route)) if kernel_route.target != desired.target => {
                plan.ops.push(FibOp::Replace {
                    previous: previous.clone(),
                    desired: desired.clone(),
                });
            }
            (Some(_), Some(_)) => {}
        }
    }

    plan
}

/// Update owned state after a successful future apply operation.
pub(crate) fn record_fib_success(owned: &mut FibOwnedState, op: &FibOp) {
    match op {
        FibOp::Add(route) | FibOp::Adopt(route) => {
            owned.routes.insert(route.key, route.clone());
        }
        FibOp::Replace { desired, .. } => {
            owned.routes.insert(desired.key, desired.clone());
        }
        FibOp::Remove(route) => {
            owned.routes.remove(&route.key);
        }
    }
}

fn table_allows_prefix(table: &FibTableConfig, prefix: Prefix) -> bool {
    let wanted = match prefix {
        Prefix::V4(_) => "ipv4_unicast",
        Prefix::V6(_) => "ipv6_unicast",
    };
    table.families.iter().any(|family| family == wanted)
}

fn prefix_and_nexthop_same_family(prefix: Prefix, next_hop: IpAddr) -> bool {
    matches!(
        (prefix, next_hop),
        (Prefix::V4(_), IpAddr::V4(_)) | (Prefix::V6(_), IpAddr::V6(_))
    )
}

fn cmp_prefix(left: Prefix, right: Prefix) -> Ordering {
    match (left, right) {
        (Prefix::V4(a), Prefix::V4(b)) => a
            .addr
            .octets()
            .cmp(&b.addr.octets())
            .then(a.len.cmp(&b.len)),
        (Prefix::V6(a), Prefix::V6(b)) => a
            .addr
            .octets()
            .cmp(&b.addr.octets())
            .then(a.len.cmp(&b.len)),
        (Prefix::V4(_), Prefix::V6(_)) => Ordering::Less,
        (Prefix::V6(_), Prefix::V4(_)) => Ordering::Greater,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Instant;

    use rustbgpd_rib::{Route, RouteOrigin};
    use rustbgpd_wire::{
        AsPath, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
    };

    use super::*;
    use crate::config::FibTableConfig;

    fn table(name: &str, table_id: u32, metric: u32, families: &[&str]) -> FibTableConfig {
        FibTableConfig {
            name: name.to_string(),
            table_id,
            metric,
            families: families
                .iter()
                .map(|family| (*family).to_string())
                .collect(),
        }
    }

    fn v4_prefix(octet: u8, len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, octet, 0), len))
    }

    fn v6_prefix(segment: u16, len: u8) -> Prefix {
        Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(0x2001, 0x0db8, segment, 0, 0, 0, 0, 0),
            len,
        ))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn route(prefix: Prefix, next_hop: IpAddr, origin_type: RouteOrigin, path_id: u32) -> Route {
        Route {
            prefix,
            next_hop,
            link_local_next_hop: None,
            peer: ip("198.51.100.1"),
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
            ]),
            received_at: Instant::now(),
            origin_type,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
            is_stale: false,
            is_llgr_stale: false,
            path_id,
            validation_state: RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        }
    }

    fn one_route(key: FibRouteKey, next_hop: &str) -> FibRoute {
        FibRoute {
            table_name: "edge".to_string(),
            key,
            target: FibRouteTarget {
                next_hop: ip(next_hop),
            },
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        }
    }

    fn key(prefix: Prefix) -> FibRouteKey {
        FibRouteKey {
            table_id: 1000,
            metric: 200,
            prefix,
        }
    }

    fn kernel(next_hop: &str, protocol: FibKernelProtocol) -> FibKernelRoute {
        FibKernelRoute {
            target: FibRouteTarget {
                next_hop: ip(next_hop),
            },
            protocol,
        }
    }

    #[test]
    fn empty_tables_produce_empty_intent() {
        let routes = vec![route(
            v4_prefix(2, 24),
            ip("203.0.113.1"),
            RouteOrigin::Ebgp,
            0,
        )];

        let intent = project_fib_intent(&[], &routes);

        assert!(intent.routes.is_empty());
        assert!(intent.drops.is_empty());
    }

    #[test]
    fn projects_ipv4_and_ipv6_when_default_families_are_present() {
        let tables = vec![table("edge", 1000, 200, &["ipv4_unicast", "ipv6_unicast"])];
        let routes = vec![
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 11),
            route(
                v6_prefix(1, 48),
                ip("2001:db8:ffff::1"),
                RouteOrigin::Ibgp,
                12,
            ),
        ];

        let intent = project_fib_intent(&tables, &routes);

        assert_eq!(intent.routes.len(), 2);
        assert!(intent.drops.is_empty());
        assert!(
            intent
                .routes
                .values()
                .any(|route| route.origin_type == RouteOrigin::Ibgp && route.path_id == 12)
        );
    }

    #[test]
    fn table_family_filter_suppresses_other_family_without_drop() {
        let tables = vec![table("v4-only", 1000, 200, &["ipv4_unicast"])];
        let routes = vec![
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            route(
                v6_prefix(1, 48),
                ip("2001:db8:ffff::1"),
                RouteOrigin::Ebgp,
                0,
            ),
        ];

        let intent = project_fib_intent(&tables, &routes);

        assert_eq!(intent.routes.len(), 1);
        assert!(matches!(
            intent.routes.keys().next().unwrap().prefix,
            Prefix::V4(_)
        ));
        assert!(intent.drops.is_empty());
    }

    #[test]
    fn multiple_matching_tables_fan_out_same_best_route() {
        let tables = vec![
            table("edge-a", 1000, 200, &["ipv4_unicast"]),
            table("edge-b", 1001, 300, &["ipv4_unicast"]),
        ];
        let routes = vec![route(
            v4_prefix(2, 24),
            ip("203.0.113.1"),
            RouteOrigin::Local,
            7,
        )];

        let intent = project_fib_intent(&tables, &routes);

        assert_eq!(intent.routes.len(), 2);
        assert!(
            intent
                .routes
                .keys()
                .any(|key| key.table_id == 1000 && key.metric == 200)
        );
        assert!(
            intent
                .routes
                .keys()
                .any(|key| key.table_id == 1001 && key.metric == 300)
        );
        assert!(
            intent
                .routes
                .values()
                .all(|route| route.origin_type == RouteOrigin::Local)
        );
    }

    #[test]
    fn prefix_next_hop_family_mismatch_is_dropped() {
        let tables = vec![table("edge", 1000, 200, &["ipv4_unicast"])];
        let routes = vec![route(
            v4_prefix(2, 24),
            ip("2001:db8::1"),
            RouteOrigin::Ebgp,
            0,
        )];

        let intent = project_fib_intent(&tables, &routes);

        assert!(intent.routes.is_empty());
        assert!(matches!(
            intent.drops.as_slice(),
            [FibDrop::NextHopFamilyUnsupported { table_name, .. }] if table_name == "edge"
        ));
    }

    #[test]
    fn desired_absent_from_owned_and_kernel_emits_add() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route.clone())]),
            drops: vec![],
        };

        let plan = compute_fib_diff(
            &intent,
            &FibOwnedState::default(),
            &FibKernelSnapshot::default(),
        );

        assert_eq!(plan.ops, vec![FibOp::Add(route)]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn desired_owned_with_same_kernel_value_is_noop() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route)]),
            drops: vec![],
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert!(plan.ops.is_empty());
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn desired_owned_with_changed_kernel_value_emits_replace() {
        let previous = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let desired = one_route(previous.key, "203.0.113.2");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(previous.key, previous.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(previous.key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(desired.key, desired.clone())]),
            drops: vec![],
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Replace { previous, desired }]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn owned_route_missing_from_desired_emits_remove() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };

        let plan = compute_fib_diff(&FibIntent::default(), &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Remove(route)]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn foreign_kernel_route_at_desired_key_blocks_add() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.9", FibKernelProtocol::Other))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route.clone())]),
            drops: vec![],
        };

        let plan = compute_fib_diff(&intent, &FibOwnedState::default(), &kernel);

        assert!(plan.ops.is_empty());
        assert_eq!(
            plan.drops,
            vec![FibDrop::ForeignRouteExists { key: route.key }]
        );
    }

    #[test]
    fn stale_bgp_kernel_route_with_same_value_is_adopted_after_restart() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route.clone())]),
            drops: vec![],
        };

        let plan = compute_fib_diff(&intent, &FibOwnedState::default(), &kernel);

        assert_eq!(plan.ops, vec![FibOp::Adopt(route)]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn stale_bgp_kernel_route_with_wrong_value_is_replaced_after_restart() {
        let desired = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let mut previous = desired.clone();
        previous.target = FibRouteTarget {
            next_hop: ip("203.0.113.9"),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(desired.key, kernel("203.0.113.9", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(desired.key, desired.clone())]),
            drops: vec![],
        };

        let plan = compute_fib_diff(&intent, &FibOwnedState::default(), &kernel);

        assert_eq!(plan.ops, vec![FibOp::Replace { previous, desired }]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn foreign_kernel_route_not_owned_and_not_desired_is_ignored() {
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(
                key(v4_prefix(2, 24)),
                kernel("203.0.113.9", FibKernelProtocol::Other),
            )]),
        };

        let plan = compute_fib_diff(&FibIntent::default(), &FibOwnedState::default(), &kernel);

        assert!(plan.ops.is_empty());
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn owned_route_missing_from_kernel_readds_from_desired() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route.clone())]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route.clone())]),
            drops: vec![],
        };

        let plan = compute_fib_diff(&intent, &owned, &FibKernelSnapshot::default());

        assert_eq!(plan.ops, vec![FibOp::Add(route)]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn record_success_updates_owned_state() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let replacement = one_route(route.key, "203.0.113.2");
        let mut owned = FibOwnedState::default();

        record_fib_success(&mut owned, &FibOp::Add(route.clone()));
        assert_eq!(owned.routes.get(&route.key), Some(&route));

        record_fib_success(&mut owned, &FibOp::Adopt(route.clone()));
        assert_eq!(owned.routes.get(&route.key), Some(&route));

        record_fib_success(
            &mut owned,
            &FibOp::Replace {
                previous: route.clone(),
                desired: replacement.clone(),
            },
        );
        assert_eq!(owned.routes.get(&route.key), Some(&replacement));

        record_fib_success(&mut owned, &FibOp::Remove(replacement.clone()));
        assert!(owned.routes.is_empty());
    }
}
