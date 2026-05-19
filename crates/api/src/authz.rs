//! Static gRPC authorization inventory.
//!
//! ADR-0064 uses this table as the code-level source of truth for
//! method risk tiers. Runtime authorization enforces listener-level
//! `AccessMode` checks in `server.rs`, per-listener `max_tier`
//! ceilings in `authz_runtime.rs`, and opt-in per-principal role
//! ceilings when ADR-0064 `enforcement = "tier"` is enabled.

/// Authorization tier assigned to one gRPC method.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuthTier {
    /// Pure liveness / health read with no topology disclosure.
    Read,
    /// Read-only, but exposes topology, routes, policy, metrics, or live state.
    SensitiveRead,
    /// Per-object or reversible daemon state change.
    Mutating,
    /// Process-wide, network-wide, dataplane-injection, or other high-blast-radius operation.
    OperatorOnly,
}

impl AuthTier {
    /// Stable lower-case label used by docs, JSON, and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::SensitiveRead => "sensitive_read",
            Self::Mutating => "mutating",
            Self::OperatorOnly => "operator_only",
        }
    }
}

/// Runtime gRPC authorization enforcement mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthEnforcement {
    /// Preserve legacy listener-wide behavior. Listener `max_tier`
    /// caps still apply, but principal roles do not authorize calls.
    #[default]
    Legacy,
    /// Enforce per-principal role ceilings in addition to listener
    /// `max_tier` caps.
    Tier,
}

impl AuthEnforcement {
    /// Stable lower-case label used by logs and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Tier => "tier",
        }
    }
}

/// ADR-0064 role assigned to an authenticated gRPC principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalRole {
    /// Read-only observer. Can use `read` and `sensitive_read` RPCs.
    Observer,
    /// Automation role. Can use read RPCs plus reversible mutating RPCs.
    Automation,
    /// Operator role. Can use the full gRPC surface.
    Operator,
}

impl PrincipalRole {
    /// Maximum method tier permitted by this role.
    #[must_use]
    pub const fn max_tier(self) -> AuthTier {
        match self {
            Self::Observer => AuthTier::SensitiveRead,
            Self::Automation => AuthTier::Mutating,
            Self::Operator => AuthTier::OperatorOnly,
        }
    }

    /// Stable lower-case label used by structured logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observer => "observer",
            Self::Automation => "automation",
            Self::Operator => "operator",
        }
    }
}

/// Static authorization metadata for one generated gRPC method path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrpcMethodAuthz {
    /// Fully-qualified HTTP/2 path as seen by tonic's router.
    pub path: &'static str,
    /// Fully-qualified service name, e.g. `rustbgpd.v1.RibService`.
    pub service: &'static str,
    /// Method name without the service prefix.
    pub method: &'static str,
    /// Risk tier for this method.
    pub tier: AuthTier,
}

const fn method(
    service: &'static str,
    name: &'static str,
    path: &'static str,
    tier: AuthTier,
) -> GrpcMethodAuthz {
    GrpcMethodAuthz {
        path,
        service,
        method: name,
        tier,
    }
}

/// Complete gRPC method inventory for `proto/rustbgpd.proto`.
pub const METHODS: &[GrpcMethodAuthz] = &[
    method(
        "rustbgpd.v1.GlobalService",
        "GetGlobal",
        "/rustbgpd.v1.GlobalService/GetGlobal",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.GlobalService",
        "SetGlobal",
        "/rustbgpd.v1.GlobalService/SetGlobal",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "DiffRuntimeConfig",
        "/rustbgpd.v1.ConfigService/DiffRuntimeConfig",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "AddNeighbor",
        "/rustbgpd.v1.NeighborService/AddNeighbor",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "DeleteNeighbor",
        "/rustbgpd.v1.NeighborService/DeleteNeighbor",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "ListNeighbors",
        "/rustbgpd.v1.NeighborService/ListNeighbors",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "GetNeighborState",
        "/rustbgpd.v1.NeighborService/GetNeighborState",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "EnableNeighbor",
        "/rustbgpd.v1.NeighborService/EnableNeighbor",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "DisableNeighbor",
        "/rustbgpd.v1.NeighborService/DisableNeighbor",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "SoftResetIn",
        "/rustbgpd.v1.NeighborService/SoftResetIn",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "ListDynamicNeighbors",
        "/rustbgpd.v1.NeighborService/ListDynamicNeighbors",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "AddDynamicNeighbor",
        "/rustbgpd.v1.NeighborService/AddDynamicNeighbor",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "DeleteDynamicNeighbor",
        "/rustbgpd.v1.NeighborService/DeleteDynamicNeighbor",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.NeighborService",
        "SetGracefulShutdown",
        "/rustbgpd.v1.NeighborService/SetGracefulShutdown",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "ListPolicies",
        "/rustbgpd.v1.PolicyService/ListPolicies",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "GetPolicy",
        "/rustbgpd.v1.PolicyService/GetPolicy",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "SetPolicy",
        "/rustbgpd.v1.PolicyService/SetPolicy",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "DeletePolicy",
        "/rustbgpd.v1.PolicyService/DeletePolicy",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "ListNeighborSets",
        "/rustbgpd.v1.PolicyService/ListNeighborSets",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "GetNeighborSet",
        "/rustbgpd.v1.PolicyService/GetNeighborSet",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "SetNeighborSet",
        "/rustbgpd.v1.PolicyService/SetNeighborSet",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "DeleteNeighborSet",
        "/rustbgpd.v1.PolicyService/DeleteNeighborSet",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "GetGlobalPolicyChains",
        "/rustbgpd.v1.PolicyService/GetGlobalPolicyChains",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "SetGlobalImportChain",
        "/rustbgpd.v1.PolicyService/SetGlobalImportChain",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "SetGlobalExportChain",
        "/rustbgpd.v1.PolicyService/SetGlobalExportChain",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "ClearGlobalImportChain",
        "/rustbgpd.v1.PolicyService/ClearGlobalImportChain",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "ClearGlobalExportChain",
        "/rustbgpd.v1.PolicyService/ClearGlobalExportChain",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "GetNeighborPolicyChains",
        "/rustbgpd.v1.PolicyService/GetNeighborPolicyChains",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "SetNeighborImportChain",
        "/rustbgpd.v1.PolicyService/SetNeighborImportChain",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "SetNeighborExportChain",
        "/rustbgpd.v1.PolicyService/SetNeighborExportChain",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "ClearNeighborImportChain",
        "/rustbgpd.v1.PolicyService/ClearNeighborImportChain",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "ClearNeighborExportChain",
        "/rustbgpd.v1.PolicyService/ClearNeighborExportChain",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.PeerGroupService",
        "ListPeerGroups",
        "/rustbgpd.v1.PeerGroupService/ListPeerGroups",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PeerGroupService",
        "GetPeerGroup",
        "/rustbgpd.v1.PeerGroupService/GetPeerGroup",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PeerGroupService",
        "SetPeerGroup",
        "/rustbgpd.v1.PeerGroupService/SetPeerGroup",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.PeerGroupService",
        "DeletePeerGroup",
        "/rustbgpd.v1.PeerGroupService/DeletePeerGroup",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.PeerGroupService",
        "SetNeighborPeerGroup",
        "/rustbgpd.v1.PeerGroupService/SetNeighborPeerGroup",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.PeerGroupService",
        "ClearNeighborPeerGroup",
        "/rustbgpd.v1.PeerGroupService/ClearNeighborPeerGroup",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListReceivedRoutes",
        "/rustbgpd.v1.RibService/ListReceivedRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListBestRoutes",
        "/rustbgpd.v1.RibService/ListBestRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListAdvertisedRoutes",
        "/rustbgpd.v1.RibService/ListAdvertisedRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ExplainAdvertisedRoute",
        "/rustbgpd.v1.RibService/ExplainAdvertisedRoute",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ExplainBestPath",
        "/rustbgpd.v1.RibService/ExplainBestPath",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListBlackholeDiscards",
        "/rustbgpd.v1.RibService/ListBlackholeDiscards",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListFibRoutes",
        "/rustbgpd.v1.RibService/ListFibRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListRouteEvents",
        "/rustbgpd.v1.RibService/ListRouteEvents",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "WatchRoutes",
        "/rustbgpd.v1.RibService/WatchRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListFlowSpecRoutes",
        "/rustbgpd.v1.RibService/ListFlowSpecRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListEvpnRoutes",
        "/rustbgpd.v1.RibService/ListEvpnRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.EventService",
        "WatchEvents",
        "/rustbgpd.v1.EventService/WatchEvents",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.EventService",
        "ListSessionEvents",
        "/rustbgpd.v1.EventService/ListSessionEvents",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.EventService",
        "ListPolicyEvents",
        "/rustbgpd.v1.EventService/ListPolicyEvents",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.InjectionService",
        "AddPath",
        "/rustbgpd.v1.InjectionService/AddPath",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.InjectionService",
        "DeletePath",
        "/rustbgpd.v1.InjectionService/DeletePath",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.InjectionService",
        "AddFlowSpec",
        "/rustbgpd.v1.InjectionService/AddFlowSpec",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.InjectionService",
        "DeleteFlowSpec",
        "/rustbgpd.v1.InjectionService/DeleteFlowSpec",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.InjectionService",
        "AddEvpnRoute",
        "/rustbgpd.v1.InjectionService/AddEvpnRoute",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.InjectionService",
        "DeleteEvpnRoute",
        "/rustbgpd.v1.InjectionService/DeleteEvpnRoute",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.ControlService",
        "Shutdown",
        "/rustbgpd.v1.ControlService/Shutdown",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.ControlService",
        "GetHealth",
        "/rustbgpd.v1.ControlService/GetHealth",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.ControlService",
        "GetMetrics",
        "/rustbgpd.v1.ControlService/GetMetrics",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.ControlService",
        "TriggerMrtDump",
        "/rustbgpd.v1.ControlService/TriggerMrtDump",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.EvpnService",
        "ListEvpnInstances",
        "/rustbgpd.v1.EvpnService/ListEvpnInstances",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.EvpnService",
        "ListEvpnNexthops",
        "/rustbgpd.v1.EvpnService/ListEvpnNexthops",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.EvpnService",
        "ListIpVrfs",
        "/rustbgpd.v1.EvpnService/ListIpVrfs",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.EvpnService",
        "GetIpVrf",
        "/rustbgpd.v1.EvpnService/GetIpVrf",
        AuthTier::SensitiveRead,
    ),
];

/// Find authorization metadata by full tonic method path.
#[must_use]
pub fn method_authz(path: &str) -> Option<&'static GrpcMethodAuthz> {
    METHODS.iter().find(|method| method.path == path)
}

/// Count methods with a given authorization tier.
#[must_use]
pub fn method_count_by_tier(tier: AuthTier) -> usize {
    METHODS.iter().filter(|method| method.tier == tier).count()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{AuthTier, METHODS, method_authz, method_count_by_tier};
    use serde_json::json;

    const PROTO: &str = include_str!("../../../proto/rustbgpd.proto");
    const INVENTORY_JSON: &str = include_str!("../../../docs/grpc-method-inventory.json");

    fn proto_package_from(proto: &str) -> String {
        proto
            .lines()
            .find_map(|raw| {
                raw.trim()
                    .strip_prefix("package ")
                    .map(|package| package.trim_end_matches(';').to_string())
            })
            .expect("proto package declaration missing")
    }

    fn proto_methods_from(proto: &str) -> BTreeSet<String> {
        let package = proto_package_from(proto);
        let mut service = None::<String>;
        let mut service_depth = 0i32;
        let mut methods = BTreeSet::new();
        for raw in proto.lines() {
            let line = raw.trim();
            if service.is_none()
                && let Some(rest) = line.strip_prefix("service ")
            {
                service = rest
                    .split_whitespace()
                    .next()
                    .map(|name| format!("{package}.{name}"));
                service_depth = brace_delta(line);
                continue;
            }
            if let Some(service_name) = service.as_deref() {
                if let Some(rest) = line.strip_prefix("rpc ")
                    && let Some(name) = rest.split('(').next()
                {
                    methods.insert(format!("/{service_name}/{}", name.trim()));
                }
                service_depth += brace_delta(line);
                if service_depth <= 0 {
                    service = None;
                    service_depth = 0;
                }
            }
        }
        methods
    }

    fn proto_methods() -> BTreeSet<String> {
        proto_methods_from(PROTO)
    }

    fn expected_inventory_json() -> serde_json::Value {
        let methods = METHODS
            .iter()
            .map(|method| {
                json!({
                    "service": method.service,
                    "method": method.method,
                    "path": method.path,
                    "tier": method.tier.as_str(),
                })
            })
            .collect::<Vec<_>>();

        json!({
            "schema_version": 1,
            "package": "rustbgpd.v1",
            "source": "crates/api/src/authz.rs",
            "proto": "proto/rustbgpd.proto",
            "method_count": METHODS.len(),
            "tier_counts": {
                "read": method_count_by_tier(AuthTier::Read),
                "sensitive_read": method_count_by_tier(AuthTier::SensitiveRead),
                "mutating": method_count_by_tier(AuthTier::Mutating),
                "operator_only": method_count_by_tier(AuthTier::OperatorOnly),
            },
            "methods": methods,
        })
    }

    fn brace_delta(line: &str) -> i32 {
        let opens = i32::try_from(line.chars().filter(|ch| *ch == '{').count())
            .expect("proto line has more than i32::MAX opening braces");
        let closes = i32::try_from(line.chars().filter(|ch| *ch == '}').count())
            .expect("proto line has more than i32::MAX closing braces");
        opens - closes
    }

    #[test]
    fn method_matrix_covers_every_proto_rpc_once() {
        let proto_methods = proto_methods();
        let matrix_methods = METHODS
            .iter()
            .map(|method| method.path.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(matrix_methods, proto_methods);
        assert_eq!(METHODS.len(), 66);
    }

    #[test]
    fn proto_method_parser_handles_annotated_rpc_blocks() {
        let proto = r#"
            syntax = "proto3";
            package rustbgpd.v1;
            service DemoService {
              rpc First (FirstRequest) returns (FirstResponse) {
                option deprecated = true;
              }
              rpc Second (SecondRequest) returns (SecondResponse);
            }
        "#;
        let methods = proto_methods_from(proto);
        assert_eq!(
            methods,
            BTreeSet::from([
                "/rustbgpd.v1.DemoService/First".to_string(),
                "/rustbgpd.v1.DemoService/Second".to_string(),
            ])
        );
    }

    #[test]
    fn method_matrix_paths_match_service_and_method_fields() {
        for method in METHODS {
            assert_eq!(
                method.path,
                format!("/{}/{}", method.service, method.method),
                "path mismatch for {}.{}",
                method.service,
                method.method
            );
        }
    }

    #[test]
    fn method_matrix_tier_counts_match_inventory() {
        assert_eq!(method_count_by_tier(AuthTier::Read), 0);
        assert_eq!(method_count_by_tier(AuthTier::SensitiveRead), 33);
        assert_eq!(method_count_by_tier(AuthTier::Mutating), 15);
        assert_eq!(method_count_by_tier(AuthTier::OperatorOnly), 18);
    }

    #[test]
    fn machine_readable_inventory_matches_method_matrix() {
        let actual = serde_json::from_str::<serde_json::Value>(INVENTORY_JSON)
            .expect("docs/grpc-method-inventory.json must be valid JSON");
        assert_eq!(actual, expected_inventory_json());
    }

    #[test]
    fn method_lookup_returns_expected_tiers() {
        assert_eq!(
            method_authz("/rustbgpd.v1.ControlService/GetHealth").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/ListBestRoutes").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.NeighborService/AddNeighbor").map(|m| m.tier),
            Some(AuthTier::Mutating)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.ControlService/Shutdown").map(|m| m.tier),
            Some(AuthTier::OperatorOnly)
        );
        assert!(method_authz("/rustbgpd.v1.Nope/Missing").is_none());
    }
}
