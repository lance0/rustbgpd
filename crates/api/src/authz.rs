//! Static gRPC authorization inventory.
//!
//! ADR-0064 uses this table as the code-level source of truth for
//! method risk tiers. The table is not enforced yet; current runtime
//! authorization is still the listener-level `AccessMode` check in
//! `server.rs`.

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
        AuthTier::Mutating,
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
        AuthTier::Mutating,
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
        AuthTier::Read,
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

    const PROTO: &str = include_str!("../../../proto/rustbgpd.proto");

    fn proto_methods() -> BTreeSet<String> {
        let mut service = None::<String>;
        let mut methods = BTreeSet::new();
        for raw in PROTO.lines() {
            let line = raw.trim();
            if let Some(rest) = line.strip_prefix("service ") {
                service = rest
                    .split_whitespace()
                    .next()
                    .map(|name| format!("rustbgpd.v1.{name}"));
                continue;
            }
            if line == "}" {
                service = None;
                continue;
            }
            let Some(rest) = line.strip_prefix("rpc ") else {
                continue;
            };
            let Some(service) = service.as_deref() else {
                continue;
            };
            let Some(name) = rest.split('(').next() else {
                continue;
            };
            methods.insert(format!("/{service}/{name}"));
        }
        methods
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
    fn method_matrix_tier_counts_match_inventory() {
        assert_eq!(method_count_by_tier(AuthTier::Read), 1);
        assert_eq!(method_count_by_tier(AuthTier::SensitiveRead), 32);
        assert_eq!(method_count_by_tier(AuthTier::Mutating), 17);
        assert_eq!(method_count_by_tier(AuthTier::OperatorOnly), 16);
    }

    #[test]
    fn method_lookup_returns_expected_tiers() {
        assert_eq!(
            method_authz("/rustbgpd.v1.ControlService/GetHealth").map(|m| m.tier),
            Some(AuthTier::Read)
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
