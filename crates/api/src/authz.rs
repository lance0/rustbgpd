//! Static gRPC authorization inventory.
//!
//! ADR-0064 uses this table as the code-level source of truth for
//! method risk tiers. Runtime authorization enforces listener-level
//! `AccessMode` checks in `server.rs`, per-listener `max_tier`
//! ceilings in `authz_runtime`, and per-principal role ceilings under
//! ADR-0064 `enforcement = "tier"`, the default since v0.24.0.

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

/// Complete gRPC method inventory for the daemon's generated gRPC protos.
pub const METHODS: &[GrpcMethodAuthz] = &[
    method(
        "gnmi.gNMI",
        "Capabilities",
        "/gnmi.gNMI/Capabilities",
        AuthTier::SensitiveRead,
    ),
    method(
        "gnmi.gNMI",
        "Get",
        "/gnmi.gNMI/Get",
        AuthTier::SensitiveRead,
    ),
    method("gnmi.gNMI", "Set", "/gnmi.gNMI/Set", AuthTier::OperatorOnly),
    method(
        "gnmi.gNMI",
        "Subscribe",
        "/gnmi.gNMI/Subscribe",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.GlobalService",
        "GetGlobal",
        "/rustbgpd.v1.GlobalService/GetGlobal",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "DiffRuntimeConfig",
        "/rustbgpd.v1.ConfigService/DiffRuntimeConfig",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "PlanConfigTransaction",
        "/rustbgpd.v1.ConfigService/PlanConfigTransaction",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "ApplyConfigTransaction",
        "/rustbgpd.v1.ConfigService/ApplyConfigTransaction",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "ConfirmConfigTransaction",
        "/rustbgpd.v1.ConfigService/ConfirmConfigTransaction",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "AbortConfigTransaction",
        "/rustbgpd.v1.ConfigService/AbortConfigTransaction",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "GetConfigTransactionStatus",
        "/rustbgpd.v1.ConfigService/GetConfigTransactionStatus",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "GetEffectiveConfig",
        "/rustbgpd.v1.ConfigService/GetEffectiveConfig",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "ListConfigHistory",
        "/rustbgpd.v1.ConfigService/ListConfigHistory",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.ConfigService",
        "RollbackConfigTransaction",
        "/rustbgpd.v1.ConfigService/RollbackConfigTransaction",
        AuthTier::OperatorOnly,
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
        "RefreshOutbound",
        "/rustbgpd.v1.NeighborService/RefreshOutbound",
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
        "ExplainImportPolicy",
        "/rustbgpd.v1.PolicyService/ExplainImportPolicy",
        AuthTier::SensitiveRead,
    ),
    // LAN-472: same tier as ExplainImportPolicy — it reads the same
    // per-session import diagnostic state, enumerated instead of by
    // point lookup.
    method(
        "rustbgpd.v1.PolicyService",
        "ListRejectedRoutes",
        "/rustbgpd.v1.PolicyService/ListRejectedRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "TestPolicy",
        "/rustbgpd.v1.PolicyService/TestPolicy",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.PolicyService",
        "GetPolicyStats",
        "/rustbgpd.v1.PolicyService/GetPolicyStats",
        AuthTier::SensitiveRead,
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
    // ADR-0074: SetFibTable/DeleteFibTable program the kernel FIB via the
    // ADR-0061 reconciler, but stay `Mutating` on purpose — they are
    // validated, coordinator-serialized, persisted config-surface mutations
    // (the unicast sibling of dynamic-neighbor CRUD), not operator-authored
    // route injection. The decision is pinned in
    // method_lookup_returns_expected_tiers below; do not flip it to "fix" the
    // kernel-dataplane guardrail.
    method(
        "rustbgpd.v1.RibService",
        "SetFibTable",
        "/rustbgpd.v1.RibService/SetFibTable",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.RibService",
        "DeleteFibTable",
        "/rustbgpd.v1.RibService/DeleteFibTable",
        AuthTier::Mutating,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListFibTables",
        "/rustbgpd.v1.RibService/ListFibTables",
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
        "WatchRouteEvents",
        "/rustbgpd.v1.RibService/WatchRouteEvents",
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
        "rustbgpd.v1.RibService",
        "ListBgpLsRoutes",
        "/rustbgpd.v1.RibService/ListBgpLsRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListVpnRoutes",
        "/rustbgpd.v1.RibService/ListVpnRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListLabeledRoutes",
        "/rustbgpd.v1.RibService/ListLabeledRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListRtcRoutes",
        "/rustbgpd.v1.RibService/ListRtcRoutes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListTopologyNodes",
        "/rustbgpd.v1.RibService/ListTopologyNodes",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListTopologyLinks",
        "/rustbgpd.v1.RibService/ListTopologyLinks",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.RibService",
        "ListOrrStatus",
        "/rustbgpd.v1.RibService/ListOrrStatus",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.BfdService",
        "GetBfdSessions",
        "/rustbgpd.v1.BfdService/GetBfdSessions",
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
        "ListEvpnEvents",
        "/rustbgpd.v1.EventService/ListEvpnEvents",
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
        "rustbgpd.v1.EventService",
        "SubscribeFromEvent",
        "/rustbgpd.v1.EventService/SubscribeFromEvent",
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
        "GetEvpnRuntime",
        "/rustbgpd.v1.EvpnService/GetEvpnRuntime",
        AuthTier::SensitiveRead,
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
        "ListEthernetSegments",
        "/rustbgpd.v1.EvpnService/ListEthernetSegments",
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
        "ListManagedNetdevs",
        "/rustbgpd.v1.EvpnService/ListManagedNetdevs",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.EvpnService",
        "GetIpVrf",
        "/rustbgpd.v1.EvpnService/GetIpVrf",
        AuthTier::SensitiveRead,
    ),
    method(
        "rustbgpd.v1.EvpnService",
        "ClearDuplicateMacQuarantine",
        "/rustbgpd.v1.EvpnService/ClearDuplicateMacQuarantine",
        AuthTier::Mutating,
    ),
    // ADR-0084: SetEthernetSegmentDrain is `operator_only` on purpose —
    // draining an ES withdraws its Type 4/EAD routes and the member
    // VNIs' local Type 2 routes, redirecting live customer traffic to
    // the remote PEs' backup path. That is traffic-impacting
    // origination control (a step above ClearDuplicateMacQuarantine's
    // per-key, restorative `Mutating` clear), in the same blast-radius
    // class as SetGracefulShutdown.
    method(
        "rustbgpd.v1.EvpnService",
        "SetEthernetSegmentDrain",
        "/rustbgpd.v1.EvpnService/SetEthernetSegmentDrain",
        AuthTier::OperatorOnly,
    ),
    method(
        "rustbgpd.v1.EvpnService",
        "ApplyEvpnRuntime",
        "/rustbgpd.v1.EvpnService/ApplyEvpnRuntime",
        AuthTier::Mutating,
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
    use std::collections::{BTreeMap, BTreeSet};

    use super::{AuthTier, METHODS, method_authz, method_count_by_tier};
    use serde_json::json;

    const RUSTBGPD_PROTO: &str = include_str!("../../../proto/rustbgpd.proto");
    const GNMI_PROTO: &str =
        include_str!("../../../proto/github.com/openconfig/gnmi/proto/gnmi/gnmi.proto");
    const INVENTORY_JSON: &str = include_str!("../../../docs/grpc-method-inventory.json");
    const INVENTORY_MD: &str = include_str!("../../../docs/grpc-method-inventory.md");
    const AUTHZ_SOURCE_PATH: &str = "crates/api/src/authz.rs";
    const PRIMARY_PROTO_PATH: &str = "proto/rustbgpd.proto";
    const ADDITIONAL_PROTO_PATHS: &[&str] =
        &["proto/github.com/openconfig/gnmi/proto/gnmi/gnmi.proto"];

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
        let mut methods = proto_methods_from(RUSTBGPD_PROTO);
        methods.extend(proto_methods_from(GNMI_PROTO));
        methods
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
            "package": proto_package_from(RUSTBGPD_PROTO),
            "source": AUTHZ_SOURCE_PATH,
            "proto": PRIMARY_PROTO_PATH,
            "additional_protos": ADDITIONAL_PROTO_PATHS,
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

    /// Strip markdown code ticks and emphasis from one table cell.
    fn cell_text(cell: &str) -> String {
        cell.replace(['`', '*'], "").trim().to_owned()
    }

    /// One documented row: `(method path, tier)`.
    type InventoryRow = (String, String);
    /// One `### Service (N RPCs)` heading: `(service, claimed, listed)`.
    type ServiceHeading = (String, usize, usize);

    /// Per-service table rows of `docs/grpc-method-inventory.md`, plus the
    /// claimed and listed RPC count of every per-service heading.
    fn markdown_inventory() -> (BTreeSet<InventoryRow>, Vec<ServiceHeading>) {
        let mut rows = BTreeSet::new();
        let mut headings = Vec::new();
        let mut section: Option<ServiceHeading> = None;
        for line in INVENTORY_MD.lines() {
            if let Some(rest) = line.strip_prefix("### ") {
                headings.extend(section.take());
                let (name, claimed) = rest
                    .split_once(" (")
                    .expect("per-service heading states its RPC count");
                let claimed = claimed
                    .split_whitespace()
                    .next()
                    .and_then(|count| count.parse().ok())
                    .expect("per-service heading states its RPC count");
                let service = if name.contains('.') {
                    name.to_owned()
                } else {
                    format!("rustbgpd.v1.{name}")
                };
                section = Some((service, claimed, 0));
                continue;
            }
            if line.starts_with("## ") {
                headings.extend(section.take());
                continue;
            }
            let Some((service, _, listed)) = section.as_mut() else {
                continue;
            };
            if !line.starts_with("| `") {
                continue;
            }
            let mut cells = line.split('|').skip(1).map(cell_text);
            let method = cells.next().expect("inventory row has a method cell");
            let method = method.strip_suffix(" (stream)").unwrap_or(&method);
            let tier = cells.next().expect("inventory row has a tier cell");
            *listed += 1;
            assert!(
                rows.insert((format!("/{service}/{method}"), tier)),
                "duplicate inventory row for {service}/{method}"
            );
        }
        headings.extend(section);
        (rows, headings)
    }

    /// The `## Totals` table of `docs/grpc-method-inventory.md`, keyed by tier
    /// label plus the `Total` row.
    fn markdown_totals() -> BTreeMap<String, usize> {
        let mut totals = BTreeMap::new();
        let mut in_totals = false;
        for line in INVENTORY_MD.lines() {
            if line.starts_with("## ") {
                in_totals = line == "## Totals";
                continue;
            }
            if !in_totals || !line.starts_with('|') {
                continue;
            }
            let mut cells = line.split('|').skip(1).map(cell_text);
            let (Some(label), Some(count)) = (cells.next(), cells.next()) else {
                continue;
            };
            if let Ok(count) = count.parse() {
                totals.insert(label, count);
            }
        }
        totals
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
        assert_eq!(METHODS.len(), 102);
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
        assert_eq!(method_count_by_tier(AuthTier::SensitiveRead), 59);
        assert_eq!(method_count_by_tier(AuthTier::Mutating), 20);
        assert_eq!(method_count_by_tier(AuthTier::OperatorOnly), 23);
    }

    #[test]
    fn machine_readable_inventory_matches_method_matrix() {
        let actual = serde_json::from_str::<serde_json::Value>(INVENTORY_JSON)
            .expect("docs/grpc-method-inventory.json must be valid JSON");
        assert_eq!(actual, expected_inventory_json());
    }

    /// `docs/grpc-method-inventory.md` is external-review evidence, so it is
    /// fenced to the generated export by set equality in both directions: an
    /// RPC missing from the prose and a stale row surviving in it both fail
    /// here, as does a per-service heading or totals count that stops matching
    /// the rows underneath it.
    #[test]
    fn markdown_inventory_matches_machine_readable_export() {
        let export = serde_json::from_str::<serde_json::Value>(INVENTORY_JSON)
            .expect("docs/grpc-method-inventory.json must be valid JSON");
        let exported = export["methods"]
            .as_array()
            .expect("export lists methods")
            .iter()
            .map(|method| {
                (
                    method["path"].as_str().expect("method path").to_owned(),
                    method["tier"].as_str().expect("method tier").to_owned(),
                )
            })
            .collect::<BTreeSet<_>>();
        let method_count = usize::try_from(
            export["method_count"]
                .as_u64()
                .expect("export method_count"),
        )
        .expect("method count fits usize");

        let (documented, headings) = markdown_inventory();
        let missing = exported.difference(&documented).collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "RPCs absent from the tables: {missing:?}"
        );
        let stale = documented.difference(&exported).collect::<Vec<_>>();
        assert!(stale.is_empty(), "rows absent from the export: {stale:?}");
        assert_eq!(documented.len(), method_count);

        for (service, claimed, listed) in headings {
            assert_eq!(
                claimed, listed,
                "{service} heading claims {claimed} RPCs but lists {listed} rows"
            );
        }

        let mut expected_totals = export["tier_counts"]
            .as_object()
            .expect("export tier_counts")
            .iter()
            .map(|(tier, count)| {
                (
                    tier.clone(),
                    usize::try_from(count.as_u64().expect("tier count"))
                        .expect("tier count fits usize"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        expected_totals.insert("Total".to_owned(), method_count);
        assert_eq!(markdown_totals(), expected_totals);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one assertion per pinned tier decision; splitting would scatter the pins"
    )]
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
            method_authz("/rustbgpd.v1.RibService/ListBgpLsRoutes").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/ListVpnRoutes").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/ListLabeledRoutes").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/ListRtcRoutes").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/ListTopologyNodes").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/ListTopologyLinks").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/ListOrrStatus").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.NeighborService/AddNeighbor").map(|m| m.tier),
            Some(AuthTier::Mutating)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.ConfigService/PlanConfigTransaction").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.ConfigService/ApplyConfigTransaction").map(|m| m.tier),
            Some(AuthTier::OperatorOnly)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.ConfigService/ConfirmConfigTransaction").map(|m| m.tier),
            Some(AuthTier::OperatorOnly)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.ConfigService/AbortConfigTransaction").map(|m| m.tier),
            Some(AuthTier::OperatorOnly)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.ConfigService/GetConfigTransactionStatus").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        // The effective-config dump discloses the whole config (peer lists,
        // policy, topology) but never secret material — the peer manager
        // redacts before the document reaches the service. Read-only
        // full-config disclosure pins at sensitive_read, never read.
        assert_eq!(
            method_authz("/rustbgpd.v1.ConfigService/GetEffectiveConfig").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        // History listing is metadata-only (timestamps, hashes, count
        // summaries), but it still discloses config-change cadence and
        // identity facts — full-config-adjacent reads pin at sensitive_read.
        assert_eq!(
            method_authz("/rustbgpd.v1.ConfigService/ListConfigHistory").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        // Rollback IS an apply: it routes a retained snapshot through the
        // same transaction executor, so it carries the same tier as
        // ApplyConfigTransaction.
        assert_eq!(
            method_authz("/rustbgpd.v1.ConfigService/RollbackConfigTransaction").map(|m| m.tier),
            Some(AuthTier::OperatorOnly)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.EvpnService/GetEvpnRuntime").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.EvpnService/ClearDuplicateMacQuarantine").map(|m| m.tier),
            Some(AuthTier::Mutating)
        );
        // DELIBERATE PIN (ADR-0084): SetEthernetSegmentDrain is
        // `operator_only` — an ES drain withdraws live origination state
        // and redirects customer traffic onto remote PEs' backup paths.
        // Do not lower it to `Mutating` to make automation easier; if an
        // automation role ever needs drains, decide that via an ADR-0084
        // update, not by editing this assertion.
        assert_eq!(
            method_authz("/rustbgpd.v1.EvpnService/SetEthernetSegmentDrain").map(|m| m.tier),
            Some(AuthTier::OperatorOnly)
        );
        // DELIBERATE PIN (ADR-0073 audit, WS2): ApplyEvpnRuntime was the
        // first `Mutating` method that programs the kernel dataplane. It stays
        // `Mutating` on purpose — ADR-0063 accepts only validated
        // shape-bounded EVPN runtime candidates, and moving it to
        // `operator_only` would force EVPN automation to over-grant Operator
        // credentials. Do not flip this to "fix" it; if its scope widens past
        // ADR-0063's bounded shape set (issue #268), change the tier via a
        // deliberate ADR update — not by editing this assertion. See the
        // dataplane-programming RPC guardrail in docs/RELEASE_CHECKLIST.md.
        assert_eq!(
            method_authz("/rustbgpd.v1.EvpnService/ApplyEvpnRuntime").map(|m| m.tier),
            Some(AuthTier::Mutating)
        );
        // DELIBERATE PIN (ADR-0074): SetFibTable/DeleteFibTable program the
        // kernel FIB via the ADR-0061 reconciler — the second and third
        // `Mutating` methods that touch the kernel dataplane after
        // ApplyEvpnRuntime. They stay `Mutating` on purpose: validated,
        // coordinator-serialized, persisted config-surface mutations (the
        // unicast sibling of dynamic-neighbor CRUD) that back-fill
        // already-learned routes, not operator-authored injection.
        // `operator_only` would force FIB automation to over-grant Operator
        // credentials. A dedicated `dataplane_mutating` tier was considered and
        // rejected (no ADR-0064 role maps to it). If scope widens past
        // back-filling learned routes, change the tier via an ADR-0074 update
        // — not by editing these assertions. See the dataplane-programming
        // guardrail in
        // docs/RELEASE_CHECKLIST.md.
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/SetFibTable").map(|m| m.tier),
            Some(AuthTier::Mutating)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/DeleteFibTable").map(|m| m.tier),
            Some(AuthTier::Mutating)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.RibService/ListFibTables").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/rustbgpd.v1.ControlService/Shutdown").map(|m| m.tier),
            Some(AuthTier::OperatorOnly)
        );
        assert_eq!(
            method_authz("/gnmi.gNMI/Capabilities").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/gnmi.gNMI/Get").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/gnmi.gNMI/Subscribe").map(|m| m.tier),
            Some(AuthTier::SensitiveRead)
        );
        assert_eq!(
            method_authz("/gnmi.gNMI/Set").map(|m| m.tier),
            Some(AuthTier::OperatorOnly)
        );
        assert!(method_authz("/rustbgpd.v1.Nope/Missing").is_none());
    }
}
