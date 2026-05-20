//! Generationed EVPN runtime model foundation (ADR-0063).
//!
//! This module intentionally models the committed runtime snapshot
//! without adding mutation commands. The daemon still builds the
//! model from startup-resolved tables and SIGHUP continues to pin
//! EVPN edits as restart-required until a future coordinator can
//! validate, drain, replay, and publish a new generation safely.

use crate::ip_vrf::IpVrfTable;
use crate::{EthernetSegment, EvpnInstanceTable};

/// Generation number for the committed EVPN runtime model.
///
/// Generation `1` is the startup snapshot. Future ADR-0063 mutation
/// commands will allocate later generations only after validation
/// succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvpnRuntimeGeneration(u64);

impl EvpnRuntimeGeneration {
    /// Startup generation. Zero is reserved for "unknown" on wire
    /// surfaces that use proto3 scalar defaults.
    pub const STARTUP: Self = Self(1);

    /// Raw generation value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// High-level lifecycle of the committed runtime generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvpnRuntimeLifecycle {
    /// The committed generation is active and no coordinator drain or
    /// activation is in progress.
    Active,
    /// A future mutation has published a generation that is still
    /// activating downstream actors.
    Activating,
    /// A future mutation is draining owned state for a generation.
    Deleting,
    /// A future mutation encountered a retryable/degraded subsystem
    /// condition.
    Degraded,
}

impl EvpnRuntimeLifecycle {
    /// Stable lowercase label for CLI/docs/telemetry-style output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Activating => "activating",
            Self::Deleting => "deleting",
            Self::Degraded => "degraded",
        }
    }
}

/// Runtime mutation state for the coordinator surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvpnRuntimeMutationState {
    /// Mutation commands are not exposed in this foundation slice.
    Disabled,
    /// A future coordinator has no active operation.
    Idle,
    /// A future coordinator is applying an operation.
    InProgress,
    /// A future coordinator's last operation failed and requires
    /// operator attention or retry.
    Failed,
}

impl EvpnRuntimeMutationState {
    /// Stable lowercase label for CLI/docs/telemetry-style output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Idle => "idle",
            Self::InProgress => "in-progress",
            Self::Failed => "failed",
        }
    }
}

/// Immutable committed EVPN runtime model.
///
/// This owns the resolved domain tables that a future coordinator
/// will validate and publish. The first implementation only snapshots
/// startup state; downstream actors still receive their existing
/// table handles until mutation commands are implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeModel {
    generation: EvpnRuntimeGeneration,
    lifecycle: EvpnRuntimeLifecycle,
    mutation_state: EvpnRuntimeMutationState,
    instances: EvpnInstanceTable,
    ip_vrfs: IpVrfTable,
    ethernet_segments: Vec<EthernetSegment>,
}

impl EvpnRuntimeModel {
    /// Build the startup runtime model from already-resolved config
    /// tables.
    #[must_use]
    pub fn startup(
        instances: EvpnInstanceTable,
        ip_vrfs: IpVrfTable,
        ethernet_segments: Vec<EthernetSegment>,
    ) -> Self {
        Self {
            generation: EvpnRuntimeGeneration::STARTUP,
            lifecycle: EvpnRuntimeLifecycle::Active,
            mutation_state: EvpnRuntimeMutationState::Disabled,
            instances,
            ip_vrfs,
            ethernet_segments,
        }
    }

    /// Current committed generation.
    #[must_use]
    pub const fn generation(&self) -> EvpnRuntimeGeneration {
        self.generation
    }

    /// Current high-level lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> EvpnRuntimeLifecycle {
        self.lifecycle
    }

    /// Current mutation state.
    #[must_use]
    pub const fn mutation_state(&self) -> EvpnRuntimeMutationState {
        self.mutation_state
    }

    /// Resolved L2 EVPN instance table for the committed generation.
    #[must_use]
    pub const fn instances(&self) -> &EvpnInstanceTable {
        &self.instances
    }

    /// Resolved IP-VRF table for the committed generation.
    #[must_use]
    pub const fn ip_vrfs(&self) -> &IpVrfTable {
        &self.ip_vrfs
    }

    /// Resolved Ethernet Segment bindings for the committed generation.
    #[must_use]
    pub fn ethernet_segments(&self) -> &[EthernetSegment] {
        &self.ethernet_segments
    }

    /// Compact operator/API summary of the current committed model.
    #[must_use]
    pub fn snapshot(&self) -> EvpnRuntimeSnapshot {
        EvpnRuntimeSnapshot::from_model(self)
    }
}

/// Compact runtime state exported to gRPC/CLI surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeSnapshot {
    /// Committed runtime generation.
    pub generation: EvpnRuntimeGeneration,
    /// Committed generation lifecycle.
    pub lifecycle: EvpnRuntimeLifecycle,
    /// Runtime mutation/coordinator state.
    pub mutation_state: EvpnRuntimeMutationState,
    /// Number of configured L2 EVPN instances.
    pub evpn_instances_count: usize,
    /// Number of configured IP-VRFs.
    pub evpn_ip_vrfs_count: usize,
    /// Number of configured Ethernet Segments.
    pub ethernet_segments_count: usize,
    /// Total `(ES, member VNI)` bindings across Ethernet Segments.
    pub ethernet_segment_member_vnis_count: usize,
    /// Operator-facing summary.
    pub message: &'static str,
}

impl EvpnRuntimeSnapshot {
    /// Build a snapshot from a committed runtime model.
    #[must_use]
    pub fn from_model(model: &EvpnRuntimeModel) -> Self {
        Self {
            generation: model.generation,
            lifecycle: model.lifecycle,
            mutation_state: model.mutation_state,
            evpn_instances_count: model.instances.len(),
            evpn_ip_vrfs_count: model.ip_vrfs.len(),
            ethernet_segments_count: model.ethernet_segments.len(),
            ethernet_segment_member_vnis_count: model
                .ethernet_segments
                .iter()
                .map(|segment| segment.member_vnis.len())
                .sum(),
            message: "startup snapshot active; runtime EVPN mutation disabled",
        }
    }

    /// Build a startup snapshot directly from resolved tables. Useful
    /// for legacy constructors that do not yet own a runtime model.
    #[must_use]
    pub fn startup_from_tables(
        instances: &EvpnInstanceTable,
        ip_vrfs: &IpVrfTable,
        ethernet_segments: &[EthernetSegment],
    ) -> Self {
        Self {
            generation: EvpnRuntimeGeneration::STARTUP,
            lifecycle: EvpnRuntimeLifecycle::Active,
            mutation_state: EvpnRuntimeMutationState::Disabled,
            evpn_instances_count: instances.len(),
            evpn_ip_vrfs_count: ip_vrfs.len(),
            ethernet_segments_count: ethernet_segments.len(),
            ethernet_segment_member_vnis_count: ethernet_segments
                .iter()
                .map(|segment| segment.member_vnis.len())
                .sum(),
            message: "startup snapshot active; runtime EVPN mutation disabled",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_vrf::IpVrfId;
    use crate::{DfAlgorithm, EvpnInstanceId};
    use rustbgpd_wire::EthernetSegmentIdentifier;

    fn segment(member_vnis: &[u32]) -> EthernetSegment {
        EthernetSegment {
            esi: EthernetSegmentIdentifier::new([3, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            member_vnis: member_vnis
                .iter()
                .map(|vni| EvpnInstanceId::new(*vni).unwrap())
                .collect(),
            df_preference: 32_768,
            df_algorithm: DfAlgorithm::DefaultModulo,
            originator_ip: "10.0.0.1".parse().unwrap(),
        }
    }

    #[test]
    fn startup_model_reports_generation_one_active_disabled_mutation() {
        let model =
            EvpnRuntimeModel::startup(EvpnInstanceTable::new(), IpVrfTable::new(), Vec::new());

        assert_eq!(model.generation(), EvpnRuntimeGeneration::STARTUP);
        assert_eq!(model.generation().as_u64(), 1);
        assert_eq!(model.lifecycle(), EvpnRuntimeLifecycle::Active);
        assert_eq!(model.lifecycle().as_str(), "active");
        assert_eq!(model.mutation_state(), EvpnRuntimeMutationState::Disabled);
        assert_eq!(model.mutation_state().as_str(), "disabled");
    }

    #[test]
    fn snapshot_counts_tables_and_es_member_bindings() {
        let segments = vec![segment(&[100, 200]), segment(&[300])];
        let snapshot = EvpnRuntimeSnapshot::startup_from_tables(
            &EvpnInstanceTable::new(),
            &IpVrfTable::new(),
            &segments,
        );

        assert_eq!(snapshot.generation.as_u64(), 1);
        assert_eq!(snapshot.evpn_instances_count, 0);
        assert_eq!(snapshot.evpn_ip_vrfs_count, 0);
        assert_eq!(snapshot.ethernet_segments_count, 2);
        assert_eq!(snapshot.ethernet_segment_member_vnis_count, 3);
        assert_eq!(
            snapshot.message,
            "startup snapshot active; runtime EVPN mutation disabled"
        );
    }

    #[test]
    fn model_snapshot_matches_owned_tables() {
        let ip_vrfs = IpVrfTable::new();
        assert!(ip_vrfs.is_empty());
        // Exercise the concrete table type in this module without
        // needing a full IP-VRF fixture. The runtime model stores it
        // by value and reports through the same table API.
        assert!(IpVrfId::new(5000).is_ok());

        let model =
            EvpnRuntimeModel::startup(EvpnInstanceTable::new(), ip_vrfs, vec![segment(&[100])]);
        let snapshot = model.snapshot();

        assert_eq!(snapshot.lifecycle, EvpnRuntimeLifecycle::Active);
        assert_eq!(snapshot.mutation_state, EvpnRuntimeMutationState::Disabled);
        assert_eq!(snapshot.ethernet_segments_count, 1);
        assert_eq!(snapshot.ethernet_segment_member_vnis_count, 1);
    }
}
