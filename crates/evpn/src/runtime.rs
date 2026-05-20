//! Generationed EVPN runtime model foundation (ADR-0063).
//!
//! This module intentionally models the committed runtime snapshot
//! without adding mutation commands. The daemon still builds the
//! model from startup-resolved tables and SIGHUP continues to pin
//! EVPN edits as restart-required until a future coordinator can
//! validate, drain, replay, and publish a new generation safely.

use std::{collections::BTreeMap, sync::Arc};

use crate::ip_vrf::IpVrfTable;
use crate::{EthernetSegment, EvpnInstanceTable};
use rustbgpd_wire::EthernetSegmentIdentifier;

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

    /// Next generation value a future coordinator would publish after
    /// a candidate model validates and all required converge actions
    /// are planned.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
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
/// This shares the resolved domain tables that startup already hands
/// to downstream actors, so the read-only foundation does not keep a
/// second deep copy of the L2/IP-VRF model for the daemon lifetime. A
/// future coordinator will publish later generations only after
/// validation and converge planning succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeModel {
    generation: EvpnRuntimeGeneration,
    lifecycle: EvpnRuntimeLifecycle,
    mutation_state: EvpnRuntimeMutationState,
    instances: Arc<EvpnInstanceTable>,
    ip_vrfs: Arc<IpVrfTable>,
    ethernet_segments: Vec<EthernetSegment>,
}

impl EvpnRuntimeModel {
    /// Build the startup runtime model from already-resolved config
    /// tables.
    #[must_use]
    pub fn startup<I, V>(instances: I, ip_vrfs: V, ethernet_segments: Vec<EthernetSegment>) -> Self
    where
        I: Into<Arc<EvpnInstanceTable>>,
        V: Into<Arc<IpVrfTable>>,
    {
        Self {
            generation: EvpnRuntimeGeneration::STARTUP,
            lifecycle: EvpnRuntimeLifecycle::Active,
            mutation_state: EvpnRuntimeMutationState::Disabled,
            instances: instances.into(),
            ip_vrfs: ip_vrfs.into(),
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
    pub fn instances(&self) -> &EvpnInstanceTable {
        self.instances.as_ref()
    }

    /// Resolved IP-VRF table for the committed generation.
    #[must_use]
    pub fn ip_vrfs(&self) -> &IpVrfTable {
        self.ip_vrfs.as_ref()
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

    /// Build a pure mutation plan for a fully validated candidate
    /// model without publishing it.
    ///
    /// The config layer remains responsible for syntactic and
    /// cross-table validation. This method only classifies the
    /// already-typed candidate into add/delete/redefine/unchanged
    /// buckets so a future coordinator can attach drain/replay
    /// actions before committing the next generation.
    #[must_use]
    pub fn plan_candidate(&self, candidate: &EvpnRuntimeCandidate) -> EvpnRuntimePlan {
        EvpnRuntimePlan {
            current_generation: self.generation,
            proposed_generation: self.generation.next(),
            evpn_instances: plan_evpn_instances(self.instances(), candidate.instances()),
            ip_vrfs: plan_ip_vrfs(self.ip_vrfs(), candidate.ip_vrfs()),
            ethernet_segments: plan_ethernet_segments(
                &self.ethernet_segments,
                candidate.ethernet_segments(),
            ),
        }
    }
}

/// Fully validated candidate EVPN runtime model.
///
/// Construction accepts already-resolved domain tables. The daemon
/// config layer must call `resolve_evpn_instances`,
/// `resolve_evpn_ip_vrfs`, and `resolve_ethernet_segments` before it
/// creates this value; this type intentionally does not duplicate the
/// TOML parser's validation logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeCandidate {
    instances: EvpnInstanceTable,
    ip_vrfs: IpVrfTable,
    ethernet_segments: Vec<EthernetSegment>,
}

impl EvpnRuntimeCandidate {
    /// Build a candidate from fully resolved EVPN runtime tables.
    #[must_use]
    pub fn new(
        instances: EvpnInstanceTable,
        ip_vrfs: IpVrfTable,
        ethernet_segments: Vec<EthernetSegment>,
    ) -> Self {
        Self {
            instances,
            ip_vrfs,
            ethernet_segments,
        }
    }

    /// Snapshot the currently committed model as a no-op candidate.
    #[must_use]
    pub fn from_model(model: &EvpnRuntimeModel) -> Self {
        Self {
            instances: model.instances().clone(),
            ip_vrfs: model.ip_vrfs().clone(),
            ethernet_segments: model.ethernet_segments.clone(),
        }
    }

    /// Candidate L2 EVPN instances.
    #[must_use]
    pub const fn instances(&self) -> &EvpnInstanceTable {
        &self.instances
    }

    /// Candidate IP-VRF table.
    #[must_use]
    pub const fn ip_vrfs(&self) -> &IpVrfTable {
        &self.ip_vrfs
    }

    /// Candidate Ethernet Segment bindings.
    #[must_use]
    pub fn ethernet_segments(&self) -> &[EthernetSegment] {
        &self.ethernet_segments
    }
}

/// Add/delete/redefine summary for one keyed EVPN runtime domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeChangeSet<K> {
    /// Keys present only in the candidate model.
    pub added: Vec<K>,
    /// Keys present only in the committed model.
    pub deleted: Vec<K>,
    /// Keys present in both models but with changed row content.
    pub redefined: Vec<K>,
    /// Keys present in both models with identical row content.
    pub unchanged: Vec<K>,
}

impl<K> Default for EvpnRuntimeChangeSet<K> {
    fn default() -> Self {
        Self {
            added: Vec::new(),
            deleted: Vec::new(),
            redefined: Vec::new(),
            unchanged: Vec::new(),
        }
    }
}

impl<K> EvpnRuntimeChangeSet<K> {
    /// Whether this domain requires any converge work.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !(self.added.is_empty() && self.deleted.is_empty() && self.redefined.is_empty())
    }
}

/// Pure candidate plan for a future coordinator generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimePlan {
    /// Currently committed generation.
    pub current_generation: EvpnRuntimeGeneration,
    /// Generation that would be committed if the coordinator accepts
    /// this plan and queues every required converge action.
    pub proposed_generation: EvpnRuntimeGeneration,
    /// L2 EVPN instance changes keyed by VNI.
    pub evpn_instances: EvpnRuntimeChangeSet<u32>,
    /// IP-VRF changes keyed by operator-facing name.
    pub ip_vrfs: EvpnRuntimeChangeSet<String>,
    /// Ethernet Segment changes keyed by ESI.
    pub ethernet_segments: EvpnRuntimeChangeSet<EthernetSegmentIdentifier>,
}

impl EvpnRuntimePlan {
    /// True when the candidate is identical to the committed model.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !(self.evpn_instances.has_changes()
            || self.ip_vrfs.has_changes()
            || self.ethernet_segments.has_changes())
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

fn plan_evpn_instances(
    current: &EvpnInstanceTable,
    candidate: &EvpnInstanceTable,
) -> EvpnRuntimeChangeSet<u32> {
    let current = current
        .iter()
        .map(|instance| (instance.id.as_u32(), instance))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .iter()
        .map(|instance| (instance.id.as_u32(), instance))
        .collect::<BTreeMap<_, _>>();
    diff_keyed_maps(&current, &candidate)
}

fn plan_ip_vrfs(current: &IpVrfTable, candidate: &IpVrfTable) -> EvpnRuntimeChangeSet<String> {
    let current = current
        .iter()
        .map(|vrf| (vrf.name.clone(), vrf))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .iter()
        .map(|vrf| (vrf.name.clone(), vrf))
        .collect::<BTreeMap<_, _>>();
    diff_keyed_maps(&current, &candidate)
}

fn plan_ethernet_segments(
    current: &[EthernetSegment],
    candidate: &[EthernetSegment],
) -> EvpnRuntimeChangeSet<EthernetSegmentIdentifier> {
    let current = current
        .iter()
        .map(|segment| (segment.esi, segment))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .iter()
        .map(|segment| (segment.esi, segment))
        .collect::<BTreeMap<_, _>>();
    diff_keyed_maps(&current, &candidate)
}

fn diff_keyed_maps<K, V>(
    current: &BTreeMap<K, &V>,
    candidate: &BTreeMap<K, &V>,
) -> EvpnRuntimeChangeSet<K>
where
    K: Ord + Clone,
    V: PartialEq,
{
    let mut out = EvpnRuntimeChangeSet::default();
    for (key, current_value) in current {
        match candidate.get(key) {
            None => out.deleted.push(key.clone()),
            Some(candidate_value) if *candidate_value == *current_value => {
                out.unchanged.push(key.clone());
            }
            Some(_) => out.redefined.push(key.clone()),
        }
    }
    for key in candidate.keys() {
        if !current.contains_key(key) {
            out.added.push(key.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_vrf::{IpVrf, IpVrfId};
    use crate::{DfAlgorithm, EvpnInstance, EvpnInstanceId, RouteTarget};
    use rustbgpd_wire::{EthernetSegmentIdentifier, MacAddress, RouteDistinguisher};

    fn instance(vni: u32, rd: &str, rt: &str) -> EvpnInstance {
        EvpnInstance::new(
            EvpnInstanceId::new(vni).unwrap(),
            rd.parse::<RouteDistinguisher>().unwrap(),
            vec![rt.parse::<RouteTarget>().unwrap()],
            "10.0.0.1".parse().unwrap(),
            None,
            false,
        )
        .unwrap()
    }

    fn instance_table(instances: Vec<EvpnInstance>) -> EvpnInstanceTable {
        let mut table = EvpnInstanceTable::new();
        for instance in instances {
            table.insert(instance).unwrap();
        }
        table
    }

    fn ip_vrf(name: &str, vni: u32, rd: &str, rt: &str, table_id: u32) -> IpVrf {
        IpVrf::new(
            name.to_string(),
            IpVrfId::new(vni).unwrap(),
            rd.parse::<RouteDistinguisher>().unwrap(),
            vec![rt.parse::<RouteTarget>().unwrap()],
            "10.0.0.1".parse().unwrap(),
            MacAddress::new([0x02, 0, 0, 0, 0, 1]),
            format!("vrf-{name}"),
            format!("vxl-{name}"),
            table_id,
        )
        .unwrap()
    }

    fn ip_vrf_table(vrfs: Vec<IpVrf>) -> IpVrfTable {
        let mut table = IpVrfTable::new();
        for vrf in vrfs {
            table.insert(vrf).unwrap();
        }
        table
    }

    fn segment(member_vnis: &[u32]) -> EthernetSegment {
        segment_with_esi([3, 0, 0, 0, 0, 0, 0, 0, 0, 1], member_vnis)
    }

    fn segment_with_esi(esi: [u8; 10], member_vnis: &[u32]) -> EthernetSegment {
        EthernetSegment {
            esi: EthernetSegmentIdentifier::new(esi),
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
        // needing a full IP-VRF fixture. The runtime model shares it
        // and reports through the same table API.
        assert!(IpVrfId::new(5000).is_ok());

        let model =
            EvpnRuntimeModel::startup(EvpnInstanceTable::new(), ip_vrfs, vec![segment(&[100])]);
        let snapshot = model.snapshot();

        assert_eq!(snapshot.lifecycle, EvpnRuntimeLifecycle::Active);
        assert_eq!(snapshot.mutation_state, EvpnRuntimeMutationState::Disabled);
        assert_eq!(snapshot.ethernet_segments_count, 1);
        assert_eq!(snapshot.ethernet_segment_member_vnis_count, 1);
    }

    #[test]
    fn no_op_candidate_keeps_generation_preview_but_has_no_changes() {
        let model = EvpnRuntimeModel::startup(
            instance_table(vec![instance(100, "65000:100", "65000:100")]),
            ip_vrf_table(vec![ip_vrf("blue", 5000, "65000:5000", "65000:5000", 5000)]),
            vec![segment(&[100])],
        );
        let candidate = EvpnRuntimeCandidate::from_model(&model);
        let plan = model.plan_candidate(&candidate);

        assert_eq!(plan.current_generation.as_u64(), 1);
        assert_eq!(plan.proposed_generation.as_u64(), 2);
        assert!(plan.is_noop());
        assert_eq!(model.generation().as_u64(), 1);
        assert_eq!(model.snapshot().evpn_instances_count, 1);
    }

    #[test]
    fn plan_classifies_l2_add_delete_redefine_and_unchanged() {
        let current = EvpnRuntimeModel::startup(
            instance_table(vec![
                instance(100, "65000:100", "65000:100"),
                instance(200, "65000:200", "65000:200"),
                instance(300, "65000:300", "65000:300"),
            ]),
            IpVrfTable::new(),
            Vec::new(),
        );
        let candidate = EvpnRuntimeCandidate::new(
            instance_table(vec![
                instance(100, "65000:100", "65000:101"),
                instance(300, "65000:300", "65000:300"),
                instance(400, "65000:400", "65000:400"),
            ]),
            IpVrfTable::new(),
            Vec::new(),
        );

        let plan = current.plan_candidate(&candidate);

        assert!(!plan.is_noop());
        assert_eq!(plan.evpn_instances.added, vec![400]);
        assert_eq!(plan.evpn_instances.deleted, vec![200]);
        assert_eq!(plan.evpn_instances.redefined, vec![100]);
        assert_eq!(plan.evpn_instances.unchanged, vec![300]);
    }

    #[test]
    fn plan_tracks_ip_vrf_and_ethernet_segment_changes() {
        let esi_a = EthernetSegmentIdentifier::new([3, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let esi_b = EthernetSegmentIdentifier::new([3, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let current = EvpnRuntimeModel::startup(
            instance_table(vec![instance(100, "65000:100", "65000:100")]),
            ip_vrf_table(vec![ip_vrf("blue", 5000, "65000:5000", "65000:5000", 5000)]),
            vec![segment_with_esi(esi_a.octets(), &[100])],
        );
        let candidate = EvpnRuntimeCandidate::new(
            instance_table(vec![instance(100, "65000:100", "65000:100")]),
            ip_vrf_table(vec![
                ip_vrf("blue", 5000, "65000:5000", "65000:5001", 5000),
                ip_vrf("green", 6000, "65000:6000", "65000:6000", 6000),
            ]),
            vec![
                segment_with_esi(esi_a.octets(), &[100, 200]),
                segment_with_esi(esi_b.octets(), &[100]),
            ],
        );

        let plan = current.plan_candidate(&candidate);

        assert_eq!(plan.ip_vrfs.added, vec!["green".to_string()]);
        assert!(plan.ip_vrfs.deleted.is_empty());
        assert_eq!(plan.ip_vrfs.redefined, vec!["blue".to_string()]);
        assert_eq!(plan.ethernet_segments.added, vec![esi_b]);
        assert!(plan.ethernet_segments.deleted.is_empty());
        assert_eq!(plan.ethernet_segments.redefined, vec![esi_a]);
    }
}
