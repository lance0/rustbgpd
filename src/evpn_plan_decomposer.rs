//! EVPN runtime plan decomposer (#268, ADR-0063).
//!
//! Turns a *mixed* EVPN runtime candidate — one the converger dispatch
//! rejects as an unsupported composition — into an ordered sequence of
//! already-supported primitive plans. Each step is applied through the
//! unchanged converge path (its own validation, its own generation
//! commit), so one SIGHUP / `ApplyEvpnRuntime` produces **N committed
//! runtime generations**, one per step.
//!
//! # Ordering contract
//!
//! Steps are emitted in a fixed phase order:
//!
//! 1. **deletes** — every deleted L2VNI / IP-VRF / Ethernet Segment in
//!    one step (routing to the existing single-delete or atomic
//!    tenant-teardown shapes). Surviving Ethernet Segments are
//!    member-shrunk by exactly the deleted VNIs.
//! 2. **redefines** — one batch step for L2VNI redefines, then one step
//!    per redefined IP-VRF, then one step per redefined Ethernet
//!    Segment (each primitive validator accepts exactly one). ES
//!    redefines at this phase carry the candidate row with any
//!    *newly added* member VNIs held back for the add step.
//! 3. **relink** — one pure `ip_vrf` relink step moving every surviving
//!    L2VNI's link to its candidate target.
//! 4. **adds** — everything remaining, as one additive build-up (or
//!    single-add) step whose candidate is the operator's candidate
//!    verbatim.
//!
//! Deletes-first frees identities (VNIs, VRF names, table ids, ESIs,
//! ES-member slots) that later adds may reuse; adds-last guarantees
//! every earlier step references only rows that already exist.
//!
//! # Shapes where the fixed order is WRONG (fail closed, no reordering)
//!
//! - **Relink away from a deleted IP-VRF**: the delete step runs before
//!   the relink step, so the surviving L2VNI's link would dangle.
//!   Apply the relink first, then delete the IP-VRF (two changes).
//! - **Relink of an existing L2VNI onto a newly added IP-VRF**: the
//!   relink step runs before the add step, so the target VRF does not
//!   exist yet. Add the IP-VRF first, then relink (two changes).
//! - **Ethernet Segment left memberless mid-sequence**: deleting all of
//!   an ES's current member VNIs while re-membering it with VNIs that
//!   only appear in the add step (or redefining away every
//!   pre-existing member) would leave the ES empty between steps.
//! - Any step that fails its primitive validator (notably an IP-VRF
//!   **L3VNI / device / table identity redefine**, which is
//!   restart-required by design) fails the whole candidate closed with
//!   that validator's error, naming the offending step, before any
//!   step commits.
//!
//! # Failure semantics
//!
//! The precondition simulation below validates every step against the
//! model it would see, *before anything commits*. A residual
//! mid-sequence failure (actor gone, publish failure) is **fail-stop**:
//! generations committed by earlier steps stay committed (no
//! cross-step rollback), the coordinator pins the last good model, and
//! the operator fixes the config and re-SIGHUPs / re-applies — the
//! next attempt replans from the committed model and converges only
//! the remainder.

use std::collections::{BTreeMap, BTreeSet};

use rustbgpd_evpn::{
    EthernetSegment, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, EvpnRuntimeCandidate,
    EvpnRuntimeModel, EvpnRuntimePlan, IpVrf, IpVrfTable,
};
use rustbgpd_wire::EthernetSegmentIdentifier;

use crate::evpn_runtime_converger::validate_supported_plan_shape;

/// One primitive step of a decomposed mixed candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecomposedStep {
    /// Operator-facing summary of what this step changes.
    pub(crate) description: String,
    /// Full-model candidate for this step; applied through the
    /// existing converge path and committed as its own generation.
    pub(crate) candidate: EvpnRuntimeCandidate,
}

/// Why a candidate did not decompose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EvpnDecomposeError {
    /// The plan is already a supported primitive shape (or a no-op);
    /// decomposition does not apply and the caller's original outcome
    /// stands.
    AlreadyPrimitive,
    /// The candidate cannot decompose into supported primitive steps;
    /// the message names the offending step and embeds the primitive
    /// validator's error. Nothing was committed.
    Unsupported(String),
}

fn unsupported(message: impl Into<String>) -> EvpnDecomposeError {
    EvpnDecomposeError::Unsupported(message.into())
}

fn parse_vnis(raw: &[u32]) -> Result<BTreeSet<EvpnInstanceId>, EvpnDecomposeError> {
    raw.iter()
        .map(|&raw| {
            EvpnInstanceId::new(raw)
                .map_err(|err| unsupported(format!("invalid planned L2VNI {raw}: {err}")))
        })
        .collect()
}

fn build_candidate(
    instances: &BTreeMap<EvpnInstanceId, EvpnInstance>,
    vrfs: &BTreeMap<String, IpVrf>,
    links: &BTreeMap<EvpnInstanceId, String>,
    segments: &BTreeMap<EthernetSegmentIdentifier, EthernetSegment>,
) -> Result<EvpnRuntimeCandidate, EvpnDecomposeError> {
    let mut instance_table = EvpnInstanceTable::new();
    for instance in instances.values() {
        instance_table.insert(instance.clone()).map_err(|err| {
            unsupported(format!(
                "cannot decompose: intermediate L2VNI table invalid: {err}"
            ))
        })?;
    }
    let mut vrf_table = IpVrfTable::new();
    for vrf in vrfs.values() {
        vrf_table.insert(vrf.clone()).map_err(|err| {
            unsupported(format!(
                "cannot decompose: intermediate IP-VRF table invalid: {err}"
            ))
        })?;
    }
    for (vni, name) in links {
        vrf_table.mark_referenced_by_l2vni(name.clone(), *vni);
    }
    Ok(EvpnRuntimeCandidate::new(
        instance_table,
        vrf_table,
        segments.values().cloned().collect(),
    ))
}

/// Decompose a mixed EVPN runtime candidate into ordered primitive
/// steps (deletes → redefines → relink → adds). See the module doc for
/// the ordering contract and the fail-closed wrong-order shapes.
///
/// # Errors
/// [`EvpnDecomposeError::AlreadyPrimitive`] when the plan is a no-op or
/// already a supported single shape; [`EvpnDecomposeError::Unsupported`]
/// when a wrong-order shape or an unsupported step (e.g. an IP-VRF
/// identity redefine) makes the whole candidate fail closed.
#[expect(
    clippy::too_many_lines,
    reason = "the phase-ordered synthesis reads clearest as one sequence mirroring the module-doc ordering contract"
)]
pub(crate) fn decompose_evpn_runtime_candidate(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> Result<Vec<DecomposedStep>, EvpnDecomposeError> {
    if plan.is_noop() || validate_supported_plan_shape(current, candidate, plan).is_ok() {
        return Err(EvpnDecomposeError::AlreadyPrimitive);
    }

    let deleted_vnis = parse_vnis(&plan.evpn_instances.deleted)?;
    let added_vnis = parse_vnis(&plan.evpn_instances.added)?;
    let redefined_vnis = parse_vnis(&plan.evpn_instances.redefined)?;
    let deleted_vrfs: BTreeSet<&String> = plan.ip_vrfs.deleted.iter().collect();
    let added_vrfs: BTreeSet<&String> = plan.ip_vrfs.added.iter().collect();

    let cur_links = current.ip_vrfs().l2vni_link_map();
    let cand_links = candidate.ip_vrfs().l2vni_link_map();

    // Wrong-order guard: a surviving L2VNI still linked (in the committed
    // model) to an IP-VRF this candidate deletes would dangle when the
    // delete step (ordered first) runs.
    for (vni, vrf_name) in &cur_links {
        if !deleted_vnis.contains(vni) && deleted_vrfs.contains(vrf_name) {
            return Err(unsupported(format!(
                "cannot decompose: IP-VRF {vrf_name:?} is deleted while surviving L2VNI {vni} \
                 still links to it when the delete step (ordered first) runs; apply the \
                 relink/unlink as its own change first, then delete the IP-VRF"
            )));
        }
    }
    // Wrong-order guard: an existing L2VNI relinking onto an IP-VRF this
    // candidate adds would target a VRF that does not exist until the add
    // step (ordered last).
    for (vni, vrf_name) in &cand_links {
        if !added_vnis.contains(vni) && added_vrfs.contains(vrf_name) {
            return Err(unsupported(format!(
                "cannot decompose: L2VNI {vni} links to IP-VRF {vrf_name:?}, which is added \
                 only in the final add step (relinks are ordered before adds); add the IP-VRF \
                 as its own change first, then relink"
            )));
        }
    }

    // Working state, advanced phase by phase from the committed model.
    let mut instances: BTreeMap<EvpnInstanceId, EvpnInstance> = current
        .instances()
        .iter()
        .map(|instance| (instance.id, instance.clone()))
        .collect();
    let mut vrfs: BTreeMap<String, IpVrf> = current
        .ip_vrfs()
        .iter()
        .map(|vrf| (vrf.name.clone(), vrf.clone()))
        .collect();
    let mut links = cur_links;
    let mut segments: BTreeMap<EthernetSegmentIdentifier, EthernetSegment> = current
        .ethernet_segments()
        .iter()
        .map(|segment| (segment.esi, segment.clone()))
        .collect();

    let mut steps: Vec<DecomposedStep> = Vec::new();

    // Phase 1: deletes (one step; routes to single-delete or tenant teardown).
    if !deleted_vnis.is_empty()
        || !plan.ip_vrfs.deleted.is_empty()
        || !plan.ethernet_segments.deleted.is_empty()
    {
        for vni in &deleted_vnis {
            instances.remove(vni);
            links.remove(vni);
        }
        for name in &plan.ip_vrfs.deleted {
            vrfs.remove(name);
        }
        for esi in &plan.ethernet_segments.deleted {
            segments.remove(esi);
        }
        for segment in segments.values_mut() {
            let shrunk: BTreeSet<EvpnInstanceId> = segment
                .member_vnis
                .iter()
                .filter(|vni| !deleted_vnis.contains(vni))
                .copied()
                .collect();
            if shrunk.len() != segment.member_vnis.len() {
                if shrunk.is_empty() {
                    return Err(unsupported(format!(
                        "cannot decompose: deleting its current member VNIs would leave \
                         Ethernet Segment {} with no members at the delete step (ordered \
                         first); replace the segment's membership in its own change instead",
                        segment.esi
                    )));
                }
                segment.member_vnis = shrunk;
            }
        }
        steps.push(DecomposedStep {
            description: format!(
                "deletes ({} L2VNI, {} IP-VRF, {} Ethernet Segment)",
                deleted_vnis.len(),
                plan.ip_vrfs.deleted.len(),
                plan.ethernet_segments.deleted.len()
            ),
            candidate: build_candidate(&instances, &vrfs, &links, &segments)?,
        });
    }

    // Phase 2a: L2VNI redefines (one batch step; single and batch are both
    // supported primitive shapes).
    if !redefined_vnis.is_empty() {
        for vni in &redefined_vnis {
            let row = candidate.instances().get(*vni).ok_or_else(|| {
                unsupported(format!(
                    "candidate is missing planned redefined L2VNI {vni}"
                ))
            })?;
            instances.insert(*vni, row.clone());
        }
        steps.push(DecomposedStep {
            description: format!("L2VNI redefine ({} instance(s))", redefined_vnis.len()),
            candidate: build_candidate(&instances, &vrfs, &links, &segments)?,
        });
    }

    // Phase 2b: IP-VRF redefines (one step per VRF; the primitive validator
    // accepts exactly one, and rejects identity redefines fail-closed).
    let mut redefined_vrfs = plan.ip_vrfs.redefined.clone();
    redefined_vrfs.sort();
    for name in &redefined_vrfs {
        let row = candidate.ip_vrfs().get(name).ok_or_else(|| {
            unsupported(format!(
                "candidate is missing planned redefined IP-VRF {name:?}"
            ))
        })?;
        vrfs.insert(name.clone(), row.clone());
        steps.push(DecomposedStep {
            description: format!("IP-VRF {name:?} redefine"),
            candidate: build_candidate(&instances, &vrfs, &links, &segments)?,
        });
    }

    // Phase 2c: Ethernet Segment redefines (one step per ES). Newly added
    // member VNIs are held back for the add step (additive member
    // expansion); a redefine whose only delta is that expansion needs no
    // step here.
    let mut redefined_esis = plan.ethernet_segments.redefined.clone();
    redefined_esis.sort();
    for esi in &redefined_esis {
        let cand_row = candidate
            .ethernet_segments()
            .iter()
            .find(|segment| segment.esi == *esi)
            .ok_or_else(|| {
                unsupported(format!(
                    "candidate is missing planned redefined Ethernet Segment {esi}"
                ))
            })?;
        let working = segments.get(esi).ok_or_else(|| {
            unsupported(format!(
                "planned redefined Ethernet Segment {esi} is not committed"
            ))
        })?;
        let mut target = cand_row.clone();
        target.member_vnis = cand_row
            .member_vnis
            .iter()
            .filter(|vni| !added_vnis.contains(vni))
            .copied()
            .collect();
        if target == *working {
            continue;
        }
        if target.member_vnis.is_empty() {
            return Err(unsupported(format!(
                "cannot decompose: every candidate member VNI of Ethernet Segment {esi} is \
                 newly added, so the redefine step (ordered before adds) would leave the \
                 segment with no members; add the member VNIs first, then redefine the segment"
            )));
        }
        segments.insert(*esi, target);
        steps.push(DecomposedStep {
            description: format!("Ethernet Segment {esi} redefine"),
            candidate: build_candidate(&instances, &vrfs, &links, &segments)?,
        });
    }

    // Phase 3: pure ip_vrf relink for surviving L2VNIs.
    let desired_links: BTreeMap<EvpnInstanceId, String> = cand_links
        .iter()
        .filter(|(vni, _)| instances.contains_key(vni))
        .map(|(vni, name)| (*vni, name.clone()))
        .collect();
    if desired_links != links {
        links = desired_links;
        steps.push(DecomposedStep {
            description: "ip_vrf relink".to_string(),
            candidate: build_candidate(&instances, &vrfs, &links, &segments)?,
        });
    }

    // Phase 4: adds — the final step is the operator's candidate verbatim.
    let working = build_candidate(&instances, &vrfs, &links, &segments)?;
    if working != *candidate {
        steps.push(DecomposedStep {
            description: format!(
                "adds ({} L2VNI, {} IP-VRF, {} Ethernet Segment)",
                added_vnis.len(),
                plan.ip_vrfs.added.len(),
                plan.ethernet_segments.added.len()
            ),
            candidate: candidate.clone(),
        });
    }

    if steps.len() < 2 {
        // A single-step "decomposition" is the original plan; the caller's
        // original outcome (today's fail-closed error) stands.
        return Err(EvpnDecomposeError::AlreadyPrimitive);
    }

    // Precondition: simulate the sequence and validate every step as a
    // supported primitive shape BEFORE anything commits. A failure here
    // fails the whole candidate closed, naming the offending step.
    let total = steps.len();
    let mut model = current.clone();
    for (index, step) in steps.iter().enumerate() {
        let step_plan = model.plan_candidate(&step.candidate);
        validate_supported_plan_shape(&model, &step.candidate, &step_plan).map_err(|err| {
            unsupported(format!(
                "mixed EVPN runtime candidate does not decompose into supported primitive \
                 steps: step {}/{} ({}) fails validation: {}",
                index + 1,
                total,
                step.description,
                err.message()
            ))
        })?;
        model = EvpnRuntimeModel::startup(
            step.candidate.instances().clone(),
            step.candidate.ip_vrfs().clone(),
            step.candidate.ethernet_segments().to_vec(),
        );
    }

    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn candidate_from_toml(toml: &str) -> EvpnRuntimeCandidate {
        let config = Config::load_toml_with_diagnostics(toml, "decomposer test config").unwrap();
        EvpnRuntimeCandidate::new(
            config.resolve_evpn_instances().unwrap(),
            config.resolve_evpn_ip_vrfs().unwrap(),
            config.resolve_ethernet_segments().unwrap(),
        )
    }

    fn model_from_toml(toml: &str) -> EvpnRuntimeModel {
        let candidate = candidate_from_toml(toml);
        EvpnRuntimeModel::startup(
            candidate.instances().clone(),
            candidate.ip_vrfs().clone(),
            candidate.ethernet_segments().to_vec(),
        )
    }

    fn decompose(
        current_toml: &str,
        candidate_toml: &str,
    ) -> Result<Vec<DecomposedStep>, EvpnDecomposeError> {
        let current = model_from_toml(current_toml);
        let candidate = candidate_from_toml(candidate_toml);
        let plan = current.plan_candidate(&candidate);
        decompose_evpn_runtime_candidate(&current, &candidate, &plan)
    }

    const HEADER: &str = r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[security.grpc]
enforcement = "legacy"
"#;

    fn with_header(body: &str) -> String {
        format!("{HEADER}{body}")
    }

    fn vni(raw: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(raw).unwrap()
    }

    // The maintainer's #268 example shape: delete an ES, redefine its
    // (surviving) member L2VNI, and add a new L2VNI — one candidate.
    fn maintainer_example() -> (String, String) {
        let current = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#,
        );
        let candidate = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:101"
route_targets = ["65000:101"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#,
        );
        (current, candidate)
    }

    #[test]
    fn maintainer_example_decomposes_deletes_then_redefine_then_add() {
        let (current, candidate) = maintainer_example();
        let steps = decompose(&current, &candidate).unwrap();
        assert_eq!(
            steps.len(),
            3,
            "expected deletes, redefine, add: {steps:#?}"
        );

        // Step 1: ES delete only; VNI 100 keeps its committed definition.
        assert!(steps[0].description.starts_with("deletes"));
        assert!(steps[0].candidate.ethernet_segments().is_empty());
        assert_eq!(
            steps[0]
                .candidate
                .instances()
                .get(vni(100))
                .unwrap()
                .rd
                .to_string(),
            "65000:100"
        );
        assert!(steps[0].candidate.instances().get(vni(200)).is_none());

        // Step 2: L2VNI 100 redefined; 200 still absent.
        assert!(steps[1].description.starts_with("L2VNI redefine"));
        assert_eq!(
            steps[1]
                .candidate
                .instances()
                .get(vni(100))
                .unwrap()
                .rd
                .to_string(),
            "65000:101"
        );
        assert!(steps[1].candidate.instances().get(vni(200)).is_none());

        // Step 3: the add; final candidate verbatim.
        assert!(steps[2].description.starts_with("adds"));
        assert!(steps[2].candidate.instances().get(vni(200)).is_some());
    }

    #[test]
    fn supported_single_shape_is_already_primitive() {
        let current = with_header("");
        let candidate = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
"#,
        );
        assert_eq!(
            decompose(&current, &candidate),
            Err(EvpnDecomposeError::AlreadyPrimitive)
        );
    }

    #[test]
    fn noop_is_already_primitive() {
        let current = with_header("");
        assert_eq!(
            decompose(&current, &current.clone()),
            Err(EvpnDecomposeError::AlreadyPrimitive)
        );
    }

    #[test]
    fn ip_vrf_identity_redefine_fails_closed_naming_the_step() {
        // Mixed: L2VNI add + IP-VRF l3vni (identity) redefine. The whole
        // candidate must fail closed with the identity validator's error,
        // naming the offending step, before anything commits.
        let current = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:00"
vrf_device = "vrf-blue"
l3vxlan_device = "vxlan5000"
table_id = 100
"#,
        );
        let candidate = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5001
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:00"
vrf_device = "vrf-blue"
l3vxlan_device = "vxlan5000"
table_id = 100
"#,
        );
        let Err(EvpnDecomposeError::Unsupported(message)) = decompose(&current, &candidate) else {
            panic!("identity redefine must fail closed");
        };
        assert!(
            message.contains("step 1/2"),
            "step naming missing: {message}"
        );
        assert!(
            message.contains("restart-required by design"),
            "must carry today's identity-redefine error: {message}"
        );
    }

    #[test]
    fn relink_away_from_deleted_ip_vrf_fails_closed() {
        // VNI 100 linked to tenant-blue; candidate deletes tenant-blue and
        // relinks 100 to tenant-green. Deletes-first would dangle the link.
        let current = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:00"
vrf_device = "vrf-blue"
l3vxlan_device = "vxlan5000"
table_id = 100

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:01"
vrf_device = "vrf-green"
l3vxlan_device = "vxlan5001"
table_id = 101
"#,
        );
        let candidate = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-green"

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:01"
vrf_device = "vrf-green"
l3vxlan_device = "vxlan5001"
table_id = 101
"#,
        );
        let Err(EvpnDecomposeError::Unsupported(message)) = decompose(&current, &candidate) else {
            panic!("relink-away-from-deleted-vrf must fail closed");
        };
        assert!(
            message.contains("apply the relink/unlink as its own change first"),
            "wrong-order error expected: {message}"
        );
    }

    #[test]
    fn relink_onto_added_ip_vrf_fails_closed() {
        let current = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#,
        );
        // Deleting VNI 200 makes this a mixed (delete + relink-onto-added-vrf)
        // candidate; the relink of existing VNI 100 onto the added VRF must
        // fail closed.
        let candidate = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-green"

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:01"
vrf_device = "vrf-green"
l3vxlan_device = "vxlan5001"
table_id = 101
"#,
        );
        let Err(EvpnDecomposeError::Unsupported(message)) = decompose(&current, &candidate) else {
            panic!("relink-onto-added-vrf must fail closed");
        };
        assert!(
            message.contains("add the IP-VRF as its own change first"),
            "wrong-order error expected: {message}"
        );
    }

    #[test]
    fn es_membership_replacement_fails_closed_when_memberless_mid_sequence() {
        // ES keeps existing but its only member is deleted and replaced by a
        // newly added VNI — the segment would be memberless between the
        // delete step and the add step.
        let current = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#,
        );
        let candidate = with_header(
            r#"
[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [200]
originator_ip = "10.0.0.1"
"#,
        );
        let Err(EvpnDecomposeError::Unsupported(message)) = decompose(&current, &candidate) else {
            panic!("memberless-mid-sequence ES must fail closed");
        };
        assert!(
            message.contains("no members at the delete step"),
            "wrong-order error expected: {message}"
        );
    }

    #[test]
    fn per_phase_grouping_splits_ip_vrf_redefines_and_batches_l2vni_redefines() {
        // Two L2VNI redefines (one batch step) + two IP-VRF non-identity
        // redefines (one step each) + one add (final step) = 4 steps.
        let current = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:00"
vrf_device = "vrf-blue"
l3vxlan_device = "vxlan5000"
table_id = 100

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:01"
vrf_device = "vrf-green"
l3vxlan_device = "vxlan5001"
table_id = 101
"#,
        );
        let candidate = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:110"
route_targets = ["65000:110"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:210"
route_targets = ["65000:210"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5100"
route_targets = ["65000:5100"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:00"
vrf_device = "vrf-blue"
l3vxlan_device = "vxlan5000"
table_id = 100

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5101"
route_targets = ["65000:5101"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:01"
vrf_device = "vrf-green"
l3vxlan_device = "vxlan5001"
table_id = 101
"#,
        );
        let steps = decompose(&current, &candidate).unwrap();
        let descriptions: Vec<&str> = steps.iter().map(|s| s.description.as_str()).collect();
        assert_eq!(steps.len(), 4, "{descriptions:?}");
        assert!(
            descriptions[0].starts_with("L2VNI redefine (2"),
            "{descriptions:?}"
        );
        assert!(descriptions[1].contains("tenant-blue"), "{descriptions:?}");
        assert!(descriptions[2].contains("tenant-green"), "{descriptions:?}");
        assert!(descriptions[3].starts_with("adds"), "{descriptions:?}");
    }

    #[test]
    fn delete_plus_relink_of_surviving_vni_orders_delete_then_relink() {
        // Delete VNI 200 and relink surviving VNI 100 between existing VRFs:
        // deletes step, then a pure relink step.
        let current = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:00"
vrf_device = "vrf-blue"
l3vxlan_device = "vxlan5000"
table_id = 100

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:01"
vrf_device = "vrf-green"
l3vxlan_device = "vxlan5001"
table_id = 101
"#,
        );
        let candidate = with_header(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-green"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:00"
vrf_device = "vrf-blue"
l3vxlan_device = "vxlan5000"
table_id = 100

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.1"
router_mac = "02:00:00:00:50:01"
vrf_device = "vrf-green"
l3vxlan_device = "vxlan5001"
table_id = 101
"#,
        );
        let steps = decompose(&current, &candidate).unwrap();
        assert_eq!(steps.len(), 2, "{steps:#?}");
        assert!(steps[0].description.starts_with("deletes"));
        assert_eq!(steps[1].description, "ip_vrf relink");
        assert!(
            steps[1]
                .candidate
                .ip_vrfs()
                .referenced_l2vnis("tenant-green")
                .is_some_and(|vnis| vnis.contains(&vni(100)))
        );
    }
}
