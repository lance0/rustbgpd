//! Pure classification and validation for supported EVPN runtime plan shapes.

// This module is public so the daemon binary can share policy with the domain
// crate; its individual helpers remain an internal implementation surface.
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "the publish-disabled domain crate exposes these helpers only for the daemon's cross-crate integration"
)]

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SupportedPlanShapeError(String);

impl SupportedPlanShapeError {
    fn unsupported(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

/// The supported converge route [`route_supported_plan_shape`] classified
/// a plan into, carrying the routed validator's output where the
/// actor-availability gate needs it (see the daemon's
/// `DaemonEvpnRuntimeConverger::validate_availability`).
pub enum SupportedPlanRoute {
    TenantTeardown(Vec<crate::EvpnInstance>),
    IpVrfRelink,
    AdditiveBuildUp(Vec<crate::EvpnInstance>),
    L2vniMixed(L2VniMixedChanges),
    SingleL2vniDelete(Box<crate::EvpnInstance>),
    SingleL2vniRedefine(crate::EvpnInstanceId),
    SingleL2vniAdd(crate::EvpnInstanceId),
    SingleIpVrfDelete(String),
    SingleIpVrfRedefine(String),
    SingleIpVrfAdd(String),
    SingleEthernetSegmentDelete(rustbgpd_wire::EthernetSegmentIdentifier),
    SingleEthernetSegmentRedefine(rustbgpd_wire::EthernetSegmentIdentifier),
    SingleEthernetSegmentAdd(rustbgpd_wire::EthernetSegmentIdentifier),
}

/// Pure shape gate mirroring the daemon's `EvpnRuntimeActorConverger::converge`
/// dispatch: routes `plan` to the same shape detector + validator the
/// dispatch would pick, without any actor side effects. Used by the
/// #268 plan decomposer (`crate::evpn_plan_decomposer`) to prove — up
/// front, before any step commits — that every decomposed step is an
/// already-supported primitive shape, and to recognize a plan that is
/// already primitive. Keep the routing here and in `converge` in sync —
/// `shape_gate_and_converge_reject_unsupported_shapes_identically` and
/// `shape_gate_accepts_every_supported_converge_shape` enforce it.
///
/// # Errors
/// The routed validator's error when the plan is not a supported shape.
pub fn validate_supported_plan_shape(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<(), SupportedPlanShapeError> {
    route_supported_plan_shape(current, candidate, plan).map(drop)
}

/// [`validate_supported_plan_shape`] with the classified route kept, so
/// the LAN-897 availability gate can run the routed converge method's
/// actor preconditions without re-implementing the routing ladder.
pub fn route_supported_plan_shape(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<SupportedPlanRoute, SupportedPlanShapeError> {
    if is_tenant_teardown_plan(plan, current) {
        return validate_tenant_teardown(current, candidate, plan)
            .map(SupportedPlanRoute::TenantTeardown);
    }
    if is_ip_vrf_relink_plan(plan) {
        return validate_ip_vrf_relink(current, candidate, plan)
            .map(|()| SupportedPlanRoute::IpVrfRelink);
    }
    if is_additive_build_up_plan(plan) {
        return validate_additive_build_up(current, candidate, plan)
            .map(SupportedPlanRoute::AdditiveBuildUp);
    }
    if is_l2vni_mixed_plan(plan) {
        return validate_l2vni_mixed(current, candidate, plan).map(SupportedPlanRoute::L2vniMixed);
    }
    validate_no_unexpected_relink(current, candidate, plan)?;
    if plan.evpn_instances.has_changes() {
        if plan.evpn_instances.added.is_empty()
            && !plan.evpn_instances.deleted.is_empty()
            && plan.evpn_instances.redefined.is_empty()
        {
            return validate_single_l2vni_delete(current, candidate, plan)
                .map(|deleted| SupportedPlanRoute::SingleL2vniDelete(Box::new(deleted)));
        }
        if plan.evpn_instances.added.is_empty()
            && plan.evpn_instances.deleted.is_empty()
            && !plan.evpn_instances.redefined.is_empty()
        {
            return validate_single_l2vni_redefine(current, candidate, plan)
                .map(SupportedPlanRoute::SingleL2vniRedefine);
        }
        return validate_single_l2vni_add(current, candidate, plan)
            .map(SupportedPlanRoute::SingleL2vniAdd);
    }
    if plan.ip_vrfs.has_changes() {
        if plan.ip_vrfs.added.is_empty()
            && !plan.ip_vrfs.deleted.is_empty()
            && plan.ip_vrfs.redefined.is_empty()
        {
            return validate_single_ip_vrf_delete(current, candidate, plan)
                .map(SupportedPlanRoute::SingleIpVrfDelete);
        }
        if plan.ip_vrfs.added.is_empty()
            && plan.ip_vrfs.deleted.is_empty()
            && !plan.ip_vrfs.redefined.is_empty()
        {
            return validate_single_ip_vrf_redefine(current, candidate, plan)
                .map(SupportedPlanRoute::SingleIpVrfRedefine);
        }
        return validate_single_ip_vrf_add(plan).map(SupportedPlanRoute::SingleIpVrfAdd);
    }
    if plan.ethernet_segments.has_changes() {
        if plan.ethernet_segments.added.is_empty()
            && !plan.ethernet_segments.deleted.is_empty()
            && plan.ethernet_segments.redefined.is_empty()
        {
            return validate_single_ethernet_segment_delete(current, candidate, plan)
                .map(SupportedPlanRoute::SingleEthernetSegmentDelete);
        }
        if plan.ethernet_segments.added.is_empty()
            && plan.ethernet_segments.deleted.is_empty()
            && !plan.ethernet_segments.redefined.is_empty()
        {
            return validate_single_ethernet_segment_redefine(current, candidate, plan)
                .map(SupportedPlanRoute::SingleEthernetSegmentRedefine);
        }
        return validate_single_ethernet_segment_add(current, candidate, plan)
            .map(SupportedPlanRoute::SingleEthernetSegmentAdd);
    }
    Err(SupportedPlanShapeError::unsupported(
        "ApplyEvpnRuntime has no supported changes in this candidate",
    ))
}
pub fn validate_single_l2vni_add(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<crate::EvpnInstanceId, SupportedPlanShapeError> {
    if plan.ip_vrfs.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently does not support mixed L2VNI and IP-VRF changes in one request",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "L2VNI add cannot be combined with Ethernet Segment changes in one request; apply each as a separate ApplyEvpnRuntime request",
        ));
    }
    if !plan.evpn_instances.deleted.is_empty() || !plan.evpn_instances.redefined.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports only add-only L2VNI changes; combining add/delete/redefine in one request is not supported — apply each change as a separate ApplyEvpnRuntime request (tracked in #268)",
        ));
    }
    if plan.evpn_instances.added.len() != 1 {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one added L2VNI per request",
        ));
    }

    let raw_vni = plan.evpn_instances.added[0];
    let added_vni = crate::EvpnInstanceId::new(raw_vni).map_err(|err| {
        SupportedPlanShapeError::unsupported(format!("invalid planned L2VNI {raw_vni}: {err}"))
    })?;
    if current.instances().get(added_vni).is_some() {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "planned L2VNI {added_vni} is already committed"
        )));
    }
    if candidate.instances().get(added_vni).is_none() {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "candidate is missing planned L2VNI {added_vni}"
        )));
    }
    Ok(added_vni)
}

pub fn validate_single_l2vni_delete(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<crate::EvpnInstance, SupportedPlanShapeError> {
    if plan.ip_vrfs.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports L2VNI delete only when IP-VRF changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports L2VNI delete only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.evpn_instances.added.is_empty() || !plan.evpn_instances.redefined.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports only delete-only L2VNI changes; combining add/delete/redefine in one request is not supported — apply each change as a separate ApplyEvpnRuntime request (tracked in #268)",
        ));
    }
    if plan.evpn_instances.deleted.len() != 1 {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one deleted L2VNI per request",
        ));
    }
    let raw_vni = plan.evpn_instances.deleted[0];
    let deleted_vni = crate::EvpnInstanceId::new(raw_vni).map_err(|err| {
        SupportedPlanShapeError::unsupported(format!("invalid planned L2VNI {raw_vni}: {err}"))
    })?;
    let Some(instance) = current.instances().get(deleted_vni).cloned() else {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "planned L2VNI {deleted_vni} is not committed"
        )));
    };
    if candidate.instances().get(deleted_vni).is_some() {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "candidate still contains planned deleted L2VNI {deleted_vni}"
        )));
    }
    validate_l2vni_delete_ip_vrf_metadata(current, candidate, deleted_vni)?;
    if current
        .ethernet_segments()
        .iter()
        .any(|segment| segment.member_vnis.contains(&deleted_vni))
    {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "L2VNI {deleted_vni} is an Ethernet Segment member; delete it together with its Ethernet Segment (atomic tenant teardown) or after removing it from the segment"
        )));
    }

    Ok(instance)
}

#[derive(Debug, Clone)]
pub struct L2VniMixedChanges {
    pub added: Vec<crate::EvpnInstance>,
    pub deleted: Vec<crate::EvpnInstance>,
    pub redefined: Vec<(crate::EvpnInstance, crate::EvpnInstance)>,
}

pub fn is_l2vni_swap_plan(plan: &crate::EvpnRuntimePlan) -> bool {
    is_l2vni_mixed_plan(plan)
}

pub fn is_l2vni_mixed_plan(plan: &crate::EvpnRuntimePlan) -> bool {
    let l2_change_classes = [
        !plan.evpn_instances.added.is_empty(),
        !plan.evpn_instances.deleted.is_empty(),
        !plan.evpn_instances.redefined.is_empty(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    let batch_redefine_only = plan.evpn_instances.added.is_empty()
        && plan.evpn_instances.deleted.is_empty()
        && plan.evpn_instances.redefined.len() > 1;
    (l2_change_classes >= 2 || batch_redefine_only)
        && !plan.ip_vrfs.has_changes()
        && !plan.ethernet_segments.has_changes()
}

pub fn validate_l2vni_swap(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<(Vec<crate::EvpnInstance>, Vec<crate::EvpnInstance>), SupportedPlanShapeError> {
    let changes = validate_l2vni_mixed(current, candidate, plan)?;
    if !changes.redefined.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime L2VNI swap validator accepts only add/delete changes; use the mixed L2VNI validator for redefine compositions",
        ));
    }
    Ok((changes.added, changes.deleted))
}

pub fn validate_l2vni_mixed(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<L2VniMixedChanges, SupportedPlanShapeError> {
    if !is_l2vni_mixed_plan(plan) {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime mixed L2VNI update requires at least two L2VNI change classes or multiple L2VNI redefines, with no IP-VRF row or Ethernet Segment row changes",
        ));
    }
    validate_no_unexpected_relink(current, candidate, plan)?;

    let mut added_instances = Vec::with_capacity(plan.evpn_instances.added.len());
    for &raw_vni in &plan.evpn_instances.added {
        let vni = crate::EvpnInstanceId::new(raw_vni).map_err(|err| {
            SupportedPlanShapeError::unsupported(format!(
                "invalid planned added L2VNI {raw_vni}: {err}"
            ))
        })?;
        if current.instances().get(vni).is_some() {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned added L2VNI {vni} is already committed"
            )));
        }
        let Some(instance) = candidate.instances().get(vni).cloned() else {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate is missing planned added L2VNI {vni}"
            )));
        };
        added_instances.push(instance);
    }

    let mut deleted_instances = Vec::with_capacity(plan.evpn_instances.deleted.len());
    for &raw_vni in &plan.evpn_instances.deleted {
        let vni = crate::EvpnInstanceId::new(raw_vni).map_err(|err| {
            SupportedPlanShapeError::unsupported(format!(
                "invalid planned deleted L2VNI {raw_vni}: {err}"
            ))
        })?;
        let Some(instance) = current.instances().get(vni).cloned() else {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned deleted L2VNI {vni} is not committed"
            )));
        };
        if candidate.instances().get(vni).is_some() {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate still contains planned deleted L2VNI {vni}"
            )));
        }
        if current
            .ethernet_segments()
            .iter()
            .any(|segment| segment.member_vnis.contains(&vni))
        {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "L2VNI swap cannot delete Ethernet Segment member L2VNI {vni}; use atomic tenant teardown or remove the segment membership first"
            )));
        }
        deleted_instances.push(instance);
    }

    let mut redefined_instances = Vec::with_capacity(plan.evpn_instances.redefined.len());
    for &raw_vni in &plan.evpn_instances.redefined {
        let vni = crate::EvpnInstanceId::new(raw_vni).map_err(|err| {
            SupportedPlanShapeError::unsupported(format!(
                "invalid planned redefined L2VNI {raw_vni}: {err}"
            ))
        })?;
        let Some(old_instance) = current.instances().get(vni).cloned() else {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned redefined L2VNI {vni} is not committed"
            )));
        };
        let Some(new_instance) = candidate.instances().get(vni).cloned() else {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate is missing planned redefined L2VNI {vni}"
            )));
        };
        redefined_instances.push((old_instance, new_instance));
    }

    Ok(L2VniMixedChanges {
        added: added_instances,
        deleted: deleted_instances,
        redefined: redefined_instances,
    })
}

pub fn validate_single_l2vni_redefine(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<crate::EvpnInstanceId, SupportedPlanShapeError> {
    if plan.ip_vrfs.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports L2VNI redefine only when IP-VRF changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports L2VNI redefine only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.evpn_instances.added.is_empty() || !plan.evpn_instances.deleted.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports only redefine-only L2VNI changes; combining add/delete/redefine in one request is not supported — apply each change as a separate ApplyEvpnRuntime request (tracked in #268)",
        ));
    }
    if plan.evpn_instances.redefined.len() != 1 {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one redefined L2VNI per request",
        ));
    }

    let raw_vni = plan.evpn_instances.redefined[0];
    let redefined_vni = crate::EvpnInstanceId::new(raw_vni).map_err(|err| {
        SupportedPlanShapeError::unsupported(format!("invalid planned L2VNI {raw_vni}: {err}"))
    })?;
    if current.instances().get(redefined_vni).is_none() {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "planned L2VNI {redefined_vni} is not committed"
        )));
    }
    if candidate.instances().get(redefined_vni).is_none() {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "candidate is missing planned L2VNI {redefined_vni}"
        )));
    }

    // A *pure* `ip_vrf` relink (link change with no row edits) is routed to
    // `converge_ip_vrf_relink` upstream on `plan.ip_vrf_references_changed`. This
    // check therefore only fires for a redefine *combined* with a relink (the
    // L2VNI row is redefined AND its link moved) — keep that fail-closed; a
    // redefine and a relink must be applied as separate requests.
    if current.ip_vrfs() != candidate.ip_vrfs() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime does not support an L2VNI redefine combined with an ip_vrf relink in one request; apply the relink separately",
        ));
    }

    Ok(redefined_vni)
}

pub fn validate_l2vni_delete_ip_vrf_metadata(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    deleted_vni: crate::EvpnInstanceId,
) -> Result<(), SupportedPlanShapeError> {
    for vrf in current.ip_vrfs().iter() {
        let mut expected = current
            .ip_vrfs()
            .referenced_l2vnis(&vrf.name)
            .cloned()
            .unwrap_or_default();
        expected.remove(&deleted_vni);

        let actual = candidate
            .ip_vrfs()
            .referenced_l2vnis(&vrf.name)
            .cloned()
            .unwrap_or_default();
        let candidate_reference_present = candidate.ip_vrfs().is_referenced(&vrf.name);
        let expected_reference_present = !expected.is_empty();
        if actual != expected || candidate_reference_present != expected_reference_present {
            let name = &vrf.name;
            return Err(SupportedPlanShapeError::unsupported(format!(
                "ApplyEvpnRuntime currently supports L2VNI delete only when candidate IP-VRF link metadata for {name:?} matches the committed metadata except for removing deleted L2VNI {deleted_vni}"
            )));
        }
    }
    Ok(())
}

/// True when the plan is a pure `ip_vrf` relink: the L2VNI->IP-VRF reference
/// metadata changed but no IP-VRF / L2VNI / Ethernet Segment row did. Routed
/// before the row-changeset blocks; teardown is classified first so a delete
/// (which also shifts references) never lands here.
pub fn is_ip_vrf_relink_plan(plan: &crate::EvpnRuntimePlan) -> bool {
    plan.ip_vrf_references_changed
        && !plan.evpn_instances.has_changes()
        && !plan.ip_vrfs.has_changes()
        && !plan.ethernet_segments.has_changes()
}

/// Validate an `ip_vrf` relink: no row changesets, and the divergence is purely
/// in the IP-VRF reference metadata.
pub fn validate_ip_vrf_relink(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<(), SupportedPlanShapeError> {
    if plan.evpn_instances.has_changes()
        || plan.ip_vrfs.has_changes()
        || plan.ethernet_segments.has_changes()
    {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime ip_vrf relink converge requires no L2VNI / IP-VRF / Ethernet Segment row changes",
        ));
    }
    if !plan.ip_vrf_references_changed || !current.ip_vrfs().references_differ(candidate.ip_vrfs())
    {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime ip_vrf relink converge requires an IP-VRF link reference change",
        ));
    }
    Ok(())
}

/// Central guard for the fourth change signal. `ip_vrf_references_changed` (an
/// L2VNI's `ip_vrf` link moving) is not one of the three row changesets the
/// single-shape validators gate on, so without this a relink could be silently
/// composed with any row shape — e.g. an ES change would commit the candidate
/// but never republish `ip_vrfs`, diverging the dataplane from the committed
/// model. The invariant: a pure relink and atomic tenant teardown own reference
/// changes on their own paths (both routed before this); a row-shape change may
/// only carry the link delta intrinsic to its own added/deleted L2VNIs. Any
/// other relinked VNI is a mixed-in relink and is rejected.
pub fn validate_no_unexpected_relink(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<(), SupportedPlanShapeError> {
    if !plan.ip_vrf_references_changed {
        return Ok(());
    }
    let touched: std::collections::BTreeSet<crate::EvpnInstanceId> = plan
        .evpn_instances
        .added
        .iter()
        .chain(plan.evpn_instances.deleted.iter())
        .filter_map(|raw| crate::EvpnInstanceId::new(*raw).ok())
        .collect();
    let current_links = current.ip_vrfs().l2vni_link_map();
    let candidate_links = candidate.ip_vrfs().l2vni_link_map();
    let mut vnis: std::collections::BTreeSet<crate::EvpnInstanceId> =
        current_links.keys().copied().collect();
    vnis.extend(candidate_links.keys().copied());
    for vni in vnis {
        if current_links.get(&vni) != candidate_links.get(&vni) && !touched.contains(&vni) {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "ApplyEvpnRuntime: L2VNI {vni} `ip_vrf` link change (relink) is mixed into another \
                 runtime change; apply the relink as a separate request"
            )));
        }
    }
    Ok(())
}

/// True when the plan is an additive build-up that the single-row add paths
/// cannot express: multiple domains change together, one domain adds more than
/// one row, or an existing ES expands membership only for newly added L2VNIs.
/// Single-row adds keep routing through their narrower legacy validators.
pub fn is_additive_build_up_plan(plan: &crate::EvpnRuntimePlan) -> bool {
    let no_deletes_or_non_es_redefines = plan.evpn_instances.deleted.is_empty()
        && plan.evpn_instances.redefined.is_empty()
        && plan.ip_vrfs.deleted.is_empty()
        && plan.ip_vrfs.redefined.is_empty()
        && plan.ethernet_segments.deleted.is_empty();
    let has_add = !plan.evpn_instances.added.is_empty()
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ethernet_segments.added.is_empty();
    if !(no_deletes_or_non_es_redefines && has_add) {
        return false;
    }
    let resource_types_added = [
        !plan.evpn_instances.added.is_empty(),
        !plan.ip_vrfs.added.is_empty(),
        !plan.ethernet_segments.added.is_empty(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    resource_types_added > 1
        || plan.evpn_instances.added.len() > 1
        || plan.ip_vrfs.added.len() > 1
        || plan.ethernet_segments.added.len() > 1
        || !plan.ethernet_segments.redefined.is_empty()
}

pub fn validate_additive_build_up(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<Vec<crate::EvpnInstance>, SupportedPlanShapeError> {
    if !is_additive_build_up_plan(plan) {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime additive build-up requires add-only changes across multiple rows or EVPN runtime domains, with only existing-ES member expansion allowed as a redefine",
        ));
    }
    validate_no_unexpected_relink(current, candidate, plan)?;

    let mut added_instances = Vec::with_capacity(plan.evpn_instances.added.len());
    for &raw_vni in &plan.evpn_instances.added {
        let vni = crate::EvpnInstanceId::new(raw_vni).map_err(|err| {
            SupportedPlanShapeError::unsupported(format!("invalid planned L2VNI {raw_vni}: {err}"))
        })?;
        if current.instances().get(vni).is_some() {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned L2VNI {vni} is already committed"
            )));
        }
        let Some(instance) = candidate.instances().get(vni).cloned() else {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate is missing planned L2VNI {vni}"
            )));
        };
        added_instances.push(instance);
    }

    for name in &plan.ip_vrfs.added {
        if current.ip_vrfs().get(name).is_some() {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned IP-VRF {name:?} is already committed"
            )));
        }
        if candidate.ip_vrfs().get(name).is_none() {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate is missing planned IP-VRF {name:?}"
            )));
        }
    }

    for esi in &plan.ethernet_segments.added {
        if current
            .ethernet_segments()
            .iter()
            .any(|segment| segment.esi == *esi)
        {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned Ethernet Segment {esi} is already committed"
            )));
        }
        let Some(segment) = candidate
            .ethernet_segments()
            .iter()
            .find(|segment| segment.esi == *esi)
        else {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate is missing planned Ethernet Segment {esi}"
            )));
        };
        validate_ethernet_segment_member_vnis_present(
            *esi,
            &segment.member_vnis,
            candidate.instances(),
        )?;
    }

    let added_l2vnis = added_instances
        .iter()
        .map(|instance| instance.id)
        .collect::<BTreeSet<_>>();
    for esi in &plan.ethernet_segments.redefined {
        validate_additive_existing_es_member_expansion(current, candidate, *esi, &added_l2vnis)?;
    }

    Ok(added_instances)
}

pub fn validate_additive_existing_es_member_expansion(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    esi: rustbgpd_wire::EthernetSegmentIdentifier,
    added_l2vnis: &BTreeSet<crate::EvpnInstanceId>,
) -> Result<(), SupportedPlanShapeError> {
    let Some(current_segment) = current
        .ethernet_segments()
        .iter()
        .find(|segment| segment.esi == esi)
    else {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "planned Ethernet Segment {esi} is not committed"
        )));
    };
    let Some(candidate_segment) = candidate
        .ethernet_segments()
        .iter()
        .find(|segment| segment.esi == esi)
    else {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "candidate is missing planned Ethernet Segment {esi}"
        )));
    };

    if candidate_segment.member_vnis.len() <= current_segment.member_vnis.len()
        || !candidate_segment
            .member_vnis
            .is_superset(&current_segment.member_vnis)
    {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "additive build-up may only expand Ethernet Segment {esi} member_vnis"
        )));
    }
    let added_members = candidate_segment
        .member_vnis
        .difference(&current_segment.member_vnis)
        .copied()
        .collect::<BTreeSet<_>>();
    if added_members.is_empty() || !added_members.iter().all(|vni| added_l2vnis.contains(vni)) {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "additive build-up may only add newly planned L2VNIs to Ethernet Segment {esi}"
        )));
    }
    validate_ethernet_segment_member_vnis_present(
        esi,
        &candidate_segment.member_vnis,
        candidate.instances(),
    )?;

    let mut probe = current_segment.clone();
    probe.member_vnis.clone_from(&candidate_segment.member_vnis);
    if &probe != candidate_segment {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "additive build-up may not change Ethernet Segment {esi} fields other than member_vnis"
        )));
    }

    Ok(())
}

/// Whether `plan` is an atomic tenant teardown — a delete-only mutation that
/// the single-shape converters cannot handle (multi-element, cross-resource,
/// an ES-member L2VNI delete, or a still-referenced IP-VRF delete). Clean
/// single-element non-ES, non-referenced deletes return `false` so they keep
/// routing to the existing single-shape delete converters.
pub fn is_tenant_teardown_plan(
    plan: &crate::EvpnRuntimePlan,
    current: &crate::EvpnRuntimeModel,
) -> bool {
    let no_adds = plan.evpn_instances.added.is_empty()
        && plan.ip_vrfs.added.is_empty()
        && plan.ethernet_segments.added.is_empty();
    // L2VNI / IP-VRF redefines stay on their dedicated single-redefine paths;
    // teardown allows ES redefines (member-shrink) only.
    let no_l2_ipvrf_redefine =
        plan.evpn_instances.redefined.is_empty() && plan.ip_vrfs.redefined.is_empty();
    let has_deletion = !plan.evpn_instances.deleted.is_empty()
        || !plan.ip_vrfs.deleted.is_empty()
        || !plan.ethernet_segments.deleted.is_empty();
    if !(no_adds && no_l2_ipvrf_redefine && has_deletion) {
        return false;
    }

    let resource_types_changed = [
        plan.evpn_instances.has_changes(),
        plan.ip_vrfs.has_changes(),
        plan.ethernet_segments.has_changes(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    let multi_resource = resource_types_changed > 1;
    let multi_element = plan.evpn_instances.deleted.len() > 1
        || plan.ip_vrfs.deleted.len() > 1
        || plan.ethernet_segments.deleted.len() > 1;
    let es_member_l2vni_deleted = plan.evpn_instances.deleted.iter().any(|&raw| {
        crate::EvpnInstanceId::new(raw).is_ok_and(|vni| {
            current
                .ethernet_segments()
                .iter()
                .any(|segment| segment.member_vnis.contains(&vni))
        })
    });
    let referenced_ip_vrf_deleted = plan
        .ip_vrfs
        .deleted
        .iter()
        .any(|name| current.ip_vrfs().is_referenced(name));

    multi_resource || multi_element || es_member_l2vni_deleted || referenced_ip_vrf_deleted
}

/// Validate an atomic tenant teardown and return the deleted L2VNI instances
/// (needed for IMET withdraw + SVI gating + rollback restore). Accepts a
/// delete-only plan: ≥1 deletion, no adds, no L2VNI/IP-VRF redefines, ES
/// redefines limited to member-shrink, and the candidate internally consistent
/// (no IP-VRF deleted while an L2VNI still references it; no ES still listing a
/// deleted member VNI).
#[expect(
    clippy::too_many_lines,
    reason = "sequential teardown guards read clearer inline than split across helpers"
)]
pub fn validate_tenant_teardown(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<Vec<crate::EvpnInstance>, SupportedPlanShapeError> {
    if !plan.evpn_instances.added.is_empty()
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ethernet_segments.added.is_empty()
    {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime tenant teardown does not support adds in the same request",
        ));
    }
    if !plan.evpn_instances.redefined.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime tenant teardown does not support L2VNI redefine in the same request",
        ));
    }
    if !plan.ip_vrfs.redefined.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime tenant teardown does not support IP-VRF redefine in the same request",
        ));
    }
    if plan.evpn_instances.deleted.is_empty()
        && plan.ip_vrfs.deleted.is_empty()
        && plan.ethernet_segments.deleted.is_empty()
    {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime tenant teardown requires at least one deletion",
        ));
    }

    // ES redefines in a teardown may only shrink member_vnis (drop the VNIs
    // being deleted); every other ES field must be unchanged.
    for esi in &plan.ethernet_segments.redefined {
        let Some(cur) = current
            .ethernet_segments()
            .iter()
            .find(|seg| seg.esi == *esi)
        else {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned redefined Ethernet Segment {esi} is not committed"
            )));
        };
        let Some(cand) = candidate
            .ethernet_segments()
            .iter()
            .find(|seg| seg.esi == *esi)
        else {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate is missing planned redefined Ethernet Segment {esi}"
            )));
        };
        let member_shrink_only = cand.member_vnis.len() < cur.member_vnis.len()
            && cand.member_vnis.iter().all(|v| cur.member_vnis.contains(v))
            && {
                let mut probe = cur.clone();
                probe.member_vnis.clone_from(&cand.member_vnis);
                &probe == cand
            };
        if !member_shrink_only {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "ApplyEvpnRuntime tenant teardown supports Ethernet Segment {esi} redefine only as a member_vnis shrink; other field changes are not supported"
            )));
        }
    }

    // Resolve + validate each deleted L2VNI.
    let mut deleted_instances = Vec::with_capacity(plan.evpn_instances.deleted.len());
    for &raw_vni in &plan.evpn_instances.deleted {
        let vni = crate::EvpnInstanceId::new(raw_vni).map_err(|err| {
            SupportedPlanShapeError::unsupported(format!("invalid planned L2VNI {raw_vni}: {err}"))
        })?;
        let Some(instance) = current.instances().get(vni).cloned() else {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned L2VNI {vni} is not committed"
            )));
        };
        if candidate.instances().get(vni).is_some() {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate still contains planned deleted L2VNI {vni}"
            )));
        }
        deleted_instances.push(instance);
    }
    let deleted_vnis: std::collections::BTreeSet<crate::EvpnInstanceId> =
        deleted_instances.iter().map(|inst| inst.id).collect();

    // Consistency A — a deleted IP-VRF must have all its referencing L2VNIs
    // deleted in the same request (no surviving L2VNI may dangle on it).
    // Defense-in-depth: config validation (`config/mod.rs` L2VNI->IP-VRF
    // cross-ref) already rejects a candidate that leaves a dangling reference,
    // so the dangling-ref branch below is unreachable from the gRPC entry
    // point — kept in case a future caller constructs a candidate directly.
    for name in &plan.ip_vrfs.deleted {
        if current.ip_vrfs().get(name).is_none() {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned IP-VRF {name:?} is not committed"
            )));
        }
        if candidate.ip_vrfs().get(name).is_some() {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate still contains planned deleted IP-VRF {name:?}"
            )));
        }
        let refs = current
            .ip_vrfs()
            .referenced_l2vnis(name)
            .cloned()
            .unwrap_or_default();
        for vni in refs {
            if !deleted_vnis.contains(&vni) {
                return Err(SupportedPlanShapeError::unsupported(format!(
                    "tenant teardown: IP-VRF {name:?} is referenced by L2VNI {vni}, which must be deleted in the same request"
                )));
            }
        }
    }

    // Consistency B — no candidate Ethernet Segment may still list a deleted
    // VNI as a member (delete or member-shrink the segment in the same request).
    // Like Consistency A, config validation (`config/mod.rs` ES member_vnis
    // existence check) rejects a candidate ES that references an absent VNI, so
    // this branch is unreachable from the gRPC entry point and stands as
    // defense-in-depth for direct candidate construction.
    for seg in candidate.ethernet_segments() {
        for vni in &seg.member_vnis {
            if deleted_vnis.contains(vni) {
                return Err(SupportedPlanShapeError::unsupported(format!(
                    "tenant teardown: candidate Ethernet Segment {} still references deleted L2VNI {vni}; delete or member-shrink the segment in the same request",
                    seg.esi
                )));
            }
        }
    }

    // Validate each deleted Ethernet Segment.
    for esi in &plan.ethernet_segments.deleted {
        if !current
            .ethernet_segments()
            .iter()
            .any(|seg| seg.esi == *esi)
        {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "planned deleted Ethernet Segment {esi} is not committed"
            )));
        }
        if candidate
            .ethernet_segments()
            .iter()
            .any(|seg| seg.esi == *esi)
        {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "candidate still contains planned deleted Ethernet Segment {esi}"
            )));
        }
    }

    Ok(deleted_instances)
}

pub fn validate_single_ip_vrf_add(
    plan: &crate::EvpnRuntimePlan,
) -> Result<String, SupportedPlanShapeError> {
    if plan.evpn_instances.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF add only when L2VNI changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF add only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.ip_vrfs.deleted.is_empty() || !plan.ip_vrfs.redefined.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports only add-only IP-VRF changes — apply a delete/redefine as a separate ApplyEvpnRuntime request (tracked in #268)",
        ));
    }
    if plan.ip_vrfs.added.len() != 1 {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one added IP-VRF per request",
        ));
    }
    Ok(plan.ip_vrfs.added[0].clone())
}

pub fn validate_single_ip_vrf_delete(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<String, SupportedPlanShapeError> {
    if plan.evpn_instances.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF delete only when L2VNI changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF delete only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.ip_vrfs.added.is_empty() || !plan.ip_vrfs.redefined.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports only delete-only IP-VRF changes — apply an add/redefine as a separate ApplyEvpnRuntime request (tracked in #268)",
        ));
    }
    if plan.ip_vrfs.deleted.len() != 1 {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one deleted IP-VRF per request",
        ));
    }

    let deleted_name = plan.ip_vrfs.deleted[0].clone();
    if current.ip_vrfs().get(&deleted_name).is_none() {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "planned IP-VRF {deleted_name:?} is not committed"
        )));
    }
    if candidate.ip_vrfs().get(&deleted_name).is_some() {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "candidate still contains planned deleted IP-VRF {deleted_name:?}"
        )));
    }
    if current.ip_vrfs().is_referenced(&deleted_name) {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "IP-VRF {deleted_name:?} is referenced by an L2VNI; delete it together with the referencing L2VNI(s) (atomic tenant teardown) or after removing the reference"
        )));
    }

    Ok(deleted_name)
}

pub fn validate_single_ip_vrf_redefine(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<String, SupportedPlanShapeError> {
    if plan.evpn_instances.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF redefine only when L2VNI changes are absent",
        ));
    }
    if plan.ethernet_segments.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports IP-VRF redefine only when Ethernet Segment changes are absent",
        ));
    }
    if !plan.ip_vrfs.added.is_empty() || !plan.ip_vrfs.deleted.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports only redefine-only IP-VRF changes — apply an add/delete as a separate ApplyEvpnRuntime request (tracked in #268)",
        ));
    }
    if plan.ip_vrfs.redefined.len() != 1 {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one redefined IP-VRF per request",
        ));
    }

    let name = plan.ip_vrfs.redefined[0].clone();
    let Some(old) = current.ip_vrfs().get(&name) else {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "planned redefined IP-VRF {name:?} is not committed"
        )));
    };
    let Some(new) = candidate.ip_vrfs().get(&name) else {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "candidate is missing planned redefined IP-VRF {name:?}"
        )));
    };

    // The L3VNI, VRF device, L3VXLAN device, and table id are the IP-VRF's
    // kernel-object identity; changing one is a VRF lifecycle operation (destroy
    // + recreate the kernel VRF), which is restart-required by design — a runtime
    // drain/recreate would risk a dual-state window (kernel on the old identity
    // while the originator publishes the new). `router_mac` is NOT identity: it
    // is an accepted live route/policy-field redefine (the Type 5 originator +
    // dataplane self-diff it cleanly), so it is intentionally absent from this
    // guard.
    if old.id != new.id
        || old.vrf_device != new.vrf_device
        || old.l3vxlan_device != new.l3vxlan_device
        || old.table_id != new.table_id
    {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "ApplyEvpnRuntime IP-VRF redefine supports live route/policy/egress field changes (rd, route_targets, local_vtep_ip, router_mac) for {name:?}; changing the L3VNI, vrf_device, l3vxlan_device, or table_id is restart-required by design (kernel VRF identity lifecycle)"
        )));
    }

    let current_refs = current
        .ip_vrfs()
        .referenced_l2vnis(&name)
        .cloned()
        .unwrap_or_default();
    let candidate_refs = candidate
        .ip_vrfs()
        .referenced_l2vnis(&name)
        .cloned()
        .unwrap_or_default();
    if current_refs != candidate_refs
        || current.ip_vrfs().is_referenced(&name) != candidate.ip_vrfs().is_referenced(&name)
    {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "ApplyEvpnRuntime does not support an IP-VRF redefine combined with an ip_vrf relink for {name:?} in one request; apply the relink as a separate request"
        )));
    }

    Ok(name)
}

pub fn validate_single_ethernet_segment_add(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<rustbgpd_wire::EthernetSegmentIdentifier, SupportedPlanShapeError> {
    if plan.evpn_instances.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment add only when L2VNI changes are absent",
        ));
    }
    if plan.ip_vrfs.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment add only when IP-VRF changes are absent",
        ));
    }
    if !plan.ethernet_segments.deleted.is_empty() || !plan.ethernet_segments.redefined.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "Ethernet Segment add cannot be combined with ES delete/redefine in one request; apply each as a separate ApplyEvpnRuntime request",
        ));
    }
    if plan.ethernet_segments.added.len() != 1 {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one added Ethernet Segment per request",
        ));
    }

    let added_esi = plan.ethernet_segments.added[0];
    if current
        .ethernet_segments()
        .iter()
        .any(|seg| seg.esi == added_esi)
    {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "planned Ethernet Segment {added_esi} is already committed"
        )));
    }
    let Some(seg) = candidate
        .ethernet_segments()
        .iter()
        .find(|seg| seg.esi == added_esi)
    else {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "candidate is missing planned Ethernet Segment {added_esi}"
        )));
    };

    validate_ethernet_segment_member_vnis_present(
        added_esi,
        &seg.member_vnis,
        candidate.instances(),
    )?;

    Ok(added_esi)
}

pub fn validate_single_ethernet_segment_delete(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<rustbgpd_wire::EthernetSegmentIdentifier, SupportedPlanShapeError> {
    if plan.evpn_instances.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment delete only when L2VNI changes are absent",
        ));
    }
    if plan.ip_vrfs.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment delete only when IP-VRF changes are absent",
        ));
    }
    if !plan.ethernet_segments.added.is_empty() || !plan.ethernet_segments.redefined.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports only delete-only Ethernet Segment changes — apply an add/redefine as a separate ApplyEvpnRuntime request (tracked in #268)",
        ));
    }
    if plan.ethernet_segments.deleted.len() != 1 {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one deleted Ethernet Segment per request",
        ));
    }

    let deleted_esi = plan.ethernet_segments.deleted[0];
    if !current
        .ethernet_segments()
        .iter()
        .any(|seg| seg.esi == deleted_esi)
    {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "planned Ethernet Segment {deleted_esi} is not committed"
        )));
    }
    if candidate
        .ethernet_segments()
        .iter()
        .any(|seg| seg.esi == deleted_esi)
    {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "candidate still contains planned deleted Ethernet Segment {deleted_esi}"
        )));
    }

    Ok(deleted_esi)
}

pub fn validate_single_ethernet_segment_redefine(
    current: &crate::EvpnRuntimeModel,
    candidate: &crate::EvpnRuntimeCandidate,
    plan: &crate::EvpnRuntimePlan,
) -> Result<rustbgpd_wire::EthernetSegmentIdentifier, SupportedPlanShapeError> {
    if plan.evpn_instances.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment redefine only when L2VNI changes are absent",
        ));
    }
    if plan.ip_vrfs.has_changes() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports Ethernet Segment redefine only when IP-VRF changes are absent",
        ));
    }
    if !plan.ethernet_segments.added.is_empty() || !plan.ethernet_segments.deleted.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports only redefine-only Ethernet Segment changes — apply an add/delete as a separate ApplyEvpnRuntime request (tracked in #268)",
        ));
    }
    if plan.ethernet_segments.redefined.len() != 1 {
        return Err(SupportedPlanShapeError::unsupported(
            "ApplyEvpnRuntime currently supports exactly one redefined Ethernet Segment per request",
        ));
    }

    let redefined_esi = plan.ethernet_segments.redefined[0];
    if !current
        .ethernet_segments()
        .iter()
        .any(|seg| seg.esi == redefined_esi)
    {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "planned Ethernet Segment {redefined_esi} is not committed"
        )));
    }
    let Some(seg) = candidate
        .ethernet_segments()
        .iter()
        .find(|seg| seg.esi == redefined_esi)
    else {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "candidate is missing planned Ethernet Segment {redefined_esi}"
        )));
    };

    validate_ethernet_segment_member_vnis_present(
        redefined_esi,
        &seg.member_vnis,
        candidate.instances(),
    )?;

    Ok(redefined_esi)
}

pub fn validate_ethernet_segment_member_vnis_present(
    esi: rustbgpd_wire::EthernetSegmentIdentifier,
    member_vnis: &std::collections::BTreeSet<crate::EvpnInstanceId>,
    instances: &crate::EvpnInstanceTable,
) -> Result<(), SupportedPlanShapeError> {
    if member_vnis.is_empty() {
        return Err(SupportedPlanShapeError::unsupported(format!(
            "Ethernet Segment {esi} has no member VNIs"
        )));
    }
    for vni in member_vnis {
        if instances.get(*vni).is_none() {
            return Err(SupportedPlanShapeError::unsupported(format!(
                "Ethernet Segment {esi} references unknown member VNI {}",
                vni.as_u32()
            )));
        }
    }
    Ok(())
}
