use std::time::{Duration, Instant as StdInstant};

use rustbgpd_evpn::runtime_plan_shape::{
    is_additive_build_up_plan, is_ip_vrf_relink_plan, is_l2vni_mixed_plan, is_l2vni_swap_plan,
    is_tenant_teardown_plan, validate_additive_build_up,
    validate_ethernet_segment_member_vnis_present, validate_ip_vrf_relink, validate_l2vni_mixed,
    validate_l2vni_swap, validate_no_unexpected_relink, validate_single_ethernet_segment_add,
    validate_single_ethernet_segment_delete, validate_single_ethernet_segment_redefine,
    validate_single_ip_vrf_delete, validate_single_ip_vrf_redefine, validate_single_l2vni_delete,
    validate_single_l2vni_redefine, validate_tenant_teardown,
};
use rustbgpd_rib::RibCommandError;
use tokio::sync::{broadcast, watch};

use super::*;

impl EvpnRuntimeReloadApply {
    pub(crate) async fn apply_config(
        &self,
        config: &Config,
    ) -> Result<EvpnRuntimeReloadApplyResult, GrpcEvpnRuntimeApplyError> {
        let response = self.apply_candidate_config(config, false).await?;
        let outcome = response_to_reload_outcome(response.outcome)?;
        Ok(EvpnRuntimeReloadApplyResult {
            outcome,
            message: response.message,
        })
    }
}

fn evpn_runtime_candidate_from_toml(
    candidate_toml: &str,
) -> Result<rustbgpd_evpn::EvpnRuntimeCandidate, GrpcEvpnRuntimeApplyError> {
    if candidate_toml.trim().is_empty() {
        return Err(GrpcEvpnRuntimeApplyError::InvalidArgument(
            "candidate_toml must contain a full rustbgpd config".to_string(),
        ));
    }
    let candidate_toml = crate::test_support::tier_authorized_uds_test_config(candidate_toml);
    let candidate =
        Config::load_toml_with_diagnostics(&candidate_toml, "candidate EVPN runtime config")
            .map_err(GrpcEvpnRuntimeApplyError::InvalidArgument)?;
    crate::test_support::assert_tier_authorized_test_config(&candidate);
    evpn_runtime_candidate_from_config(&candidate)
}

pub(crate) async fn apply_evpn_runtime_request(
    request: &proto::ApplyEvpnRuntimeRequest,
    coordinator: &Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>,
    apply_lock: &tokio::sync::Mutex<()>,
    converger: &dyn DaemonEvpnRuntimeConverger,
) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError> {
    apply_evpn_runtime_request_with_metrics(
        request,
        coordinator,
        apply_lock,
        converger,
        &BgpMetrics::new(),
    )
    .await
}

/// Same as [`apply_evpn_runtime_request`] but with a caller-owned metrics
/// handle, so a test can assert the fail-stop counter moved.
pub(crate) async fn apply_evpn_runtime_request_with_metrics(
    request: &proto::ApplyEvpnRuntimeRequest,
    coordinator: &Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>,
    apply_lock: &tokio::sync::Mutex<()>,
    converger: &dyn DaemonEvpnRuntimeConverger,
    metrics: &BgpMetrics,
) -> Result<proto::ApplyEvpnRuntimeResponse, GrpcEvpnRuntimeApplyError> {
    let candidate = evpn_runtime_candidate_from_toml(&request.candidate_toml)?;
    let _apply_guard = apply_lock.lock().await;
    apply_evpn_runtime_candidate_locked(
        candidate,
        request.validate_only,
        coordinator,
        converger,
        metrics,
        || {},
    )
    .await
}

#[derive(Clone)]
struct TestRuntimeConverger {
    result: Result<(), DaemonEvpnRuntimeConvergeError>,
}

impl TestRuntimeConverger {
    const fn ok() -> Self {
        Self { result: Ok(()) }
    }

    fn unsupported(message: &str) -> Self {
        Self {
            result: Err(DaemonEvpnRuntimeConvergeError::unsupported(message)),
        }
    }

    fn failed(message: &str) -> Self {
        Self {
            result: Err(DaemonEvpnRuntimeConvergeError::failed(message)),
        }
    }
}

impl DaemonEvpnRuntimeConverger for TestRuntimeConverger {
    fn converge<'a>(
        &'a self,
        _current: &'a rustbgpd_evpn::EvpnRuntimeModel,
        _candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
        _plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
    ) -> DaemonEvpnRuntimeConvergeFuture<'a> {
        Box::pin(async move { self.result.clone() })
    }
}

fn reload_test_state(
    generation: rustbgpd_evpn::EvpnRuntimeGeneration,
    lifecycle: rustbgpd_evpn::EvpnRuntimeLifecycle,
    mutation_state: rustbgpd_evpn::EvpnRuntimeMutationState,
) -> EvpnRuntimeReloadState {
    EvpnRuntimeReloadState {
        generation,
        lifecycle,
        mutation_state,
    }
}

#[test]
fn reload_classifier_reports_determinate_idle_rejection() {
    let state = reload_test_state(
        rustbgpd_evpn::EvpnRuntimeGeneration::STARTUP,
        rustbgpd_evpn::EvpnRuntimeLifecycle::Active,
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle,
    );
    let terminal = classify_reload_terminal(
        state,
        state,
        Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(
            "unsupported candidate".to_string(),
        )),
    );
    assert!(matches!(
        terminal,
        EvpnRuntimeReloadTerminal::RejectedNoEffect(_)
    ));
}

#[test]
fn reload_classifier_reports_advanced_generation_as_known_partial() {
    let before = reload_test_state(
        rustbgpd_evpn::EvpnRuntimeGeneration::STARTUP,
        rustbgpd_evpn::EvpnRuntimeLifecycle::Active,
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle,
    );
    let after = reload_test_state(
        rustbgpd_evpn::EvpnRuntimeGeneration::STARTUP.next(),
        rustbgpd_evpn::EvpnRuntimeLifecycle::Active,
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle,
    );
    let terminal = classify_reload_terminal(
        before,
        after,
        Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(
            "decomposed step failed".to_string(),
        )),
    );
    assert!(matches!(
        terminal,
        EvpnRuntimeReloadTerminal::KnownPartial(_)
    ));
}

#[test]
fn reload_classifier_reports_failed_or_degraded_state_as_divergence() {
    let before = reload_test_state(
        rustbgpd_evpn::EvpnRuntimeGeneration::STARTUP,
        rustbgpd_evpn::EvpnRuntimeLifecycle::Active,
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle,
    );
    let after = reload_test_state(
        before.generation,
        rustbgpd_evpn::EvpnRuntimeLifecycle::Degraded,
        rustbgpd_evpn::EvpnRuntimeMutationState::Failed,
    );
    let terminal = classify_reload_terminal(
        before,
        after,
        Err(GrpcEvpnRuntimeApplyError::FailedPrecondition(
            "converger failed after effects".to_string(),
        )),
    );
    assert!(matches!(
        terminal,
        EvpnRuntimeReloadTerminal::KnownDivergence(_)
    ));
}

#[tokio::test]
async fn reload_classifier_reports_transport_and_join_uncertainty_as_ambiguous() {
    let state = reload_test_state(
        rustbgpd_evpn::EvpnRuntimeGeneration::STARTUP,
        rustbgpd_evpn::EvpnRuntimeLifecycle::Active,
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle,
    );
    for error in [
        GrpcEvpnRuntimeApplyError::Internal("internal".to_string()),
        GrpcEvpnRuntimeApplyError::Unavailable("unavailable".to_string()),
    ] {
        assert!(matches!(
            classify_reload_terminal(state, state, Err(error)),
            EvpnRuntimeReloadTerminal::PublicationAmbiguous(_)
        ));
    }

    let baseline = load_runtime_test_config(minimal_runtime_candidate_toml(), "test baseline");
    let candidate = load_runtime_test_config(l2vni_runtime_candidate_toml(), "test candidate");
    let reload_apply = EvpnRuntimeReloadApply::new(
        empty_evpn_runtime_coordinator(),
        Arc::new(tokio::sync::Mutex::new(())),
        Arc::new(TestRuntimeConverger::ok()),
        baseline,
    );
    let attempt = reload_apply
        .apply_config_if_changed(
            &candidate,
            |_, _| panic!("join-error proof"),
            || panic!("join-error must fail before mutation"),
        )
        .await;
    assert!(matches!(
        attempt.terminal,
        EvpnRuntimeReloadTerminal::PublicationAmbiguous(GrpcEvpnRuntimeApplyError::Internal(_))
    ));
}

/// Signals entry into `converge` and then blocks until the test grants
/// a permit — lets a test drop the caller's future mid-converge.
struct GatedRuntimeConverger {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
}

impl DaemonEvpnRuntimeConverger for GatedRuntimeConverger {
    fn converge<'a>(
        &'a self,
        _current: &'a rustbgpd_evpn::EvpnRuntimeModel,
        _candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
        _plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
    ) -> DaemonEvpnRuntimeConvergeFuture<'a> {
        Box::pin(async move {
            self.entered.notify_one();
            // A closed semaphore must fail the test loudly — silently
            // proceeding would let the cancellation-shield tests pass
            // without ever blocking mid-converge.
            let _permit = self
                .release
                .acquire()
                .await
                .expect("gate semaphore closed while converge was blocked");
            Ok(())
        })
    }
}

fn minimal_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

"#
}

fn l2vni_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
"#
}

fn l2vni_one_es_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#
}

// Two committed L2VNIs + one ES over VNI 100. Config requires one
// local ES per VNI, so a second ES must target VNI 200. This is the
// pre-add baseline for the single-ES-add tests.
fn two_l2vni_one_es_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#
}

// Adds a second ES over VNI 200 on top of the one-ES baseline (one
// local ES per VNI). Used as the single-ES-add candidate.
fn two_l2vni_two_es_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
originator_ip = "10.0.0.1"
"#
}

// Redefines the existing ES so it also covers VNI 200. Used by the
// single-ES-redefine tests.
fn two_l2vni_redefined_es_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100, 200]
originator_ip = "10.0.0.1"
"#
}

// Adds VNI 300 while trying to expand the existing ES with committed VNI
// 200 instead. The additive ES-expansion validator must reject this: every
// newly added ES member must be an L2VNI added in the same request.
fn three_l2vni_redefined_es_existing_member_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100, 200]
originator_ip = "10.0.0.1"
"#
}

// A full tenant: L2VNI 100 that is both an Ethernet Segment member and
// linked to IP-VRF tenant-blue. Tearing this down to the minimal candidate
// exercises ES-aware L2VNI delete + ES delete + linked IP-VRF delete at
// once.
fn es_member_l2vni_linked_ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#
}

fn es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"
advertise_svi_mac = true

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#
}

fn two_tenant_additive_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"
advertise_svi_mac = true

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-green"
advertise_svi_mac = true

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 6000
rd = "65000:6000"
route_targets = ["65000:6000"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni6000"
table_id = 6000

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
originator_ip = "10.0.0.1"
"#
}

fn relink_green_plus_l2vni_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-green"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-green"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni5001"
table_id = 5001

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
originator_ip = "10.0.0.1"
"#
}

fn l2vni_linked_ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

fn two_l2vni_linked_ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

fn l2vni_swap_linked_ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

fn l2vni_mixed_redefine_linked_ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

fn l2vni_mixed_redefine_relink_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

fn l2vni_mixed_redefine_delete_vni100_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 200
rd = "65000:222"
route_targets = ["65000:222"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
"#
}

fn l2vni_one_ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

fn two_l2vni_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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
"#
}

fn l2vni_swap_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
"#
}

fn l2vni_swap_delete_vni100_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
"#
}

// Two L2VNIs where VNI 100 advertises its SVI MAC. Tearing both down is a
// multi-element teardown that exercises the SVI drain leg of
// converge_tenant_teardown.
fn two_l2vni_one_svi_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
advertise_svi_mac = true

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#
}

// Redefines VNI 100's route identity (new RD + RT) on top of the
// `two_l2vni` baseline; VNI 200 is untouched. The single-L2VNI-redefine
// candidate.
fn two_l2vni_one_redefined_l2vni_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#
}

// Redefines VNI 100 by flipping its dataplane aliasing-ECMP gate off; all
// other fields (including RD/RT) are unchanged. Exercises the
// dataplane-only `FdbNhg -> SingleDst` redefine transition.
fn two_l2vni_aliasing_toggle_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
apply_aliasing_ecmp = false

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"
"#
}

// Redefines BOTH VNIs at once — the batch-redefine composer accepts this
// as a pure L2VNI-only runtime update.
fn two_l2vni_both_redefined_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:222"
route_targets = ["65000:222"]
local_vtep_ip = "10.0.0.1"
"#
}

// Redefines VNI 100 (new RD) AND adds a standalone IP-VRF — used to assert
// the validator rejects a redefine mixed with an IP-VRF change.
fn two_l2vni_one_redefined_plus_ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:111"
route_targets = ["65000:111"]
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
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

// Redefines VNI 100 (new RD) while it remains an Ethernet Segment member.
fn two_l2vni_one_es_redefined_member_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:111"
route_targets = ["65000:111"]
local_vtep_ip = "10.0.0.1"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.1"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.1"
"#
}

fn two_l2vni_one_ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

fn ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

// Two declared IP-VRFs (tenant-blue, tenant-green) with L2VNI 100 linked to
// tenant-blue. The `_relinked` variant moves only the L2VNI's `ip_vrf` to
// tenant-green — every IP-VRF and L2VNI row is byte-identical, so the diff
// is a pure reference-metadata (relink) change.
fn relink_blue_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni5001"
table_id = 5001
"#
}

fn relink_green_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni5001"
table_id = 5001
"#
}

// The relink fixtures' two IP-VRFs with no L2VNI — a baseline for adding a
// linked L2VNI (the reference delta the central relink guard must allow).
fn ip_vrfs_blue_green_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni5001"
table_id = 5001
"#
}

fn ip_vrf_redefined_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5555"
route_targets = ["65000:5555"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:11"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

fn ip_vrf_redefined_l3vni_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5001
rd = "65000:5555"
route_targets = ["65000:5555"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:11"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5001"
table_id = 5001
"#
}

fn ip_vrf_redefined_plus_l2vni_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5555"
route_targets = ["65000:5555"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:11"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#
}

fn two_ip_vrf_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 6000
rd = "65000:6000"
route_targets = ["65000:6000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-green"
l3vxlan_device = "vni6000"
table_id = 6000
"#
}

fn two_ip_vrf_both_redefined_runtime_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5555"
route_targets = ["65000:5555"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:11"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-green"
vni = 6000
rd = "65000:6666"
route_targets = ["65000:6666"]
local_vtep_ip = "10.0.0.101"
router_mac = "02:00:00:00:00:12"
vrf_device = "vrf-green"
l3vxlan_device = "vni6000"
table_id = 6000
"#
}

fn empty_evpn_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
    Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        rustbgpd_evpn::EvpnInstanceTable::new(),
        rustbgpd_evpn::IpVrfTable::new(),
        Vec::new(),
    )))
}

fn ip_vrf_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
    let current = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
    Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        rustbgpd_evpn::EvpnInstanceTable::new(),
        current.ip_vrfs().clone(),
        Vec::new(),
    )))
}

fn two_ip_vrf_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
    let current = runtime_candidate_from_toml(two_ip_vrf_runtime_candidate_toml());
    Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        rustbgpd_evpn::EvpnInstanceTable::new(),
        current.ip_vrfs().clone(),
        Vec::new(),
    )))
}

fn two_l2vni_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
    let current = runtime_candidate_from_toml(two_l2vni_runtime_candidate_toml());
    Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        rustbgpd_evpn::IpVrfTable::new(),
        Vec::new(),
    )))
}

fn two_l2vni_one_es_runtime_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
    let current = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        rustbgpd_evpn::IpVrfTable::new(),
        current.ethernet_segments().to_vec(),
    )))
}

fn runtime_model_from_candidate_toml(toml: &str) -> rustbgpd_evpn::EvpnRuntimeModel {
    let candidate = evpn_runtime_candidate_from_toml(toml).unwrap();
    rustbgpd_evpn::EvpnRuntimeModel::coordinator_startup(
        candidate.instances().clone(),
        candidate.ip_vrfs().clone(),
        candidate.ethernet_segments().to_vec(),
    )
}

fn materialize_shared_test_only_grpc_token(toml: &str) -> String {
    let token = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/grpc-test-only-operator.token"
    );
    toml.replace("/run/rustbgpd/grpc-test-only-operator.token", token)
}

fn runtime_candidate_from_toml(toml: &str) -> rustbgpd_evpn::EvpnRuntimeCandidate {
    evpn_runtime_candidate_from_toml(toml).unwrap()
}

fn load_runtime_test_config(toml: &str, source: &str) -> Config {
    let config = Config::load_toml_with_diagnostics(
        &crate::test_support::tier_authorized_uds_test_config(toml),
        source,
    )
    .unwrap();
    crate::test_support::assert_tier_authorized_test_config(&config);
    config
}

fn runtime_model_from_toml(toml: &str) -> rustbgpd_evpn::EvpnRuntimeModel {
    let candidate = runtime_candidate_from_toml(toml);
    rustbgpd_evpn::EvpnRuntimeModel::startup(
        candidate.instances().clone(),
        candidate.ip_vrfs().clone(),
        candidate.ethernet_segments().to_vec(),
    )
}

fn pre_authorized_runtime_candidate_from_toml(toml: &str) -> rustbgpd_evpn::EvpnRuntimeCandidate {
    let config = Config::load_toml_with_diagnostics(toml, "pre-authorized test config").unwrap();
    crate::test_support::assert_tier_authorized_test_config(&config);
    evpn_runtime_candidate_from_config(&config).unwrap()
}

fn pre_authorized_runtime_model_from_toml(toml: &str) -> rustbgpd_evpn::EvpnRuntimeModel {
    let candidate = pre_authorized_runtime_candidate_from_toml(toml);
    rustbgpd_evpn::EvpnRuntimeModel::coordinator_startup(
        candidate.instances().clone(),
        candidate.ip_vrfs().clone(),
        candidate.ethernet_segments().to_vec(),
    )
}

fn runtime_converger_rib_responder(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    injects: Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (events_tx, _) = broadcast::channel(16);
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                    let _ = reply.send(events_tx.subscribe());
                }
                RibUpdate::QueryEvpnRoutes { reply, .. } => {
                    let _ = reply.send(vec![]);
                }
                RibUpdate::InjectEvpn { route, reply } => {
                    injects.lock().await.push(route.key());
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::WithdrawEvpn { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
    })
}

// Like `runtime_converger_rib_responder` but also records withdraws,
// for tests that need to observe drains (e.g. ES-add re-stamping a
// member VNI's local MAC origination).
fn runtime_converger_rib_recorder(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    injects: Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
    withdraws: Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (events_tx, _) = broadcast::channel(16);
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                    let _ = reply.send(events_tx.subscribe());
                }
                RibUpdate::QueryEvpnRoutes { reply, .. } => {
                    let _ = reply.send(vec![]);
                }
                RibUpdate::InjectEvpn { route, reply } => {
                    injects.lock().await.push(route.key());
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::WithdrawEvpn { key, reply } => {
                    withdraws.lock().await.push(key);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
    })
}

fn runtime_ip_vrf_ready_status(
    id: rustbgpd_evpn::IpVrfId,
    name: &str,
) -> rustbgpd_evpn::IpVrfDataplaneStatus {
    rustbgpd_evpn::IpVrfDataplaneStatus {
        vrf_id: id,
        vrf_name: name.to_string(),
        status: rustbgpd_evpn::ip_vrf::IpVrfStatus::Ready {
            vrf_ifindex: 60,
            l3vxlan_ifindex: 61,
            table_id: id.as_u32(),
            router_mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0x60]),
        },
    }
}

fn runtime_local_ip_observation(
    id: rustbgpd_evpn::IpVrfId,
) -> rustbgpd_evpn::ip_vrf::LocalIpRouteObservation {
    rustbgpd_evpn::ip_vrf::LocalIpRouteObservation {
        vrf_id: id,
        prefix: rustbgpd_wire::EvpnIpPrefixValue::V4(rustbgpd_wire::Ipv4Prefix::new(
            std::net::Ipv4Addr::new(10, 6, 0, 0),
            24,
        )),
        source: rustbgpd_evpn::RouteSource::Static,
        via: None,
    }
}

async fn wait_for_recorded_evpn_key(
    records: &Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
    message: &'static str,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !records.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect(message);
}

async fn wait_for_recorded_evpn_key_matching<F>(
    records: &Arc<tokio::sync::Mutex<Vec<rustbgpd_wire::EvpnRouteKey>>>,
    message: &'static str,
    matches_key: F,
) where
    F: Fn(&rustbgpd_wire::EvpnRouteKey) -> bool,
{
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if records.lock().await.iter().any(&matches_key) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect(message);
}

#[tokio::test]
async fn apply_evpn_runtime_validate_only_plans_without_advancing() {
    let coordinator = empty_evpn_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: l2vni_runtime_candidate_toml().to_string(),
            validate_only: true,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyValidated as i32
    );
    let plan = response.plan.unwrap();
    assert_eq!(plan.current_generation, 1);
    assert_eq!(plan.proposed_generation, 2);
    assert_eq!(plan.evpn_instances.unwrap().added, vec!["100"]);
    assert_eq!(response.runtime.unwrap().generation, 1);
    assert_eq!(coordinator.lock().unwrap().model().generation().as_u64(), 1);
}

#[tokio::test]
async fn apply_evpn_runtime_validate_only_rejects_unsupported_shape() {
    // LAN-214 #9: a dry-run must reject what a real apply rejects. An
    // IP-VRF L3VNI (identity) redefine is restart-required by design; a
    // real apply fails it closed, so validate_only must too — not return
    // "validated". The converger is scripted to fail if converge is ever
    // called, proving the dry-run stays side-effect free.
    let current = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::failed("validate_only must not converge");

    let error = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: ip_vrf_redefined_l3vni_runtime_candidate_toml().to_string(),
            validate_only: true,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap_err();

    let GrpcEvpnRuntimeApplyError::FailedPrecondition(message) = error else {
        panic!("expected FailedPrecondition, got: {error:?}");
    };
    assert!(
        message.contains("rejected"),
        "dry-run must reject, not validate: {message}"
    );
    assert!(
        message.contains("restart-required by design"),
        "must carry the real shape rejection: {message}"
    );

    let guard = coordinator.lock().unwrap();
    assert_eq!(
        guard.model().generation().as_u64(),
        1,
        "a rejected dry-run must not advance the generation"
    );
    assert_eq!(
        guard.model().mutation_state(),
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle,
        "a rejected dry-run must not pin/degrade the runtime"
    );
}

#[tokio::test]
async fn apply_evpn_runtime_validate_only_agrees_with_commit_on_missing_actors() {
    // LAN-897: on an RR-only daemon no EVPN actors are spawned, so a
    // commit of an L2VNI add fails the dataplane-availability
    // precondition. The dry-run of the identical candidate must reject
    // with the same precondition — a validate_only verdict of
    // "Validated" that a commit then contradicts breaks the dry-run's
    // commit-predictability promise.
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };
    let apply_lock = tokio::sync::Mutex::new(());

    let commit_error = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: l2vni_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        empty_evpn_runtime_coordinator().as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .expect_err("commit without a dataplane actor must fail");
    let GrpcEvpnRuntimeApplyError::FailedPrecondition(commit_message) = commit_error else {
        panic!("expected FailedPrecondition from commit, got: {commit_error:?}");
    };
    assert!(
        commit_message.contains("requires an active EVPN dataplane actor"),
        "commit must fail on the missing dataplane actor: {commit_message}"
    );

    let coordinator = empty_evpn_runtime_coordinator();
    let dry_run_error = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: l2vni_runtime_candidate_toml().to_string(),
            validate_only: true,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .expect_err("dry-run must reject exactly what the commit rejects");
    let GrpcEvpnRuntimeApplyError::FailedPrecondition(dry_run_message) = dry_run_error else {
        panic!("expected FailedPrecondition from dry-run, got: {dry_run_error:?}");
    };
    assert!(
        dry_run_message.contains("requires an active EVPN dataplane actor"),
        "dry-run must carry the commit's availability precondition: {dry_run_message}"
    );

    let guard = coordinator.lock().unwrap();
    assert_eq!(
        guard.model().generation().as_u64(),
        1,
        "a rejected dry-run must not advance the generation"
    );
    assert_eq!(
        guard.model().mutation_state(),
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle,
        "a rejected dry-run must not pin/degrade the runtime"
    );
}

#[tokio::test]
async fn apply_evpn_runtime_validate_only_validates_when_required_actors_present() {
    // LAN-897 accept side: the availability gate must not reject a
    // dry-run whose routed converge would find its actors. An ES add
    // requires only the segment actor; with it spawned, validate_only
    // must still report Validated (and converge must not run — the
    // committed generation stays put).
    let current = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_responder(rib_rx, injects);

    let instances = Arc::new(current.instances().clone());
    let segment_handle = evpn_segment::spawn(
        &instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_l2vni_two_es_runtime_candidate_toml().to_string(),
            validate_only: true,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyValidated as i32
    );
    assert_eq!(coordinator.lock().unwrap().model().generation().as_u64(), 1);
    segment_handle.shutdown().await;
}

#[tokio::test]
async fn shape_gate_and_converge_reject_unsupported_shapes_identically() {
    // LAN-214 #8: both the shape gate and converge use the shared routed
    // validator. Asserting byte-identical messages keeps their rejection
    // behavior aligned for unsupported shapes.
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    // L2VNI add mixed with an IP-VRF identity redefine: undecomposable,
    // routes to the L2VNI-add branch which rejects the IP-VRF change.
    let mut mixed_candidate = ip_vrf_redefined_l3vni_runtime_candidate_toml().to_string();
    mixed_candidate.push_str(
        r#"
[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
"#,
    );

    let cases: Vec<(
        &str,
        rustbgpd_evpn::EvpnRuntimeModel,
        rustbgpd_evpn::EvpnRuntimeCandidate,
    )> = vec![
        (
            "ip_vrf identity (L3VNI) redefine",
            runtime_model_from_toml(ip_vrf_runtime_candidate_toml()),
            runtime_candidate_from_toml(ip_vrf_redefined_l3vni_runtime_candidate_toml()),
        ),
        (
            "l2vni add mixed with ip_vrf identity redefine",
            runtime_model_from_toml(ip_vrf_runtime_candidate_toml()),
            runtime_candidate_from_toml(&mixed_candidate),
        ),
    ];

    for (name, current, candidate) in &cases {
        let plan = current.plan_candidate(candidate);
        let gate_error = validate_supported_plan_shape(current, candidate, &plan)
            .expect_err(&format!("{name}: shape gate must reject"));
        let converge_error = converger
            .converge(current, candidate, &plan)
            .await
            .expect_err(&format!("{name}: converge dispatch must reject"));
        assert_eq!(
            gate_error.message(),
            converge_error.message(),
            "{name}: shape gate and converge dispatch must route to the identical rejection"
        );
    }
}

#[test]
fn converge_dispatch_consumes_one_routed_validation_result() {
    let source = include_str!("../evpn_runtime_converger.rs");
    let dispatch = source
        .split_once("impl DaemonEvpnRuntimeConverger for EvpnRuntimeActorConverger")
        .unwrap()
        .1
        .split_once("    fn validate_availability(")
        .unwrap()
        .0;

    assert_eq!(dispatch.matches("route_supported_plan_shape(").count(), 1);
    assert!(!dispatch.contains("validate_"));
}

#[test]
fn shape_gate_accepts_every_supported_converge_shape() {
    // LAN-214 #8 (accept side): the shape gate must accept exactly the
    // shapes the converge dispatch commits. Each shape below has a
    // dedicated committing test through the real converger (e.g.
    // `apply_evpn_runtime_ethernet_segment_add_commits_after_convergence`);
    // this asserts the gate agrees they are supported.
    let cases: [(&str, rustbgpd_evpn::EvpnRuntimeModel, &str); 3] = [
        (
            "single L2VNI add",
            runtime_model_from_toml(minimal_runtime_candidate_toml()),
            l2vni_runtime_candidate_toml(),
        ),
        (
            "single IP-VRF add",
            runtime_model_from_toml(minimal_runtime_candidate_toml()),
            ip_vrf_runtime_candidate_toml(),
        ),
        (
            "Ethernet Segment add",
            runtime_model_from_toml(two_l2vni_one_es_runtime_candidate_toml()),
            two_l2vni_two_es_runtime_candidate_toml(),
        ),
    ];
    for (name, current, candidate_toml) in &cases {
        let candidate = runtime_candidate_from_toml(candidate_toml);
        let plan = current.plan_candidate(&candidate);
        assert!(
            validate_supported_plan_shape(current, &candidate, &plan).is_ok(),
            "{name}: shape gate must accept a shape the converge dispatch commits"
        );
    }
}

#[tokio::test]
async fn apply_evpn_runtime_noop_succeeds_without_generation_advance() {
    let coordinator = empty_evpn_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::failed("noop should not converge");

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: minimal_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyNoop as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 1);
    assert_eq!(coordinator.lock().unwrap().model().generation().as_u64(), 1);
}

#[tokio::test]
async fn apply_evpn_runtime_l2vni_add_commits_after_convergence() {
    let coordinator = empty_evpn_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: l2vni_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    let runtime = response.runtime.unwrap();
    assert_eq!(runtime.generation, 2);
    assert_eq!(
        runtime.mutation_state,
        proto::EvpnRuntimeMutationState::EvpnRuntimeMutationIdle as i32
    );
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_instances.unwrap().added, vec!["100"]);
    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 2);
    assert!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .is_some()
    );
}

#[tokio::test]
async fn apply_evpn_runtime_l2vni_delete_commits_after_convergence() {
    let coordinator = two_l2vni_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: l2vni_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    let runtime = response.runtime.unwrap();
    assert_eq!(runtime.generation, 2);
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_instances.unwrap().deleted, vec!["200"]);
    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 2);
    assert!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
            .is_none()
    );
}

#[tokio::test]
async fn apply_evpn_runtime_l2vni_swap_commits_after_convergence() {
    let coordinator = two_l2vni_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: l2vni_swap_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    let runtime = response.runtime.unwrap();
    assert_eq!(runtime.generation, 2);
    let plan = response.plan.unwrap();
    let instances = plan.evpn_instances.unwrap();
    assert_eq!(instances.added, vec!["300"]);
    assert_eq!(instances.deleted, vec!["200"]);
    let guard = coordinator.lock().unwrap();
    assert!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(300).unwrap())
            .is_some()
    );
    assert!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
            .is_none()
    );
}

#[tokio::test]
async fn apply_evpn_runtime_l2vni_batch_redefine_commits_after_convergence() {
    let coordinator = two_l2vni_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_l2vni_both_redefined_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    let instances = response.plan.unwrap().evpn_instances.unwrap();
    assert_eq!(instances.redefined, vec!["100", "200"]);
    let guard = coordinator.lock().unwrap();
    assert_eq!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .expect("VNI 100")
            .rd
            .to_string(),
        "65000:111"
    );
    assert_eq!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
            .expect("VNI 200")
            .rd
            .to_string(),
        "65000:222"
    );
}

#[tokio::test]
async fn apply_evpn_runtime_l2vni_delete_commits_in_ip_vrf_deployment() {
    let current = runtime_candidate_from_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        Vec::new(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: ip_vrf_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_instances.unwrap().deleted, vec!["100"]);
    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 2);
    assert!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .is_none()
    );
    assert!(guard.model().ip_vrfs().get("tenant-blue").is_some());
    assert!(!guard.model().ip_vrfs().is_referenced("tenant-blue"));
}

#[tokio::test]
async fn apply_evpn_runtime_ip_vrf_add_commits_after_convergence() {
    let coordinator = ip_vrf_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_ip_vrf_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    let runtime = response.runtime.unwrap();
    assert_eq!(runtime.generation, 2);
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_ip_vrfs.unwrap().added, vec!["tenant-green"]);
    let guard = coordinator.lock().unwrap();
    assert!(guard.model().ip_vrfs().get("tenant-green").is_some());
}

#[tokio::test]
async fn apply_evpn_runtime_ip_vrf_delete_commits_after_convergence() {
    let coordinator = two_ip_vrf_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: ip_vrf_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    let runtime = response.runtime.unwrap();
    assert_eq!(runtime.generation, 2);
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_ip_vrfs.unwrap().deleted, vec!["tenant-green"]);
    let guard = coordinator.lock().unwrap();
    assert!(guard.model().ip_vrfs().get("tenant-green").is_none());
    assert!(guard.model().ip_vrfs().get("tenant-blue").is_some());
}

#[tokio::test]
async fn apply_evpn_runtime_ip_vrf_redefine_commits_after_convergence() {
    let coordinator = ip_vrf_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: ip_vrf_redefined_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    let runtime = response.runtime.unwrap();
    assert_eq!(runtime.generation, 2);
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_ip_vrfs.unwrap().redefined, vec!["tenant-blue"]);
    let guard = coordinator.lock().unwrap();
    let vrf = guard
        .model()
        .ip_vrfs()
        .get("tenant-blue")
        .expect("tenant-blue should still be committed");
    assert_eq!(guard.model().generation().as_u64(), 2);
    assert_eq!(vrf.id.as_u32(), 5000);
    assert_eq!(vrf.rd.to_string(), "65000:5555");
    assert_eq!(vrf.local_vtep_ip.to_string(), "10.0.0.101");
    assert_eq!(vrf.router_mac.to_string(), "02:00:00:00:00:11");
    assert_eq!(vrf.table_id, 5000);
    assert_eq!(vrf.vrf_device, "vrf-blue");
    assert_eq!(vrf.l3vxlan_device, "vni5000");
}

/// ADR-0080: dropping the request future mid-converge (a disconnected
/// gRPC client) must not cancel the apply — the detached task finishes
/// the commit and advances the reload baseline on its own.
#[tokio::test]
async fn apply_request_dropped_mid_converge_still_commits_and_advances_baseline() {
    let baseline = load_runtime_test_config(minimal_runtime_candidate_toml(), "test baseline");
    let coordinator = empty_evpn_runtime_coordinator();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let converger = Arc::new(GatedRuntimeConverger {
        entered: entered.clone(),
        release: release.clone(),
    });
    let reload_apply = EvpnRuntimeReloadApply::new(
        coordinator.clone(),
        Arc::new(tokio::sync::Mutex::new(())),
        converger,
        baseline,
    );

    let request = proto::ApplyEvpnRuntimeRequest {
        candidate_toml: crate::test_support::tier_authorized_uds_test_config(
            l2vni_runtime_candidate_toml(),
        ),
        validate_only: false,
    };
    let mut caller = Box::pin(reload_apply.apply_request(&request));
    tokio::select! {
        _ = &mut caller => panic!("apply must still be blocked in converge"),
        () = entered.notified() => {}
    }
    // Simulate the client disconnect: tonic drops the request future.
    drop(caller);
    release.add_permits(1);

    let deadline = StdInstant::now() + Duration::from_secs(5);
    loop {
        if coordinator.lock().unwrap().model().generation().as_u64() == 2
            && reload_apply.committed_config_locked().evpn_instances.len() == 1
        {
            break;
        }
        assert!(
            StdInstant::now() < deadline,
            "dropped caller cancelled the apply: generation/baseline never advanced"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// ADR-0080, SIGHUP flavor: losing the outer reload waiter must not
/// cancel an EVPN converge already past planning.
#[tokio::test]
async fn reload_apply_dropped_mid_converge_still_commits_and_advances_baseline() {
    let baseline = load_runtime_test_config(minimal_runtime_candidate_toml(), "test baseline");
    let candidate = load_runtime_test_config(l2vni_runtime_candidate_toml(), "test candidate");
    let coordinator = empty_evpn_runtime_coordinator();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let converger = Arc::new(GatedRuntimeConverger {
        entered: entered.clone(),
        release: release.clone(),
    });
    let reload_apply = EvpnRuntimeReloadApply::new(
        coordinator.clone(),
        Arc::new(tokio::sync::Mutex::new(())),
        converger,
        baseline,
    );

    let mutation_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let apply = reload_apply.clone();
    let phase = mutation_started.clone();
    let mut caller = Box::pin(async move {
        apply
            .apply_config_if_changed(
                &candidate,
                |_, _| true,
                move || phase.store(true, std::sync::atomic::Ordering::SeqCst),
            )
            .await
    });
    tokio::select! {
        _ = &mut caller => panic!("reload apply must still be blocked in converge"),
        () = entered.notified() => {}
    }
    assert!(
        mutation_started.load(std::sync::atomic::Ordering::SeqCst),
        "blocked converge must observe the mutation phase"
    );
    // Simulate an outer reload waiter going away.
    drop(caller);
    release.add_permits(1);

    let deadline = StdInstant::now() + Duration::from_secs(5);
    loop {
        if coordinator.lock().unwrap().model().generation().as_u64() == 2
            && reload_apply.committed_config_locked().evpn_instances.len() == 1
        {
            break;
        }
        assert!(
            StdInstant::now() < deadline,
            "dropped reload waiter cancelled the apply: generation/baseline never advanced"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// ADR-0085: a binding-only `[[ethernet_segments]]` edit plans as
/// an EVPN runtime no-op (the binding lives outside the domain
/// type the planner diffs) but must still advance the committed
/// config AND republish the resolved bindings to the link-drain
/// coordinator's watch — both directions: bind and unbind.
#[tokio::test]
async fn committed_config_advance_republishes_es_link_bindings() {
    let baseline = load_runtime_test_config(l2vni_one_es_runtime_candidate_toml(), "test baseline");
    let bound_toml = format!(
        "{}interface = \"bond0\"\nrecovery_delay_secs = 5\n",
        l2vni_one_es_runtime_candidate_toml()
    );
    let bound = load_runtime_test_config(&bound_toml, "test candidate");

    // Coordinator already holds the baseline model, so the
    // binding-only candidate is a planner no-op.
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        baseline.resolve_evpn_instances().unwrap(),
        baseline.resolve_evpn_ip_vrfs().unwrap(),
        baseline.resolve_ethernet_segments().unwrap(),
    )));
    let (bindings_tx, mut bindings_rx) =
        tokio::sync::watch::channel(Arc::new(baseline.resolve_es_link_bindings().unwrap())
            as crate::evpn_es_link_drain::EsLinkBindings);
    let reload_apply = EvpnRuntimeReloadApply::new(
        coordinator,
        Arc::new(tokio::sync::Mutex::new(())),
        Arc::new(TestRuntimeConverger::ok()),
        baseline,
    )
    .with_es_link_bindings_publisher(Arc::new(bindings_tx));

    assert!(bindings_rx.borrow_and_update().is_empty());

    // Bind: SIGHUP-shaped apply commits (Noop) and republishes.
    let attempt = reload_apply
        .apply_config_if_changed(&bound, evpn_runtime_changed_for_test, || {
            panic!("planner no-op must remain preflight")
        })
        .await;
    assert!(matches!(
        attempt.terminal,
        EvpnRuntimeReloadTerminal::Applied(EvpnRuntimeReloadApplyResult {
            outcome: EvpnRuntimeReloadOutcome::Noop,
            ..
        })
    ));
    assert!(bindings_rx.has_changed().unwrap(), "binding add published");
    let published = bindings_rx.borrow_and_update().clone();
    let binding = published.values().next().expect("one binding");
    assert_eq!(binding.interface, "bond0");
    assert_eq!(binding.recovery_delay, Duration::from_secs(5));

    // Unbind: removing the keys republishes the empty map.
    let unbound = load_runtime_test_config(l2vni_one_es_runtime_candidate_toml(), "test candidate");
    let attempt = reload_apply
        .apply_config_if_changed(&unbound, evpn_runtime_changed_for_test, || {
            panic!("planner no-op must remain preflight")
        })
        .await;
    assert!(matches!(
        attempt.terminal,
        EvpnRuntimeReloadTerminal::Applied(_)
    ));
    assert!(
        bindings_rx.has_changed().unwrap(),
        "binding removal published"
    );
    assert!(bindings_rx.borrow_and_update().is_empty());
}

fn evpn_runtime_changed_for_test(new_config: &Config, current: &Config) -> bool {
    new_config.evpn_instances != current.evpn_instances
        || new_config.evpn_ip_vrfs != current.evpn_ip_vrfs
        || new_config.ethernet_segments != current.ethernet_segments
}

#[test]
fn validate_single_ip_vrf_redefine_accepts_one_redefined_vrf() {
    let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(ip_vrf_redefined_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let redefined = validate_single_ip_vrf_redefine(&current, &candidate, &plan).unwrap();
    assert_eq!(redefined, "tenant-blue");
}

#[test]
fn validate_single_ip_vrf_delete_rejects_linked_l2vni() {
    let current = runtime_model_from_candidate_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate = rustbgpd_evpn::EvpnRuntimeCandidate::new(
        current.instances().clone(),
        rustbgpd_evpn::IpVrfTable::new(),
        Vec::new(),
    );
    let plan = current.plan_candidate(&candidate);

    let error = validate_single_ip_vrf_delete(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("referenced by an L2VNI"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_single_ip_vrf_redefine_rejects_mixed_l2vni_change() {
    let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(ip_vrf_redefined_plus_l2vni_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let error = validate_single_ip_vrf_redefine(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("L2VNI changes are absent"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_single_ip_vrf_redefine_rejects_multiple_redefined_vrfs() {
    let current = runtime_model_from_candidate_toml(two_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_ip_vrf_both_redefined_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let error = validate_single_ip_vrf_redefine(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("exactly one redefined IP-VRF"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_single_ip_vrf_redefine_rejects_l3vni_device_or_table_change() {
    let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(ip_vrf_redefined_l3vni_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let error = validate_single_ip_vrf_redefine(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("L3VNI"),
        "unexpected error message: {message}"
    );
}

#[test]
fn ip_vrf_relink_is_not_a_noop_and_classifies() {
    // A pure relink edits no IP-VRF / L2VNI / ES row, so without the
    // reference-delta signal the plan would read as a no-op and never
    // converge. Pin that the signal is set, the plan is non-noop, and the
    // relink classifier routes it.
    let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(relink_green_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert!(
        !plan.evpn_instances.has_changes(),
        "L2VNI rows are identical"
    );
    assert!(!plan.ip_vrfs.has_changes(), "IP-VRF rows are identical");
    assert!(!plan.ethernet_segments.has_changes());
    assert!(plan.ip_vrf_references_changed, "the link reference moved");
    assert!(!plan.is_noop(), "a relink must not read as a no-op");
    assert!(is_ip_vrf_relink_plan(&plan));
    assert!(!is_tenant_teardown_plan(&plan, &current));
}

#[test]
fn validate_ip_vrf_relink_accepts_pure_relink() {
    let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(relink_green_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    validate_ip_vrf_relink(&current, &candidate, &plan).unwrap();
}

#[test]
fn validate_ip_vrf_relink_rejects_row_changes() {
    // Dropping the L2VNI shifts references too, but it is a row delete — not
    // a pure relink — so the relink validator must fail closed.
    let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert!(plan.evpn_instances.has_changes() || plan.ip_vrfs.has_changes());
    let error = validate_ip_vrf_relink(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("no L2VNI / IP-VRF / Ethernet Segment row changes"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_no_unexpected_relink_rejects_relink_outside_add_delete() {
    // A relinked VNI that is neither added nor deleted (the dispatcher only
    // reaches this guard for non-pure-relink, non-teardown plans) is a relink
    // mixed into another change — e.g. ES change + relink, which would
    // otherwise commit but never republish ip_vrfs and diverge the dataplane.
    let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(relink_green_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    assert!(plan.ip_vrf_references_changed);
    assert!(plan.evpn_instances.added.is_empty() && plan.evpn_instances.deleted.is_empty());

    let error = validate_no_unexpected_relink(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("relink") && message.contains("separate request"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_no_unexpected_relink_allows_linked_l2vni_add() {
    // Adding an L2VNI that links an IP-VRF is the reference delta intrinsic to
    // that add (the VNI is in evpn_instances.added), so the guard must allow
    // it — otherwise building up a linked tenant would fail closed.
    let current = runtime_model_from_candidate_toml(ip_vrfs_blue_green_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(relink_blue_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    assert_eq!(plan.evpn_instances.added, vec![100]);
    assert!(plan.ip_vrf_references_changed);

    validate_no_unexpected_relink(&current, &candidate, &plan).unwrap();
}

#[test]
fn validate_no_unexpected_relink_noop_when_references_unchanged() {
    let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(relink_blue_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    assert!(!plan.ip_vrf_references_changed);
    validate_no_unexpected_relink(&current, &candidate, &plan).unwrap();
}

#[tokio::test]
async fn apply_evpn_runtime_unsupported_non_noop_does_not_degrade_runtime() {
    let coordinator = empty_evpn_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::unsupported("unsupported test shape");

    let error = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: l2vni_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        GrpcEvpnRuntimeApplyError::FailedPrecondition(_)
    ));
    // A non-noop apply with no convergence backend is a capability gap,
    // not an operational failure: the committed generation stays healthy
    // (Active/Idle) so `GetEvpnRuntime` never reports a misleading
    // degraded state from a fail-closed probe.
    let snapshot = coordinator.lock().unwrap().snapshot();
    assert_eq!(snapshot.generation.as_u64(), 1);
    assert_eq!(
        snapshot.lifecycle,
        rustbgpd_evpn::EvpnRuntimeLifecycle::Active
    );
    assert_eq!(
        snapshot.mutation_state,
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle
    );
}

#[tokio::test]
async fn apply_evpn_runtime_ethernet_segment_add_commits_after_convergence() {
    // Start with one committed ES over VNI 100 (so the segment actor
    // spawns), then add a second ES over VNI 200 — the single
    // supported ES mutation shape (one local ES per VNI).
    let current = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_responder(rib_rx, injects);

    let instances = Arc::new(current.instances().clone());
    let segment_handle = evpn_segment::spawn(
        &instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_l2vni_two_es_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    {
        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert_eq!(guard.model().ethernet_segments().len(), 2);
    }
    segment_handle.shutdown().await;
}

#[tokio::test]
async fn apply_evpn_runtime_ethernet_segment_delete_commits_after_convergence() {
    // Committed model has two ES; the candidate drops one → delete,
    // the segment actor owns the Type 1/4 drain for the removed ES.
    let current = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_responder(rib_rx, injects);

    let instances = Arc::new(current.instances().clone());
    let segment_handle = evpn_segment::spawn(
        &instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_l2vni_one_es_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    {
        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert_eq!(guard.model().ethernet_segments().len(), 1);
    }
    segment_handle.shutdown().await;
}

#[tokio::test]
async fn apply_evpn_runtime_ethernet_segment_redefine_commits_after_convergence() {
    // Committed model has one ES over VNI 100; the candidate redefines
    // that same ESI so it also covers VNI 200.
    let current = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_responder(rib_rx, injects);

    let instances = Arc::new(current.instances().clone());
    let segment_handle = evpn_segment::spawn(
        &instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_l2vni_redefined_es_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    {
        let guard = coordinator.lock().unwrap();
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert_eq!(guard.model().ethernet_segments().len(), 1);
        assert_eq!(guard.model().ethernet_segments()[0].member_vnis.len(), 2);
    }
    segment_handle.shutdown().await;
}

#[tokio::test]
async fn apply_evpn_runtime_l2vni_redefine_commits_after_convergence() {
    let coordinator = two_l2vni_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_l2vni_one_redefined_l2vni_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_instances.unwrap().redefined, vec!["100"]);

    let expected_rd =
        runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml())
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .unwrap()
            .rd;
    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 2);
    assert_eq!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .unwrap()
            .rd,
        expected_rd,
        "committed model should carry the redefined RD for VNI 100"
    );
}

#[tokio::test]
async fn apply_evpn_runtime_l2vni_redefine_es_member_commits_after_convergence() {
    let coordinator = two_l2vni_one_es_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_l2vni_one_es_redefined_member_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_instances.unwrap().redefined, vec!["100"]);

    let expected_rd =
        runtime_candidate_from_toml(two_l2vni_one_es_redefined_member_runtime_candidate_toml())
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .unwrap()
            .rd;
    let guard = coordinator.lock().unwrap();
    assert_eq!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .unwrap()
            .rd,
        expected_rd,
        "committed model should carry the redefined RD for ES-member VNI 100"
    );
    assert_eq!(guard.model().ethernet_segments().len(), 1);
    assert!(
        guard.model().ethernet_segments()[0]
            .member_vnis
            .contains(&rustbgpd_evpn::EvpnInstanceId::new(100).unwrap()),
        "ES membership should remain unchanged"
    );
}

#[test]
fn validate_single_l2vni_redefine_accepts_one_redefined_instance() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let redefined = validate_single_l2vni_redefine(&current, &candidate, &plan).unwrap();
    assert_eq!(redefined, rustbgpd_evpn::EvpnInstanceId::new(100).unwrap());
}

#[test]
fn validate_single_l2vni_redefine_accepts_es_member() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(two_l2vni_one_es_redefined_member_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let redefined = validate_single_l2vni_redefine(&current, &candidate, &plan).unwrap();
    assert_eq!(redefined, rustbgpd_evpn::EvpnInstanceId::new(100).unwrap());
}

#[test]
fn validate_single_l2vni_redefine_rejects_mixed_ip_vrf_change() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(two_l2vni_one_redefined_plus_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let error = validate_single_l2vni_redefine(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("IP-VRF changes are absent"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_single_l2vni_redefine_rejects_multiple_redefined() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_both_redefined_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let error = validate_single_l2vni_redefine(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("exactly one redefined L2VNI"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_single_ethernet_segment_add_accepts_committed_runtime_added_member_vni() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let added_esi = validate_single_ethernet_segment_add(&current, &candidate, &plan).unwrap();
    assert_eq!(
        added_esi,
        rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
    );
}

#[test]
fn validate_single_ethernet_segment_add_rejects_unknown_member_vni() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let member_vnis =
        std::collections::BTreeSet::from([rustbgpd_evpn::EvpnInstanceId::new(300).unwrap()]);

    let error =
        validate_ethernet_segment_member_vnis_present(esi, &member_vnis, current.instances())
            .unwrap_err();
    let message = error.message();
    assert!(
        message.contains("unknown member VNI 300"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_single_ethernet_segment_redefine_accepts_one_redefined_segment() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let redefined_esi =
        validate_single_ethernet_segment_redefine(&current, &candidate, &plan).unwrap();
    assert_eq!(
        redefined_esi,
        rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
}

#[test]
fn validate_single_ethernet_segment_redefine_accepts_committed_runtime_added_member_vni() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let redefined_esi =
        validate_single_ethernet_segment_redefine(&current, &candidate, &plan).unwrap();
    assert_eq!(
        redefined_esi,
        rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
}

#[test]
fn validate_single_ethernet_segment_delete_accepts_one_removed_segment() {
    let current = runtime_model_from_candidate_toml(two_l2vni_two_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let deleted_esi = validate_single_ethernet_segment_delete(&current, &candidate, &plan).unwrap();
    assert_eq!(
        deleted_esi,
        rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
    );
}

#[tokio::test]
async fn apply_evpn_runtime_convergence_failure_marks_runtime_failed() {
    let coordinator = empty_evpn_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::failed("RIB unavailable");

    let error = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: l2vni_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        GrpcEvpnRuntimeApplyError::FailedPrecondition(_)
    ));
    let snapshot = coordinator.lock().unwrap().snapshot();
    assert_eq!(snapshot.generation.as_u64(), 1);
    assert_eq!(
        snapshot.lifecycle,
        rustbgpd_evpn::EvpnRuntimeLifecycle::Degraded
    );
    assert_eq!(
        snapshot.mutation_state,
        rustbgpd_evpn::EvpnRuntimeMutationState::Failed
    );
}

#[tokio::test]
async fn runtime_actor_converger_l2vni_add_publishes_imet_and_actor_models() {
    let current = runtime_model_from_candidate_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_responder(rib_rx, injects.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    let added_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
    assert!(evpn_instances_rx.borrow().get(added_vni).is_some());
    assert!(
        ip_vrfs_rx
            .borrow()
            .referenced_l2vnis("tenant-blue")
            .is_some_and(|vnis| vnis.contains(&added_vni)),
        "dataplane IP-VRF model should learn that the runtime-added L2VNI is linked to tenant-blue"
    );
    assert!(
        injects
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. })),
        "L2VNI add should originate an IMET route before generation commit"
    );
    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_l2vni_add_updates_segment_instance_view() {
    let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
    let l2_candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    let l2_plan = current.plan_candidate(&l2_candidate);
    let current_after_l2 =
        runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let es_candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
    let es_plan = current_after_l2.plan_candidate(&es_candidate);
    let current_instances = Arc::new(current.instances().clone());

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(128);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws);

    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &l2_candidate, &l2_plan)
        .await
        .unwrap();
    converger
        .converge(&current_after_l2, &es_candidate, &es_plan)
        .await
        .unwrap();

    // The Ethernet Tag is pinned to 0 (RFC 7432 §6.1); the
    // runtime-added VNI's EAD-per-EVI is identified by its RD.
    let added_rd = current_after_l2
        .instances()
        .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
        .expect("VNI 200 present after the L2 add")
        .rd;
    let deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let observed = injects.lock().await.clone();
        if observed.iter().any(|key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                    rd,
                    ..
                } if *rd == added_rd
            )
        }) {
            break;
        }
        assert!(
            StdInstant::now() < deadline,
            "timed out waiting for EAD-per-EVI over runtime-added VNI; observed {observed:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    segment_handle.shutdown().await;
    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_additive_build_up_rejects_missing_originator() {
    let current = runtime_model_from_candidate_toml(
        es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml(),
    );
    let candidate = runtime_candidate_from_toml(two_tenant_additive_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances);
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: None,
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let error = converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap_err();
    let message = error.message();
    assert!(
        message.contains("Type 2 originator"),
        "unexpected error message: {message}"
    );
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_additive_build_up_rejects_missing_segment_actor() {
    let current = runtime_model_from_candidate_toml(l2vni_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    assert!(is_additive_build_up_plan(&plan));

    let current_instances = Arc::new(current.instances().clone());
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let error = converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap_err();
    let message = error.message();
    assert!(
        message.contains("segment actor"),
        "unexpected error message: {message}"
    );
    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[test]
fn additive_build_failure_escalates_when_rollback_fails() {
    let restored = additive_build_failure(true, "EVPN segment publish failed");
    assert_eq!(restored.message(), "EVPN segment publish failed");

    let stranded = additive_build_failure(false, "EVPN segment publish failed");
    assert!(stranded.message().contains("EVPN segment publish failed"));
    assert!(
        stranded
            .message()
            .contains("additive build-up rollback also failed"),
        "unexpected message: {}",
        stranded.message()
    );
    assert!(stranded.message().contains("repair/restart"));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "rollback proof wires dataplane, IMET, Type 5, and segment actors"
)]
async fn runtime_actor_converger_additive_build_up_rollback_restores_imet_and_models() {
    let current = runtime_model_from_candidate_toml(
        es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml(),
    );
    let candidate = runtime_candidate_from_toml(two_tenant_additive_runtime_candidate_toml());
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let candidate_instances = Arc::new(candidate.instances().clone());
    let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
    let candidate_segments = Arc::new(candidate.ethernet_segments().to_vec());
    let added_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
    let added_instance = candidate.instances().get(added_vni).unwrap().clone();
    let added_rd = added_instance.rd;
    let added_esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let type5_id = rustbgpd_evpn::IpVrfId::new(6000).unwrap();
    let expected_overlay_rd = candidate.ip_vrfs().get("tenant-green").unwrap().rd;

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(128);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs.clone());
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(8);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };

    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");

    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let (obs_tx, obs_rx) = watch::channel(Arc::new(std::collections::HashMap::<
        rustbgpd_evpn::IpVrfId,
        Vec<rustbgpd_evpn::ip_vrf::LocalIpRouteObservation>,
    >::new()));
    let (status_tx, status_rx) = watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());
    let l3_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
        ip_vrfs: current_ip_vrfs,
        rib_tx: rib_tx.clone(),
        route_observations_rx: obs_rx,
        ip_vrf_status_rx: status_rx,
        metrics: BgpMetrics::new(),
        originated_counts: evpn_l3_originator::OriginatedIpVrfRouteCounts::default(),
        shutdown: tokio_util::sync::CancellationToken::new(),
    })
    .expect("Type 5 originator should spawn for a non-empty current IP-VRF table");
    status_tx.send_replace(vec![runtime_ip_vrf_ready_status(type5_id, "tenant-green")]);
    let mut observations = std::collections::HashMap::new();
    observations.insert(type5_id, vec![runtime_local_ip_observation(type5_id)]);
    obs_tx.send_replace(Arc::new(observations));

    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let _ = imet_controller
        .originate_instance(added_instance.clone(), &rib_tx)
        .await;
    let imet_controller = Arc::new(tokio::sync::Mutex::new(imet_controller));
    let dataplane = dataplane_handle.runtime_control();
    let segment = segment_handle.runtime_control();
    let originator = originator_handle.runtime_control();
    let l3 = l3_handle.runtime_control();
    assert!(dataplane.replace_ip_vrfs(candidate_ip_vrfs.clone()));
    assert!(dataplane.replace_evpn_instances(candidate_instances.clone()));
    assert!(originator.replace_runtime_model(
        candidate_instances.clone(),
        evpn_vni_to_esi_map(candidate.ethernet_segments()),
        Arc::new(std::collections::BTreeSet::new()),
    ));
    assert!(segment.replace_instances(candidate_instances));
    assert!(segment.replace_segments(candidate_segments));
    assert!(l3.replace_ip_vrfs(candidate_ip_vrfs));

    wait_for_recorded_evpn_key_matching(
        &injects,
        "mid-build state should have originated added IMET",
        |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd),
    )
    .await;
    wait_for_recorded_evpn_key_matching(
        &injects,
        "mid-build state should have originated added ES",
        |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == added_esi),
    )
    .await;
    wait_for_recorded_evpn_key_matching(
            &injects,
            "mid-build state should have originated tenant-green Type 5",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::IpPrefix { rd, .. } if *rd == expected_overlay_rd),
        )
        .await;

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller,
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: Some(l3_handle.runtime_control()),
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let restored = converger
        .rollback_additive_build_up(&current, &[added_instance])
        .await;
    assert!(restored, "rollback should restore all touched state");
    assert!(evpn_instances_rx.borrow().get(added_vni).is_none());
    assert!(
        !ip_vrfs_rx.borrow().is_referenced("tenant-green"),
        "rollback should restore the committed IP-VRF reference map"
    );
    wait_for_recorded_evpn_key_matching(
        &withdraws,
        "rollback should withdraw added IMET",
        |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd),
    )
    .await;
    wait_for_recorded_evpn_key_matching(
        &withdraws,
        "rollback should withdraw added ES state",
        |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == added_esi),
    )
    .await;
    wait_for_recorded_evpn_key_matching(
            &withdraws,
            "rollback should withdraw tenant-green Type 5 state",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::IpPrefix { rd, .. } if *rd == expected_overlay_rd),
        )
        .await;

    l3_handle.shutdown().await;
    segment_handle.shutdown().await;
    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "wires every EVPN runtime actor to prove cross-domain additive convergence"
)]
async fn runtime_actor_converger_additive_build_up_publishes_all_actor_models() {
    let current = runtime_model_from_candidate_toml(
        es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml(),
    );
    let candidate = runtime_candidate_from_toml(two_tenant_additive_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    assert!(is_additive_build_up_plan(&plan));

    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let added_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
    let added_esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let added_rd = candidate.instances().get(added_vni).unwrap().rd;
    let expected_overlay_rd = candidate.ip_vrfs().get("tenant-green").unwrap().rd;

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(128);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws);

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs.clone());
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(8);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };

    let (local_tx, local_rx) = mpsc::channel(16);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");

    let (svi_report_tx, svi_report_rx) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(8);
    let svi_handle = evpn_svi::spawn(
        &current_instances,
        rib_tx.clone(),
        svi_report_rx,
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("SVI actor should spawn when a committed instance advertises its SVI MAC");

    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let (obs_tx, obs_rx) = watch::channel(Arc::new(std::collections::HashMap::<
        rustbgpd_evpn::IpVrfId,
        Vec<rustbgpd_evpn::ip_vrf::LocalIpRouteObservation>,
    >::new()));
    let (status_tx, status_rx) = watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());
    let l3_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
        ip_vrfs: current_ip_vrfs,
        rib_tx: rib_tx.clone(),
        route_observations_rx: obs_rx,
        ip_vrf_status_rx: status_rx,
        metrics: BgpMetrics::new(),
        originated_counts: evpn_l3_originator::OriginatedIpVrfRouteCounts::default(),
        shutdown: tokio_util::sync::CancellationToken::new(),
    })
    .expect("Type 5 originator should spawn for a non-empty current IP-VRF table");
    let type5_id = rustbgpd_evpn::IpVrfId::new(6000).unwrap();
    status_tx.send_replace(vec![runtime_ip_vrf_ready_status(type5_id, "tenant-green")]);
    let mut observations = std::collections::HashMap::new();
    observations.insert(type5_id, vec![runtime_local_ip_observation(type5_id)]);
    obs_tx.send_replace(Arc::new(observations));

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: Some(svi_handle.runtime_control()),
        l3_originator: Some(l3_handle.runtime_control()),
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert!(evpn_instances_rx.borrow().get(added_vni).is_some());
    assert!(
        ip_vrfs_rx
            .borrow()
            .referenced_l2vnis("tenant-green")
            .is_some_and(|vnis| vnis.contains(&added_vni)),
        "dataplane IP-VRF model should learn the new tenant-green link"
    );

    wait_for_recorded_evpn_key_matching(
        &injects,
        "additive build-up should originate IMET for the added L2VNI",
        |key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::Imet {
                    rd,
                    ..
                } if *rd == added_rd
            )
        },
    )
    .await;
    wait_for_recorded_evpn_key_matching(
            &injects,
            "additive build-up should publish tenant-green Type 5 state",
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::IpPrefix { rd, .. } if *rd == expected_overlay_rd),
        )
        .await;
    wait_for_recorded_evpn_key_matching(
        &injects,
        "additive build-up should publish the added Ethernet Segment",
        |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == added_esi),
    )
    .await;
    wait_for_recorded_evpn_key_matching(
        &injects,
        "additive build-up should publish EAD-per-EVI for the added member VNI",
        // Ethernet Tag is pinned to 0 (RFC 7432 §6.1); the added
        // member VNI's EAD-per-EVI is identified by its RD.
        |key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                    esi,
                    rd,
                    ..
                } if *esi == added_esi && *rd == added_rd
            )
        },
    )
    .await;

    let local_mac = rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xab]);
    let local_mac_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        local_tx
            .send(rustbgpd_evpn::LocalMacObservation::Learned {
                vni: added_vni,
                mac: local_mac,
                ifindex: 20,
            })
            .await
            .unwrap();
        if injects.lock().await.iter().any(|key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::MacIp {
                    rd,
                    mac,
                    ..
                } if *rd == added_rd && *mac == local_mac
            )
        }) {
            break;
        }
        assert!(
            StdInstant::now() < local_mac_deadline,
            "Type 2 originator did not accept the added L2VNI"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let svi_mac = rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xcd]);
    let svi_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let _ = svi_report_tx.send(svi_dataplane_report(200, svi_mac));
        if injects.lock().await.iter().any(|key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::MacIp {
                    rd,
                    mac,
                    ..
                } if *rd == added_rd && *mac == svi_mac
            )
        }) {
            break;
        }
        assert!(
            StdInstant::now() < svi_deadline,
            "SVI actor did not accept the added L2VNI"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    l3_handle.shutdown().await;
    svi_handle.shutdown().await;
    segment_handle.shutdown().await;
    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "full dataplane-handle + segment-actor wiring per the sibling converger proofs"
)]
async fn runtime_actor_converger_additive_existing_es_member_expansion_publishes_models() {
    let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    assert!(is_additive_build_up_plan(&plan));
    let current_instances = Arc::new(current.instances().clone());
    let added_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
    let added_rd = candidate.instances().get(added_vni).unwrap().rd;
    let expanded_esi =
        rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(128);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws);

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (local_tx, local_rx) = mpsc::channel(8);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert!(evpn_instances_rx.borrow().get(added_vni).is_some());
    wait_for_recorded_evpn_key_matching(
        &injects,
        "additive ES member expansion should originate IMET for the added L2VNI",
        |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd),
    )
    .await;
    wait_for_recorded_evpn_key_matching(
        &injects,
        "additive ES member expansion should publish EAD-per-EVI for the added member",
        |key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                    esi,
                    rd,
                    ..
                } if *esi == expanded_esi && *rd == added_rd
            )
        },
    )
    .await;

    let local_mac = rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xee]);
    local_tx
        .send(rustbgpd_evpn::LocalMacObservation::Learned {
            vni: added_vni,
            mac: local_mac,
            ifindex: 20,
        })
        .await
        .unwrap();
    wait_for_recorded_evpn_key_matching(
        &injects,
        "Type 2 originator should accept local MACs on the newly ES-membered L2VNI",
        |key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::MacIp {
                    rd,
                    mac,
                    ..
                } if *rd == added_rd && *mac == local_mac
            )
        },
    )
    .await;

    segment_handle.shutdown().await;
    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "actor convergence regression sets up dataplane, IMET, and Type 2 controls end to end"
)]
async fn runtime_actor_converger_l2vni_delete_drains_imet_and_actor_models() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(l2vni_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (local_tx, local_rx) = mpsc::channel(8);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let imet_keys = imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;
    assert_eq!(imet_keys.len(), 2);

    // Prove the originator has live local state on the deleted VNI,
    // so the delete convergence has a Type 2 drain to perform.
    local_tx
        .send(rustbgpd_evpn::LocalMacObservation::Learned {
            vni: deleted_vni,
            mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xcc]),
            ifindex: 20,
        })
        .await
        .unwrap();
    let mac_inject_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if injects
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < mac_inject_deadline,
            "originator did not originate the VNI 200 local MAC"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert!(evpn_instances_rx.borrow().get(deleted_vni).is_none());
    assert!(
        withdraws
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. })),
        "L2VNI delete should withdraw the removed VNI's IMET route before generation commit"
    );

    let mac_withdraw_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if withdraws
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < mac_withdraw_deadline,
            "L2VNI delete did not drain the removed VNI's local MAC"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_l2vni_swap_updates_models_and_imet() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(l2vni_swap_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let added_vni = rustbgpd_evpn::EvpnInstanceId::new(300).unwrap();
    let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
    let added_rd = candidate.instances().get(added_vni).unwrap().rd;
    let deleted_rd = current.instances().get(deleted_vni).unwrap().rd;

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let imet_keys = imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;
    assert_eq!(imet_keys.len(), 2);

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert!(evpn_instances_rx.borrow().get(added_vni).is_some());
    assert!(evpn_instances_rx.borrow().get(deleted_vni).is_none());

    let drained = withdraws.lock().await.clone();
    let injected = injects.lock().await.clone();
    assert!(
        drained.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == deleted_rd
        )),
        "swap should withdraw the deleted L2VNI's IMET route; drained {drained:?}"
    );
    assert!(
        injected.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd
        )),
        "swap should originate the added L2VNI's IMET route; injected {injected:?}"
    );

    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_l2vni_swap_publishes_ip_vrf_metadata() {
    let current =
        runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(l2vni_swap_linked_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let added_vni = rustbgpd_evpn::EvpnInstanceId::new(300).unwrap();
    let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
    let added_rd = candidate.instances().get(added_vni).unwrap().rd;
    let deleted_rd = current.instances().get(deleted_vni).unwrap().rd;

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let imet_keys = imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;
    assert_eq!(imet_keys.len(), 2);

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert!(evpn_instances_rx.borrow().get(added_vni).is_some());
    assert!(evpn_instances_rx.borrow().get(deleted_vni).is_none());
    assert!(
        ip_vrfs_rx
            .borrow()
            .referenced_l2vnis("tenant-blue")
            .is_some_and(|vnis| {
                vnis == &std::collections::BTreeSet::from([
                    rustbgpd_evpn::EvpnInstanceId::new(100).unwrap(),
                    added_vni,
                ])
            }),
        "dataplane IP-VRF model should reference the added L2VNI and drop the deleted L2VNI"
    );

    let drained = withdraws.lock().await.clone();
    let injected = injects.lock().await.clone();
    assert!(
        drained.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == deleted_rd
        )),
        "linked swap should withdraw the deleted L2VNI's IMET route; drained {drained:?}"
    );
    assert!(
        injected.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd
        )),
        "linked swap should originate the added L2VNI's IMET route; injected {injected:?}"
    );

    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "wires real dataplane/originator/IMET controls for the mixed L2VNI composer"
)]
async fn runtime_actor_converger_l2vni_mixed_redefine_swap_updates_models_and_imet() {
    let current =
        runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(l2vni_mixed_redefine_linked_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let redefined_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
    let added_vni = rustbgpd_evpn::EvpnInstanceId::new(300).unwrap();
    let old_redefined_rd = current.instances().get(redefined_vni).unwrap().rd;
    let deleted_rd = current.instances().get(deleted_vni).unwrap().rd;
    let new_redefined_rd = candidate.instances().get(redefined_vni).unwrap().rd;
    let added_rd = candidate.instances().get(added_vni).unwrap().rd;

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let imet_keys = imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;
    assert_eq!(imet_keys.len(), 2);

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert_eq!(
        evpn_instances_rx
            .borrow()
            .get(redefined_vni)
            .expect("redefined VNI should remain present")
            .rd,
        new_redefined_rd
    );
    assert!(evpn_instances_rx.borrow().get(added_vni).is_some());
    assert!(evpn_instances_rx.borrow().get(deleted_vni).is_none());
    assert!(
        ip_vrfs_rx
            .borrow()
            .referenced_l2vnis("tenant-blue")
            .is_some_and(|vnis| {
                vnis == &std::collections::BTreeSet::from([redefined_vni, added_vni])
            }),
        "mixed composer should keep the redefined VNI linked and replace the deleted link with the added link"
    );

    let drained = withdraws.lock().await.clone();
    let injected = injects.lock().await.clone();
    assert!(
        drained.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == old_redefined_rd
        )),
        "mixed composer should withdraw the old-RD redefined IMET route; drained {drained:?}"
    );
    assert!(
        drained.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == deleted_rd
        )),
        "mixed composer should withdraw the deleted L2VNI's IMET route; drained {drained:?}"
    );
    assert!(
        injected.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == new_redefined_rd
        )),
        "mixed composer should originate the new-RD redefined IMET route; injected {injected:?}"
    );
    assert!(
        injected.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd
        )),
        "mixed composer should originate the added L2VNI's IMET route; injected {injected:?}"
    );

    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_l2vni_batch_redefine_updates_models_and_imet() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_both_redefined_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let vni100 = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    let vni200 = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
    let old_rd100 = current.instances().get(vni100).unwrap().rd;
    let old_rd200 = current.instances().get(vni200).unwrap().rd;
    let new_rd100 = candidate.instances().get(vni100).unwrap().rd;
    let new_rd200 = candidate.instances().get(vni200).unwrap().rd;

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let imet_keys = imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;
    assert_eq!(imet_keys.len(), 2);

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    let published = evpn_instances_rx.borrow();
    assert_eq!(published.get(vni100).expect("VNI 100").rd, new_rd100);
    assert_eq!(published.get(vni200).expect("VNI 200").rd, new_rd200);
    drop(published);

    let drained = withdraws.lock().await.clone();
    let injected = injects.lock().await.clone();
    for rd in [old_rd100, old_rd200] {
        assert!(
            drained.iter().any(|key| matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::Imet { rd: seen, .. } if *seen == rd
            )),
            "batch redefine should withdraw old-RD IMET {rd}; drained {drained:?}"
        );
    }
    for rd in [new_rd100, new_rd200] {
        assert!(
            injected.iter().any(|key| matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::Imet { rd: seen, .. } if *seen == rd
            )),
            "batch redefine should originate new-RD IMET {rd}; injected {injected:?}"
        );
    }

    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_l2vni_mixed_redefine_withdraw_failure_rolls_back_without_deadlock()
{
    // Regression: the redefine withdraw-failure path used to call
    // rollback_l2vni_mixed while still holding the imet_controller guard.
    // rollback re-locks the (non-reentrant) Mutex, so the converge task
    // deadlocked. Drive a mixed compose (add 300 + redefine 100 + delete
    // 200) where the redefined VNI's old-RD IMET withdraw is rejected while
    // an added VNI is already originated, and assert converge RETURNS an
    // error within a bound rather than hanging.
    let current =
        runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(l2vni_mixed_redefine_linked_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let redefined_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    let old_redefined_rd = current.instances().get(redefined_vni).unwrap().rd;

    // RIB responder: accept injects and all withdraws EXCEPT the redefined
    // VNI's committed old-RD IMET, whose withdraw is rejected to force the
    // redefine rollback leg (with an already-originated added VNI present).
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let _rib = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::InjectEvpn { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::WithdrawEvpn { key, reply } => {
                    let reject = matches!(
                        key,
                        rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if rd == old_redefined_rd
                    );
                    let _ = reply.send(if reject {
                        Err(RibCommandError::internal("withdraw rejected"))
                    } else {
                        Ok(())
                    });
                }
                _ => {}
            }
        }
    });

    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let _ = imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        converger.converge(&current, &candidate, &plan),
    )
    .await
    .expect("converge must return rather than deadlock on the redefine rollback leg");
    assert!(
        result.is_err(),
        "a rejected redefine IMET withdraw must surface as a converge error"
    );

    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "wires the dataplane/originator/IMET actors to prove swap rollback restoration"
)]
async fn runtime_actor_converger_l2vni_swap_rollback_restores_imet_and_models() {
    // Drive the mixed L2VNI forward legs up to the rollback point (added
    // IMET originated, redefined IMET re-keyed, candidate models
    // published, deleted IMET withdrawn), then call rollback directly and
    // prove it restores the committed model and unwinds all speculative
    // IMET state.
    let current =
        runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(l2vni_mixed_redefine_linked_ip_vrf_runtime_candidate_toml());
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let candidate_instances = Arc::new(candidate.instances().clone());
    let candidate_ip_vrfs = Arc::new(candidate.ip_vrfs().clone());
    let redefined_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    let added_vni = rustbgpd_evpn::EvpnInstanceId::new(300).unwrap();
    let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(200).unwrap();
    let old_redefined_instance = current.instances().get(redefined_vni).unwrap().clone();
    let new_redefined_instance = candidate.instances().get(redefined_vni).unwrap().clone();
    let added_instance = candidate.instances().get(added_vni).unwrap().clone();
    let deleted_instance = current.instances().get(deleted_vni).unwrap().clone();
    let old_redefined_rd = old_redefined_instance.rd;
    let new_redefined_rd = new_redefined_instance.rd;
    let added_rd = added_instance.rd;
    let deleted_rd = deleted_instance.rd;

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");

    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let imet_keys = imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;
    assert_eq!(imet_keys.len(), 2);
    // Forward leg 1: originate the added L2VNI's IMET.
    let _ = imet_controller
        .originate_instance(added_instance.clone(), &rib_tx)
        .await;
    // Forward leg 1b: re-key the redefined L2VNI's IMET.
    let _ = imet_controller
        .withdraw_instance(redefined_vni, &rib_tx)
        .await;
    let _ = imet_controller
        .originate_instance(new_redefined_instance, &rib_tx)
        .await;
    let imet_controller = Arc::new(tokio::sync::Mutex::new(imet_controller));

    // Forward leg 2: publish the candidate models to dataplane + originator.
    let dataplane = dataplane_handle.runtime_control();
    let originator = originator_handle.runtime_control();
    assert!(dataplane.replace_ip_vrfs(candidate_ip_vrfs));
    assert!(dataplane.replace_evpn_instances(candidate_instances.clone()));
    assert!(originator.replace_runtime_model(
        candidate_instances.clone(),
        evpn_vni_to_esi_map(candidate.ethernet_segments()),
        Arc::new(std::collections::BTreeSet::new()),
    ));
    // Forward leg 3: withdraw the deleted L2VNI's IMET.
    let _ = imet_controller
        .lock()
        .await
        .withdraw_instance(deleted_vni, &rib_tx)
        .await;

    // The forward legs above are all awaited (the recorder pushes before
    // replying), so the mid-swap RIB effects are fully recorded. Clear so
    // the rollback's effects are unambiguous.
    injects.lock().await.clear();
    withdraws.lock().await.clear();

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller,
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let restored = converger
        .rollback_l2vni_mixed(
            &current,
            &[added_instance],
            &[deleted_instance],
            &[old_redefined_instance],
            true,
        )
        .await;
    assert!(restored, "swap rollback should restore all touched state");

    // Committed L2/IP-VRF models restored: the deleted VNI is back, the
    // added VNI is gone, the redefined VNI has its old row, and the tenant
    // binding points back at the committed VNI set.
    assert!(
        evpn_instances_rx.borrow().get(deleted_vni).is_some(),
        "rollback should restore the deleted L2VNI to the committed model"
    );
    assert!(
        evpn_instances_rx.borrow().get(added_vni).is_none(),
        "rollback should drop the speculatively-added L2VNI"
    );
    assert_eq!(
        evpn_instances_rx
            .borrow()
            .get(redefined_vni)
            .expect("rollback should retain the redefined L2VNI")
            .rd,
        old_redefined_rd,
        "rollback should restore the redefined L2VNI's committed row"
    );
    assert!(
        ip_vrfs_rx
            .borrow()
            .referenced_l2vnis("tenant-blue")
            .is_some_and(|vnis| {
                vnis == &std::collections::BTreeSet::from([
                    rustbgpd_evpn::EvpnInstanceId::new(100).unwrap(),
                    deleted_vni,
                ])
            }),
        "rollback should restore committed IP-VRF link metadata"
    );

    // Speculative added IMET withdrawn; deleted IMET re-originated.
    wait_for_recorded_evpn_key_matching(
        &withdraws,
        "rollback should withdraw the speculatively-added L2VNI IMET",
        |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == added_rd),
    )
    .await;
    wait_for_recorded_evpn_key_matching(
        &injects,
        "rollback should restore the deleted L2VNI IMET",
        |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == deleted_rd),
    )
    .await;
    wait_for_recorded_evpn_key_matching(
            &withdraws,
            "rollback should withdraw the redefined L2VNI's speculative new-RD IMET",
            |key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == new_redefined_rd)
            },
        )
        .await;
    wait_for_recorded_evpn_key_matching(
            &injects,
            "rollback should restore the redefined L2VNI's committed old-RD IMET",
            |key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == old_redefined_rd)
            },
        )
        .await;

    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_l2vni_delete_publishes_ip_vrf_metadata() {
    let current = runtime_model_from_candidate_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let imet_keys = imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;
    assert_eq!(imet_keys.len(), 1);

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert!(evpn_instances_rx.borrow().get(deleted_vni).is_none());
    assert!(
        !ip_vrfs_rx.borrow().is_referenced("tenant-blue"),
        "dataplane IP-VRF model should drop the deleted L2VNI's tenant binding"
    );
    assert!(
        withdraws
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. })),
        "IP-VRF-linked L2VNI delete should still withdraw the removed VNI's IMET route"
    );

    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[test]
fn validate_single_l2vni_delete_allows_unlinked_ip_vrf_table() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(l2vni_one_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let deleted = validate_single_l2vni_delete(&current, &candidate, &plan).unwrap();
    assert_eq!(deleted.id, rustbgpd_evpn::EvpnInstanceId::new(200).unwrap());
}

#[test]
fn validate_single_l2vni_delete_allows_ip_vrf_link_metadata_update() {
    let current = runtime_model_from_candidate_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert!(
        !plan.ip_vrfs.has_changes(),
        "IP-VRF row changes should stay fail-closed; this case only changes link metadata"
    );
    assert_ne!(current.ip_vrfs(), candidate.ip_vrfs());
    let deleted = validate_single_l2vni_delete(&current, &candidate, &plan).unwrap();
    assert_eq!(deleted.id, rustbgpd_evpn::EvpnInstanceId::new(100).unwrap());
}

#[test]
fn validate_single_l2vni_delete_allows_remaining_ip_vrf_link_metadata() {
    let current =
        runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(l2vni_linked_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    let deleted = validate_single_l2vni_delete(&current, &candidate, &plan).unwrap();
    assert_eq!(deleted.id, rustbgpd_evpn::EvpnInstanceId::new(200).unwrap());
    assert!(
        candidate
            .ip_vrfs()
            .referenced_l2vnis("tenant-blue")
            .is_some_and(|vnis| {
                vnis == &std::collections::BTreeSet::from([
                    rustbgpd_evpn::EvpnInstanceId::new(100).unwrap()
                ])
            })
    );
}

#[test]
fn validate_l2vni_swap_accepts_standalone_add_delete() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(l2vni_swap_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert!(is_l2vni_swap_plan(&plan));
    let (added, deleted) = validate_l2vni_swap(&current, &candidate, &plan).unwrap();
    assert_eq!(
        added
            .iter()
            .map(|instance| instance.id.as_u32())
            .collect::<Vec<_>>(),
        vec![300]
    );
    assert_eq!(
        deleted
            .iter()
            .map(|instance| instance.id.as_u32())
            .collect::<Vec<_>>(),
        vec![200]
    );
}

#[test]
fn validate_l2vni_swap_accepts_ip_vrf_link_metadata_change_for_swapped_vnis() {
    let current =
        runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(l2vni_swap_linked_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert!(is_l2vni_swap_plan(&plan));
    assert!(
        !plan.ip_vrfs.has_changes(),
        "IP-VRF row diffing intentionally ignores link metadata"
    );
    assert_ne!(current.ip_vrfs(), candidate.ip_vrfs());
    let (added, deleted) = validate_l2vni_swap(&current, &candidate, &plan).unwrap();
    assert_eq!(
        added
            .iter()
            .map(|instance| instance.id.as_u32())
            .collect::<Vec<_>>(),
        vec![300]
    );
    assert_eq!(
        deleted
            .iter()
            .map(|instance| instance.id.as_u32())
            .collect::<Vec<_>>(),
        vec![200]
    );
}

#[test]
fn validate_l2vni_mixed_accepts_redefine_swap_with_link_metadata() {
    let current =
        runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(l2vni_mixed_redefine_linked_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.added, vec![300]);
    assert_eq!(plan.evpn_instances.deleted, vec![200]);
    assert_eq!(plan.evpn_instances.redefined, vec![100]);
    assert!(is_l2vni_mixed_plan(&plan));
    assert!(
        !plan.ip_vrfs.has_changes(),
        "IP-VRF row diffing intentionally ignores link metadata"
    );
    assert_ne!(current.ip_vrfs(), candidate.ip_vrfs());

    let changes = validate_l2vni_mixed(&current, &candidate, &plan).unwrap();
    let redefined_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    assert_eq!(
        changes
            .added
            .iter()
            .map(|instance| instance.id.as_u32())
            .collect::<Vec<_>>(),
        vec![300]
    );
    assert_eq!(
        changes
            .deleted
            .iter()
            .map(|instance| instance.id.as_u32())
            .collect::<Vec<_>>(),
        vec![200]
    );
    assert_eq!(
        changes
            .redefined
            .iter()
            .map(|(old, new)| (old.id.as_u32(), old.rd, new.rd))
            .collect::<Vec<_>>(),
        vec![(
            100,
            current.instances().get(redefined_vni).unwrap().rd,
            candidate.instances().get(redefined_vni).unwrap().rd
        )]
    );
}

#[test]
fn validate_l2vni_mixed_accepts_batch_redefine_only() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_both_redefined_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.redefined, vec![100, 200]);
    assert!(plan.evpn_instances.added.is_empty());
    assert!(plan.evpn_instances.deleted.is_empty());
    assert!(is_l2vni_mixed_plan(&plan));

    let changes = validate_l2vni_mixed(&current, &candidate, &plan).unwrap();
    assert!(changes.added.is_empty());
    assert!(changes.deleted.is_empty());
    assert_eq!(
        changes
            .redefined
            .iter()
            .map(|(old, new)| (old.id.as_u32(), old.rd, new.rd))
            .collect::<Vec<_>>(),
        vec![
            (
                100,
                current
                    .instances()
                    .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                    .unwrap()
                    .rd,
                candidate
                    .instances()
                    .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                    .unwrap()
                    .rd
            ),
            (
                200,
                current
                    .instances()
                    .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
                    .unwrap()
                    .rd,
                candidate
                    .instances()
                    .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
                    .unwrap()
                    .rd
            )
        ]
    );
}

#[test]
fn validate_l2vni_mixed_rejects_redefined_vni_relink() {
    let current =
        runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(l2vni_mixed_redefine_relink_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.added, vec![300]);
    assert_eq!(plan.evpn_instances.deleted, vec![200]);
    assert_eq!(plan.evpn_instances.redefined, vec![100]);
    assert!(is_l2vni_mixed_plan(&plan));
    let error = validate_l2vni_mixed(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("L2VNI 100 `ip_vrf` link change"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_l2vni_mixed_rejects_es_member_delete() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let base_candidate =
        runtime_candidate_from_toml(l2vni_mixed_redefine_delete_vni100_runtime_candidate_toml());
    let candidate = rustbgpd_evpn::EvpnRuntimeCandidate::new(
        base_candidate.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    );
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.added, vec![300]);
    assert_eq!(plan.evpn_instances.deleted, vec![100]);
    assert_eq!(plan.evpn_instances.redefined, vec![200]);
    assert!(is_l2vni_mixed_plan(&plan));
    let error = validate_l2vni_mixed(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("Ethernet Segment member"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_l2vni_swap_rejects_es_member_delete() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let base_candidate =
        runtime_candidate_from_toml(l2vni_swap_delete_vni100_runtime_candidate_toml());
    let candidate = rustbgpd_evpn::EvpnRuntimeCandidate::new(
        base_candidate.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    );
    let plan = current.plan_candidate(&candidate);

    assert!(is_l2vni_swap_plan(&plan));
    let error = validate_l2vni_swap(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("Ethernet Segment member"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_single_l2vni_delete_rejects_mixed_ip_vrf_link_metadata_update() {
    let current =
        runtime_model_from_candidate_toml(two_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(l2vni_one_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.deleted, vec![200]);
    assert!(
        !plan.ip_vrfs.has_changes(),
        "IP-VRF row diffing intentionally ignores link metadata"
    );
    let error = validate_single_l2vni_delete(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("candidate IP-VRF link metadata for \"tenant-blue\""),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_tenant_teardown_accepts_full_tenant() {
    let current =
        runtime_model_from_candidate_toml(es_member_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(minimal_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    // A tenant teardown spans all three resource types in one delete-only plan.
    assert_eq!(plan.evpn_instances.deleted, vec![100]);
    assert_eq!(plan.ip_vrfs.deleted, vec!["tenant-blue".to_string()]);
    assert_eq!(plan.ethernet_segments.deleted.len(), 1);
    assert!(plan.evpn_instances.added.is_empty());
    assert!(is_tenant_teardown_plan(&plan, &current));

    let deleted = validate_tenant_teardown(&current, &candidate, &plan).unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(
        deleted[0].id,
        rustbgpd_evpn::EvpnInstanceId::new(100).unwrap()
    );
}

#[test]
fn validate_tenant_teardown_accepts_es_member_shrink() {
    // VNI 200 leaves; the ES it shared with VNI 100 shrinks its member set
    // to [100] in the same request (a member-shrink redefine, not a delete).
    let current =
        runtime_model_from_candidate_toml(two_l2vni_redefined_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(l2vni_one_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.deleted, vec![200]);
    assert_eq!(plan.ethernet_segments.redefined.len(), 1);
    assert!(plan.ethernet_segments.deleted.is_empty());
    assert!(is_tenant_teardown_plan(&plan, &current));

    let deleted = validate_tenant_teardown(&current, &candidate, &plan).unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(
        deleted[0].id,
        rustbgpd_evpn::EvpnInstanceId::new(200).unwrap()
    );
}

#[test]
fn validate_tenant_teardown_rejects_add() {
    let current = runtime_model_from_candidate_toml(l2vni_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.added, vec![200]);
    let error = validate_tenant_teardown(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("does not support adds"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_tenant_teardown_rejects_l2vni_redefine() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.redefined, vec![100]);
    let error = validate_tenant_teardown(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("does not support L2VNI redefine"),
        "unexpected error message: {message}"
    );
}

#[test]
fn m47_interop_configs_describe_a_tenant_teardown() {
    // Pin the M47 interop fixtures: the booted PE config and the gRPC
    // teardown candidate must parse through the real config loader and
    // diff to an atomic tenant teardown (L2VNI 100 + its Ethernet
    // Segment). Guards the smoke against drift in either the configs or
    // the teardown classifier.
    let current = pre_authorized_runtime_model_from_toml(&materialize_shared_test_only_grpc_token(
        include_str!("../../tests/interop/configs/rustbgpd-m47-pe1.toml"),
    ));
    let candidate =
        pre_authorized_runtime_candidate_from_toml(&materialize_shared_test_only_grpc_token(
            include_str!("../../tests/interop/configs/rustbgpd-m47-teardown.toml"),
        ));
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.deleted, vec![100]);
    assert_eq!(plan.ethernet_segments.deleted.len(), 1);
    assert!(is_tenant_teardown_plan(&plan, &current));

    let deleted = validate_tenant_teardown(&current, &candidate, &plan).unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(
        deleted[0].id,
        rustbgpd_evpn::EvpnInstanceId::new(100).unwrap()
    );
}

#[test]
fn m48_interop_configs_describe_a_linked_ip_vrf_teardown() {
    // Pin the M48 datapath interop fixtures: the booted PE config and the
    // gRPC teardown candidate must parse through the real config loader and
    // diff to an atomic tenant teardown of a linked L2VNI + IP-VRF (vrf1 is
    // referenced by L2VNI 10, so dropping both routes through the teardown
    // path rather than a standalone IP-VRF delete). Guards the smoke
    // against drift in either the configs or the teardown classifier.
    let current = pre_authorized_runtime_model_from_toml(&materialize_shared_test_only_grpc_token(
        include_str!("../../tests/interop/configs/rustbgpd-m48-pe1.toml"),
    ));
    let candidate =
        pre_authorized_runtime_candidate_from_toml(&materialize_shared_test_only_grpc_token(
            include_str!("../../tests/interop/configs/rustbgpd-m48-teardown.toml"),
        ));
    let plan = current.plan_candidate(&candidate);

    assert_eq!(plan.evpn_instances.deleted, vec![10]);
    assert_eq!(plan.ip_vrfs.deleted, vec!["vrf1".to_string()]);
    assert!(is_tenant_teardown_plan(&plan, &current));

    let deleted = validate_tenant_teardown(&current, &candidate, &plan).unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(
        deleted[0].id,
        rustbgpd_evpn::EvpnInstanceId::new(10).unwrap()
    );
}

#[test]
fn validate_additive_build_up_accepts_l2vni_ip_vrf_and_es() {
    let current = runtime_model_from_candidate_toml(
        es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml(),
    );
    let candidate = runtime_candidate_from_toml(two_tenant_additive_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert!(is_additive_build_up_plan(&plan));
    let added = validate_additive_build_up(&current, &candidate, &plan).unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(
        added[0].id,
        rustbgpd_evpn::EvpnInstanceId::new(200).unwrap()
    );
}

#[test]
fn validate_additive_build_up_accepts_existing_es_member_expansion() {
    let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert!(is_additive_build_up_plan(&plan));
    assert_eq!(plan.evpn_instances.added, vec![200]);
    assert_eq!(plan.ethernet_segments.redefined.len(), 1);
    let added = validate_additive_build_up(&current, &candidate, &plan).unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(
        added[0].id,
        rustbgpd_evpn::EvpnInstanceId::new(200).unwrap()
    );
}

#[test]
fn validate_additive_build_up_rejects_existing_es_member_expansion_field_change() {
    let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
    let valid = runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
    let mut bad_segment = valid.ethernet_segments()[0].clone();
    bad_segment.originator_ip = "10.0.0.2".parse().unwrap();
    let bad_candidate = rustbgpd_evpn::EvpnRuntimeCandidate::new(
        valid.instances().clone(),
        rustbgpd_evpn::IpVrfTable::new(),
        vec![bad_segment],
    );
    let plan = current.plan_candidate(&bad_candidate);

    assert!(is_additive_build_up_plan(&plan));
    let error = validate_additive_build_up(&current, &bad_candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("fields other than member_vnis"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_additive_build_up_rejects_existing_vni_es_member_expansion() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let bad_candidate = runtime_candidate_from_toml(
        three_l2vni_redefined_es_existing_member_runtime_candidate_toml(),
    );
    let plan = current.plan_candidate(&bad_candidate);

    assert!(is_additive_build_up_plan(&plan));
    assert_eq!(plan.evpn_instances.added, vec![300]);
    assert_eq!(plan.ethernet_segments.redefined.len(), 1);
    let error = validate_additive_build_up(&current, &bad_candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("newly planned L2VNIs"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_additive_build_up_rejects_add_with_redefine() {
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(two_l2vni_one_redefined_plus_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert!(!plan.ip_vrfs.added.is_empty());
    assert!(!plan.evpn_instances.redefined.is_empty());
    assert!(!is_additive_build_up_plan(&plan));
    let error = validate_additive_build_up(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("add-only changes")
            && message.contains("only existing-ES member expansion allowed as a redefine"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_additive_build_up_rejects_existing_l2vni_relink() {
    let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(relink_green_plus_l2vni_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);

    assert!(is_additive_build_up_plan(&plan));
    assert!(plan.ip_vrf_references_changed);
    let error = validate_additive_build_up(&current, &candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("L2VNI 100") && message.contains("relink"),
        "unexpected error message: {message}"
    );
}

#[test]
fn validate_additive_build_up_rejects_unknown_es_member() {
    let current = runtime_model_from_candidate_toml(minimal_runtime_candidate_toml());
    let valid = runtime_candidate_from_toml(l2vni_one_es_runtime_candidate_toml());
    let mut bad_segment = valid.ethernet_segments()[0].clone();
    bad_segment.member_vnis =
        std::collections::BTreeSet::from([rustbgpd_evpn::EvpnInstanceId::new(300).unwrap()]);
    let bad_candidate = rustbgpd_evpn::EvpnRuntimeCandidate::new(
        valid.instances().clone(),
        rustbgpd_evpn::IpVrfTable::new(),
        vec![bad_segment],
    );
    let plan = current.plan_candidate(&bad_candidate);

    assert!(is_additive_build_up_plan(&plan));
    let error = validate_additive_build_up(&current, &bad_candidate, &plan).unwrap_err();
    let message = error.message();
    assert!(
        message.contains("unknown member VNI 300"),
        "unexpected error message: {message}"
    );
}

#[tokio::test]
async fn apply_evpn_runtime_tenant_teardown_commits() {
    let current =
        runtime_candidate_from_toml(es_member_l2vni_linked_ip_vrf_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: minimal_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_instances.unwrap().deleted, vec!["100"]);
    assert_eq!(plan.evpn_ip_vrfs.unwrap().deleted, vec!["tenant-blue"]);
    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 2);
    assert!(guard.model().instances().is_empty());
    assert!(guard.model().ip_vrfs().get("tenant-blue").is_none());
    assert!(guard.model().ethernet_segments().is_empty());
}

#[tokio::test]
async fn apply_evpn_runtime_additive_build_up_commits() {
    let current =
        runtime_candidate_from_toml(es_member_l2vni_linked_ip_vrf_svi_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_tenant_additive_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_instances.unwrap().added, vec!["200"]);
    assert_eq!(plan.evpn_ip_vrfs.unwrap().added, vec!["tenant-green"]);
    assert_eq!(plan.ethernet_segments.unwrap().added.len(), 1);
    assert!(
        plan.ip_vrf_references_changed,
        "the added L2VNI links to the added IP-VRF"
    );

    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 2);
    assert!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
            .is_some()
    );
    assert!(guard.model().ip_vrfs().get("tenant-green").is_some());
    assert_eq!(guard.model().ethernet_segments().len(), 2);
}

#[tokio::test]
async fn apply_evpn_runtime_ip_vrf_relink_commits() {
    // The coordinator must commit a pure relink (not short-circuit to Noop):
    // the candidate edits no row, so this only works because the plan's
    // ip_vrf_references_changed signal makes is_noop() false.
    let current = runtime_candidate_from_toml(relink_blue_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: relink_green_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert_eq!(response.runtime.unwrap().generation, 2);
    let plan = response.plan.unwrap();
    assert!(
        plan.ip_vrf_references_changed,
        "the plan summary must surface the relink so it doesn't read as empty/COMMITTED"
    );
    assert!(plan.evpn_instances.unwrap().redefined.is_empty());
    assert!(plan.evpn_ip_vrfs.unwrap().redefined.is_empty());
    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 2);
    let vni100 = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    assert!(
        guard
            .model()
            .ip_vrfs()
            .referenced_l2vnis("tenant-green")
            .is_some_and(|v| v.contains(&vni100))
    );
    assert!(!guard.model().ip_vrfs().is_referenced("tenant-blue"));
}

#[tokio::test]
async fn runtime_actor_converger_ip_vrf_add_publishes_dataplane_model() {
    let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(32);

    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances);
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs.clone());
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_obs_tx, obs_rx) = watch::channel(Arc::new(std::collections::HashMap::<
        rustbgpd_evpn::IpVrfId,
        Vec<rustbgpd_evpn::ip_vrf::LocalIpRouteObservation>,
    >::new()));
    let (_status_tx, status_rx) = watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());
    let l3_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
        ip_vrfs: current_ip_vrfs,
        rib_tx: rib_tx.clone(),
        route_observations_rx: obs_rx,
        ip_vrf_status_rx: status_rx,
        metrics: BgpMetrics::new(),
        originated_counts: evpn_l3_originator::OriginatedIpVrfRouteCounts::default(),
        shutdown: tokio_util::sync::CancellationToken::new(),
    })
    .expect("L3 originator should spawn for non-empty current model");
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: None,
        svi: None,
        l3_originator: Some(l3_handle.runtime_control()),
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert!(ip_vrfs_rx.borrow().get("tenant-green").is_some());
    l3_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_ip_vrf_relink_republishes_ip_vrfs() {
    // A relink is dataplane-only: republish the candidate IP-VRF table (now
    // carrying the moved link reference) to the dataplane watch. No IMET /
    // originator / SVI / segment / l3 work.
    let current = runtime_model_from_candidate_toml(relink_blue_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(relink_green_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let vni100 = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    assert!(
        current_ip_vrfs
            .referenced_l2vnis("tenant-blue")
            .is_some_and(|v| v.contains(&vni100)),
        "baseline links L2VNI 100 to tenant-blue"
    );

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances);
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: None,
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    let published = ip_vrfs_rx.borrow();
    assert!(
        published
            .referenced_l2vnis("tenant-green")
            .is_some_and(|v| v.contains(&vni100)),
        "relink republishes ip_vrfs with L2VNI 100 now referencing tenant-green"
    );
    assert!(
        !published.is_referenced("tenant-blue"),
        "tenant-blue should no longer be referenced after the relink"
    );
    drop(published);
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_ip_vrf_delete_publishes_dataplane_and_l3_model() {
    let current = runtime_model_from_candidate_toml(two_ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances);
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs.clone());
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (obs_tx, obs_rx) = watch::channel(Arc::new(std::collections::HashMap::<
        rustbgpd_evpn::IpVrfId,
        Vec<rustbgpd_evpn::ip_vrf::LocalIpRouteObservation>,
    >::new()));
    let (status_tx, status_rx) = watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());
    let l3_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
        ip_vrfs: current_ip_vrfs,
        rib_tx: rib_tx.clone(),
        route_observations_rx: obs_rx,
        ip_vrf_status_rx: status_rx,
        metrics: BgpMetrics::new(),
        originated_counts: evpn_l3_originator::OriginatedIpVrfRouteCounts::default(),
        shutdown: tokio_util::sync::CancellationToken::new(),
    })
    .expect("L3 originator should spawn for non-empty current model");
    let green_id = rustbgpd_evpn::IpVrfId::new(6000).unwrap();
    status_tx.send_replace(vec![runtime_ip_vrf_ready_status(green_id, "tenant-green")]);
    let mut observations = std::collections::HashMap::new();
    observations.insert(green_id, vec![runtime_local_ip_observation(green_id)]);
    obs_tx.send_replace(Arc::new(observations));
    wait_for_recorded_evpn_key(
        &injects,
        "Type 5 originator should inject tenant-green before delete",
    )
    .await;

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: None,
        svi: None,
        l3_originator: Some(l3_handle.runtime_control()),
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert!(ip_vrfs_rx.borrow().get("tenant-green").is_none());
    assert!(ip_vrfs_rx.borrow().get("tenant-blue").is_some());
    wait_for_recorded_evpn_key(
        &withdraws,
        "Type 5 originator should withdraw tenant-green after delete",
    )
    .await;
    l3_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_ip_vrf_redefine_reoriginates_type5() {
    let current = runtime_model_from_candidate_toml(ip_vrf_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(ip_vrf_redefined_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances);
    let (ip_vrfs_tx, ip_vrfs_rx) = watch::channel(current_ip_vrfs.clone());
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (obs_tx, obs_rx) = watch::channel(Arc::new(std::collections::HashMap::<
        rustbgpd_evpn::IpVrfId,
        Vec<rustbgpd_evpn::ip_vrf::LocalIpRouteObservation>,
    >::new()));
    let (status_tx, status_rx) = watch::channel(Vec::<rustbgpd_evpn::IpVrfDataplaneStatus>::new());
    let l3_handle = evpn_l3_originator::spawn(evpn_l3_originator::SpawnConfig {
        ip_vrfs: current_ip_vrfs,
        rib_tx: rib_tx.clone(),
        route_observations_rx: obs_rx,
        ip_vrf_status_rx: status_rx,
        metrics: BgpMetrics::new(),
        originated_counts: evpn_l3_originator::OriginatedIpVrfRouteCounts::default(),
        shutdown: tokio_util::sync::CancellationToken::new(),
    })
    .expect("L3 originator should spawn for non-empty current model");
    let blue_id = rustbgpd_evpn::IpVrfId::new(5000).unwrap();
    status_tx.send_replace(vec![runtime_ip_vrf_ready_status(blue_id, "tenant-blue")]);
    let mut observations = std::collections::HashMap::new();
    observations.insert(blue_id, vec![runtime_local_ip_observation(blue_id)]);
    obs_tx.send_replace(Arc::new(observations));
    wait_for_recorded_evpn_key(
        &injects,
        "Type 5 originator should inject tenant-blue before redefine",
    )
    .await;
    let old_key = injects.lock().await[0];

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: None,
        svi: None,
        l3_originator: Some(l3_handle.runtime_control()),
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert_eq!(
        ip_vrfs_rx
            .borrow()
            .get("tenant-blue")
            .expect("redefined VRF should be published to dataplane")
            .rd
            .to_string(),
        "65000:5555"
    );
    let deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let observed_withdraws = withdraws.lock().await.clone();
        let observed_injects = injects.lock().await.clone();
        if observed_withdraws.contains(&old_key)
            && observed_injects.iter().any(|key| *key != old_key)
        {
            break;
        }
        assert!(
            StdInstant::now() < deadline,
            "timed out waiting for Type 5 withdraw/re-inject after IP-VRF redefine; injects={observed_injects:?} withdraws={observed_withdraws:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    l3_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_ethernet_segment_add_publishes_es_routes() {
    // current = one ES over VNI 100 (actor spawned); candidate adds a
    // second ES over VNI 200 (one local ES per VNI).
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let instances = Arc::new(current.instances().clone());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_responder(rib_rx, injects.clone());

    let segment_handle = evpn_segment::spawn(
        &instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    // The segment actor consumes the new ES snapshot asynchronously and
    // re-originates Type 4 ES + Type 1 EAD-per-ES + EAD-per-EVI for the
    // full set. Poll until at least two ES (Type 4) routes are seen,
    // proving the added ES drove origination past the single startup ES.
    let deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let observed = injects.lock().await.clone();
        let es = observed
            .iter()
            .filter(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { .. }))
            .count();
        let has_ead_es = observed
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEs { .. }));
        let has_ead_evi = observed
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEvi { .. }));
        if es >= 2 && has_ead_es && has_ead_evi {
            break;
        }
        assert!(
            StdInstant::now() < deadline,
            "timed out waiting for ES routes; observed {observed:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    segment_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_ethernet_segment_add_restamps_member_vni_local_macs() {
    // Adding an ES over VNI 200 must republish the Type 2 originator's
    // vni->esi map so its local MACs stop carrying ESI=0. The
    // originator drains the member VNI's stale local routes on the map
    // change — observe that drain (a MacIp withdraw) as proof the
    // originator model was republished by the ES-add converger.
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_two_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (local_tx, local_rx) = mpsc::channel(8);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    // Learn a local MAC on the to-be-segment-bound VNI 200; the
    // originator originates a MAC-only Type 2 (ESI 0 — VNI 200 has no
    // segment yet).
    local_tx
        .send(rustbgpd_evpn::LocalMacObservation::Learned {
            vni: rustbgpd_evpn::EvpnInstanceId::new(200).unwrap(),
            mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xbb]),
            ifindex: 20,
        })
        .await
        .unwrap();
    let mac_inject_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if injects
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < mac_inject_deadline,
            "originator did not originate the VNI 200 local MAC"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    // The originator must drain VNI 200's now-stale ESI=0 local MAC
    // (then re-originate under the segment's ESI). Seeing the MacIp
    // withdraw proves the ES-add converger republished the originator
    // runtime model — without that, the originator would keep
    // advertising the member VNI with ESI 0.
    let drain_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if withdraws
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < drain_deadline,
            "ES add did not republish the originator model (no local MAC drain observed)"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    originator_handle.shutdown().await;
    segment_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_ethernet_segment_redefine_rebuilds_es_routes() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let redefined_esi =
        rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    // Ethernet Tag is pinned to 0 (RFC 7432 §6.1); member VNIs'
    // EAD-per-EVI routes are told apart by their per-VNI RDs.
    let member_rd = |raw_vni: u32| {
        current
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(raw_vni).unwrap())
            .unwrap_or_else(|| panic!("VNI {raw_vni} present in the current model"))
            .rd
    };
    let old_member_rd = member_rd(100);
    let new_member_rd = member_rd(200);

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let initial_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if injects.lock().await.iter().any(|key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                    esi,
                    rd,
                    ..
                } if *esi == redefined_esi && *rd == old_member_rd
            )
        }) {
            break;
        }
        assert!(
            StdInstant::now() < initial_deadline,
            "timed out waiting for initial ES EAD-per-EVI route"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    let redefine_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let drained = withdraws.lock().await.clone();
        let injected = injects.lock().await.clone();
        let drained_old_evi = drained.iter().any(|key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                    esi,
                    rd,
                    ..
                } if *esi == redefined_esi && *rd == old_member_rd
            )
        });
        let injected_new_evi = injected.iter().any(|key| {
            matches!(
                key,
                rustbgpd_wire::EvpnRouteKey::EadPerEvi {
                    esi,
                    rd,
                    ..
                } if *esi == redefined_esi && *rd == new_member_rd
            )
        });
        if drained_old_evi && injected_new_evi {
            break;
        }
        assert!(
            StdInstant::now() < redefine_deadline,
            "ES redefine did not drain/rebuild EAD-per-EVI routes; drained {drained:?}, injected {injected:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    segment_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_ethernet_segment_redefine_restamps_member_vni_local_macs() {
    let current = runtime_model_from_candidate_toml(two_l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_redefined_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (local_tx, local_rx) = mpsc::channel(8);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    local_tx
        .send(rustbgpd_evpn::LocalMacObservation::Learned {
            vni: rustbgpd_evpn::EvpnInstanceId::new(200).unwrap(),
            mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xee]),
            ifindex: 20,
        })
        .await
        .unwrap();
    let mac_inject_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if injects
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < mac_inject_deadline,
            "originator did not originate the VNI 200 local MAC"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    let drain_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if withdraws
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < drain_deadline,
            "ES redefine did not republish the originator model (no local MAC drain observed)"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    originator_handle.shutdown().await;
    segment_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_l2vni_redefine_reoriginates_imet() {
    // Committed VNI 100 (RD 65000:100); candidate redefines it to RD
    // 65000:111. The redefine path must withdraw the committed Type 3 IMET
    // route and originate the new-RD one through the real converger.
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let vni100 = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    let old_rd = current.instances().get(vni100).unwrap().rd;
    let new_rd = candidate.instances().get(vni100).unwrap().rd;

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    // Pre-originate the committed (old-RD) IMET so the redefine has a
    // Type 3 route to withdraw.
    let imet_controller = Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()));
    {
        let old_inst = current.instances().get(vni100).unwrap().clone();
        let _ = imet_controller
            .lock()
            .await
            .originate_instance(old_inst, &rib_tx)
            .await;
    }

    // Dataplane + originator are required by the redefine converge path.
    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller,
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    // IMET withdraw/originate are awaited round-trips through the RIB
    // recorder, so both are recorded by the time `converge` returns.
    let drained = withdraws.lock().await.clone();
    let injected = injects.lock().await.clone();
    assert!(
        drained.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == old_rd
        )),
        "redefine should withdraw the committed (old-RD) IMET route; drained {drained:?}"
    );
    assert!(
        injected.iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::Imet { rd, .. } if *rd == new_rd
        )),
        "redefine should originate the new-RD IMET route; injected {injected:?}"
    );

    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn rollback_imet_redefine_reports_failure_when_withdraw_rejected() {
    // If the IMET withdraw of the new key fails, the controller keeps
    // tracking it, so a bare re-originate of the old instance would no-op
    // with AlreadyOriginated. rollback_imet_redefine must report failure
    // (false) rather than claiming the committed route was restored.
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let candidate =
        runtime_candidate_from_toml(two_l2vni_one_redefined_l2vni_runtime_candidate_toml());
    let vni100 = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    let old_instance = current.instances().get(vni100).unwrap().clone();
    let new_instance = candidate.instances().get(vni100).unwrap().clone();

    // RIB responder that accepts injects but rejects every withdraw.
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let _rib = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::InjectEvpn { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::WithdrawEvpn { reply, .. } => {
                    let _ = reply.send(Err(RibCommandError::internal("withdraw rejected")));
                }
                _ => {}
            }
        }
    });

    // Pre-originate the new key so the controller tracks it (the state
    // after a successful redefine main path).
    let imet_controller = Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new()));
    {
        let _ = imet_controller
            .lock()
            .await
            .originate_instance(new_instance, &rib_tx)
            .await;
    }

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller,
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let restored = converger.rollback_imet_redefine(vni100, old_instance).await;
    assert!(
        !restored,
        "rollback must report failure when the new IMET key could not be withdrawn"
    );
}

#[test]
fn l2vni_swap_failure_escalates_when_rollback_fails() {
    let error = l2vni_swap_failure(false, "EVPN dataplane runtime model publish failed");
    let DaemonEvpnRuntimeConvergeError::Failed(source) = error else {
        panic!("expected failed error, got {error:?}");
    };
    assert!(
        source.message().contains("rollback also failed"),
        "unexpected error message: {}",
        source.message()
    );
}

#[tokio::test]
async fn restore_imet_reports_failure_when_origination_rejected() {
    // restore_imet must report whether the committed Type 3 was actually
    // re-originated, so the redefine originate-failure path can escalate
    // when even the restore fails.
    let current = runtime_model_from_candidate_toml(two_l2vni_runtime_candidate_toml());
    let old_instance = current
        .instances()
        .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
        .unwrap()
        .clone();

    // RIB responder that rejects every inject (origination).
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let _rib = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            if let RibUpdate::InjectEvpn { reply, .. } = msg {
                let _ = reply.send(Err(RibCommandError::internal("inject rejected")));
            }
        }
    });

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    assert!(
        !converger.restore_imet(old_instance).await,
        "restore_imet must report failure when the RIB rejects the re-origination"
    );
}

#[tokio::test]
async fn apply_evpn_runtime_l2vni_redefine_aliasing_toggle_commits() {
    // Toggling apply_aliasing_ecmp off is a redefine; it is now
    // runtime-drivable (the dataplane diff converges it via the
    // FdbNhg -> SingleDst transition). Confirm the committed model carries
    // the flag flip for VNI 100.
    let coordinator = two_l2vni_runtime_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = TestRuntimeConverger::ok();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: two_l2vni_aliasing_toggle_runtime_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    let plan = response.plan.unwrap();
    assert_eq!(plan.evpn_instances.unwrap().redefined, vec!["100"]);
    let guard = coordinator.lock().unwrap();
    assert!(
        !guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .unwrap()
            .apply_aliasing_ecmp,
        "committed model should carry apply_aliasing_ecmp=false for VNI 100"
    );
}

#[tokio::test]
async fn runtime_actor_converger_ethernet_segment_delete_drains_es_routes() {
    let current = runtime_model_from_candidate_toml(two_l2vni_two_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let removed_esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    let initial_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let observed = injects.lock().await.clone();
        let has_es = observed.iter().any(
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
        );
        let has_ead_es = observed.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEs { esi, .. } if *esi == removed_esi)
            });
        let has_ead_evi = observed.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEvi { esi, .. } if *esi == removed_esi)
            });
        if has_es && has_ead_es && has_ead_evi {
            break;
        }
        assert!(
            StdInstant::now() < initial_deadline,
            "timed out waiting for initial removed-ES routes; observed {observed:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: None,
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    let drain_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let drained = withdraws.lock().await.clone();
        let has_es = drained.iter().any(
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
        );
        let has_ead_es = drained.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEs { esi, .. } if *esi == removed_esi)
            });
        let has_ead_evi = drained.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEvi { esi, .. } if *esi == removed_esi)
            });
        if has_es && has_ead_es && has_ead_evi {
            break;
        }
        assert!(
            StdInstant::now() < drain_deadline,
            "ES delete did not drain removed segment routes; drained {drained:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    segment_handle.shutdown().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "tenant teardown exercises every actor at once"
)]
async fn runtime_actor_converger_tenant_teardown_drains_imet_and_es_routes() {
    // Tear down an ES-member L2VNI + its Ethernet Segment in one pass and
    // assert the multi-actor drain: Type 3 IMET withdraw, Type 1/4 segment
    // withdraws, and the dataplane instance model emptied.
    let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(minimal_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    let removed_esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    let imet_keys = imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;
    assert_eq!(imet_keys.len(), 1);

    let initial_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let observed = injects.lock().await.clone();
        let has_es = observed.iter().any(
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
        );
        let has_ead_es = observed.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEs { esi, .. } if *esi == removed_esi)
            });
        let has_ead_evi = observed.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEvi { esi, .. } if *esi == removed_esi)
            });
        if has_es && has_ead_es && has_ead_evi {
            break;
        }
        assert!(
            StdInstant::now() < initial_deadline,
            "timed out waiting for initial ES routes; observed {observed:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    assert!(
        evpn_instances_rx.borrow().get(deleted_vni).is_none(),
        "dataplane instance model should drop the torn-down L2VNI"
    );

    let drain_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let drained = withdraws.lock().await.clone();
        let has_imet = drained
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. }));
        let has_es = drained.iter().any(
            |key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
        );
        let has_ead_es = drained.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEs { esi, .. } if *esi == removed_esi)
            });
        let has_ead_evi = drained.iter().any(|key| {
                matches!(key, rustbgpd_wire::EvpnRouteKey::EadPerEvi { esi, .. } if *esi == removed_esi)
            });
        if has_imet && has_es && has_ead_es && has_ead_evi {
            break;
        }
        assert!(
            StdInstant::now() < drain_deadline,
            "tenant teardown did not drain IMET + segment routes; drained {drained:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    originator_handle.shutdown().await;
    segment_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

fn svi_dataplane_report(
    vni: u32,
    bridge_mac: rustbgpd_evpn::MacAddress,
) -> rustbgpd_evpn::DataplaneReport {
    rustbgpd_evpn::DataplaneReport {
        intent_generation: 0,
        reconcile_generation: 0,
        instance_status: vec![rustbgpd_evpn::InstanceDataplaneStatus {
            vni: rustbgpd_evpn::EvpnInstanceId::new(vni).unwrap(),
            state: rustbgpd_evpn::InstanceState::Ready,
            message: None,
            bridge_mac: Some(bridge_mac),
        }],
        applied: vec![],
        failed: vec![],
        bum_enforcement: vec![],
        ip_vrf_status: vec![],
        ip_vrf_routes: Some(rustbgpd_evpn::ip_vrf::IpVrfRouteDump::default()),
        managed_netdevs: vec![],
        ip_vrf_installed_routes: std::collections::HashMap::new(),
        ip_vrf_install_drop_counts: std::collections::BTreeMap::new(),
        fdb_nexthops: rustbgpd_evpn::FdbNexthopDataplaneStatus::default(),
        fdb_nhg_drift_counters: rustbgpd_evpn::FdbNhgDriftCounters::default(),
        l3_adoption_counters: rustbgpd_evpn::L3AdoptionCounters::default(),
        single_active_counters: rustbgpd_evpn::SingleActiveCounters::default(),
        foreign_state_counters: rustbgpd_evpn::ForeignStateCounters::default(),
    }
}

#[test]
fn teardown_failure_escalates_when_imet_not_restored() {
    // When the rollback restored IMET, the error is the bare step message.
    let restored = teardown_failure(true, "EVPN segment publish failed");
    assert_eq!(restored.message(), "EVPN segment publish failed");

    // When IMET could NOT be restored, the message escalates so an operator
    // knows live Type 3 state may need repair/restart.
    let stranded = teardown_failure(false, "EVPN segment publish failed");
    assert!(stranded.message().contains("EVPN segment publish failed"));
    assert!(
        stranded
            .message()
            .contains("IMET teardown rollback also failed"),
        "unexpected message: {}",
        stranded.message()
    );
    assert!(stranded.message().contains("repair/restart"));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "rollback test wires every actor + simulates a mid-teardown state"
)]
async fn runtime_actor_converger_tenant_teardown_rollback_restores_imet_and_models() {
    // Drive the rollback ladder directly: seed a live tenant, simulate a
    // mid-teardown state (IMET withdrawn + segment routes drained), then
    // call rollback_tenant_teardown and assert it re-originates the Type 3
    // IMET and the Type 1/4 segment routes and reports full restoration.
    let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let deleted_vni = rustbgpd_evpn::EvpnInstanceId::new(100).unwrap();
    let deleted_instances = vec![current.instances().get(deleted_vni).cloned().unwrap()];
    let removed_esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;

    // Wait for the live tenant's initial origination (IMET + Type 1/4).
    let initial_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let observed = injects.lock().await.clone();
        let imet = observed
            .iter()
            .filter(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Imet { .. }))
            .count();
        let es = observed.iter().any(
            |k| matches!(k, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
        );
        if imet >= 1 && es {
            break;
        }
        assert!(
            StdInstant::now() < initial_deadline,
            "no initial origination"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Simulate the mid-teardown state: IMET withdrawn + segment drained.
    imet_controller
        .withdraw_instance(deleted_vni, &rib_tx)
        .await;
    let empty_instances = Arc::new(rustbgpd_evpn::EvpnInstanceTable::new());
    let segment_control = segment_handle.runtime_control();
    assert!(segment_control.replace_instances(empty_instances.clone()));
    assert!(segment_control.replace_segments(Arc::new(Vec::new())));
    let drain_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let drained = withdraws.lock().await.clone();
        let imet = drained
            .iter()
            .any(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Imet { .. }));
        let es = drained.iter().any(
            |k| matches!(k, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
        );
        if imet && es {
            break;
        }
        assert!(
            StdInstant::now() < drain_deadline,
            "mid-teardown drain stalled"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let imet_before = injects
        .lock()
        .await
        .iter()
        .filter(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Imet { .. }))
        .count();
    let es_before = injects
        .lock()
        .await
        .iter()
        .filter(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi))
        .count();

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    let restored = converger
        .rollback_tenant_teardown(&current, &deleted_instances)
        .await;
    assert!(restored, "rollback should report full IMET restoration");

    // Rollback re-originates the IMET (synchronously) and republishes the
    // committed segment snapshot (which re-originates the Type 4 ES route).
    let restore_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let observed = injects.lock().await.clone();
        let imet_now = observed
            .iter()
            .filter(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::Imet { .. }))
            .count();
        let es_now = observed
            .iter()
            .filter(
                |k| matches!(k, rustbgpd_wire::EvpnRouteKey::Es { esi, .. } if *esi == removed_esi),
            )
            .count();
        if imet_now > imet_before && es_now > es_before {
            break;
        }
        assert!(
            StdInstant::now() < restore_deadline,
            "rollback did not re-originate IMET + ES (imet {imet_before}->{imet_now}, es {es_before}->{es_now})"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    originator_handle.shutdown().await;
    segment_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "wires dataplane + originator + SVI actors and drives a report"
)]
async fn runtime_actor_converger_tenant_teardown_drains_svi_mac() {
    // A multi-element teardown that deletes an advertise_svi_mac L2VNI must
    // drain its SVI MAC (Type 2) through the SVI actor's instance-watch path.
    let current = runtime_model_from_candidate_toml(two_l2vni_one_svi_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(minimal_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let current_ip_vrfs = Arc::new(current.ip_vrfs().clone());
    let svi_mac = rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0x5b]);

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(current_ip_vrfs);
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let (_local_tx, local_rx) = mpsc::channel(1);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let (svi_report_tx, svi_report_rx) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(8);
    let svi_handle = evpn_svi::spawn(
        &current_instances,
        rib_tx.clone(),
        svi_report_rx,
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("SVI actor should spawn when an instance advertises its SVI MAC");
    let mut imet_controller = evpn_imet::EvpnImetController::new();
    imet_controller
        .originate_all(current.instances().iter().cloned(), &rib_tx)
        .await;

    // Drive the SVI MAC origination via a Ready dataplane report, then
    // capture the originated Type 2 key.
    svi_report_tx
        .send(svi_dataplane_report(100, svi_mac))
        .unwrap();
    let svi_deadline = StdInstant::now() + Duration::from_secs(2);
    let svi_key = loop {
        let observed = injects.lock().await.clone();
        if let Some(key) = observed
            .iter()
            .find(|k| matches!(k, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
            .copied()
        {
            break key;
        }
        assert!(
            StdInstant::now() < svi_deadline,
            "SVI actor never originated the SVI MAC; observed {observed:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(imet_controller)),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: Some(svi_handle.runtime_control()),
        l3_originator: None,
        segment: None,
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    let drain_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if withdraws.lock().await.contains(&svi_key) {
            break;
        }
        assert!(
            StdInstant::now() < drain_deadline,
            "tenant teardown did not withdraw the SVI MAC"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    svi_handle.shutdown().await;
    originator_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

#[tokio::test]
async fn runtime_actor_converger_ethernet_segment_delete_restamps_member_vni_local_macs() {
    let current = runtime_model_from_candidate_toml(two_l2vni_two_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (local_tx, local_rx) = mpsc::channel(8);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    local_tx
        .send(rustbgpd_evpn::LocalMacObservation::Learned {
            vni: rustbgpd_evpn::EvpnInstanceId::new(200).unwrap(),
            mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xdd]),
            ifindex: 20,
        })
        .await
        .unwrap();
    let mac_inject_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if injects
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < mac_inject_deadline,
            "originator did not originate the VNI 200 segmented local MAC"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: crate::evpn_es_drain::EvpnEsDrainState::default(),
    };

    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    let drain_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if withdraws
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < drain_deadline,
            "ES delete did not republish the originator model (no local MAC drain observed)"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    originator_handle.shutdown().await;
    segment_handle.shutdown().await;
}

/// ADR-0084 decision 3 on the originator side, pinned at the
/// converger: every runtime-model publish carries the LIVE
/// coordinator drained set, so an unrelated runtime apply (here an
/// L2VNI add) committed while an Ethernet Segment is
/// operator-drained must not undrain it — neither the member
/// VNI's local Type 2 nor the segment's Type 1/4 routes may
/// re-originate from the apply.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "full two-actor + drain-primitive wiring per the sibling converger proofs"
)]
async fn runtime_apply_preserves_operator_drain_across_unrelated_l2vni_add() {
    let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let current_instances = Arc::new(current.instances().clone());
    let drained_esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _rib = runtime_converger_rib_recorder(rib_rx, injects.clone(), withdraws.clone());

    let (local_tx, local_rx) = mpsc::channel(8);
    let originator_handle = evpn_originator::spawn(
        evpn_originator::OriginatorConfig::default(),
        &current_instances,
        rib_tx.clone(),
        Some(local_rx),
        BgpMetrics::new(),
        evpn_originator::OriginatedLocalMacCounts::default(),
        tokio_util::sync::CancellationToken::new(),
        evpn_vni_to_esi_map(current.ethernet_segments()),
    )
    .expect("originator should spawn for non-empty current model");
    let segment_handle = evpn_segment::spawn(
        &current_instances,
        current.ethernet_segments().to_vec(),
        rib_tx.clone(),
        None,
        BgpMetrics::new(),
        tokio_util::sync::CancellationToken::new(),
    )
    .expect("segment actor should spawn for non-empty ES config");

    // A local MAC on the ES member VNI 100 originates a Type 2.
    local_tx
        .send(rustbgpd_evpn::LocalMacObservation::Learned {
            vni: rustbgpd_evpn::EvpnInstanceId::new(100).unwrap(),
            mac: rustbgpd_evpn::MacAddress::new([0x02, 0, 0, 0, 0, 0xab]),
            ifindex: 10,
        })
        .await
        .unwrap();
    let mac_inject_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if injects
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < mac_inject_deadline,
            "originator did not originate the VNI 100 local MAC"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Operator-drain the ES through the shared primitive against
    // the same drain state the converger will read.
    let es_drain = crate::evpn_es_drain::EvpnEsDrainState::default();
    let apply_lock = tokio::sync::Mutex::new(());
    let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::from_model(&current));
    let segment_control = segment_handle.runtime_control();
    let originator_control = originator_handle.runtime_control();
    let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
        drained_esi,
        crate::evpn_es_drain::EsDrainReason::Operator,
        true,
        &apply_lock,
        &coordinator,
        &es_drain,
        Some(&segment_control),
        Some(&originator_control),
    )
    .await
    .expect("drain applies against the committed model");
    assert!(outcome.drained && outcome.changed);
    let drain_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        let drained = withdraws.lock().await.clone();
        let macip_withdrawn = drained
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::MacIp { .. }));
        let es_withdrawn = drained
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Es { .. }));
        if macip_withdrawn && es_withdrawn {
            break;
        }
        assert!(
            StdInstant::now() < drain_deadline,
            "drain did not withdraw across both actors; withdrew {drained:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let inject_floor = injects.lock().await.len();

    // Unrelated runtime apply: add L2VNI 200. The converger
    // publishes the originator model with `es_drain.snapshot()`.
    let (evpn_instances_tx, _evpn_instances_rx) = watch::channel(current_instances.clone());
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(originator_handle.runtime_control()),
        svi: None,
        l3_originator: None,
        segment: Some(segment_handle.runtime_control()),
        es_drain: es_drain.clone(),
    };
    converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap();

    // The add's IMET origination round-trips the publish.
    let imet_deadline = StdInstant::now() + Duration::from_secs(2);
    loop {
        if injects
            .lock()
            .await
            .iter()
            .any(|key| matches!(key, rustbgpd_wire::EvpnRouteKey::Imet { .. }))
        {
            break;
        }
        assert!(
            StdInstant::now() < imet_deadline,
            "L2VNI add did not originate the new VNI's IMET"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        es_drain.snapshot().contains(&drained_esi),
        "the apply must not GC a still-configured drained ES"
    );
    let post = injects.lock().await.clone();
    assert!(
        !post[inject_floor..].iter().any(|key| matches!(
            key,
            rustbgpd_wire::EvpnRouteKey::MacIp { .. }
                | rustbgpd_wire::EvpnRouteKey::Es { .. }
                | rustbgpd_wire::EvpnRouteKey::EadPerEs { .. }
                | rustbgpd_wire::EvpnRouteKey::EadPerEvi { .. }
        )),
        "an unrelated L2VNI add must not undrain the ES (no Type 2 replay, \
             no Type 1/4 re-origination); injected {post:?}"
    );

    originator_handle.shutdown().await;
    segment_handle.shutdown().await;
    dataplane_handle.shutdown().await;
}

/// The drain-GC split-state fix (cross-actor seam audit follow-up to
/// ADR-0084): an ES-delete apply whose Type 2 originator publish
/// fails mid-converge must leave the coordinator's drain state
/// (the gauge / RPC drain-reason source) and the segment actor's
/// drained-set mirror AGREEING — both still drained — and a
/// subsequent bare operator undrain must be a real transition that
/// fans the undrained set out to the actor, not an idempotent no-op
/// against an entry the converge already GC'd.
#[tokio::test]
async fn failed_es_delete_publish_keeps_coordinator_and_actor_drain_agreeing() {
    let current = runtime_model_from_candidate_toml(two_l2vni_two_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(two_l2vni_one_es_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let removed_esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
    let es_drain = crate::evpn_es_drain::EvpnEsDrainState::default();
    let apply_lock = tokio::sync::Mutex::new(());
    let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::from_model(&current));
    let mut probe = evpn_segment::EvpnSegmentControlProbe::new();

    // Operator-drain the ES the apply will delete, through the shared
    // primitive: coordinator state + the segment actor's mirror.
    let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
        removed_esi,
        crate::evpn_es_drain::EsDrainReason::Operator,
        true,
        &apply_lock,
        &coordinator,
        &es_drain,
        Some(&probe.control),
        None,
    )
    .await
    .expect("drain applies against the committed model");
    assert!(outcome.drained && outcome.changed);
    assert!(probe.drained_rx.borrow_and_update().contains(&removed_esi));

    // ES delete whose originator publish fails mid-converge (the
    // actor exited) — after the segment actor already received the
    // candidate instance snapshot.
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: None,
        originator: Some(evpn_originator::EvpnOriginatorRuntimeControl::closed_for_test()),
        svi: None,
        l3_originator: None,
        segment: Some(probe.control.clone()),
        es_drain: es_drain.clone(),
    };
    let err = converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap_err();
    assert!(
        err.message()
            .contains("originator runtime control is closed"),
        "expected the originator publish failure; got {err:?}"
    );

    // The invariant: both sides still report the ES drained.
    assert!(
        es_drain.snapshot().contains(&removed_esi),
        "a failed converge must not GC the coordinator's drain entry"
    );
    assert_eq!(
        es_drain.reasons_for(removed_esi),
        std::collections::BTreeSet::from([crate::evpn_es_drain::EsDrainReason::Operator]),
        "the RPC drain-reason source must still report the operator drain"
    );
    assert!(
        probe.drained_rx.borrow_and_update().contains(&removed_esi),
        "the segment actor's drained mirror must still hold the ES"
    );

    // And a bare operator undrain is a real transition that fans out.
    let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
        removed_esi,
        crate::evpn_es_drain::EsDrainReason::Operator,
        false,
        &apply_lock,
        &coordinator,
        &es_drain,
        Some(&probe.control),
        None,
    )
    .await
    .expect("undrain applies against the committed model");
    assert!(
        outcome.changed,
        "the undrain after the failed apply must not be an idempotent no-op"
    );
    assert!(!outcome.drained);
    assert!(
        !probe.drained_rx.borrow_and_update().contains(&removed_esi),
        "the undrain must fan the undrained set out to the segment actor"
    );
}

/// The same invariant on the tenant-teardown path: a teardown that
/// would delete a drained ES but fails before completing (here: the
/// Type 2 originator is gone) must leave the coordinator drain state
/// and the segment actor's mirror agreeing (both drained), with a
/// subsequent operator undrain fanning out.
#[tokio::test]
async fn failed_tenant_teardown_keeps_coordinator_and_actor_drain_agreeing() {
    let current = runtime_model_from_candidate_toml(l2vni_one_es_runtime_candidate_toml());
    let candidate = runtime_candidate_from_toml(minimal_runtime_candidate_toml());
    let plan = current.plan_candidate(&candidate);
    let drained_esi = rustbgpd_wire::EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
    let es_drain = crate::evpn_es_drain::EvpnEsDrainState::default();
    let apply_lock = tokio::sync::Mutex::new(());
    let coordinator = Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::from_model(&current));
    let mut probe = evpn_segment::EvpnSegmentControlProbe::new();

    let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
        drained_esi,
        crate::evpn_es_drain::EsDrainReason::Operator,
        true,
        &apply_lock,
        &coordinator,
        &es_drain,
        Some(&probe.control),
        None,
    )
    .await
    .expect("drain applies against the committed model");
    assert!(outcome.drained && outcome.changed);

    // Open dataplane control so the teardown reaches the originator
    // requirement, which fails (the actor exited).
    let (evpn_instances_tx, _evpn_instances_rx) =
        watch::channel(Arc::new(current.instances().clone()));
    let (ip_vrfs_tx, _ip_vrfs_rx) = watch::channel(Arc::new(rustbgpd_evpn::IpVrfTable::new()));
    let (bum_enforcement_tx, _bum_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::BumEnforcementTable::new()));
    let (same_esi_bias_tx, _bias_rx) =
        watch::channel(Arc::new(rustbgpd_evpn::SameEsiBiasTable::new()));
    let (_drop_counts_tx, remote_prefix_drop_counts_rx) =
        watch::channel(Arc::new(evpn_dataplane::RemoteIpPrefixDropCounts::new()));
    let (report_tx, _) = broadcast::channel::<rustbgpd_evpn::DataplaneReport>(1);
    let dataplane_handle = evpn_dataplane::EvpnDataplaneHandle {
        shutdown: tokio_util::sync::CancellationToken::new(),
        supervisor_join: tokio::spawn(async {}),
        actor_join: tokio::spawn(async {}),
        local_mac_rx: None,
        report_tx,
        bum_enforcement_tx,
        same_esi_bias_tx,
        evpn_instances_tx,
        ip_vrfs_tx,
        remote_prefix_drop_counts_rx,
    };
    let converger = EvpnRuntimeActorConverger {
        rib_tx,
        imet_controller: Arc::new(tokio::sync::Mutex::new(evpn_imet::EvpnImetController::new())),
        dataplane: Some(dataplane_handle.runtime_control()),
        originator: Some(evpn_originator::EvpnOriginatorRuntimeControl::closed_for_test()),
        svi: None,
        l3_originator: None,
        segment: Some(probe.control.clone()),
        es_drain: es_drain.clone(),
    };
    let err = converger
        .converge(&current, &candidate, &plan)
        .await
        .unwrap_err();
    assert!(
        err.message()
            .contains("originator runtime control is closed"),
        "expected the originator failure; got {err:?}"
    );

    assert!(
        es_drain.snapshot().contains(&drained_esi),
        "a failed teardown must not GC the coordinator's drain entry"
    );
    assert!(
        probe.drained_rx.borrow_and_update().contains(&drained_esi),
        "the segment actor's drained mirror must still hold the ES"
    );

    let outcome = crate::evpn_es_drain::apply_ethernet_segment_drain(
        drained_esi,
        crate::evpn_es_drain::EsDrainReason::Operator,
        false,
        &apply_lock,
        &coordinator,
        &es_drain,
        Some(&probe.control),
        None,
    )
    .await
    .expect("undrain applies against the committed model");
    assert!(
        outcome.changed,
        "the undrain after the failed teardown must not be an idempotent no-op"
    );
    assert!(
        !probe.drained_rx.borrow_and_update().contains(&drained_esi),
        "the undrain must fan the undrained set out to the segment actor"
    );

    dataplane_handle.shutdown().await;
}

// ---- #268 mixed-candidate decomposition (apply-level) ----

/// Behaves like the real dispatch's validation without actor side
/// effects: accepts exactly the supported primitive shapes (via
/// `validate_supported_plan_shape`), rejects everything else as
/// `Unsupported`, records each accepted plan, and can be scripted to
/// fail the Nth accepted converge with a `Failed` error.
struct ShapeCheckingConverger {
    accepted_plans: Arc<std::sync::Mutex<Vec<rustbgpd_evpn::EvpnRuntimePlan>>>,
    fail_on_accepted_call: Option<usize>,
}

impl ShapeCheckingConverger {
    fn new() -> Self {
        Self {
            accepted_plans: Arc::new(std::sync::Mutex::new(Vec::new())),
            fail_on_accepted_call: None,
        }
    }

    fn failing_on(call: usize) -> Self {
        Self {
            fail_on_accepted_call: Some(call),
            ..Self::new()
        }
    }
}

impl DaemonEvpnRuntimeConverger for ShapeCheckingConverger {
    fn converge<'a>(
        &'a self,
        current: &'a rustbgpd_evpn::EvpnRuntimeModel,
        candidate: &'a rustbgpd_evpn::EvpnRuntimeCandidate,
        plan: &'a rustbgpd_evpn::EvpnRuntimePlan,
    ) -> DaemonEvpnRuntimeConvergeFuture<'a> {
        Box::pin(async move {
            validate_supported_plan_shape(current, candidate, plan)?;
            let call_number = {
                let mut accepted = self.accepted_plans.lock().unwrap();
                accepted.push(plan.clone());
                accepted.len()
            };
            if self.fail_on_accepted_call == Some(call_number) {
                return Err(DaemonEvpnRuntimeConvergeError::failed(
                    "injected decomposed-step failure",
                ));
            }
            Ok(())
        })
    }
}

// The #268 maintainer example candidate on top of the committed
// `l2vni_one_es_runtime_candidate_toml()` model: delete the ES,
// redefine its (surviving) member L2VNI 100, and add L2VNI 200.
fn decomposer_mixed_candidate_toml() -> &'static str {
    r#"
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

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
"#
}

fn one_es_coordinator() -> Arc<Mutex<rustbgpd_evpn::EvpnRuntimeCoordinator>> {
    let current = runtime_candidate_from_toml(l2vni_one_es_runtime_candidate_toml());
    Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )))
}

#[tokio::test]
async fn apply_evpn_runtime_mixed_candidate_decomposes_across_generations() {
    let coordinator = one_es_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = ShapeCheckingConverger::new();

    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: decomposer_mixed_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap();

    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    assert!(
        response.message.contains("3 decomposed steps"),
        "message must surface the decomposition: {}",
        response.message
    );
    assert!(
        response.message.contains("generations 2..=4"),
        "message must name the N committed generations: {}",
        response.message
    );
    assert_eq!(response.runtime.unwrap().generation, 4);

    // The converger saw the mixed whole (rejected, not recorded) and
    // then exactly the ordered primitive steps: deletes, redefine, add.
    let accepted = converger.accepted_plans.lock().unwrap();
    assert_eq!(accepted.len(), 3, "three primitive converges expected");
    assert_eq!(accepted[0].ethernet_segments.deleted.len(), 1);
    assert!(!accepted[0].evpn_instances.has_changes());
    assert_eq!(accepted[1].evpn_instances.redefined, vec![100]);
    assert!(accepted[1].evpn_instances.added.is_empty());
    assert_eq!(accepted[2].evpn_instances.added, vec![200]);
    assert!(accepted[2].evpn_instances.redefined.is_empty());

    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 4);
    assert_eq!(
        guard.model().mutation_state(),
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle
    );
    assert!(guard.model().ethernet_segments().is_empty());
    assert_eq!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .unwrap()
            .rd
            .to_string(),
        "65000:101"
    );
    assert!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
            .is_some()
    );
}

#[tokio::test]
async fn apply_evpn_runtime_decomposed_mid_sequence_failure_is_fail_stop_and_recoverable() {
    let coordinator = one_es_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    // Accepted call 2 = decomposed step 2 (the L2VNI redefine).
    let converger = ShapeCheckingConverger::failing_on(2);

    let error = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: decomposer_mixed_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap_err();

    let GrpcEvpnRuntimeApplyError::FailedPrecondition(message) = error else {
        panic!("expected FailedPrecondition, got: {error:?}");
    };
    assert!(
        message.contains("decomposed step 2/3"),
        "must name the failed step: {message}"
    );
    assert!(
        message.contains("generations [2]"),
        "must name the generations committed by earlier steps: {message}"
    );
    assert!(
        message.contains("no cross-step rollback"),
        "must state fail-stop semantics: {message}"
    );
    assert!(
        message.contains("re-SIGHUP"),
        "must carry the recovery instruction: {message}"
    );

    {
        let guard = coordinator.lock().unwrap();
        // Step 1 (the ES delete) committed generation 2 and stays
        // committed; the failed step pins the model.
        assert_eq!(guard.model().generation().as_u64(), 2);
        assert!(guard.model().ethernet_segments().is_empty());
        assert_eq!(
            guard.model().mutation_state(),
            rustbgpd_evpn::EvpnRuntimeMutationState::Failed
        );
        assert_eq!(
            guard.model().lifecycle(),
            rustbgpd_evpn::EvpnRuntimeLifecycle::Degraded
        );
        // The redefine never published: VNI 100 keeps the committed RD.
        assert_eq!(
            guard
                .model()
                .instances()
                .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
                .unwrap()
                .rd
                .to_string(),
            "65000:100"
        );
    }

    // Recovery: re-apply the same candidate with a healthy converger —
    // the remainder replans from the committed model (redefine + add is
    // a supported L2VNI-mixed shape) and converges.
    let healthy = ShapeCheckingConverger::new();
    let response = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: decomposer_mixed_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &healthy,
    )
    .await
    .unwrap();
    assert_eq!(
        response.outcome,
        proto::EvpnRuntimeApplyOutcome::EvpnRuntimeApplyCommitted as i32
    );
    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 3);
    assert_eq!(
        guard.model().mutation_state(),
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle
    );
    assert_eq!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(100).unwrap())
            .unwrap()
            .rd
            .to_string(),
        "65000:101"
    );
    assert!(
        guard
            .model()
            .instances()
            .get(rustbgpd_evpn::EvpnInstanceId::new(200).unwrap())
            .is_some()
    );
}

// LAN-215 #10: a mid-sequence decomposed fail-stop must bump the
// observability counter exactly once (it pins mutation_state=Failed).
#[tokio::test]
async fn apply_evpn_runtime_decomposed_fail_stop_increments_metric() {
    use prometheus::Encoder;

    let coordinator = one_es_coordinator();
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = ShapeCheckingConverger::failing_on(2);
    let metrics = BgpMetrics::new();

    let error = apply_evpn_runtime_request_with_metrics(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml: decomposer_mixed_candidate_toml().to_string(),
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
        &metrics,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        GrpcEvpnRuntimeApplyError::FailedPrecondition(_)
    ));

    let encoder = prometheus::TextEncoder::new();
    let mut buf = Vec::new();
    encoder
        .encode(&metrics.registry().gather(), &mut buf)
        .unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(
        text.contains("evpn_runtime_decomposed_fail_stops_total 1"),
        "fail-stop must bump the counter exactly once: {text}"
    );
}

#[tokio::test]
async fn apply_evpn_runtime_undecomposable_mixed_fails_closed_without_commit() {
    // L2VNI add mixed with an IP-VRF identity (L3VNI) redefine: the
    // precondition must fail the whole candidate closed, naming the
    // offending step, with no generation advance and no pinning.
    let current = runtime_candidate_from_toml(ip_vrf_runtime_candidate_toml());
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        current.instances().clone(),
        current.ip_vrfs().clone(),
        current.ethernet_segments().to_vec(),
    )));
    let apply_lock = tokio::sync::Mutex::new(());
    let converger = ShapeCheckingConverger::new();

    let mut candidate_toml = ip_vrf_redefined_l3vni_runtime_candidate_toml().to_string();
    candidate_toml.push_str(
        r#"
[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
"#,
    );

    let error = apply_evpn_runtime_request(
        &proto::ApplyEvpnRuntimeRequest {
            candidate_toml,
            validate_only: false,
        },
        coordinator.as_ref(),
        &apply_lock,
        &converger,
    )
    .await
    .unwrap_err();

    let GrpcEvpnRuntimeApplyError::FailedPrecondition(message) = error else {
        panic!("expected FailedPrecondition, got: {error:?}");
    };
    assert!(
        message.contains("does not decompose"),
        "must fail as a decomposition precondition: {message}"
    );
    assert!(
        message.contains("restart-required by design"),
        "must carry today's identity-redefine error: {message}"
    );
    assert!(
        message.contains("generation 1 remains committed"),
        "nothing may commit: {message}"
    );

    let guard = coordinator.lock().unwrap();
    assert_eq!(guard.model().generation().as_u64(), 1);
    assert_eq!(
        guard.model().mutation_state(),
        rustbgpd_evpn::EvpnRuntimeMutationState::Idle,
        "an unsupported candidate must not pin/degrade the runtime"
    );
}

#[tokio::test]
async fn reload_undecomposable_candidate_stays_preflight() {
    let baseline = load_runtime_test_config(ip_vrf_runtime_candidate_toml(), "test baseline");
    let mut candidate_toml = ip_vrf_redefined_l3vni_runtime_candidate_toml().to_string();
    candidate_toml.push_str(
        r#"
[[evpn_instances]]
vni = 300
rd = "65000:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.1"
"#,
    );
    let candidate = load_runtime_test_config(&candidate_toml, "test candidate");
    let coordinator = Arc::new(Mutex::new(rustbgpd_evpn::EvpnRuntimeCoordinator::new(
        baseline.resolve_evpn_instances().unwrap(),
        baseline.resolve_evpn_ip_vrfs().unwrap(),
        baseline.resolve_ethernet_segments().unwrap(),
    )));
    let reload_apply = EvpnRuntimeReloadApply::new(
        coordinator,
        Arc::new(tokio::sync::Mutex::new(())),
        Arc::new(ShapeCheckingConverger::new()),
        baseline,
    );
    let mutation_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let phase = mutation_started.clone();

    let attempt = reload_apply
        .apply_config_if_changed(
            &candidate,
            |_, _| true,
            move || phase.store(true, std::sync::atomic::Ordering::SeqCst),
        )
        .await;

    assert!(matches!(
        attempt.terminal,
        EvpnRuntimeReloadTerminal::RejectedNoEffect(_)
    ));
    assert!(
        !mutation_started.load(std::sync::atomic::Ordering::SeqCst),
        "rejected candidate must remain preflight"
    );
}
