//! Actual RIB ownership regression. The encoder holds two production probes;
//! the peer-manager harness supplies the independent first/last RPC stages.

use std::any::Any;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustbgpd_policy::{NamedPolicy, PolicyChain, rpol::RpolFile, sets::SetStore};
use rustbgpd_rib::{
    ExactExportCandidate, ExactExportEncoder, ExactExportError, ExactExportResult,
    ExactExportSnapshot, PeerExportPolicyReplacement, RibManager, RibSummaryQuery, RibUpdate,
    Route, RouteOrigin, SelectionDeferralConfig, SelectionDeferralWaiterConfig,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    Afi, AspaValidation, AspaValidationContext, Ipv4Prefix, Origin, PathAttribute, Prefix,
    RpkiValidation, Safi,
};
use tokio::sync::{mpsc, oneshot};
use tonic::Request;

use crate::control_service::ControlService;
use crate::peer_types::{
    EnqueuedOperatorQuery, PeerManagerOperatorQuery, PeerManagerReadinessQuery,
};
use crate::policy_service::PolicyService;
use crate::proto::control_service_server::ControlService as ControlRpc;
use crate::proto::neighbor_service_server::NeighborService as NeighborRpc;
use crate::proto::policy_service_server::PolicyService as PolicyRpc;
use crate::server::AccessMode;
use crate::{NeighborService, proto};

struct ProbeHold {
    armed: AtomicBool,
    calls: AtomicUsize,
    entered: mpsc::UnboundedSender<usize>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

#[derive(Clone)]
struct HeldEncoder(Arc<ProbeHold>);

impl ExactExportEncoder for HeldEncoder {
    fn owner_id(&self) -> u64 {
        1
    }
    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot> {
        Arc::new(self.clone())
    }
}

impl ExactExportSnapshot for HeldEncoder {
    fn owner_id(&self) -> u64 {
        1
    }
    fn generation(&self) -> u64 {
        1
    }
    fn probe_announcement(
        &self,
        _candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError> {
        if self.0.armed.load(Ordering::SeqCst) {
            let call = self.0.calls.fetch_add(1, Ordering::SeqCst);
            if call < 2 {
                self.0.entered.send(call).unwrap();
                self.0
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .expect("test releases held probe");
                if call == 0 {
                    // Cross the production 25ms service interval before the
                    // next probe. This bounds fixture timing, not an RPC budget.
                    std::thread::sleep(Duration::from_millis(30));
                }
            }
        }
        Ok(ExactExportResult {
            encoded_len: 64,
            max_len: 4096,
            generation: 1,
        })
    }
    fn probe_announcements_with_checkpoint(
        &self,
        candidates: &[ExactExportCandidate<'_>],
        checkpoint: &mut dyn FnMut(),
    ) -> Vec<Result<ExactExportResult, ExactExportError>> {
        candidates
            .iter()
            .copied()
            .map(|candidate| {
                checkpoint();
                let result = self.probe_announcement(candidate);
                checkpoint();
                result
            })
            .collect()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn chain(community: u32) -> PolicyChain {
    let source = format!("policy out {{ term all {{ add community 65000:{community}; accept }} }}");
    let compiled = RpolFile::parse(&source)
        .unwrap()
        .compile_policy("out", &[], &mut SetStore::new())
        .unwrap();
    PolicyChain::from_named(vec![NamedPolicy::from_rpol(
        "out".to_string(),
        Arc::new(compiled),
    )])
}

fn route(index: u8) -> Route {
    let source = Ipv4Addr::new(192, 0, 2, 9);
    Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, index, 0), 24)),
        peer: source.into(),
        next_hop: source.into(),
        link_local_next_hop: None,
        next_hop_scope: None,
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: std::time::Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: source,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        aspa_context: AspaValidationContext::default(),
    }
}

async fn stats(service: &PolicyService, peer: IpAddr) -> proto::GetPolicyStatsResponse {
    PolicyRpc::get_policy_stats(
        service,
        Request::new(proto::GetPolicyStatsRequest {
            peer_address: peer.to_string(),
            direction: "export".to_string(),
        }),
    )
    .await
    .unwrap()
    .into_inner()
}

async fn neighbors(service: &NeighborService) -> proto::ListNeighborsResponse {
    NeighborRpc::list_neighbors(service, Request::new(proto::ListNeighborsRequest {}))
        .await
        .unwrap()
        .into_inner()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end fixture holds an actual RIB restore and checks both API projections before its acknowledgement"
)]
async fn replacement_summaries_complete_api_reads_inside_actual_rib_restore() {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let hold = Arc::new(ProbeHold {
        armed: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let (rib_tx, rib_rx) = mpsc::channel(16);
    let (query_tx, query_rx) = mpsc::channel(8);
    let (summary_tx, summary_rx) = mpsc::channel::<RibSummaryQuery>(8);
    let manager = RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new())
        .with_summary_queries(summary_rx);
    let export_roster = manager.export_roster();
    let manager_task = tokio::spawn(manager.run());
    let (peer_tx, _peer_rx) = mpsc::channel(1);
    let (operator_tx, mut operator_rx) = mpsc::channel::<EnqueuedOperatorQuery>(8);
    let peer_task = tokio::spawn(async move {
        while let Some(query) = operator_rx.recv().await {
            match query.query {
                PeerManagerOperatorQuery::ListPeers { reply } => {
                    let _ = reply.send(vec![crate::test_support::peer_info(peer)]);
                }
                _ => panic!("unexpected operator query"),
            }
        }
    });
    let (_publication, receiver) = tokio::sync::watch::channel(None);
    let roster = crate::import_roster::test_support::publisher(
        vec![crate::import_roster::test_support::peer(
            &peer.to_string(),
            receiver,
        )],
        Vec::new(),
    );
    let policy = Arc::new(
        PolicyService::new(AccessMode::ReadOnly, peer_tx.clone(), None, None)
            .with_rib_query(query_tx.clone())
            .with_operator_queries(operator_tx.clone())
            .with_import_roster(roster.reader())
            .with_export_roster(export_roster),
    );
    let neighbor = Arc::new(
        NeighborService::new(65000, AccessMode::ReadOnly, peer_tx, query_tx.clone(), None)
            .with_operator_queries(operator_tx)
            .with_rib_summary_queries(summary_tx.clone()),
    );
    rib_tx
        .send(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id: 0,
            encoder: Arc::new(HeldEncoder(hold.clone())),
        })
        .await
        .unwrap();
    let (outbound_tx, mut outbound_rx) = mpsc::channel(32);
    let outbound_task = tokio::spawn(async move { while outbound_rx.recv().await.is_some() {} });
    rib_tx
        .send(RibUpdate::PeerUp {
            peer,
            session_id: 0,
            peer_asn: 65001,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
            outbound_tx,
            export_policy: Some(chain(1)),
            sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();
    rib_tx
        .send(RibUpdate::RoutesReceived {
            peer: "192.0.2.9".parse().unwrap(),
            session_id: 0,
            announced: (0..4).map(route).collect(),
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    let baseline_neighbors = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let response = neighbors(&neighbor).await;
            if response.neighbors[0].prefixes_sent == 4 {
                break response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let baseline_stats = stats(&policy, peer).await;
    assert!(baseline_stats.chains[0].routes_evaluated >= 4);
    assert!(!baseline_stats.chains[0].terms.is_empty());
    hold.armed.store(true, Ordering::SeqCst);
    let (restore_reply, mut restore_response) = oneshot::channel();
    rib_tx
        .send(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements: vec![PeerExportPolicyReplacement {
                peer,
                export_policy: Some(chain(2)),
            }],
            reply: restore_reply,
        })
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), entered_rx.recv())
            .await
            .unwrap(),
        Some(0)
    );
    // A general query queued before the operator summaries must remain fenced.
    let (general_reply, mut general_response) = oneshot::channel();
    query_tx
        .send(RibUpdate::QueryLocRibCount {
            reply: general_reply,
        })
        .await
        .unwrap();
    let started = std::time::Instant::now();
    // Export statistics read the RIB's published roster (ADR-0136): they
    // complete while the restore still holds the RIB, reporting the
    // instances of the last completed operation.
    let actual_stats = tokio::time::timeout(Duration::from_secs(1), stats(&policy, peer))
        .await
        .expect("export statistics do not wait for the held RIB");
    let mut neighbor_request = tokio::spawn({
        let neighbor = neighbor.clone();
        async move { neighbors(&neighbor).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while summary_tx.capacity() != 7 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the neighbor RPC reached the real RIB summary lane");
    release_tx.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), entered_rx.recv())
            .await
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        summary_tx.capacity(),
        8,
        "checkpoint must have consumed the queued summary"
    );
    let actual_neighbors = tokio::time::timeout(Duration::from_secs(1), &mut neighbor_request)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "neighbor RPC incomplete while restore held: {error}; neighbor={}",
                neighbor_request.is_finished()
            )
        })
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(actual_stats, baseline_stats);
    assert_eq!(actual_neighbors, baseline_neighbors);
    assert!(matches!(
        restore_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        general_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    release_tx.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), restore_response)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    assert_eq!(general_response.await.unwrap(), 4);
    assert_eq!(neighbors(&neighbor).await.neighbors[0].prefixes_sent, 4);
    manager_task.abort();
    peer_task.abort();
    outbound_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_completes_inside_actual_rib_initial_export() {
    health_completes_inside_actual_rib_export(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_completes_inside_actual_rib_selection_release() {
    health_completes_inside_actual_rib_export(true).await;
}

#[expect(
    clippy::too_many_lines,
    reason = "shared end-to-end fixture holds real export and proves health completion and command fencing before owner release"
)]
async fn health_completes_inside_actual_rib_export(selection_release: bool) {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let source: IpAddr = "192.0.2.9".parse().unwrap();
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let hold = Arc::new(ProbeHold {
        armed: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let (rib_tx, rib_rx) = mpsc::channel(16);
    let (query_tx, query_rx) = mpsc::channel(8);
    let (readiness_tx, readiness_rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new())
        .with_readiness_queries(readiness_rx);
    if selection_release {
        manager = manager.with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: source,
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            }],
        });
    }
    let manager_task = tokio::spawn(manager.run());
    let (peer_tx, _peer_rx) = mpsc::channel(1);
    let (peer_readiness_tx, mut peer_readiness_rx) = mpsc::channel(8);
    let peer_task = tokio::spawn(async move {
        while let Some(query) = peer_readiness_rx.recv().await {
            match query {
                PeerManagerReadinessQuery::ListPeers { reply } => {
                    let _ = reply.send(vec![crate::test_support::peer_info(peer)]);
                }
                PeerManagerReadinessQuery::Ping { .. } => panic!("unexpected readiness query"),
            }
        }
    });
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    let service = ControlService::new(
        AccessMode::ReadOnly,
        tokio::time::Instant::now(),
        BgpMetrics::new(),
        peer_tx,
        query_tx.clone(),
        shutdown_tx,
        None,
    )
    .with_peer_manager_readiness(peer_readiness_tx)
    .with_rib_readiness(readiness_tx.clone());
    let (source_tx, _source_rx) = mpsc::channel(32);
    if selection_release {
        rib_tx
            .send(RibUpdate::SetPeerGracefulRestartContext {
                peer: source,
                session_id: 1,
                peer_restart_state: false,
                peer_gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
                peer_enhanced_refresh: true,
                peer_llgr_families: Vec::new(),
                local_llgr_stale_time: 0,
            })
            .await
            .unwrap();
        rib_tx
            .send(export_peer_up(source, 1, source_tx))
            .await
            .unwrap();
    }
    // Selection remains deferred until the source EoR; without deferral these
    // routes seed the table before the destination's initial registration.
    rib_tx
        .send(RibUpdate::RoutesReceived {
            peer: source,
            session_id: u64::from(selection_release),
            announced: (0..4).map(route).collect(),
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    rib_tx
        .send(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id: 0,
            encoder: Arc::new(HeldEncoder(hold.clone())),
        })
        .await
        .unwrap();
    let (outbound_tx, mut outbound_rx) = mpsc::channel(32);
    rib_tx
        .send(export_peer_up(peer, 0, outbound_tx))
        .await
        .unwrap();
    if selection_release {
        // The command-lane barrier proves all four routes reached Adj-RIB-In
        // while the live Loc-RIB is still empty, before release recomputes it.
        let (reply, response) = oneshot::channel();
        rib_tx
            .send(RibUpdate::QueryLocRibCount { reply })
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), response)
                .await
                .unwrap()
                .unwrap(),
            0
        );
        let before = ControlRpc::get_health(&service, Request::new(proto::HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(before.total_routes, 0);
        assert!(outbound_rx.try_recv().is_err(), "selection gate holds EoR");
        rib_tx
            .send(RibUpdate::EndOfRib {
                peer: source,
                session_id: 1,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            })
            .await
            .unwrap();
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), entered_rx.recv())
            .await
            .unwrap(),
        Some(0)
    );
    let (general_reply, mut general_response) = oneshot::channel();
    query_tx
        .send(RibUpdate::QueryLocRibCount {
            reply: general_reply,
        })
        .await
        .unwrap();
    // A mutation with an acknowledgement must stay queued too. The absent
    // injection leaves the four-route expectation unchanged after dispatch.
    let (mutation_reply, mut mutation_response) = oneshot::channel();
    rib_tx
        .send(RibUpdate::WithdrawInjected {
            prefix: route(255).prefix,
            path_id: 0,
            reply: mutation_reply,
        })
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let mut health_request = tokio::spawn(async move {
        ControlRpc::get_health(&service, Request::new(proto::HealthRequest {})).await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while readiness_tx.capacity() != 7 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("GetHealth reached the real RIB readiness lane");
    release_tx.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), entered_rx.recv())
            .await
            .unwrap(),
        Some(1)
    );
    let readiness_capacity = readiness_tx.capacity();
    let health = tokio::time::timeout(Duration::from_secs(1), &mut health_request).await;
    let elapsed = started.elapsed();
    let calls = hold.calls.load(Ordering::SeqCst);
    let general_fenced = matches!(
        general_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    );
    let mutation_fenced = matches!(
        mutation_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    );
    let outbound_held = outbound_rx.try_recv().is_err();
    // Capture all results while the owner is held, then release it before
    // asserting so a failing negative control does not strand the probe.
    release_tx.send(()).unwrap();
    assert_eq!(
        readiness_capacity, 8,
        "export checkpoint must consume the queued readiness request"
    );
    let health = health
        .expect("GetHealth must complete while the export owner remains held")
        .unwrap()
        .expect("GetHealth retains its 200 ms readiness deadline")
        .into_inner();
    assert!(elapsed < crate::health_probe::CORE_READINESS_DEADLINE);
    assert!(health.healthy);
    assert_eq!(health.total_routes, 4);
    assert_eq!(calls, 2);
    assert!(general_fenced);
    assert!(mutation_fenced);
    assert!(outbound_held, "export is still held");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), general_response)
            .await
            .unwrap()
            .unwrap(),
        4
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), mutation_response)
            .await
            .unwrap()
            .unwrap(),
        Err(rustbgpd_rib::RibCommandError::NotFound(_))
    ));
    let mut announced = 0;
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(update) = outbound_rx.recv().await {
            announced += update.announce.len();
            if !update.end_of_rib.is_empty() {
                assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::Unicast)]);
                return;
            }
        }
        panic!("outbound closed before initial EoR");
    })
    .await
    .expect("export finishes with EoR after probe release");
    assert_eq!(announced, 4);
    manager_task.abort();
    peer_task.abort();
}

fn export_peer_up(
    peer: IpAddr,
    session_id: u64,
    outbound_tx: mpsc::Sender<rustbgpd_rib::OutboundRouteUpdate>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
        outbound_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    }
}
