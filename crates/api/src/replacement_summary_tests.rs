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
    Route, RouteOrigin,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    Afi, AspaValidation, AspaValidationContext, Ipv4Prefix, Origin, PathAttribute, Prefix,
    RpkiValidation, Safi,
};
use tokio::sync::{mpsc, oneshot};
use tonic::Request;

use crate::peer_types::PeerManagerOperatorQuery;
use crate::policy_service::PolicyService;
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
    let manager_task = tokio::spawn(manager.run());
    let (peer_tx, _peer_rx) = mpsc::channel(1);
    let (operator_tx, mut operator_rx) = mpsc::channel(8);
    let peer_task = tokio::spawn(async move {
        while let Some(query) = operator_rx.recv().await {
            match query {
                PeerManagerOperatorQuery::ListPeers { reply } => {
                    let _ = reply.send(vec![crate::test_support::peer_info(peer)]);
                }
                PeerManagerOperatorQuery::HasPeerAddress { address, reply } => {
                    let _ = reply.send(address == peer);
                }
                PeerManagerOperatorQuery::QueryPolicyDatasets { reply } => {
                    let _ = reply.send(Vec::new());
                }
                _ => panic!("unexpected operator query"),
            }
        }
    });
    let policy = Arc::new(
        PolicyService::new(AccessMode::ReadOnly, peer_tx.clone(), None, None)
            .with_rib_query(query_tx.clone())
            .with_operator_queries(operator_tx.clone())
            .with_rib_summary_queries(summary_tx.clone()),
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
    let mut policy_request = tokio::spawn({
        let policy = policy.clone();
        async move { stats(&policy, peer).await }
    });
    let mut neighbor_request = tokio::spawn({
        let neighbor = neighbor.clone();
        async move { neighbors(&neighbor).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while summary_tx.capacity() != 6 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both RPCs reached the real RIB summary lane");
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
        "checkpoint must have consumed both queued summaries"
    );
    let (actual_stats, actual_neighbors) = tokio::time::timeout(Duration::from_secs(1), async {
        (
            (&mut policy_request).await.unwrap(),
            (&mut neighbor_request).await.unwrap(),
        )
    })
    .await
    .unwrap_or_else(|error| {
        panic!(
            "operator RPCs incomplete while restore held: {error}; policy={}, neighbor={}",
            policy_request.is_finished(),
            neighbor_request.is_finished()
        )
    });
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
