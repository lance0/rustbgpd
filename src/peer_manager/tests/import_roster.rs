//! The published import roster (ADR-0136) against the real peer manager:
//! every peer-table transition republishes the exact projection, retired
//! sessions are released, and `GetPolicyStats` succeeds without the owner.

use super::*;
use rustbgpd_api::import_roster::{ImportCaptureProgress, ImportRosterReader, capture_import};
use rustbgpd_api::proto::policy_service_server::PolicyService as PolicyServiceRpc;
use rustbgpd_transport::handle::InstalledImportPolicy;
use std::sync::Weak;

/// A fake session owning its import publication: installed with `chain`
/// (evaluated `evals` times) until the task stops, which closes it.
fn published_handle(chain: Option<&PolicyChain>, evals: usize) -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel::<PeerCommand>(8);
    if let Some(chain) = chain {
        let context = rustbgpd_policy::RouteContext {
            prefix: None,
            next_hop: None,
            extended_communities: &[],
            communities: &[],
            large_communities: &[],
            as_path_str: "",
            as_path: None,
            as_path_len: 0,
            origin_asn: None,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            family: None,
            evpn_route_type: None,
            local_pref: None,
            med: None,
        };
        for _ in 0..evals {
            let _ = chain.evaluate(&context);
        }
    }
    let (publication, receiver) = tokio::sync::watch::channel(Some(installed_policy(0, chain)));
    let task = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                break;
            }
        }
        drop(publication);
        Ok(())
    });
    PeerHandle::from_parts_with_import_policy_counters(commands, task, receiver)
}

/// The installed descriptor the roster designates for `peer`.
fn designated(roster: &ImportRosterReader, peer: IpAddr) -> Weak<InstalledImportPolicy> {
    let roster = roster.load();
    let row = roster.unique_peer(peer).expect("peer is on the roster");
    Arc::downgrade(row.publication.borrow().as_ref().expect("installed"))
}

async fn capture_all(
    roster: &ImportRosterReader,
) -> Result<
    Vec<(IpAddr, rustbgpd_transport::ImportPolicyTermHits)>,
    rustbgpd_transport::handle::ImportPolicyStatsError,
> {
    let roster = roster.load();
    capture_import(
        roster.peers(),
        tokio::time::Instant::now() + Duration::from_secs(2),
        &mut ImportCaptureProgress::default(),
    )
    .await
}

/// A retired descriptor is freed once its session exits and no roster or
/// reader holds it.
async fn assert_released(retired: &Weak<InstalledImportPolicy>, what: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while retired.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}: the retired session's descriptor is still retained"));
}

/// Collision promotion and notification replacement swap the current
/// session in one step: the next read succeeds on the new handle with no
/// `SessionGone`, and the retired session's descriptor is freed. Deletion
/// and dataset rebinding republish too; after every step the published
/// roster equals the manager's projection.
#[tokio::test]
async fn roster_follows_replacement_deletion_and_rebinding() {
    let mut mgr = test_peer_manager();
    let roster = mgr.import_roster();
    let peer: IpAddr = "192.0.2.10".parse().unwrap();
    let first_chain = named_deny_policy_chain(&[Some("first-in")]);
    insert_test_managed_peer(
        &mut mgr,
        peer,
        published_handle(Some(&first_chain), 2),
        false,
    );
    mgr.assert_import_roster_projection();
    assert_eq!(roster.load().peers().len(), 1);
    let first = designated(&roster, peer);

    // Inbound collision: the candidate becomes the primary.
    let second_chain = named_deny_policy_chain(&[Some("second-in")]);
    mgr.peers.get_mut(&key(peer)).unwrap().pending_inbound = Some(PendingInbound {
        handle: published_handle(Some(&second_chain), 5),
        session_id: 77,
    });
    let (retired, retired_id, promoted_id) =
        mgr.promote_pending_inbound_handle(&key(peer)).unwrap();
    assert_eq!(promoted_id, 77);
    mgr.assert_import_roster_projection();
    assert_eq!(roster.load().unique_peer(peer).unwrap().session_id, 77);
    retired.shutdown().await.unwrap().unwrap();
    mgr.unregister_session(retired_id);
    let rows = capture_all(&roster)
        .await
        .expect("the promoted session reads without SessionGone");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1.evals, 5, "counters of the promoted session");
    assert_released(&first, "collision promotion").await;

    // Notification replacement of an unstoppable primary.
    let second = designated(&roster, peer);
    mgr.replace_unstoppable_primary(&key(peer)).await;
    mgr.assert_import_roster_projection();
    let replaced_id = roster.load().unique_peer(peer).unwrap().session_id;
    assert_ne!(replaced_id, 77);
    assert_eq!(replaced_id, mgr.peers[&key(peer)].session_id());
    let rows = capture_all(&roster)
        .await
        .expect("the replacement reads without SessionGone");
    assert!(
        rows.is_empty(),
        "the respawned session installed no import chain"
    );
    assert_released(&second, "notification replacement").await;

    // Dataset rebinding through the single config setter.
    let dir = tempfile::tempdir().unwrap();
    mgr.replace_current_config(super::wait_sites::dataset_generation_config(dir.path()));
    mgr.assert_import_roster_projection();
    let datasets = roster.load();
    assert_eq!(datasets.datasets().len(), 1);
    assert_eq!(datasets.datasets()[0].handle.name().as_ref(), "customers");
    assert!(datasets.datasets()[0].path.ends_with("customers.list"));

    // Peer deletion.
    mgr.delete_peer_checked(key(peer), false, None, false, None)
        .await
        .unwrap();
    mgr.assert_import_roster_projection();
    assert!(roster.load().peers().is_empty());
    assert!(!roster.is_closed());
}

/// Dynamic accept inserts the accepted session and its expiry removes it;
/// the expired session's descriptor is freed once readers drop.
#[tokio::test]
async fn roster_follows_dynamic_accept_and_expiry() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::channel(1).1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        make_dynamic_manager_config(),
    );
    let roster = mgr.import_roster();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let _client_stream = client.await.unwrap();
    let peer = remote_addr.ip();

    mgr.handle_inbound(server_stream, sock(peer), None, None)
        .await;
    mgr.assert_import_roster_projection();
    let accepted = roster.load();
    assert_eq!(accepted.peers().len(), 1);
    assert!(mgr.peers[&key(peer)].is_dynamic);
    // The real session publishes at construction; a chainless session adds
    // no row but reads successfully.
    assert!(capture_all(&roster).await.unwrap().is_empty());
    let accepted_session = Arc::downgrade(
        accepted.peers()[0]
            .publication
            .borrow()
            .as_ref()
            .expect("constructed session published"),
    );

    let session_id = mgr.peers[&key(peer)].session_id();
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: peer,
    })
    .await;
    mgr.assert_import_roster_projection();
    assert!(roster.load().peers().is_empty());
    assert!(
        accepted_session.upgrade().is_some(),
        "a reader still holding the old roster keeps its snapshot"
    );
    drop(accepted);
    assert_released(&accepted_session, "dynamic expiry").await;
}

/// A bulk peer operation publishes the roster once at its end, however
/// many peers it adds, removes or replaces (ADR-0136's one publication per
/// operation), and the result is the exact projection.
#[tokio::test]
async fn bulk_reconcile_publishes_the_roster_once() {
    const ADDED: u8 = 16;

    let mut mgr = test_peer_manager();
    let roster = mgr.import_roster();
    let peer = |index: u8| IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100 + index));
    let before = roster.load().version();
    let added = (0..ADDED)
        .map(|index| make_config(peer(index), 65100))
        .collect();
    let outcome = mgr.reconcile_peers(added, Vec::new(), Vec::new()).await;
    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    mgr.assert_import_roster_projection();
    assert_eq!(roster.load().peers().len(), usize::from(ADDED));
    assert_eq!(
        roster.load().version(),
        before + 1,
        "adding {ADDED} peers is one publication"
    );

    let before = roster.load().version();
    let removed = (0..ADDED / 2).map(|index| key(peer(index))).collect();
    let changed = (ADDED / 2..ADDED - 2)
        .map(|index| {
            let mut config = make_config(peer(index), 65100);
            config.hold_time = Some(30);
            config
        })
        .collect();
    let added = (ADDED..ADDED + 4)
        .map(|index| make_config(peer(index), 65100))
        .collect();
    let outcome = mgr.reconcile_peers(added, removed, changed).await;
    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);
    mgr.assert_import_roster_projection();
    assert_eq!(roster.load().peers().len(), usize::from(ADDED / 2 + 4));
    assert_eq!(
        roster.load().version(),
        before + 1,
        "removing, replacing and adding peers is one publication"
    );
    for (_, managed) in mgr.peers.drain() {
        let _ = managed.into_parts().0.shutdown().await;
    }
}

/// Shutdown drains the table and its dataset bindings, publishing an empty
/// roster, and the exiting owner closes the cell.
#[tokio::test]
async fn shutdown_drains_the_roster_and_closes_the_cell() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    mgr.replace_current_config(super::wait_sites::dataset_generation_config(dir.path()));
    let roster = mgr.import_roster();
    assert_eq!(roster.load().datasets().len(), 1);
    let peer: IpAddr = "192.0.2.20".parse().unwrap();
    insert_test_managed_peer(&mut mgr, peer, published_handle(None, 0), false);
    let running = designated(&roster, peer);
    let actor = tokio::spawn(mgr.run());
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
    let drained = roster.load();
    assert!(drained.peers().is_empty(), "drain published no peers");
    assert!(
        drained.datasets().is_empty(),
        "a shutting-down daemon publishes no dataset rows"
    );
    assert!(roster.is_closed(), "the stopped owner closed the cell");
    assert_released(&running, "shutdown").await;
}

/// ADR-0136 held owner: with the peer manager's operator and ordinary lanes
/// never polled, a `both` request with datasets succeeds from the published
/// roster. Before the roster, peer validation, import and datasets queued
/// on the operator lane and this request returned `DEADLINE_EXCEEDED`.
#[tokio::test(start_paused = true)]
async fn policy_stats_succeed_while_the_peer_manager_is_never_polled() {
    use rustbgpd_api::server::AccessMode;

    let dir = tempfile::tempdir().unwrap();
    let (command_tx, command_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut mgr = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_operator_queries(operator_rx);
    mgr.replace_current_config(super::wait_sites::dataset_generation_config(dir.path()));
    let peer: IpAddr = "192.0.2.30".parse().unwrap();
    let chain = named_deny_policy_chain(&[Some("held-in")]);
    insert_test_managed_peer(&mut mgr, peer, published_handle(Some(&chain), 3), false);

    let (query_tx, mut query_rx) = mpsc::channel(4);
    let rib = tokio::spawn(async move {
        while let Some(update) = query_rx.recv().await {
            let RibUpdate::QueryExportPolicyTermHits { reply, .. } = update else {
                panic!("unexpected RIB query");
            };
            let _ = reply.send(Vec::new());
        }
    });
    let service = rustbgpd_api::PolicyService::with_runtime_config_coordinator(
        AccessMode::ReadOnly,
        command_tx.clone(),
        None,
        None,
        rustbgpd_api::server::RuntimeConfigCoordinator::new(),
    )
    .with_operator_queries(operator_tx.clone())
    .with_rib_query(query_tx)
    .with_import_roster(mgr.import_roster());
    let started = tokio::time::Instant::now();
    let response = service
        .get_policy_stats(tonic::Request::new(
            rustbgpd_api::proto::GetPolicyStatsRequest {
                peer_address: peer.to_string(),
                direction: "both".to_string(),
            },
        ))
        .await
        .expect("stats succeed without the peer manager")
        .into_inner();
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(response.chains.len(), 1);
    assert_eq!(response.chains[0].direction, "import");
    assert_eq!(response.chains[0].routes_evaluated, 3);
    assert_eq!(response.datasets.len(), 1);
    assert_eq!(response.datasets[0].name, "customers");
    assert_eq!(response.datasets[0].records, 1);
    // Neither lane was ever served or needed.
    assert_eq!(operator_tx.capacity(), operator_tx.max_capacity());
    assert_eq!(command_tx.capacity(), command_tx.max_capacity());
    drop(service);
    rib.await.unwrap();
    for (_, managed) in mgr.peers.drain() {
        managed.into_parts().0.shutdown().await.unwrap().unwrap();
    }
}

/// A request held in its capture while the real peer manager is dropped
/// returns `UNAVAILABLE` once it resumes, not the values it captured.
#[tokio::test]
async fn policy_stats_fail_when_the_peer_manager_stops_mid_capture() {
    use rustbgpd_api::server::AccessMode;

    let mut mgr = test_peer_manager();
    let peer: IpAddr = "192.0.2.40".parse().unwrap();
    let (commands, _command_rx) = mpsc::channel(1);
    let (publication, receiver) = tokio::sync::watch::channel(None);
    insert_test_managed_peer(
        &mut mgr,
        peer,
        PeerHandle::from_parts_with_import_policy_counters(
            commands,
            tokio::spawn(std::future::pending()),
            receiver,
        ),
        false,
    );
    let (peer_tx, _) = mpsc::channel(1);
    let service = rustbgpd_api::PolicyService::with_runtime_config_coordinator(
        AccessMode::ReadOnly,
        peer_tx,
        None,
        None,
        rustbgpd_api::server::RuntimeConfigCoordinator::new(),
    )
    .with_import_roster(mgr.import_roster());
    let read = tokio::spawn(async move {
        service
            .get_policy_stats(tonic::Request::new(
                rustbgpd_api::proto::GetPolicyStatsRequest {
                    peer_address: String::new(),
                    direction: "import".to_string(),
                },
            ))
            .await
    });
    // The roster and the handle hold one receiver each; the capture's
    // Pending cursor is the third.
    while publication.receiver_count() < 3 {
        tokio::task::yield_now().await;
    }
    drop(mgr);
    publication.send_replace(Some(installed_policy(0, None)));
    let error = read.await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert_eq!(error.message(), "peer manager stopped");
}
