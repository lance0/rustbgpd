use super::*;

use rustbgpd_api::peer_types::{
    ConfiguredOwnerPublicationError as PublicationError,
    ConfiguredOwnerPublicationOperation as PublicationOperation,
    ConfiguredOwnerPublicationReceipt as PublicationReceipt,
};
use rustbgpd_rib::dampening::{DampeningControlError, DampeningOwner};

fn owner_manager() -> (PeerManager, mpsc::Receiver<RibUpdate>) {
    let mut manager = dynamic_test_manager();
    let (rib_tx, rib_rx) = mpsc::channel(4);
    manager.rib_tx = rib_tx;
    (manager, rib_rx)
}

async fn begin(manager: &mut PeerManager) -> PublicationReceipt {
    manager
        .configured_owner_publication(PublicationOperation::Begin)
        .await
        .unwrap()
}

async fn publish(
    manager: &mut PeerManager,
    rib_rx: &mut mpsc::Receiver<RibUpdate>,
    receipt: PublicationReceipt,
) -> Vec<Arc<DampeningOwner>> {
    let (result, owners) = tokio::join!(
        manager.configured_owner_publication(PublicationOperation::Publish(receipt)),
        async {
            let RibUpdate::PublishDampeningOwners {
                publication,
                owners,
                reply,
            } = rib_rx.recv().await.unwrap()
            else {
                panic!("expected owner publication")
            };
            assert_eq!(publication, receipt.0);
            reply.send(Ok(())).unwrap();
            owners
        }
    );
    assert_eq!(result, Ok(receipt));
    owners
}

fn static_config(asn: u32) -> Config {
    load_test_config(&format!(
        "[global]\nasn = 65001\nrouter_id = '10.0.0.1'\nlisten_port = 1179\n\
         [global.telemetry]\nlog_format = 'json'\n\
         [[neighbors]]\naddress = '192.0.2.1'\nremote_asn = {asn}\n"
    ))
}

fn static_owner(manager: &mut PeerManager, asn: u32) -> Option<Arc<DampeningOwner>> {
    manager
        .configured_owner_admission_for_static(key("192.0.2.1".parse().unwrap()), asn)
        .unwrap()
        .map(|admission| admission.owner)
}

#[tokio::test]
async fn configured_owner_empty_startup_admits_commands_without_rib_publication() {
    let mut manager = test_peer_manager();
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    manager.rib_tx = rib_tx;
    let (tx, rx) = mpsc::channel(4);
    manager.rx = rx;
    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::Ping { reply }).await.unwrap();
    let task = tokio::spawn(manager.run());
    tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .expect("empty owner catalogue must not wait for a RIB acknowledgement")
        .unwrap();
    assert!(matches!(
        rib_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn configured_owner_startup_publication_precedes_command_admission() {
    let (mut manager, mut rib_rx) = owner_manager();
    let (tx, rx) = mpsc::channel(4);
    manager.rx = rx;
    let (reply, mut response) = oneshot::channel();
    tx.send(PeerManagerCommand::Ping { reply }).await.unwrap();
    let task = tokio::spawn(manager.run());
    let RibUpdate::PublishDampeningOwners {
        publication,
        owners,
        reply,
    } = rib_rx.recv().await.unwrap()
    else {
        panic!("expected initial owner publication")
    };
    assert_eq!(publication, 0);
    assert_eq!(owners.len(), 1);
    assert!(matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    reply.send(Ok(())).unwrap();
    response.await.unwrap();
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn configured_owner_tentative_delete_and_compensation_preserve_incarnation() {
    let (mut manager, mut rib_rx) = owner_manager();
    manager.replace_current_config(static_config(65002));
    let receipt = begin(&mut manager).await;
    let first = static_owner(&mut manager, 65002).unwrap();
    publish(&mut manager, &mut rib_rx, receipt).await;

    let prior = manager.current_config.clone();
    let tentative = begin(&mut manager).await;
    manager.current_config.neighbors.clear();
    assert_eq!(static_owner(&mut manager, 65002).unwrap(), first);
    manager.replace_current_config(prior);
    manager
        .configured_owner_publication(PublicationOperation::Discard(tentative))
        .await
        .unwrap();
    assert_eq!(static_owner(&mut manager, 65002).unwrap(), first);

    let unchanged = begin(&mut manager).await;
    manager.current_config.neighbors[0].description = Some("new label".into());
    publish(&mut manager, &mut rib_rx, unchanged).await;
    assert_eq!(static_owner(&mut manager, 65002).unwrap(), first);
}

#[tokio::test]
async fn configured_owner_committed_delete_readd_and_asn_change_allocate_fresh_tokens() {
    let (mut manager, mut rib_rx) = owner_manager();
    manager.replace_current_config(static_config(65002));
    let first_receipt = begin(&mut manager).await;
    let first = static_owner(&mut manager, 65002).unwrap();
    publish(&mut manager, &mut rib_rx, first_receipt).await;

    let deletion = begin(&mut manager).await;
    manager.current_config.neighbors.clear();
    assert_eq!(
        publish(&mut manager, &mut rib_rx, deletion).await,
        Vec::new()
    );
    assert!(static_owner(&mut manager, 65002).is_none());

    let readd = begin(&mut manager).await;
    manager.replace_current_config(static_config(65002));
    let second = static_owner(&mut manager, 65002).unwrap();
    assert_ne!(second, first);
    publish(&mut manager, &mut rib_rx, readd).await;
    assert_eq!(
        manager
            .configured_owner_publication(PublicationOperation::Publish(readd))
            .await,
        Ok(readd)
    );
    assert!(rib_rx.try_recv().is_err());
    assert_eq!(
        manager
            .configured_owner_publication(PublicationOperation::Publish(first_receipt))
            .await,
        Err(PublicationError::StaleAuthority)
    );

    let changed = begin(&mut manager).await;
    manager.current_config.neighbors[0].remote_asn = 65003;
    let third = static_owner(&mut manager, 65003).unwrap();
    assert_ne!(third, second);
    publish(&mut manager, &mut rib_rx, changed).await;
    assert!(static_owner(&mut manager, 65002).is_none());
}

#[tokio::test]
async fn configured_owner_dynamic_prefix_spelling_preserves_captured_range() {
    let (mut manager, mut rib_rx) = owner_manager();
    let accepted = manager.dynamic_ranges[0].accepted_attribution();
    let first = manager
        .configured_owner_admission_for_dynamic(&accepted, 0)
        .unwrap()
        .unwrap();
    let receipt = begin(&mut manager).await;
    manager.current_config.dynamic_neighbors[0].prefix = "127.99.12.34/8".into();
    publish(&mut manager, &mut rib_rx, receipt).await;
    let same = manager
        .configured_owner_admission_for_dynamic(&accepted, 0)
        .unwrap()
        .unwrap();
    assert_eq!(first.owner, same.owner);

    let changed = begin(&mut manager).await;
    manager.current_config.dynamic_neighbors[0].remote_asn = 65002;
    let replacement = manager
        .configured_owner_admission_for_dynamic(&accepted, 65002)
        .unwrap()
        .unwrap();
    assert_ne!(first.owner, replacement.owner);
    publish(&mut manager, &mut rib_rx, changed).await;
    assert_eq!(first.owner, same.owner, "captured sources remain immutable");
}

#[tokio::test]
async fn configured_owner_discarded_reservation_is_never_reused() {
    let (mut manager, mut rib_rx) = owner_manager();
    let failed = begin(&mut manager).await;
    let tentative = manager
        .configured_owner_admission_for_static(key("192.0.2.1".parse().unwrap()), 65002)
        .unwrap()
        .unwrap();
    assert!(!tentative.is_published());
    manager
        .configured_owner_publication(PublicationOperation::Discard(failed))
        .await
        .unwrap();
    assert!(static_owner(&mut manager, 65002).is_none());
    assert!(
        !tentative.is_published(),
        "discard cannot authorize a never-committed incarnation"
    );
    let accepted = begin(&mut manager).await;
    manager.replace_current_config(static_config(65002));
    let next = static_owner(&mut manager, 65002).unwrap();
    assert_ne!(tentative.owner, next);
    publish(&mut manager, &mut rib_rx, accepted).await;
}

#[tokio::test]
async fn configured_owner_failed_rib_ack_keeps_committed_catalogue() {
    for reject in [true, false] {
        let (mut manager, mut rib_rx) = owner_manager();
        let accepted = manager.dynamic_ranges[0].accepted_attribution();
        let original = manager
            .configured_owner_admission_for_dynamic(&accepted, 0)
            .unwrap()
            .unwrap();
        let receipt = begin(&mut manager).await;
        let candidate = manager
            .configured_owner_admission_for_dynamic(&accepted, 0)
            .unwrap()
            .unwrap();
        assert!(!candidate.is_published());
        manager.current_config.dynamic_neighbors.clear();
        let (result, ()) = tokio::join!(
            manager.configured_owner_publication(PublicationOperation::Publish(receipt)),
            async {
                let RibUpdate::PublishDampeningOwners { reply, .. } = rib_rx.recv().await.unwrap()
                else {
                    panic!("expected publication")
                };
                if reject {
                    reply
                        .send(Err(DampeningControlError::OwnerCapacity))
                        .unwrap();
                }
            }
        );
        if reject {
            assert!(matches!(result, Err(PublicationError::RibRejected(_))));
        } else {
            assert_eq!(result, Err(PublicationError::RibAcknowledgementLost));
        }
        let retained = manager
            .configured_owner_admission_for_dynamic(&accepted, 0)
            .unwrap()
            .unwrap();
        assert_eq!(original.owner, retained.owner);
        assert!(original.is_published());
        assert!(!candidate.is_published());
        assert!(
            !retained.is_published(),
            "failed acknowledgement cannot authorize pending captures"
        );
    }
}

#[tokio::test]
async fn configured_owner_static_role_change_waits_for_publication_ack() {
    let (mut manager, mut rib_rx) = owner_manager();
    let peer = key("192.0.2.1".parse().unwrap());
    let mut initial_config = static_config(65002);
    initial_config.neighbors[0].route_server_client = Some(true);
    manager.replace_current_config(initial_config);
    let initial = begin(&mut manager).await;
    let original = manager
        .configured_owner_admission_for_static(peer.clone(), 65002)
        .unwrap()
        .unwrap();
    publish(&mut manager, &mut rib_rx, initial).await;
    assert!(original.is_published());

    let changed = begin(&mut manager).await;
    manager.current_config.neighbors[0].route_server_client = Some(false);
    let candidate = manager
        .configured_owner_admission_for_static(peer.clone(), 65002)
        .unwrap()
        .unwrap();
    assert_eq!(
        candidate.owner, original.owner,
        "role-only changes preserve incarnation"
    );
    assert!(!candidate.is_published());
    assert!(
        original.is_published(),
        "new captures cannot revoke the committed context"
    );
    let (result, ()) = tokio::join!(
        manager.configured_owner_publication(PublicationOperation::Publish(changed)),
        async {
            let RibUpdate::PublishDampeningOwners { owners, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected role-change publication")
            };
            assert_eq!(owners, vec![original.owner.clone()]);
            assert!(
                !candidate.is_published(),
                "RIB queue admission is not publication acknowledgement"
            );
            assert!(original.is_published());
            reply.send(Ok(())).unwrap();
        }
    );
    assert_eq!(result, Ok(changed));
    assert!(candidate.is_published());
    assert!(original.is_published());
    let committed = manager
        .configured_owner_admission_for_static(peer, 65002)
        .unwrap()
        .unwrap();
    assert_eq!(committed.owner, original.owner);
    assert!(committed.is_published());
}

#[tokio::test]
async fn configured_owner_dynamic_children_share_pending_publication_authority() {
    let (mut manager, mut rib_rx) = owner_manager();
    let accepted = manager.dynamic_ranges[0].accepted_attribution();
    let original = manager
        .configured_owner_admission_for_dynamic(&accepted, 0)
        .unwrap()
        .unwrap();
    assert!(original.is_published());
    let changed = begin(&mut manager).await;
    let first = manager
        .configured_owner_admission_for_dynamic(&accepted, 0)
        .unwrap()
        .unwrap();
    let second = manager
        .configured_owner_admission_for_dynamic(&accepted, 0)
        .unwrap()
        .unwrap();
    assert_eq!(first.owner, original.owner);
    assert_eq!(second.owner, original.owner);
    assert!(!first.is_published());
    assert!(!second.is_published());
    // Dynamic recovery is child-local even when its publication is shared.
    first.acknowledge_capacity_disable();
    assert!(!second.capacity_disable_complete());
    assert!(!original.capacity_disable_complete());
    let (result, ()) = tokio::join!(
        manager.configured_owner_publication(PublicationOperation::Publish(changed)),
        async {
            let RibUpdate::PublishDampeningOwners { owners, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected dynamic owner publication")
            };
            assert_eq!(owners, vec![original.owner.clone()]);
            assert!(!first.is_published());
            assert!(!second.is_published());
            assert!(original.is_published());
            reply.send(Ok(())).unwrap();
        }
    );
    assert_eq!(result, Ok(changed));
    assert!(first.is_published());
    assert!(
        second.is_published(),
        "all captures must share the one acknowledged authority"
    );
    assert!(original.is_published());
}

#[tokio::test]
async fn configured_owner_static_compensation_authorizes_restored_capture() {
    let (mut manager, mut rib_rx) = owner_manager();
    let peer = key("192.0.2.1".parse().unwrap());
    manager.replace_current_config(static_config(65002));
    let initial = begin(&mut manager).await;
    let original = manager
        .configured_owner_admission_for_static(peer.clone(), 65002)
        .unwrap()
        .unwrap();
    publish(&mut manager, &mut rib_rx, initial).await;
    assert!(original.is_published());
    let prior = manager.current_config.clone();

    let failed = begin(&mut manager).await;
    manager.current_config.neighbors[0].route_server_client = Some(true);
    let candidate = manager
        .configured_owner_admission_for_static(peer.clone(), 65002)
        .unwrap()
        .unwrap();
    assert_eq!(candidate.owner, original.owner);
    assert!(!candidate.is_published());
    assert!(original.is_published());

    // Model the publication step of clean compensation: lifecycle callers
    // join candidate producers, then restore configuration and capture the
    // replacement context before settling Discard.
    manager.replace_current_config(prior);
    let restored = manager
        .configured_owner_admission_for_static(peer.clone(), 65002)
        .unwrap()
        .unwrap();
    assert_eq!(restored.owner, original.owner);
    assert!(
        !restored.is_published(),
        "restored capture still waits for compensation settlement"
    );
    manager
        .configured_owner_publication(PublicationOperation::Discard(failed))
        .await
        .unwrap();
    assert!(restored.is_published());
    assert!(original.is_published());
    let committed = manager
        .configured_owner_admission_for_static(peer, 65002)
        .unwrap()
        .unwrap();
    assert_eq!(committed.owner, restored.owner);
    assert!(committed.is_published());
    assert!(
        matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "discard settles against the unchanged committed RIB publication"
    );
}
