//! Mutations preserve the configured interface neighbor's policy and state.

use rustbgpd_api::peer_types::{ConfigEvent, OwnedCatalogMutation, OwnedCatalogMutationOutcome};

use super::*;

fn policy_config(extra: &str) -> crate::config::Config {
    config_with(&format!(
        "[policy.definitions.allow]\ndefault_action = \"permit\"\n\
         [policy.definitions.deny]\ndefault_action = \"deny\"\n{extra}"
    ))
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "all four chain events share the persistence and scoped live-target proof"
)]
async fn scoped_chain_edits_persist_and_reach_only_the_selected_binding() {
    let mut h = harness(&[], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.reload(policy_config(&format!(
        "{}{}",
        port_stanza("swp1", ""),
        port_stanza("swp2", "")
    )))
    .await;
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(2, 8))).await;
    let selected = swp1_key(2);
    let sibling = PeerKey::new(IpAddr::V6(ll(2)), Some("swp2".into()));
    let session = h.session(&selected);
    let _ = h.mgr.peers.replace_handle(
        &selected,
        acking_policy_handle(selected.address, SessionState::Established),
        session,
    );
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let mut rib_rx = std::mem::replace(&mut h.rib_rx, mpsc::channel(1).1);
    let rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = update {
                observed_tx.send(peer).unwrap();
                let _ = reply.send(Ok(()));
            }
        }
    });
    for import in [true, false] {
        for set in [true, false] {
            let names = vec!["allow".to_string()];
            let address = selected.address;
            let interface = selected.interface.clone();
            let (mutation, event) = match (import, set) {
                (true, true) => (
                    OwnedCatalogMutation::SetNeighborImportChain {
                        address,
                        interface: interface.clone(),
                        policy_names: names.clone(),
                    },
                    ConfigEvent::SetNeighborImportChain {
                        address,
                        interface,
                        policy_names: names.clone(),
                        ack: None,
                    },
                ),
                (false, true) => (
                    OwnedCatalogMutation::SetNeighborExportChain {
                        address,
                        interface: interface.clone(),
                        policy_names: names.clone(),
                    },
                    ConfigEvent::SetNeighborExportChain {
                        address,
                        interface,
                        policy_names: names.clone(),
                        ack: None,
                    },
                ),
                (true, false) => (
                    OwnedCatalogMutation::ClearNeighborImportChain {
                        address,
                        interface: interface.clone(),
                    },
                    ConfigEvent::ClearNeighborImportChain {
                        address,
                        interface,
                        ack: None,
                    },
                ),
                (false, false) => (
                    OwnedCatalogMutation::ClearNeighborExportChain {
                        address,
                        interface: interface.clone(),
                    },
                    ConfigEvent::ClearNeighborExportChain {
                        address,
                        interface,
                        ack: None,
                    },
                ),
            };
            assert!(
                crate::policy_admin::neighbor_policy_chains_from_config(
                    &h.mgr.current_config,
                    &selected
                )
                .is_some()
            );
            // The persistence bridge applies this same event before dispatch.
            let mut persisted = h.mgr.current_config.clone();
            crate::policy_admin::apply_config_event(&mut persisted, &event).unwrap();
            let document = crate::config::persisted_config_document(&persisted).unwrap();
            let persisted: crate::config::Config = toml::from_str(&document).unwrap();
            let (reply, response) = oneshot::channel();
            let _ = Box::pin(
                h.mgr
                    .dispatch_command(PeerManagerCommand::OwnedCatalogMutation { mutation, reply }),
            )
            .await;
            let outcome = response.await.unwrap();
            assert!(
                matches!(outcome, OwnedCatalogMutationOutcome::Success),
                "{outcome:?}"
            );
            let stanza = h
                .mgr
                .current_config
                .neighbors
                .interface_only_on("swp1")
                .unwrap();
            let persisted = persisted.neighbors.interface_only_on("swp1").unwrap();
            let (configured, stored, live) = if import {
                (
                    &stanza.import_policy_chain,
                    &persisted.import_policy_chain,
                    &h.mgr.peers[&selected].import_policy,
                )
            } else {
                (
                    &stanza.export_policy_chain,
                    &persisted.export_policy_chain,
                    &h.mgr.peers[&selected].export_policy,
                )
            };
            assert_eq!(configured, stored);
            assert_eq!(configured.is_empty(), !set);
            assert_eq!(live.is_some(), set);
            assert!(h.mgr.peers[&sibling].import_policy.is_none());
            assert!(h.mgr.peers[&sibling].export_policy.is_none());
            if !import {
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(1), observed_rx.recv())
                        .await
                        .expect("the selected export apply reached the RIB")
                        .unwrap(),
                    h.mgr.rib_peer_of(&selected)
                );
            }
        }
    }
    rib_task.abort();
}

#[tokio::test]
async fn a_late_terminal_notice_survives_retirement_but_not_neighbor_deletion() {
    for change in ["carrier", "recreated", "settings", "deleted"] {
        let mut h = harness_with(
            &["swp1"],
            &[("swp1", 7, true)],
            "max_prefixes = 100\nmax_prefix_restart_seconds = 60\n",
            "",
            None,
        );
        recording_launcher(&mut h.mgr);
        h.bind("swp1", Some(endpoint(2, 7))).await;
        let old = swp1_key(2);
        let session_id = h.session(&old);
        let notices = h.mgr.session_notify_tx.clone();
        let (commands, mut receiver) = mpsc::channel(8);
        let handle = PeerHandle::from_parts(
            commands,
            tokio::spawn(async move {
                while let Some(command) = receiver.recv().await {
                    match command {
                        PeerCommand::QueryState { reply } => {
                            let _ = reply.send(policy_test_peer_state(
                                IpAddr::V6(ll(2)),
                                SessionState::Established,
                            ));
                        }
                        PeerCommand::Shutdown => {
                            // Shutdown is queued after both initial owner drains.
                            notices
                                .send(SessionNotification::MaxPrefixExceeded {
                                    session_id,
                                    role: rustbgpd_transport::SessionRole::Primary,
                                    peer_addr: IpAddr::V6(ll(2)),
                                    count: 101,
                                    bound: 100,
                                    family: None,
                                    received: false,
                                    path_limit: false,
                                })
                                .unwrap();
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(())
            }),
        );
        let _ = h.mgr.peers.replace_handle(&old, handle, session_id);
        match change {
            "carrier" => {
                h.links_changed(snapshot(true, &[("swp1", 7, false)]));
                h.reconcile().await;
                h.links_changed(snapshot(true, &[("swp1", 7, true)]));
            }
            "recreated" => {
                h.links_changed(snapshot(true, &[("swp1", 8, true)]));
                h.reconcile().await;
            }
            "settings" => {
                let mut candidate = h.mgr.current_config.clone();
                let mut stanza = candidate
                    .neighbors
                    .interface_only_on("swp1")
                    .unwrap()
                    .clone();
                stanza.hold_time = Some(30);
                candidate.neighbors.set_interface_only("swp1", Some(stanza));
                h.reload(candidate).await;
            }
            "deleted" => {
                h.reload(config_with("")).await;
                assert!(!h.mgr.max_prefix_latches.contains_key(&old));
                h.reload(config_with(&port_stanza("swp1", ""))).await;
            }
            _ => unreachable!(),
        }
        h.bind(
            "swp1",
            Some(endpoint(2, if change == "recreated" { 8 } else { 7 })),
        )
        .await;
        let replacement = h
            .mgr
            .peers
            .get(&old)
            .unwrap_or_else(|| panic!("{change}: expected rebound peer {old}"));
        assert_eq!(replacement.enabled, change == "deleted", "{change}");
        assert_eq!(
            h.mgr.max_prefix_latches.contains_key(&old),
            change != "deleted",
            "{change}"
        );
        if change != "deleted" {
            assert_eq!(h.mgr.max_prefix_latches[&old].source_session_id, session_id);
            assert!(
                h.mgr.max_prefix_latches[&old].deadline.is_some(),
                "the retiring session's timed restart survives"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "bound and unbound edits share exact old/new deadline, cancellation, and manual-enable controls"
)]
async fn restart_duration_edits_rearm_bound_and_unbound_neighbors_at_the_edit() {
    for bound in [true, false] {
        let mut h = harness_with(
            &["swp1"],
            &[("swp1", 7, true)],
            "max_prefixes = 100\nmax_prefix_restart_seconds = 60\n",
            "",
            None,
        );
        h.bind("swp1", Some(endpoint(2, 7))).await;
        let key = swp1_key(2);
        let start = tokio::time::Instant::now();
        let session = h.session(&key);
        h.mgr
            .install_max_prefix_latch(key.clone(), session, "max-prefix".into(), Some(60));
        h.mgr.peers.get_mut(&key).unwrap().enabled = false;
        tokio::time::advance(Duration::from_secs(30)).await;
        if !bound {
            h.links_changed(snapshot(true, &[("swp1", 7, false)]));
            h.reconcile().await;
        }
        let mut candidate = h.mgr.current_config.clone();
        let mut stanza = candidate
            .neighbors
            .interface_only_on("swp1")
            .unwrap()
            .clone();
        stanza.max_prefix_restart_seconds = std::num::NonZeroU32::new(600);
        candidate.neighbors.set_interface_only("swp1", Some(stanza));
        h.reload(candidate).await;
        if bound {
            assert_eq!(
                h.mgr.max_prefix_latches[&key].deadline,
                Some(start + Duration::from_secs(630))
            );
        } else {
            let rows = h.mgr.unbound_interface_only_infos();
            assert_eq!(rows[0].max_prefix_restart_remaining_millis, Some(600_000));
        }
        tokio::time::advance(Duration::from_secs(31)).await;
        if !bound {
            h.links_changed(snapshot(true, &[("swp1", 7, true)]));
            h.bind("swp1", Some(endpoint(2, 7))).await;
        }
        h.mgr.handle_due_max_prefix_restarts().await;
        assert!(
            !h.mgr.peers[&key].enabled,
            "the old deadline cannot start the peer"
        );
        assert_eq!(
            h.mgr.max_prefix_latches[&key].deadline,
            Some(start + Duration::from_secs(630))
        );

        let deadline = h.mgr.max_prefix_latches[&key].deadline;
        let mut candidate = h.mgr.current_config.clone();
        let mut stanza = candidate
            .neighbors
            .interface_only_on("swp1")
            .unwrap()
            .clone();
        stanza.hold_time = Some(45);
        candidate.neighbors.set_interface_only("swp1", Some(stanza));
        h.reload(candidate).await;
        assert_eq!(
            h.mgr.max_prefix_latches[&key].deadline, deadline,
            "unchanged duration"
        );
        let starts = Arc::new(FakePeerCounters::default());
        let session = h.session(&key);
        let _ = h.mgr.peers.replace_handle(
            &key,
            fake_peer_handle(key.address, SessionState::Idle, None, Arc::clone(&starts)),
            session,
        );
        let deadline = deadline.unwrap();
        let before_deadline = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        tokio::time::advance(before_deadline).await;
        h.mgr.handle_due_max_prefix_restarts().await;
        assert!(!h.mgr.peers[&key].enabled, "not before the edited deadline");
        assert_eq!(starts.start.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_millis(1)).await;
        h.mgr.handle_due_max_prefix_restarts().await;
        wait_counter(&starts.start, 1).await;
        assert!(h.mgr.peers[&key].enabled, "automatic restart at t=630");
        assert!(!h.mgr.max_prefix_latches.contains_key(&key));
        h.mgr.handle_due_max_prefix_restarts().await;
        assert_eq!(
            starts.start.load(Ordering::SeqCst),
            1,
            "one automatic attempt"
        );

        // A new incident then exercises cancellation and explicit enable.
        h.mgr
            .install_max_prefix_latch(key.clone(), session, "max-prefix again".into(), Some(600));
        h.mgr.peers.get_mut(&key).unwrap().enabled = false;
        for duration in [None, std::num::NonZeroU32::new(600)] {
            if !bound {
                h.links_changed(snapshot(true, &[("swp1", 7, false)]));
                h.reconcile().await;
            }
            let mut candidate = h.mgr.current_config.clone();
            let mut stanza = candidate
                .neighbors
                .interface_only_on("swp1")
                .unwrap()
                .clone();
            stanza.max_prefix_restart_seconds = duration;
            candidate.neighbors.set_interface_only("swp1", Some(stanza));
            h.reload(candidate).await;
            if !bound {
                assert_eq!(
                    h.mgr.unbound_interface_only_infos()[0].max_prefix_restart_remaining_millis,
                    None
                );
                h.links_changed(snapshot(true, &[("swp1", 7, true)]));
                h.bind("swp1", Some(endpoint(2, 7))).await;
            }
            assert_eq!(
                h.mgr.max_prefix_latches[&key].deadline, None,
                "an indefinite latch gains no countdown"
            );
            assert!(!h.mgr.peers[&key].enabled);
        }
        h.mgr.enable_peer(key.clone()).await.unwrap();
        assert!(h.mgr.peers[&key].enabled);
        assert!(!h.mgr.max_prefix_latches.contains_key(&key));
    }
}

#[tokio::test]
async fn lifetime_counters_follow_the_neighbor_until_its_stanza_is_deleted() {
    for change in ["address", "carrier", "settings", "recreated"] {
        let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
        recording_launcher(&mut h.mgr);
        h.bind("swp1", Some(endpoint(2, 7))).await;
        let original = h.mgr.peers[&swp1_key(2)]
            .transport_config
            .neighbor_counters
            .clone();
        original.record_update_received();
        original.record_update_sent();
        original.record_flap();
        original.record_notification_received();
        original.record_notification_sent();
        original.record_otc_routes_blocked(3);
        original.record_import_policy_routes(5, 7);
        original
            .export_policy()
            .add(rustbgpd_rib::NeighborPolicyStats {
                export_policy_routes_permitted: 11,
                export_policy_routes_denied: 13,
                ..Default::default()
            });
        h.mgr
            .metrics
            .record_message_received("interface:swp1", "update");
        h.mgr
            .metrics
            .record_message_sent("interface:swp1", "update");
        match change {
            "address" => h.bind("swp1", Some(endpoint(3, 7))).await,
            "carrier" => {
                h.links_changed(snapshot(true, &[("swp1", 7, false)]));
                h.reconcile().await;
                h.links_changed(snapshot(true, &[("swp1", 7, true)]));
                h.bind("swp1", Some(endpoint(2, 7))).await;
            }
            "settings" => {
                h.reload(config_with(&port_stanza("swp1", "hold_time = 30\n")))
                    .await;
            }
            "recreated" => {
                h.links_changed(snapshot(true, &[("swp1", 8, true)]));
                h.reconcile().await;
                h.bind("swp1", Some(endpoint(2, 8))).await;
            }
            _ => unreachable!(),
        }
        let key = swp1_key(if change == "address" { 3 } else { 2 });
        let counters = &h
            .mgr
            .peers
            .get(&key)
            .unwrap_or_else(|| panic!("{change}: expected rebound peer {key}"))
            .transport_config
            .neighbor_counters;
        assert!(counters.same_block(&original), "{change}");
        assert_eq!(counters.updates_received(), 1);
        assert_eq!(counters.updates_sent(), 1);
        assert!(counters.flaps() >= 1);

        // Deleting an already-unbound neighbor also ends its counter block.
        h.links_changed(snapshot(true, &[("swp1", 7, false)]));
        h.reconcile().await;
        let unbound = h.mgr.unbound_interface_only_infos();
        let row = &unbound[0];
        assert_eq!((row.updates_received, row.updates_sent), (1, 1));
        assert_eq!((row.notifications_received, row.notifications_sent), (1, 1));
        assert_eq!((row.messages_received, row.messages_sent), (1, 1));
        assert_eq!(row.otc_routes_blocked, 3);
        assert_eq!(
            (
                row.import_policy_routes_permitted,
                row.import_policy_routes_denied
            ),
            (5, 7)
        );
        assert_eq!(
            (
                row.export_policy_routes_permitted,
                row.export_policy_routes_denied
            ),
            (11, 13)
        );
        assert!(row.flap_count >= 1);
        h.reload(config_with("")).await;
        h.reload(config_with(&port_stanza("swp1", ""))).await;
        h.links_changed(snapshot(true, &[("swp1", 7, true)]));
        h.bind("swp1", Some(endpoint(2, 7))).await;
        let fresh = &h.mgr.peers[&swp1_key(2)].transport_config.neighbor_counters;
        assert!(!fresh.same_block(&original));
        assert_eq!(fresh.updates_received(), 0);
        assert_eq!(fresh.updates_sent(), 0);
        assert_eq!(fresh.flaps(), 0);
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the queued selector proof shares unbound, rebound, sibling, and invalid-selector controls"
)]
async fn a_scoped_chain_edit_resolves_an_unbound_stanza_and_its_current_binding() {
    let mut h = harness(&[], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.reload(policy_config(&format!(
        "{}{}",
        port_stanza("swp1", ""),
        port_stanza("swp2", "")
    )))
    .await;
    let selector = PeerKey::new(IpAddr::V6(ll(99)), Some("swp1".into()));
    h.bind("swp1", Some(endpoint(99, 7))).await;
    assert!(
        crate::policy_admin::neighbor_policy_chains_from_config(&h.mgr.current_config, &selector,)
            .is_some()
    );
    // The RPC parsed its valid selector before waiting for the mutation
    // coordinator. Its interface still owns the neighbor after a rebind.
    h.links_changed(snapshot(true, &[("swp1", 7, false), ("swp2", 8, true)]));
    h.reconcile().await;
    h.bind("swp2", Some(endpoint(99, 8))).await;
    h.links_changed(snapshot(true, &[("swp1", 7, true), ("swp2", 8, true)]));
    let (reply, response) = oneshot::channel();
    let _ = Box::pin(
        h.mgr
            .dispatch_command(PeerManagerCommand::ListRejectedRoutes {
                peer: selector.clone(),
                reply,
            }),
    )
    .await;
    assert!(
        response.await.unwrap().is_none(),
        "session reads keep their stale-scope NOT_FOUND result"
    );
    for bound in [None, Some(endpoint(2, 7))] {
        h.bind("swp1", bound).await;
        if bound.is_some() {
            let peer = swp1_key(2);
            let session = h.session(&peer);
            let _ = h.mgr.peers.replace_handle(
                &peer,
                acking_policy_handle(peer.address, SessionState::Idle),
                session,
            );
        }
        for name in ["allow", "deny"] {
            let (reply, response) = oneshot::channel();
            let _ = Box::pin(
                h.mgr
                    .dispatch_command(PeerManagerCommand::OwnedCatalogMutation {
                        mutation: OwnedCatalogMutation::SetNeighborExportChain {
                            address: selector.address,
                            interface: selector.interface.clone(),
                            policy_names: vec![name.into()],
                        },
                        reply,
                    }),
            )
            .await;
            assert!(matches!(
                response.await.unwrap(),
                OwnedCatalogMutationOutcome::Success
            ));
            let stanza = h
                .mgr
                .current_config
                .neighbors
                .interface_only_on("swp1")
                .unwrap();
            assert_eq!(stanza.export_policy_chain, [name]);
            if bound.is_some() {
                assert_eq!(
                    h.mgr.peers[&swp1_key(2)].export_policy,
                    h.mgr
                        .current_config
                        .interface_only_policy_chains(stanza)
                        .unwrap()
                        .1
                );
            }
            let sibling = PeerKey::new(IpAddr::V6(ll(99)), Some("swp2".into()));
            assert!(h.mgr.peers[&sibling].export_policy.is_none());
        }
    }
    let before = h.mgr.current_config.clone();
    for (address, interface) in [
        ("192.0.2.1".parse().unwrap(), "swp1"),
        (IpAddr::V6(ll(99)), "missing"),
    ] {
        let (reply, response) = oneshot::channel();
        let _ = Box::pin(
            h.mgr
                .dispatch_command(PeerManagerCommand::OwnedCatalogMutation {
                    mutation: OwnedCatalogMutation::SetNeighborExportChain {
                        address,
                        interface: Some(interface.into()),
                        policy_names: vec!["allow".into()],
                    },
                    reply,
                }),
        )
        .await;
        assert!(matches!(
            response.await.unwrap(),
            OwnedCatalogMutationOutcome::RejectedNoEffect(_)
        ));
        assert_eq!(h.mgr.current_config, before);
    }
}

#[tokio::test(start_paused = true)]
async fn a_mixed_group_edit_waits_for_the_binding_policy_to_converge() {
    Box::pin(policy_timeout_requires_convergence(PolicyMutation::Commit)).await;
}

#[tokio::test(start_paused = true)]
async fn restoring_a_binding_policy_waits_for_rib_convergence() {
    Box::pin(policy_timeout_requires_convergence(PolicyMutation::Restore)).await;
}

#[tokio::test(start_paused = true)]
async fn a_failed_mixed_group_edit_restores_the_rib_after_a_state_query_timeout() {
    Box::pin(policy_timeout_requires_convergence(
        PolicyMutation::Compensate,
    ))
    .await;
}

#[derive(Clone, Copy)]
enum PolicyMutation {
    Commit,
    Restore,
    Compensate,
}

#[expect(
    clippy::too_many_lines,
    reason = "forward and restore share one controlled post-ack timeout and authoritative RIB proof"
)]
async fn policy_timeout_requires_convergence(path: PolicyMutation) {
    let mut h = harness(&[], &[("swp1", 7, true)]);
    let static_member = if matches!(path, PolicyMutation::Compensate) {
        "[[neighbors]]\naddress = \"192.0.2.7\"\nremote_asn = 65002\npeer_group = \"fabric\"\n"
    } else {
        ""
    };
    h.reload(policy_config(&format!(
        "[peer_groups.fabric]\nhold_time = 30\nmax_prefixes = 10\nexport_policy_chain = [\"allow\"]\n{static_member}{}",
        port_stanza("swp1", "peer_group = \"fabric\"\nhold_time = 60\nmax_prefixes = 50\n")
    )))
    .await;
    if matches!(path, PolicyMutation::Compensate) {
        insert_test_managed_peer(
            &mut h.mgr,
            "192.0.2.7".parse().unwrap(),
            closed_peer_handle(),
            false,
        );
    }
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let key = swp1_key(2);
    let session = h.session(&key);
    let prior = h.mgr.peers[&key].export_policy.clone();
    let mut desired = h.mgr.current_config.clone();
    desired
        .peer_groups
        .get_mut("fabric")
        .unwrap()
        .export_policy_chain = vec!["deny".into()];
    let requested = desired
        .interface_only_policy_chains(desired.neighbors.interface_only_on("swp1").unwrap())
        .unwrap()
        .1;
    let expected = if matches!(path, PolicyMutation::Compensate) {
        prior.clone()
    } else {
        requested.clone()
    };
    let accepted = Arc::new(Mutex::new(prior.clone()));
    let accepted_by_session = Arc::clone(&accepted);
    let (queries, mut held_queries) = mpsc::unbounded_channel();
    let (commands, mut receiver) = mpsc::channel(8);
    let handle = PeerHandle::from_parts(
        commands,
        tokio::spawn(async move {
            let mut queries_seen = 0;
            let held_query = if matches!(path, PolicyMutation::Compensate) {
                2
            } else {
                1
            };
            while let Some(command) = receiver.recv().await {
                match command {
                    PeerCommand::UpdateExportPolicy { policy, reply } => {
                        *accepted_by_session.lock().unwrap() = policy.map(|policy| *policy);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::UpdateImportPolicy { reply, .. }
                    | PeerCommand::SendRouteRefresh { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        queries_seen += 1;
                        if queries_seen == held_query {
                            queries.send(reply).unwrap();
                        } else {
                            let _ = reply.send(policy_test_peer_state(
                                key.address,
                                SessionState::Established,
                            ));
                        }
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        }),
    );
    let key = swp1_key(2);
    let _ = h.mgr.peers.replace_handle(&key, handle, session);
    let installed = Arc::new(Mutex::new(prior));
    let observed = Arc::clone(&installed);
    let mut rib_rx = std::mem::replace(&mut h.rib_rx, mpsc::channel(1).1);
    let rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy {
                export_policy,
                reply,
                ..
            } = update
            {
                *observed.lock().unwrap() = export_policy;
                let _ = reply.send(Ok(()));
            }
        }
    });
    let apply = async {
        if matches!(path, PolicyMutation::Restore) {
            assert!(
                h.mgr
                    .restore_interface_only_policies(vec![
                        rustbgpd_api::peer_types::ResolvedPeerPolicy {
                            address: key.address,
                            interface: key.interface.clone(),
                            import_policy: None,
                            export_policy: requested.clone(),
                        },
                    ])
                    .await
            );
        } else {
            let mut definition = crate::policy_admin::config_peer_group_to_api(
                &h.mgr.current_config.peer_groups["fabric"],
            );
            if matches!(path, PolicyMutation::Compensate) {
                definition.max_prefixes = Some(20);
            } else {
                definition.hold_time = Some(45);
            }
            definition.export_policy_chain = vec!["deny".into()];
            let (reply, response) = oneshot::channel();
            let _ = Box::pin(
                h.mgr
                    .dispatch_command(PeerManagerCommand::OwnedCatalogMutation {
                        mutation: OwnedCatalogMutation::SetPeerGroup {
                            name: "fabric".into(),
                            definition: Box::new(definition),
                        },
                        reply,
                    }),
            )
            .await;
            let outcome = response.await.unwrap();
            if matches!(path, PolicyMutation::Compensate) {
                assert!(
                    matches!(
                        outcome,
                        OwnedCatalogMutationOutcome::CompensationAmbiguous(_)
                    ),
                    "{outcome:?}"
                );
            } else {
                assert!(
                    matches!(outcome, OwnedCatalogMutationOutcome::Success),
                    "{outcome:?}"
                );
            }
        }
    };
    let hold_state_reply = async {
        let mut reply = held_queries.recv().await.unwrap();
        assert_eq!(
            *accepted.lock().unwrap(),
            expected,
            "session accepted the requested forward or restore chain before its state query stalls"
        );
        tokio::time::advance(PEER_QUERY_TIMEOUT + Duration::from_millis(1)).await;
        reply.closed().await;
        // The timed-out query may still answer after the owner has moved on.
        let _ = reply.send(policy_test_peer_state(
            IpAddr::V6(ll(2)),
            SessionState::Established,
        ));
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(apply, hold_state_reply);
    })
    .await
    .expect("the controlled state timeout and policy settlement complete");
    assert_eq!(
        *installed.lock().unwrap(),
        expected,
        "RIB installed the requested forward or restore chain"
    );
    assert_eq!(h.mgr.peers[&key].export_policy, expected);
    assert_eq!(*accepted.lock().unwrap(), expected);
    if matches!(path, PolicyMutation::Compensate) {
        assert_eq!(
            h.mgr.current_config.peer_groups["fabric"].max_prefixes,
            Some(10)
        );
    }
    assert!(
        !h.mgr.peers[&key].pending_export_apply,
        "success owes no export apply"
    );
    h.reconcile().await;
    assert_eq!(
        h.session(&key),
        session,
        "the member overrides the changed timer"
    );
    rib_task.abort();
}
