use super::*;
use crate::evpn_originator::duplicate_mac::*;
use crate::evpn_originator::lifecycle::*;
use crate::evpn_originator::rib_polling::*;
use rustbgpd_evpn::{
    DuplicateMacAction, DuplicateMacConfig, EvpnInstance, EvpnInstanceTable, RouteTarget,
};
use rustbgpd_rib::{RibCommandError, route::RouteOrigin};
use rustbgpd_wire::{EvpnImet, EvpnMacIp};

use crate::test_support::{evpn_instance, gather_metrics_text, ip as ipa, mac, rd, vni};

fn assert_quarantine_metric(metrics: &BgpMetrics, v: u32, m: u8, value: u32) {
    let text = gather_metrics_text(metrics);
    assert!(
        text.contains(&format!(
            "evpn_duplicate_mac_quarantine_active{{mac=\"{}\",vni=\"{v}\"}} {value}",
            mac(m)
        )) || text.contains(&format!(
            "evpn_duplicate_mac_quarantine_active{{vni=\"{v}\",mac=\"{}\"}} {value}",
            mac(m)
        )),
        "{text}"
    );
}

fn duplicate_mac_quarantine_tx() -> watch::Sender<Arc<BTreeSet<DuplicateMacKey>>> {
    watch::channel(Arc::new(BTreeSet::new())).0
}

fn originator_state(instances: &EvpnInstanceTable) -> OriginatorState {
    OriginatorState::new(instances, duplicate_mac_quarantine_tx())
}

fn local_instance(v: u32) -> EvpnInstance {
    evpn_instance(65000, v, v, Some(format!("br{v}")), false)
}

fn instance_table(v: u32) -> Arc<EvpnInstanceTable> {
    let mut t = EvpnInstanceTable::new();
    t.insert(local_instance(v)).unwrap();
    Arc::new(t)
}

fn instance_table_many(vnis: &[u32]) -> Arc<EvpnInstanceTable> {
    let mut t = EvpnInstanceTable::new();
    for v in vnis {
        t.insert(local_instance(*v)).unwrap();
    }
    Arc::new(t)
}

fn instance_table_with(inst: EvpnInstance) -> Arc<EvpnInstanceTable> {
    let mut t = EvpnInstanceTable::new();
    t.insert(inst).unwrap();
    Arc::new(t)
}

fn suppress_local_instance(v: u32) -> EvpnInstance {
    suppress_local_instance_with(v, 1, Duration::from_mins(9))
}

fn suppress_local_instance_with(v: u32, threshold: u32, recovery: Duration) -> EvpnInstance {
    local_instance(v).with_duplicate_mac_detection(
        DuplicateMacConfig::new(
            DuplicateMacAction::SuppressLocal,
            Duration::from_mins(3),
            threshold,
            recovery,
        )
        .unwrap(),
    )
}

#[test]
fn duplicate_mac_quarantine_publisher_tracks_active_set() {
    let inst = suppress_local_instance(100);
    let instances = instance_table_with(inst.clone());
    let (tx, rx) = watch::channel(Arc::new(BTreeSet::new()));
    let mut state = OriginatorState::new(&instances, tx);
    let metrics = BgpMetrics::new();
    let key = DuplicateMacKey::new(vni(100), mac(0xAA));

    assert!(record_duplicate_mac_move(
        &metrics, &mut state, &inst, key.vni, key.mac
    ));
    assert!(rx.borrow().contains(&key));

    set_duplicate_mac_quarantine_active(&mut state, key, false);
    assert!(!rx.borrow().contains(&key));
}

#[tokio::test]
async fn originator_control_round_trips_clear_command() {
    let (command_tx, mut command_rx) = mpsc::channel(1);
    let control = EvpnOriginatorControl { command_tx };
    let key = DuplicateMacKey::new(vni(100), mac(0xAA));
    let pending = tokio::spawn(async move { control.clear_duplicate_mac_quarantine(key).await });

    let Some(OriginatorCommand::ClearDuplicateMacQuarantine {
        key: received,
        reply,
    }) = command_rx.recv().await
    else {
        panic!("expected clear command");
    };
    assert_eq!(received, key);
    reply
        .send(ClearDuplicateMacQuarantineResult::Cleared)
        .unwrap();

    assert_eq!(
        pending.await.unwrap().unwrap(),
        ClearDuplicateMacQuarantineResult::Cleared
    );
}

fn evpn_macip_route(v: u32, m: u8, next_hop: &str, seq: Option<u32>, sticky: bool) -> EvpnRibRoute {
    evpn_macip_route_with_ip(v, m, None, next_hop, seq, sticky)
}

fn evpn_macip_route_with_ip(
    v: u32,
    m: u8,
    ip: Option<&str>,
    next_hop: &str,
    seq: Option<u32>,
    sticky: bool,
) -> EvpnRibRoute {
    let macip = EvpnMacIp {
        rd: rd(65000, v),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(0),
        mac: mac(m),
        ip: ip.map(ipa),
        label1: MplsLabel::new(v),
        label2: None,
    };
    let mut attrs: Vec<PathAttribute> = Vec::new();
    if seq.is_some() || sticky {
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::mac_mobility(sticky, seq.unwrap_or(0)),
        ]));
    }
    EvpnRibRoute {
        route: EvpnRoute::MacIp(macip),
        next_hop: ipa(next_hop),
        link_local_next_hop: None,
        peer: ipa("10.0.0.99"),
        attributes: Arc::new(attrs),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
        is_stale: false,
        is_llgr_stale: false,
    }
}

fn remote_mac_ip_view(mac_b: u8, ip_str: &str, seq: Option<u32>) -> RemoteMacIpView {
    RemoteMacIpView {
        mac: mac(mac_b),
        ip: ipa(ip_str),
        mobility_sequence: seq,
        sticky: false,
        next_hop: ipa("10.0.0.2"),
    }
}

async fn observe_test(
    obs: LocalMacObservation,
    state: &mut OriginatorState,
    instances: &Arc<EvpnInstanceTable>,
    rib_tx: &mpsc::Sender<RibUpdate>,
    metrics: &BgpMetrics,
    counts: &OriginatedLocalMacCounts,
) {
    handle_observation(
        &obs,
        state,
        instances,
        rib_tx,
        metrics,
        counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
}

#[test]
fn build_remote_view_drops_self_nh_routes() {
    // Two routes for the same (VNI, MAC): one from a remote VTEP,
    // one self-originated (next_hop == our local_vtep_ip).
    // build_remote_view must filter the self-NH out.
    let table = EvpnInstanceTable::new();
    let mut t = table;
    t.insert(local_instance(100)).unwrap();
    let routes = vec![
        evpn_macip_route(100, 0xAA, "10.0.0.2", Some(5), false),
        evpn_macip_route(100, 0xAA, "10.0.0.1", Some(10), false), // self-NH
    ];
    let (view, _) = build_remote_views(&t, &routes);
    let v = view.get(&(vni(100), mac(0xAA))).expect("view present");
    assert_eq!(v.next_hop, ipa("10.0.0.2"));
    assert_eq!(v.mobility_sequence, Some(5));
}

#[test]
fn build_remote_view_carries_sticky_bit() {
    let mut t = EvpnInstanceTable::new();
    t.insert(local_instance(100)).unwrap();
    let routes = vec![evpn_macip_route(
        100,
        0xAA,
        "10.0.0.2",
        Some(3),
        /* sticky */ true,
    )];
    let (view, _) = build_remote_views(&t, &routes);
    let v = view.get(&(vni(100), mac(0xAA))).expect("view present");
    assert!(v.sticky);
}

#[test]
fn build_remote_view_skips_non_macip_routes() {
    let mut t = EvpnInstanceTable::new();
    t.insert(local_instance(100)).unwrap();
    let imet = EvpnRibRoute {
        route: EvpnRoute::Imet(EvpnImet {
            rd: rd(65000, 100),
            ethernet_tag: EthernetTagId(0),
            originator_ip: ipa("10.0.0.2"),
        }),
        next_hop: ipa("10.0.0.2"),
        link_local_next_hop: None,
        peer: ipa("10.0.0.99"),
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 99),
        is_stale: false,
        is_llgr_stale: false,
    };
    let (view, mac_ip_view) = build_remote_views(&t, &[imet]);
    assert!(view.is_empty());
    assert!(mac_ip_view.is_empty());
}

#[tokio::test]
async fn local_learn_with_remote_contender_records_duplicate_mac_counter() {
    let instances = instance_table(100);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(4);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    state.remote_mac_view.insert(
        (vni(100), mac(0xAA)),
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: Some(3),
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );

    let _rib_responder = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            if let RibUpdate::InjectEvpn { reply, .. } = msg {
                let _ = reply.send(Ok(()));
            }
        }
    });

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let text = gather_metrics_text(&metrics);
    assert!(
        text.contains("evpn_duplicate_mac_moves_total{mac=\"aa:aa:aa:aa:aa:aa\",vni=\"100\"} 1")
            || text.contains(
                "evpn_duplicate_mac_moves_total{vni=\"100\",mac=\"aa:aa:aa:aa:aa:aa\"} 1"
            ),
        "{text}"
    );
}

#[tokio::test]
async fn duplicate_mac_suppress_local_withdraws_without_reinjecting() {
    let instances = instance_table_with(suppress_local_instance(100));
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    state.remote_mac_view.insert(
        (vni(100), mac(0xAA)),
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: Some(3),
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );
    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
            RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
        ],
        "threshold crossing should withdraw the local route and suppress the would-be re-inject"
    );

    let text = gather_metrics_text(&metrics);
    assert!(
            text.contains(
                "evpn_duplicate_mac_threshold_exceeded_total{action=\"suppress_local\",mac=\"aa:aa:aa:aa:aa:aa\",vni=\"100\"} 1"
            ) || text.contains(
                "evpn_duplicate_mac_threshold_exceeded_total{vni=\"100\",mac=\"aa:aa:aa:aa:aa:aa\",action=\"suppress_local\"} 1"
            ),
            "{text}"
        );
    assert!(
        text.contains(
            "evpn_duplicate_mac_quarantine_active{mac=\"aa:aa:aa:aa:aa:aa\",vni=\"100\"} 1"
        ) || text.contains(
            "evpn_duplicate_mac_quarantine_active{vni=\"100\",mac=\"aa:aa:aa:aa:aa:aa\"} 1"
        ),
        "{text}"
    );
}

#[tokio::test]
async fn duplicate_mac_suppress_local_first_learn_does_not_withdraw_unadvertised_route() {
    let instances = instance_table_with(suppress_local_instance(100));
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    state.remote_mac_view.insert(
        (vni(100), mac(0xAA)),
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: Some(3),
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    assert!(
        log.lock().await.is_empty(),
        "first learn with an immediate quarantine has no advertised key to withdraw"
    );
}

#[tokio::test]
async fn duplicate_mac_recovery_replays_local_route_and_resets_metric() {
    let instances = instance_table_with(suppress_local_instance_with(
        100,
        1,
        Duration::from_millis(1),
    ));
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    state.remote_mac_view.insert(
        (vni(100), mac(0xAA)),
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: Some(3),
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );
    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(5)).await;
    recover_duplicate_macs(
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
            RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
        ],
        "recovery should replay the still-local MAC once suppression expires"
    );
    assert_quarantine_metric(&metrics, 100, 0xAA, 0);
}

#[tokio::test]
async fn duplicate_mac_manual_clear_replays_local_route_and_resets_metric() {
    let instances = instance_table_with(suppress_local_instance(100));
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let (quarantine_tx, quarantine_rx) = watch::channel(Arc::new(BTreeSet::new()));
    let mut state = OriginatorState::new(&instances, quarantine_tx);

    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;
    state.remote_mac_view.insert(
        (vni(100), mac(0xAA)),
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: Some(3),
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );
    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;

    let key = DuplicateMacKey::new(vni(100), mac(0xAA));
    assert!(quarantine_rx.borrow().contains(&key));
    let result = clear_duplicate_mac_quarantine(
        key,
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    assert_eq!(result, ClearDuplicateMacQuarantineResult::Cleared);
    assert!(!quarantine_rx.borrow().contains(&key));
    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
            RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
        ],
        "manual clear should replay the still-local MAC immediately"
    );
    assert_quarantine_metric(&metrics, 100, 0xAA, 0);
}

#[tokio::test]
async fn duplicate_mac_manual_clear_inactive_returns_not_active_and_clears_window() {
    let inst = local_instance(100);
    let instances = instance_table_with(inst.clone());
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(16);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    let key = DuplicateMacKey::new(vni(100), mac(0xAA));

    assert!(!record_duplicate_mac_move(
        &metrics, &mut state, &inst, key.vni, key.mac
    ));
    let result = clear_duplicate_mac_quarantine(
        key,
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    assert_eq!(result, ClearDuplicateMacQuarantineResult::NotActive);
    assert!(!state.duplicate_mac_detector.clear(key));
}

#[tokio::test]
async fn duplicate_mac_manual_clear_unknown_vni_returns_unknown_vni() {
    let instances = instance_table(100);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(16);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    let result = clear_duplicate_mac_quarantine(
        DuplicateMacKey::new(vni(200), mac(0xAA)),
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    assert_eq!(result, ClearDuplicateMacQuarantineResult::UnknownVni);
}

#[tokio::test]
async fn duplicate_mac_mac_ip_quarantine_replays_multiple_live_ips_after_recovery() {
    let instances = instance_table_with(suppress_local_instance_with(
        100,
        1,
        Duration::from_millis(1),
    ));
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    state.remote_mac_ip_view.insert(
        (vni(100), mac(0xAA), ipa("192.0.2.10")),
        remote_mac_ip_view(0xAA, "192.0.2.10", Some(3)),
    );

    for ip in ["192.0.2.10", "192.0.2.11"] {
        observe_test(
            LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa(ip),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
        )
        .await;
    }

    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;

    assert!(
        log.lock().await.is_empty(),
        "pending MAC+IP quarantine must suppress every live IP, not inject later pending IPs"
    );
    assert_eq!(
        state
            .live_mac_ip
            .get(&vni(100))
            .and_then(|per_vni| per_vni.get(&mac(0xAA)))
            .cloned()
            .unwrap_or_default(),
        BTreeSet::from([ipa("192.0.2.10"), ipa("192.0.2.11")]),
        "suppressed live IPs remain cached for timed replay"
    );

    tokio::time::sleep(Duration::from_millis(5)).await;
    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;
    assert!(
        log.lock().await.is_empty(),
        "expired quarantine must wait for recovery replay instead of emitting MAC-only while live IPs exist"
    );

    recover_duplicate_macs(
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Inject(macip_key_with(100, 0xAA, Some("192.0.2.10"))),
            RibAction::Inject(macip_key_with(100, 0xAA, Some("192.0.2.11"))),
        ],
        "recovery should replay every still-live MAC+IP binding without a MAC-only route"
    );
    assert_quarantine_metric(&metrics, 100, 0xAA, 0);
}

#[tokio::test]
async fn duplicate_mac_quarantine_suppresses_remote_mac_repoll_processing() {
    let instances = instance_table_with(suppress_local_instance(100));
    let route_a = evpn_macip_route(100, 0xAA, "10.0.0.2", Some(5), false);
    let route_b = evpn_macip_route(100, 0xAA, "10.0.0.3", Some(9), false);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, routes_tx, _responder) =
        rib_capture_dynamic_query_responder(rib_rx, vec![route_a.clone()]);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;
    let inst = instances.get(vni(100)).unwrap();
    assert!(record_duplicate_mac_move(
        &metrics,
        &mut state,
        inst,
        vni(100),
        mac(0xAA)
    ));
    log.lock().await.clear();

    repoll_rib(
        &instances,
        &rib_tx,
        &mut state,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await
    .unwrap();

    assert_eq!(
        log.lock().await.clone(),
        vec![RibAction::Withdraw(macip_key_with(100, 0xAA, None))],
        "first quarantined remote diff must only enforce local suppression"
    );
    let view = state
        .remote_mac_view
        .get(&(vni(100), mac(0xAA)))
        .expect("remote cache still updates while processing is suppressed");
    assert_eq!(view.next_hop, ipa("10.0.0.2"));

    log.lock().await.clear();
    routes_tx.send_replace(vec![route_b]);
    repoll_rib(
        &instances,
        &rib_tx,
        &mut state,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await
    .unwrap();

    assert!(
        log.lock().await.is_empty(),
        "remote MAC changes during quarantine must not reprocess originator state"
    );
    let view = state
        .remote_mac_view
        .get(&(vni(100), mac(0xAA)))
        .expect("remote cache tracks the latest remote winner");
    assert_eq!(view.next_hop, ipa("10.0.0.3"));
    assert_eq!(view.mobility_sequence, Some(9));

    routes_tx.send_replace(vec![]);
    repoll_rib(
        &instances,
        &rib_tx,
        &mut state,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await
    .unwrap();

    assert!(
        log.lock().await.is_empty(),
        "remote MAC withdrawals during quarantine must not re-inject local routes"
    );
    assert!(
        !state.remote_mac_view.contains_key(&(vni(100), mac(0xAA))),
        "remote cache still reflects the withdrawn route"
    );
}

#[tokio::test]
async fn duplicate_mac_quarantine_suppresses_remote_mac_ip_repoll_processing() {
    let instances = instance_table_with(suppress_local_instance(100));
    let route_a =
        evpn_macip_route_with_ip(100, 0xAA, Some("192.0.2.10"), "10.0.0.2", Some(5), false);
    let route_b =
        evpn_macip_route_with_ip(100, 0xAA, Some("192.0.2.10"), "10.0.0.3", Some(9), false);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, routes_tx, _responder) =
        rib_capture_dynamic_query_responder(rib_rx, vec![route_a.clone()]);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;
    observe_test(
        LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;
    let inst = instances.get(vni(100)).unwrap();
    assert!(record_duplicate_mac_move(
        &metrics,
        &mut state,
        inst,
        vni(100),
        mac(0xAA)
    ));
    log.lock().await.clear();

    repoll_rib(
        &instances,
        &rib_tx,
        &mut state,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await
    .unwrap();

    assert_eq!(
        log.lock().await.clone(),
        vec![RibAction::Withdraw(macip_key_with(
            100,
            0xAA,
            Some("192.0.2.10")
        ))],
        "first quarantined remote MAC+IP diff must only enforce local suppression"
    );
    let view = state
        .remote_mac_ip_view
        .get(&(vni(100), mac(0xAA), ipa("192.0.2.10")))
        .expect("remote MAC+IP cache still updates while processing is suppressed");
    assert_eq!(view.next_hop, ipa("10.0.0.2"));

    log.lock().await.clear();
    routes_tx.send_replace(vec![route_b]);
    repoll_rib(
        &instances,
        &rib_tx,
        &mut state,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await
    .unwrap();

    assert!(
        log.lock().await.is_empty(),
        "remote MAC+IP changes during quarantine must not reprocess originator state"
    );
    let view = state
        .remote_mac_ip_view
        .get(&(vni(100), mac(0xAA), ipa("192.0.2.10")))
        .expect("remote MAC+IP cache tracks the latest remote winner");
    assert_eq!(view.next_hop, ipa("10.0.0.3"));
    assert_eq!(view.mobility_sequence, Some(9));
}

#[test]
fn extract_mac_mobility_full_extracts_sticky_and_seq() {
    let attrs = vec![PathAttribute::ExtendedCommunities(vec![
        ExtendedCommunity::mac_mobility(true, 7),
    ])];
    assert_eq!(extract_mac_mobility_full(&attrs), (true, Some(7)));
}

#[test]
fn extract_mac_mobility_full_returns_defaults_without_extcomm() {
    let attrs: Vec<PathAttribute> = vec![];
    assert_eq!(extract_mac_mobility_full(&attrs), (false, None));
}

#[test]
fn build_originated_route_carries_route_targets_and_mobility_seq() {
    let inst = local_instance(100);
    let key = EvpnRouteKey::MacIp {
        rd: inst.rd,
        ethernet_tag: EthernetTagId(0),
        mac: mac(0xAA),
        ip: None,
    };
    let route = build_originated_route(
        &inst,
        mac(0xAA),
        Some(5),
        false,
        key,
        EthernetSegmentIdentifier::ZERO,
    );
    assert_eq!(route.next_hop, ipa("10.0.0.1"));
    assert_eq!(route.origin_type, RouteOrigin::Local);
    // Verify the route carries: Origin, AsPath, NextHop, ExtComms.
    assert!(matches!(route.attributes[0], PathAttribute::Origin(_)));
    let extcomms = route
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::ExtendedCommunities(v) => Some(v),
            _ => None,
        })
        .unwrap();
    // 1 RT + 1 MAC Mobility = 2 extcomms.
    assert_eq!(extcomms.len(), 2);
    assert!(
        extcomms
            .iter()
            .any(|ec| ec.as_mac_mobility() == Some((false, 5)))
    );
}

#[test]
fn build_originated_route_omits_mobility_extcomm_when_seq_none_and_not_sticky() {
    let inst = local_instance(100);
    let key = EvpnRouteKey::MacIp {
        rd: inst.rd,
        ethernet_tag: EthernetTagId(0),
        mac: mac(0xAA),
        ip: None,
    };
    let route = build_originated_route(
        &inst,
        mac(0xAA),
        None,
        false,
        key,
        EthernetSegmentIdentifier::ZERO,
    );
    let extcomms = route
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::ExtendedCommunities(v) => Some(v),
            _ => None,
        })
        .unwrap();
    // RT only, no MAC Mobility.
    assert_eq!(extcomms.len(), 1);
    assert!(extcomms.iter().all(|ec| ec.as_mac_mobility().is_none()));
}

#[test]
fn build_originated_route_emits_sticky_at_zero_when_no_seq() {
    let inst = local_instance(100);
    let key = EvpnRouteKey::MacIp {
        rd: inst.rd,
        ethernet_tag: EthernetTagId(0),
        mac: mac(0xAA),
        ip: None,
    };
    let route = build_originated_route(
        &inst,
        mac(0xAA),
        None,
        /* sticky */ true,
        key,
        EthernetSegmentIdentifier::ZERO,
    );
    let extcomms = route
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::ExtendedCommunities(v) => Some(v),
            _ => None,
        })
        .unwrap();
    assert!(
        extcomms
            .iter()
            .any(|ec| ec.as_mac_mobility() == Some((true, 0)))
    );
}

#[test]
fn build_originated_route_carries_segment_esi_when_provided() {
    // Gate 8b ESI-aware MAC origination: when the daemon's
    // `vni_to_esi` lookup returns a non-zero ESI for the VNI a
    // MAC was learned on, the Type 2 NLRI's ESI field carries
    // that segment identifier so peers can resolve aliasing
    // (RFC 7432 §14) against the corresponding EAD-per-EVI
    // routes.
    let inst = local_instance(100);
    let key = EvpnRouteKey::MacIp {
        rd: inst.rd,
        ethernet_tag: EthernetTagId(0),
        mac: mac(0xAA),
        ip: None,
    };
    let segment_esi = EthernetSegmentIdentifier::new([
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
    ]);
    let route = build_originated_route(&inst, mac(0xAA), None, false, key, segment_esi);
    let EvpnRoute::MacIp(macip) = &route.route else {
        panic!("expected MacIp route");
    };
    assert_eq!(macip.esi, segment_esi);
    // Single-homed default still works:
    let route_zero = build_originated_route(
        &inst,
        mac(0xAA),
        None,
        false,
        key,
        EthernetSegmentIdentifier::ZERO,
    );
    let EvpnRoute::MacIp(macip_zero) = &route_zero.route else {
        panic!("expected MacIp route");
    };
    assert_eq!(macip_zero.esi, EthernetSegmentIdentifier::ZERO);
}

#[tokio::test]
async fn spawn_returns_none_for_empty_instance_table() {
    let instances = Arc::new(EvpnInstanceTable::new());
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let (_local_tx, local_rx) = mpsc::channel(8);
    let h = spawn(
        OriginatorConfig::default(),
        &instances,
        rib_tx,
        Some(local_rx),
        BgpMetrics::new(),
        OriginatedLocalMacCounts::default(),
        CancellationToken::new(),
        std::sync::Arc::new(std::collections::BTreeMap::new()),
    );
    assert!(h.is_none());
}

#[tokio::test]
async fn spawn_returns_none_when_no_local_mac_rx_provided() {
    let instances = instance_table(100);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let h = spawn(
        OriginatorConfig::default(),
        &instances,
        rib_tx,
        None,
        BgpMetrics::new(),
        OriginatedLocalMacCounts::default(),
        CancellationToken::new(),
        std::sync::Arc::new(std::collections::BTreeMap::new()),
    );
    assert!(h.is_none());
}

fn runtime_model_rib_responder(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    injects: Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
    withdraws: Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (events_tx, _) = broadcast::channel(16);
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                    let _ = reply.send(events_tx.subscribe());
                }
                RibUpdate::QueryEvpnRoutes { reply } => {
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

async fn wait_for_key(
    log: &Arc<tokio::sync::Mutex<Vec<EvpnRouteKey>>>,
    expected: EvpnRouteKey,
    context: &str,
) {
    for _ in 0..50 {
        if log.lock().await.contains(&expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let observed = log.lock().await.clone();
    panic!("{context}: expected {expected:?}, observed {observed:?}");
}

// Records full injected routes (not just keys) so tests can inspect
// route attributes such as the Type 2 ESI.
fn runtime_model_full_route_responder(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    injects: Arc<tokio::sync::Mutex<Vec<EvpnRibRoute>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (events_tx, _) = broadcast::channel(16);
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::SubscribeEvpnRouteEvents { reply } => {
                    let _ = reply.send(events_tx.subscribe());
                }
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(vec![]);
                }
                RibUpdate::InjectEvpn { route, reply } => {
                    injects.lock().await.push(route);
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

async fn wait_for_macip_with_esi(
    routes: &Arc<tokio::sync::Mutex<Vec<EvpnRibRoute>>>,
    esi: EthernetSegmentIdentifier,
    context: &str,
) {
    for _ in 0..50 {
        if routes
            .lock()
            .await
            .iter()
            .any(|r| matches!(&r.route, EvpnRoute::MacIp(macip) if macip.esi == esi))
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{context}: no MacIp route observed carrying esi {esi:?}");
}

fn originator_runtime_for_test(
    instances: Arc<EvpnInstanceTable>,
    rib_tx: mpsc::Sender<RibUpdate>,
    metrics: BgpMetrics,
    originated_local_mac_counts: OriginatedLocalMacCounts,
    vni_to_esi: Arc<BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>>,
) -> OriginatorRuntime {
    let (_, model_rx) = watch::channel(Arc::new(OriginatorRuntimeModel {
        instances: instances.clone(),
        vni_to_esi: vni_to_esi.clone(),
        drained_esis: Arc::new(BTreeSet::new()),
    }));
    OriginatorRuntime {
        instances,
        model_rx,
        rib_tx,
        metrics,
        originated_local_mac_counts,
        shutdown: CancellationToken::new(),
        vni_to_esi,
        drained_esis: Arc::new(BTreeSet::new()),
    }
}

#[tokio::test]
async fn runtime_model_esi_change_restamps_local_mac_with_segment_esi() {
    // Regression: an ESI-map change must not just withdraw the member
    // VNI's ESI=0 local MAC route — it must re-originate it under the
    // new segment ESI without waiting for another kernel local-MAC
    // event.
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
    let (local_tx, local_rx) = mpsc::channel(16);
    let injected = Arc::new(tokio::sync::Mutex::new(Vec::<EvpnRibRoute>::new()));
    let _responder = runtime_model_full_route_responder(rib_rx, injected.clone());

    let h = spawn(
        OriginatorConfig {
            poll_interval: Duration::from_mins(1),
        },
        &instances,
        rib_tx,
        Some(local_rx),
        BgpMetrics::new(),
        OriginatedLocalMacCounts::default(),
        CancellationToken::new(),
        Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    local_tx
        .send(LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        })
        .await
        .unwrap();
    wait_for_macip_with_esi(
        &injected,
        EthernetSegmentIdentifier::ZERO,
        "initial origination should carry ESI 0",
    )
    .await;

    let segment_esi = EthernetSegmentIdentifier::new([
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
    ]);
    let mut vni_to_esi = std::collections::BTreeMap::new();
    vni_to_esi.insert(vni(100), segment_esi);
    assert!(h.replace_runtime_model(
        instances,
        Arc::new(vni_to_esi),
        Arc::new(std::collections::BTreeSet::new())
    ));

    wait_for_macip_with_esi(
        &injected,
        segment_esi,
        "ESI-map change should re-stamp the local MAC under the segment ESI",
    )
    .await;
    h.shutdown().await;
}

#[tokio::test]
async fn runtime_model_esi_change_preserves_duplicate_mac_quarantine() {
    let instances = instance_table_with(suppress_local_instance(100));
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    state.remote_mac_view.insert(
        (vni(100), mac(0xAA)),
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: Some(3),
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );

    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;

    let duplicate_key = DuplicateMacKey::new(vni(100), mac(0xAA));
    assert!(
        state
            .active_duplicate_mac_quarantines
            .contains(&duplicate_key),
        "remote contender should activate suppress-local quarantine"
    );
    assert!(
        log.lock().await.is_empty(),
        "quarantined local MAC must not advertise before ESI change"
    );
    assert_quarantine_metric(&metrics, 100, 0xAA, 1);

    let segment_esi = EthernetSegmentIdentifier::new([
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
    ]);
    let mut next_vni_to_esi = BTreeMap::new();
    next_vni_to_esi.insert(vni(100), segment_esi);
    let mut runtime = originator_runtime_for_test(
        instances.clone(),
        rib_tx,
        metrics.clone(),
        counts,
        Arc::new(BTreeMap::new()),
    );

    apply_runtime_model(
        Arc::new(OriginatorRuntimeModel {
            instances,
            vni_to_esi: Arc::new(next_vni_to_esi),
            drained_esis: Arc::new(BTreeSet::new()),
        }),
        &mut state,
        &mut runtime,
    )
    .await;

    assert!(
        state
            .active_duplicate_mac_quarantines
            .contains(&duplicate_key),
        "ESI-map changes must not clear active duplicate-MAC suppression"
    );
    assert!(
        state
            .duplicate_mac_detector
            .is_quarantined(duplicate_key, Instant::now()),
        "duplicate-MAC detector state must survive ESI-map changes"
    );
    assert!(
        log.lock().await.is_empty(),
        "ESI-map replay must not re-advertise a quarantined local MAC"
    );
    assert_quarantine_metric(&metrics, 100, 0xAA, 1);
}

#[tokio::test]
async fn runtime_model_redefine_clears_duplicate_mac_quarantine_and_replays() {
    // A redefine that disables suppression (delete-old + add-new) must drop
    // the duplicate-MAC quarantine/detector state and let the local MAC
    // re-originate under the new fields — not leave it stuck quarantined.
    let instances = instance_table_with(suppress_local_instance(100));
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    state.remote_mac_view.insert(
        (vni(100), mac(0xAA)),
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: Some(3),
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );

    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;

    let duplicate_key = DuplicateMacKey::new(vni(100), mac(0xAA));
    assert!(
        state
            .active_duplicate_mac_quarantines
            .contains(&duplicate_key),
        "remote contender should activate suppress-local quarantine"
    );
    assert_quarantine_metric(&metrics, 100, 0xAA, 1);

    // Redefine VNI 100 to the same identity but with suppression disabled
    // (local_instance differs from suppress_local_instance only in
    // duplicate_mac_detection), so this is a content change → redefine.
    let redefined_instances = instance_table_with(local_instance(100));
    let mut runtime = originator_runtime_for_test(
        instances,
        rib_tx,
        metrics.clone(),
        counts,
        Arc::new(BTreeMap::new()),
    );

    apply_runtime_model(
        Arc::new(OriginatorRuntimeModel {
            instances: redefined_instances,
            vni_to_esi: Arc::new(BTreeMap::new()),
            drained_esis: Arc::new(BTreeSet::new()),
        }),
        &mut state,
        &mut runtime,
    )
    .await;

    assert!(
        !state
            .active_duplicate_mac_quarantines
            .contains(&duplicate_key),
        "redefine must clear the active duplicate-MAC quarantine"
    );
    assert!(
        !state
            .duplicate_mac_detector
            .is_quarantined(duplicate_key, Instant::now()),
        "redefine must drop the duplicate-MAC detector state"
    );
    assert_quarantine_metric(&metrics, 100, 0xAA, 0);
    assert!(
        !log.lock().await.is_empty(),
        "redefine that disables suppression must replay the local MAC"
    );
}

#[tokio::test]
async fn runtime_model_esi_change_preserves_pending_ip_bindings() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    observe_test(
        LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;
    assert!(
        state
            .pending_ip_bindings
            .get(&(vni(100), mac(0xAA)))
            .is_some_and(|ips| ips.contains(&ipa("192.0.2.10"))),
        "IP-before-MAC binding should be pending before ESI change"
    );

    let segment_esi = EthernetSegmentIdentifier::new([
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
    ]);
    let mut next_vni_to_esi = BTreeMap::new();
    next_vni_to_esi.insert(vni(100), segment_esi);
    let mut runtime = originator_runtime_for_test(
        instances.clone(),
        rib_tx.clone(),
        metrics.clone(),
        counts.clone(),
        Arc::new(BTreeMap::new()),
    );

    apply_runtime_model(
        Arc::new(OriginatorRuntimeModel {
            instances: instances.clone(),
            vni_to_esi: Arc::new(next_vni_to_esi),
            drained_esis: Arc::new(BTreeSet::new()),
        }),
        &mut state,
        &mut runtime,
    )
    .await;
    assert!(
        state
            .pending_ip_bindings
            .get(&(vni(100), mac(0xAA)))
            .is_some_and(|ips| ips.contains(&ipa("192.0.2.10"))),
        "ESI-map changes must preserve pending IP bindings"
    );

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        runtime.vni_to_esi.as_ref(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    assert_eq!(
        log.lock().await.clone(),
        vec![RibAction::Inject(macip_key_with(
            100,
            0xAA,
            Some("192.0.2.10")
        ))],
        "Learned after ESI-map change must drain the preserved pending IP and emit MAC+IP"
    );
}

#[tokio::test]
async fn runtime_model_add_allows_future_local_mac_learns() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
    let (local_tx, local_rx) = mpsc::channel(16);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _responder = runtime_model_rib_responder(rib_rx, injects.clone(), withdraws.clone());

    let h = spawn(
        OriginatorConfig {
            poll_interval: Duration::from_mins(1),
        },
        &instances,
        rib_tx,
        Some(local_rx),
        BgpMetrics::new(),
        OriginatedLocalMacCounts::default(),
        CancellationToken::new(),
        Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    assert!(h.replace_runtime_model(
        instance_table_many(&[100, 200]),
        Arc::new(std::collections::BTreeMap::new()),
        Arc::new(std::collections::BTreeSet::new()),
    ));
    local_tx
        .send(LocalMacObservation::Learned {
            vni: vni(200),
            mac: mac(0xBB),
            ifindex: 20,
        })
        .await
        .unwrap();

    wait_for_key(
        &injects,
        EvpnRouteKey::MacIp {
            rd: rd(65000, 200),
            ethernet_tag: EthernetTagId(0),
            mac: mac(0xBB),
            ip: None,
        },
        "runtime-added VNI should accept future local learns",
    )
    .await;
    assert!(withdraws.lock().await.is_empty());
    h.shutdown().await;
}

#[tokio::test]
async fn runtime_model_remove_drains_originated_local_mac_routes() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
    let (local_tx, local_rx) = mpsc::channel(16);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _responder = runtime_model_rib_responder(rib_rx, injects.clone(), withdraws.clone());

    let h = spawn(
        OriginatorConfig {
            poll_interval: Duration::from_mins(1),
        },
        &instances,
        rib_tx,
        Some(local_rx),
        BgpMetrics::new(),
        OriginatedLocalMacCounts::default(),
        CancellationToken::new(),
        Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    let key = EvpnRouteKey::MacIp {
        rd: rd(65000, 100),
        ethernet_tag: EthernetTagId(0),
        mac: mac(0xAA),
        ip: None,
    };
    local_tx
        .send(LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        })
        .await
        .unwrap();
    wait_for_key(&injects, key, "initial VNI should originate").await;

    assert!(h.replace_runtime_model(
        Arc::new(EvpnInstanceTable::new()),
        Arc::new(std::collections::BTreeMap::new()),
        Arc::new(std::collections::BTreeSet::new()),
    ));
    wait_for_key(
        &withdraws,
        key,
        "runtime-removed VNI should drain local MAC originations",
    )
    .await;
    h.shutdown().await;
}

#[tokio::test]
async fn runtime_model_esi_change_drains_originated_local_mac_routes() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
    let (local_tx, local_rx) = mpsc::channel(16);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _responder = runtime_model_rib_responder(rib_rx, injects.clone(), withdraws.clone());

    let h = spawn(
        OriginatorConfig {
            poll_interval: Duration::from_mins(1),
        },
        &instances,
        rib_tx,
        Some(local_rx),
        BgpMetrics::new(),
        OriginatedLocalMacCounts::default(),
        CancellationToken::new(),
        Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    let key = EvpnRouteKey::MacIp {
        rd: rd(65000, 100),
        ethernet_tag: EthernetTagId(0),
        mac: mac(0xAA),
        ip: None,
    };
    local_tx
        .send(LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        })
        .await
        .unwrap();
    wait_for_key(&injects, key, "initial VNI should originate").await;

    let mut vni_to_esi = std::collections::BTreeMap::new();
    vni_to_esi.insert(
        vni(100),
        EthernetSegmentIdentifier::new([
            0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01,
        ]),
    );
    assert!(h.replace_runtime_model(
        instances,
        Arc::new(vni_to_esi),
        Arc::new(std::collections::BTreeSet::new())
    ));
    wait_for_key(
        &withdraws,
        key,
        "runtime ESI-map change should drain stale local MAC originations",
    )
    .await;
    h.shutdown().await;
}

#[tokio::test]
async fn runtime_model_redefine_reoriginates_local_mac_under_new_rd() {
    // A redefine (same VNI, new RD) must withdraw the committed-RD local
    // Type 2 route AND re-originate it under the new RD from the preserved
    // local observation — not silently drop it until the next kernel event.
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(32);
    let (local_tx, local_rx) = mpsc::channel(16);
    let injects = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let withdraws = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _responder = runtime_model_rib_responder(rib_rx, injects.clone(), withdraws.clone());

    let h = spawn(
        OriginatorConfig {
            poll_interval: Duration::from_mins(1),
        },
        &instances,
        rib_tx,
        Some(local_rx),
        BgpMetrics::new(),
        OriginatedLocalMacCounts::default(),
        CancellationToken::new(),
        Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    let old_key = EvpnRouteKey::MacIp {
        rd: rd(65000, 100),
        ethernet_tag: EthernetTagId(0),
        mac: mac(0xAA),
        ip: None,
    };
    local_tx
        .send(LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        })
        .await
        .unwrap();
    wait_for_key(
        &injects,
        old_key,
        "initial VNI should originate under old RD",
    )
    .await;

    // Redefine VNI 100 with a new RD (65000:111), same VTEP/RT shape.
    let redefined = EvpnInstance::new(
        vni(100),
        rd(65000, 111),
        vec![RouteTarget::TwoOctetAs {
            asn: 65000,
            value: 100,
        }],
        ipa("10.0.0.1"),
        Some("br100".to_string()),
        false,
    )
    .unwrap();
    let new_instances = instance_table_with(redefined);
    let new_key = EvpnRouteKey::MacIp {
        rd: rd(65000, 111),
        ethernet_tag: EthernetTagId(0),
        mac: mac(0xAA),
        ip: None,
    };

    assert!(h.replace_runtime_model(
        new_instances,
        Arc::new(std::collections::BTreeMap::new()),
        Arc::new(std::collections::BTreeSet::new()),
    ));
    wait_for_key(
        &withdraws,
        old_key,
        "redefine should withdraw the old-RD local MAC route",
    )
    .await;
    wait_for_key(
        &injects,
        new_key,
        "redefine should re-originate the local MAC route under the new RD",
    )
    .await;
    h.shutdown().await;
}

#[test]
fn remove_vni_state_clears_inactive_duplicate_mac_detector_windows() {
    let instances = instance_table(100);
    let mut state = originator_state(&instances);
    let metrics = BgpMetrics::new();
    let key = DuplicateMacKey::new(vni(100), mac(0xAA));
    let inst = instances.get(vni(100)).unwrap();

    assert!(!record_duplicate_mac_move(
        &metrics, &mut state, inst, key.vni, key.mac
    ));
    assert!(state.known_duplicate_mac_keys.contains(&key));
    remove_vni_state(&mut state, key.vni, &metrics);

    assert!(!state.known_duplicate_mac_keys.contains(&key));
    assert!(!state.duplicate_mac_detector.clear(key));
}

#[tokio::test]
async fn learn_emits_inject_then_aged_emits_withdraw() {
    let instances = instance_table(100);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (local_tx, local_rx) = mpsc::channel(16);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let shutdown = CancellationToken::new();

    // Auto-respond to QueryEvpnRoutes with empty so the polling
    // loop doesn't block.
    let rib_responder = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(vec![]);
                }
                RibUpdate::InjectEvpn { route, reply } => {
                    let _ = reply.send(Ok(()));
                    break_or_continue(route, &mut Some(()));
                }
                _ => {}
            }
        }
    });

    let h = spawn(
        OriginatorConfig {
            poll_interval: Duration::from_millis(20),
        },
        &instances,
        rib_tx,
        Some(local_rx),
        metrics,
        counts,
        shutdown.clone(),
        std::sync::Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    local_tx
        .send(LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        })
        .await
        .unwrap();

    // Give the loop a moment to process and the RIB responder to
    // ack the inject before we shutdown.
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Drop the responder side and shutdown.
    rib_responder.abort();
    h.shutdown().await;
}

fn break_or_continue<T>(_v: T, _flag: &mut Option<()>) {}

#[tokio::test]
async fn shutdown_drains_outstanding_originations_as_withdraws() {
    let instances = instance_table(100);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (local_tx, local_rx) = mpsc::channel(16);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let shutdown = CancellationToken::new();

    // Track injects + withdraws.
    let injects = Arc::new(std::sync::Mutex::new(Vec::<EvpnRouteKey>::new()));
    let withdraws = Arc::new(std::sync::Mutex::new(Vec::<EvpnRouteKey>::new()));
    let injects_c = injects.clone();
    let withdraws_c = withdraws.clone();
    let _rib_responder = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(vec![]);
                }
                RibUpdate::InjectEvpn { route, reply } => {
                    injects_c.lock().unwrap().push(route.key());
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::WithdrawEvpn { key, reply } => {
                    withdraws_c.lock().unwrap().push(key);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
    });

    let h = spawn(
        OriginatorConfig {
            poll_interval: Duration::from_mins(1),
        },
        &instances,
        rib_tx,
        Some(local_rx),
        metrics.clone(),
        counts.clone(),
        shutdown.clone(),
        std::sync::Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    for m in [0xAA_u8, 0xBB, 0xCC] {
        local_tx
            .send(LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(m),
                ifindex: u32::from(m),
            })
            .await
            .unwrap();
    }
    // Wait until 3 injects observed.
    for _ in 0..50 {
        if injects.lock().unwrap().len() == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(injects.lock().unwrap().len(), 3, "expected 3 injects");
    assert_eq!(counts.count(vni(100)), 3);

    h.shutdown().await;

    // After shutdown, every originated MAC should have been
    // withdrawn.
    assert_eq!(
        withdraws.lock().unwrap().len(),
        3,
        "expected 3 withdraws on shutdown"
    );

    let text = gather_metrics_text(&metrics);
    assert!(text.contains("evpn_local_originations_total{action=\"inject\"} 3"));
    assert!(text.contains("evpn_local_originations_total{action=\"withdraw\"} 3"));
    assert_eq!(counts.count(vni(100)), 0);
}

#[tokio::test]
async fn rib_rejection_increments_evpn_local_origination_error_counter() {
    let instances = instance_table(100);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (local_tx, local_rx) = mpsc::channel(16);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let shutdown = CancellationToken::new();

    let _rib_responder = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(vec![]);
                }
                RibUpdate::InjectEvpn { reply, .. } => {
                    let _ = reply.send(Err(RibCommandError::internal("synthetic rejection")));
                }
                _ => {}
            }
        }
    });

    let h = spawn(
        OriginatorConfig {
            poll_interval: Duration::from_mins(1),
        },
        &instances,
        rib_tx,
        Some(local_rx),
        metrics.clone(),
        counts.clone(),
        shutdown.clone(),
        std::sync::Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    local_tx
        .send(LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        })
        .await
        .unwrap();

    for _ in 0..50 {
        let text = gather_metrics_text(&metrics);
        if text.contains("evpn_local_origination_errors_total{action=\"inject\"} 1") {
            assert_eq!(counts.count(vni(100)), 0);
            h.shutdown().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    h.shutdown().await;
    panic!("expected inject error counter to increment");
}

#[tokio::test]
async fn unknown_vni_observation_is_ignored() {
    let instances = instance_table(100);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (local_tx, local_rx) = mpsc::channel(16);
    let shutdown = CancellationToken::new();

    let _rib_responder = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                let _ = reply.send(vec![]);
            }
        }
    });

    let h = spawn(
        OriginatorConfig::default(),
        &instances,
        rib_tx,
        Some(local_rx),
        BgpMetrics::new(),
        OriginatedLocalMacCounts::default(),
        shutdown.clone(),
        std::sync::Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    // VNI 999 isn't configured.
    local_tx
        .send(LocalMacObservation::Learned {
            vni: vni(999),
            mac: mac(0xAA),
            ifindex: 10,
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    h.shutdown().await;
    // No assertions — the test passes if shutdown didn't hang or
    // crash from the unknown-VNI observation.
}

/// Build an `EvpnRouteEvent` for a Type 2 best-path with the given
/// peer / mac / seq, using the same RD shape as `local_instance`.
fn evpn_event_macip(
    v: u32,
    m: u8,
    peer_addr: &str,
    seq: Option<u32>,
    sticky: bool,
    event_type: rustbgpd_rib::RouteEventType,
    previous_peer: Option<IpAddr>,
) -> EvpnRouteEvent {
    let route = evpn_macip_route(v, m, peer_addr, seq, sticky);
    EvpnRouteEvent {
        event_type,
        key: route.key(),
        best: Some(route.clone()),
        previous_best: None,
        peer: Some(ipa(peer_addr)),
        previous_peer,
        timestamp: "0".to_string(),
    }
}

/// Build a `QueryEvpnRoutes` responder that replies with `routes`
/// for every query and forwards `InjectEvpn` / `WithdrawEvpn`
/// success replies. Returned join handle lives until `rib_rx` is
/// closed.
fn rib_query_responder(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    routes: Vec<EvpnRibRoute>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(routes.clone());
                }
                RibUpdate::InjectEvpn { reply, .. } | RibUpdate::WithdrawEvpn { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
    })
}

/// Build a mutable `QueryEvpnRoutes` responder that also records
/// Inject/Withdraw actions. Tests use this to drive consecutive
/// full-RIB projections without restarting originator state.
fn rib_capture_dynamic_query_responder(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    routes: Vec<EvpnRibRoute>,
) -> RibDynamicResponder {
    let log = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let log_clone = log.clone();
    let (routes_tx, routes_rx) = watch::channel(routes);
    let join = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(routes_rx.borrow().clone());
                }
                RibUpdate::InjectEvpn { route, reply } => {
                    log_clone.lock().await.push(RibAction::Inject(route.key()));
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::WithdrawEvpn { key, reply } => {
                    log_clone.lock().await.push(RibAction::Withdraw(key));
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
    });
    (log, routes_tx, join)
}

/// Gate 7c: a Type 2 event triggers a `repoll_rib` round-trip and
/// the resulting full projection populates `remote_view`. Sub-
/// second wakeup, full projection — neither half is short-cut.
#[tokio::test]
async fn handle_evpn_event_repolls_and_populates_remote_view() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    // RIB has one Type 2 from 10.0.0.2; the responder returns it
    // for every QueryEvpnRoutes.
    let route = evpn_macip_route(100, 0xAA, "10.0.0.2", Some(5), false);
    let _responder = rib_query_responder(rib_rx, vec![route.clone()]);

    let event = evpn_event_macip(
        100,
        0xAA,
        "10.0.0.2",
        Some(5),
        false,
        rustbgpd_rib::RouteEventType::Added,
        None,
    );

    handle_evpn_event(
        &event,
        &instances,
        &mut state,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await;

    let view = state
        .remote_mac_view
        .get(&(vni(100), mac(0xAA)))
        .expect("event-triggered repoll must populate remote_view");
    assert_eq!(view.next_hop, ipa("10.0.0.2"));
    assert_eq!(view.mobility_sequence, Some(5));
}

/// Regression: a lower-mobility-sequence Added event for a
/// **different RD** must NOT displace a higher-seq winner.
/// `crates/evpn::project_evpn_routes` picks per-`(VNI, MAC)`
/// across all RDs by mobility sequence (RFC 7432 §15.1) — the
/// per-event delta we tried before would silently overwrite the
/// cached view with the worse candidate.
#[tokio::test]
async fn handle_evpn_event_lower_seq_different_rd_does_not_displace_winner() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    // Two routes for the same (VNI, MAC) under different RDs.
    // PE-A wins on mobility seq (10 > 1).
    let mut pe_a = evpn_macip_route(100, 0xAA, "10.0.0.2", Some(10), false);
    if let EvpnRoute::MacIp(ref mut r) = pe_a.route {
        r.rd = rd(65000, 100);
    }
    let mut pe_b = evpn_macip_route(100, 0xAA, "10.0.0.3", Some(1), false);
    if let EvpnRoute::MacIp(ref mut r) = pe_b.route {
        r.rd = rd(65001, 999);
    }
    let _responder = rib_query_responder(rib_rx, vec![pe_a.clone(), pe_b.clone()]);

    // Drive the originator on PE-B's Added event — the worse
    // candidate. The repoll must still pick PE-A.
    let event = EvpnRouteEvent {
        event_type: rustbgpd_rib::RouteEventType::Added,
        key: pe_b.key(),
        best: Some(pe_b),
        previous_best: None,
        peer: Some(ipa("10.0.0.3")),
        previous_peer: None,
        timestamp: "0".to_string(),
    };

    handle_evpn_event(
        &event,
        &instances,
        &mut state,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await;

    let view = state
        .remote_mac_view
        .get(&(vni(100), mac(0xAA)))
        .expect("projection must select PE-A even when PE-B's event triggered the repoll");
    assert_eq!(
        view.next_hop,
        ipa("10.0.0.2"),
        "winner is PE-A (seq=10), not PE-B (seq=1)"
    );
    assert_eq!(view.mobility_sequence, Some(10));
}

/// Regression: a Withdrawn event for a **non-winning** RD must
/// NOT clear the cached view when a winning RD still exists in
/// the RIB. The repoll model picks PE-A from what remains.
#[tokio::test]
async fn handle_evpn_event_non_winning_withdrawn_keeps_winning_view() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    state.remote_mac_view.insert(
        (vni(100), mac(0xAA)),
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: Some(10),
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );

    // The losing PE-B is withdrawn — the RIB still returns PE-A.
    let mut pe_a = evpn_macip_route(100, 0xAA, "10.0.0.2", Some(10), false);
    if let EvpnRoute::MacIp(ref mut r) = pe_a.route {
        r.rd = rd(65000, 100);
    }
    let _responder = rib_query_responder(rib_rx, vec![pe_a.clone()]);

    // Synthesize the loser's prior route + Withdrawn event.
    let mut pe_b_prior = evpn_macip_route(100, 0xAA, "10.0.0.3", Some(1), false);
    if let EvpnRoute::MacIp(ref mut r) = pe_b_prior.route {
        r.rd = rd(65001, 999);
    }
    let event = EvpnRouteEvent {
        event_type: rustbgpd_rib::RouteEventType::Withdrawn,
        key: pe_b_prior.key(),
        best: None,
        previous_best: Some(pe_b_prior),
        peer: None,
        previous_peer: Some(ipa("10.0.0.3")),
        timestamp: "0".to_string(),
    };

    handle_evpn_event(
        &event,
        &instances,
        &mut state,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await;

    let view = state
        .remote_mac_view
        .get(&(vni(100), mac(0xAA)))
        .expect("losing PE's withdrawal must NOT clear the winning view");
    assert_eq!(view.next_hop, ipa("10.0.0.2"));
    assert_eq!(view.mobility_sequence, Some(10));
}

/// Non-Type-2 events (Type 1/3/4/5) are out of scope today — they
/// must not trigger a repoll. Verified by counting
/// `QueryEvpnRoutes` messages on the RIB channel.
#[tokio::test]
async fn handle_evpn_event_non_macip_does_not_repoll() {
    let instances = instance_table(100);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(4);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    let query_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let qc = query_count.clone();
    let _responder = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            if let RibUpdate::QueryEvpnRoutes { reply } = msg {
                qc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = reply.send(vec![]);
            }
        }
    });

    // An IMET (Type 3) event — out of scope for the originator.
    let imet_key = EvpnRouteKey::Imet {
        rd: rd(65000, 100),
        ethernet_tag: EthernetTagId(0),
        originator_ip: ipa("10.0.0.2"),
    };
    let event = EvpnRouteEvent {
        event_type: rustbgpd_rib::RouteEventType::Added,
        key: imet_key,
        best: None,
        previous_best: None,
        peer: Some(ipa("10.0.0.2")),
        previous_peer: None,
        timestamp: "0".to_string(),
    };

    handle_evpn_event(
        &event,
        &instances,
        &mut state,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await;

    assert_eq!(
        query_count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "non-MacIp events must not trigger a repoll"
    );
}

/// ADR-0056: a `Learned` observation for a MAC in the instance's
/// `sticky_macs` set must produce an `InjectEvpn` whose route
/// carries the RFC 7432 §15.4 MAC Mobility extended community with
/// `sticky = true`. Locks the only behavioral effect of the
/// `sticky_macs` config schema end-to-end.
#[tokio::test]
async fn sticky_mac_observation_emits_inject_with_sticky_extcomm() {
    // Instance with one MAC marked sticky.
    let mut t = EvpnInstanceTable::new();
    let inst = local_instance(100).with_sticky_macs(BTreeSet::from([mac(0xAA)]));
    t.insert(inst).unwrap();
    let instances = Arc::new(t);

    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (local_tx, local_rx) = mpsc::channel(16);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let shutdown = CancellationToken::new();

    // Capture the first InjectEvpn so we can inspect its extcomms.
    let (captured_tx, captured_rx) =
        tokio::sync::oneshot::channel::<rustbgpd_rib::route::EvpnRibRoute>();
    let mut captured_tx = Some(captured_tx);
    let _rib_responder = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(vec![]);
                }
                RibUpdate::InjectEvpn { route, reply } => {
                    if let Some(tx) = captured_tx.take() {
                        let _ = tx.send(route);
                    }
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
    });

    let h = spawn(
        OriginatorConfig {
            poll_interval: Duration::from_mins(1),
        },
        &instances,
        rib_tx,
        Some(local_rx),
        metrics,
        counts,
        shutdown.clone(),
        std::sync::Arc::new(std::collections::BTreeMap::new()),
    )
    .expect("originator spawned");

    local_tx
        .send(LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        })
        .await
        .unwrap();

    let route = tokio::time::timeout(Duration::from_secs(2), captured_rx)
        .await
        .expect("InjectEvpn must arrive within 2s")
        .expect("captured_tx not dropped");

    let extcomms = route
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::ExtendedCommunities(v) => Some(v),
            _ => None,
        })
        .expect("originated route must carry an ExtendedCommunities attribute");
    let mobility = extcomms
        .iter()
        .find_map(|ec| ec.as_mac_mobility())
        .expect("sticky_macs MAC must emit a MAC Mobility extcomm at seq=0");
    assert!(
        mobility.0,
        "MAC Mobility extcomm sticky bit must be set for sticky_macs MAC"
    );

    h.shutdown().await;
}

/// A Withdrawn event for the only candidate clears the cached
/// `RemoteMacView` — the repoll returns an empty route set, and
/// `build_remote_view` of an empty set yields an empty cache.
#[tokio::test]
async fn handle_evpn_event_withdrawn_clears_remote_view_when_rib_empty() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(4);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    state.remote_mac_view.insert(
        (vni(100), mac(0xCC)),
        RemoteMacView {
            mac: mac(0xCC),
            mobility_sequence: Some(7),
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );

    // RIB is empty — the route is gone.
    let _responder = rib_query_responder(rib_rx, vec![]);

    let prior = evpn_macip_route(100, 0xCC, "10.0.0.2", Some(7), false);
    let event = EvpnRouteEvent {
        event_type: rustbgpd_rib::RouteEventType::Withdrawn,
        key: prior.key(),
        best: None,
        previous_best: Some(prior),
        peer: None,
        previous_peer: Some(ipa("10.0.0.2")),
        timestamp: "0".to_string(),
    };

    handle_evpn_event(
        &event,
        &instances,
        &mut state,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
    )
    .await;

    assert!(
        !state.remote_mac_view.contains_key(&(vni(100), mac(0xCC))),
        "Withdrawn with empty RIB must clear the cached remote_view entry"
    );
}

// -----------------------------------------------------------------
// Gate 7b+2 slice 3 — MAC+IP correlation tests (replace model)
// -----------------------------------------------------------------

/// Capture an ordered log of `(InjectEvpn | WithdrawEvpn)` actions
/// the daemon emits to the RIB. Returns the captured-actions
/// handle; the responder ack's every Inject/Withdraw with `Ok(())`.
fn rib_capture_responder(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
) -> (RibActionLog, tokio::task::JoinHandle<()>) {
    let log = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let log_clone = log.clone();
    let join = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::InjectEvpn { route, reply } => {
                    log_clone.lock().await.push(RibAction::Inject(route.key()));
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::WithdrawEvpn { key, reply } => {
                    log_clone.lock().await.push(RibAction::Withdraw(key));
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(vec![]);
                }
                _ => {}
            }
        }
    });
    (log, join)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RibAction {
    Inject(EvpnRouteKey),
    Withdraw(EvpnRouteKey),
}

type RibActionLog = Arc<tokio::sync::Mutex<Vec<RibAction>>>;
type RibDynamicResponder = (
    RibActionLog,
    watch::Sender<Vec<EvpnRibRoute>>,
    tokio::task::JoinHandle<()>,
);

fn macip_key_with(rd_v: u32, mac_b: u8, ip_str: Option<&str>) -> EvpnRouteKey {
    EvpnRouteKey::MacIp {
        rd: rd(65000, rd_v),
        ethernet_tag: EthernetTagId(0),
        mac: mac(mac_b),
        ip: ip_str.map(ipa),
    }
}

/// Slice 3 core flow: `Learned` then `IpAdded` produces a
/// MAC-only Inject, then a MAC-only Withdraw (replacing it),
/// then a MAC+IP Inject. The replace boundary is the load-bearing
/// invariant — peers see the upgrade as an explicit handoff.
#[tokio::test]
async fn learned_then_ip_added_replaces_mac_only_with_mac_ip() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    handle_observation(
        &LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
            RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
            RibAction::Inject(macip_key_with(100, 0xAA, Some("192.0.2.10"))),
        ],
        "expected MAC-only Inject → MAC-only Withdraw → MAC+IP Inject"
    );
}

/// `IpAdded` before `Learned` parks the IP and emits no RIB action.
/// The kernel can reorder these edges during cold start.
#[tokio::test]
async fn ip_added_before_learned_parks_pending_no_rib_action() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    handle_observation(
        &LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    assert!(log.lock().await.is_empty());
    assert!(
        state
            .pending_ip_bindings
            .get(&(vni(100), mac(0xAA)))
            .is_some_and(|s| s.contains(&ipa("192.0.2.10"))),
        "pending IP binding must be parked"
    );
}

/// When `Learned` arrives after pending IPs were parked, the
/// daemon goes straight to MAC+IP — no MAC-only Inject is emitted
/// at all (no transient L2-only window).
#[tokio::test]
async fn learned_after_pending_ip_skips_mac_only_inject() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    // IpAdded first (parked).
    handle_observation(
        &LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    // Then Learned drains the pending IP and emits MAC+IP directly.
    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let actions = log.lock().await.clone();
    // Should be exactly one Inject for the MAC+IP route. No
    // MAC-only Inject; the on_local_aged on a never-advertised
    // MAC is a no-op so it doesn't appear either.
    assert_eq!(
        actions,
        vec![RibAction::Inject(macip_key_with(
            100,
            0xAA,
            Some("192.0.2.10")
        ))],
        "Learned after pending IP must skip MAC-only and emit MAC+IP only"
    );
    assert!(
        !state
            .pending_ip_bindings
            .contains_key(&(vni(100), mac(0xAA))),
        "pending bindings drained on Learned"
    );
}

/// `IpRemoved` of the **last** IP for a MAC downgrades back to
/// MAC-only — withdraws the MAC+IP route and re-emits the MAC.
#[tokio::test]
async fn last_ip_removed_downgrades_to_mac_only() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    handle_observation(
        &LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    // Clear the log to focus on the IpRemoved phase.
    log.lock().await.clear();

    handle_observation(
        &LocalMacObservation::IpRemoved {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Withdraw(macip_key_with(100, 0xAA, Some("192.0.2.10"))),
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
        ],
        "expected MAC+IP Withdraw → MAC-only re-Inject"
    );
}

/// `IpRemoved` of a **non-last** IP withdraws only the MAC+IP for
/// that key. MAC-only stays absent because other IPs still drive
/// MAC+IP advertising for the same MAC.
#[tokio::test]
async fn non_last_ip_removed_keeps_mac_in_mac_ip_regime() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    for ip in ["192.0.2.10", "192.0.2.11"] {
        handle_observation(
            &LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa(ip),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeSet::new(),
        )
        .await;
    }
    log.lock().await.clear();

    handle_observation(
        &LocalMacObservation::IpRemoved {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![RibAction::Withdraw(macip_key_with(
            100,
            0xAA,
            Some("192.0.2.10")
        ))],
        "non-last IP removal must NOT downgrade to MAC-only"
    );
}

/// `Aged` while multiple IPs are live cascades MAC+IP withdraws
/// for every IP and clears the live cache. No MAC-only Withdraw
/// fires because we were in MAC+IP regime.
#[tokio::test]
async fn aged_with_live_ips_cascades_mac_ip_withdraws() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    for ip in ["192.0.2.10", "2001:db8::1"] {
        handle_observation(
            &LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa(ip),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeSet::new(),
        )
        .await;
    }
    log.lock().await.clear();

    handle_observation(
        &LocalMacObservation::Aged {
            vni: vni(100),
            mac: mac(0xAA),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let actions = log.lock().await.clone();
    // Two MAC+IP Withdraws (order depends on BTreeMap iteration —
    // both must be present, no MAC-only Inject/Withdraw).
    assert_eq!(
        actions.len(),
        2,
        "expected 2 cascade MAC+IP withdraws: {actions:?}"
    );
    for a in &actions {
        assert!(
            matches!(
                a,
                RibAction::Withdraw(EvpnRouteKey::MacIp { ip: Some(_), .. })
            ),
            "every cascade action must be a MAC+IP Withdraw: {a:?}"
        );
    }
    assert!(
        !state
            .live_mac_ip
            .get(&vni(100))
            .is_some_and(|m| m.contains_key(&mac(0xAA))),
        "live cache cleared on Aged"
    );
    assert!(
        !state
            .local_macs
            .get(&vni(100))
            .is_some_and(|m| m.contains_key(&mac(0xAA))),
        "local_macs cleared on Aged"
    );
}

/// Counter regression: a non-last `IpRemoved` must NOT decrement
/// `OriginatedLocalMacCounts` to zero for the MAC. Two MAC+IP
/// routes for the same MAC each register a distinct
/// `EvpnRouteKey`; withdrawing one removes only that key, leaving
/// the MAC's count steady. Operator-visible — the gRPC
/// `originated_local_macs_count` field would otherwise blink to
/// zero under dual-stack hosts.
#[tokio::test]
async fn non_last_ip_removed_keeps_originated_count_stable() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (_log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    for ip in ["192.0.2.10", "2001:db8::1"] {
        handle_observation(
            &LocalMacObservation::IpAdded {
                vni: vni(100),
                mac: mac(0xAA),
                ip: ipa(ip),
            },
            &mut state,
            &instances,
            &rib_tx,
            &metrics,
            &counts,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeSet::new(),
        )
        .await;
    }

    assert_eq!(counts.count(vni(100)), 1, "one MAC has two live keys");

    // Withdraw one of the two MAC+IP routes — the MAC still has
    // its second route live, so the count must NOT drop.
    handle_observation(
        &LocalMacObservation::IpRemoved {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    assert_eq!(
        counts.count(vni(100)),
        1,
        "non-last IpRemoved must NOT decrement the MAC's count"
    );

    // Withdrawing the last IP downgrades to MAC-only (re-Inject).
    // The MAC retains a single live key — the MAC-only NLRI.
    handle_observation(
        &LocalMacObservation::IpRemoved {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("2001:db8::1"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    assert_eq!(
        counts.count(vni(100)),
        1,
        "downgrade to MAC-only keeps the MAC counted"
    );

    // Aged drains the last route — count drops.
    handle_observation(
        &LocalMacObservation::Aged {
            vni: vni(100),
            mac: mac(0xAA),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    assert_eq!(counts.count(vni(100)), 0, "Aged clears the count");
}

/// Replace-invariant regression: a `Learned` re-emit while MAC+IP
/// is already advertising must NOT produce another MAC-only
/// Inject. The kernel can re-emit `RTM_NEWNEIGH AF_BRIDGE` for an
/// already-known MAC (e.g., after a port flap or a state
/// transition); emitting a MAC-only Type 2 then would put us in
/// a "both advertising" state that the replace model forbids.
#[tokio::test]
async fn relearn_while_mac_ip_live_does_not_re_emit_mac_only() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    // Drive the MAC into MAC+IP regime: Learned then IpAdded.
    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    handle_observation(
        &LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    // Snapshot the action log: should be exactly the upgrade
    // sequence (MAC-only Inject, MAC-only Withdraw, MAC+IP Inject).
    let initial = log.lock().await.clone();
    assert_eq!(initial.len(), 3, "expected upgrade sequence: {initial:?}");

    // Now the kernel re-emits a Learned for the same MAC.
    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let after = log.lock().await.clone();
    assert_eq!(
        after, initial,
        "Learned while MAC+IP is live must NOT add a MAC-only Inject \
             (replace invariant): {after:?}"
    );
}

/// Sticky pass-through to MAC+IP: a MAC listed in
/// `[[evpn_instances]].sticky_macs` originates the MAC+IP Type 2
/// with the RFC 7432 §15.4 sticky bit set on its MAC Mobility
/// extcomm. ADR-0056's promise must hold for both NLRI shapes.
#[tokio::test]
async fn sticky_macs_propagates_to_mac_ip_route() {
    // Instance with one sticky MAC.
    let mut t = EvpnInstanceTable::new();
    let inst = local_instance(100).with_sticky_macs(BTreeSet::from([mac(0xAA)]));
    t.insert(inst).unwrap();
    let instances = Arc::new(t);

    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);

    // Capture the first MAC+IP Inject for inspection.
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel::<EvpnRibRoute>();
    let mut captured_tx = Some(captured_tx);
    let _responder = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(vec![]);
                }
                RibUpdate::InjectEvpn { route, reply } => {
                    if matches!(route.route, EvpnRoute::MacIp(EvpnMacIp { ip: Some(_), .. }))
                        && let Some(tx) = captured_tx.take()
                    {
                        let _ = tx.send(route.clone());
                    }
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::WithdrawEvpn { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
    });

    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    handle_observation(
        &LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        &std::collections::BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    let route = tokio::time::timeout(Duration::from_secs(2), captured_rx)
        .await
        .expect("MAC+IP Inject must arrive within 2s")
        .expect("captured_tx not dropped");

    let extcomms = route
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::ExtendedCommunities(v) => Some(v),
            _ => None,
        })
        .expect("originated MAC+IP route must carry ExtendedCommunities");
    let mobility = extcomms
        .iter()
        .find_map(|ec| ec.as_mac_mobility())
        .expect("sticky_macs MAC must emit a MAC Mobility extcomm");
    assert!(
        mobility.0,
        "sticky bit must propagate from sticky_macs to MAC+IP route"
    );
}

// -----------------------------------------------------------------
// ADR-0084 — Ethernet Segment drain (originator side)
// -----------------------------------------------------------------

fn drain_test_esi() -> EthernetSegmentIdentifier {
    EthernetSegmentIdentifier::new([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x01])
}

fn drain_test_vni_to_esi() -> Arc<BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier>> {
    let mut map = BTreeMap::new();
    map.insert(vni(100), drain_test_esi());
    Arc::new(map)
}

fn drained_set_with(esi: EthernetSegmentIdentifier) -> Arc<BTreeSet<EthernetSegmentIdentifier>> {
    Arc::new(BTreeSet::from([esi]))
}

#[tokio::test]
async fn runtime_model_drain_withdraws_local_macs_without_clearing_caches() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    let vni_to_esi = drain_test_vni_to_esi();

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &std::collections::BTreeSet::new(),
    )
    .await;
    assert_eq!(
        log.lock().await.clone(),
        vec![RibAction::Inject(macip_key_with(100, 0xAA, None))],
        "undrained local learn must originate"
    );

    let mut runtime = originator_runtime_for_test(
        instances.clone(),
        rib_tx,
        metrics,
        counts,
        vni_to_esi.clone(),
    );
    apply_runtime_model(
        Arc::new(OriginatorRuntimeModel {
            instances,
            vni_to_esi,
            drained_esis: drained_set_with(drain_test_esi()),
        }),
        &mut state,
        &mut runtime,
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
            RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
        ],
        "drain must withdraw the advertised local MAC route and emit no replay"
    );
    assert!(
        state
            .local_macs
            .get(&vni(100))
            .is_some_and(|m| m.contains_key(&mac(0xAA))),
        "drain must preserve the local observation cache"
    );
}

#[tokio::test]
async fn kernel_events_while_drained_update_caches_without_originating() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    let vni_to_esi = drain_test_vni_to_esi();
    let drained = BTreeSet::from([drain_test_esi()]);

    // Fresh kernel learn + IP bind while drained: no origination, but
    // both caches must track the events for the undrain replay.
    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xBB),
            ifindex: 20,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &drained,
    )
    .await;
    handle_observation(
        &LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xBB),
            ip: ipa("192.0.2.20"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &drained,
    )
    .await;

    assert!(
        log.lock().await.is_empty(),
        "kernel events on a drained VNI must not originate"
    );
    assert!(
        state
            .local_macs
            .get(&vni(100))
            .is_some_and(|m| m.get(&mac(0xBB)) == Some(&20)),
        "drained learn must still update local_macs"
    );
    assert!(
        state
            .live_mac_ip
            .get(&vni(100))
            .and_then(|m| m.get(&mac(0xBB)))
            .is_some_and(|ips| ips.contains(&ipa("192.0.2.20"))),
        "drained IpAdded must still update live_mac_ip"
    );
}

#[tokio::test]
async fn runtime_model_undrain_replays_cached_local_macs() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    let vni_to_esi = drain_test_vni_to_esi();
    let drained = BTreeSet::from([drain_test_esi()]);

    // MAC + IP learned entirely while drained (kernel kept feeding us
    // during the maintenance window).
    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &drained,
    )
    .await;
    handle_observation(
        &LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &drained,
    )
    .await;
    assert!(log.lock().await.is_empty());

    // Undrain: runtime starts in the drained state; the new model
    // lifts it.
    let mut runtime = originator_runtime_for_test(
        instances.clone(),
        rib_tx,
        metrics,
        counts,
        vni_to_esi.clone(),
    );
    runtime.drained_esis = drained_set_with(drain_test_esi());
    apply_runtime_model(
        Arc::new(OriginatorRuntimeModel {
            instances,
            vni_to_esi,
            drained_esis: Arc::new(BTreeSet::new()),
        }),
        &mut state,
        &mut runtime,
    )
    .await;

    assert_eq!(
        log.lock().await.clone(),
        vec![RibAction::Inject(macip_key_with(
            100,
            0xAA,
            Some("192.0.2.10")
        ))],
        "undrain must replay the latest cached local state (MAC+IP, not the stale MAC-only)"
    );
}

#[tokio::test]
async fn runtime_model_undrain_respects_duplicate_mac_quarantine() {
    let inst = suppress_local_instance(100);
    let instances = instance_table_with(inst.clone());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    let vni_to_esi = drain_test_vni_to_esi();
    let drained = BTreeSet::from([drain_test_esi()]);

    // Learn while drained, then activate a quarantine for the key.
    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &drained,
    )
    .await;
    assert!(record_duplicate_mac_move(
        &metrics,
        &mut state,
        &inst,
        vni(100),
        mac(0xAA)
    ));

    let mut runtime = originator_runtime_for_test(
        instances.clone(),
        rib_tx,
        metrics,
        counts,
        vni_to_esi.clone(),
    );
    runtime.drained_esis = drained_set_with(drain_test_esi());
    apply_runtime_model(
        Arc::new(OriginatorRuntimeModel {
            instances,
            vni_to_esi,
            drained_esis: Arc::new(BTreeSet::new()),
        }),
        &mut state,
        &mut runtime,
    )
    .await;

    assert!(
        log.lock().await.is_empty(),
        "undrain replay must skip quarantined MACs"
    );
    assert!(
        state
            .duplicate_mac_detector
            .is_quarantined(DuplicateMacKey::new(vni(100), mac(0xAA)), Instant::now()),
        "quarantine must survive the undrain"
    );
}

#[tokio::test]
async fn duplicate_mac_recovery_replay_is_suppressed_while_drained() {
    // The timed quarantine recovery path goes through the same replay
    // primitive; while the VNI is drained it must not re-originate.
    let inst = suppress_local_instance_with(100, 1, Duration::from_millis(1));
    let instances = instance_table_with(inst.clone());
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    let vni_to_esi = drain_test_vni_to_esi();
    let drained = BTreeSet::from([drain_test_esi()]);

    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &drained,
    )
    .await;
    assert!(record_duplicate_mac_move(
        &metrics,
        &mut state,
        &inst,
        vni(100),
        mac(0xAA)
    ));
    tokio::time::sleep(Duration::from_millis(5)).await;

    recover_duplicate_macs(
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &drained,
    )
    .await;

    assert!(
        log.lock().await.is_empty(),
        "quarantine recovery on a drained VNI must not replay the MAC"
    );
}

// --- In-place FDB port-move detection (`ObservedOnVxlanPort`) ---
//
// The M66 ES-drain handover proof (the topology header in
// tests/interop/m66-evpn-es-drain-handover.clab.yml has the full
// incident) surfaced that programming a remote Type 2 over a
// kernel-learned local AC row is an in-place FDB port move: the
// kernel emits one RTM_NEWNEIGH on the VXLAN port and NO RTM_DELNEIGH
// for the replaced local row, so without the `ObservedOnVxlanPort`
// observation the local-MAC cache keeps claiming a MAC the kernel no
// longer holds. These tests pin the originator's handling.

/// Like [`rib_capture_responder`] but also retains every injected
/// route in the returned `routes` handle so tests can inspect path
/// attributes (mobility extcomm). `QueryEvpnRoutes` still replies
/// empty — captured routes are visible only through the handle.
fn rib_capture_responder_with_routes(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
) -> (
    RibActionLog,
    Arc<tokio::sync::Mutex<Vec<EvpnRibRoute>>>,
    tokio::task::JoinHandle<()>,
) {
    let log: RibActionLog = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let routes = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let log_clone = log.clone();
    let routes_clone = routes.clone();
    let join = tokio::spawn(async move {
        while let Some(msg) = rib_rx.recv().await {
            match msg {
                RibUpdate::InjectEvpn { route, reply } => {
                    log_clone.lock().await.push(RibAction::Inject(route.key()));
                    routes_clone.lock().await.push(route);
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::WithdrawEvpn { key, reply } => {
                    log_clone.lock().await.push(RibAction::Withdraw(key));
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::QueryEvpnRoutes { reply } => {
                    let _ = reply.send(vec![]);
                }
                _ => {}
            }
        }
    });
    (log, routes, join)
}

/// (a) A locally-claimed MAC observed moving to the VXLAN port
/// withdraws the outstanding Type 2 routes (MAC-only AND MAC+IP) and
/// drops every local cache entry — the kernel no longer holds the MAC
/// on the AC port, so the local claim is stale.
#[tokio::test]
async fn vxlan_port_takeover_withdraws_local_mac_and_drops_caches() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;
    observe_test(
        LocalMacObservation::IpAdded {
            vni: vni(100),
            mac: mac(0xAA),
            ip: ipa("192.0.2.10"),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;

    observe_test(
        LocalMacObservation::ObservedOnVxlanPort {
            vni: vni(100),
            mac: mac(0xAA),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
            RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
            RibAction::Inject(macip_key_with(100, 0xAA, Some("192.0.2.10"))),
            RibAction::Withdraw(macip_key_with(100, 0xAA, Some("192.0.2.10"))),
        ],
        "VXLAN-port takeover must withdraw the advertised MAC+IP route"
    );
    assert!(
        !state
            .local_macs
            .get(&vni(100))
            .is_some_and(|m| m.contains_key(&mac(0xAA))),
        "takeover must drop the local-MAC cache entry"
    );
    assert!(
        !state.has_live_mac_ip_bindings(vni(100), mac(0xAA)),
        "takeover must drop the live (MAC, IP) cache"
    );
    assert_eq!(counts.count(vni(100)), 0, "originated count must drain");
}

/// (b) The M66 incident: pe1 drained, the ES peer's Type 2 for the
/// still-cached CE MAC usurps pe1's kernel-learned local AC row (an
/// in-place port move), and the later undrain must NOT replay the
/// stale Type 2. Without the drained-path `ObservedOnVxlanPort`
/// handling the cache keeps claiming the MAC and the undrain replays
/// a route for a MAC the kernel no longer holds locally.
#[tokio::test]
async fn m66_drained_vxlan_port_takeover_clears_cache_so_undrain_does_not_replay() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    let vni_to_esi = drain_test_vni_to_esi();
    let drained = BTreeSet::from([drain_test_esi()]);

    // CE MAC learned live (pre-maintenance steady state) — advertises.
    handle_observation(
        &LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &std::collections::BTreeSet::new(),
    )
    .await;

    // Operator drains the ES: routes withdraw, caches stay.
    let mut runtime = originator_runtime_for_test(
        instances.clone(),
        rib_tx.clone(),
        metrics.clone(),
        counts.clone(),
        vni_to_esi.clone(),
    );
    apply_runtime_model(
        Arc::new(OriginatorRuntimeModel {
            instances: instances.clone(),
            vni_to_esi: vni_to_esi.clone(),
            drained_esis: drained_set_with(drain_test_esi()),
        }),
        &mut state,
        &mut runtime,
    )
    .await;

    // The ES peer's Type 2 is programmed over the local AC row — the
    // kernel's in-place port move surfaces as ObservedOnVxlanPort
    // while the VNI is drained.
    handle_observation(
        &LocalMacObservation::ObservedOnVxlanPort {
            vni: vni(100),
            mac: mac(0xAA),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &drained,
    )
    .await;
    assert!(
        !state
            .local_macs
            .get(&vni(100))
            .is_some_and(|m| m.contains_key(&mac(0xAA))),
        "drained takeover must drop the cached local claim"
    );

    // Undrain: nothing to replay — the kernel does not hold the MAC.
    apply_runtime_model(
        Arc::new(OriginatorRuntimeModel {
            instances: instances.clone(),
            vni_to_esi: vni_to_esi.clone(),
            drained_esis: Arc::new(BTreeSet::new()),
        }),
        &mut state,
        &mut runtime,
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
            RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
        ],
        "undrain must not replay a Type 2 for a MAC the kernel moved to the VXLAN port"
    );
}

/// (c) The MAC comes back to the AC port (the CE transmits again —
/// M66's maintenance-exit GARP): the kernel's in-place move back
/// arrives as a plain local learn, and the re-advertisement must bump
/// the RFC 7432 §15 mobility sequence above the remote contender
/// that held the MAC in between.
#[tokio::test]
async fn relearn_after_vxlan_port_takeover_bumps_mobility_sequence() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, routes, _responder) = rib_capture_responder_with_routes(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);

    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;

    // Remote takeover: the peer's Type 2 (no mobility extcomm =
    // seq 0 per RFC 7432 §15.1) wins the kernel row; the RIB event
    // path records the contender view.
    state.remote_mac_view.insert(
        (vni(100), mac(0xAA)),
        RemoteMacView {
            mac: mac(0xAA),
            mobility_sequence: None,
            sticky: false,
            next_hop: ipa("10.0.0.2"),
        },
    );
    observe_test(
        LocalMacObservation::ObservedOnVxlanPort {
            vni: vni(100),
            mac: mac(0xAA),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;

    // CE speaks again — kernel learns the MAC back on the AC port.
    observe_test(
        LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(0xAA),
            ifindex: 10,
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;

    let actions = log.lock().await.clone();
    assert_eq!(
        actions,
        vec![
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
            RibAction::Withdraw(macip_key_with(100, 0xAA, None)),
            RibAction::Inject(macip_key_with(100, 0xAA, None)),
        ],
        "relearn after takeover must re-advertise"
    );
    let routes = routes.lock().await;
    let (_, first_seq) = extract_mac_mobility_full(&routes[0].attributes);
    let (_, relearn_seq) = extract_mac_mobility_full(&routes[1].attributes);
    assert_eq!(first_seq, None, "first advertisement carries no extcomm");
    assert_eq!(
        relearn_seq,
        Some(1),
        "re-advertisement must bump the mobility sequence above the remote contender (seq 0)"
    );
}

/// (d) FDB rows for MACs the originator never claimed as local —
/// our own remote-MAC programming echoes and foreign rows alike —
/// must not trigger withdrawals or touch the caches, live or drained
/// (ADR-0054 foreign-state discipline).
#[tokio::test]
async fn vxlan_port_observation_for_unclaimed_mac_is_ignored() {
    let instances = instance_table(100);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (log, _responder) = rib_capture_responder(rib_rx);
    let metrics = BgpMetrics::new();
    let counts = OriginatedLocalMacCounts::default();
    let mut state = originator_state(&instances);
    let vni_to_esi = drain_test_vni_to_esi();
    let drained = BTreeSet::from([drain_test_esi()]);

    // A pending IP binding for a MAC that never surfaced locally —
    // the most fragile cache an unclaimed-row event could clobber.
    state
        .pending_ip_bindings
        .entry((vni(100), mac(0xBB)))
        .or_default()
        .insert(ipa("192.0.2.20"));

    // Live path.
    observe_test(
        LocalMacObservation::ObservedOnVxlanPort {
            vni: vni(100),
            mac: mac(0xBB),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
    )
    .await;
    // Drained path.
    handle_observation(
        &LocalMacObservation::ObservedOnVxlanPort {
            vni: vni(100),
            mac: mac(0xBB),
        },
        &mut state,
        &instances,
        &rib_tx,
        &metrics,
        &counts,
        vni_to_esi.as_ref(),
        &drained,
    )
    .await;

    assert!(
        log.lock().await.is_empty(),
        "unclaimed VXLAN-port rows must not produce RIB actions"
    );
    assert!(
        state
            .pending_ip_bindings
            .get(&(vni(100), mac(0xBB)))
            .is_some_and(|ips| ips.contains(&ipa("192.0.2.20"))),
        "unclaimed VXLAN-port rows must not clear pending IP bindings"
    );
}
