//! RFC 9324 local re-evaluation: a VRP or ASPA change re-runs import policy
//! over retained input instead of asking the peer for Route Refresh.

use super::*;
use crate::{ImportRevalidation, ValidationDelta};
use rustbgpd_rpki::{AspaRecord, AspaTable, ValidationSnapshot, VrpEntry, VrpTable};
use tokio::sync::watch;

const VALID: [u8; 4] = [192, 0, 2, 0];
const INVALID: [u8; 4] = [198, 51, 100, 0];
const OTHER: [u8; 4] = [203, 0, 113, 0];

fn prefix(addr: [u8; 4]) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::from(addr), 24)
}

fn vrp(addr: [u8; 4], origin_asn: u32) -> VrpEntry {
    VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::from(addr)),
        prefix_len: 24,
        max_len: 24,
        origin_asn,
    }
}

fn vrps(entries: Vec<VrpEntry>) -> ValidationSnapshot {
    ValidationSnapshot {
        vrp_table: Some(Arc::new(VrpTable::new(entries))),
        aspa_table: None,
    }
}

fn deny_invalid(rpki: bool) -> PolicyChain {
    import_chain(vec![deny_invalid_statement(rpki)])
}

fn import_chain(entries: Vec<PolicyStatement>) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries,
        default_action: PolicyAction::Permit,
    }])
}

fn deny_invalid_statement(rpki: bool) -> PolicyStatement {
    let mut statement = PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: PolicyAction::Deny,
        match_community: vec![],
        match_as_path: None,
        match_neighbor_set: None,
        match_route_type: None,
        match_evpn_route_type: None,
        match_rpki_validation: None,
        match_aspa_validation: None,
        match_as_path_length_ge: None,
        match_as_path_length_le: None,
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    };
    if rpki {
        statement.match_rpki_validation = Some(rustbgpd_wire::RpkiValidation::Invalid);
    } else {
        statement.match_aspa_validation = Some(rustbgpd_wire::AspaValidation::Invalid);
    }
    statement
}

struct Fixture {
    session: PeerSession,
    rib_rx: mpsc::Receiver<RibUpdate>,
    validation: watch::Sender<ValidationSnapshot>,
    server: TcpStream,
}

async fn fixture(snapshot: ValidationSnapshot, import: PolicyChain) -> Fixture {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.local_revalidation = true;
    let (validation, validation_rx) = watch::channel(snapshot);
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let mut session = PeerSession::new(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        Some(import),
        None,
        None,
        None,
        Some(validation_rx),
        false,
    );
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    read_single_bgp_message(&mut server).await; // OPEN
    read_single_bgp_message(&mut server).await; // KEEPALIVE
    let mut fixture = Fixture {
        session,
        rib_rx,
        validation,
        server,
    };
    fixture.rib_routes();
    fixture
}

fn announce_from(addr: [u8; 4], as_path: Vec<u32>) -> UpdateMessage {
    UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: prefix(addr),
        }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(as_path)],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    )
}

impl Fixture {
    async fn announce(&mut self, addr: [u8; 4]) {
        self.session
            .process_update(announce_from(addr, vec![65002]))
            .await;
    }

    /// Announced and withdrawn prefixes delivered to the RIB since the last call.
    fn rib_routes(&mut self) -> (Vec<Prefix>, Vec<Prefix>) {
        let mut announced = Vec::new();
        let mut withdrawn = Vec::new();
        while let Ok(update) = self.rib_rx.try_recv() {
            if let RibUpdate::RoutesReceived {
                announced: routes,
                withdrawn: gone,
                ..
            } = update
            {
                announced.extend(routes.iter().map(|route| route.prefix));
                withdrawn.extend(gone.iter().map(|(prefix, _)| *prefix));
            }
        }
        (announced, withdrawn)
    }

    fn retained(&self, addr: [u8; 4]) -> Option<bool> {
        self.session
            .validation_retention
            .as_ref()
            .unwrap()
            .retained(&(Prefix::V4(prefix(addr)), 0))
    }

    /// Publish the new snapshot, then run the session's answer and every
    /// queued chunk, as the run loop would.
    async fn revalidate(&mut self, snapshot: ValidationSnapshot, delta: ValidationDelta) {
        self.validation.send_replace(snapshot);
        assert_eq!(
            self.session.revalidate_import(&delta),
            ImportRevalidation::Local {
                refresh_families: Vec::new()
            }
        );
        while self.session.revalidation_pending() {
            self.session.advance_revalidation().await;
        }
    }

    /// Nothing at all reached the peer: in particular no ROUTE-REFRESH.
    async fn assert_wire_silent(&mut self) {
        let next = tokio::time::timeout(
            Duration::from_millis(100),
            read_single_bgp_message(&mut self.server),
        )
        .await;
        assert!(next.is_err(), "unexpected message to the peer: {next:?}");
    }
}

#[tokio::test]
async fn vrp_added_admits_previously_invalid_route_without_route_refresh() {
    let mut f = fixture(vrps(vec![vrp(INVALID, 65099)]), deny_invalid(true)).await;
    f.announce(INVALID).await;
    assert_eq!(f.rib_routes(), (vec![], vec![]));
    assert_eq!(
        f.retained(INVALID),
        Some(false),
        "validation reject retained"
    );

    f.revalidate(
        vrps(vec![vrp(INVALID, 65099), vrp(INVALID, 65002)]),
        ValidationDelta::Rpki(Some(Arc::from(vec![vrp(INVALID, 65002)]))),
    )
    .await;

    assert_eq!(f.rib_routes(), (vec![Prefix::V4(prefix(INVALID))], vec![]));
    assert_eq!(f.retained(INVALID), Some(true));
    f.assert_wire_silent().await;
}

#[tokio::test]
async fn vrp_removed_withdraws_accepted_route_locally() {
    let mut f = fixture(vrps(vec![vrp(VALID, 65002)]), deny_invalid(true)).await;
    f.announce(VALID).await;
    assert_eq!(f.rib_routes(), (vec![Prefix::V4(prefix(VALID))], vec![]));

    f.revalidate(
        vrps(vec![vrp(VALID, 65099)]),
        ValidationDelta::Rpki(Some(Arc::from(vec![vrp(VALID, 65002), vrp(VALID, 65099)]))),
    )
    .await;

    assert_eq!(f.rib_routes(), (vec![], vec![Prefix::V4(prefix(VALID))]));
    assert_eq!(
        f.retained(VALID),
        Some(false),
        "now Invalid, still retained for a later VRP"
    );
    f.assert_wire_silent().await;
}

#[tokio::test]
async fn unrelated_delta_touches_no_retained_route() {
    let mut f = fixture(
        vrps(vec![vrp(VALID, 65002), vrp(INVALID, 65099)]),
        deny_invalid(true),
    )
    .await;
    f.announce(VALID).await;
    f.announce(INVALID).await;
    f.rib_routes();

    f.validation.send_replace(vrps(vec![
        vrp(VALID, 65002),
        vrp(INVALID, 65099),
        vrp(OTHER, 65002),
    ]));
    let delta = ValidationDelta::Rpki(Some(Arc::from(vec![vrp(OTHER, 65002)])));
    assert!(matches!(
        f.session.revalidate_import(&delta),
        ImportRevalidation::Local { .. }
    ));
    assert!(
        !f.session.revalidation_pending(),
        "a delta covering no retained prefix queues nothing"
    );
    assert_eq!(f.rib_routes(), (vec![], vec![]));
    assert_eq!(f.retained(VALID), Some(true));
    assert_eq!(f.retained(INVALID), Some(false));
}

#[tokio::test]
async fn withdrawn_retained_route_is_not_resurrected() {
    let mut f = fixture(vrps(vec![vrp(INVALID, 65099)]), deny_invalid(true)).await;
    let fixed = || vrps(vec![vrp(INVALID, 65099), vrp(INVALID, 65002)]);
    let delta = || ValidationDelta::Rpki(Some(Arc::from(vec![vrp(INVALID, 65002)])));

    // Withdrawn before the delta.
    f.announce(INVALID).await;
    f.session
        .process_update(ipv4_withdraw(prefix(INVALID), 0, false))
        .await;
    assert_eq!(f.retained(INVALID), None);
    f.rib_routes();
    f.revalidate(fixed(), delta()).await;
    assert_eq!(f.rib_routes(), (vec![], vec![]));

    // Withdrawn after the delta queued it, before its chunk ran.
    f.validation.send_replace(vrps(vec![vrp(INVALID, 65099)]));
    f.announce(INVALID).await;
    f.validation.send_replace(fixed());
    assert!(matches!(
        f.session.revalidate_import(&delta()),
        ImportRevalidation::Local { .. }
    ));
    assert!(f.session.revalidation_pending());
    f.session
        .process_update(ipv4_withdraw(prefix(INVALID), 0, false))
        .await;
    f.rib_routes();
    while f.session.revalidation_pending() {
        f.session.advance_revalidation().await;
    }
    assert_eq!(f.rib_routes(), (vec![], vec![]));
    f.assert_wire_silent().await;
}

#[tokio::test]
async fn non_validation_reject_is_not_retained() {
    // Deny everything from 198.51.100.0/24 regardless of validation state.
    let chain = import_chain(vec![
        PolicyStatement {
            prefix: Some(Prefix::V4(prefix(INVALID))),
            match_rpki_validation: None,
            ..deny_invalid_statement(true)
        },
        deny_invalid_statement(true),
    ]);
    let mut f = fixture(vrps(vec![vrp(INVALID, 65099)]), chain).await;
    f.announce(INVALID).await;
    assert_eq!(f.retained(INVALID), None);
}

#[tokio::test]
async fn reject_bound_overflow_falls_back_to_route_refresh() {
    let mut f = fixture(
        vrps(vec![vrp(VALID, 65099), vrp(INVALID, 65099)]),
        deny_invalid(true),
    )
    .await;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    install_test_negotiated_session(&mut f.session, negotiated);
    f.session
        .validation_retention
        .as_mut()
        .unwrap()
        .set_reject_limit(1);
    f.announce(VALID).await;
    assert_eq!(f.retained(VALID), Some(false));

    // Queue work, then overflow before it runs: the queue cannot be honoured
    // locally, so the session asks for the peer's replay at once.
    assert!(matches!(
        f.session
            .revalidate_import(&ValidationDelta::Rpki(Some(Arc::from(vec![vrp(
                VALID, 65002
            )])))),
        ImportRevalidation::Local { .. }
    ));
    f.announce(INVALID).await;
    assert!(!f.session.revalidation_pending());
    let refresh = tokio::time::timeout(
        Duration::from_secs(1),
        read_single_bgp_message(&mut f.server),
    )
    .await
    .expect("overflow with queued work must request Route Refresh");
    assert!(matches!(
        refresh,
        Message::RouteRefresh(refresh) if refresh.afi() == Some(Afi::Ipv4) && refresh.safi() == Some(Safi::Unicast)
    ));

    // Every later delta is answered Incomplete: the peer manager refreshes.
    assert_eq!(
        f.session.revalidate_import(&ValidationDelta::Rpki(None)),
        ImportRevalidation::Incomplete
    );
}

#[tokio::test]
async fn session_reset_clears_retained_input() {
    let mut f = fixture(vrps(vec![vrp(INVALID, 65099)]), deny_invalid(true)).await;
    f.announce(VALID).await;
    f.announce(INVALID).await;
    assert_eq!(
        f.session.validation_retention.as_ref().unwrap().len(),
        (2, 1)
    );
    f.session
        .drive_fsm(Event::ManualStop { reason: None })
        .await;
    let retention = f.session.validation_retention.as_ref().unwrap();
    assert_eq!(retention.len(), (0, 0));
    assert!(retention.is_complete());
}

#[tokio::test]
async fn enhanced_refresh_window_sweeps_unreplayed_retained_input() {
    let mut f = fixture(vrps(vec![vrp(INVALID, 65099)]), deny_invalid(true)).await;
    f.announce(INVALID).await;
    f.session.begin_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    // The peer has not re-sent the route yet: nothing local to replay.
    f.revalidate(
        vrps(vec![vrp(INVALID, 65099), vrp(INVALID, 65002)]),
        ValidationDelta::Rpki(Some(Arc::from(vec![vrp(INVALID, 65002)]))),
    )
    .await;
    assert_eq!(f.rib_routes(), (vec![], vec![]));
    // EoRR without a replay: the peer stopped announcing it.
    f.session.end_refresh_accounting(Afi::Ipv4, Safi::Unicast);
    assert_eq!(f.retained(INVALID), None);
}

fn aspa(records: Vec<(u32, u32)>) -> ValidationSnapshot {
    ValidationSnapshot {
        vrp_table: None,
        aspa_table: Some(Arc::new(AspaTable::new(
            records
                .into_iter()
                .map(|(customer_asn, provider)| AspaRecord {
                    customer_asn,
                    provider_asns: vec![provider],
                })
                .collect(),
        ))),
    }
}

#[tokio::test]
async fn aspa_change_admits_and_withdraws_locally() {
    // [65002, 65004]: Invalid while 65004 authorizes only 65099.
    let mut f = fixture(
        aspa(vec![(65004, 65099), (65003, 65002)]),
        deny_invalid(false),
    )
    .await;
    f.session
        .process_update(announce_from(INVALID, vec![65002, 65004]))
        .await;
    f.session
        .process_update(announce_from(VALID, vec![65002, 65003]))
        .await;
    assert_eq!(f.rib_routes(), (vec![Prefix::V4(prefix(VALID))], vec![]));
    assert_eq!(f.retained(INVALID), Some(false));

    // An unrelated customer ASN changes: nothing is queued.
    f.validation
        .send_replace(aspa(vec![(65004, 65099), (65003, 65002), (65123, 1)]));
    let unrelated = ValidationDelta::Aspa(Some(Arc::new([65123].into_iter().collect())));
    assert!(matches!(
        f.session.revalidate_import(&unrelated),
        ImportRevalidation::Local { .. }
    ));
    assert!(!f.session.revalidation_pending());

    // 65004 now authorizes 65002, 65003 stops doing so.
    f.revalidate(
        aspa(vec![(65004, 65002), (65003, 65099)]),
        ValidationDelta::Aspa(Some(Arc::new([65003, 65004].into_iter().collect()))),
    )
    .await;
    assert_eq!(
        f.rib_routes(),
        (
            vec![Prefix::V4(prefix(INVALID))],
            vec![Prefix::V4(prefix(VALID))]
        )
    );
    f.assert_wire_silent().await;
}

#[tokio::test]
async fn ipv6_mp_reach_input_replays_with_its_next_hop() {
    let v6 = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);
    let covering = |origin_asn| VrpEntry {
        prefix: IpAddr::V6("2001:db8::".parse().unwrap()),
        prefix_len: 32,
        max_len: 48,
        origin_asn,
    };
    let mut f = fixture(
        ValidationSnapshot {
            vrp_table: Some(Arc::new(VrpTable::new(vec![covering(65099)]))),
            aspa_table: None,
        },
        deny_invalid(true),
    )
    .await;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut f.session, negotiated);
    f.session.process_update(ipv6_announce(v6, 0)).await;
    assert_eq!(f.rib_routes(), (vec![], vec![]));

    f.validation.send_replace(ValidationSnapshot {
        vrp_table: Some(Arc::new(VrpTable::new(vec![
            covering(65099),
            covering(65002),
        ]))),
        aspa_table: None,
    });
    let delta = ValidationDelta::Rpki(Some(Arc::from(vec![covering(65002)])));
    assert!(matches!(
        f.session.revalidate_import(&delta),
        ImportRevalidation::Local { .. }
    ));
    while f.session.revalidation_pending() {
        f.session.advance_revalidation().await;
    }
    let mut announced = Vec::new();
    while let Ok(update) = f.rib_rx.try_recv() {
        if let RibUpdate::RoutesReceived {
            announced: routes, ..
        } = update
        {
            announced.extend(routes);
        }
    }
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].prefix, Prefix::V6(v6));
    assert_eq!(
        announced[0].next_hop,
        IpAddr::V6("2001:db8::2".parse().unwrap())
    );
}

#[tokio::test]
async fn run_loop_answers_then_replays_queued_work() {
    let mut f = fixture(vrps(vec![vrp(INVALID, 65099)]), deny_invalid(true)).await;
    f.announce(INVALID).await;
    f.rib_routes();
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    f.session.commands = cmd_rx;
    f.validation
        .send_replace(vrps(vec![vrp(INVALID, 65099), vrp(INVALID, 65002)]));
    let Fixture {
        mut session,
        mut rib_rx,
        validation: _validation,
        mut server,
    } = f;
    let actor = tokio::spawn(async move { session.run().await });

    let (reply, answer) = oneshot::channel();
    cmd_tx
        .send(PeerCommand::RevalidateImport {
            delta: ValidationDelta::Rpki(Some(Arc::from(vec![vrp(INVALID, 65002)]))),
            reply,
        })
        .await
        .unwrap();
    assert_eq!(
        answer.await.unwrap(),
        ImportRevalidation::Local {
            refresh_families: Vec::new()
        }
    );
    let announced = loop {
        if let RibUpdate::RoutesReceived { announced, .. } =
            tokio::time::timeout(Duration::from_secs(1), rib_rx.recv())
                .await
                .expect("queued re-evaluation reaches the RIB")
                .unwrap()
        {
            break announced;
        }
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].prefix, Prefix::V4(prefix(INVALID)));
    let next = tokio::time::timeout(
        Duration::from_millis(100),
        read_single_bgp_message(&mut server),
    )
    .await;
    assert!(next.is_err(), "unexpected message to the peer: {next:?}");
    actor.abort();
}
