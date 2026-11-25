//! Admission and recovery at a private `FlowSpec` departure page.

use super::exportability::MockExactExportEncoder;
use super::*;
use crate::manager::distribution::OutboundCommitBatch;
use crate::manager::source_departure::take_flowspec_withdrawal_work;
use crate::outbound_credit::OutboundCharge;
use crate::update::ExactExportKey;
use rustbgpd_wire::{FlowSpecComponent, FlowSpecPrefix};

const CREDIT: usize = 8;
const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);

fn target() -> (RibManager, PeerId, mpsc::Receiver<OutboundRouteUpdate>) {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_outbound_row_credit(CREDIT);
    manager.test_force_ungrouped = true;
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 10));
    let (tx, mut output) = mpsc::channel(16);
    let mut up = super::lifecycle::test_peer_up(peer, 1, tx);
    let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    else {
        unreachable!()
    };
    *sendable_families = ipv4_flowspec_sendable();
    manager.handle_update(up);
    while output.try_recv().is_ok() {}
    (manager, peer, output)
}

fn rule(subnet: u8) -> FlowSpecRoute {
    let mut route = make_flowspec_route(SOURCE);
    route.rule.components = vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, subnet, 0), 24),
    ))];
    route
}

fn announce(manager: &mut RibManager, peer: PeerId, routes: Vec<FlowSpecRoute>) {
    manager
        .try_send_and_commit_outbound_update(
            peer,
            OutboundCommitBatch {
                flowspec_announce: routes,
                ..Default::default()
            },
        )
        .unwrap();
}

#[derive(Clone, Copy, Debug)]
enum Refusal {
    Writer,
    Credit,
    Encoder,
}

#[test]
fn flowspec_departure_refusal_keeps_old_until_recovery_withdraws_it_once() {
    for refusal in [Refusal::Writer, Refusal::Credit, Refusal::Encoder] {
        let (mut manager, peer, mut output) = target();
        let initial = rule(1);
        let key = initial.selection_key();
        announce(&mut manager, peer, vec![initial]);
        assert_eq!(
            output.try_recv().unwrap().flowspec_announce[0].selection_key(),
            key
        );
        let credit = manager.outbound_credit_handle(peer);
        assert_eq!(credit.rows(), 0);
        let fill = FillChannelOnSnapshot::install(&mut manager, peer);
        let mut charge = None;
        let mut encoder = None;
        match refusal {
            Refusal::Writer => fill.arm(),
            Refusal::Credit => charge = Some(OutboundCharge::new(&credit, CREDIT)),
            Refusal::Encoder => encoder = Some(manager.peer_export_encoders.remove(&peer).unwrap()),
        }
        take_flowspec_withdrawal_work();
        manager.distribute_flowspec_departure_page(&HashSet::from([key.clone()]), &[peer]);
        let (_, _, removed) = take_flowspec_withdrawal_work();
        assert_eq!(
            removed, 0,
            "{refusal:?} lost advertised state before admission"
        );
        assert!(manager.adj_ribs_out[&peer].get_flowspec(&key).is_some());
        assert!(output.try_recv().is_err());
        if matches!(refusal, Refusal::Credit) {
            assert!(manager.owes(peer, key.family()));
        } else {
            assert!(manager.dirty_peers.contains(&peer));
        }
        // A refused member handed to the dirty resync counts; owed rows
        // stay paced.
        let expected: &[_] = match refusal {
            Refusal::Writer => &[("source_departure", "writer_unavailable", 1.0)],
            Refusal::Credit => &[],
            Refusal::Encoder => &[("source_departure", "commit_refused", 1.0)],
        };
        crate::manager::tests::assert_paced_fallbacks(&manager.metrics, expected);
        if matches!(refusal, Refusal::Writer) {
            fill.release(); // Also proves refusal happened after the encoder snapshot.
        }
        if let Some(encoder) = encoder {
            manager.peer_export_encoders.insert(peer, encoder);
        }
        drop(charge);
        assert_eq!(credit.rows(), 0);
        manager.resync_dirty_peers_bounded();
        let withdrawn: Vec<_> = std::iter::from_fn(|| output.try_recv().ok())
            .flat_map(|update| update.flowspec_withdraw)
            .collect();
        assert_eq!(
            withdrawn.as_slice(),
            std::slice::from_ref(&key),
            "{refusal:?} recovery"
        );
        assert!(manager.adj_ribs_out[&peer].get_flowspec(&key).is_none());
        assert!(!manager.owes(peer, key.family()));
        assert!(!manager.dirty_peers.contains(&peer));
    }
}

#[test]
fn flowspec_departure_with_an_outstanding_recovery_operation_uses_ordinary_staging() {
    let (mut manager, peer, mut output) = target();
    let route = rule(1);
    let key = route.selection_key();
    announce(&mut manager, peer, vec![route]);
    assert_eq!(output.try_recv().unwrap().flowspec_announce.len(), 1);
    let operation = manager.begin_outbound_operation(peer, 1).unwrap();
    take_flowspec_withdrawal_work();
    manager.distribute_flowspec_departure_page(&HashSet::from([key.clone()]), &[peer]);
    assert_eq!(take_flowspec_withdrawal_work(), (1, 1, 1));
    assert_eq!(output.try_recv().unwrap().flowspec_withdraw, [key]);
    drop(operation);
}

#[test]
fn flowspec_departure_preserves_an_exact_rejection_and_withdraws_its_admitted_neighbor() {
    let (mut manager, peer, mut output) = target();
    let good = rule(1);
    let denied = rule(2);
    let admitted = good.selection_key();
    let rejected = denied.selection_key();
    let overlay = ExactExportKey::FlowSpec(rejected.clone());
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(2, [overlay.clone()]);
    manager.peer_export_encoders.insert(peer, encoder);
    announce(&mut manager, peer, vec![good, denied]);
    let sent = delivered(output.try_recv().unwrap());
    assert_eq!(sent.flowspec_announce.len(), 1);
    assert_eq!(sent.flowspec_announce[0].selection_key(), admitted);
    assert!(manager.peer_unexportable[&peer].contains(&overlay));
    assert!(
        manager.adj_ribs_out[&peer]
            .get_flowspec(&rejected)
            .is_none()
    );
    take_flowspec_withdrawal_work();
    manager
        .distribute_flowspec_departure_page(&HashSet::from([admitted.clone(), rejected]), &[peer]);
    assert_eq!(
        take_flowspec_withdrawal_work().0,
        1,
        "active rejection must retain ordinary staging"
    );
    assert_eq!(
        output.try_recv().unwrap().flowspec_withdraw.as_slice(),
        std::slice::from_ref(&admitted)
    );
    assert!(output.try_recv().is_err());
    assert!(manager.peer_unexportable[&peer].contains(&overlay));
    assert!(
        manager.adj_ribs_out[&peer]
            .get_flowspec(&admitted)
            .is_none()
    );
}

#[test]
fn flowspec_departure_with_a_surviving_winner_uses_ordinary_staging_for_the_page() {
    let (mut manager, peer, mut output) = target();
    let lost = rule(1);
    let lost_key = lost.selection_key();
    let old = rule(2);
    let mut alternate = old.clone();
    alternate.peer = peer_v4(Ipv4Addr::new(198, 51, 100, 11));
    AttrSet::edit(&mut alternate.attributes, |attrs| {
        attrs.push(PathAttribute::Communities(vec![0xfde8_002a]));
    });
    let surviving_key = old.selection_key();
    announce(&mut manager, peer, vec![lost, old]);
    assert_eq!(output.try_recv().unwrap().flowspec_announce.len(), 2);
    assert!(
        manager
            .loc_rib
            .recompute_flowspec(surviving_key.clone(), std::iter::once(&alternate))
    );
    take_flowspec_withdrawal_work();
    manager.distribute_flowspec_departure_page(
        &HashSet::from([lost_key.clone(), surviving_key.clone()]),
        &[peer],
    );
    assert_eq!(take_flowspec_withdrawal_work().0, 1);
    let update = delivered(output.try_recv().unwrap());
    assert_eq!(
        update.flowspec_withdraw.as_slice(),
        std::slice::from_ref(&lost_key)
    );
    assert_eq!(update.flowspec_announce.len(), 1);
    let live = &update.flowspec_announce[0];
    assert_eq!(live.selection_key(), surviving_key);
    assert_eq!(live.peer, alternate.peer);
    assert_eq!(live.communities(), alternate.communities());
    assert_eq!(
        manager.adj_ribs_out[&peer]
            .get_flowspec(&surviving_key)
            .unwrap()
            .peer,
        alternate.peer
    );
    assert!(
        manager.adj_ribs_out[&peer]
            .get_flowspec(&lost_key)
            .is_none()
    );
    assert!(output.try_recv().is_err());
}
