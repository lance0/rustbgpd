//! An accepted reload owns its result even if the peer manager stops waiting.

use std::future::{Future, poll_fn};

use crate::manager::tests::update_groups::community_chain;
use crate::{PeerExportPolicyReplacement, PeerExportPolicyRestoreReceipt};

use super::*;

const PRIOR: u32 = 0xfde8_0021;
const NEXT: u32 = PRIOR + 1;
const ROWS: u16 = 2050;

type RestoreReply =
    oneshot::Receiver<Result<Vec<PeerExportPolicyRestoreReceipt>, crate::RibCommandError>>;

fn registration(
    peer: PeerId,
    session: u64,
    tag: u32,
) -> (RibUpdate, mpsc::Receiver<OutboundRouteUpdate>) {
    let (tx, rx) = mpsc::channel(64);
    let mut up = test_peer_up(peer, session, tx);
    let RibUpdate::PeerUp {
        is_ebgp,
        route_reflector_client,
        export_policy,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *is_ebgp = false;
    *route_reflector_client = true;
    *export_policy = Some(community_chain(tag));
    (up, rx)
}

fn replacements(tag: u32) -> Vec<PeerExportPolicyReplacement> {
    [receiver(1), receiver(2)]
        .into_iter()
        .map(|peer| PeerExportPolicyReplacement {
            peer,
            export_policy: Some(community_chain(tag)),
        })
        .collect()
}

fn marker_tags(update: &OutboundRouteUpdate, prefix: Prefix) -> impl Iterator<Item = u32> + '_ {
    assert!(!update.unicast_withdrawals().any(|key| key.0 == prefix));
    update
        .announce
        .iter()
        .filter(move |row| row.prefix == prefix)
        .map(|row| {
            let [tag] = row.communities() else {
                panic!("expected one export-generation community on {}", row.prefix);
            };
            *tag
        })
}

struct Reload {
    manager: RibManager,
    primary: mpsc::Sender<RibUpdate>,
    outputs: [mpsc::Receiver<OutboundRouteUpdate>; 2],
}

impl Reload {
    fn new() -> Self {
        let (mut manager, primary, _) = fixture(0);
        manager.handle_update(test_routes_received(
            peer_v4(SOURCE),
            (0..ROWS)
                .map(|i| route(prefixes(i)[0], SOURCE, 100))
                .collect(),
        ));
        drain_route_chunks(&mut manager);
        let outputs = [receiver(1), receiver(2)].map(|peer| {
            let (up, mut rx) = registration(peer, 1, PRIOR);
            manager.handle_update(up);
            finish(&mut manager);
            let mut count = 0;
            while let Ok(update) = rx.try_recv() {
                for row in update.announce.iter() {
                    assert_eq!(row.communities(), &[PRIOR]);
                    count += 1;
                }
            }
            assert_eq!(count, usize::from(ROWS));
            rx
        });
        assert_eq!(
            manager
                .grouped_member_of(receiver(1))
                .expect("source group"),
            manager.grouped_member_of(receiver(2)).unwrap()
        );
        Self {
            manager,
            primary,
            outputs,
        }
    }

    fn forward(&self) -> PolicyReply {
        self.forward_with(replacements(NEXT))
    }

    fn forward_with(&self, replacements: Vec<PeerExportPolicyReplacement>) -> PolicyReply {
        let (reply, response) = oneshot::channel();
        self.primary
            .try_send(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            })
            .unwrap();
        response
    }

    fn restore(&self) -> RestoreReply {
        let (reply, response) = oneshot::channel();
        self.primary
            .try_send(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                replacements: replacements(PRIOR),
                reply,
            })
            .unwrap();
        response
    }

    // Observe a real staged route, rather than equating channel admission with
    // acceptance of the command or assuming that one particular bucket is full.
    fn accept(&mut self) -> Prefix {
        let update = self.manager.try_recv_primary().expect("queued command");
        self.manager.handle_update(update);
        for _ in 0..16 {
            assert!(
                self.manager.first_group_build.is_some(),
                "expected an accepted private build"
            );
            if let Some(prefix) = (0..ROWS)
                .map(|i| prefixes(i)[0])
                .find(|&prefix| self.manager.first_group_contains(prefix))
            {
                return prefix;
            }
            self.manager.advance_first_group_build();
        }
        panic!("expected an unpublished destination row");
    }

    // Let the real actor drain a finite primary queue and work it has accepted.
    // Read the receivers after every physical poll to release the session credit.
    async fn finish(self, marker: Prefix) -> (RibManager, [Vec<u32>; 2]) {
        let Self {
            manager,
            primary,
            mut outputs,
        } = self;
        drop(primary);
        let mut actor = Box::pin(manager.run_actor());
        let mut tags = [Vec::new(), Vec::new()];
        let manager = poll_fn(|cx| {
            let result = actor.as_mut().poll(cx);
            for (rx, seen) in outputs.iter_mut().zip(&mut tags) {
                while let Ok(update) = rx.try_recv() {
                    seen.extend(marker_tags(&update, marker));
                }
            }
            result
        })
        .await;
        (manager, tags)
    }
}

fn assert_tag(manager: &RibManager, peer: PeerId, prefix: Prefix, tag: u32) {
    let group = manager.grouped_member_of(peer).expect("installed member");
    let row = manager.group_ribs[&group].table.get(&prefix, 0).unwrap();
    assert_eq!(row.communities(), &[tag]);
}

fn restored(peer: PeerId) -> PeerExportPolicyRestoreReceipt {
    PeerExportPolicyRestoreReceipt::Restored { peer }
}

#[tokio::test]
async fn closed_forward_before_acceptance_leaves_no_candidate_output() {
    let reload = Reload::new();
    drop(reload.forward());
    let mut restore = reload.restore();
    let sentinel = prefixes(0)[0];
    let (manager, tags) = reload.finish(sentinel).await;
    assert_eq!(
        restore.try_recv().unwrap().unwrap(),
        [restored(receiver(2)), restored(receiver(1))]
    );
    for (peer, seen) in [receiver(1), receiver(2)].into_iter().zip(tags) {
        assert!(seen.is_empty(), "abandoned forward emitted {seen:?}");
        assert_tag(&manager, peer, sentinel, PRIOR);
    }
}

#[tokio::test]
async fn closed_forward_after_acceptance_finishes_before_the_queued_restore() {
    let mut reload = Reload::new();
    let mut forward = reload.forward();
    reload.accept();
    assert_eq!(forward.try_recv(), Err(oneshot::error::TryRecvError::Empty));

    let (marker, update) = other_marker();
    reload.primary.try_send(update).unwrap();
    build_turns_until_installed(&mut reload.manager, marker).await;
    for (peer, rx) in [receiver(1), receiver(2)]
        .into_iter()
        .zip(&mut reload.outputs)
    {
        assert_tag(&reload.manager, peer, marker, PRIOR);
        let update = rx
            .try_recv()
            .expect("the old policy served the live update");
        assert_eq!(marker_tags(&update, marker).collect::<Vec<_>>(), [PRIOR]);
    }
    assert_eq!(forward.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    drop(forward);
    let mut restore = reload.restore();
    let (manager, tags) = reload.finish(marker).await;
    assert_eq!(
        restore.try_recv().unwrap().unwrap(),
        [restored(receiver(2)), restored(receiver(1))]
    );
    for (peer, seen) in [receiver(1), receiver(2)].into_iter().zip(tags) {
        assert_eq!(
            seen,
            [NEXT, PRIOR],
            "restore overtook or lost the accepted change"
        );
        assert_tag(&manager, peer, marker, PRIOR);
    }
}

#[tokio::test]
async fn closed_mandatory_restore_reinstalls_prior_after_accepted_forward() {
    let mut reload = Reload::new();
    let mut forward = reload.forward();
    reload.accept();
    assert_eq!(forward.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    drop(reload.restore());
    let sentinel = prefixes(0)[0];
    let (manager, tags) = reload.finish(sentinel).await;
    assert_eq!(forward.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    for (peer, seen) in [receiver(1), receiver(2)].into_iter().zip(tags) {
        assert_eq!(seen, [NEXT, PRIOR]);
        assert_tag(&manager, peer, sentinel, PRIOR);
    }
}

#[tokio::test]
async fn departure_before_queued_restore_gets_not_found_and_rejoin_uses_new_session_policy() {
    let mut reload = Reload::new();
    let mut forward = reload.forward();
    reload.accept();
    reload
        .primary
        .try_send(RibUpdate::PeerDown {
            peer: receiver(2),
            session_id: 1,
        })
        .unwrap();
    let mut restore = reload.restore();
    let sentinel = prefixes(0)[0];
    let (mut manager, tags) = reload.finish(sentinel).await;
    assert_eq!(forward.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    assert_eq!(
        restore.try_recv().unwrap().unwrap(),
        [
            PeerExportPolicyRestoreReceipt::NotFound { peer: receiver(2) },
            restored(receiver(1))
        ]
    );
    assert_eq!(tags[0], [NEXT, PRIOR]);
    assert!(manager.current_session_id(receiver(2)).is_none());
    assert_tag(&manager, receiver(1), sentinel, PRIOR);

    let (up, mut rx) = registration(receiver(2), 2, NEXT + 1);
    manager.handle_update(up);
    finish(&mut manager);
    assert_tag(&manager, receiver(2), sentinel, NEXT + 1);
    let mut replay = Vec::new();
    while let Ok(update) = rx.try_recv() {
        replay.extend(marker_tags(&update, sentinel));
    }
    assert_eq!(replay, [NEXT + 1]);
}

#[tokio::test]
async fn rpki_refresh_behind_accepted_reload_revalidates_a_staged_prefix() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};

    let mut reload = Reload::new();
    let mut terms = community_chain(NEXT).policies;
    let mut valid = community_chain(NEXT + 1).policies[0].policy.entries[0].clone();
    valid.match_rpki_validation = Some(RpkiValidation::Valid);
    terms[0].policy.entries.insert(0, valid);
    let chain = rustbgpd_policy::PolicyChain::from_named(terms);
    let mut forward = reload.forward_with(
        [receiver(1), receiver(2)]
            .into_iter()
            .map(|peer| PeerExportPolicyReplacement {
                peer,
                export_policy: Some(chain.clone()),
            })
            .collect(),
    );
    let sentinel = reload.accept();
    let Prefix::V4(prefix) = sentinel else {
        unreachable!()
    };
    assert_eq!(
        reload
            .manager
            .loc_rib
            .get(&sentinel)
            .unwrap()
            .validation_state,
        RpkiValidation::NotFound
    );
    reload
        .primary
        .try_send(RibUpdate::RpkiCacheUpdate {
            table: Arc::new(VrpTable::new(vec![VrpEntry {
                prefix: IpAddr::V4(prefix.addr),
                prefix_len: 32,
                max_len: 32,
                origin_asn: 65001,
            }])),
            delta: None,
            admission: None,
        })
        .unwrap();
    let (manager, tags) = reload.finish(sentinel).await;
    assert_eq!(forward.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    assert_eq!(
        manager.loc_rib.get(&sentinel).unwrap().validation_state,
        RpkiValidation::Valid
    );
    for (peer, seen) in [receiver(1), receiver(2)].into_iter().zip(tags) {
        assert_eq!(seen.last(), Some(&(NEXT + 1)));
        assert_tag(&manager, peer, sentinel, NEXT + 1);
    }
}

#[tokio::test]
async fn mutable_dataset_destination_uses_current_denials_on_the_synchronous_path() {
    use crate::manager::tests::cursor_presize::prefix_dataset;
    use crate::manager::tests::local_route_export::allowed_dataset_chain;

    let mut reload = Reload::new();
    let (chain, handle) = allowed_dataset_chain(
        "policy p { term t { if route.prefix in allowed { reject } accept } }",
        false,
    );
    let sentinel = prefixes(0)[0];
    assert_eq!(handle.refresh(prefix_dataset([sentinel])), Some(2));
    let mut response = reload.forward_with(
        [receiver(1), receiver(2)]
            .into_iter()
            .map(|peer| PeerExportPolicyReplacement {
                peer,
                export_policy: Some(chain.clone()),
            })
            .collect(),
    );
    let request = reload.manager.try_recv_primary().unwrap();
    reload.manager.handle_update(request);
    assert!(reload.manager.first_group_build.is_none());
    assert_eq!(response.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    for (peer, mut rx) in [receiver(1), receiver(2)].into_iter().zip(reload.outputs) {
        let group = &reload.manager.group_ribs[&reload.manager.grouped_member_of(peer).unwrap()];
        assert!(group.table.get(&sentinel, 0).is_none());
        assert_eq!(group.table.len(), usize::from(ROWS) - 1);
        let mut withdrawals = Vec::new();
        while let Ok(update) = rx.try_recv() {
            withdrawals.extend(update.unicast_withdrawals().copied());
        }
        assert_eq!(withdrawals, [(sentinel, 0)]);
    }
}

#[tokio::test]
async fn reload_pages_freeze_affected_summaries_while_unrelated_rows_stay_live() {
    let mut reload = Reload::new();
    let mover = receiver(1);
    let sibling = receiver(3);
    let witness = receiver(4);
    let (up, mut sibling_rx) = registration(sibling, 1, PRIOR);
    reload.manager.handle_update(up);
    finish(&mut reload.manager);
    while sibling_rx.try_recv().is_ok() {}
    assert_eq!(
        reload.manager.grouped_member_of(mover),
        reload.manager.grouped_member_of(sibling)
    );
    let (up, mut witness_rx) = registration(witness, 1, PRIOR + 2);
    reload.manager.handle_update(up);
    finish(&mut reload.manager);
    while witness_rx.try_recv().is_ok() {}
    assert_ne!(
        reload.manager.grouped_member_of(mover),
        reload.manager.grouped_member_of(witness)
    );
    let mover_at_entry = reload.manager.neighbor_rib_snapshot(mover);
    let sibling_at_entry = reload.manager.neighbor_rib_snapshot(sibling);
    let witness_at_entry = reload.manager.neighbor_rib_snapshot(witness);

    let (summary, summary_rx) = mpsc::channel(1);
    reload.manager = reload.manager.with_summary_queries(summary_rx);
    let (general, general_rx) = mpsc::channel(1);
    reload.manager.query_rx = general_rx;
    let mut forward = reload.forward();
    reload.accept();

    let (reply, mut policy_read) = oneshot::channel();
    general
        .try_send(RibUpdate::QueryInstalledExportChain { peer: mover, reply })
        .unwrap();
    // Visit the normal post-update drain before admitting the marker. Taking the
    // general head here would seal the build and put the marker behind commit.
    reload.manager.drain_general_queries_if_unfenced();
    assert!(matches!(
        policy_read.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let (marker, update) = other_marker();
    reload.primary.try_send(update).unwrap();
    build_turns_until_installed(&mut reload.manager, marker).await;
    assert_tag(&reload.manager, mover, marker, PRIOR);
    assert_tag(&reload.manager, witness, marker, PRIOR + 2);
    for (rx, tag) in [
        (&mut witness_rx, PRIOR + 2),
        (&mut reload.outputs[0], PRIOR),
    ] {
        let mut seen = Vec::new();
        while let Ok(update) = rx.try_recv() {
            seen.extend(marker_tags(&update, marker));
        }
        assert_eq!(seen, [tag], "the live marker must arrive during the build");
    }
    let live_witness = reload.manager.neighbor_rib_snapshot(witness);
    for (peer, row) in [(mover, &mover_at_entry), (sibling, &sibling_at_entry)] {
        assert_eq!(
            reload.manager.neighbor_rib_snapshot(peer).advertised_count,
            row.advertised_count + 1
        );
    }
    assert_eq!(
        live_witness.advertised_count,
        witness_at_entry.advertised_count + 1
    );

    let (reply, mut rows) = oneshot::channel();
    summary
        .try_send(crate::update::RibSummaryQuery::NeighborRibSnapshots {
            peers: vec![mover, sibling, witness],
            comparison: None,
            include_retained: false,
            reply,
        })
        .unwrap();
    reload.manager.drain_general_queries_if_unfenced();
    assert_eq!(
        rows.try_recv()
            .expect("summary served before commit")
            .snapshots,
        [mover_at_entry, sibling_at_entry, live_witness]
    );
    assert_eq!(forward.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    assert!(matches!(
        policy_read.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let (manager, ()) = tokio::join!(reload.manager.run_actor(), async move {
        let installed = policy_read.await.unwrap().expect("registered mover");
        assert_eq!(
            installed.chain.as_deref(),
            Some(community_chain(NEXT).compiled())
        );
        assert_eq!(
            forward.try_recv().expect("terminal policy reply").unwrap(),
            Vec::<PeerId>::new()
        );
        drop(reload.primary);
    });
    assert_tag(&manager, mover, marker, NEXT);
}
