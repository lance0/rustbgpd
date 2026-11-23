//! Compare the actual TCP UPDATEs of cold authoritative apply and restore against
//! the same members below the production pacing threshold.
use super::*;
use rustbgpd_rib::{PeerExportPolicyReplacement, PeerExportPolicyRestoreReceipt};
use std::collections::{BTreeMap, BTreeSet};

const OLD: u32 = 0xfde8_0011;
const NEW: u32 = 0xfde8_0022;
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

fn policy(tag: u32) -> PolicyChain {
    let entries = [0, if tag == OLD { 1 } else { 2 }]
        .map(|i| {
            let mut statement =
                retention_statement(Some(Prefix::V4(v4_prefix(i))), PolicyAction::Permit);
            statement.modifications.communities_add.push(tag);
            statement
        })
        .into();
    PolicyChain::new(vec![Policy {
        entries,
        default_action: PolicyAction::Deny,
    }])
}

struct Member {
    session: PeerSession,
    socket: TcpStream,
    exports: mpsc::Receiver<OutboundRouteUpdate>,
}

type Announcements = BTreeMap<Ipv4Prefix, Vec<PathAttribute>>;

#[derive(Debug, Default, PartialEq, Eq)]
struct Delta {
    announce: Announcements,
    withdraw: BTreeSet<Ipv4Prefix>,
}

impl Member {
    async fn register(primary: &mpsc::Sender<RibUpdate>, last: u8) -> Self {
        let (mut session, _) = make_test_session_with_rib(65001, 65002);
        session.rib_tx = primary.clone();
        session.peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last));
        let (client, socket) = connected_stream_pair().await;
        session.test_install_stream(client);
        install_test_negotiated_session(&mut session, negotiated_session(65002, false));
        session.publish_export_profile();
        let mut exports = register_export_session(&session, 1, Some(policy(OLD))).await;
        assert_eq!(
            next_export(&mut exports).await.end_of_rib,
            [(Afi::Ipv4, Safi::Unicast)]
        );
        Self {
            session,
            socket,
            exports,
        }
    }

    async fn read_delta(&mut self) -> Delta {
        while let Ok(envelope) = self.exports.try_recv() {
            self.session.test_drain_outbound(envelope).await;
        }
        // Same FIFO and writer as the data. The marker makes an extra frame
        // visible and terminates even a completely empty phase.
        self.session.enqueue_bulk(&Message::Keepalive).unwrap();
        let mut delta = Delta::default();
        loop {
            match read_single_bgp_message(&mut self.socket).await {
                Message::Keepalive => return delta,
                Message::Update(update) => {
                    let parsed = update.parse(true, false, &[]).unwrap();
                    assert!(!parsed.announced.is_empty() || !parsed.withdrawn.is_empty());
                    for route in parsed.withdrawn {
                        assert_eq!(route.path_id, 0);
                        assert!(delta.withdraw.insert(route.prefix), "duplicate withdrawal");
                    }
                    for route in parsed.announced {
                        assert_eq!(route.path_id, 0);
                        assert!(
                            delta
                                .announce
                                .insert(route.prefix, parsed.attributes.clone())
                                .is_none(),
                            "duplicate announcement"
                        );
                    }
                }
                other => panic!("unexpected message from established peer: {other:?}"),
            }
        }
    }
}

fn group(primary: &mpsc::Sender<RibUpdate>, peer: PeerId) -> oneshot::Receiver<String> {
    let (reply, response) = oneshot::channel();
    primary
        .try_send(RibUpdate::QueryPeerUpdateGroup { peer, reply })
        .unwrap();
    response
}

async fn capture(members: &mut [Member; 2], tag: u32, withdraw: Option<u8>) -> [Delta; 2] {
    let [first, second] = members;
    let (first, second) = tokio::join!(first.read_delta(), second.read_delta());
    for delta in [&first, &second] {
        let exclusive = if tag == OLD { 1 } else { 2 };
        assert_eq!(
            delta.announce.keys().copied().collect::<Vec<_>>(),
            [v4_prefix(0), v4_prefix(exclusive)]
        );
        assert_eq!(
            delta.withdraw,
            withdraw.into_iter().map(v4_prefix).collect()
        );
        for attrs in delta.announce.values() {
            let communities: Vec<_> = attrs
                .iter()
                .filter_map(|attr| match attr {
                    PathAttribute::Communities(values) => Some(values.as_slice()),
                    _ => None,
                })
                .collect();
            assert_eq!(communities, [&[tag][..]]);
        }
    }
    [first, second]
}

async fn reload_and_restore(filler: u32) -> Vec<[Delta; 2]> {
    let (primary, rx) = mpsc::channel(64);
    let (query, queries) = mpsc::channel(8);
    let actor = tokio::spawn(
        rustbgpd_rib::RibManager::new(rx, queries, None, None, BgpMetrics::new()).run(),
    );
    let mut members = [
        Member::register(&primary, 2).await,
        Member::register(&primary, 3).await,
    ];
    let peers = members
        .each_ref()
        .map(|m| PeerId::from_addr(m.session.peer_ip));
    register_test_source(&primary, PeerId::from_ipv4(SOURCE), 0).await;
    // Only the three witnesses can reach either socket. The extra /32s are
    // distinct Loc-RIB winners denied by both policies.
    let prefixes = (0..3)
        .map(v4_prefix)
        .chain((0..filler).map(|i| Ipv4Prefix::new(Ipv4Addr::from(0x0a40_0000 + i), 32)));
    primary
        .send(RibUpdate::RoutesReceived {
            peer: PeerId::from_ipv4(SOURCE),
            session_id: 0,
            announced: prefixes
                .map(|p| make_sourced_route(SOURCE, p, 65009))
                .collect(),
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    let (reply, count) = oneshot::channel();
    primary
        .send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    assert_eq!(count.await.unwrap(), usize::try_from(filler + 3).unwrap());
    let mut phases = vec![capture(&mut members, OLD, None).await];
    for (target, withdrawn) in [(NEW, 1), (OLD, 2)] {
        let source = group(&primary, peers[0]).await.unwrap();
        assert!(source.starts_with("group:"));
        assert_eq!(group(&primary, peers[1]).await.unwrap(), source);
        let replacements = peers
            .map(|peer| PeerExportPolicyReplacement {
                peer,
                export_policy: Some(policy(target)),
            })
            .into();
        let (forward, applied) = oneshot::channel();
        let (rollback, restored) = oneshot::channel();
        let command = if target == NEW {
            RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements,
                reply: forward,
            }
        } else {
            RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                replacements,
                reply: rollback,
            }
        };
        primary.try_send(command).unwrap();
        if target == NEW {
            assert_eq!(applied.await.unwrap().unwrap(), Vec::<PeerId>::new());
        } else {
            assert_eq!(
                restored.await.unwrap().unwrap(),
                [peers[1], peers[0]].map(|peer| PeerExportPolicyRestoreReceipt::Restored { peer })
            );
        }
        let destination = group(&primary, peers[0]).await.unwrap();
        assert_ne!(destination, source);
        assert_eq!(group(&primary, peers[1]).await.unwrap(), destination);
        phases.push(capture(&mut members, target, Some(withdrawn)).await);
    }
    drop((members, primary, query));
    actor.await.unwrap();
    phases
}

#[tokio::test]
async fn authoritative_reload_and_restore_match_synchronous_receiver_updates() {
    let synchronous = Box::pin(reload_and_restore(0)).await;
    let paged = Box::pin(reload_and_restore(10_000)).await;
    assert_eq!(
        paged, synchronous,
        "decoded path attributes and NLRI on each real TCP receiver"
    );
}
