//! Differential oracle for update-group staging (design risk 1).
//!
//! Every scenario runs twice through the REAL manager task: once with
//! grouping live and once with the `test_force_ungrouped` hook putting
//! every peer on the per-peer path — the correctness oracle. The
//! per-peer outbound streams must be IDENTICAL message for message
//! (announces normalized by sort; intra-message ordering is `HashSet`
//! iteration order and deliberately not part of the contract).
//!
//! The one scenario compared by FINAL ADVERTISED STATE instead of exact
//! streams is the dirty-member resync: a grouped member keeps no
//! per-peer advertised record, so its resync deliberately over-emits
//! (full-table announce + tombstone over-withdraw — the safe
//! direction) where the per-peer path diffs against Adj-RIB-Out. The
//! folded end state must still be identical.

use std::collections::BTreeMap;

use rustbgpd_policy::{
    NextHopAction, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
};

use super::*;
use crate::route::RouteOrigin;

const SESSION: u64 = 1;

/// An iBGP-learned route fixture: `LOCAL_PREF` ranks it, optional
/// communities ride along (e.g. `COMMUNITY_LLGR_STALE`).
fn ibgp_route(prefix: Ipv4Prefix, src: Ipv4Addr, local_pref: u32, communities: Vec<u32>) -> Route {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(local_pref),
    ];
    if !communities.is_empty() {
        attributes.push(PathAttribute::Communities(communities));
    }
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(src),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(src),
        attributes: Arc::new(attributes),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

fn pfx(a: u8, b: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(10, 200, a, b), 24)
}

fn permit_all_with(modifications: RouteModifications) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
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
            modifications,
        }],
        default_action: PolicyAction::Permit,
    }])
}

fn deny_prefix_chain(prefix: Ipv4Prefix) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: Some(Prefix::V4(prefix)),
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
        }],
        default_action: PolicyAction::Permit,
    }])
}

/// One outbound message, normalized: announces carry everything the
/// wire path consumes (route identity, next hop, source, attributes,
/// aligned next-hop-override flag), sorted so intra-message iteration
/// order is not compared.
/// (prefix, path id, next hop, source peer, attributes, nh-override).
type NormAnnounce = (
    Prefix,
    u32,
    IpAddr,
    IpAddr,
    Vec<PathAttribute>,
    Option<NextHopAction>,
);

#[derive(Debug, PartialEq, Clone)]
struct NormMsg {
    announce: Vec<NormAnnounce>,
    withdraw: Vec<(Prefix, u32)>,
    end_of_rib: Vec<(Afi, Safi)>,
}

fn normalize(update: &OutboundRouteUpdate) -> NormMsg {
    let mut announce: Vec<_> = update
        .announce
        .iter()
        .enumerate()
        .map(|(i, r)| {
            (
                r.prefix,
                r.path_id,
                r.next_hop,
                r.peer,
                (*r.attributes).clone(),
                update.next_hop_override.get(i).cloned().flatten(),
            )
        })
        .collect();
    // `Prefix`/`Afi`/`Safi` don't implement `Ord` — sort textually
    // (comparison stability is all that matters here).
    announce.sort_by_key(|entry| (entry.0.to_string(), entry.1));
    let mut withdraw = update.withdraw.clone();
    withdraw.sort_by_key(|(prefix, path_id)| (prefix.to_string(), *path_id));
    let mut end_of_rib = update.end_of_rib.clone();
    end_of_rib.sort_by_key(|(afi, safi)| (*afi as u16, *safi as u8));
    NormMsg {
        announce,
        withdraw,
        end_of_rib,
    }
}

type Streams = BTreeMap<IpAddr, Vec<NormMsg>>;

/// Fold a stream into the final advertised state (announce replaces,
/// withdraw removes; unknown withdraws are RFC 4271 no-ops).
/// (next hop, source peer, attributes, nh-override).
type FoldedEntry = (IpAddr, IpAddr, Vec<PathAttribute>, Option<NextHopAction>);
type FoldedState = BTreeMap<IpAddr, HashMap<(Prefix, u32), FoldedEntry>>;

fn fold(streams: &Streams) -> FoldedState {
    let mut state = FoldedState::new();
    for (peer, msgs) in streams {
        let table = state.entry(*peer).or_default();
        for msg in msgs {
            for (prefix, path_id) in &msg.withdraw {
                table.remove(&(*prefix, *path_id));
            }
            for (prefix, path_id, nh, src, attrs, nh_override) in &msg.announce {
                table.insert(
                    (*prefix, *path_id),
                    (*nh, *src, attrs.clone(), nh_override.clone()),
                );
            }
        }
    }
    state
}

struct Oracle {
    tx: mpsc::Sender<RibUpdate>,
    outs: BTreeMap<IpAddr, mpsc::Receiver<OutboundRouteUpdate>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Oracle {
    fn spawn(force_ungrouped: bool, cluster_id: Option<Ipv4Addr>) -> Self {
        let (tx, rx) = mpsc::channel(512);
        let mut manager =
            RibManager::new(rx, dummy_query_rx(), None, cluster_id, BgpMetrics::new());
        manager.test_force_ungrouped = force_ungrouped;
        let handle = tokio::spawn(manager.run());
        Self {
            tx,
            outs: BTreeMap::new(),
            handle,
        }
    }

    async fn peer_up(
        &mut self,
        peer: Ipv4Addr,
        is_ebgp: bool,
        route_reflector_client: bool,
        export_policy: Option<PolicyChain>,
        capacity: usize,
    ) {
        let (out_tx, out_rx) = mpsc::channel(capacity);
        self.tx
            .send(RibUpdate::PeerUp {
                session_id: SESSION,
                peer: IpAddr::V4(peer),
                peer_asn: if is_ebgp { 65010 } else { 65000 },
                peer_router_id: peer,
                outbound_tx: out_tx,
                export_policy,
                sendable_families: ipv4_sendable(),
                is_ebgp,
                route_reflector_client,
                orr_vantage: None,
                add_path_send_families: vec![],
                add_path_send_max: 0,
                negotiated_orf_recv: Vec::new(),
                negotiated_llgr_families: Vec::new(),
            })
            .await
            .unwrap();
        self.outs.insert(IpAddr::V4(peer), out_rx);
        self.quiesce().await;
    }

    async fn peer_down(&mut self, peer: Ipv4Addr) {
        self.tx
            .send(RibUpdate::PeerDown {
                peer: IpAddr::V4(peer),
                session_id: SESSION,
            })
            .await
            .unwrap();
        self.quiesce().await;
    }

    async fn routes(&mut self, from: Ipv4Addr, announce: Vec<Route>, withdraw: Vec<Ipv4Prefix>) {
        self.tx
            .send(RibUpdate::RoutesReceived {
                session_id: SESSION,
                peer: IpAddr::V4(from),
                announced: announce,
                withdrawn: withdraw.into_iter().map(|p| (Prefix::V4(p), 0)).collect(),
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
            })
            .await
            .unwrap();
        self.quiesce().await;
    }

    async fn replace_policy(&mut self, peer: Ipv4Addr, export_policy: Option<PolicyChain>) {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::ReplacePeerExportPolicy {
                peer: IpAddr::V4(peer),
                export_policy,
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap().unwrap();
    }

    /// RFC 2918 ROUTE-REFRESH from the peer: the grouped path replays
    /// the group table, the per-peer path re-runs full staging.
    async fn route_refresh(&mut self, peer: Ipv4Addr, afi: Afi, safi: Safi) {
        self.tx
            .send(RibUpdate::RouteRefreshRequest {
                peer: IpAddr::V4(peer),
                session_id: SESSION,
                afi,
                safi,
            })
            .await
            .unwrap();
        self.quiesce().await;
    }

    async fn refresh_outbound(&mut self, peer: Ipv4Addr) {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::RefreshPeerOutbound {
                peer: IpAddr::V4(peer),
                reply: reply_tx,
            })
            .await
            .unwrap();
        reply_rx.await.unwrap().unwrap();
    }

    /// Round-trip a query on the primary channel: the run loop only
    /// handles it after every prior update (and its route chunks) has
    /// been fully processed, so all resulting outbound sends have
    /// happened by the time the reply arrives.
    async fn quiesce(&mut self) {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await.unwrap();
    }

    /// Drain one pending message from a peer's channel (channel-fill
    /// scenarios).
    async fn drain_one(&mut self, peer: Ipv4Addr) -> OutboundRouteUpdate {
        self.outs
            .get_mut(&IpAddr::V4(peer))
            .expect("peer registered")
            .recv()
            .await
            .expect("message pending")
    }

    /// Collect every message every peer has received so far. Messages
    /// drained early via `drain_one` are NOT re-collected — scenarios
    /// that pre-drain must compare folded state, not streams.
    async fn finish(mut self) -> Streams {
        self.quiesce().await;
        let mut streams = Streams::new();
        for (peer, rx) in &mut self.outs {
            let mut msgs = Vec::new();
            while let Ok(update) = rx.try_recv() {
                msgs.push(normalize(&update));
            }
            streams.insert(*peer, msgs);
        }
        drop(self.tx);
        self.handle.await.unwrap();
        streams
    }
}

const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const C: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
const D: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
const E: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const F: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 6);

async fn run_grouped_and_ungrouped<S>(
    cluster_id: Option<Ipv4Addr>,
    scenario: S,
) -> (Streams, Streams)
where
    S: AsyncFn(&mut Oracle),
{
    let mut grouped = Oracle::spawn(false, cluster_id);
    scenario(&mut grouped).await;
    let grouped = grouped.finish().await;
    let mut ungrouped = Oracle::spawn(true, cluster_id);
    scenario(&mut ungrouped).await;
    let ungrouped = ungrouped.finish().await;
    (grouped, ungrouped)
}

/// The kitchen-sink exact-stream scenario: initial dump, best change,
/// best withdraw, split horizon (source inside the group), source-flip
/// X→Y→X, policy-modified attributes, next-hop-override flags,
/// RR-client vs non-client groups, eBGP LLGR suppression, member join
/// mid-stream, leave, regroup on policy change (content-equal reinstall
/// AND a genuine change), and a GShut-style forced refresh.
#[tokio::test]
async fn oracle_streams_identical_across_rr_mix() {
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let modifying_chain = || {
        permit_all_with(RouteModifications {
            set_med: Some(77),
            communities_add: vec![0xFDE8_0001],
            set_next_hop: Some(NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 99,
            )))),
            ..RouteModifications::default()
        })
    };
    let scenario = async |o: &mut Oracle| {
        // Three RR clients (one group), a non-client (second group), an
        // eBGP peer with an attribute-modifying chain (third group).
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        o.peer_up(C, false, true, None, 64).await;
        o.peer_up(D, false, false, None, 64).await;
        o.peer_up(E, true, false, Some(modifying_chain()), 64).await;

        // Initial announces from a member: split horizon inside the group.
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;

        // Source flip X→Y (B takes over p1 with higher LOCAL_PREF)...
        o.routes(B, vec![ibgp_route(pfx(1, 0), B, 200, vec![])], vec![])
            .await;
        // ... and flip back Y→X (B withdraws its path).
        o.routes(B, vec![], vec![pfx(1, 0)]).await;

        // Attribute change on the standing best (same source).
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 150, vec![])], vec![])
            .await;

        // LLGR-stale-tagged route: suppressed toward the eBGP peer
        // (no LLGR capability), advertised to iBGP members.
        o.routes(
            B,
            vec![ibgp_route(
                pfx(3, 0),
                B,
                100,
                vec![rustbgpd_wire::COMMUNITY_LLGR_STALE],
            )],
            vec![],
        )
        .await;

        // Late joiner into the client group: replay, not restage.
        o.peer_up(F, false, true, None, 64).await;

        // RFC 2918 route refresh, both group shapes: a grouped RR
        // client with own-sourced entries (split-horizon exclusion in
        // the replay) and the eBGP peer whose chain modifies attributes
        // + sets a next-hop override (the replay must reproduce both
        // from the staged residue without re-running policy).
        o.route_refresh(A, Afi::Ipv4, Safi::Unicast).await;
        o.route_refresh(E, Afi::Ipv4, Safi::Unicast).await;

        // Best withdraw: p1 goes away entirely.
        o.routes(A, vec![], vec![pfx(1, 0)]).await;

        // Member leaves (its p3 route falls out of the Loc-RIB too).
        o.peer_down(B).await;

        // Regroup fast path: a content-equal chain reinstall on E must
        // emit nothing on either path.
        o.replace_policy(E, Some(modifying_chain())).await;

        // Genuine regroup: C moves to a deny-p2 group — one-shot diff
        // withdraws p2 and leaves everything else untouched.
        o.replace_policy(C, Some(deny_prefix_chain(pfx(2, 0))))
            .await;

        // GShut-style forced re-emission (RefreshPeerOutbound).
        o.refresh_outbound(D).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        grouped, ungrouped,
        "grouped and per-peer outbound streams must be identical"
    );
    // Sanity: the scenario actually produced traffic.
    assert!(
        grouped.values().any(|msgs| !msgs.is_empty()),
        "scenario must exercise outbound traffic"
    );
}

/// Dirty-member resync (channel-full → tombstones → timer resync).
/// Streams intentionally differ (the grouped resync over-emits — the
/// safe direction); the folded final advertised state must be
/// identical, and the withdraw of the prefix that went away while
/// dirty must reach the wire on both paths.
#[tokio::test]
async fn oracle_dirty_resync_converges_to_identical_state() {
    tokio::time::pause();
    let cluster = Some(Ipv4Addr::new(192, 0, 2, 1));
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(B, false, true, None, 64).await;
        // C gets a capacity-1 channel so a second update fails try_reserve.
        o.peer_up(C, false, true, None, 1).await;
        // Drain the initial-dump EoR so the channel starts empty.
        let eor = o.drain_one(C).await;
        assert!(eor.announce.is_empty() && !eor.end_of_rib.is_empty());

        // p1 lands in C's channel (fills it).
        o.routes(A, vec![ibgp_route(pfx(1, 0), A, 100, vec![])], vec![])
            .await;
        // p2 announce fails for C → C goes dirty.
        o.routes(A, vec![ibgp_route(pfx(2, 0), A, 100, vec![])], vec![])
            .await;
        // p1 withdrawn WHILE C is dirty → tombstone; C's channel still full.
        o.routes(A, vec![], vec![pfx(1, 0)]).await;

        // Free the channel and let the resync timer fire.
        let first = o.drain_one(C).await;
        assert_eq!(first.announce.len(), 1, "p1 was delivered before the jam");
        tokio::time::advance(Duration::from_secs(2)).await;
        o.quiesce().await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(cluster, scenario).await;
    assert_eq!(
        fold(&grouped),
        fold(&ungrouped),
        "final advertised state must converge on both paths"
    );
    // The dirty member must have (over-)withdrawn the tombstoned p1 on
    // the grouped path: its folded table must not contain p1 (fold
    // starts after the pre-drained p1 announce, so a leftover p1 key
    // could only come from a resync bug).
    let c_final = fold(&grouped)
        .get(&IpAddr::V4(C))
        .cloned()
        .unwrap_or_default();
    assert!(
        !c_final.contains_key(&(Prefix::V4(pfx(1, 0)), 0)),
        "tombstoned prefix must not survive the grouped resync"
    );
    assert!(
        c_final.contains_key(&(Prefix::V4(pfx(2, 0)), 0)),
        "the update lost to the full channel must be recovered by the resync"
    );
}

/// A second peer joining an existing group whose chain sets a next-hop
/// override: the join replay must reproduce the override flags without
/// re-running policy (they ride the group table residue).
#[tokio::test]
async fn oracle_nh_override_survives_group_join_replay() {
    let chain = || {
        permit_all_with(RouteModifications {
            set_next_hop: Some(NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 42,
            )))),
            ..RouteModifications::default()
        })
    };
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, true, None, 64).await;
        o.peer_up(D, true, false, Some(chain()), 64).await;
        o.routes(A, vec![ibgp_route(pfx(9, 0), A, 100, vec![])], vec![])
            .await;
        // E joins D's group (same eBGP + content-equal chain): its
        // initial dump replays the staged route WITH the nh override.
        o.peer_up(E, true, false, Some(chain()), 64).await;
    };
    let (grouped, ungrouped) =
        run_grouped_and_ungrouped(Some(Ipv4Addr::new(192, 0, 2, 1)), scenario).await;
    assert_eq!(grouped, ungrouped);
    // Belt and braces: E's dump carries the override flag on both paths.
    let e_msgs = &grouped[&IpAddr::V4(E)];
    let announced_with_flag = e_msgs.iter().flat_map(|m| &m.announce).any(|entry| {
        entry.5
            == Some(NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 42,
            ))))
    });
    assert!(
        announced_with_flag,
        "join replay must reproduce the next-hop-override flag"
    );
}

/// iBGP full mesh (no cluster id): plain split horizon suppresses
/// iBGP-learned routes toward every iBGP peer; locally-injected and
/// eBGP-origin routes still flow. Exercises the no-RR key shape.
#[tokio::test]
async fn oracle_plain_ibgp_split_horizon_identical() {
    let scenario = async |o: &mut Oracle| {
        o.peer_up(A, false, false, None, 64).await;
        o.peer_up(B, false, false, None, 64).await;
        o.peer_up(E, true, false, None, 64).await;
        // iBGP-learned: suppressed toward A/B (split horizon, no RR),
        // advertised to the eBGP peer.
        o.routes(A, vec![ibgp_route(pfx(4, 0), A, 100, vec![])], vec![])
            .await;
        // An eBGP-origin route from E flows to the iBGP peers.
        let mut ebgp = ibgp_route(pfx(5, 0), E, 100, vec![]);
        ebgp.origin_type = RouteOrigin::Ebgp;
        o.routes(E, vec![ebgp], vec![]).await;
    };
    let (grouped, ungrouped) = run_grouped_and_ungrouped(None, scenario).await;
    assert_eq!(grouped, ungrouped);
}
