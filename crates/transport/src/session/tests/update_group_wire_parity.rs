//! Grouped versus per-peer RIB output, compared on the wire.
//!
//! One scenario runs a real `RibManager` twice. In the grouped run the
//! receivers share an update group; in the private run each export chain
//! carries a never-matching neighbor-set guard, a production trigger for the
//! per-peer path. Every receiver is a real `PeerSession` established through
//! its FSM, so the RIB sees the production context and `PeerUp` sequence, and
//! every outbound envelope goes through the session's own encoder onto a
//! loopback socket. The comparison is per receiver, family and key: ordered
//! NLRI bytes, attribute bytes (the `MP_REACH_NLRI` next hop included) and
//! the per-key progress each End-of-RIB covers. UPDATE packing, batch
//! boundaries and cross-key order are not compared.
use std::collections::BTreeMap;
use std::net::SocketAddr;

use rustbgpd_policy::NextHopAction;

use super::*;

const CLUSTER_ID: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LOCAL_ASN: u32 = 65001;
const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 11);
const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 12);
const C: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 13);
const OVERRIDE_NEXT_HOP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 99);
/// Runner-up prefixes from B, exported without a next-hop override.
const PLAIN_BLOCK: std::ops::Range<u8> = 10..18;
/// Runner-up prefixes from C, each exported next-hop-self. When A withdraws
/// its better paths for both blocks in one message, one pass promotes B and
/// C routes in table order; the shared encoder sorts them by source, so an
/// override misaligned by that sort lands on the wrong route.
const SELF_BLOCK: std::ops::Range<u8> = 32..40;

fn families() -> Vec<(Afi, Safi)> {
    vec![
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv6, Safi::Unicast),
        (Afi::Ipv4, Safi::MplsVpn),
    ]
}

fn statement(
    action: PolicyAction,
    prefix: Option<Prefix>,
    match_neighbor_set: Option<NeighborSetMatch>,
    modifications: RouteModifications,
) -> PolicyStatement {
    PolicyStatement {
        prefix,
        ge: None,
        le: None,
        action,
        match_community: vec![],
        match_as_path: None,
        match_neighbor_set,
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
    }
}

/// The same export verdicts and modifications on both runs: one IPv4 prefix
/// gets a specific next hop and a MED, another next-hop-self, so a shared
/// inventory carries a mixed override vector. The RIB folds a specific next
/// hop into the route; next-hop-self is resolved only by the encoder. The private run prepends a neighbor-set deny for
/// an ASN no receiver uses; it never matches, but it makes the chain depend
/// on peer context, which keeps the receiver on the per-peer path.
fn export_chain(private: bool) -> PolicyChain {
    let mut entries = Vec::new();
    if private {
        entries.push(statement(
            PolicyAction::Deny,
            None,
            Some(NeighborSetMatch {
                addresses: vec![],
                remote_asns: vec![65099],
                peer_groups: vec![],
            }),
            RouteModifications::default(),
        ));
    }
    entries.push(statement(
        PolicyAction::Permit,
        Some(Prefix::V4(v4_prefix(1))),
        None,
        RouteModifications {
            set_next_hop: Some(NextHopAction::Specific(IpAddr::V4(OVERRIDE_NEXT_HOP))),
            set_med: Some(77),
            ..RouteModifications::default()
        },
    ));
    for n in std::iter::once(6).chain(SELF_BLOCK) {
        entries.push(statement(
            PolicyAction::Permit,
            Some(Prefix::V4(v4_prefix(n))),
            None,
            RouteModifications {
                set_next_hop: Some(NextHopAction::Self_),
                ..RouteModifications::default()
            },
        ));
    }
    PolicyChain::new(vec![Policy {
        entries,
        default_action: PolicyAction::Permit,
    }])
}

fn v4_prefix(n: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(10, 200, n, 0), 24)
}

fn v6_prefix(n: u8) -> Prefix {
    Prefix::V6(Ipv6Prefix::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0x200, u16::from(n), 0, 0, 0, 0),
        64,
    ))
}

fn ibgp_attrs(local_pref: u32, communities: Vec<u32>) -> Arc<AttrSet> {
    let mut attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(local_pref),
    ];
    if !communities.is_empty() {
        attributes.push(PathAttribute::Communities(communities));
    }
    AttrSet::new(attributes)
}

/// An iBGP-learned unicast route from one of the receivers.
fn route(src: Ipv4Addr, prefix: Prefix, local_pref: u32, communities: Vec<u32>) -> Route {
    let next_hop = match prefix {
        Prefix::V4(_) => IpAddr::V4(src),
        Prefix::V6(_) => IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            0xff,
            0,
            0,
            0,
            0,
            u16::from(src.octets()[3]),
        )),
    };
    Route {
        prefix,
        next_hop,
        peer: IpAddr::V4(src),
        attributes: ibgp_attrs(local_pref, communities),
        origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
        peer_router_id: src,
        ..make_route(local_pref)
    }
}

fn vpn_nlri(n: u8, label: u32) -> VpnNlri {
    VpnNlri {
        labels: vec![MplsLabelEntry::try_new(label, 0, true).unwrap()],
        route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, n]),
        prefix: VpnPrefix::v4(Ipv4Addr::new(10, 210, n, 0), 24).unwrap(),
    }
}

fn vpn_route(src: Ipv4Addr, n: u8, label: u32, local_pref: u32) -> rustbgpd_rib::VpnRibRoute {
    rustbgpd_rib::VpnRibRoute {
        nlri: vpn_nlri(n, label),
        next_hop: IpAddr::V4(src),
        peer: IpAddr::V4(src),
        attributes: ibgp_attrs(local_pref, vec![]),
        origin_type: rustbgpd_rib::RouteOrigin::Ibgp,
        peer_router_id: src,
        ..make_vpn_rib_route(label)
    }
}

fn vpn_key(n: u8) -> rustbgpd_rib::VpnRibRouteKey {
    rustbgpd_rib::VpnRibRouteKey {
        nlri_key: vpn_nlri(n, 0).key(),
        path_id: 0,
    }
}

struct Receiver {
    addr: Ipv4Addr,
    session: PeerSession,
    wire: TcpStream,
    _commands: mpsc::Sender<PeerCommand>,
}

/// One real RIB manager plus real receiver sessions.
struct Run {
    private: bool,
    rib_tx: mpsc::Sender<RibUpdate>,
    manager: tokio::task::JoinHandle<()>,
    receivers: Vec<Receiver>,
    settles: usize,
    shared_envelopes: usize,
    private_envelopes: usize,
}

/// Raw UPDATE frames per receiver, plus how many envelopes asked for
/// shared encoding and how many did not.
struct RunOutput {
    frames: BTreeMap<Ipv4Addr, Vec<Vec<u8>>>,
    shared_envelopes: usize,
    private_envelopes: usize,
}

impl Run {
    fn start(private: bool) -> Self {
        let (rib_tx, rib_rx) = mpsc::channel(256);
        let (_query_tx, query_rx) = mpsc::channel(1);
        let manager = tokio::spawn(
            rustbgpd_rib::RibManager::new(
                rib_rx,
                query_rx,
                None,
                Some(CLUSTER_ID),
                BgpMetrics::new(),
            )
            .run(),
        );
        Self {
            private,
            rib_tx,
            manager,
            receivers: Vec::new(),
            settles: 0,
            shared_envelopes: 0,
            private_envelopes: 0,
        }
    }

    /// Establish an iBGP route-reflector client through the session FSM.
    async fn peer_up(&mut self, addr: Ipv4Addr) {
        let mut peer_config = PeerConfig::new(LOCAL_ASN, LOCAL_ASN, Ipv4Addr::new(10, 0, 0, 1));
        peer_config.connect_retry_secs = 30;
        peer_config.families = families();
        let mut config = TransportConfig::new(peer_config, SocketAddr::new(IpAddr::V4(addr), 179));
        config.route_reflector_client = true;
        config.cluster_id = Some(CLUSTER_ID);
        let (commands, cmd_rx) = mpsc::channel(8);
        let mut session = PeerSession::new(
            config,
            BgpMetrics::new(),
            cmd_rx,
            self.rib_tx.clone(),
            None,
            Some(export_chain(self.private)),
            None,
            None,
            None,
            false,
        );
        let (client, wire) = connected_stream_pair().await;
        session.test_install_stream(client);
        session.drive_fsm(Event::ManualStart).await;
        let mut capabilities: Vec<_> = families()
            .into_iter()
            .map(|(afi, safi)| Capability::MultiProtocol { afi, safi })
            .collect();
        capabilities.push(Capability::FourOctetAs { asn: LOCAL_ASN });
        session
            .drive_fsm(Event::OpenReceived(rustbgpd_wire::OpenMessage {
                version: 4,
                my_as: u16::try_from(LOCAL_ASN).unwrap(),
                hold_time: 90,
                bgp_identifier: addr,
                capabilities,
            }))
            .await;
        session.drive_fsm(Event::KeepaliveReceived).await;
        assert_eq!(session.fsm.state(), SessionState::Established);
        self.receivers.push(Receiver {
            addr,
            session,
            wire,
            _commands: commands,
        });
        self.settle().await;
    }

    async fn send(&mut self, update: RibUpdate) {
        self.rib_tx.send(update).await.unwrap();
    }

    async fn routes(&mut self, from: Ipv4Addr, announced: Vec<Route>, withdrawn: Vec<Prefix>) {
        self.send(RibUpdate::RoutesReceived {
            peer: IpAddr::V4(from),
            session_id: 0,
            announced,
            withdrawn: withdrawn.into_iter().map(|prefix| (prefix, 0)).collect(),
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await;
    }

    async fn vpn_routes(
        &mut self,
        from: Ipv4Addr,
        announced: Vec<rustbgpd_rib::VpnRibRoute>,
        withdrawn: Vec<rustbgpd_rib::VpnRibRouteKey>,
    ) {
        self.send(RibUpdate::VpnRoutesReceived {
            peer: IpAddr::V4(from),
            session_id: 0,
            announced,
            withdrawn,
        })
        .await;
    }

    /// Wait until the RIB has processed everything queued so far, then let
    /// each session encode what it received. The drain order rotates, so the
    /// elected shared encoder is not always the same member.
    async fn settle(&mut self) {
        let (reply, done) = oneshot::channel();
        self.send(RibUpdate::QueryBestRoutes {
            deadline: tokio::time::Instant::now() + Duration::from_secs(10),
            reply,
        })
        .await;
        done.await.unwrap();
        let count = self.receivers.len();
        for offset in 0..count {
            let receiver = &mut self.receivers[(offset + self.settles) % count];
            while let Ok(update) = receiver.session.outbound_rx.try_recv() {
                if update.shared_group_encode.is_some() {
                    self.shared_envelopes += 1;
                } else {
                    self.private_envelopes += 1;
                }
                receiver.session.test_drain_outbound(update).await;
            }
        }
        self.settles += 1;
    }

    /// Ends each stream with a sentinel announcement on the ordinary path
    /// and collects every UPDATE before it.
    async fn finish(mut self) -> RunOutput {
        let mut frames = BTreeMap::new();
        for receiver in &mut self.receivers {
            let mut sentinel = empty_outbound_update();
            sentinel.exact_export_snapshot = Some(receiver.session.publish_export_profile());
            sentinel.announce = vec![make_sourced_route(
                A,
                Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 128), 25),
                64_999,
            )]
            .into();
            sentinel.next_hop_override = vec![None].into();
            receiver.session.test_drain_outbound(sentinel).await;
            let mut updates = Vec::new();
            loop {
                let frame = tokio::time::timeout(
                    Duration::from_secs(5),
                    read_single_raw_bgp_message(&mut receiver.wire),
                )
                .await
                .expect("wire read timed out");
                if frame[18] != 2 {
                    continue;
                }
                if frame.ends_with(&[25, 192, 0, 2, 128]) {
                    break;
                }
                updates.push(frame);
            }
            frames.insert(receiver.addr, updates);
        }
        self.manager.abort();
        RunOutput {
            frames,
            shared_envelopes: self.shared_envelopes,
            private_envelopes: self.private_envelopes,
        }
    }
}

/// Initial table, member joins, multi-source passes, a source flip and
/// back, an attribute change and withdrawals in every family.
async fn scenario(private: bool) -> RunOutput {
    let mut run = Run::start(private);
    run.peer_up(A).await;
    run.routes(
        A,
        vec![
            route(A, Prefix::V4(v4_prefix(1)), 100, vec![]),
            route(A, Prefix::V4(v4_prefix(2)), 100, vec![]),
            route(A, Prefix::V4(v4_prefix(3)), 100, vec![0xFDE8_0003]),
            route(A, v6_prefix(1), 100, vec![]),
        ],
        vec![],
    )
    .await;
    run.vpn_routes(A, vec![vpn_route(A, 1, 100, 100)], vec![])
        .await;
    run.settle().await;
    run.peer_up(B).await;
    run.peer_up(C).await;

    // Two sources in quick succession, which one distribution window may
    // coalesce; B takes over prefix 1 with a higher LOCAL_PREF.
    run.routes(
        B,
        vec![
            route(B, Prefix::V4(v4_prefix(4)), 100, vec![]),
            route(B, Prefix::V4(v4_prefix(1)), 200, vec![]),
            route(B, v6_prefix(2), 100, vec![]),
        ],
        vec![],
    )
    .await;
    run.routes(
        C,
        vec![
            route(C, Prefix::V4(v4_prefix(5)), 100, vec![]),
            route(C, Prefix::V4(v4_prefix(6)), 100, vec![0xFDE8_0006]),
            route(C, v6_prefix(3), 100, vec![]),
        ],
        vec![],
    )
    .await;
    run.vpn_routes(B, vec![vpn_route(B, 2, 200, 100)], vec![])
        .await;
    run.settle().await;

    // Attribute change, withdrawals in every family and a VPN relabel.
    run.routes(
        A,
        vec![route(A, Prefix::V4(v4_prefix(2)), 150, vec![0xFDE8_0002])],
        vec![Prefix::V4(v4_prefix(3))],
    )
    .await;
    run.routes(B, vec![], vec![v6_prefix(2)]).await;
    run.vpn_routes(A, vec![], vec![vpn_key(1)]).await;
    run.vpn_routes(B, vec![vpn_route(B, 2, 222, 100)], vec![])
        .await;
    run.settle().await;

    // A's better paths hide B's and C's runner-ups, then one withdrawal
    // promotes both sources in a single pass.
    let blocks = || PLAIN_BLOCK.chain(SELF_BLOCK).map(v4_prefix);
    run.routes(
        B,
        PLAIN_BLOCK
            .map(|n| route(B, Prefix::V4(v4_prefix(n)), 100, vec![]))
            .collect(),
        vec![],
    )
    .await;
    run.routes(
        C,
        SELF_BLOCK
            .map(|n| route(C, Prefix::V4(v4_prefix(n)), 100, vec![]))
            .collect(),
        vec![],
    )
    .await;
    run.routes(
        A,
        blocks()
            .map(|prefix| route(A, Prefix::V4(prefix), 300, vec![]))
            .collect(),
        vec![],
    )
    .await;
    run.settle().await;
    run.routes(A, vec![], blocks().map(Prefix::V4).collect())
        .await;
    run.settle().await;

    // Flip prefix 1 back to A and withdraw routes from C and B.
    run.routes(B, vec![], vec![Prefix::V4(v4_prefix(1))]).await;
    run.routes(C, vec![], vec![Prefix::V4(v4_prefix(5)), v6_prefix(3)])
        .await;
    run.vpn_routes(B, vec![], vec![vpn_key(2)]).await;
    run.settle().await;
    run.finish().await
}

type Family = (u16, u8);
type Key = (Family, Vec<u8>);
/// Path attributes other than `MP_REACH`/`MP_UNREACH`, in wire order, plus
/// the `MP_REACH_NLRI` next-hop field (empty for the IPv4 body).
type Attrs = (Vec<u8>, Vec<u8>);
/// NLRI bytes as sent, with attributes for an announce or `None` for a
/// withdrawal.
type WireEvent = (Vec<u8>, Option<Attrs>);

#[derive(Debug, Default, PartialEq)]
struct WireTrace {
    events: BTreeMap<Key, Vec<WireEvent>>,
    state: BTreeMap<Key, Attrs>,
    /// Per family, each `EoR` with the per-key event count it follows.
    eors: BTreeMap<Family, Vec<BTreeMap<Key, usize>>>,
}

fn be16(bytes: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn split_nlri(mut bytes: &[u8]) -> Vec<&[u8]> {
    let mut rows = Vec::new();
    while !bytes.is_empty() {
        let (row, rest) = bytes.split_at(1 + usize::from(bytes[0]).div_ceil(8));
        rows.push(row);
        bytes = rest;
    }
    rows
}

/// Route identity: the NLRI without its VPN label, which is route data.
fn nlri_key(family: Family, nlri: &[u8]) -> Key {
    let identity = if family.1 == 128 {
        let mut key = vec![nlri[0] - 24];
        key.extend_from_slice(&nlri[4..]);
        key
    } else {
        nlri.to_vec()
    };
    (family, identity)
}

impl WireTrace {
    fn withdraw(&mut self, family: Family, nlri: &[u8]) {
        let key = nlri_key(family, nlri);
        assert!(
            self.state.remove(&key).is_some(),
            "unknown or duplicate withdrawal of {key:?}"
        );
        self.events
            .entry(key)
            .or_default()
            .push((nlri.to_vec(), None));
    }

    fn announce(&mut self, family: Family, nlri: &[u8], attrs: &Attrs) {
        let key = nlri_key(family, nlri);
        self.state.insert(key.clone(), attrs.clone());
        self.events
            .entry(key)
            .or_default()
            .push((nlri.to_vec(), Some(attrs.clone())));
    }

    fn end_of_rib(&mut self, family: Family) {
        let progress = self
            .events
            .iter()
            .filter(|((key_family, _), _)| *key_family == family)
            .map(|(key, events)| (key.clone(), events.len()))
            .collect();
        self.eors.entry(family).or_default().push(progress);
    }
}

fn trace(frames: &[Vec<u8>]) -> WireTrace {
    let mut trace = WireTrace::default();
    for frame in frames {
        let withdrawn_len = be16(&frame[19..]);
        let withdrawn = &frame[21..21 + withdrawn_len];
        let attrs_at = 21 + withdrawn_len;
        let attrs_len = be16(&frame[attrs_at..]);
        let mut attrs = &frame[attrs_at + 2..attrs_at + 2 + attrs_len];
        let body_nlri = &frame[attrs_at + 2 + attrs_len..];
        if withdrawn.is_empty() && attrs.is_empty() && body_nlri.is_empty() {
            trace.end_of_rib((1, 1));
            continue;
        }
        let mut plain = Vec::new();
        let mut reach = None;
        let mut unreach = None;
        while !attrs.is_empty() {
            let (header, len) = if attrs[0] & 0x10 == 0 {
                (3, usize::from(attrs[2]))
            } else {
                (4, be16(&attrs[2..]))
            };
            let (attr, rest) = attrs.split_at(header + len);
            match attr[1] {
                14 => reach = Some(&attr[header..]),
                15 => unreach = Some(&attr[header..]),
                _ => plain.extend_from_slice(attr),
            }
            attrs = rest;
        }
        for nlri in split_nlri(withdrawn) {
            trace.withdraw((1, 1), nlri);
        }
        if let Some(value) = unreach {
            let family = (u16::from_be_bytes([value[0], value[1]]), value[2]);
            if value.len() == 3 && reach.is_none() && plain.is_empty() && withdrawn.is_empty() {
                trace.end_of_rib(family);
                continue;
            }
            for nlri in split_nlri(&value[3..]) {
                trace.withdraw(family, nlri);
            }
        }
        if let Some(value) = reach {
            let family = (u16::from_be_bytes([value[0], value[1]]), value[2]);
            let next_hop_len = usize::from(value[3]);
            let attrs = (plain.clone(), value[4..4 + next_hop_len].to_vec());
            for nlri in split_nlri(&value[5 + next_hop_len..]) {
                trace.announce(family, nlri, &attrs);
            }
        }
        let attrs = (plain, Vec::new());
        for nlri in split_nlri(body_nlri) {
            trace.announce((1, 1), nlri, &attrs);
        }
    }
    trace
}

/// The scenario must exercise every compared dimension, or a green
/// comparison proves nothing.
fn assert_coverage(receiver: Ipv4Addr, trace: &WireTrace) {
    for family in [(1, 1), (2, 1), (1, 128)] {
        let keys: Vec<_> = trace
            .events
            .iter()
            .filter(|((key_family, _), _)| *key_family == family)
            .collect();
        assert!(
            keys.iter()
                .any(|(_, events)| events.iter().any(|(_, a)| a.is_some())),
            "{receiver}: no announce in {family:?}"
        );
        assert!(
            keys.iter()
                .any(|(_, events)| events.iter().any(|(_, a)| a.is_none())),
            "{receiver}: no withdrawal in {family:?}"
        );
        assert!(
            trace.eors.contains_key(&family),
            "{receiver}: no EoR in {family:?}"
        );
    }
    assert!(
        trace.events.values().any(|events| events.len() >= 2),
        "{receiver}: no key with a second event"
    );
}

/// The grouped and per-peer RIB paths must put the same per-key NLRI and
/// attribute bytes and `EoR` coverage on every receiver's wire.
#[tokio::test]
async fn grouped_and_private_rib_output_match_on_the_wire() {
    let grouped = scenario(false).await;
    let private = scenario(true).await;
    assert!(
        grouped.shared_envelopes > 0,
        "the grouped run must reach the shared encoder"
    );
    assert_eq!(
        private.shared_envelopes, 0,
        "the private run must stay on the per-peer path"
    );
    assert!(private.private_envelopes > 0);
    assert_eq!(
        grouped.frames.keys().collect::<Vec<_>>(),
        private.frames.keys().collect::<Vec<_>>()
    );
    for (receiver, frames) in &private.frames {
        let expected = trace(frames);
        assert_coverage(*receiver, &expected);
        assert_eq!(
            trace(&grouped.frames[receiver]),
            expected,
            "receiver {receiver}: grouped wire output differs from per-peer output"
        );
    }
}

/// Negative control: the comparison above must notice a changed attribute
/// byte that leaves the NLRI alone, and an `EoR` sent before routes it covers.
#[tokio::test]
async fn wire_parity_trace_detects_attribute_and_eor_perturbations() {
    let output = scenario(true).await;
    let frames = &output.frames[&B];
    let baseline = trace(frames);

    // Change the last octet of the NEXT_HOP attribute in the first IPv4-body
    // announcement, the byte an override-alignment defect would change.
    let mut changed = frames.clone();
    let frame = changed
        .iter_mut()
        .find(|frame| {
            let withdrawn_len = be16(&frame[19..]);
            let attrs_len = be16(&frame[21 + withdrawn_len..]);
            frame.len() > 23 + withdrawn_len + attrs_len
        })
        .expect("an IPv4-body announcement");
    let withdrawn_len = be16(&frame[19..]);
    let mut at = 23 + withdrawn_len;
    while frame[at + 1] != 3 {
        at += if frame[at] & 0x10 == 0 {
            3 + usize::from(frame[at + 2])
        } else {
            4 + be16(&frame[at + 2..])
        };
    }
    frame[at + 6] ^= 1;
    assert_ne!(
        trace(&changed),
        baseline,
        "attribute byte change undetected"
    );

    // Move the last EoR to the front of the stream.
    let mut early = frames.clone();
    let eor = early
        .iter()
        .rposition(|frame| frame[19..] == [0, 0, 0, 0])
        .expect("an IPv4 EoR");
    let moved = early.remove(eor);
    early.insert(0, moved);
    assert_ne!(trace(&early), baseline, "premature EoR undetected");
}
