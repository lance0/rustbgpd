//! RFC 9069 Loc-RIB BMP tap tests: recompute-commit emissions,
//! VPN best-change emission, the collector-connect table dump, and
//! install-time timestamps.

use std::time::SystemTime;

use rustbgpd_bmp::{BmpDumpCursor, BmpEvent, BmpPathStatus, tlv as bmp_tlv};
use rustbgpd_wire::UpdateMessage;

use super::*;

/// Decode a synthesized Loc-RIB PDU with the fabricated-OPEN session
/// parameters (4-octet ASN, no Add-Path).
fn decode_pdu(pdu: &bytes::Bytes) -> rustbgpd_wire::ParsedUpdate {
    let mut buf = pdu.clone();
    let header =
        rustbgpd_wire::BgpHeader::decode(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)
            .unwrap();
    let body_len = usize::from(header.length) - 19;
    UpdateMessage::decode(&mut buf, body_len)
        .unwrap()
        .parse(true, false, &[])
        .unwrap()
}

async fn recv_loc_rib_rm(
    bmp_rx: &mut mpsc::Receiver<BmpEvent>,
) -> (bytes::Bytes, std::time::SystemTime, Option<BmpPathStatus>) {
    let event = tokio::time::timeout(Duration::from_secs(2), bmp_rx.recv())
        .await
        .expect("expected a Loc-RIB BMP event")
        .expect("BMP channel open");
    match event {
        BmpEvent::LocRibRouteMonitoring {
            update_pdu,
            timestamp,
            path_status,
        } => (update_pdu, timestamp, path_status),
        other => panic!("expected LocRibRouteMonitoring, got {other:?}"),
    }
}

fn assert_no_event(bmp_rx: &mut mpsc::Receiver<BmpEvent>) {
    match bmp_rx.try_recv() {
        Err(mpsc::error::TryRecvError::Empty) => {}
        other => panic!("expected no BMP event, got {other:?}"),
    }
}

/// Drive the resumable Loc-RIB dump the way the BMP forwarder does —
/// request one bounded chunk, then the next from the returned cursor —
/// asserting the per-request allocation bound on every chunk. Returns
/// the messages in arrival order plus the number of chunk requests.
async fn drive_loc_rib_dump_from(
    tx: &mpsc::Sender<RibUpdate>,
    mut cursor: Option<BmpDumpCursor>,
) -> (
    Vec<(bytes::Bytes, SystemTime, Option<BmpPathStatus>)>,
    usize,
) {
    let mut messages = Vec::new();
    let mut requests = 0usize;
    loop {
        let (reply, chunk_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBmpLocRibDump { cursor, reply })
            .await
            .unwrap();
        let chunk = tokio::time::timeout(Duration::from_secs(2), chunk_rx)
            .await
            .expect("dump chunk within timeout")
            .expect("RIB manager replies to every chunk request");
        requests += 1;
        // Per-request allocation bound: chunk size, plus the per-family
        // End-of-RIB markers on the final chunk only.
        let bound = if chunk.next.is_some() {
            BMP_DUMP_CHUNK_SIZE
        } else {
            BMP_DUMP_CHUNK_SIZE + crate::bmp_sync::LOC_RIB_FAMILIES.len()
        };
        assert!(
            chunk.messages.len() <= bound,
            "chunk of {} messages exceeds the per-request bound {bound}",
            chunk.messages.len()
        );
        messages.extend(chunk.messages);
        match chunk.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    (messages, requests)
}

/// Announced unicast prefixes across a slice of dump messages, in dump
/// order (End-of-RIB and VPN PDUs contribute none).
fn dumped_unicast_prefixes(
    messages: &[(bytes::Bytes, SystemTime, Option<BmpPathStatus>)],
) -> Vec<Ipv4Prefix> {
    let mut prefixes = Vec::new();
    for (pdu, _, _) in messages {
        prefixes.extend(decode_pdu(pdu).announced.iter().map(|e| e.prefix));
    }
    prefixes
}

/// New best → RM announce; better path from another peer → RM announce
/// of the new best; a change that leaves the best untouched → no
/// emission; best withdrawn entirely → RM withdraw.
#[tokio::test]
async fn recompute_best_changes_emit_loc_rib_route_monitoring() {
    let (tx, rx) = mpsc::channel(64);
    let (bmp_tx, mut bmp_rx) = mpsc::channel(64);
    let manager =
        RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()).with_bmp_tx(bmp_tx);
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16);
    let peer_a = Ipv4Addr::new(10, 0, 0, 1);
    let peer_b = Ipv4Addr::new(10, 0, 0, 2);

    // 1. New best → announce.
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer_a),
        session_id: 0,
        announced: vec![make_route_with_lp(prefix, peer_a, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let (pdu, _, status) = recv_loc_rib_rm(&mut bmp_rx).await;
    let parsed = decode_pdu(&pdu);
    assert_eq!(parsed.announced.len(), 1);
    assert_eq!(parsed.announced[0].prefix, prefix);
    // Path Marking: sole candidate is Best with no reason (nothing was
    // compared against it).
    let status = status.expect("announce carries a path status");
    assert_eq!(status.status, bmp_tlv::PATH_STATUS_BEST);
    assert_eq!(status.reason, None);

    // 2. Higher LOCAL_PREF from another peer → best changes → announce
    // of the new best (next-hop = peer B).
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer_b),
        session_id: 0,
        announced: vec![make_route_with_lp(prefix, peer_b, 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let (pdu, _, status) = recv_loc_rib_rm(&mut bmp_rx).await;
    let parsed = decode_pdu(&pdu);
    assert_eq!(parsed.announced[0].prefix, prefix);
    assert!(
        parsed
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::NextHop(nh) if *nh == peer_b)),
        "announce must carry the NEW best's next-hop"
    );
    // Two candidates decided on LOCAL_PREF: Best bit + the draft's
    // "local preference" Reason Code re-derived vs the runner-up.
    let status = status.expect("announce carries a path status");
    assert_eq!(status.status, bmp_tlv::PATH_STATUS_BEST);
    assert_eq!(status.reason, Some(bmp_tlv::REASON_LOCAL_PREF));

    // 3. Losing path withdrawn — the best (peer B) is unchanged → no
    // Loc-RIB emission.
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer_a),
        session_id: 0,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    // Synchronize on the RIB task having processed the withdraw.
    let _ = query_vpn_routes(&tx).await;
    assert_no_event(&mut bmp_rx);

    // 4. Best withdrawn entirely → RM withdraw.
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer_b),
        session_id: 0,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let (pdu, _, status) = recv_loc_rib_rm(&mut bmp_rx).await;
    let parsed = decode_pdu(&pdu);
    assert!(parsed.announced.is_empty());
    assert_eq!(parsed.withdrawn.len(), 1);
    assert_eq!(parsed.withdrawn[0].prefix, prefix);
    assert_eq!(status, None, "withdrawals carry no path status");

    drop(tx);
    handle.await.unwrap();
}

/// path-marking-05 §3.1 Stale: a best route flagged by the GR/LLGR
/// stale machinery carries Best | Stale in its Path Marking payload.
#[tokio::test]
async fn stale_best_route_sets_stale_path_status_bit() {
    let (tx, rx) = mpsc::channel(64);
    let (bmp_tx, mut bmp_rx) = mpsc::channel(64);
    let manager =
        RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()).with_bmp_tx(bmp_tx);
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 7, 0, 0), 16);
    let peer = Ipv4Addr::new(10, 0, 0, 1);
    let mut route = make_route_with_lp(prefix, peer, 100);
    route.is_stale = true; // what the RFC 4724 helper marks at restart
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let (_, _, status) = recv_loc_rib_rm(&mut bmp_rx).await;
    let status = status.expect("stale announce still carries a path status");
    assert_eq!(
        status.status,
        bmp_tlv::PATH_STATUS_BEST | bmp_tlv::PATH_STATUS_STALE
    );

    drop(tx);
    handle.await.unwrap();
}

/// A VPN best change emits an MP announce; losing the last candidate
/// emits an MP withdraw carrying the RD+prefix identity.
#[tokio::test]
async fn vpn_best_change_emits_loc_rib_route_monitoring() {
    let (tx, rx) = mpsc::channel(64);
    let (bmp_tx, mut bmp_rx) = mpsc::channel(64);
    let manager =
        RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()).with_bmp_tx(bmp_tx);
    let handle = tokio::spawn(manager.run());

    let peer = Ipv4Addr::new(10, 0, 0, 5);
    let route = make_vpn_rib_route(peer, 42, 1042, 100);
    let nlri = route.nlri.clone();
    tx.send(RibUpdate::VpnRoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![route],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let (pdu, _, status) = recv_loc_rib_rm(&mut bmp_rx).await;
    let parsed = decode_pdu(&pdu);
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("VPN announce rides in MP_REACH");
    assert_eq!(mp.vpn_announced.len(), 1);
    assert_eq!(mp.vpn_announced[0].nlri, nlri);
    // VPN announces mark Best (bits only — the VPN ladder has no
    // with-reason variant).
    let status = status.expect("VPN announce carries a path status");
    assert_eq!(status.status, bmp_tlv::PATH_STATUS_BEST);
    assert_eq!(status.reason, None);

    tx.send(RibUpdate::VpnRoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![],
        withdrawn: vec![crate::route::VpnRibRouteKey {
            nlri_key: nlri.key(),
            path_id: 0,
        }],
    })
    .await
    .unwrap();
    let (pdu, _, status) = recv_loc_rib_rm(&mut bmp_rx).await;
    let parsed = decode_pdu(&pdu);
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("VPN withdraw rides in MP_UNREACH");
    assert_eq!(mp.vpn_withdrawn.len(), 1);
    assert_eq!(mp.vpn_withdrawn[0].nlri.key(), nlri.key());
    assert_eq!(status, None, "VPN withdrawals carry no path status");

    drop(tx);
    handle.await.unwrap();
}

/// The Loc-RIB dump streams every best (unicast + VPN) in chunks and
/// closes with exactly one End-of-RIB per streamed family; dump-entry
/// timestamps reflect route install time, not dump time.
#[tokio::test]
async fn query_bmp_loc_rib_dump_streams_routes_then_eor_per_family() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = Ipv4Addr::new(10, 0, 0, 1);
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![
            make_route_with_lp(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16), peer, 100),
            make_route_with_lp(Ipv4Prefix::new(Ipv4Addr::new(10, 2, 0, 0), 16), peer, 100),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::VpnRoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![make_vpn_rib_route(peer, 42, 1042, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    // Let the routes age so install-time and dump-time are separable.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let dump_started = SystemTime::now();
    let (messages, requests) = drive_loc_rib_dump_from(&tx, None).await;
    // Two resumable requests: the unicast phase, then the VPN phase
    // closing with the End-of-RIB markers.
    assert_eq!(requests, 2, "unicast chunk, then VPN + EoR chunk");
    // 2 unicast + 1 VPN route, then 4 EoRs (v4u, v6u, vpnv4, vpnv6).
    assert_eq!(messages.len(), 3 + 4, "routes then one EoR per family");

    let (route_msgs, eor_msgs) = messages.split_at(3);
    let mut dumped_prefixes = Vec::new();
    let mut dumped_vpn = 0;
    for (pdu, timestamp, status) in route_msgs {
        // Dump entries are Loc-RIB bests: Best bit, no reason code.
        let status = status.expect("dump route carries a path status");
        assert_eq!(status.status, bmp_tlv::PATH_STATUS_BEST);
        assert_eq!(status.reason, None);
        let parsed = decode_pdu(pdu);
        assert!(
            *timestamp < dump_started - Duration::from_millis(900),
            "dump timestamp must be the route install time, not the dump time"
        );
        if let Some(mp) = parsed.attributes.iter().find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        }) {
            dumped_vpn += mp.vpn_announced.len();
        } else {
            dumped_prefixes.extend(parsed.announced.iter().map(|e| e.prefix));
        }
    }
    dumped_prefixes.sort_by_key(|p| p.addr);
    assert_eq!(
        dumped_prefixes,
        vec![
            Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16),
            Ipv4Prefix::new(Ipv4Addr::new(10, 2, 0, 0), 16),
        ]
    );
    assert_eq!(dumped_vpn, 1);

    // The trailing four PDUs are EoRs: no NLRI anywhere, one per family.
    let mut eor_families = Vec::new();
    for (pdu, _, status) in eor_msgs {
        assert_eq!(*status, None, "EoR markers carry no path status");
        let parsed = decode_pdu(pdu);
        assert!(parsed.announced.is_empty() && parsed.withdrawn.is_empty());
        match parsed.attributes.iter().find_map(|a| match a {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        }) {
            Some(mp) => {
                assert!(mp.withdrawn.is_empty() && mp.vpn_withdrawn.is_empty());
                eor_families.push((mp.afi, mp.safi));
            }
            None => eor_families.push((Afi::Ipv4, Safi::Unicast)),
        }
    }
    eor_families.sort_by_key(|&(afi, safi)| (afi as u16, safi as u8));
    assert_eq!(
        eor_families,
        vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv4, Safi::MplsVpn),
            (Afi::Ipv6, Safi::Unicast),
            (Afi::Ipv6, Safi::MplsVpn),
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

/// LAN-193: dump timestamps are the STORED wall-clock Loc-RIB install
/// time — byte-identical to the live tap's emission timestamp for the
/// same install — not a reconstruction from the monotonic clock at
/// dump time (which skews if NTP steps the wall clock between install
/// and dump).
#[tokio::test]
async fn dump_timestamps_equal_stored_install_time() {
    let (tx, rx) = mpsc::channel(64);
    let (bmp_tx, mut bmp_rx) = mpsc::channel(64);
    let manager =
        RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()).with_bmp_tx(bmp_tx);
    let handle = tokio::spawn(manager.run());

    let peer = Ipv4Addr::new(10, 0, 0, 1);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16);
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![make_route_with_lp(prefix, peer, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let (_, unicast_live_ts, _) = recv_loc_rib_rm(&mut bmp_rx).await;

    tx.send(RibUpdate::VpnRoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![make_vpn_rib_route(peer, 42, 1042, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let (_, vpn_live_ts, _) = recv_loc_rib_rm(&mut bmp_rx).await;

    // Let wall time move on so an "== now at dump time" implementation
    // could not accidentally pass.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (messages, _) = drive_loc_rib_dump_from(&tx, None).await;
    let (route_msgs, _) = messages.split_at(2);
    for (pdu, timestamp, _) in route_msgs {
        let parsed = decode_pdu(pdu);
        let is_vpn = parsed
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(mp) if !mp.vpn_announced.is_empty()));
        let expected = if is_vpn { vpn_live_ts } else { unicast_live_ts };
        assert_eq!(
            *timestamp, expected,
            "dump timestamp must be the exact stored install stamp the live \
             emission carried, not a monotonic-clock reconstruction"
        );
    }

    drop(tx);
    handle.await.unwrap();
}

/// A table larger than one chunk streams to completion across multiple
/// bounded chunk requests: every route present exactly once, no chunk
/// above the per-request allocation bound (asserted in the drive
/// helper), and the End-of-RIB markers only on the final chunk.
#[tokio::test]
async fn loc_rib_dump_chunks_stream_complete_table() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = Ipv4Addr::new(10, 0, 0, 1);
    let total = 2 * BMP_DUMP_CHUNK_SIZE + 88;
    let prefixes: Vec<Ipv4Prefix> = (0..total)
        .map(|i| {
            Ipv4Prefix::new(
                Ipv4Addr::new(
                    10,
                    u8::try_from(i / 256).unwrap(),
                    u8::try_from(i % 256).unwrap(),
                    0,
                ),
                24,
            )
        })
        .collect();
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: prefixes
            .iter()
            .map(|&p| make_route_with_lp(p, peer, 100))
            .collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (messages, requests) = drive_loc_rib_dump_from(&tx, None).await;
    // Three bounded unicast chunks (256 + 256 + 88), then the VPN
    // phase closing the dump with the four EoR markers.
    assert_eq!(requests, 4, "dump streams across multiple chunk requests");
    assert_eq!(
        messages.len(),
        total + 4,
        "every route plus one EoR per family"
    );

    let mut dumped = dumped_unicast_prefixes(&messages);
    assert_eq!(
        dumped.len(),
        total,
        "no route lost or duplicated across chunks"
    );
    dumped.sort_unstable();
    assert_eq!(dumped, prefixes, "every route present exactly once");

    drop(tx);
    handle.await.unwrap();
}

/// Live RIB commands interleave between dump chunk requests, and the
/// key-based cursor is robust to mutations mid-dump: a stats query
/// fired between chunks is serviced before the dump resumes, a route
/// inserted behind the cursor stays off the dump (the live stream
/// covers it — the accepted race), a route inserted ahead of the
/// cursor is picked up, and a not-yet-dumped route withdrawn between
/// chunks never appears. The dump still completes with the
/// End-of-RIB set.
#[expect(
    clippy::too_many_lines,
    reason = "one mid-dump mutation walk: chunk, mutate, live query, resume, membership asserts"
)]
#[tokio::test]
async fn loc_rib_dump_interleaves_live_commands_between_chunks() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = Ipv4Addr::new(10, 0, 0, 1);
    let total = BMP_DUMP_CHUNK_SIZE + 44;
    // Ascending insertion order == cursor (key) order for these prefixes.
    let prefixes: Vec<Ipv4Prefix> = (0..total)
        .map(|i| {
            Ipv4Prefix::new(
                Ipv4Addr::new(
                    10,
                    u8::try_from(i / 256).unwrap(),
                    u8::try_from(i % 256).unwrap(),
                    0,
                ),
                24,
            )
        })
        .collect();
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: prefixes
            .iter()
            .map(|&p| make_route_with_lp(p, peer, 100))
            .collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // First chunk by hand (the forwarder's opening request): exactly
    // the chunk-size smallest prefixes, with a resume cursor.
    let (reply, chunk_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBmpLocRibDump {
        cursor: None,
        reply,
    })
    .await
    .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), chunk_rx)
        .await
        .expect("first chunk within timeout")
        .expect("RIB manager replies");
    assert_eq!(first.messages.len(), BMP_DUMP_CHUNK_SIZE);
    let cursor = first.next.expect("table larger than one chunk");

    // Mutate the table between chunk requests: one prefix sorting
    // before the cursor (dump must skip it), one after (dump must pick
    // it up), and withdraw a not-yet-dumped prefix.
    let low = Ipv4Prefix::new(Ipv4Addr::new(1, 0, 0, 0), 24);
    let high = Ipv4Prefix::new(Ipv4Addr::new(240, 0, 0, 0), 24);
    let withdrawn_mid = prefixes[BMP_DUMP_CHUNK_SIZE + 10];
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![
            make_route_with_lp(low, peer, 100),
            make_route_with_lp(high, peer, 100),
        ],
        withdrawn: vec![(Prefix::V4(withdrawn_mid), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // A live query between chunk requests is serviced before the dump
    // resumes — the dump holds no lock on the manager.
    let (stats_reply, stats_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBmpLocRibStats { reply: stats_reply })
        .await
        .unwrap();
    let stats = tokio::time::timeout(Duration::from_secs(2), stats_rx)
        .await
        .expect("stats reply while the dump is mid-flight")
        .expect("stats channel open");
    let v4_count = stats
        .iter()
        .find(|&&(afi, safi, _)| afi == Afi::Ipv4 as u16 && safi == Safi::Unicast as u8)
        .map(|&(_, _, count)| count)
        .unwrap();
    assert_eq!(
        v4_count,
        u64::try_from(total + 2 - 1).unwrap(),
        "the mutation batch was applied between dump chunks"
    );

    // Resume the dump to completion from the first chunk's cursor.
    let (rest, _) = drive_loc_rib_dump_from(&tx, Some(cursor)).await;
    let mut messages = first.messages;
    messages.extend(rest);

    let dumped = dumped_unicast_prefixes(&messages);
    let mut expected: Vec<Ipv4Prefix> = prefixes
        .iter()
        .copied()
        .filter(|&p| p != withdrawn_mid)
        .chain(std::iter::once(high))
        .collect();
    expected.sort_unstable();
    let mut sorted = dumped.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted, expected,
        "surviving + ahead-of-cursor routes exactly once; behind-cursor \
         insert and mid-dump withdrawal absent"
    );
    assert!(
        !dumped.contains(&low),
        "insertion behind the cursor is live-stream territory, not dump"
    );

    drop(tx);
    handle.await.unwrap();
}

/// Per-family Loc-RIB counts for the RFC 9069 stats report.
#[tokio::test]
async fn query_bmp_loc_rib_stats_counts_per_family() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = Ipv4Addr::new(10, 0, 0, 1);
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![
            make_route_with_lp(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16), peer, 100),
            make_route_with_lp(Ipv4Prefix::new(Ipv4Addr::new(10, 2, 0, 0), 16), peer, 100),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::VpnRoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![make_vpn_rib_route(peer, 42, 1042, 100)],
        withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply, rx_stats) = oneshot::channel();
    tx.send(RibUpdate::QueryBmpLocRibStats { reply })
        .await
        .unwrap();
    let counts = rx_stats.await.unwrap();
    assert_eq!(
        counts,
        vec![
            (Afi::Ipv4 as u16, Safi::Unicast as u8, 2),
            (Afi::Ipv6 as u16, Safi::Unicast as u8, 0),
            (Afi::Ipv4 as u16, Safi::MplsVpn as u8, 1),
            (Afi::Ipv6 as u16, Safi::MplsVpn as u8, 0),
        ]
    );

    drop(tx);
    handle.await.unwrap();
}

/// Without the tap installed (no collector monitors `loc_rib`), best
/// changes emit nothing and cost only the `is_some()` check — proven by
/// the absence of any panic/blocking with no BMP channel at all, and
/// the default construction path used by every other test in this
/// suite.
#[tokio::test]
async fn no_bmp_tx_means_no_synthesis() {
    let (tx, rx) = mpsc::channel(8);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let peer = Ipv4Addr::new(10, 0, 0, 1);
    tx.send(RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: vec![make_route_with_lp(
            Ipv4Prefix::new(Ipv4Addr::new(10, 9, 0, 0), 16),
            peer,
            100,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    let (reply, rx_count) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    assert_eq!(rx_count.await.unwrap(), 1);
    drop(tx);
    handle.await.unwrap();
}
