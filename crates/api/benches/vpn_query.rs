//! Occupancy and timing receipt for the production VPN RIB query path.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rustbgpd_api::proto;
use rustbgpd_api::proto::rib_service_server::RibService as RibServiceTrait;
use rustbgpd_api::rib_service::{RibService, VpnQueryServiceReceipt};
use rustbgpd_rib::{RibManager, RibUpdate, RouteOrigin, VpnRibRoute};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AsPath, AsPathSegment, ExtendedCommunity, MplsLabelEntry, Origin, PathAttribute,
    RouteDistinguisher, VpnNlri, VpnPrefix,
};
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tonic::Request;

#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const PEERS: usize = 16;
const SMOKE_ROUTES: usize = 256;
const BATCH: usize = 4_096;

#[derive(Debug)]
struct QueryReceipt {
    actor_ns: u64,
    service_method_ns: u64,
    post_actor_ns: u64,
    actor_rows: usize,
    actor_capacity: usize,
    returned_rows: usize,
    dispatch: u64,
    checksum: u64,
}

fn mix(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn semantic_hash(rd: &[u8], prefix: &str, peer: &str, label: u32) -> u64 {
    let hash = mix(0xcbf2_9ce4_8422_2325, rd);
    let hash = mix(hash, prefix.as_bytes());
    let hash = mix(hash, peer.as_bytes());
    mix(hash, &label.to_be_bytes())
}

fn route(index: usize, attributes: &Arc<Vec<PathAttribute>>) -> VpnRibRoute {
    let peer_octet = u8::try_from(index % PEERS + 1).unwrap();
    let peer = Ipv4Addr::new(10, 0, 0, peer_octet);
    let prefix = Ipv4Addr::from(0x0b00_0000_u32 + u32::try_from(index).unwrap());
    VpnRibRoute {
        nlri: VpnNlri {
            labels: vec![MplsLabelEntry::try_new(300, 0, true).unwrap()],
            route_distinguisher: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
            prefix: VpnPrefix::v4(prefix, 32).unwrap(),
        },
        next_hop: Ipv4Addr::new(192, 0, 2, 1).into(),
        link_local_next_hop: None,
        peer: peer.into(),
        attributes: Arc::clone(attributes),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

fn expected_checksum(routes: usize, filtered: bool) -> u64 {
    let rd = [0, 0, 0xfd, 0xe8, 0, 0, 0, 100];
    (0..routes)
        .filter(|index| !filtered || index % PEERS == 0)
        .fold(0_u64, |sum, index| {
            let peer = format!("10.0.0.{}", index % PEERS + 1);
            let prefix = format!("{}/32", Ipv4Addr::from(0x0b00_0000_u32 + index as u32));
            sum.wrapping_add(semantic_hash(&rd, &prefix, &peer, 300))
        })
}

async fn query(
    service: &RibService,
    actor_rx: &mut mpsc::Receiver<(u64, usize, usize, u64)>,
    service_rx: &mut mpsc::Receiver<VpnQueryServiceReceipt>,
    peer_filter: &str,
) -> QueryReceipt {
    let started = Instant::now();
    let response = service
        .list_vpn_routes(Request::new(proto::ListVpnRoutesRequest {
            afi_safi: String::new(),
            peer_filter: peer_filter.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    let service_method_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let (actor_ns, actor_rows, actor_capacity, dispatch) = actor_rx.recv().await.unwrap();
    let service_receipt = service_rx.recv().await.unwrap();
    assert_eq!(service_receipt.returned_rows, response.routes.len());
    let checksum = response.routes.iter().fold(0_u64, |sum, row| {
        sum.wrapping_add(semantic_hash(
            &row.route_distinguisher,
            &row.prefix,
            &row.peer_address,
            row.labels[0],
        ))
    });
    QueryReceipt {
        actor_ns,
        service_method_ns,
        post_actor_ns: service_receipt.post_actor_ns,
        actor_rows,
        actor_capacity,
        returned_rows: service_receipt.returned_rows,
        dispatch,
        checksum,
    }
}

fn verify(receipt: &QueryReceipt, routes: usize, filtered: bool, dispatch: u64) {
    let expected_rows = if filtered { routes / PEERS } else { routes };
    assert_eq!(receipt.actor_rows, routes);
    assert!(receipt.actor_capacity >= routes);
    assert_eq!(receipt.returned_rows, expected_rows);
    assert_eq!(receipt.dispatch, dispatch);
    assert_eq!(receipt.checksum, expected_checksum(routes, filtered));
    assert!(receipt.actor_ns > 0);
    assert!(receipt.service_method_ns > 0);
    assert!(receipt.post_actor_ns > 0);
}

async fn run(routes: usize, output: &str) {
    let (primary_tx, primary_rx) = mpsc::channel(32);
    let (query_tx, query_rx) = mpsc::channel(8);
    let (actor_tx, mut actor_rx) = mpsc::channel(4);
    let manager = RibManager::new(primary_rx, query_rx, None, None, BgpMetrics::new())
        .with_vpn_query_bench_receipts(actor_tx);
    let manager_task = tokio::spawn(manager.run());
    let attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![64512, 64513])],
        }),
        PathAttribute::LocalPref(100),
        PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(0x0002_fde8_0000_0064)]),
    ]);
    for start in (0..routes).step_by(BATCH) {
        let end = (start + BATCH).min(routes);
        primary_tx
            .send(RibUpdate::VpnRoutesReceived {
                peer: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                session_id: 0,
                announced: (start..end).map(|i| route(i, &attributes)).collect(),
                withdrawn: Vec::new(),
            })
            .await
            .unwrap();
    }
    let (barrier_tx, barrier_rx) = oneshot::channel();
    primary_tx
        .send(RibUpdate::QueryLocRibCount { reply: barrier_tx })
        .await
        .unwrap();
    let _ = barrier_rx.await.unwrap();

    let (service_tx, mut service_rx) = mpsc::channel(4);
    let service = RibService::new(query_tx).with_vpn_query_bench_receipts(service_tx);
    let all = query(&service, &mut actor_rx, &mut service_rx, "").await;
    let filtered = query(&service, &mut actor_rx, &mut service_rx, "10.0.0.1").await;
    verify(&all, routes, false, 1);
    verify(&filtered, routes, true, 2);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let document = json!({
        "schema": 1,
        "allocator": "tikv-jemallocator",
        "mode": "timing",
        "timestamp_unix": timestamp,
        "routes": routes,
        "peers": PEERS,
        "queries": {
            "all": receipt_json(&all),
            "peer_10_0_0_1": receipt_json(&filtered),
        }
    });
    std::fs::write(output, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    manager_task.abort();
}

fn receipt_json(value: &QueryReceipt) -> serde_json::Value {
    json!({
        "actor_handler_ns": value.actor_ns,
        "service_method_ns": value.service_method_ns,
        "post_actor_ns": value.post_actor_ns,
        "actor_rows": value.actor_rows,
        "actor_capacity": value.actor_capacity,
        "returned_rows": value.returned_rows,
        "dispatch": value.dispatch,
        "checksum": value.checksum,
    })
}

fn main() {
    let args: Vec<_> = std::env::args().filter(|arg| arg != "--bench").collect();
    let (routes, output) = match args.as_slice() {
        [_, mode, output] if mode == "smoke" => (SMOKE_ROUTES, output.as_str()),
        [_, mode, count, output] if mode == "measure" => {
            let routes = count.parse::<usize>().unwrap();
            assert!([10_000, 100_000, 1_000_000].contains(&routes));
            (routes, output.as_str())
        }
        _ => {
            panic!("usage: vpn_query smoke OUTPUT | vpn_query measure 10000|100000|1000000 OUTPUT")
        }
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(routes, output));
}
