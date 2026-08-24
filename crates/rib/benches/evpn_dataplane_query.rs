use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustbgpd_rib::route::{EvpnRibRoute, RouteOrigin};
use rustbgpd_rib::{
    bench_evpn_dataplane_generation_query, bench_evpn_dataplane_generation_snapshot,
    bench_evpn_dataplane_legacy_snapshot,
};
use rustbgpd_wire::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnEadPerEvi, EvpnEs, EvpnImet, EvpnIpPrefixRoute,
    EvpnIpPrefixValue, EvpnMacIp, EvpnRoute, Ipv4Prefix, MacAddress, MplsLabel, RouteDistinguisher,
};

const CURRENT_GENERATION: u64 = 73;

fn rd(index: usize) -> RouteDistinguisher {
    let bytes = u64::try_from(index).unwrap_or(u64::MAX).to_be_bytes();
    RouteDistinguisher(bytes)
}

fn route(index: usize, route_type: u8) -> EvpnRibRoute {
    let octets = u32::try_from(index).unwrap_or(u32::MAX).to_be_bytes();
    let tag = EthernetTagId(u32::try_from(index).unwrap_or(u32::MAX));
    let peer = Ipv4Addr::new(192, 0, 2, 1);
    let route = match route_type {
        1 => EvpnRoute::EadPerEvi(EvpnEadPerEvi {
            rd: rd(index),
            esi: EthernetSegmentIdentifier::new([0, 1, 2, 3, 4, 5, 6, 7, 8, octets[3]]),
            ethernet_tag: tag,
            label: MplsLabel::new(u32::try_from(index % 16_000_000).unwrap()),
        }),
        2 => EvpnRoute::MacIp(EvpnMacIp {
            rd: rd(index),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: tag,
            mac: MacAddress::new([0x02, octets[0], octets[1], octets[2], octets[3], 1]),
            ip: Some(IpAddr::V4(Ipv4Addr::new(
                198, octets[1], octets[2], octets[3],
            ))),
            label1: MplsLabel::new(u32::try_from(index % 16_000_000).unwrap()),
            label2: None,
        }),
        3 => EvpnRoute::Imet(EvpnImet {
            rd: rd(index),
            ethernet_tag: tag,
            originator_ip: IpAddr::V4(Ipv4Addr::new(203, octets[1], octets[2], octets[3])),
        }),
        4 => EvpnRoute::Es(EvpnEs {
            rd: rd(index),
            esi: EthernetSegmentIdentifier::new([0, 9, 8, 7, 6, 5, 4, 3, 2, octets[3]]),
            originator_ip: IpAddr::V4(Ipv4Addr::new(203, octets[1], octets[2], octets[3])),
        }),
        5 => EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd: rd(index),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: tag,
            prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(
                Ipv4Addr::new(10, octets[1], octets[2], 0),
                24,
            )),
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: MplsLabel::new(u32::try_from(index % 16_000_000).unwrap()),
        }),
        _ => unreachable!(),
    };
    EvpnRibRoute {
        route,
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
    }
}

fn fixture(rows: usize, mixed: bool) -> Vec<EvpnRibRoute> {
    const RELEVANT: [u8; 3] = [1, 2, 5];
    const ALL_TYPES: [u8; 5] = [1, 2, 3, 4, 5];
    (0..rows)
        .map(|index| {
            let route_type = if mixed {
                ALL_TYPES[index % ALL_TYPES.len()]
            } else {
                RELEVANT[index % RELEVANT.len()]
            };
            route(index, route_type)
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    for (dataset, mixed) in [("all-relevant", false), ("mixed-types-1-through-5", true)] {
        let mut group = c.benchmark_group(format!("evpn_dataplane_query/{dataset}"));
        group.sample_size(10);
        group.warm_up_time(Duration::from_secs(1));
        group.measurement_time(Duration::from_secs(3));

        for rows in [0usize, 1_000, 50_000] {
            let routes = fixture(rows, mixed);
            let relevant_rows = routes
                .iter()
                .filter(|route| matches!(route.route_type(), 1 | 2 | 5))
                .count();
            let changed = bench_evpn_dataplane_generation_snapshot(
                &routes,
                Some(CURRENT_GENERATION.wrapping_sub(1)),
                CURRENT_GENERATION,
            );
            assert_eq!(changed.row_visits, rows);
            assert_eq!(changed.routes.as_ref().map(Vec::len), Some(relevant_rows));
            let unchanged = bench_evpn_dataplane_generation_snapshot(
                &routes,
                Some(CURRENT_GENERATION),
                CURRENT_GENERATION,
            );
            assert_eq!(unchanged.row_visits, 0);
            assert!(unchanged.routes.is_none());
            assert_eq!(bench_evpn_dataplane_legacy_snapshot(&routes).len(), rows);

            group.throughput(Throughput::Elements(u64::try_from(rows).unwrap()));
            group.bench_with_input(
                BenchmarkId::new("legacy-whole-table", rows),
                &routes,
                |b, r| {
                    b.iter(|| black_box(bench_evpn_dataplane_legacy_snapshot(black_box(r))));
                },
            );
            group.bench_with_input(
                BenchmarkId::new("generation-changed", rows),
                &routes,
                |b, r| {
                    b.iter(|| {
                        black_box(bench_evpn_dataplane_generation_query(
                            black_box(r),
                            relevant_rows,
                            Some(CURRENT_GENERATION.wrapping_sub(1)),
                            CURRENT_GENERATION,
                        ))
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new("generation-unchanged", rows),
                &routes,
                |b, r| {
                    b.iter(|| {
                        black_box(bench_evpn_dataplane_generation_query(
                            black_box(r),
                            relevant_rows,
                            Some(CURRENT_GENERATION),
                            CURRENT_GENERATION,
                        ))
                    });
                },
            );
        }
        group.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
