//! Session-side outbound encode: `send_route_update` grouping, UPDATE build
//! and writer-queue enqueue for one announce-only envelope, against an
//! in-memory writer queue. Only `send_route_update` is timed; draining the
//! queue happens outside the measurement.
//!
//! - `shared_arc`: every route shares one attribute allocation (the common
//!   case: interned source attributes and a pass-scoped export memo).
//! - `equal_values`: equal attribute values behind one allocation per route
//!   (a replay of routes stored across many distribution passes).
//! - `distinct_values`: a distinct MED per route (a diverse table: one
//!   UPDATE per route whatever the grouping key).
//!
//!
//! `failover_encode` times one grouped distribution pass across identical
//! update-group members sharing one encode cell: `announce_only`, and
//! `mixed` (the same announcements plus withdrawals, the shape of a member
//! failover where some prefixes have an alternate source and some do not).
//! Each cell reports the summed session time of all members.
//!
//! `outbound_admission` drives the production pending cursor with completed
//! writer watermarks between steps. It includes slicing and encoding;
//! large-frame cells exercise the byte limit under both message-size modes.
//!
//!   cargo bench -p rustbgpd-transport --features bench-internals --bench outbound_encode

use rustbgpd_rib::PeerId;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustbgpd_rib::AttrSet;
use rustbgpd_rib::{EvpnRibRoute, OutboundRouteUpdate, Route, RouteOrigin, VpnRibRoute};
use rustbgpd_transport::{OutboundEncodeBench, OutboundGroupBench};
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, EthernetSegmentIdentifier, EthernetTagId, EvpnIpPrefixRoute,
    EvpnIpPrefixValue, EvpnRoute, Ipv4Prefix, MplsLabel, MplsLabelEntry, Origin, PathAttribute,
    Prefix, Safi, VpnNlri, VpnPrefix,
};

/// Benches link the allocator the daemon ships with, so allocation-heavy
/// paths are timed under jemalloc rather than the system allocator.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn attrs(med: Option<u32>) -> Vec<PathAttribute> {
    let mut attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65_002, 64_600, 64_700])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Communities(vec![0xFF78_03E8, 0xFDE8_0064]),
    ];
    if let Some(med) = med {
        attrs.push(PathAttribute::Med(med));
    }
    attrs
}

fn routes(count: u32, shape: &str) -> Arc<Vec<Route>> {
    let shared = AttrSet::new(attrs(None));
    (0..count)
        .map(|i| Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | (i << 8)), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            attributes: match shape {
                "shared_arc" => Arc::clone(&shared),
                "equal_values" => AttrSet::new(attrs(None)),
                _ => AttrSet::new(attrs(Some(i))),
            },
            received_at: rustbgpd_rib::route::ReceivedAt::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            received_as_path: None,
            aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
        })
        .collect::<Vec<_>>()
        .into()
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbound_encode");
    for shape in ["shared_arc", "equal_values", "distinct_values"] {
        for count in [100u32, 1_000, 10_000] {
            let announce = routes(count, shape);
            let mut bench = OutboundEncodeBench::new(1 << 16);
            group.throughput(Throughput::Elements(u64::from(count)));
            group.bench_with_input(BenchmarkId::new(shape, count), &announce, |b, announce| {
                b.iter_custom(|iterations| {
                    (0..iterations)
                        .map(|_| bench.send(black_box(announce)))
                        .sum()
                });
            });
        }
    }
    group.finish();
}

fn admission(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbound_admission");
    for shape in ["shared_arc", "equal_values", "distinct_values"] {
        let announce = routes(10_000, shape);
        let mut bench = OutboundEncodeBench::new(4_096);
        group.throughput(Throughput::Elements(10_000));
        group.bench_function(shape, |b| {
            b.iter_custom(|iterations| {
                (0..iterations)
                    .map(|_| bench.send_paced(black_box(&announce), false))
                    .sum()
            });
        });
    }
    for (shape, extended, communities) in [
        ("large_standard", false, 1_000u32),
        ("large_extended", true, 16_350),
    ] {
        let mut announce = routes(2_049, "distinct_values");
        for route in Arc::make_mut(&mut announce) {
            AttrSet::edit(&mut route.attributes, |attrs| {
                attrs.retain(|attr| !matches!(attr, PathAttribute::Communities(_)));
                attrs.push(PathAttribute::Communities((0..communities).collect()));
            });
        }
        let mut bench = OutboundEncodeBench::new(4_096);
        group.throughput(Throughput::Elements(2_049));
        group.bench_function(shape, |b| {
            b.iter_custom(|iterations| {
                (0..iterations)
                    .map(|_| bench.send_paced(black_box(&announce), extended))
                    .sum()
            });
        });
    }
    group.finish();
}

fn evpn_routes(count: u32, shape: &str) -> Arc<Vec<EvpnRibRoute>> {
    routes(count, shape)
        .iter()
        .map(|base| {
            let Prefix::V4(prefix) = base.prefix else {
                unreachable!()
            };
            EvpnRibRoute {
                route: EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
                    rd: "65000:1".parse().unwrap(),
                    esi: EthernetSegmentIdentifier::ZERO,
                    ethernet_tag: EthernetTagId(0),
                    prefix: EvpnIpPrefixValue::V4(prefix),
                    gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    label: MplsLabel::new(100),
                }),
                next_hop: base.next_hop,
                link_local_next_hop: None,
                peer: base.peer,
                attributes: Arc::clone(&base.attributes),
                received_at: std::time::Instant::now(),
                origin_type: base.origin_type,
                peer_router_id: base.peer_router_id,
                is_stale: false,
                is_llgr_stale: false,
            }
        })
        .collect::<Vec<_>>()
        .into()
}

fn vpn_routes(count: u32, shape: &str) -> Arc<Vec<VpnRibRoute>> {
    routes(count, shape)
        .iter()
        .map(|base| {
            let Prefix::V4(prefix) = base.prefix else {
                unreachable!()
            };
            VpnRibRoute {
                nlri: VpnNlri {
                    labels: vec![MplsLabelEntry::try_new(100, 0, true).unwrap()],
                    route_distinguisher: "65000:1".parse().unwrap(),
                    prefix: VpnPrefix::v4(prefix.addr, prefix.len).unwrap(),
                },
                next_hop: base.next_hop,
                link_local_next_hop: None,
                next_hop_scope: None,
                peer: base.peer,
                attributes: Arc::clone(&base.attributes),
                received_at: std::time::Instant::now(),
                origin_type: base.origin_type,
                peer_router_id: base.peer_router_id,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
            }
        })
        .collect::<Vec<_>>()
        .into()
}

fn family_admission(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbound_admission");
    group.throughput(Throughput::Elements(10_000));
    for shape in ["shared_arc", "distinct_values"] {
        let evpn = evpn_routes(10_000, shape);
        let vpn = vpn_routes(10_000, shape);
        let mut bench = OutboundEncodeBench::new(4_096);
        group.bench_function(format!("evpn_{shape}"), |b| {
            b.iter_custom(|iterations| {
                (0..iterations)
                    .map(|_| {
                        bench.send_paced_update(
                            OutboundRouteUpdate {
                                evpn_announce: Arc::clone(black_box(&evpn)),
                                ..OutboundRouteUpdate::default()
                            },
                            (Afi::L2Vpn, Safi::Evpn),
                            false,
                        )
                    })
                    .sum()
            });
        });
        group.bench_function(format!("vpn_{shape}"), |b| {
            b.iter_custom(|iterations| {
                (0..iterations)
                    .map(|_| {
                        bench.send_paced_update(
                            OutboundRouteUpdate {
                                vpn_announce: Arc::clone(black_box(&vpn)),
                                ..OutboundRouteUpdate::default()
                            },
                            (Afi::Ipv4, Safi::MplsVpn),
                            false,
                        )
                    })
                    .sum()
            });
        });
    }
    let evpn: Vec<_> = evpn_routes(10_000, "shared_arc")
        .iter()
        .map(EvpnRibRoute::key)
        .collect();
    let vpn: Vec<_> = vpn_routes(10_000, "shared_arc")
        .iter()
        .map(VpnRibRoute::key)
        .collect();
    let mut bench = OutboundEncodeBench::new(4_096);
    group.bench_function("evpn_withdraw", |b| {
        b.iter_custom(|iterations| {
            (0..iterations)
                .map(|_| {
                    bench.send_paced_update(
                        OutboundRouteUpdate {
                            evpn_withdraw: black_box(&evpn).clone(),
                            ..OutboundRouteUpdate::default()
                        },
                        (Afi::L2Vpn, Safi::Evpn),
                        false,
                    )
                })
                .sum()
        });
    });
    group.bench_function("vpn_withdraw", |b| {
        b.iter_custom(|iterations| {
            (0..iterations)
                .map(|_| {
                    bench.send_paced_update(
                        OutboundRouteUpdate {
                            vpn_withdraw: black_box(&vpn).clone(),
                            ..OutboundRouteUpdate::default()
                        },
                        (Afi::Ipv4, Safi::MplsVpn),
                        false,
                    )
                })
                .sum()
        });
    });
    group.finish();
}

/// 50 sources x 40 prefixes, one interned attribute set per source.
fn failover_announce() -> Arc<Vec<Route>> {
    let template = routes(1, "shared_arc")[0].clone();
    (1..=50u8)
        .flat_map(|s| {
            let source = Ipv4Addr::new(10, 1, 0, s);
            let mut source_attrs = attrs(None);
            source_attrs[1] = PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![64_600 + u32::from(s)])],
            });
            source_attrs[2] = PathAttribute::NextHop(source);
            let shared = AttrSet::new(source_attrs);
            let template = template.clone();
            (0..40u32).map(move |j| {
                let i = u32::from(s - 1) * 40 + j;
                Route {
                    prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | (i << 8)), 24)),
                    peer: PeerId::from_addr(IpAddr::V4(source)),
                    next_hop: IpAddr::V4(source),
                    attributes: Arc::clone(&shared),
                    ..template.clone()
                }
            })
        })
        .collect::<Vec<_>>()
        .into()
}

fn failover(c: &mut Criterion) {
    let mut group = c.benchmark_group("failover_encode");
    let announce = failover_announce();
    let withdraw: Vec<(Prefix, u32)> = (0..1_000u32)
        .map(|i| {
            (
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((30 << 24) | (i << 8)), 24)),
                0,
            )
        })
        .collect();
    for (shape, withdraw) in [("announce_only", &[][..]), ("mixed", &withdraw[..])] {
        for members in [8usize, 32] {
            let mut bench = OutboundGroupBench::new(members, 1 << 16);
            group.bench_function(BenchmarkId::new(shape, members), |b| {
                b.iter_custom(|iterations| {
                    (0..iterations)
                        .map(|_| bench.send(black_box(&announce), black_box(withdraw)))
                        .sum()
                });
            });
        }
    }
    group.finish();
}

fn run_benches(c: &mut Criterion) {
    // Admission can arm the slow-peer timer. Enter its reactor once, outside
    // all measured intervals; the session work remains synchronously polled.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    bench(c);
    admission(c);
    family_admission(c);
    failover(c);
}

criterion_group!(benches, run_benches);
criterion_main!(benches);
