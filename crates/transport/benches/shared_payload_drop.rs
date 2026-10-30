//! Final-drop cost of a shared update-group payload: the time one session
//! turn spends when the last member drops `Arc<Vec<Route>>` (unicast) or
//! `Arc<Vec<VpnRibRoute>>` (VPN) at full-table scale.
//!
//! Attribute shapes:
//! - `shared`: every route behind one attribute allocation.
//! - `distinct_held`: one attribute allocation per route, still owned
//!   elsewhere (the RIB), so the drop only decrements scattered refcounts.
//! - `distinct_last`: one attribute allocation per route, freed by this drop
//!   (worst case: the envelope outlived the RIB's copies).
//!
//! Plain timing harness (no Criterion): one drop per sample, rebuilt between
//! samples. Prints min / median / max in milliseconds.
//!
//!   cargo bench -p rustbgpd-transport --bench shared_payload_drop

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustbgpd_rib::{AttrSet, PeerId, Route, RouteOrigin, VpnRibRoute};
use rustbgpd_wire::{
    AsPath, AsPathSegment, ExtendedCommunity, Ipv4Prefix, MplsLabelEntry, Origin, PathAttribute,
    Prefix, RouteDistinguisher, VpnNlri, VpnPrefix,
};

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const ROUTES: u32 = 1_000_000;
const SAMPLES: usize = 7;

fn attrs(i: u32, vpn: bool) -> Vec<PathAttribute> {
    let mut attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![
                65_002,
                64_600 + (i % 97),
                64_700 + (i % 89),
            ])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Med(i),
        PathAttribute::Communities(vec![0xFF78_03E8, 0xFDE8_0064]),
    ];
    if vpn {
        attrs.push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::new(0x0002_FDE8_0000_0001),
        ]));
    }
    attrs
}

fn attr_table(shape: &str, vpn: bool) -> Vec<Arc<AttrSet>> {
    match shape {
        "shared" => vec![AttrSet::new(attrs(0, vpn))],
        _ => (0..ROUTES).map(|i| AttrSet::new(attrs(i, vpn))).collect(),
    }
}

fn peer() -> PeerId {
    PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
}

fn unicast(table: &[Arc<AttrSet>]) -> Arc<Vec<Route>> {
    (0..ROUTES)
        .map(|i| Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(i << 8), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: peer(),
            attributes: Arc::clone(&table[i as usize % table.len()]),
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

fn vpn(table: &[Arc<AttrSet>]) -> Arc<Vec<VpnRibRoute>> {
    (0..ROUTES)
        .map(|i| VpnRibRoute {
            nlri: VpnNlri {
                labels: vec![MplsLabelEntry::try_new(16 + (i % 1_000_000), 0, true).unwrap()],
                route_distinguisher: RouteDistinguisher([
                    0,
                    0,
                    0xFD,
                    0xE8,
                    0,
                    0,
                    0,
                    u8::try_from(i % 251).unwrap(),
                ]),
                prefix: VpnPrefix::v4(Ipv4Addr::from(i << 8), 24).unwrap(),
            },
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: peer(),
            attributes: Arc::clone(&table[i as usize % table.len()]),
            received_at: std::time::Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        })
        .collect::<Vec<_>>()
        .into()
}

fn time_drop<T>(build: impl Fn() -> Arc<Vec<T>>) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let payload = black_box(build());
        // A second member's reference, released first, as in a group.
        let member = Arc::clone(&payload);
        drop(member);
        let start = Instant::now();
        drop(payload);
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    samples
}

fn report(case: &str, samples: &[Duration]) {
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    println!(
        "{case:<28} n={} min={:.2}ms median={:.2}ms max={:.2}ms",
        samples.len(),
        ms(samples[0]),
        ms(samples[samples.len() / 2]),
        ms(samples[samples.len() - 1]),
    );
}

fn main() {
    // `cargo bench` passes `--bench`; a filter argument selects cases.
    let filter = std::env::args().skip(1).find(|a| !a.starts_with("--"));
    for shape in ["shared", "distinct_held", "distinct_last"] {
        for family in ["unicast", "vpn"] {
            let case = format!("{family}/{shape}");
            if filter.as_deref().is_some_and(|f| !case.contains(f)) {
                continue;
            }
            let is_vpn = family == "vpn";
            let held = (shape != "distinct_last").then(|| attr_table(shape, is_vpn));
            let samples = if is_vpn {
                time_drop(|| match &held {
                    Some(table) => vpn(table),
                    None => vpn(&attr_table(shape, true)),
                })
            } else {
                time_drop(|| match &held {
                    Some(table) => unicast(table),
                    None => unicast(&attr_table(shape, false)),
                })
            };
            report(&case, &samples);
        }
    }
}
