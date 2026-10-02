//! Graceful Restart End-of-RIB cost for one restarting source.
//!
//! One unregistered eBGP source announces the fixture table through the
//! production `RoutesReceived` path, enters Graceful Restart
//! (`PeerGracefulRestart`: every route in its GR families retained and marked
//! stale), re-advertises the identical table (stale flags cleared on insert),
//! and then sends one End-of-RIB per GR family. Each End-of-RIB is timed as one
//! production `EndOfRib` dispatch, with the unicast recompute and distribution
//! split reported separately. `stale_resolution_ns` covers unicast stale
//! removal and retained local LLGR-tag cleanup together; attribute GC and
//! exact stale counting retain separate spans. Fixture construction, the
//! restart, and the re-advertisement stay outside the timed interval.
//!
//! Modes:
//! - `dual`: 1,000,000 IPv4 + 200,000 IPv6 routes; GR families IPv4, IPv6
//!   and VPNv4 (no VPN routes, so its End-of-RIB changes no unicast input);
//!   two plain grouped route-server clients.
//! - `pcb-group`: `dual` with the two clients negotiating per-client-best
//!   on unicast only, so they form one per-client-best update group (the
//!   group stages the whole affected set, and each member's pass scope
//!   widens to it).
//! - `pcb-fallback`: `dual` with per-client-best clients that also negotiate
//!   VPNv4, which keeps them ungrouped on the per-peer per-client-best path
//!   (each peer scans the whole affected set).
//! - `ipv4`: 1,000,000 IPv4 routes, IPv4 as the only GR family.
//! - `--self-test`: every mode at 2,000 / 400 routes.
//! - `--attribute-sets N`: deterministic synthetic MED values make N distinct
//!   interned sets; omitted means the original one-set fixture.
//!
//! Each invocation prints one JSON line per mode.
//!
//!   cargo bench -p rustbgpd-rib --features bench-internals --bench gr_end_of_rib -- --mode dual

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rustbgpd_rib::AttrSet;
use rustbgpd_rib::{
    ExactExportCandidate, ExactExportEncoder, ExactExportError, ExactExportResult,
    ExactExportSnapshot, OutboundRouteUpdate, RibManager, RibUpdate, Route, RouteOrigin,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, Ipv4Prefix, Ipv6Prefix, MAX_MESSAGE_LEN, Origin, PathAttribute,
    Prefix, RpkiValidation, Safi,
};
use tokio::sync::mpsc;

const IPV4_UNICAST: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const IPV6_UNICAST: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);
const VPNV4: (Afi, Safi) = (Afi::Ipv4, Safi::MplsVpn);
const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Dual,
    PerClientBestGroup,
    PerClientBestFallback,
    Ipv4,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Dual => "dual",
            Self::PerClientBestGroup => "pcb-group",
            Self::PerClientBestFallback => "pcb-fallback",
            Self::Ipv4 => "ipv4",
        }
    }

    const fn gr_families(self) -> &'static [(Afi, Safi)] {
        match self {
            Self::Dual | Self::PerClientBestGroup | Self::PerClientBestFallback => {
                &[VPNV4, IPV4_UNICAST, IPV6_UNICAST]
            }
            Self::Ipv4 => &[IPV4_UNICAST],
        }
    }

    const fn client_families(self) -> &'static [(Afi, Safi)] {
        match self {
            Self::Dual | Self::PerClientBestGroup => &[IPV4_UNICAST, IPV6_UNICAST],
            Self::PerClientBestFallback => &[IPV4_UNICAST, IPV6_UNICAST, VPNV4],
            Self::Ipv4 => &[IPV4_UNICAST],
        }
    }

    const fn ipv6_routes(self, full: usize) -> usize {
        match self {
            Self::Dual | Self::PerClientBestGroup | Self::PerClientBestFallback => full,
            Self::Ipv4 => 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PermissiveExactExport;

impl ExactExportSnapshot for PermissiveExactExport {
    fn owner_id(&self) -> u64 {
        1
    }

    fn generation(&self) -> u64 {
        0
    }

    fn probe_announcement(
        &self,
        _candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError> {
        Ok(ExactExportResult {
            encoded_len: 0,
            max_len: usize::from(MAX_MESSAGE_LEN),
            generation: 0,
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl ExactExportEncoder for PermissiveExactExport {
    fn owner_id(&self) -> u64 {
        1
    }

    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot> {
        Arc::new(*self)
    }
}

fn route(prefix: Prefix, attributes: &Arc<AttrSet>) -> Route {
    Route {
        prefix,
        next_hop: match prefix {
            Prefix::V4(_) => IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            Prefix::V6(_) => IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1)),
        },
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: SOURCE,
        attributes: Arc::clone(attributes),
        received_at: rustbgpd_rib::route::ReceivedAt::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(172, 16, 0, 1),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
    }
}

fn attribute_pool(count: usize) -> Vec<Arc<AttrSet>> {
    let base = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![64_600, 64_601])],
        }),
    ];
    (0..count)
        .map(|index| {
            let mut attributes = base.clone();
            if count > 1 {
                attributes.push(PathAttribute::Med(
                    u32::try_from(index).expect("MED fits u32"),
                ));
            }
            AttrSet::new(attributes)
        })
        .collect()
}

fn table(ipv4: usize, ipv6: usize, attributes: &[Arc<AttrSet>]) -> Vec<Route> {
    let v4 = (0..ipv4).map(|index| {
        let index = u32::try_from(index).expect("IPv4 count fits u32");
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x1400_0000 + index), 32))
    });
    let v6 = (0..ipv6).map(|index| {
        let index = u128::try_from(index).expect("IPv6 count fits u128");
        Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::from((0x2001_0db8_u128 << 96) | (index << 64)),
            64,
        ))
    });
    v4.chain(v6)
        .enumerate()
        .map(|(index, prefix)| route(prefix, &attributes[index % attributes.len()]))
        .collect()
}

fn drain(receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>]) -> usize {
    receivers
        .iter_mut()
        .map(|receiver| {
            let mut count = 0;
            while receiver.try_recv().is_ok() {
                count += 1;
            }
            count
        })
        .sum()
}

fn run(mode: Mode, ipv4: usize, ipv6_full: usize, attribute_sets: usize) {
    let ipv6 = mode.ipv6_routes(ipv6_full);
    assert!(
        (1..=ipv4 + ipv6).contains(&attribute_sets),
        "attribute-set count must be between 1 and the route count"
    );
    let attributes = attribute_pool(attribute_sets);
    let (_tx, rx) = mpsc::channel::<RibUpdate>(16);
    let (_qtx, qrx) = mpsc::channel::<RibUpdate>(16);
    let mut manager = RibManager::new(rx, qrx, None, None, BgpMetrics::new());
    let mut receivers = manager.bench_register_unicast_route_server_peers(
        2,
        mode.client_families(),
        matches!(mode, Mode::PerClientBestGroup | Mode::PerClientBestFallback),
        1 << 20,
        |_| Arc::new(PermissiveExactExport),
    );
    manager.bench_seed_loc_rib(table(ipv4, ipv6, &attributes));
    drain(&mut receivers);
    let receipt = manager.bench_adj_rib_out_fanout_receipt();
    let grouped = mode != Mode::PerClientBestFallback;
    assert_eq!(
        (
            receipt.update_groups,
            receipt.grouped_peers,
            receipt.ungrouped_peers
        ),
        if grouped { (1, 2, 0) } else { (0, 0, 2) },
        "{} clients must take the intended distribution path",
        mode.name()
    );
    manager.bench_gr_restart(SOURCE, mode.gr_families());
    manager.bench_seed_loc_rib(table(ipv4, ipv6, &attributes));
    drain(&mut receivers);
    let intern = manager.bench_attr_intern_inventory();
    assert_eq!(
        intern[2], attribute_sets,
        "intern cardinality matches fixture"
    );

    let mut eors = Vec::new();
    for &(afi, safi) in mode.gr_families() {
        let receipt = manager.bench_end_of_rib(SOURCE, afi, safi);
        let envelopes = drain(&mut receivers);
        eors.push(format!(
            "{{\"family\":\"{afi:?}/{safi:?}\",\"total_ns\":{},\"recompute_ns\":{},\"distribute_ns\":{},\"affected\":{},\"changed\":{},\"retained_stale\":{},\"gr_complete\":{},\"attr_gc_ns\":{},\"stale_count_ns\":{},\"stale_resolution_ns\":{},\"envelopes\":{envelopes}}}",
            receipt[0], receipt[1], receipt[2], receipt[3], receipt[4], receipt[5], receipt[6], receipt[7], receipt[8], receipt[9]
        ));
        assert_eq!(
            (receipt[3], receipt[4], receipt[5], envelopes),
            (0, 0, 0, 0),
            "identical re-advertisement leaves no EoR work or output"
        );
    }
    let last = eors.last().expect("at least one GR family");
    assert!(
        last.contains("\"gr_complete\":1"),
        "GR completes after the last End-of-RIB"
    );
    // `bench_selection_deferral_inventory`: [0] Loc-RIB IPv4, [2] Loc-RIB IPv6.
    let inventory = manager.bench_selection_deferral_inventory();
    assert_eq!(
        (inventory[0], inventory[2]),
        (ipv4 as u64, ipv6 as u64),
        "every route survives End-of-RIB"
    );
    println!(
        "{{\"mode\":\"{}\",\"ipv4_routes\":{ipv4},\"ipv6_routes\":{ipv6},\"attribute_shape\":\"{}\",\"requested_attribute_sets\":{attribute_sets},\"interned_sets\":{},\"intern_capacity\":{},\"end_of_rib\":[{}]}}",
        mode.name(),
        if attribute_sets == 1 {
            "uniform"
        } else {
            "synthetic-distinct-med"
        },
        intern[2],
        intern[3],
        eors.join(",")
    );
}

fn main() {
    let mut modes = Vec::new();
    let mut self_test = false;
    let mut attribute_sets = 1;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--bench" => {}
            "--self-test" => self_test = true,
            "--attribute-sets" => {
                attribute_sets = args
                    .next()
                    .expect("--attribute-sets requires a value")
                    .parse()
                    .expect("--attribute-sets must be a positive integer");
            }
            "--mode" => {
                let value = args.next().expect("--mode requires a value");
                modes.push(match value.as_str() {
                    "dual" => Mode::Dual,
                    "pcb-group" => Mode::PerClientBestGroup,
                    "pcb-fallback" => Mode::PerClientBestFallback,
                    "ipv4" => Mode::Ipv4,
                    other => panic!("unknown mode {other}"),
                });
            }
            other => panic!("unknown argument {other}"),
        }
    }
    if modes.is_empty() {
        modes = vec![
            Mode::Dual,
            Mode::PerClientBestGroup,
            Mode::PerClientBestFallback,
            Mode::Ipv4,
        ];
    }
    let (ipv4, ipv6) = if self_test {
        (2_000, 400)
    } else {
        (1_000_000, 200_000)
    };
    for mode in modes {
        run(mode, ipv4, ipv6, attribute_sets);
    }
}
