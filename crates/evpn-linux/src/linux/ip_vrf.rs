//! IP-VRF and L3 VXLAN device inventory (Gate 9, ADR-0058 §3 + §7).
//!
//! Companion to [`crate::linux::links`]: that module covers
//! bridge-and-L2-VXLAN topology for L2 EVPN. This one covers the L3
//! side — VRF master devices and the L3 VXLAN devices enslaved to them
//! for symmetric Interface-less IRB (RFC 9136 §4.4.2).
//!
//! The dump is a single pass over every netlink-reported link. We pick
//! out:
//!
//! - **VRF kind links** (`InfoKind::Vrf`) — the master device an IP-VRF
//!   configuration references via `vrf_device`. The dump captures
//!   ifindex, administrative UP flag, and `IFLA_VRF_TABLE`.
//! - **VXLAN kind links** (`InfoKind::Vxlan`) — both L2 and L3 VXLANs
//!   appear here; we index every one by `IFLA_IFNAME` and the caller
//!   asks for the one matching `l3vxlan_device`. The probe's seven
//!   predicates (ADR-0058 §3.3–§3.7) decide whether it's actually a
//!   well-formed L3 VXLAN — this layer just observes.
//!
//! ## Why a dedicated pass
//!
//! [`crate::linux::links::dump_links`] traverses every link too, but
//! indexes bridges and their attached VXLAN ports. L3 VXLANs have a
//! VRF master, not a bridge, so they never make it into that cache.
//! Trying to fold both shapes into one cache would have entangled the
//! L2 and L3 representations on what is supposed to be a kernel-free
//! data layer; a second, narrowly-scoped pass keeps the boundary clean.
//! The wire dump itself is cheap relative to the probe / reconcile
//! cycle that consumes it (one extra `RTM_GETLINK`).
//!
//! ## "Up" semantics
//!
//! Linux VRF master devices commonly report `OperState::Unknown` even
//! when administratively up (the kernel doesn't drive an oper-state
//! machine for them). The probe therefore reads the administrative
//! `IFF_UP` flag from the link header instead of `IFLA_OPERSTATE` —
//! same convention `ip link` itself uses for the UP/DOWN column.

// Slice 4a ships the dumps + composition helper alongside its own
// tests; the reconciler / `dump_snapshot` consumer arrives in slice
// 4b. The `expect` flips to a hard warning once that wiring lands,
// prompting removal here.
#![expect(dead_code, reason = "consumed by reconcile wiring in slice 4b")]

use std::collections::HashMap;
use std::net::IpAddr;

use futures::stream::TryStreamExt;
use netlink_packet_route::link::{
    InfoData, InfoKind, InfoVrf, InfoVxlan, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use rtnetlink::Handle;

use rustbgpd_evpn::MacAddress;
use rustbgpd_evpn::ip_vrf::{IpVrfKernelSnapshot, L3VxlanObservation, VrfObservation};

use crate::error::DataplaneError;

/// All VRF / L3 VXLAN devices observed in one netlink link dump,
/// indexed by `IFLA_IFNAME`.
///
/// The reconciler builds one of these per pass and uses
/// [`Self::snapshot_for`] to compose the kernel-free
/// [`IpVrfKernelSnapshot`] that the readiness probe consumes.
#[derive(Debug, Clone, Default)]
pub(crate) struct IpVrfObservations {
    vrfs: HashMap<String, VrfObservation>,
    l3vxlans: HashMap<String, L3VxlanObservation>,
}

impl IpVrfObservations {
    /// Compose the per-IP-VRF kernel-free snapshot for the configured
    /// device-name pair. Each side returns `None` when the kernel did
    /// not return a link with that name in this dump pass — which is
    /// structurally distinct from "the device exists but doesn't match
    /// the configuration" and produces a different `IpVrfNotReady`
    /// variant downstream.
    pub(crate) fn snapshot_for(
        &self,
        vrf_device: &str,
        l3vxlan_device: &str,
    ) -> IpVrfKernelSnapshot {
        IpVrfKernelSnapshot {
            vrf: self.vrfs.get(vrf_device).copied(),
            l3vxlan: self.l3vxlans.get(l3vxlan_device).copied(),
        }
    }

    /// Number of VRF observations captured. Exposed for telemetry /
    /// diagnostics; not used by the readiness probe.
    pub(crate) fn vrf_count(&self) -> usize {
        self.vrfs.len()
    }

    /// Number of VXLAN observations captured (both L2 and L3 — the
    /// reconciler decides which ones matter by name lookup).
    pub(crate) fn vxlan_count(&self) -> usize {
        self.l3vxlans.len()
    }
}

/// Walk every netlink-reported link and pick out VRF + VXLAN devices.
///
/// Returns observations keyed by `IFLA_IFNAME`. Empty when no
/// VRF/VXLAN devices exist on the host (a host with only L2 bridges
/// and no L3 configuration still legitimately reaches this code path
/// — Gate 9 is opt-in via `[[evpn_ip_vrfs]]`).
///
/// # Errors
///
/// Returns [`DataplaneError::Other`] if the underlying rtnetlink
/// `link().get()` stream yields an error. The reconciler treats this
/// as "do not advance readiness state" and retries on the next pass.
pub(crate) async fn dump_ip_vrf_observations(
    handle: &Handle,
) -> Result<IpVrfObservations, DataplaneError> {
    let mut out = IpVrfObservations::default();
    let mut stream = handle.link().get().execute();
    while let Some(msg) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("ip-vrf link dump: {e}")))?
    {
        ingest_link_message(&msg, &mut out);
    }
    Ok(out)
}

/// Classify one `LinkMessage` and, if it is a VRF or VXLAN, record
/// the appropriate observation. Public-in-crate so the test module
/// can drive it against synthesized messages without a kernel.
pub(crate) fn ingest_link_message(msg: &LinkMessage, out: &mut IpVrfObservations) {
    let Parsed {
        name,
        kind,
        data,
        master,
        mac,
    } = parse_link_message(msg);

    let Some(name) = name else { return };
    let up = msg.header.flags.contains(LinkFlags::Up);
    let ifindex = msg.header.index;

    match (kind, data) {
        (Some(InfoKind::Vrf), data) => {
            // Take the first IFLA_VRF_TABLE the kernel emits. A VRF
            // device that omits the attribute is malformed — we record
            // `table_id = 0` so the probe surfaces an explicit
            // VrfTableIdMismatch rather than silently dropping the
            // observation.
            let table_id = match data {
                Some(InfoData::Vrf(items)) => items
                    .iter()
                    .find_map(|item| match item {
                        InfoVrf::TableId(id) => Some(*id),
                        _ => None,
                    })
                    .unwrap_or(0),
                _ => 0,
            };
            out.vrfs.insert(
                name,
                VrfObservation {
                    ifindex,
                    up,
                    table_id,
                },
            );
        }
        (Some(InfoKind::Vxlan), data) => {
            let (vni, local_vtep_ip) = match data {
                Some(InfoData::Vxlan(items)) => extract_vxlan_fields(&items),
                _ => (0, None),
            };
            out.l3vxlans.insert(
                name,
                L3VxlanObservation {
                    ifindex,
                    up,
                    vni,
                    local_vtep_ip,
                    master_ifindex: master,
                    mac,
                },
            );
        }
        _ => {}
    }
}

struct Parsed {
    name: Option<String>,
    kind: Option<InfoKind>,
    data: Option<InfoData>,
    master: Option<u32>,
    mac: Option<MacAddress>,
}

fn parse_link_message(msg: &LinkMessage) -> Parsed {
    let mut parsed = Parsed {
        name: None,
        kind: None,
        data: None,
        master: None,
        mac: None,
    };
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::IfName(n) => parsed.name = Some(n.clone()),
            LinkAttribute::Controller(idx) => parsed.master = Some(*idx),
            LinkAttribute::Address(bytes) => {
                if let Ok(arr) = <[u8; 6]>::try_from(bytes.as_slice()) {
                    parsed.mac = Some(MacAddress::new(arr));
                }
            }
            LinkAttribute::LinkInfo(infos) => {
                for info in infos {
                    match info {
                        LinkInfo::Kind(k) => parsed.kind = Some(k.clone()),
                        LinkInfo::Data(d) => parsed.data = Some(d.clone()),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    parsed
}

fn extract_vxlan_fields(items: &[InfoVxlan]) -> (u32, Option<IpAddr>) {
    let mut vni: u32 = 0;
    let mut local: Option<IpAddr> = None;
    for item in items {
        match item {
            InfoVxlan::Id(v) => vni = *v,
            InfoVxlan::Local(addr) => local = Some(IpAddr::V4(*addr)),
            InfoVxlan::Local6(addr) => local = Some(IpAddr::V6(*addr)),
            _ => {}
        }
    }
    (vni, local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::link::{LinkHeader, LinkMessage};

    fn vrf_msg(
        ifindex: u32,
        name: &str,
        up: bool,
        table_id_attr: Option<u32>,
        mac: Option<[u8; 6]>,
    ) -> LinkMessage {
        let header = LinkHeader {
            index: ifindex,
            flags: if up {
                LinkFlags::Up
            } else {
                LinkFlags::empty()
            },
            ..LinkHeader::default()
        };
        let mut msg = LinkMessage::default();
        msg.header = header;
        msg.attributes.push(LinkAttribute::IfName(name.to_string()));
        if let Some(bytes) = mac {
            msg.attributes.push(LinkAttribute::Address(bytes.to_vec()));
        }
        let mut infos: Vec<LinkInfo> = vec![LinkInfo::Kind(InfoKind::Vrf)];
        if let Some(t) = table_id_attr {
            infos.push(LinkInfo::Data(InfoData::Vrf(vec![InfoVrf::TableId(t)])));
        }
        msg.attributes.push(LinkAttribute::LinkInfo(infos));
        msg
    }

    fn vxlan_msg(
        ifindex: u32,
        name: &str,
        up: bool,
        vni: Option<u32>,
        local: Option<IpAddr>,
        master: Option<u32>,
        mac: Option<[u8; 6]>,
    ) -> LinkMessage {
        let header = LinkHeader {
            index: ifindex,
            flags: if up {
                LinkFlags::Up
            } else {
                LinkFlags::empty()
            },
            ..LinkHeader::default()
        };
        let mut msg = LinkMessage::default();
        msg.header = header;
        msg.attributes.push(LinkAttribute::IfName(name.to_string()));
        if let Some(m) = master {
            msg.attributes.push(LinkAttribute::Controller(m));
        }
        if let Some(bytes) = mac {
            msg.attributes.push(LinkAttribute::Address(bytes.to_vec()));
        }
        let mut data_items: Vec<InfoVxlan> = Vec::new();
        if let Some(v) = vni {
            data_items.push(InfoVxlan::Id(v));
        }
        if let Some(IpAddr::V4(v4)) = local {
            data_items.push(InfoVxlan::Local(v4));
        }
        if let Some(IpAddr::V6(v6)) = local {
            data_items.push(InfoVxlan::Local6(v6));
        }
        let infos = vec![
            LinkInfo::Kind(InfoKind::Vxlan),
            LinkInfo::Data(InfoData::Vxlan(data_items)),
        ];
        msg.attributes.push(LinkAttribute::LinkInfo(infos));
        msg
    }

    #[test]
    fn vrf_message_yields_observation_with_table_id_and_up_flag() {
        let mut out = IpVrfObservations::default();
        ingest_link_message(
            &vrf_msg(
                11,
                "vrf-blue",
                /*up=*/ true,
                Some(5000),
                Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ),
            &mut out,
        );
        let obs = out
            .vrfs
            .get("vrf-blue")
            .copied()
            .expect("vrf-blue observation");
        assert_eq!(obs.ifindex, 11);
        assert!(obs.up);
        assert_eq!(obs.table_id, 5000);
        // A VRF observation doesn't carry a MAC — the predicate uses
        // the L3 VXLAN's MAC for the Router MAC check.
        assert_eq!(out.l3vxlans.len(), 0);
    }

    #[test]
    fn vrf_without_iff_up_flag_is_reported_as_down() {
        let mut out = IpVrfObservations::default();
        ingest_link_message(
            &vrf_msg(11, "vrf-blue", /*up=*/ false, Some(5000), None),
            &mut out,
        );
        let obs = out.vrfs.get("vrf-blue").copied().expect("observation");
        assert!(!obs.up);
    }

    #[test]
    fn vrf_without_table_id_attribute_records_table_zero() {
        // Probe should then report VrfTableIdMismatch{observed:0,…}
        // instead of treating the malformed device as "no VRF".
        let mut out = IpVrfObservations::default();
        ingest_link_message(
            &vrf_msg(11, "vrf-blue", true, /*table_id_attr=*/ None, None),
            &mut out,
        );
        let obs = out.vrfs.get("vrf-blue").copied().expect("observation");
        assert_eq!(obs.table_id, 0);
    }

    #[test]
    fn vxlan_message_yields_observation_with_vni_local_master_mac() {
        let local = IpAddr::V4("10.0.0.1".parse().unwrap());
        let mut out = IpVrfObservations::default();
        ingest_link_message(
            &vxlan_msg(
                12,
                "vni5000",
                true,
                Some(5000),
                Some(local),
                Some(11),
                Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ),
            &mut out,
        );
        let obs = out.l3vxlans.get("vni5000").copied().expect("observation");
        assert_eq!(obs.ifindex, 12);
        assert!(obs.up);
        assert_eq!(obs.vni, 5000);
        assert_eq!(obs.local_vtep_ip, Some(local));
        assert_eq!(obs.master_ifindex, Some(11));
        assert_eq!(
            obs.mac,
            Some(MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
        );
    }

    #[test]
    fn vxlan_without_local_attribute_reports_no_local_vtep() {
        let mut out = IpVrfObservations::default();
        ingest_link_message(
            &vxlan_msg(12, "vni5000", true, Some(5000), None, Some(11), None),
            &mut out,
        );
        let obs = out.l3vxlans.get("vni5000").copied().expect("observation");
        assert_eq!(obs.local_vtep_ip, None);
        assert_eq!(obs.mac, None);
    }

    #[test]
    fn vxlan_with_ipv6_local_records_v6_variant() {
        let local = IpAddr::V6("2001:db8::1".parse().unwrap());
        let mut out = IpVrfObservations::default();
        ingest_link_message(
            &vxlan_msg(12, "vni5000", true, Some(5000), Some(local), Some(11), None),
            &mut out,
        );
        let obs = out.l3vxlans.get("vni5000").copied().expect("observation");
        assert_eq!(obs.local_vtep_ip, Some(local));
    }

    #[test]
    fn vxlan_without_master_attribute_records_none_master() {
        let mut out = IpVrfObservations::default();
        ingest_link_message(
            &vxlan_msg(
                12,
                "vni5000",
                true,
                Some(5000),
                None,
                /*master=*/ None,
                None,
            ),
            &mut out,
        );
        let obs = out.l3vxlans.get("vni5000").copied().expect("observation");
        assert_eq!(obs.master_ifindex, None);
    }

    #[test]
    fn unrelated_link_kinds_are_ignored() {
        // A bridge or dummy link must not appear in either map. Only
        // VRF and VXLAN kinds are captured by this dump.
        let mut msg = LinkMessage::default();
        msg.header.index = 99;
        msg.attributes
            .push(LinkAttribute::IfName("br0".to_string()));
        msg.attributes
            .push(LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
                InfoKind::Bridge,
            )]));
        let mut out = IpVrfObservations::default();
        ingest_link_message(&msg, &mut out);
        assert_eq!(out.vrfs.len(), 0);
        assert_eq!(out.l3vxlans.len(), 0);
    }

    #[test]
    fn snapshot_for_returns_none_sides_when_devices_missing() {
        let out = IpVrfObservations::default();
        let snap = out.snapshot_for("vrf-blue", "vni5000");
        assert!(snap.vrf.is_none());
        assert!(snap.l3vxlan.is_none());
    }

    #[test]
    fn snapshot_for_returns_observations_when_both_devices_present() {
        let local = IpAddr::V4("10.0.0.1".parse().unwrap());
        let mut out = IpVrfObservations::default();
        ingest_link_message(&vrf_msg(11, "vrf-blue", true, Some(5000), None), &mut out);
        ingest_link_message(
            &vxlan_msg(
                12,
                "vni5000",
                true,
                Some(5000),
                Some(local),
                Some(11),
                Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ),
            &mut out,
        );
        let snap = out.snapshot_for("vrf-blue", "vni5000");
        let v = snap.vrf.expect("vrf side");
        let l = snap.l3vxlan.expect("l3vxlan side");
        assert_eq!(v.ifindex, 11);
        assert_eq!(l.ifindex, 12);
        assert_eq!(l.master_ifindex, Some(11));
    }

    #[test]
    fn snapshot_for_picks_up_only_the_named_devices() {
        // Two configured IP-VRFs in the same dump — name lookup must
        // route each to its own snapshot.
        let mut out = IpVrfObservations::default();
        ingest_link_message(&vrf_msg(11, "vrf-blue", true, Some(5000), None), &mut out);
        ingest_link_message(&vrf_msg(21, "vrf-red", true, Some(6000), None), &mut out);
        ingest_link_message(
            &vxlan_msg(12, "vni5000", true, Some(5000), None, Some(11), None),
            &mut out,
        );
        ingest_link_message(
            &vxlan_msg(22, "vni6000", true, Some(6000), None, Some(21), None),
            &mut out,
        );

        let blue = out.snapshot_for("vrf-blue", "vni5000");
        let red = out.snapshot_for("vrf-red", "vni6000");
        assert_eq!(blue.vrf.unwrap().ifindex, 11);
        assert_eq!(blue.l3vxlan.unwrap().ifindex, 12);
        assert_eq!(red.vrf.unwrap().ifindex, 21);
        assert_eq!(red.l3vxlan.unwrap().ifindex, 22);
    }

    #[test]
    fn snapshot_with_mismatched_pair_keeps_both_observations_intact() {
        // Operator points l3vxlan_device at vni6000 but the configured
        // vrf_device is vrf-blue. The observation layer doesn't care
        // — it just composes by name. The probe is what decides the
        // master-ifindex mismatch downstream.
        let mut out = IpVrfObservations::default();
        ingest_link_message(&vrf_msg(11, "vrf-blue", true, Some(5000), None), &mut out);
        ingest_link_message(
            &vxlan_msg(
                22,
                "vni6000",
                true,
                Some(6000),
                None,
                /*master=*/ Some(21),
                None,
            ),
            &mut out,
        );
        let snap = out.snapshot_for("vrf-blue", "vni6000");
        assert_eq!(snap.vrf.unwrap().ifindex, 11);
        assert_eq!(snap.l3vxlan.unwrap().master_ifindex, Some(21));
        // The probe (not this layer) will surface L3VxlanNotInVrf
        // because master=21 != configured vrf_ifindex=11.
    }
}
