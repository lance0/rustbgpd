//! Pure-logic IP-VRF readiness probe (Gate 9, ADR-0058 §3 + §7).
//!
//! Maps a portable [`IpVrfKernelSnapshot`] (built by the
//! `crates/evpn-linux` reconciler from rtnetlink dumps in a later
//! slice — kernel-free in this layer) against an [`IpVrf`] config and
//! returns an [`IpVrfStatus`] verdict. The seven predicates from
//! ADR-0058 §3 are checked exhaustively so every `NotReady` result
//! names *every* failing condition, not just the first.
//!
//! ## Why pure
//!
//! The same separation ADR-0054 imposes for L2: the daemon decides,
//! the Linux layer observes. Keeping the probe in `crates/evpn`
//! means it is unit-testable against synthesized snapshots — no
//! netlink, no privileged runners, no containerlab. The
//! corresponding netlink-reading code lives in
//! `crates/evpn-linux` and produces an
//! [`IpVrfKernelSnapshot`] per configured IP-VRF on every
//! reconcile pass; this function consumes it.
//!
//! ## Coverage
//!
//! Every predicate in ADR-0058 §3 maps 1:1 to an
//! [`IpVrfNotReady`] variant:
//!
//! | # | Predicate | NotReady variant |
//! |---|-----------|------------------|
//! | 1 | `vrf_device` exists | `VrfDeviceMissing` |
//! | 1 | `vrf_device` state UP | `VrfDeviceDown` |
//! | 2 | `vrf_device.IFLA_VRF_TABLE == table_id` | `VrfTableIdMismatch` |
//! | 3 | `l3vxlan_device` exists | `L3VxlanMissing` |
//! | 3 | `l3vxlan_device` state UP | `L3VxlanDown` |
//! | 4 | `l3vxlan_device.IFLA_VXLAN_ID == vni` | `L3VxlanVniMismatch` |
//! | 5 | `l3vxlan_device.IFLA_VXLAN_LOCAL == local_vtep_ip` | `L3VxlanLocalMismatch` |
//! | 6 | `l3vxlan_device.IFLA_MASTER == vrf_device.ifindex` | `L3VxlanNotInVrf` |
//! | 7 | `l3vxlan_device.address == router_mac` | `RouterMacMismatch` |

use std::net::IpAddr;

use rustbgpd_wire::MacAddress;

use crate::ip_vrf::IpVrf;

/// Portable snapshot of kernel state for one IP-VRF, built by the
/// `crates/evpn-linux` reconciler from rtnetlink. Holds two
/// independent observations: the configured-named VRF device, and
/// the configured-named L3VXLAN device. Each is `None` when the
/// kernel did not return a link with that name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpVrfKernelSnapshot {
    /// Observation of the configured `vrf_device`, or `None` if the
    /// kernel didn't return one with that name.
    pub vrf: Option<VrfObservation>,
    /// Observation of the configured `l3vxlan_device`, or `None` if
    /// the kernel didn't return one with that name.
    pub l3vxlan: Option<L3VxlanObservation>,
}

/// Kernel-observed state of a VRF device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfObservation {
    /// Kernel ifindex of the VRF device.
    pub ifindex: u32,
    /// `state UP` (true) or any of DOWN / DORMANT / etc. (false).
    pub up: bool,
    /// VRF route table id from `IFLA_VRF_TABLE`.
    pub table_id: u32,
}

/// Kernel-observed state of an L3 VXLAN device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L3VxlanObservation {
    /// Kernel ifindex of the L3 VXLAN device.
    pub ifindex: u32,
    /// `state UP` (true) or any of DOWN / DORMANT / etc. (false).
    pub up: bool,
    /// VXLAN VNI from `IFLA_VXLAN_ID`.
    pub vni: u32,
    /// Local VTEP IP from `IFLA_VXLAN_LOCAL` (IPv4) or
    /// `IFLA_VXLAN_LOCAL6` (IPv6). `None` if neither attribute
    /// was reported.
    pub local_vtep_ip: Option<IpAddr>,
    /// Master ifindex (`IFLA_MASTER`). `None` if the device isn't
    /// enslaved to anything.
    pub master_ifindex: Option<u32>,
    /// Link-layer (MAC) address of the L3VXLAN device — the value
    /// the kernel will put as the inner destination MAC on
    /// recursive lookup. Asserted against the configured Router
    /// MAC per ADR-0058 §4.
    pub mac: Option<MacAddress>,
}

/// Result of evaluating an IP-VRF against its kernel snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpVrfStatus {
    /// All seven §3 predicates hold; the daemon may originate
    /// Type 5 from this IP-VRF and install remote Type 5 into it.
    Ready {
        vrf_ifindex: u32,
        l3vxlan_ifindex: u32,
        table_id: u32,
        router_mac: MacAddress,
    },
    /// At least one predicate failed. Every failing predicate is
    /// reported so an operator's `--json` view can render the full
    /// list, not just the first one tripped.
    NotReady { reasons: Vec<IpVrfNotReady> },
}

impl IpVrfStatus {
    /// `true` when the status is `Ready`.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    /// Iterate the failing predicates, or an empty slice when ready.
    #[must_use]
    pub fn reasons(&self) -> &[IpVrfNotReady] {
        match self {
            Self::Ready { .. } => &[],
            Self::NotReady { reasons } => reasons,
        }
    }
}

/// One failing readiness predicate. Variants map 1:1 to ADR-0058 §3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpVrfNotReady {
    /// Configured `vrf_device` wasn't found in the kernel snapshot.
    VrfDeviceMissing,
    /// VRF device exists but is not `state UP`.
    VrfDeviceDown,
    /// `IFLA_VRF_TABLE` value disagrees with the configured `table_id`.
    VrfTableIdMismatch { observed: u32, configured: u32 },
    /// Configured `l3vxlan_device` wasn't found in the kernel snapshot.
    L3VxlanMissing,
    /// L3VXLAN device exists but is not `state UP`.
    L3VxlanDown,
    /// `IFLA_VXLAN_ID` value disagrees with the configured `vni`.
    L3VxlanVniMismatch { observed: u32, configured: u32 },
    /// `IFLA_VXLAN_LOCAL` value disagrees with the configured
    /// `local_vtep_ip`. `None` when the kernel didn't report any
    /// local address on the L3VXLAN device.
    L3VxlanLocalMismatch {
        observed: Option<IpAddr>,
        configured: IpAddr,
    },
    /// L3VXLAN is enslaved to a different device than the configured
    /// `vrf_device`, or not enslaved at all.
    L3VxlanNotInVrf {
        observed_master: Option<u32>,
        expected_master: u32,
    },
    /// L3VXLAN device's MAC disagrees with the configured `router_mac`.
    /// `None` when the kernel didn't report a MAC.
    RouterMacMismatch {
        observed: Option<MacAddress>,
        configured: MacAddress,
    },
}

/// Run the seven predicates and return the verdict.
///
/// Pure: no I/O, no allocation beyond the [`IpVrfNotReady`] vector
/// when the status is `NotReady`. The result is deterministic for
/// any fixed `(vrf, snapshot)` pair.
#[must_use]
pub fn probe(vrf: &IpVrf, snapshot: &IpVrfKernelSnapshot) -> IpVrfStatus {
    let mut reasons: Vec<IpVrfNotReady> = Vec::new();

    // VRF-device predicates (§3.1–§3.2).
    let vrf_obs = snapshot.vrf;
    if vrf_obs.is_none() {
        reasons.push(IpVrfNotReady::VrfDeviceMissing);
    }
    if let Some(v) = vrf_obs {
        if !v.up {
            reasons.push(IpVrfNotReady::VrfDeviceDown);
        }
        if v.table_id != vrf.table_id {
            reasons.push(IpVrfNotReady::VrfTableIdMismatch {
                observed: v.table_id,
                configured: vrf.table_id,
            });
        }
    }

    // L3VXLAN-device predicates (§3.3–§3.7).
    let l3_obs = snapshot.l3vxlan;
    if l3_obs.is_none() {
        reasons.push(IpVrfNotReady::L3VxlanMissing);
    }
    if let Some(l) = l3_obs {
        if !l.up {
            reasons.push(IpVrfNotReady::L3VxlanDown);
        }
        if l.vni != vrf.id.as_u32() {
            reasons.push(IpVrfNotReady::L3VxlanVniMismatch {
                observed: l.vni,
                configured: vrf.id.as_u32(),
            });
        }
        if l.local_vtep_ip != Some(vrf.local_vtep_ip) {
            reasons.push(IpVrfNotReady::L3VxlanLocalMismatch {
                observed: l.local_vtep_ip,
                configured: vrf.local_vtep_ip,
            });
        }
        // §3.6: must be enslaved to the configured VRF device. We can
        // only assert this when we observed the VRF (otherwise we
        // don't have its ifindex to compare against). When the VRF
        // is missing, that fact is already reported via
        // VrfDeviceMissing and we skip the slave check to avoid a
        // duplicate "master is None" complaint with no useful info.
        if let Some(v) = vrf_obs
            && l.master_ifindex != Some(v.ifindex)
        {
            reasons.push(IpVrfNotReady::L3VxlanNotInVrf {
                observed_master: l.master_ifindex,
                expected_master: v.ifindex,
            });
        }
        if l.mac != Some(vrf.router_mac) {
            reasons.push(IpVrfNotReady::RouterMacMismatch {
                observed: l.mac,
                configured: vrf.router_mac,
            });
        }
    }

    if reasons.is_empty() {
        // Both observations are `Some` here — `reasons` would be
        // non-empty otherwise.
        let (Some(v), Some(l)) = (vrf_obs, l3_obs) else {
            // Defense-in-depth: the predicates above already handle
            // both `None` cases, but if a future refactor breaks
            // that invariant, fall through to NotReady with a
            // synthetic reason instead of unwrapping.
            return IpVrfStatus::NotReady {
                reasons: vec![IpVrfNotReady::VrfDeviceMissing],
            };
        };
        IpVrfStatus::Ready {
            vrf_ifindex: v.ifindex,
            l3vxlan_ifindex: l.ifindex,
            table_id: v.table_id,
            router_mac: vrf.router_mac,
        }
    } else {
        IpVrfStatus::NotReady { reasons }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_vrf::IpVrfId;
    use rustbgpd_wire::RouteDistinguisher;

    fn router_mac() -> MacAddress {
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    }

    fn vrf() -> IpVrf {
        IpVrf::new(
            "tenant-blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            "65000:5000".parse::<RouteDistinguisher>().unwrap(),
            vec!["65000:5000".parse().unwrap()],
            "10.0.0.1".parse().unwrap(),
            router_mac(),
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap()
    }

    fn happy_snapshot() -> IpVrfKernelSnapshot {
        IpVrfKernelSnapshot {
            vrf: Some(VrfObservation {
                ifindex: 11,
                up: true,
                table_id: 5000,
            }),
            l3vxlan: Some(L3VxlanObservation {
                ifindex: 12,
                up: true,
                vni: 5000,
                local_vtep_ip: Some("10.0.0.1".parse().unwrap()),
                master_ifindex: Some(11),
                mac: Some(router_mac()),
            }),
        }
    }

    #[test]
    fn ready_when_all_predicates_hold() {
        let status = probe(&vrf(), &happy_snapshot());
        assert!(status.is_ready());
        let IpVrfStatus::Ready {
            vrf_ifindex,
            l3vxlan_ifindex,
            table_id,
            router_mac: mac,
        } = status
        else {
            panic!("expected Ready");
        };
        assert_eq!(vrf_ifindex, 11);
        assert_eq!(l3vxlan_ifindex, 12);
        assert_eq!(table_id, 5000);
        assert_eq!(mac, router_mac());
    }

    #[test]
    fn both_device_missing_predicates_reported_when_neither_observed() {
        let snap = IpVrfKernelSnapshot {
            vrf: None,
            l3vxlan: None,
        };
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.contains(&IpVrfNotReady::VrfDeviceMissing));
        assert!(reasons.contains(&IpVrfNotReady::L3VxlanMissing));
        // No NotInVrf or RouterMacMismatch when L3VXLAN is missing.
        assert!(!reasons.iter().any(|r| matches!(
            r,
            IpVrfNotReady::L3VxlanNotInVrf { .. } | IpVrfNotReady::RouterMacMismatch { .. }
        )));
    }

    #[test]
    fn vrf_down_is_reported() {
        let mut snap = happy_snapshot();
        snap.vrf.as_mut().unwrap().up = false;
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.contains(&IpVrfNotReady::VrfDeviceDown));
    }

    #[test]
    fn table_id_mismatch_is_reported() {
        let mut snap = happy_snapshot();
        snap.vrf.as_mut().unwrap().table_id = 9999;
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.contains(&IpVrfNotReady::VrfTableIdMismatch {
            observed: 9999,
            configured: 5000,
        }));
    }

    #[test]
    fn l3vxlan_down_is_reported() {
        let mut snap = happy_snapshot();
        snap.l3vxlan.as_mut().unwrap().up = false;
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.contains(&IpVrfNotReady::L3VxlanDown));
    }

    #[test]
    fn vni_mismatch_is_reported() {
        let mut snap = happy_snapshot();
        snap.l3vxlan.as_mut().unwrap().vni = 9999;
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.contains(&IpVrfNotReady::L3VxlanVniMismatch {
            observed: 9999,
            configured: 5000,
        }));
    }

    #[test]
    fn local_vtep_mismatch_is_reported_with_observed_value() {
        let mut snap = happy_snapshot();
        snap.l3vxlan.as_mut().unwrap().local_vtep_ip = Some("192.168.0.2".parse().unwrap());
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.iter().any(|r| matches!(
            r,
            IpVrfNotReady::L3VxlanLocalMismatch { observed: Some(o), configured: _ }
                if *o == "192.168.0.2".parse::<IpAddr>().unwrap()
        )));
    }

    #[test]
    fn local_vtep_missing_is_reported_with_none_observed() {
        let mut snap = happy_snapshot();
        snap.l3vxlan.as_mut().unwrap().local_vtep_ip = None;
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.iter().any(|r| matches!(
            r,
            IpVrfNotReady::L3VxlanLocalMismatch { observed: None, .. }
        )));
    }

    #[test]
    fn not_in_vrf_is_reported_when_master_wrong() {
        let mut snap = happy_snapshot();
        snap.l3vxlan.as_mut().unwrap().master_ifindex = Some(999);
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.iter().any(|r| matches!(
            r,
            IpVrfNotReady::L3VxlanNotInVrf {
                observed_master: Some(999),
                expected_master: 11
            }
        )));
    }

    #[test]
    fn not_in_vrf_is_reported_when_unenslaved() {
        let mut snap = happy_snapshot();
        snap.l3vxlan.as_mut().unwrap().master_ifindex = None;
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.iter().any(|r| matches!(
            r,
            IpVrfNotReady::L3VxlanNotInVrf {
                observed_master: None,
                ..
            }
        )));
    }

    #[test]
    fn router_mac_mismatch_is_reported() {
        let mut snap = happy_snapshot();
        snap.l3vxlan.as_mut().unwrap().mac =
            Some(MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.iter().any(|r| matches!(
            r,
            IpVrfNotReady::RouterMacMismatch {
                observed: Some(_),
                configured: _,
            }
        )));
    }

    #[test]
    fn every_failing_predicate_is_collected_not_just_the_first() {
        // Make every L3VXLAN-side predicate fail in one shot. The
        // VRF observation stays happy so we get a clean count of
        // L3VXLAN-side reasons.
        let mut snap = happy_snapshot();
        let l = snap.l3vxlan.as_mut().unwrap();
        l.up = false;
        l.vni = 0;
        l.local_vtep_ip = None;
        l.master_ifindex = None;
        l.mac = None;
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        // Five distinct L3VXLAN-side reasons.
        let expected: &[&dyn Fn(&IpVrfNotReady) -> bool] = &[
            &|r| matches!(r, IpVrfNotReady::L3VxlanDown),
            &|r| matches!(r, IpVrfNotReady::L3VxlanVniMismatch { .. }),
            &|r| matches!(r, IpVrfNotReady::L3VxlanLocalMismatch { .. }),
            &|r| matches!(r, IpVrfNotReady::L3VxlanNotInVrf { .. }),
            &|r| matches!(r, IpVrfNotReady::RouterMacMismatch { .. }),
        ];
        for predicate in expected {
            assert!(
                reasons.iter().any(predicate),
                "missing expected reason in {reasons:?}"
            );
        }
    }

    #[test]
    fn missing_vrf_skips_master_check_to_avoid_duplicate_complaint() {
        // VRF missing → we cannot know the expected master ifindex,
        // so the probe should NOT report L3VxlanNotInVrf with a
        // bogus expected_master. Only VrfDeviceMissing for the VRF
        // side, plus whatever the L3VXLAN side genuinely fails.
        let mut snap = happy_snapshot();
        snap.vrf = None;
        let reasons = probe(&vrf(), &snap).reasons().to_vec();
        assert!(reasons.contains(&IpVrfNotReady::VrfDeviceMissing));
        assert!(
            !reasons
                .iter()
                .any(|r| matches!(r, IpVrfNotReady::L3VxlanNotInVrf { .. })),
            "must not synthesize a NotInVrf when VRF is missing: {reasons:?}"
        );
    }

    #[test]
    fn is_ready_and_reasons_accessor_shapes() {
        let ready = probe(&vrf(), &happy_snapshot());
        assert!(ready.is_ready());
        assert!(ready.reasons().is_empty());

        let nr = probe(
            &vrf(),
            &IpVrfKernelSnapshot {
                vrf: None,
                l3vxlan: None,
            },
        );
        assert!(!nr.is_ready());
        assert!(!nr.reasons().is_empty());
    }
}
