//! Real Linux netlink dataplane implementation — Gate 7b phase 4 scaffold.
//!
//! Phase 4 (this commit's scope) lays down the cfg-gated module
//! structure and an honest-stub [`LinuxDataplane`] that:
//!
//! - opens *no* netlink socket (so loading the binary on a host without
//!   `CAP_NET_ADMIN` is harmless),
//! - reports every configured EVPN instance as `NotReady` with a
//!   "phase 4 stub" reason string,
//! - returns an empty [`KernelSnapshot`] from `dump_snapshot`,
//! - never produces a `KernelEvent`,
//! - rejects every `apply()` call with [`DataplaneError::Other`]
//!   indicating the netlink path is not yet wired.
//!
//! This shape exists to let the daemon wiring (Phase 5) compile and
//! run end-to-end against a real binary. The reconcile actor's
//! foreign-entry-preservation and shutdown-drain semantics are the
//! same against the stub as against a real kernel impl, so Phase 5's
//! integration tests cover the wiring even when the stub is the
//! actual dataplane.
//!
//! ## Phase 4 follow-up TODO
//!
//! When the real netlink work lands, this module gains:
//!
//! - `links.rs` — bridge + VXLAN inventory via `rtnetlink`'s
//!   `LinkHandle::get` filtered to bridges and VXLAN port types.
//!   Builds [`crate::KernelLinkInfo`] entries.
//! - `fdb.rs` — FDB dump and program/withdraw via `RTM_NEWNEIGH` /
//!   `RTM_DELNEIGH` with `NDA_LLADDR`, `NDA_DST`, `NDA_VLAN`,
//!   `NTF_EXT_LEARNED`, `NTF_MASTER`. Uses the bridge/master path so
//!   switchdev-capable drivers can offload.
//! - `notify.rs` — netlink event subscription on `RTNLGRP_LINK`,
//!   `RTNLGRP_NEIGH`, `RTNLGRP_NOTIFY`. Applies the ADR-0054 §6
//!   startup buffering rule: subscribe → buffer → dump → replay
//!   buffer onto dump → first reconcile.
//! - `probe.rs` — per-instance readiness checks: bridge exists,
//!   exactly one VXLAN port for VNI, local IP matches,
//!   `nolearning` set, *not* VLAN-aware (rejected per ADR-0054 §4).
//! - kernel-too-old detection: try setting `NTF_EXT_LEARNED` on a
//!   probe entry; if it fails with `EINVAL` fall back to `NTF_MASTER`-
//!   only and surface `NotReady` with "kernel too old".
//!
//! Tracked dependencies:
//!
//! ```toml
//! [target.'cfg(target_os = "linux")'.dependencies]
//! rtnetlink = "0.21"
//! netlink-packet-route = "0.30"
//! netlink-packet-utils = "0.6"
//! netlink-sys = "0.8"
//! ```
//!
//! And a privileged netns integration test at
//! `tests/netns_dataplane.rs`, gated behind `EVPN_LINUX_NETNS=1` so
//! PR-CI without `CAP_NET_ADMIN` skips it cleanly.
//!
//! ## Reference
//!
//! - ADR-0054 §3 (kernel observation surface)
//! - ADR-0054 §4 (FDB-only first slice)
//! - ADR-0054 §5 (local observed, remote programmed)

use rustbgpd_evpn::EvpnInstanceTable;

use crate::dataplane::{Dataplane, DataplaneOp, KernelEvent};
use crate::error::DataplaneError;
use crate::snapshot::{InstanceProbe, InstanceProbes, KernelSnapshot};

/// Linux-only dataplane impl. Gate 7b ships an honest stub that
/// reports every instance `NotReady`; the real netlink integration is
/// queued for a follow-up commit on the same feature branch.
pub struct LinuxDataplane {
    /// Reserved for the netlink connection task once real impl lands.
    /// Carrying the field now keeps the public type stable across the
    /// stub→real transition.
    _placeholder: (),
}

impl LinuxDataplane {
    /// Construct the stub. No netlink sockets are opened. This will
    /// gain a `Result<Self, DataplaneError>` return and real
    /// initialization (subscribe → buffer → dump → replay) when the
    /// kernel slice lands.
    #[must_use]
    pub fn new() -> Self {
        Self { _placeholder: () }
    }
}

impl Default for LinuxDataplane {
    fn default() -> Self {
        Self::new()
    }
}

const STUB_REASON: &str = "phase 4 stub: real netlink integration not yet wired";

impl Dataplane for LinuxDataplane {
    fn probe(
        &mut self,
        instances: &EvpnInstanceTable,
    ) -> impl Future<Output = InstanceProbes> + Send {
        let mut probes = InstanceProbes::new();
        for inst in instances.iter() {
            let probe = if inst.bridge.is_none() {
                InstanceProbe::Unbound
            } else {
                InstanceProbe::NotReady {
                    reason: STUB_REASON.to_owned(),
                }
            };
            probes.insert(inst.id, probe);
        }
        async move { probes }
    }

    async fn dump_snapshot(&mut self) -> Result<KernelSnapshot, DataplaneError> {
        Ok(KernelSnapshot::new())
    }

    async fn apply(&mut self, _op: &DataplaneOp) -> Result<(), DataplaneError> {
        Err(DataplaneError::Other(STUB_REASON.to_owned()))
    }

    fn next_event(&mut self) -> impl Future<Output = Option<KernelEvent>> + Send {
        // Stub never produces events; the actor falls back to its
        // periodic dump cadence + retry timer. Returning a future
        // that pends forever lets `tokio::select!` ignore this branch
        // until a real impl arrives.
        std::future::pending()
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use rustbgpd_evpn::{
        EvpnInstance, EvpnInstanceId, EvpnInstanceTable, MacAddress, RouteDistinguisher,
        RouteTarget,
    };

    use super::*;
    use crate::dataplane::DataplaneOp;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn ipa(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn instance_with_bridge(v: u32, bridge: Option<&str>) -> EvpnInstance {
        let mut bytes = [0u8; 8];
        bytes[2..4].copy_from_slice(&65001u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&v.to_be_bytes());
        EvpnInstance::new(
            vni(v),
            RouteDistinguisher::new(bytes),
            vec![RouteTarget::TwoOctetAs {
                asn: 65001,
                value: v,
            }],
            ipa("10.0.0.1"),
            bridge.map(String::from),
            false,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn stub_reports_unbound_for_no_bridge() {
        let mut dp = LinuxDataplane::new();
        let mut table = EvpnInstanceTable::new();
        table.insert(instance_with_bridge(100, None)).unwrap();
        let probes = dp.probe(&table).await;
        assert!(matches!(probes.get(vni(100)), Some(InstanceProbe::Unbound)));
    }

    #[tokio::test]
    async fn stub_reports_not_ready_for_bridge_bound_instance() {
        let mut dp = LinuxDataplane::new();
        let mut table = EvpnInstanceTable::new();
        table
            .insert(instance_with_bridge(200, Some("br200")))
            .unwrap();
        let probes = dp.probe(&table).await;
        match probes.get(vni(200)) {
            Some(InstanceProbe::NotReady { reason }) => {
                assert!(reason.contains("phase 4 stub"));
            }
            other => panic!("unexpected probe: {other:?}"),
        }
    }

    #[tokio::test]
    async fn stub_dump_returns_empty_snapshot() {
        let mut dp = LinuxDataplane::new();
        let snap = dp.dump_snapshot().await.unwrap();
        assert_eq!(snap.fdb_len(), 0);
    }

    #[tokio::test]
    async fn stub_apply_always_errors() {
        let mut dp = LinuxDataplane::new();
        let op = DataplaneOp::AddRemoteFdb {
            vni: vni(100),
            mac: MacAddress::new([1; 6]),
            dst: ipa("10.0.0.2"),
        };
        let err = dp.apply(&op).await.unwrap_err();
        assert!(matches!(err, DataplaneError::Other(_)));
    }
}
