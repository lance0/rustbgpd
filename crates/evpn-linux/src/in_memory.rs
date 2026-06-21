//! [`InMemoryDataplane`] — the test fake.
//!
//! Implements [`Dataplane`] without touching netlink. Phase 3's
//! reconcile actor tests drive this implementation end-to-end:
//!
//! - kernel state lives in a `Mutex<KernelSnapshot>` the test can
//!   pre-load with foreign entries before the actor starts;
//! - probes are static — set per-VNI in the constructor;
//! - apply writes to the snapshot if a matching `inject_failure` rule
//!   doesn't intercept;
//! - kernel events are pumped through an mpsc the test owns.
//!
//! This is the fake the `compute_diff` tests don't need (those are
//! pure), but Phase 3 will need to drive a complete actor lifecycle.

use std::collections::{BTreeMap, BTreeSet};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use rustbgpd_evpn::ip_vrf::{IpVrfId, IpVrfStatus, IpVrfTable};
use rustbgpd_evpn::{
    EvpnInstanceId, EvpnInstanceTable, EvpnIpPrefixValue, LocalMacObservation, MacAddress,
    parse_ownership_stamp,
};
use tokio::sync::mpsc;

use crate::dataplane::{
    Dataplane, DataplaneOp, KernelEvent, KernelNexthop, KernelNexthopKind, NexthopOps,
};
use crate::error::DataplaneError;
use crate::l3_adoption::{
    AdoptedL3Route, AdoptedL3VxlanFdb, AdoptedL3VxlanFdbTarget, L3AdoptionDump,
};
use crate::nh_id_alloc::NhIdAllocator;
use crate::snapshot::{
    InstanceProbe, InstanceProbes, KernelFdbEntry, KernelFdbFlags, KernelLinkInfo, KernelSnapshot,
    KernelVrfLinkInfo, KernelVxlanLinkInfo,
};

/// Test fake of [`Dataplane`].
///
/// All shared state lives behind one `Mutex` because the actor calls
/// trait methods serially — the lock is uncontended in the actor's
/// happy path. Tests drive concurrent state by holding their own
/// reference (via [`InMemoryDataplane::handle`]) and mutating
/// independently.
#[derive(Debug)]
pub struct InMemoryDataplane {
    state: Arc<Mutex<State>>,
    events_rx: mpsc::Receiver<KernelEvent>,
    events_tx: mpsc::Sender<KernelEvent>,
    /// Upward `LocalMacObservation` channel — handed to the daemon's
    /// originator via [`Dataplane::take_local_mac_rx`]. Held as
    /// `Option` so the take-once semantic surfaces cleanly: returns
    /// `Some(rx)` on the first call, `None` thereafter.
    local_mac_rx: Option<mpsc::Receiver<LocalMacObservation>>,
    /// Sender side — kept alive on the dataplane so the test handle's
    /// `inject_local_mac_observation` can publish even after the
    /// originator has taken the receiver.
    local_mac_tx: mpsc::Sender<LocalMacObservation>,
}

#[derive(Debug)]
struct State {
    kernel: KernelSnapshot,
    probes: InstanceProbes,
    /// Failure injection — popped FIFO. Each entry is consumed once
    /// per matching `apply` call; once the queue empties, applies
    /// succeed normally. Tests use this to validate the actor's
    /// retry-with-backoff path.
    failures: VecDeque<InjectedFailure>,
    /// Counter — total apply calls (including failed ones). Tests
    /// assert this against expectations.
    apply_count: usize,
    /// Recorded `SetBumPortFlags` calls keyed by ifindex. Tests use
    /// this to assert the reconciler issued the expected per-port
    /// flag triplet — the in-memory backend doesn't have a real
    /// kernel to inspect.
    bum_port_flags: std::collections::BTreeMap<u32, crate::bum_filter::BumPortFlags>,
    /// Recorded `SetAcPortState` calls keyed by ifindex (`true` =
    /// blocked / `BR_STATE_DISABLED`). Tests assert the reconciler
    /// gated the right AC ports; applies are also mirrored into the
    /// fake kernel's `bridge_ports` state.
    ac_port_states: std::collections::BTreeMap<u32, bool>,
    /// Recorded FDB nexthop state — tracks per-VTEP nexthops and
    /// groups installed via [`NexthopOps`]. ADR-0059 slice 3b's
    /// coordinator drives this; tests stage it pre-startup to
    /// exercise the adoption path.
    nexthop_ops: BTreeMap<u32, KernelNexthop>,
    /// Gate 9 L3 kernel route rows, keyed the way the kernel keys
    /// them: `(table_id, prefix)`. `apply` of `AddRemoteIpRoute` /
    /// `RemoveRemoteIpRoute` mutates this map (replace semantics on
    /// add, like the real `.replace()` path), and
    /// `dump_l3_adoption_candidates` reads it live — the ADR-0079
    /// reap re-check depends on the dump reflecting applies/removes
    /// since startup, not a frozen copy.
    l3_routes: BTreeMap<(u32, EvpnIpPrefixValue), InMemoryL3Route>,
    /// Gate 9 L3 neighbor rows keyed `(l3vxlan_ifindex, next_hop)`,
    /// mirroring the kernel's `(dev, dst)` neighbor key.
    l3_neighbors: BTreeMap<(u32, IpAddr), InMemoryL3Neighbor>,
    /// Gate 9 L3VXLAN FDB rows keyed `(l3vxlan_ifindex, router_mac)`,
    /// mirroring the kernel's `(dev, lladdr)` FDB key.
    l3_vxlan_fdb: BTreeMap<(u32, MacAddress), InMemoryL3VxlanFdb>,
    /// Per-IP-VRF readiness verdicts returned by `probe_ip_vrfs`,
    /// staged by tests via [`InMemoryHandle::set_ip_vrf_status`].
    /// VRFs without an entry are simply absent from the probe result
    /// (the actor synthesizes `NotReady` for them).
    ip_vrf_statuses: HashMap<IpVrfId, IpVrfStatus>,
    /// `vrf_id → l3vxlan_ifindex` "the device exists" map consulted
    /// by `dump_l3_adoption_candidates` — the fake's stand-in for the
    /// real impl's link-dump name resolution. Deliberately separate
    /// from `ip_vrf_statuses`: a device can resolve to an ifindex
    /// (so its neighbor/FDB rows are dump-visible) while the VRF as a
    /// whole is still `NotReady`, exactly like the kernel.
    l3vxlan_ifindexes: BTreeMap<IpVrfId, u32>,
    /// Pending `dump_l3_adoption_candidates` failures — each call
    /// consumes one and returns `None`, mirroring the apply-side
    /// FIFO injection. Tests use this to validate the "failed dump
    /// leaves the latch unset" path.
    l3_adoption_dump_failures: u32,
    /// Successful L3 `apply` calls in arrival order. The ADR-0079
    /// reap-order test asserts route → neighbor → FDB teardown
    /// sequencing, which no end-state map can capture.
    l3_op_log: Vec<DataplaneOp>,
}

/// One in-memory kernel route row (the value half of
/// `(table_id, prefix)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryL3Route {
    /// Output device.
    pub l3vxlan_ifindex: u32,
    /// Representative gateway kept for ADR-0079 scalar adoption and
    /// older tests. For ECMP rows this is the first canonical
    /// next-hop.
    pub next_hop: IpAddr,
    /// Full route target set.
    pub targets: InMemoryL3RouteTargets,
    /// True when the row carries the ADR-0079 marker pair
    /// (`proto bgp` + onlink). Rows written through `apply` are
    /// always marked — the real apply path always writes the markers
    /// — while `pre_load_l3_route` lets tests stage foreign rows.
    pub marked: bool,
}

/// In-memory route target shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InMemoryL3RouteTargets {
    /// Scalar route via one remote VTEP.
    Single { next_hop: IpAddr },
    /// Route-level ECMP over the L3VXLAN device.
    Ecmp { next_hops: Vec<IpAddr> },
}

impl InMemoryL3RouteTargets {
    fn representative_next_hop(&self) -> IpAddr {
        match self {
            Self::Single { next_hop } => *next_hop,
            Self::Ecmp { next_hops } => next_hops[0],
        }
    }
}

/// One in-memory L3 neighbor row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InMemoryL3Neighbor {
    /// Link-layer address the entry resolves to.
    pub router_mac: MacAddress,
    /// True when the row carries `NUD_PERMANENT` + `NTF_EXT_LEARNED`.
    pub marked: bool,
}

/// One in-memory L3VXLAN FDB row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryL3VxlanFdb {
    /// FDB target shape.
    pub target: InMemoryL3VxlanFdbTarget,
    /// True when the row carries the permanent `extern_learn` marker.
    pub marked: bool,
}

/// In-memory L3VXLAN FDB target shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InMemoryL3VxlanFdbTarget {
    /// Scalar `dst` row.
    SingleDst { next_hop: IpAddr },
    /// `nhid` row pointing at an FDB nexthop group.
    Nhg { nh_id: u32 },
}

#[derive(Debug, Clone)]
struct InjectedFailure {
    /// If `None`, fails the next apply regardless of op shape. If
    /// `Some`, fails only when applying matching ops.
    target: Option<DataplaneOp>,
    error: ErrorTemplate,
}

#[derive(Debug, Clone)]
enum ErrorTemplate {
    Io,
    Other(String),
    KernelTooOld,
}

impl ErrorTemplate {
    fn realize(&self) -> DataplaneError {
        match self {
            Self::Io => DataplaneError::Io(std::io::Error::other("injected I/O failure")),
            Self::Other(s) => DataplaneError::Other(s.clone()),
            Self::KernelTooOld => DataplaneError::KernelTooOld {
                feature: "injected feature".to_string(),
            },
        }
    }
}

impl InMemoryDataplane {
    /// Construct a fake with empty kernel state and no probes set.
    /// All instances default to `NotReady` until
    /// [`InMemoryHandle::set_probe`] records an explicit result.
    #[must_use]
    pub fn new() -> Self {
        let (events_tx, events_rx) = mpsc::channel(64);
        // 1024-slot upward observation buffer matches the bound the
        // originator advertises (see `src/evpn_originator.rs`); tests
        // can fill it to exercise overflow handling.
        let (local_mac_tx, local_mac_rx) = mpsc::channel(1024);
        Self {
            state: Arc::new(Mutex::new(State {
                nexthop_ops: BTreeMap::new(),
                kernel: KernelSnapshot::new(),
                probes: InstanceProbes::new(),
                failures: VecDeque::new(),
                apply_count: 0,
                bum_port_flags: std::collections::BTreeMap::new(),
                ac_port_states: std::collections::BTreeMap::new(),
                l3_routes: BTreeMap::new(),
                l3_neighbors: BTreeMap::new(),
                l3_vxlan_fdb: BTreeMap::new(),
                ip_vrf_statuses: HashMap::new(),
                l3vxlan_ifindexes: BTreeMap::new(),
                l3_adoption_dump_failures: 0,
                l3_op_log: Vec::new(),
            })),
            events_rx,
            events_tx,
            local_mac_rx: Some(local_mac_rx),
            local_mac_tx,
        }
    }

    /// Same shape as [`Self::new`] but with the kernel-event stream
    /// pre-closed: `next_event()` resolves to `None` on the first
    /// poll. Used by the reconcile-actor regression test that
    /// validates the "closed event stream" guard — without the
    /// guard, a biased `tokio::select!` arm whose future resolves
    /// to `None` immediately starves the periodic / retry / intent
    /// arms behind it.
    #[must_use]
    pub fn with_closed_event_stream() -> Self {
        let mut dp = Self::new();
        // Reassign `events_rx` to a fresh channel whose sender has
        // already been dropped — `recv()` then returns `None` on
        // the very next poll. The old `events_tx` (and any handle
        // clones) stays valid but talks to nobody, which is fine
        // for this regression test.
        let (closed_tx, closed_rx) = mpsc::channel::<KernelEvent>(1);
        drop(closed_tx);
        dp.events_rx = closed_rx;
        dp
    }

    /// Cloneable test handle for in-process state inspection /
    /// mutation. Tests typically grab a handle before the actor
    /// starts, then use it to pre-load kernel entries, set probes,
    /// inject failures, and assert apply counts.
    #[must_use]
    pub fn handle(&self) -> InMemoryHandle {
        InMemoryHandle {
            state: Arc::clone(&self.state),
            events_tx: self.events_tx.clone(),
            local_mac_tx: self.local_mac_tx.clone(),
        }
    }
}

impl Default for InMemoryDataplane {
    fn default() -> Self {
        Self::new()
    }
}

impl Dataplane for InMemoryDataplane {
    fn probe(
        &mut self,
        _instances: &EvpnInstanceTable,
    ) -> impl Future<Output = InstanceProbes> + Send {
        let probes = self.state.lock().expect("poisoned").probes.clone();
        async move { probes }
    }

    fn dump_snapshot(
        &mut self,
    ) -> impl Future<Output = Result<KernelSnapshot, DataplaneError>> + Send {
        let snap = self.state.lock().expect("poisoned").kernel.clone();
        async move { Ok(snap) }
    }

    fn apply(
        &mut self,
        op: &DataplaneOp,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send {
        let result = self.apply_inner(op);
        async move { result }
    }

    fn probe_ip_vrfs(
        &mut self,
        ip_vrfs: &IpVrfTable,
    ) -> impl Future<Output = HashMap<IpVrfId, IpVrfStatus>> + Send {
        // Return test-staged verdicts for configured VRFs only — a
        // status recorded for a VRF the intent no longer carries must
        // not leak into the probe result, matching the real impl's
        // per-configured-VRF probe loop.
        let state = self.state.lock().expect("poisoned");
        let out: HashMap<IpVrfId, IpVrfStatus> = ip_vrfs
            .iter()
            .filter_map(|vrf| {
                state
                    .ip_vrf_statuses
                    .get(&vrf.id)
                    .map(|status| (vrf.id, status.clone()))
            })
            .collect();
        drop(state);
        async move { out }
    }

    fn dump_l3_adoption_candidates(
        &mut self,
        ip_vrfs: &IpVrfTable,
    ) -> impl Future<Output = Option<L3AdoptionDump>> + Send {
        let result = self.dump_l3_adoption_candidates_inner(ip_vrfs);
        async move { result }
    }

    fn next_event(&mut self) -> impl Future<Output = Option<KernelEvent>> + Send {
        // The receiver lifetime is tied to &mut self for the duration
        // of the await. tokio::sync::mpsc::Receiver::recv takes &mut
        // self so this is exactly the borrow shape we want.
        self.events_rx.recv()
    }

    fn take_local_mac_rx(&mut self) -> Option<mpsc::Receiver<LocalMacObservation>> {
        self.local_mac_rx.take()
    }
}

impl InMemoryDataplane {
    /// Synchronous half of `apply` — does the fail-injection lookup
    /// and the kernel-state mutation under the same lock so the test
    /// can't observe a partially-applied op.
    #[allow(clippy::too_many_lines)] // one arm per op shape; splitting obscures the dispatch
    fn apply_inner(&self, op: &DataplaneOp) -> Result<(), DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        state.apply_count += 1;

        // Look for a matching failure injection. Pop on match.
        if let Some(idx) = state.failures.iter().position(|f| match &f.target {
            None => true,
            Some(target) => target == op,
        }) {
            let failure = state.failures.remove(idx).unwrap();
            return Err(failure.error.realize());
        }

        match op {
            DataplaneOp::AddRemoteFdb {
                vni,
                mac,
                vlan,
                dst,
            }
            | DataplaneOp::UpdateRemoteFdb {
                vni,
                mac,
                vlan,
                dst,
            } => {
                state.kernel.insert_fdb(
                    *vni,
                    KernelFdbEntry {
                        mac: *mac,
                        vlan: *vlan,
                        dst: Some(*dst),
                        nh_id: None,
                        protocol: None,
                        flags: KernelFdbFlags {
                            extern_learn: true,
                            master: true,
                            ..Default::default()
                        },
                    },
                );
            }
            DataplaneOp::RemoveRemoteFdb { vni, mac, vlan } => {
                state.kernel.remove_fdb_in_vlan(*vni, *mac, *vlan);
            }
            DataplaneOp::SetBumPortFlags { ifindex, flags } => {
                state.bum_port_flags.insert(*ifindex, *flags);
            }
            DataplaneOp::SetAcPortState { ifindex, blocked } => {
                state.ac_port_states.insert(*ifindex, *blocked);
                // Mirror into the fake kernel's bridge-port inventory
                // so the level-triggered observed-state diff sees the
                // apply on the next dump, like the real kernel.
                let new_state = if *blocked {
                    crate::ac_gate::BR_STATE_DISABLED
                } else {
                    crate::ac_gate::BR_STATE_FORWARDING
                };
                for port in state.kernel.bridge_ports.values_mut() {
                    if port.ifindex == *ifindex {
                        port.state = Some(new_state);
                    }
                }
            }
            DataplaneOp::CreateManagedBridge {
                name,
                vlan_filtering,
                ownership_stamp,
            } => match state.kernel.links.get_mut(name) {
                Some(link)
                    if managed_bridge_exact(link, name, *vlan_filtering, ownership_stamp) => {}
                Some(_) => {
                    return Err(crate::error::DataplaneError::InvalidArgument(format!(
                        "managed bridge {name} changed during apply"
                    )));
                }
                None => {
                    if state.kernel.link_name_exists(name) {
                        return Err(crate::error::DataplaneError::InvalidArgument(format!(
                            "managed bridge {name} cannot be created: desired name is occupied by a non-bridge link"
                        )));
                    }
                    let next_ifindex = state
                        .kernel
                        .links
                        .values()
                        .map(|link| link.ifindex)
                        .max()
                        .unwrap_or(0)
                        .saturating_add(1);
                    state.kernel.insert_link(KernelLinkInfo {
                        ifindex: next_ifindex,
                        bridge_name: name.clone(),
                        vlan_filtering: *vlan_filtering,
                        altnames: vec![ownership_stamp.clone()],
                        ..KernelLinkInfo::default()
                    });
                }
            },
            DataplaneOp::RemoveManagedBridge {
                name,
                ownership_stamp,
            } => match state.kernel.links.get(name) {
                Some(link) if managed_bridge_has_exact_stamp(link, name, ownership_stamp) => {
                    state.kernel.remove_link(name);
                }
                Some(_) => {
                    return Err(crate::error::DataplaneError::InvalidArgument(format!(
                        "managed bridge {name} changed before remove"
                    )));
                }
                None => {}
            },
            DataplaneOp::CreateManagedVxlan {
                name,
                spec,
                ownership_stamp,
            } => match state.kernel.vxlans.get_mut(name) {
                Some(link) if managed_vxlan_exact(link, name, spec, ownership_stamp) => {}
                Some(_) => {
                    return Err(crate::error::DataplaneError::InvalidArgument(format!(
                        "managed VXLAN {name} changed during apply"
                    )));
                }
                None => {
                    if state.kernel.link_name_exists(name) {
                        return Err(crate::error::DataplaneError::InvalidArgument(format!(
                            "managed VXLAN {name} cannot be created: desired name is occupied by a non-VXLAN link"
                        )));
                    }
                    if !state.kernel.links.contains_key(&spec.bridge) {
                        if state.kernel.link_name_exists(&spec.bridge) {
                            return Err(crate::error::DataplaneError::InvalidArgument(format!(
                                "managed VXLAN {name} cannot be created: desired bridge name {} is occupied by a non-bridge link",
                                spec.bridge
                            )));
                        }
                        return Err(crate::error::DataplaneError::Other(format!(
                            "managed VXLAN {name} cannot be created: desired bridge {} is absent",
                            spec.bridge
                        )));
                    }
                    let next_ifindex = state
                        .kernel
                        .links
                        .values()
                        .map(|link| link.ifindex)
                        .chain(state.kernel.vxlans.values().map(|link| link.ifindex))
                        .max()
                        .unwrap_or(0)
                        .saturating_add(1);
                    state.kernel.insert_vxlan(KernelVxlanLinkInfo {
                        ifindex: next_ifindex,
                        name: name.clone(),
                        altnames: vec![ownership_stamp.clone()],
                        up: true,
                        vni: Some(spec.vni),
                        local_ip: Some(spec.local_ip),
                        dstport: Some(spec.dstport),
                        learning_disabled: Some(true),
                        collect_metadata: false,
                        vnifilter: false,
                        bridge: Some(spec.bridge.clone()),
                        master: Some(spec.bridge.clone()),
                        mac: None,
                    });
                }
            },
            DataplaneOp::RemoveManagedVxlan {
                name,
                ownership_stamp,
            } => match state.kernel.vxlans.get(name) {
                Some(link) if managed_vxlan_has_exact_stamp(link, name, ownership_stamp) => {
                    state.kernel.remove_vxlan(name);
                }
                Some(_) => {
                    return Err(crate::error::DataplaneError::InvalidArgument(format!(
                        "managed VXLAN {name} changed before remove"
                    )));
                }
                None => {}
            },
            DataplaneOp::CreateManagedVrf {
                name,
                spec,
                ownership_stamp,
            } => match state.kernel.vrfs.get_mut(name) {
                Some(link) if managed_vrf_exact(link, name, spec, ownership_stamp) => {}
                Some(_) => {
                    return Err(crate::error::DataplaneError::InvalidArgument(format!(
                        "managed VRF {name} changed during apply"
                    )));
                }
                None => {
                    if state.kernel.link_name_exists(name) {
                        return Err(crate::error::DataplaneError::InvalidArgument(format!(
                            "managed VRF {name} cannot be created: desired name is occupied by a non-VRF link"
                        )));
                    }
                    let next_ifindex = state
                        .kernel
                        .links
                        .values()
                        .map(|link| link.ifindex)
                        .chain(state.kernel.vxlans.values().map(|link| link.ifindex))
                        .chain(state.kernel.vrfs.values().map(|link| link.ifindex))
                        .max()
                        .unwrap_or(0)
                        .saturating_add(1);
                    state.kernel.insert_vrf(KernelVrfLinkInfo {
                        ifindex: next_ifindex,
                        name: name.clone(),
                        altnames: vec![ownership_stamp.clone()],
                        up: true,
                        table_id: Some(spec.table_id),
                    });
                }
            },
            DataplaneOp::RemoveManagedVrf {
                name,
                ownership_stamp,
            } => match state.kernel.vrfs.get(name) {
                Some(link) if managed_vrf_has_exact_stamp(link, name, ownership_stamp) => {
                    // Mirror the prod `remove_vrf` refusal: never delete a
                    // VRF while a slave link is still enslaved to it. In the
                    // fake's kernel model an enslaved L3VXLAN records the VRF
                    // name in its `master` back-reference.
                    let mut slaves: Vec<&str> = state
                        .kernel
                        .vxlans
                        .values()
                        .filter(|vxlan| vxlan.master.as_deref() == Some(name.as_str()))
                        .map(|vxlan| vxlan.name.as_str())
                        .collect();
                    if !slaves.is_empty() {
                        slaves.sort_unstable();
                        return Err(crate::error::DataplaneError::InvalidArgument(format!(
                            "managed VRF {name} cannot be removed while slave link(s) remain attached: {slaves:?}"
                        )));
                    }
                    state.kernel.remove_vrf(name);
                }
                Some(_) => {
                    return Err(crate::error::DataplaneError::InvalidArgument(format!(
                        "managed VRF {name} changed before remove"
                    )));
                }
                None => {}
            },
            DataplaneOp::CreateManagedL3Vxlan {
                name,
                spec,
                ownership_stamp,
            } => match state.kernel.vxlans.get_mut(name) {
                Some(link) if managed_l3vxlan_exact(link, name, spec, ownership_stamp) => {}
                Some(_) => {
                    return Err(crate::error::DataplaneError::InvalidArgument(format!(
                        "managed L3VXLAN {name} changed during apply"
                    )));
                }
                None => {
                    if state.kernel.link_name_exists(name) {
                        return Err(crate::error::DataplaneError::InvalidArgument(format!(
                            "managed L3VXLAN {name} cannot be created: desired name is occupied by a non-VXLAN link"
                        )));
                    }
                    if !state.kernel.vrfs.contains_key(&spec.vrf) {
                        if state.kernel.link_name_exists(&spec.vrf) {
                            return Err(crate::error::DataplaneError::InvalidArgument(format!(
                                "managed L3VXLAN {name} cannot be created: desired VRF name {} is occupied by a non-VRF link",
                                spec.vrf
                            )));
                        }
                        return Err(crate::error::DataplaneError::Other(format!(
                            "managed L3VXLAN {name} cannot be created: desired VRF {} is absent",
                            spec.vrf
                        )));
                    }
                    let next_ifindex = state
                        .kernel
                        .links
                        .values()
                        .map(|link| link.ifindex)
                        .chain(state.kernel.vxlans.values().map(|link| link.ifindex))
                        .chain(state.kernel.vrfs.values().map(|link| link.ifindex))
                        .max()
                        .unwrap_or(0)
                        .saturating_add(1);
                    state.kernel.insert_vxlan(KernelVxlanLinkInfo {
                        ifindex: next_ifindex,
                        name: name.clone(),
                        altnames: vec![ownership_stamp.clone()],
                        up: true,
                        vni: Some(spec.vni),
                        local_ip: Some(spec.local_ip),
                        dstport: Some(spec.dstport),
                        learning_disabled: Some(true),
                        collect_metadata: false,
                        vnifilter: false,
                        bridge: None,
                        master: Some(spec.vrf.clone()),
                        mac: Some(spec.router_mac),
                    });
                }
            },
            DataplaneOp::RemoveManagedL3Vxlan {
                name,
                ownership_stamp,
            } => match state.kernel.vxlans.get(name) {
                Some(link) if managed_vxlan_has_exact_stamp(link, name, ownership_stamp) => {
                    state.kernel.remove_vxlan(name);
                }
                Some(_) => {
                    return Err(crate::error::DataplaneError::InvalidArgument(format!(
                        "managed L3VXLAN {name} changed before remove"
                    )));
                }
                None => {}
            },
            // Gate 9 slice 6c L3 ops mutate the fake's L3 kernel maps
            // with the same replace-on-add / idempotent-remove
            // semantics the real netlink path has (`.replace()` on
            // adds; ENOENT-as-ACK on removes). Rows written here are
            // always `marked: true` — the real apply path always
            // writes the ADR-0079 ownership markers. Successful ops
            // are also appended to `l3_op_log` so ordering-sensitive
            // tests (the ADR-0079 reap order) can assert sequencing.
            DataplaneOp::AddRemoteIpRoute {
                prefix,
                table_id,
                l3vxlan_ifindex,
                next_hop,
                ..
            } => {
                state.l3_routes.insert(
                    (*table_id, *prefix),
                    InMemoryL3Route {
                        l3vxlan_ifindex: *l3vxlan_ifindex,
                        next_hop: *next_hop,
                        targets: InMemoryL3RouteTargets::Single {
                            next_hop: *next_hop,
                        },
                        marked: true,
                    },
                );
                state.l3_op_log.push(op.clone());
            }
            DataplaneOp::AddRemoteIpRouteEcmp {
                prefix,
                table_id,
                l3vxlan_ifindex,
                next_hops,
                ..
            } => {
                let targets = InMemoryL3RouteTargets::Ecmp {
                    next_hops: next_hops.clone(),
                };
                state.l3_routes.insert(
                    (*table_id, *prefix),
                    InMemoryL3Route {
                        l3vxlan_ifindex: *l3vxlan_ifindex,
                        next_hop: targets.representative_next_hop(),
                        targets,
                        marked: true,
                    },
                );
                state.l3_op_log.push(op.clone());
            }
            DataplaneOp::RemoveRemoteIpRoute {
                prefix, table_id, ..
            }
            | DataplaneOp::RemoveRemoteIpRouteEcmp {
                prefix, table_id, ..
            } => {
                state.l3_routes.remove(&(*table_id, *prefix));
                state.l3_op_log.push(op.clone());
            }
            DataplaneOp::AddL3Neighbor {
                l3vxlan_ifindex,
                next_hop,
                router_mac,
                ..
            } => {
                state.l3_neighbors.insert(
                    (*l3vxlan_ifindex, *next_hop),
                    InMemoryL3Neighbor {
                        router_mac: *router_mac,
                        marked: true,
                    },
                );
                state.l3_op_log.push(op.clone());
            }
            DataplaneOp::RemoveL3Neighbor {
                l3vxlan_ifindex,
                next_hop,
                ..
            } => {
                state.l3_neighbors.remove(&(*l3vxlan_ifindex, *next_hop));
                state.l3_op_log.push(op.clone());
            }
            DataplaneOp::AddL3VxlanFdb {
                l3vxlan_ifindex,
                router_mac,
                next_hop,
                ..
            } => {
                state.l3_vxlan_fdb.insert(
                    (*l3vxlan_ifindex, *router_mac),
                    InMemoryL3VxlanFdb {
                        target: InMemoryL3VxlanFdbTarget::SingleDst {
                            next_hop: *next_hop,
                        },
                        marked: true,
                    },
                );
                state.l3_op_log.push(op.clone());
            }
            DataplaneOp::RemoveL3VxlanFdb {
                l3vxlan_ifindex,
                router_mac,
                ..
            } => {
                state.l3_vxlan_fdb.remove(&(*l3vxlan_ifindex, *router_mac));
                state.l3_op_log.push(op.clone());
            }
            // ADR-0059 slice 3 FDB-NHG ops never reach `Dataplane::apply` —
            // the reconcile actor routes them through `NexthopOps` /
            // its own coordinator (because they require allocator +
            // refcount state the `Dataplane` impl doesn't own). If
            // one slips through here it's a bug in the routing; use
            // `InvalidArgument` (classified `Permanent`) so the actor
            // suppresses rather than backoff-retrying forever.
            DataplaneOp::InstallFdbNhg { .. }
            | DataplaneOp::UpdateFdbNhgMembers { .. }
            | DataplaneOp::RemoveFdbNhg { .. }
            | DataplaneOp::InstallL3FdbNhg { .. }
            | DataplaneOp::RemoveL3FdbNhg { .. } => {
                return Err(crate::error::DataplaneError::InvalidArgument(
                    "FDB-NHG ops must be applied via the reconcile-actor coordinator, \
                     not Dataplane::apply"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// Synchronous half of `dump_l3_adoption_candidates` — collects
    /// the *currently* marked rows visible through the configured
    /// VRFs (a live view: rows added or removed by `apply` since
    /// startup are reflected, which the ADR-0079 reap re-check
    /// depends on). Mirrors the real impl's scoping: routes match by
    /// configured `table_id`; neighbor / FDB rows match by managed
    /// L3VXLAN ifindex (staged via `set_l3vxlan_ifindex`).
    fn dump_l3_adoption_candidates_inner(&self, ip_vrfs: &IpVrfTable) -> Option<L3AdoptionDump> {
        if ip_vrfs.is_empty() {
            return Some(L3AdoptionDump::default());
        }
        let mut state = self.state.lock().expect("poisoned");
        if state.l3_adoption_dump_failures > 0 {
            state.l3_adoption_dump_failures -= 1;
            return None;
        }
        let tables: BTreeMap<u32, IpVrfId> =
            ip_vrfs.iter().map(|vrf| (vrf.table_id, vrf.id)).collect();
        let configured: std::collections::BTreeSet<IpVrfId> =
            ip_vrfs.iter().map(|vrf| vrf.id).collect();
        let managed: BTreeMap<u32, IpVrfId> = state
            .l3vxlan_ifindexes
            .iter()
            .filter(|(vrf_id, _)| configured.contains(vrf_id))
            .map(|(vrf_id, ifindex)| (*ifindex, *vrf_id))
            .collect();

        let mut out = L3AdoptionDump::default();
        for (&(table_id, prefix), row) in &state.l3_routes {
            if !row.marked {
                continue;
            }
            let Some(vrf_id) = tables.get(&table_id).copied() else {
                continue;
            };
            out.routes.insert(
                (vrf_id, prefix),
                AdoptedL3Route {
                    table_id,
                    l3vxlan_ifindex: row.l3vxlan_ifindex,
                    next_hop: row.next_hop,
                    next_hops: match &row.targets {
                        InMemoryL3RouteTargets::Single { next_hop } => vec![*next_hop],
                        InMemoryL3RouteTargets::Ecmp { next_hops } => next_hops.clone(),
                    },
                },
            );
        }
        for (&(ifindex, next_hop), row) in &state.l3_neighbors {
            if !row.marked {
                continue;
            }
            let Some(vrf_id) = managed.get(&ifindex).copied() else {
                continue;
            };
            out.neighbors.insert((ifindex, next_hop), vrf_id);
        }
        for (&(ifindex, router_mac), row) in &state.l3_vxlan_fdb {
            if !row.marked {
                continue;
            }
            let Some(vrf_id) = managed.get(&ifindex).copied() else {
                continue;
            };
            let target = match row.target {
                InMemoryL3VxlanFdbTarget::SingleDst { .. } => AdoptedL3VxlanFdbTarget::SingleDst,
                InMemoryL3VxlanFdbTarget::Nhg { nh_id } => {
                    AdoptedL3VxlanFdbTarget::NexthopGroup { nh_id }
                }
            };
            out.l3vxlan_fdb
                .insert((ifindex, router_mac), AdoptedL3VxlanFdb { vrf_id, target });
        }
        Some(out)
    }
}

/// Pop the next "universal" (`target: None`) injected failure from
/// the queue, if any. `NexthopOps` methods (called via
/// `apply_nhg_op`) do not carry a `DataplaneOp` to match against,
/// so they can only consume failures the test left targetless.
/// Returns the realized error; caller short-circuits.
fn take_universal_failure(state: &mut State) -> Option<DataplaneError> {
    let idx = state.failures.iter().position(|f| f.target.is_none())?;
    let f = state.failures.remove(idx).unwrap();
    Some(f.error.realize())
}

impl NexthopOps for InMemoryDataplane {
    async fn add_nexthop_member(
        &mut self,
        id: u32,
        gateway: std::net::IpAddr,
    ) -> Result<(), DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        if let Some(e) = take_universal_failure(&mut state) {
            return Err(e);
        }
        state.nexthop_ops.insert(
            id,
            KernelNexthop {
                id,
                kind: KernelNexthopKind::Member { gateway },
            },
        );
        Ok(())
    }

    async fn add_nexthop_group(
        &mut self,
        id: u32,
        member_ids: &[u32],
    ) -> Result<(), DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        if let Some(e) = take_universal_failure(&mut state) {
            return Err(e);
        }
        state.nexthop_ops.insert(
            id,
            KernelNexthop {
                id,
                kind: KernelNexthopKind::Group {
                    member_ids: member_ids.to_vec(),
                },
            },
        );
        Ok(())
    }

    async fn del_nexthop(&mut self, id: u32) -> Result<(), DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        if let Some(e) = take_universal_failure(&mut state) {
            return Err(e);
        }
        // Idempotent: dropping a non-existent entry is fine, matching
        // the slice-2 `NexthopSocket::del` ENOENT-as-ACK contract.
        state.nexthop_ops.remove(&id);
        Ok(())
    }

    async fn install_fdb_nhg_row(
        &mut self,
        vni: EvpnInstanceId,
        mac: MacAddress,
        vlan: Option<u16>,
        nh_id: u32,
    ) -> Result<(), DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        if let Some(e) = take_universal_failure(&mut state) {
            return Err(e);
        }
        // Mirror into `state.kernel` so a subsequent `dump_snapshot`
        // reflects the row — without this, the slice 3b drift check
        // in `compute_diff` Pass 1b would see no row, treat it as
        // drift, and re-emit `InstallFdbNhg` every reconcile pass.
        state.kernel.insert_fdb(
            vni,
            KernelFdbEntry {
                mac,
                vlan,
                dst: None,
                nh_id: Some(nh_id),
                protocol: None,
                flags: KernelFdbFlags {
                    extern_learn: true,
                    master: true,
                    ..Default::default()
                },
            },
        );
        Ok(())
    }

    async fn remove_fdb_nhg_row(
        &mut self,
        vni: EvpnInstanceId,
        mac: MacAddress,
        vlan: Option<u16>,
    ) -> Result<(), DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        if let Some(e) = take_universal_failure(&mut state) {
            return Err(e);
        }
        // Idempotent — slice 3b coordinator may issue this on
        // already-removed rows during stale cleanup.
        state.kernel.remove_fdb_in_vlan(vni, mac, vlan);
        Ok(())
    }

    async fn install_l3_fdb_nhg_row(
        &mut self,
        l3vxlan_ifindex: u32,
        router_mac: MacAddress,
        nh_id: u32,
    ) -> Result<(), DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        if let Some(e) = take_universal_failure(&mut state) {
            return Err(e);
        }
        state.l3_vxlan_fdb.insert(
            (l3vxlan_ifindex, router_mac),
            InMemoryL3VxlanFdb {
                target: InMemoryL3VxlanFdbTarget::Nhg { nh_id },
                marked: true,
            },
        );
        Ok(())
    }

    async fn remove_l3_fdb_nhg_row(
        &mut self,
        l3vxlan_ifindex: u32,
        router_mac: MacAddress,
    ) -> Result<(), DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        if let Some(e) = take_universal_failure(&mut state) {
            return Err(e);
        }
        state.l3_vxlan_fdb.remove(&(l3vxlan_ifindex, router_mac));
        Ok(())
    }

    async fn dump_owned_nexthops(&mut self) -> Result<Vec<KernelNexthop>, DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        if let Some(e) = take_universal_failure(&mut state) {
            return Err(e);
        }
        // Mirror the LinuxDataplane filter: return only rustbgpd-tagged
        // entries. Tests can stage foreign-tagged entries to verify
        // adoption filtering.
        Ok(state
            .nexthop_ops
            .values()
            .filter(|n| NhIdAllocator::is_ours(n.id))
            .cloned()
            .collect())
    }

    async fn dump_owned_l3_nexthops(&mut self) -> Result<Vec<KernelNexthop>, DataplaneError> {
        let mut state = self.state.lock().expect("poisoned");
        if let Some(e) = take_universal_failure(&mut state) {
            return Err(e);
        }
        Ok(state
            .nexthop_ops
            .values()
            .filter(|n| NhIdAllocator::is_l3_ours(n.id))
            .cloned()
            .collect())
    }
}

/// Test-side handle for inspecting / mutating fake state.
#[derive(Debug, Clone)]
pub struct InMemoryHandle {
    state: Arc<Mutex<State>>,
    events_tx: mpsc::Sender<KernelEvent>,
    local_mac_tx: mpsc::Sender<LocalMacObservation>,
}

// Every method panics only on Mutex lock-poisoning, which is
// unrecoverable in this test fake. Documenting `# Panics` on each
// would be noise; suppress at the impl level.
#[allow(clippy::missing_panics_doc)]
impl InMemoryHandle {
    /// Pre-load a foreign FDB entry the actor must preserve.
    pub fn pre_load_fdb(&self, vni: EvpnInstanceId, entry: KernelFdbEntry) {
        self.state
            .lock()
            .expect("poisoned")
            .kernel
            .insert_fdb(vni, entry);
    }

    /// Replace the fake link inventory wholesale.
    pub fn set_links(&self, links: BTreeMap<String, KernelLinkInfo>) {
        self.state.lock().expect("poisoned").kernel.set_links(links);
    }

    /// Replace the fake raw link-name inventory wholesale.
    pub fn set_link_names(&self, names: BTreeSet<String>) {
        self.state
            .lock()
            .expect("poisoned")
            .kernel
            .set_link_names(names);
    }

    /// Replace the fake VXLAN inventory wholesale.
    pub fn set_vxlans(&self, vxlans: BTreeMap<String, KernelVxlanLinkInfo>) {
        self.state
            .lock()
            .expect("poisoned")
            .kernel
            .set_vxlans(vxlans);
    }

    /// Set the probe outcome for one instance.
    pub fn set_probe(&self, vni: EvpnInstanceId, probe: InstanceProbe) {
        self.state
            .lock()
            .expect("poisoned")
            .probes
            .insert(vni, probe);
    }

    /// Inject a failure for the next matching apply call. `target =
    /// None` matches any op.
    pub fn inject_failure_io(&self, target: Option<DataplaneOp>) {
        self.state
            .lock()
            .expect("poisoned")
            .failures
            .push_back(InjectedFailure {
                target,
                error: ErrorTemplate::Io,
            });
    }

    /// Inject an `Other` failure with a fixed message.
    pub fn inject_failure_other(&self, target: Option<DataplaneOp>, msg: &str) {
        self.state
            .lock()
            .expect("poisoned")
            .failures
            .push_back(InjectedFailure {
                target,
                error: ErrorTemplate::Other(msg.to_owned()),
            });
    }

    /// Inject a `KernelTooOld` failure (permanent, unretryable).
    pub fn inject_failure_kernel_too_old(&self, target: Option<DataplaneOp>) {
        self.state
            .lock()
            .expect("poisoned")
            .failures
            .push_back(InjectedFailure {
                target,
                error: ErrorTemplate::KernelTooOld,
            });
    }

    /// Push a kernel event to wake the actor's select! loop.
    pub async fn push_event(&self, event: KernelEvent) {
        // Sending to a closed channel just means the actor already
        // tore down; tests treat that as harmless.
        let _ = self.events_tx.send(event).await;
    }

    /// Inject an upward `LocalMacObservation` for the daemon-side
    /// originator to consume.
    ///
    /// Tests typically:
    /// 1. Call `Dataplane::take_local_mac_rx` to hand the receiver to
    ///    the originator under test;
    /// 2. Call this method to push synthetic Learn / Aged events.
    pub async fn inject_local_mac_observation(&self, obs: LocalMacObservation) {
        let _ = self.local_mac_tx.send(obs).await;
    }

    /// Synchronous, non-async variant — `try_send` returns
    /// `Err(TrySendError::Full)` if the buffer is full. Used by the
    /// overflow-handling tests.
    ///
    /// # Errors
    /// Forwards the underlying [`mpsc::error::TrySendError`].
    pub fn try_inject_local_mac_observation(
        &self,
        obs: LocalMacObservation,
    ) -> Result<(), mpsc::error::TrySendError<LocalMacObservation>> {
        self.local_mac_tx.try_send(obs)
    }

    /// Total apply attempts recorded so far.
    #[must_use]
    pub fn apply_count(&self) -> usize {
        self.state.lock().expect("poisoned").apply_count
    }

    /// Snapshot the kernel state for assertion.
    #[must_use]
    pub fn kernel_snapshot(&self) -> KernelSnapshot {
        self.state.lock().expect("poisoned").kernel.clone()
    }

    /// `true` if the kernel snapshot contains an FDB entry for
    /// `(vni, mac)`.
    #[must_use]
    pub fn kernel_has_fdb(&self, vni: EvpnInstanceId, mac: MacAddress) -> bool {
        self.state
            .lock()
            .expect("poisoned")
            .kernel
            .find_fdb(vni, mac)
            .is_some()
    }

    /// Snapshot the recorded `SetBumPortFlags` state by ifindex.
    /// Tests use this to assert the reconciler issued the expected
    /// per-port flag triplet.
    #[must_use]
    pub fn bum_port_flags(
        &self,
    ) -> std::collections::BTreeMap<u32, crate::bum_filter::BumPortFlags> {
        self.state.lock().expect("poisoned").bum_port_flags.clone()
    }

    /// Snapshot the recorded `SetAcPortState` calls by ifindex
    /// (`true` = blocked). Tests use this to assert the reconciler
    /// gated the expected AC ports.
    #[must_use]
    pub fn ac_port_states(&self) -> std::collections::BTreeMap<u32, bool> {
        self.state.lock().expect("poisoned").ac_port_states.clone()
    }

    /// Stage (or overwrite) one named bridge port in the fake
    /// kernel's link inventory — the AC-gate resolver's resolution
    /// surface. `state` is the raw `BR_STATE_*` scalar. Overwriting
    /// an existing entry simulates kernel-driven drift (e.g. the
    /// carrier check re-enabling a disabled port).
    pub fn set_bridge_port(&self, name: &str, ifindex: u32, state: Option<u8>) {
        self.state
            .lock()
            .expect("poisoned")
            .kernel
            .insert_bridge_port(name, ifindex, state);
    }

    /// Pre-load a kernel-side nexthop op so the actor's startup
    /// adoption pass (`dump_owned_nexthops`) sees it — used for
    /// "daemon restarts with prior NHIDs left over" tests.
    pub fn pre_load_nexthop_op(&self, nh: KernelNexthop) {
        self.state
            .lock()
            .expect("poisoned")
            .nexthop_ops
            .insert(nh.id, nh);
    }

    /// Out-of-band kernel-side delete of a nexthop op — drops the
    /// fake's tracking without going through the dataplane API. Used
    /// by ADR-0059 slice 3.5 PR 2 drift-recovery tests to simulate
    /// an operator or competing daemon issuing `ip nexthop del`
    /// behind rustbgpd's back. Returns the removed [`KernelNexthop`]
    /// for assertions.
    #[must_use]
    pub fn force_remove_nexthop_op(&self, id: u32) -> Option<KernelNexthop> {
        self.state.lock().expect("poisoned").nexthop_ops.remove(&id)
    }

    /// Out-of-band kernel-side group-member-set mutation. Replaces
    /// the kernel's tracked member list for the group at `id`
    /// without going through the dataplane API. Returns the prior
    /// member list when `id` is a group; `None` when `id` is absent
    /// or a per-VTEP member. Used by drift-recovery tests to
    /// simulate "operator changed the group out of band".
    #[must_use]
    pub fn force_set_group_members(&self, id: u32, members: Vec<u32>) -> Option<Vec<u32>> {
        let mut state = self.state.lock().expect("poisoned");
        let nh = state.nexthop_ops.get_mut(&id)?;
        match &mut nh.kind {
            crate::dataplane::KernelNexthopKind::Group { member_ids } => {
                let prev = member_ids.clone();
                *member_ids = members;
                Some(prev)
            }
            crate::dataplane::KernelNexthopKind::Member { .. } => None,
        }
    }

    /// Snapshot the current nexthop-op map for assertion — every ID
    /// the actor has installed (or test pre-loaded) and not yet
    /// deleted.
    #[must_use]
    pub fn nexthop_ops(&self) -> BTreeMap<u32, KernelNexthop> {
        self.state.lock().expect("poisoned").nexthop_ops.clone()
    }

    /// Read the `nh_id` field of an FDB row at `(vni, mac)`, if the
    /// row exists. Tests use this to verify an `InstallFdbNhg`
    /// landed and points at the right group.
    #[must_use]
    pub fn kernel_fdb_nh_id(&self, vni: EvpnInstanceId, mac: MacAddress) -> Option<u32> {
        self.state
            .lock()
            .expect("poisoned")
            .kernel
            .find_fdb(vni, mac)
            .and_then(|e| e.nh_id)
    }

    /// Stage the readiness verdict `probe_ip_vrfs` returns for one
    /// IP-VRF (the fake has no kernel topology to derive it from).
    pub fn set_ip_vrf_status(&self, vrf_id: IpVrfId, status: IpVrfStatus) {
        self.state
            .lock()
            .expect("poisoned")
            .ip_vrf_statuses
            .insert(vrf_id, status);
    }

    /// Record that an IP-VRF's L3VXLAN device "exists" at `ifindex`,
    /// making the device's neighbor / FDB rows visible to
    /// `dump_l3_adoption_candidates`. Separate from
    /// [`Self::set_ip_vrf_status`] on purpose: a resolvable device
    /// with a `NotReady` VRF is a legitimate kernel shape the ADR-0079
    /// tests need to stage.
    pub fn set_l3vxlan_ifindex(&self, vrf_id: IpVrfId, ifindex: u32) {
        self.state
            .lock()
            .expect("poisoned")
            .l3vxlan_ifindexes
            .insert(vrf_id, ifindex);
    }

    /// Pre-load a kernel route row — `marked: true` for the ADR-0079
    /// crash-leftover shape (`proto bgp` + onlink), `false` for a
    /// foreign row the sweep must never touch.
    pub fn pre_load_l3_route(
        &self,
        table_id: u32,
        prefix: EvpnIpPrefixValue,
        l3vxlan_ifindex: u32,
        next_hop: IpAddr,
        marked: bool,
    ) {
        self.state.lock().expect("poisoned").l3_routes.insert(
            (table_id, prefix),
            InMemoryL3Route {
                l3vxlan_ifindex,
                next_hop,
                targets: InMemoryL3RouteTargets::Single { next_hop },
                marked,
            },
        );
    }

    /// Pre-load an ECMP kernel route row — the all-active
    /// counterpart to [`Self::pre_load_l3_route`].
    pub fn pre_load_l3_route_ecmp(
        &self,
        table_id: u32,
        prefix: EvpnIpPrefixValue,
        l3vxlan_ifindex: u32,
        next_hops: Vec<IpAddr>,
        marked: bool,
    ) {
        assert!(
            !next_hops.is_empty(),
            "test ECMP preload requires at least one next-hop"
        );
        self.state.lock().expect("poisoned").l3_routes.insert(
            (table_id, prefix),
            InMemoryL3Route {
                l3vxlan_ifindex,
                next_hop: next_hops[0],
                targets: InMemoryL3RouteTargets::Ecmp { next_hops },
                marked,
            },
        );
    }

    /// Pre-load an L3 neighbor row — `marked` distinguishes our
    /// `NUD_PERMANENT` + `extern_learn` shape from a foreign entry.
    pub fn pre_load_l3_neighbor(
        &self,
        l3vxlan_ifindex: u32,
        next_hop: IpAddr,
        router_mac: MacAddress,
        marked: bool,
    ) {
        self.state.lock().expect("poisoned").l3_neighbors.insert(
            (l3vxlan_ifindex, next_hop),
            InMemoryL3Neighbor { router_mac, marked },
        );
    }

    /// Pre-load an L3VXLAN FDB row — `marked` distinguishes our
    /// permanent `extern_learn` shape from a foreign entry.
    pub fn pre_load_l3_vxlan_fdb(
        &self,
        l3vxlan_ifindex: u32,
        router_mac: MacAddress,
        next_hop: IpAddr,
        marked: bool,
    ) {
        self.state.lock().expect("poisoned").l3_vxlan_fdb.insert(
            (l3vxlan_ifindex, router_mac),
            InMemoryL3VxlanFdb {
                target: InMemoryL3VxlanFdbTarget::SingleDst { next_hop },
                marked,
            },
        );
    }

    /// Pre-load an L3VXLAN FDB row pointing at an FDB nexthop group.
    pub fn pre_load_l3_vxlan_fdb_nhg(
        &self,
        l3vxlan_ifindex: u32,
        router_mac: MacAddress,
        nh_id: u32,
        marked: bool,
    ) {
        self.state.lock().expect("poisoned").l3_vxlan_fdb.insert(
            (l3vxlan_ifindex, router_mac),
            InMemoryL3VxlanFdb {
                target: InMemoryL3VxlanFdbTarget::Nhg { nh_id },
                marked,
            },
        );
    }

    /// `true` if the kernel has a route row at `(table_id, prefix)`.
    #[must_use]
    pub fn kernel_has_l3_route(&self, table_id: u32, prefix: EvpnIpPrefixValue) -> bool {
        self.state
            .lock()
            .expect("poisoned")
            .l3_routes
            .contains_key(&(table_id, prefix))
    }

    /// `true` if the kernel has an L3 neighbor row at
    /// `(l3vxlan_ifindex, next_hop)`.
    #[must_use]
    pub fn kernel_has_l3_neighbor(&self, l3vxlan_ifindex: u32, next_hop: IpAddr) -> bool {
        self.state
            .lock()
            .expect("poisoned")
            .l3_neighbors
            .contains_key(&(l3vxlan_ifindex, next_hop))
    }

    /// `true` if the kernel has an L3VXLAN FDB row at
    /// `(l3vxlan_ifindex, router_mac)`.
    #[must_use]
    pub fn kernel_has_l3_vxlan_fdb(&self, l3vxlan_ifindex: u32, router_mac: MacAddress) -> bool {
        self.state
            .lock()
            .expect("poisoned")
            .l3_vxlan_fdb
            .contains_key(&(l3vxlan_ifindex, router_mac))
    }

    /// Read the `nh_id` field of an L3VXLAN FDB row at
    /// `(l3vxlan_ifindex, router_mac)`, if the row exists and is an
    /// FDB-NHG row.
    #[must_use]
    pub fn kernel_l3_vxlan_fdb_nh_id(
        &self,
        l3vxlan_ifindex: u32,
        router_mac: MacAddress,
    ) -> Option<u32> {
        self.state
            .lock()
            .expect("poisoned")
            .l3_vxlan_fdb
            .get(&(l3vxlan_ifindex, router_mac))
            .and_then(|row| match row.target {
                InMemoryL3VxlanFdbTarget::Nhg { nh_id } => Some(nh_id),
                InMemoryL3VxlanFdbTarget::SingleDst { .. } => None,
            })
    }

    /// Snapshot the kernel L3 route map. Double-crash tests copy
    /// these rows into a second fake to simulate kernel state
    /// surviving the process.
    #[must_use]
    pub fn l3_routes(&self) -> BTreeMap<(u32, EvpnIpPrefixValue), InMemoryL3Route> {
        self.state.lock().expect("poisoned").l3_routes.clone()
    }

    /// Snapshot the kernel L3 neighbor map.
    #[must_use]
    pub fn l3_neighbors(&self) -> BTreeMap<(u32, IpAddr), InMemoryL3Neighbor> {
        self.state.lock().expect("poisoned").l3_neighbors.clone()
    }

    /// Snapshot the kernel L3VXLAN FDB map.
    #[must_use]
    pub fn l3_vxlan_fdb(&self) -> BTreeMap<(u32, MacAddress), InMemoryL3VxlanFdb> {
        self.state.lock().expect("poisoned").l3_vxlan_fdb.clone()
    }

    /// Queue one `dump_l3_adoption_candidates` failure — the next
    /// call returns `None` and consumes it, like the apply-side FIFO
    /// injections.
    pub fn inject_l3_adoption_dump_failure(&self) {
        self.state
            .lock()
            .expect("poisoned")
            .l3_adoption_dump_failures += 1;
    }

    /// Successful L3 `apply` ops in arrival order — the assertion
    /// surface for ordering-sensitive tests (ADR-0079 reap order).
    #[must_use]
    pub fn l3_op_log(&self) -> Vec<DataplaneOp> {
        self.state.lock().expect("poisoned").l3_op_log.clone()
    }
}

fn managed_bridge_exact(
    link: &KernelLinkInfo,
    name: &str,
    vlan_filtering: bool,
    ownership_stamp: &str,
) -> bool {
    link.vlan_filtering == vlan_filtering
        && managed_bridge_has_exact_stamp(link, name, ownership_stamp)
}

fn managed_bridge_has_exact_stamp(
    link: &KernelLinkInfo,
    name: &str,
    ownership_stamp: &str,
) -> bool {
    let stamps: Vec<_> = link
        .altnames
        .iter()
        .filter_map(|altname| parse_ownership_stamp(altname))
        .collect();
    stamps.len() == 1 && stamps[0].raw == ownership_stamp && stamps[0].name == name
}

fn managed_vxlan_exact(
    link: &KernelVxlanLinkInfo,
    name: &str,
    spec: &rustbgpd_evpn::ManagedVxlanNetdevSpec,
    ownership_stamp: &str,
) -> bool {
    managed_vxlan_has_exact_stamp(link, name, ownership_stamp)
        && link.vni == Some(spec.vni)
        && link.local_ip == Some(spec.local_ip)
        && link.dstport == Some(spec.dstport)
        && link.learning_disabled == Some(true)
        && !link.collect_metadata
        && !link.vnifilter
        && link.bridge.as_deref() == Some(spec.bridge.as_str())
}

fn managed_vxlan_has_exact_stamp(
    link: &KernelVxlanLinkInfo,
    name: &str,
    ownership_stamp: &str,
) -> bool {
    let stamps: Vec<_> = link
        .altnames
        .iter()
        .filter_map(|altname| parse_ownership_stamp(altname))
        .collect();
    stamps.len() == 1 && stamps[0].raw == ownership_stamp && stamps[0].name == name
}

fn managed_vrf_exact(
    link: &KernelVrfLinkInfo,
    name: &str,
    spec: &rustbgpd_evpn::ManagedVrfNetdevSpec,
    ownership_stamp: &str,
) -> bool {
    managed_vrf_has_exact_stamp(link, name, ownership_stamp) && link.table_id == Some(spec.table_id)
}

fn managed_vrf_has_exact_stamp(
    link: &KernelVrfLinkInfo,
    name: &str,
    ownership_stamp: &str,
) -> bool {
    let stamps: Vec<_> = link
        .altnames
        .iter()
        .filter_map(|altname| parse_ownership_stamp(altname))
        .collect();
    stamps.len() == 1 && stamps[0].raw == ownership_stamp && stamps[0].name == name
}

fn managed_l3vxlan_exact(
    link: &KernelVxlanLinkInfo,
    name: &str,
    spec: &rustbgpd_evpn::ManagedL3VxlanNetdevSpec,
    ownership_stamp: &str,
) -> bool {
    managed_vxlan_has_exact_stamp(link, name, ownership_stamp)
        && link.vni == Some(spec.vni)
        && link.local_ip == Some(spec.local_ip)
        && link.dstport == Some(spec.dstport)
        && link.learning_disabled == Some(true)
        && !link.collect_metadata
        && !link.vnifilter
        && link.master.as_deref() == Some(spec.vrf.as_str())
        && link.mac == Some(spec.router_mac)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn apply_round_trip_program_then_remove() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        let op_add = DataplaneOp::AddRemoteFdb {
            vni: vni(100),
            mac: mac(1),
            vlan: None,
            dst: ip("10.0.0.2"),
        };
        dp.apply(&op_add).await.unwrap();
        assert!(h.kernel_has_fdb(vni(100), mac(1)));

        let op_rem = DataplaneOp::RemoveRemoteFdb {
            vni: vni(100),
            mac: mac(1),
            vlan: None,
        };
        dp.apply(&op_rem).await.unwrap();
        assert!(!h.kernel_has_fdb(vni(100), mac(1)));
        assert_eq!(h.apply_count(), 2);
    }

    #[tokio::test]
    async fn injected_io_failure_surfaces_through_apply() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        let op = DataplaneOp::AddRemoteFdb {
            vni: vni(100),
            mac: mac(1),
            vlan: None,
            dst: ip("10.0.0.2"),
        };
        h.inject_failure_io(Some(op.clone()));
        let err = dp.apply(&op).await.unwrap_err();
        assert!(matches!(err, DataplaneError::Io(_)));
        // Subsequent apply with the same op now succeeds (the
        // injection was popped).
        dp.apply(&op).await.unwrap();
    }

    #[tokio::test]
    async fn set_bum_port_flags_records_per_ifindex_state() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();

        dp.apply(&DataplaneOp::SetBumPortFlags {
            ifindex: 10,
            flags: crate::bum_filter::BumPortFlags::suppress_all(),
        })
        .await
        .unwrap();
        dp.apply(&DataplaneOp::SetBumPortFlags {
            ifindex: 11,
            flags: crate::bum_filter::BumPortFlags::allow_all(),
        })
        .await
        .unwrap();

        let recorded = h.bum_port_flags();
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            recorded[&10],
            crate::bum_filter::BumPortFlags::suppress_all()
        );
        assert_eq!(recorded[&11], crate::bum_filter::BumPortFlags::allow_all());

        // Reapply with new flags overwrites — idempotent at the
        // ifindex granularity.
        dp.apply(&DataplaneOp::SetBumPortFlags {
            ifindex: 10,
            flags: crate::bum_filter::BumPortFlags::allow_all(),
        })
        .await
        .unwrap();
        let recorded = h.bum_port_flags();
        assert_eq!(recorded[&10], crate::bum_filter::BumPortFlags::allow_all());
        assert_eq!(recorded.len(), 2, "ifindex 11 still present");
    }

    #[tokio::test]
    async fn injected_failure_with_no_target_matches_any_op() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.inject_failure_other(None, "boom");
        let op = DataplaneOp::AddRemoteFdb {
            vni: vni(100),
            mac: mac(1),
            vlan: None,
            dst: ip("10.0.0.2"),
        };
        assert!(dp.apply(&op).await.is_err());
    }

    #[tokio::test]
    async fn managed_vxlan_bridge_name_collision_is_permanent() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.set_link_names(BTreeSet::from(["br100".to_string()]));

        let err = dp
            .apply(&DataplaneOp::CreateManagedVxlan {
                name: "vxlan100".to_string(),
                spec: rustbgpd_evpn::ManagedVxlanNetdevSpec {
                    vni: 100,
                    local_ip: ip("10.0.0.1"),
                    dstport: 4789,
                    bridge: "br100".to_string(),
                },
                ownership_stamp: "rustbgpd:vxlan:leaf-1:vxlan100".to_string(),
            })
            .await
            .expect_err("bridge-name collision must fail permanently");

        assert_eq!(err.class(), crate::error::FailureClass::Permanent);
        assert!(
            err.to_string().contains("non-bridge link"),
            "unexpected error: {err}"
        );
        assert!(!h.kernel_snapshot().vxlans.contains_key("vxlan100"));
    }

    #[tokio::test]
    async fn managed_vrf_remove_refuses_while_slave_attached() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();

        dp.apply(&DataplaneOp::CreateManagedVrf {
            name: "vrf-blue".to_string(),
            spec: rustbgpd_evpn::ManagedVrfNetdevSpec { table_id: 5000 },
            ownership_stamp: "rustbgpd:vrf:leaf-1:vrf-blue".to_string(),
        })
        .await
        .expect("VRF create must succeed");
        dp.apply(&DataplaneOp::CreateManagedL3Vxlan {
            name: "l3vxlan5000".to_string(),
            spec: rustbgpd_evpn::ManagedL3VxlanNetdevSpec {
                vni: 5000,
                local_ip: ip("10.0.0.1"),
                dstport: 4789,
                vrf: "vrf-blue".to_string(),
                router_mac: mac(1),
            },
            ownership_stamp: "rustbgpd:l3vxlan:leaf-1:l3vxlan5000".to_string(),
        })
        .await
        .expect("L3VXLAN create must succeed");

        // The L3VXLAN is now enslaved to the VRF: removal must refuse
        // permanently and leave the VRF in place (matches prod
        // `remove_vrf`).
        let err = dp
            .apply(&DataplaneOp::RemoveManagedVrf {
                name: "vrf-blue".to_string(),
                ownership_stamp: "rustbgpd:vrf:leaf-1:vrf-blue".to_string(),
            })
            .await
            .expect_err("VRF remove must refuse while a slave is attached");
        assert_eq!(err.class(), crate::error::FailureClass::Permanent);
        assert!(
            err.to_string().contains("slave link(s) remain attached"),
            "unexpected error: {err}"
        );
        assert!(h.kernel_snapshot().vrfs.contains_key("vrf-blue"));

        // Detach the slave; removal now succeeds.
        dp.apply(&DataplaneOp::RemoveManagedL3Vxlan {
            name: "l3vxlan5000".to_string(),
            ownership_stamp: "rustbgpd:l3vxlan:leaf-1:l3vxlan5000".to_string(),
        })
        .await
        .expect("L3VXLAN remove must succeed");
        dp.apply(&DataplaneOp::RemoveManagedVrf {
            name: "vrf-blue".to_string(),
            ownership_stamp: "rustbgpd:vrf:leaf-1:vrf-blue".to_string(),
        })
        .await
        .expect("VRF remove must succeed once no slaves remain");
        assert!(!h.kernel_snapshot().vrfs.contains_key("vrf-blue"));
    }

    #[tokio::test]
    async fn probe_returns_recorded_outcomes() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.set_probe(vni(100), InstanceProbe::Ready);
        h.set_probe(vni(200), InstanceProbe::NotReady { reason: "x".into() });
        let probes = dp.probe(&EvpnInstanceTable::new()).await;
        assert!(probes.is_ready(vni(100)));
        assert!(!probes.is_ready(vni(200)));
    }

    #[tokio::test]
    async fn pushed_kernel_event_arrives_via_next_event() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.push_event(KernelEvent::KernelStateChanged).await;
        let evt = dp.next_event().await;
        assert_eq!(evt, Some(KernelEvent::KernelStateChanged));
    }

    #[tokio::test]
    async fn pre_loaded_fdb_visible_in_dump() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.pre_load_fdb(
            vni(100),
            KernelFdbEntry {
                mac: mac(9),
                vlan: None,
                dst: None,
                nh_id: None,
                protocol: None,
                flags: KernelFdbFlags::default(),
            },
        );
        let snap = dp.dump_snapshot().await.unwrap();
        assert!(snap.find_fdb(vni(100), mac(9)).is_some());
    }

    #[tokio::test]
    async fn nexthop_dump_partitions_l2_and_l3_tags() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        h.pre_load_nexthop_op(KernelNexthop {
            id: 0x3000_0001,
            kind: KernelNexthopKind::Member {
                gateway: ip("10.0.0.2"),
            },
        });
        h.pre_load_nexthop_op(KernelNexthop {
            id: 0x4000_0001,
            kind: KernelNexthopKind::Group {
                member_ids: vec![0x3000_0001],
            },
        });
        h.pre_load_nexthop_op(KernelNexthop {
            id: 0x5000_0001,
            kind: KernelNexthopKind::Member {
                gateway: ip("10.0.0.3"),
            },
        });
        h.pre_load_nexthop_op(KernelNexthop {
            id: 0x6000_0001,
            kind: KernelNexthopKind::Group {
                member_ids: vec![0x5000_0001],
            },
        });

        let l2: Vec<u32> = dp
            .dump_owned_nexthops()
            .await
            .unwrap()
            .into_iter()
            .map(|nh| nh.id)
            .collect();
        assert_eq!(l2, vec![0x3000_0001, 0x4000_0001]);

        let l3: Vec<u32> = dp
            .dump_owned_l3_nexthops()
            .await
            .unwrap()
            .into_iter()
            .map(|nh| nh.id)
            .collect();
        assert_eq!(l3, vec![0x5000_0001, 0x6000_0001]);
    }

    #[tokio::test]
    async fn local_mac_observation_round_trip() {
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        let mut rx = dp
            .take_local_mac_rx()
            .expect("first take returns the receiver");
        // Subsequent take returns None (single-take semantic).
        assert!(dp.take_local_mac_rx().is_none());

        h.inject_local_mac_observation(LocalMacObservation::Learned {
            vni: vni(100),
            mac: mac(1),
            ifindex: 42,
        })
        .await;
        h.inject_local_mac_observation(LocalMacObservation::Aged {
            vni: vni(100),
            mac: mac(1),
        })
        .await;

        let learned = rx.recv().await.unwrap();
        assert!(matches!(learned, LocalMacObservation::Learned { .. }));
        let aged = rx.recv().await.unwrap();
        assert!(matches!(aged, LocalMacObservation::Aged { .. }));
    }

    #[tokio::test]
    async fn local_mac_observation_buffer_overflow_surfaces_full() {
        // Channel capacity is 1024 — fill it without draining and the
        // next try_send must surface `Full`.
        let mut dp = InMemoryDataplane::new();
        let h = dp.handle();
        // Holding the rx alive without recv'ing keeps the buffer full.
        let _rx = dp.take_local_mac_rx().expect("rx");

        for i in 0..1024u32 {
            h.try_inject_local_mac_observation(LocalMacObservation::Learned {
                vni: vni(100),
                mac: MacAddress::new([(i & 0xff) as u8; 6]),
                ifindex: i,
            })
            .expect("buffer not yet full");
        }
        // Slot 1025 must error.
        let err = h
            .try_inject_local_mac_observation(LocalMacObservation::Learned {
                vni: vni(100),
                mac: mac(0xff),
                ifindex: 9999,
            })
            .expect_err("buffer should be full");
        assert!(matches!(err, mpsc::error::TrySendError::Full(_)));
    }
}
