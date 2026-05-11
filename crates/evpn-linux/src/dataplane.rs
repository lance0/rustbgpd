//! [`Dataplane`] trait — the abstract interface the reconcile actor
//! drives.
//!
//! Two implementations exist:
//!
//! - [`crate::InMemoryDataplane`] (Phase 2) — the test fake. All
//!   platforms.
//! - `LinuxDataplane` (Phase 4, behind `cfg(target_os = "linux")`) —
//!   the real netlink impl.
//!
//! The actor is generic over `D: Dataplane`, so the same `tokio::select!`
//! loop drives both impls. Diff-loop unit tests live in `src/diff.rs`
//! and don't touch this trait at all (they're pure functions over
//! [`KernelSnapshot`] + [`rustbgpd_evpn::RemoteMacTable`]).
//!
//! ## Native `async fn` in trait
//!
//! Workspace MSRV is Rust 1.92, so `async fn` in trait is stable. The
//! actor is generic over `D: Dataplane`, so we don't need
//! `dyn Dataplane` and don't need the `async-trait` macro. Trait
//! methods return RPITIT (`-> impl Future + Send`) implicitly via the
//! `async fn` syntax.
//!
//! ## Reference
//!
//! - ADR-0054 §3 (kernel observation surface)
//! - ADR-0054 §6 (reconcile-on-event plus periodic full resync)

use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_evpn::ip_vrf::{IpVrfRouteDump, IpVrfStatus, IpVrfTable};
use rustbgpd_evpn::{EvpnInstanceId, EvpnInstanceTable, IpVrfId, LocalMacObservation, MacAddress};
#[cfg_attr(not(test), allow(unused_imports))]
use tokio::sync::mpsc;

use crate::error::DataplaneError;
use crate::snapshot::{InstanceProbes, KernelSnapshot};

/// Single dataplane operation the actor asks the implementation to
/// apply.
///
/// One-to-one with [`rustbgpd_evpn::DataplaneOpKind`] but carries the
/// `(VNI, MAC)` key inline so the trait method signature is uniform.
/// The reconcile actor translates between the two when emitting
/// reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataplaneOp {
    /// Program a fresh remote-MAC FDB entry for `(vni, mac)` pointing
    /// at `dst`. Implementations should set `NTF_EXT_LEARNED` and
    /// route through the bridge/master path per ADR-0054 §5.
    AddRemoteFdb {
        /// EVPN instance identifying the bridge / VXLAN port.
        vni: EvpnInstanceId,
        /// MAC the entry programs.
        mac: MacAddress,
        /// Remote VTEP destination IP.
        dst: IpAddr,
    },
    /// Update an existing remote-MAC entry to a new VTEP destination
    /// (mobility — same MAC, different remote VTEP).
    UpdateRemoteFdb {
        /// EVPN instance identifying the bridge / VXLAN port.
        vni: EvpnInstanceId,
        /// MAC the entry programs.
        mac: MacAddress,
        /// New remote VTEP destination IP.
        dst: IpAddr,
    },
    /// Withdraw a previously-programmed remote-MAC entry. The
    /// implementation must only act on entries it owns
    /// (`NTF_EXT_LEARNED`); the actor's [`crate::OwnedSet`] makes that
    /// a structural property by iterating only owned keys at the diff
    /// level.
    RemoveRemoteFdb {
        /// EVPN instance the withdrawal targets.
        vni: EvpnInstanceId,
        /// MAC the entry programmed.
        mac: MacAddress,
    },
    /// Apply the per-port flood-flag triplet to a CE-facing bridge
    /// port (Gate 8b BUM-suppression primitive). Realized in
    /// [`crate::LinuxDataplane`] via a single `RTM_NEWLINK`
    /// (sent through `rtnetlink::LinkHandle::set_port`) carrying
    /// `IFLA_LINKINFO` with `IFLA_INFO_PORT_KIND = "bridge"` and
    /// `IFLA_INFO_PORT_DATA` holding the
    /// `IFLA_BRPORT_UNICAST_FLOOD` / `IFLA_BRPORT_MCAST_FLOOD` /
    /// `IFLA_BRPORT_BCAST_FLOOD` triplet. Implementations failing
    /// to apply the triplet surface
    /// [`DataplaneError::KernelTooOld`] (`EOPNOTSUPP`),
    /// [`DataplaneError::PermissionDenied`] (`EPERM` / `EACCES`),
    /// [`DataplaneError::LinkNotFound`] (`ENODEV` — stale
    /// ifindex), [`DataplaneError::InvalidArgument`]
    /// (caller-side guard, e.g. ifindex 0), or
    /// [`DataplaneError::Other`] (catch-all that the actor's
    /// backoff retries). The reconcile actor records the failure
    /// and the operator sees it via
    /// [`rustbgpd_evpn::DataplaneReport::failed`].
    SetBumPortFlags {
        /// CE-facing bridge port ifindex.
        ifindex: u32,
        /// Desired flag triplet for this port.
        flags: crate::bum_filter::BumPortFlags,
    },
}

/// Kernel-side notifications the actor consumes through
/// [`Dataplane::next_event`]. Phase 2 only emits a small subset; Phase 4
/// extends with the full `RTNLGRP_LINK` / `RTNLGRP_NEIGH` event set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelEvent {
    /// Some FDB or link state changed — wake the reconcile loop. The
    /// next dump will surface what changed; we don't carry deltas
    /// because the reconcile is level-triggered (ADR-0054 §6).
    KernelStateChanged,
    /// Local MAC observation flowing upward to the domain layer.
    /// Phase 2 doesn't act on these; the reconcile actor forwards
    /// them through [`crate::Dataplane::next_event`] verbatim and the
    /// daemon will route them in Phase 5.
    LocalMacObservation(rustbgpd_evpn::LocalMacObservation),
}

/// Trait the reconcile actor drives.
///
/// Implementations own the kernel-state side of the boundary —
/// netlink sockets, internal state, retry queues. The actor never
/// touches netlink directly; everything goes through this trait.
pub trait Dataplane: Send {
    /// Probe each instance against the kernel-observed topology and
    /// produce per-instance `Ready` / `NotReady` / `Unbound` results.
    /// The actor calls this on every reconcile pass so probe outcomes
    /// reflect current kernel state.
    fn probe(
        &mut self,
        instances: &EvpnInstanceTable,
    ) -> impl Future<Output = InstanceProbes> + Send;

    /// Probe each configured IP-VRF against the kernel-observed
    /// topology and produce per-VRF [`IpVrfStatus`] verdicts (Gate 9,
    /// ADR-0058 §3). Intended to be called on every reconcile pass so
    /// readiness reflects current kernel state; the call site itself
    /// lives with the rest of the reconcile-actor wiring (intent
    /// plumbing slice).
    ///
    /// Default returns an empty map — implementations that don't
    /// support Gate 9 (`InMemoryDataplane`, future non-Linux impls)
    /// silently no-op for IP-VRFs. The trait extension stays
    /// non-breaking because of this default.
    fn probe_ip_vrfs(
        &mut self,
        _ip_vrfs: &IpVrfTable,
    ) -> impl Future<Output = HashMap<IpVrfId, IpVrfStatus>> + Send {
        async { HashMap::new() }
    }

    /// Dump every kernel route in each configured IP-VRF's
    /// `table_id`, classify it, and produce per-VRF observations the
    /// daemon's L3 originator (slice 6b) can subscribe to. Counters
    /// for filtered routes ride alongside on
    /// [`IpVrfRouteDump::filter_counts`].
    ///
    /// Returns `None` on transient kernel-dump failure. The
    /// reconciler forwards `None` to the daemon, which preserves the
    /// last successful observation snapshot in its watch channel
    /// rather than synthesizing an empty dump — a swallowed dump
    /// failure would otherwise look identical to "the kernel has no
    /// routes" and the L3 originator would withdraw every
    /// currently-originated Type 5 (ADR-0054 §6 level-triggered
    /// model requires "don't advance state on failure", not "publish
    /// empty"). Implementations log the underlying error before
    /// returning `None`.
    ///
    /// Default returns `Some(IpVrfRouteDump::default())` —
    /// implementations that don't support Gate 9
    /// (`InMemoryDataplane`, future non-Linux impls) silently no-op
    /// for IP-VRF routes (zero VRFs configured → no observations,
    /// no failure either). The trait extension stays non-breaking
    /// via this default.
    fn dump_ip_vrf_routes(
        &mut self,
        _ip_vrfs: &IpVrfTable,
    ) -> impl Future<Output = Option<IpVrfRouteDump>> + Send {
        async { Some(IpVrfRouteDump::default()) }
    }

    /// Dump the current kernel FDB + link inventory.
    fn dump_snapshot(
        &mut self,
    ) -> impl Future<Output = Result<KernelSnapshot, DataplaneError>> + Send;

    /// Apply one [`DataplaneOp`]. Errors are returned per-op so the
    /// actor can record `applied` vs `failed` granularly.
    fn apply(
        &mut self,
        op: &DataplaneOp,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Wait for the next kernel event, or shutdown signal. Returning
    /// `None` is the implementation's request that the actor should
    /// no longer call this method (e.g., the netlink subscription
    /// closed). The actor falls back to its periodic dump cadence in
    /// that case.
    fn next_event(&mut self) -> impl Future<Output = Option<KernelEvent>> + Send;

    /// Take ownership of the upward `LocalMacObservation` channel
    /// receiver, if the implementation surfaces one.
    ///
    /// Called **once** at construction time by the daemon; subsequent
    /// calls return `None`. The originator (`src/evpn_originator.rs`)
    /// owns the receiver for its lifetime, running its own
    /// `tokio::select!` loop on it independently of the reconcile
    /// actor's `next_event()` loop.
    ///
    /// A dedicated channel is intentionally **not** routed through
    /// [`KernelEvent::LocalMacObservation`] + the reconcile actor —
    /// that path would couple the originator's channel layout to the
    /// reconcile actor and force the actor to outlive the originator.
    /// Splitting the upward observation flow at the trait boundary
    /// keeps the two consumers independent (ADR-0054 §1's "narrow
    /// interface" rule).
    ///
    /// Implementations that do not surface local MAC observations
    /// (e.g., `LinuxDataplane` until `RTNLGRP_NEIGH` subscription
    /// lands in Phase D-real) return `None`. The originator treats
    /// `None` as "no live observation feed available" and stays
    /// quiescent.
    fn take_local_mac_rx(&mut self) -> Option<mpsc::Receiver<LocalMacObservation>> {
        // Default impl returns None — implementations override only
        // when they actually surface observations. This keeps the
        // trait extension non-breaking for downstream impls.
        None
    }
}
