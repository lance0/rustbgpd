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

use std::net::IpAddr;

use rustbgpd_evpn::{EvpnInstanceId, EvpnInstanceTable, LocalMacObservation, MacAddress};
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
