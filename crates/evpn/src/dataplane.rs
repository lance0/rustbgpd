//! Dataplane intent and report types — Gate 7b boundary.
//!
//! The daemon publishes [`DataplaneIntent`] snapshots to the Linux
//! dataplane crate (`crates/evpn-linux`) over a
//! `tokio::sync::watch::Sender<Arc<DataplaneIntent>>`. The dataplane
//! actor reconciles its kernel state toward each received snapshot and
//! returns [`DataplaneReport`] values describing what was applied or
//! failed against the corresponding `intent_generation`.
//!
//! These types live in `crates/evpn` rather than `crates/evpn-linux`
//! deliberately — see ADR-0054 §1 / §2 — so that:
//!
//! - The daemon can construct intents on platforms that don't compile
//!   the netlink crate (macOS dev builds).
//! - A future RR-only feature flag can drop `rustbgpd-evpn-linux`
//!   entirely while leaving the intent surface untouched.
//! - The diff and projection unit tests run with no Linux dependencies.
//!
//! ## Reference
//!
//! - ADR-0054 §2 (snapshot/watch input)
//! - ADR-0054 §8 (failures surface as status, not domain mutation)

use std::net::IpAddr;
use std::sync::Arc;

use crate::mac::{MacAddress, RemoteMacTable};
use crate::{EvpnInstanceId, EvpnInstanceTable};

/// Complete desired-state snapshot fed to the Linux dataplane.
///
/// The `generation` counter is the daemon's monotonic publish counter.
/// The dataplane echoes it back on [`DataplaneReport::intent_generation`]
/// so the daemon can correlate "I sent gen N" with "Linux applied/failed
/// gen N" without timestamp guesswork.
///
/// `instances` and `remote_macs` are `Arc` so the daemon can re-publish
/// a near-identical snapshot (e.g., only the [`RemoteMacTable`] changed)
/// without cloning the full instance table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneIntent {
    /// Daemon-side monotonic counter. Strictly increases.
    pub generation: u64,
    /// Desired EVPN instance set on this VTEP.
    pub instances: Arc<EvpnInstanceTable>,
    /// Desired remote-MAC programming for the kernel FDB.
    pub remote_macs: Arc<RemoteMacTable>,
}

impl DataplaneIntent {
    /// Construct an empty intent at generation 0. Suitable as the
    /// initial value of a `watch` channel before the first real
    /// publish lands.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            generation: 0,
            instances: Arc::new(EvpnInstanceTable::new()),
            remote_macs: Arc::new(RemoteMacTable::new()),
        }
    }
}

/// Result of a single reconcile pass.
///
/// A report is emitted after every reconcile, including no-op passes
/// where `applied` and `failed` are empty — that's the heartbeat the
/// daemon uses to verify the actor is healthy. `instance_status` is
/// re-emitted on every report so subscribers don't need to track
/// transitions themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneReport {
    /// Echoes [`DataplaneIntent::generation`] of the snapshot this
    /// pass acted on.
    pub intent_generation: u64,
    /// Dataplane actor's own monotonic reconcile-pass counter, useful
    /// for metrics and debugging when many reports map to the same
    /// `intent_generation` (e.g., periodic-dump-driven re-reconciles).
    pub reconcile_generation: u64,
    /// One status row per instance in the desired snapshot.
    pub instance_status: Vec<InstanceDataplaneStatus>,
    /// Successfully-applied operations from this pass.
    pub applied: Vec<AppliedOp>,
    /// Operations that failed and are queued for retry.
    pub failed: Vec<FailedOp>,
}

/// Per-instance status emitted alongside every report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceDataplaneStatus {
    /// VNI this row describes.
    pub vni: EvpnInstanceId,
    /// Coarse-grained state.
    pub state: InstanceState,
    /// Optional human-readable explanation. Populated for `NotReady`
    /// states; empty for `Ready` and `Unbound`.
    pub message: Option<String>,
    /// Linux bridge MAC address if known. `Some` only when the
    /// dataplane has observed a `Ready` bridge with a captured
    /// MAC; `None` for `NotReady` / `Unbound` rows or when the
    /// bridge has no link-layer address attached. Surfaced through
    /// the report (rather than reaching into the dataplane's
    /// `LinkCache`) so the SVI-MAC origination path stays on the
    /// ADR-0054 §1 boundary — Linux observes, daemon decides.
    pub bridge_mac: Option<MacAddress>,
}

/// Coarse-grained per-instance dataplane state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    /// All probe checks passed; remote MACs for this instance are
    /// being reconciled into the kernel FDB.
    Ready,
    /// Bridge missing, VXLAN port missing/mismatched, learning mode
    /// wrong, VLAN-aware bridge, or local IP mismatched. Remote MACs
    /// for this instance are NOT programmed; existing kernel state is
    /// not modified. Detail in [`InstanceDataplaneStatus::message`].
    NotReady,
    /// Instance has `bridge = None` — never enters the dataplane
    /// reconcile loop. Visible via `ListEvpnInstances` but inert.
    Unbound,
}

/// A single dataplane operation that was successfully applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedOp {
    /// VNI the operation acted on.
    pub vni: EvpnInstanceId,
    /// What the operation did.
    pub kind: DataplaneOpKind,
}

/// A single dataplane operation that failed and is queued for retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedOp {
    /// VNI the operation tried to act on.
    pub vni: EvpnInstanceId,
    /// What the operation tried to do.
    pub kind: DataplaneOpKind,
    /// Human-readable error string from the dataplane crate. Stable
    /// enough for log correlation; not parsed.
    pub error: String,
    /// Backoff before this op is retried, in milliseconds.
    pub retry_in_ms: u32,
}

/// Discriminator for [`AppliedOp`] / [`FailedOp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataplaneOpKind {
    /// Add a remote-MAC FDB entry pointing at `dst` (the remote VTEP IP).
    AddRemoteFdb {
        /// MAC the entry programs.
        mac: MacAddress,
        /// Remote VTEP destination IP.
        dst: IpAddr,
    },
    /// Update an existing remote-MAC entry to point at a new VTEP IP
    /// (e.g., MAC mobility — same MAC, different remote).
    UpdateRemoteFdb {
        /// MAC the entry programs.
        mac: MacAddress,
        /// New remote VTEP destination IP.
        dst: IpAddr,
    },
    /// Withdraw a previously-programmed remote-MAC entry.
    RemoveRemoteFdb {
        /// MAC the entry programmed.
        mac: MacAddress,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_intent_is_generation_zero() {
        let intent = DataplaneIntent::empty();
        assert_eq!(intent.generation, 0);
        assert!(intent.instances.is_empty());
        assert!(intent.remote_macs.is_empty());
    }

    #[test]
    fn empty_intents_compare_equal() {
        // Equality on Arc<EvpnInstanceTable> compares contents, not
        // pointer identity — two independently-constructed empties
        // should still be equal.
        assert_eq!(DataplaneIntent::empty(), DataplaneIntent::empty());
    }

    #[test]
    fn instance_state_is_copy() {
        let s = InstanceState::Ready;
        let t = s;
        assert_eq!(s, InstanceState::Ready);
        assert_eq!(t, s);
    }

    #[test]
    fn op_kind_distinguishes_add_update_remove() {
        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);
        let dst: IpAddr = "10.0.0.1".parse().unwrap();
        let add = DataplaneOpKind::AddRemoteFdb { mac, dst };
        let upd = DataplaneOpKind::UpdateRemoteFdb { mac, dst };
        let rem = DataplaneOpKind::RemoveRemoteFdb { mac };
        assert_ne!(add, upd);
        assert_ne!(add, rem);
        assert_ne!(upd, rem);
    }

    #[test]
    fn instance_dataplane_status_round_trips_bridge_mac() {
        // ADR-0054 §1: bridge MAC surfaces from the Linux dataplane
        // through `InstanceDataplaneStatus.bridge_mac` rather than via
        // a back-channel into the dataplane crate's LinkCache.
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0xAB]);
        let status = InstanceDataplaneStatus {
            vni: EvpnInstanceId::new(100).unwrap(),
            state: InstanceState::Ready,
            message: None,
            bridge_mac: Some(mac),
        };
        // Equality comparison preserves the field — the daemon's SVI
        // task will memcmp full status rows when deciding whether a
        // re-emission is a no-op.
        let clone = status.clone();
        assert_eq!(status, clone);
        assert_eq!(status.bridge_mac, Some(mac));
    }

    #[test]
    fn intent_generation_increments_via_struct_update() {
        // Demonstrate the daemon-side publish pattern: clone the
        // existing intent, bump generation, swap the table Arc.
        let prev = DataplaneIntent::empty();
        let next = DataplaneIntent {
            generation: prev.generation + 1,
            ..prev.clone()
        };
        assert_eq!(next.generation, 1);
        assert_eq!(prev.generation, 0);
    }
}
