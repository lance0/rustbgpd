//! Error types for the EVPN Linux dataplane reconciler.

use std::net::IpAddr;

use rustbgpd_evpn::{EvpnInstanceId, MacAddress};

/// Errors returned by [`crate::Dataplane`] implementations.
///
/// These errors are *operational* — they describe what happened to the
/// kernel apply, not what's wrong with the desired intent. Per
/// ADR-0054 §8, dataplane failures must not mutate `EvpnInstance`; they
/// surface as report rows the daemon turns into logs and metrics.
#[derive(Debug, thiserror::Error)]
pub enum DataplaneError {
    /// Underlying I/O / netlink transport failure. Retried with
    /// exponential backoff (Phase 3).
    #[error("kernel I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The kernel rejected an operation as malformed — the wrong
    /// arguments were passed, or a flag isn't supported. Not retried;
    /// surfaced to the operator as a configuration / kernel-version
    /// problem (Phase 4 detects this via `EINVAL`).
    #[error("kernel rejected operation: {0}")]
    InvalidArgument(String),

    /// The expected bridge / VXLAN link does not exist. The instance
    /// will be reported `NotReady` until the operator creates it.
    #[error("link not found: {name}")]
    LinkNotFound {
        /// Link name or ifindex string the operation referenced.
        name: String,
    },

    /// `extern_learn` is not supported on this kernel (<4.18). The
    /// affected instance is reported `NotReady` with this message.
    #[error("kernel too old: NTF_EXT_LEARNED not supported (Linux ≥4.18 required)")]
    KernelTooOld,

    /// The kernel rejected the operation with `EPERM` / `EACCES` —
    /// the daemon process lacks `CAP_NET_ADMIN` (or some other
    /// privilege), or an LSM (`SELinux`, `AppArmor`) is denying the
    /// netlink call. Permanent class — retrying without an
    /// out-of-band privilege fix would just hammer the kernel.
    #[error("permission denied: {0} (CAP_NET_ADMIN missing or LSM-blocked)")]
    PermissionDenied(String),

    /// A remote-MAC entry conflicts with a kernel-learned local entry
    /// for the same `(VNI, MAC)`. The diff loop logs and skips; this
    /// variant exists for the [`InMemoryDataplane`] fake to emit
    /// during specific test scenarios.
    ///
    /// [`InMemoryDataplane`]: crate::InMemoryDataplane
    #[error("MAC {mac} in VNI {vni} conflicts with kernel-learned local entry")]
    LocalMacConflict {
        /// Affected VNI.
        vni: EvpnInstanceId,
        /// Conflicting MAC.
        mac: MacAddress,
    },

    /// A remote VTEP IP could not be programmed (e.g., a v6 destination
    /// on a v4-only VXLAN port). Surfaced as `NotReady` for the
    /// affected instance.
    #[error("VTEP destination {dst} unsupported for instance {vni}")]
    UnsupportedVtepDestination {
        /// VNI the program attempt targeted.
        vni: EvpnInstanceId,
        /// Destination IP that was rejected.
        dst: IpAddr,
    },

    /// Generic kernel-side error not classified above. Retried on the
    /// failed-op backoff schedule.
    #[error("kernel error: {0}")]
    Other(String),
}

impl DataplaneError {
    /// Coarse-grained classification used by the actor to decide
    /// whether to retry, escalate to `NotReady`, or surface verbatim.
    #[must_use]
    pub fn class(&self) -> FailureClass {
        match self {
            Self::Io(_) | Self::Other(_) => FailureClass::Transient,
            Self::InvalidArgument(_)
            | Self::LinkNotFound { .. }
            | Self::KernelTooOld
            | Self::PermissionDenied(_)
            | Self::UnsupportedVtepDestination { .. } => FailureClass::Permanent,
            Self::LocalMacConflict { .. } => FailureClass::Conflict,
        }
    }
}

/// How the actor should react to a [`DataplaneError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Transient — retry on the failed-op backoff schedule.
    Transient,
    /// Permanent — do not retry; mark the affected instance(s)
    /// `NotReady` and wait for an external change (kernel, config).
    Permanent,
    /// `(VNI, MAC)` ownership conflict with a kernel-learned local
    /// entry. Logged + skipped; the periodic dump will re-evaluate
    /// after RFC 7432 mobility resolves the race upstream.
    Conflict,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_is_transient() {
        let err: DataplaneError = std::io::Error::other("boom").into();
        assert_eq!(err.class(), FailureClass::Transient);
    }

    #[test]
    fn link_not_found_is_permanent() {
        let err = DataplaneError::LinkNotFound {
            name: "br100".into(),
        };
        assert_eq!(err.class(), FailureClass::Permanent);
    }

    #[test]
    fn local_mac_conflict_is_its_own_class() {
        let err = DataplaneError::LocalMacConflict {
            vni: EvpnInstanceId::new(100).unwrap(),
            mac: MacAddress::new([1; 6]),
        };
        assert_eq!(err.class(), FailureClass::Conflict);
    }

    #[test]
    fn permission_denied_classifies_permanent() {
        let err = DataplaneError::PermissionDenied("EPERM (Operation not permitted)".into());
        assert_eq!(err.class(), FailureClass::Permanent);
    }
}
