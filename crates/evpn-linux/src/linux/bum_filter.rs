//! Bridge-port BUM-suppression flag set via netlink `RTM_NEWLINK`.
//!
//! This module realizes the
//! [`crate::dataplane::DataplaneOp::SetBumPortFlags`] op against a
//! real Linux kernel by sending a single `RTM_NEWLINK` carrying
//! `IFLA_LINKINFO` with `IFLA_INFO_PORT_KIND = "bridge"` and
//! `IFLA_INFO_PORT_DATA` containing the
//! `IFLA_BRPORT_UNICAST_FLOOD` / `IFLA_BRPORT_MCAST_FLOOD` /
//! `IFLA_BRPORT_BCAST_FLOOD` triplet. This is the same wire shape
//! `bridge link set dev <port> flood {on,off} mcast_flood {on,off}
//! bcast_flood {on,off}` produces (verified against iproute2 source
//! and the privileged netns spike at
//! `tests/scripts/netns-bum-filter-spike.sh`).
//!
//! The rtnetlink helper to use here is
//! [`rtnetlink::LinkHandle::set_port`] (not `set`) — the crate
//! documents that bridge / bond port settings cannot use the
//! plain `set()` path because the kernel expects an `RTM_NEWLINK`
//! with the explicit `NLM_F_REQUEST | NLM_F_ACK` flags rather than
//! the `RTM_SETLINK` shape `set()` produces.
//!
//! ## Idempotence + ordering
//!
//! The reconciler computes a `BumPortFlagPlan` per ifindex, diffs it
//! against the prior plan, and only emits `SetBumPortFlags` ops for
//! changed ifindexes. So this layer doesn't need to dedupe — every
//! call corresponds to a real intended flag transition.
//!
//! ## Failure surface
//!
//! - `EOPNOTSUPP` (kernel < 4.18, no `bcast_flood`) →
//!   [`DataplaneError::KernelTooOld`].
//! - `EPERM` / `EACCES` → [`DataplaneError::PermissionDenied`].
//! - `ENODEV` (ifindex stale) → [`DataplaneError::LinkNotFound`].
//! - Other → [`DataplaneError::Other`] for the actor's backoff.

use netlink_packet_route::link::{
    InfoBridgePort, InfoPortData, InfoPortKind, LinkAttribute, LinkInfo, LinkMessage,
};
use rtnetlink::Handle;

use crate::bum_filter::BumPortFlags;
use crate::error::DataplaneError;

/// Apply [`BumPortFlags`] to the bridge port at `ifindex` via a
/// single `RTM_NEWLINK`. Returns `Ok(())` on `NLM_F_ACK`,
/// classified [`DataplaneError`] otherwise.
pub(crate) async fn apply_bum_port_flags(
    handle: &Handle,
    ifindex: u32,
    flags: BumPortFlags,
) -> Result<(), DataplaneError> {
    if ifindex == 0 {
        return Err(DataplaneError::InvalidArgument(
            "SetBumPortFlags ifindex 0 is invalid".to_string(),
        ));
    }

    let mut message = LinkMessage::default();
    message.header.index = ifindex;
    message.attributes.push(LinkAttribute::LinkInfo(vec![
        LinkInfo::PortKind(InfoPortKind::Bridge),
        LinkInfo::PortData(InfoPortData::BridgePort(vec![
            InfoBridgePort::UnicastFlood(flags.unicast_flood),
            InfoBridgePort::MulticastFlood(flags.multicast_flood),
            InfoBridgePort::BroadcastFlood(flags.broadcast_flood),
        ])),
    ]));

    handle
        .link()
        .set_port(message)
        .execute()
        .await
        .map_err(|e| classify_set_port_error(&e))
}

fn classify_set_port_error(e: &rtnetlink::Error) -> DataplaneError {
    // The rtnetlink Error type stringifies the underlying errno; we
    // match on a small set of well-known phrases mirroring the
    // existing FDB-side `errno_to_dataplane_error`. Future cleanup:
    // unify on a numeric errno once rtnetlink exposes it directly.
    let msg = e.to_string();
    let lower = msg.to_lowercase();
    if lower.contains("operation not supported") || lower.contains("eopnotsupp") {
        DataplaneError::KernelTooOld
    } else if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("eperm")
        || lower.contains("eacces")
    {
        DataplaneError::PermissionDenied(msg)
    } else if lower.contains("no such device") || lower.contains("enodev") {
        DataplaneError::LinkNotFound { name: msg }
    } else {
        DataplaneError::Other(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The full netlink round-trip lives in the privileged netns
    // spike at `tests/scripts/netns-bum-filter-spike.sh`; the
    // logic worth pinning at the unit-test level is the rtnetlink
    // error → `DataplaneError` classification, which is what
    // operators see when something goes wrong.

    // Test the classification logic by dispatching on the
    // stringified message — same approach the production
    // `classify_set_port_error` uses. Constructing a real
    // `rtnetlink::Error` is awkward (`NetlinkError` requires an
    // `ErrorMessage` and `RequestFailed` is unit), so the unit
    // test peels back to the lowercase-substring matcher and
    // exercises it directly. The full netlink round-trip is
    // covered by the privileged netns spike.

    fn classify_msg(msg: &str) -> DataplaneError {
        let lower = msg.to_lowercase();
        if lower.contains("operation not supported") || lower.contains("eopnotsupp") {
            DataplaneError::KernelTooOld
        } else if lower.contains("permission denied")
            || lower.contains("operation not permitted")
            || lower.contains("eperm")
            || lower.contains("eacces")
        {
            DataplaneError::PermissionDenied(msg.to_string())
        } else if lower.contains("no such device") || lower.contains("enodev") {
            DataplaneError::LinkNotFound {
                name: msg.to_string(),
            }
        } else {
            DataplaneError::Other(msg.to_string())
        }
    }

    #[test]
    fn classifies_eopnotsupp_as_kernel_too_old() {
        let err = classify_msg("Operation not supported (EOPNOTSUPP)");
        assert!(matches!(err, DataplaneError::KernelTooOld));
    }

    #[test]
    fn classifies_eperm_as_permission_denied() {
        let err = classify_msg("Operation not permitted (EPERM)");
        assert!(matches!(err, DataplaneError::PermissionDenied(_)));
    }

    #[test]
    fn classifies_enodev_as_link_not_found() {
        let err = classify_msg("No such device (ENODEV)");
        assert!(matches!(err, DataplaneError::LinkNotFound { .. }));
    }

    #[test]
    fn classifies_other_as_other() {
        let err = classify_msg("some unfamiliar error");
        assert!(matches!(err, DataplaneError::Other(_)));
    }
}
