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
//! - `EOPNOTSUPP` → [`DataplaneError::KernelTooOld`], naming the
//!   required `bcast_flood` feature (upstream Linux 4.12). The errno
//!   does not establish the kernel version or exact unsupported feature.
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
        .map_err(|e| classify_set_port_error(&e, ifindex))
}

fn classify_set_port_error(e: &rtnetlink::Error, ifindex: u32) -> DataplaneError {
    // Preserve the existing classification of rtnetlink's errno text.
    let msg = e.to_string();
    let lower = msg.to_lowercase();
    if lower.contains("operation not supported") || lower.contains("eopnotsupp") {
        // Broadcast flood control arrived in upstream Linux 4.12;
        // EOPNOTSUPP alone does not identify the unsupported feature.
        DataplaneError::KernelTooOld {
            feature: "IFLA_BRPORT_BCAST_FLOOD (Linux ≥4.12)".to_string(),
        }
    } else if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("eperm")
        || lower.contains("eacces")
    {
        DataplaneError::PermissionDenied(msg)
    } else if lower.contains("no such device") || lower.contains("enodev") {
        // The ifindex the operator can act on, plus the underlying
        // errno text for context. Without the ifindex the report is
        // an opaque blob no operator can correlate.
        DataplaneError::LinkNotFound {
            name: format!("bridge port ifindex {ifindex} ({msg})"),
        }
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

    fn netlink_error(errno: i32) -> rtnetlink::Error {
        let mut message = netlink_packet_core::ErrorMessage::default();
        message.code = std::num::NonZeroI32::new(-errno);
        rtnetlink::Error::NetlinkError(message)
    }

    #[test]
    fn classifies_eopnotsupp_as_kernel_too_old_with_bcast_flood_feature() {
        let err = classify_set_port_error(&netlink_error(libc::EOPNOTSUPP), 10);
        match err {
            DataplaneError::KernelTooOld { feature } => {
                assert_eq!(feature, "IFLA_BRPORT_BCAST_FLOOD (Linux ≥4.12)");
            }
            other => panic!("expected KernelTooOld, got {other:?}"),
        }
    }

    #[test]
    fn classifies_eperm_as_permission_denied() {
        let err = classify_set_port_error(&netlink_error(libc::EPERM), 10);
        assert!(matches!(err, DataplaneError::PermissionDenied(_)));
    }

    #[test]
    fn classifies_enodev_as_link_not_found_with_ifindex_in_name() {
        let err = classify_set_port_error(&netlink_error(libc::ENODEV), 42);
        match err {
            DataplaneError::LinkNotFound { name } => {
                assert!(
                    name.contains("ifindex 42"),
                    "ENODEV must surface the targeted ifindex in `name`, got {name}"
                );
            }
            other => panic!("expected LinkNotFound, got {other:?}"),
        }
    }

    #[test]
    fn classifies_other_as_other() {
        let err = classify_set_port_error(&rtnetlink::Error::RequestFailed, 10);
        assert!(matches!(err, DataplaneError::Other(_)));
    }
}
