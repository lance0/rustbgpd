//! Bridge-port state set via netlink — the single-active AC-gate
//! kernel primitive.
//!
//! Realizes [`crate::dataplane::DataplaneOp::SetAcPortState`] against
//! a real Linux kernel by sending a single `RTM_SETLINK` with
//! `ifi_family = AF_BRIDGE` carrying `IFLA_PROTINFO | NLA_F_NESTED`
//! whose one nested attribute is `IFLA_BRPORT_STATE`
//! (`BR_STATE_DISABLED` to block, `BR_STATE_FORWARDING` to restore).
//! This is the exact wire shape `bridge link set dev <port> state
//! {disabled,forwarding}` produces (iproute2 `bridge/link.c`).
//!
//! ## Why NOT the BUM filter's `set_port` shape
//!
//! The sibling flood-flag primitive (`super::bum_filter`) goes
//! through `RTM_NEWLINK` + `IFLA_INFO_PORT_DATA`
//! (`rtnetlink::LinkHandle::set_port`). That path is **silently
//! wrong for port state**: after `br_setport` applies the attribute,
//! `do_setlink` fires a `NETDEV_CHANGE` notifier, and the bridge's
//! own `br_port_carrier_check` sees the port oper-up and immediately
//! re-enables a just-`DISABLED` port — the kernel ACKs the request
//! and the state reads `forwarding` again. (Empirically reproducible
//! with plain iproute2: `ip link set dev <port> type bridge_slave
//! state 0` ACKs and changes nothing, while `bridge link set dev
//! <port> state disabled` works.) The `RTM_SETLINK`/`AF_BRIDGE`
//! path (`ndo_bridge_setlink` → `br_setlink`) applies the same
//! `br_setport` **without** the `NETDEV_CHANGE` side effect, so the
//! state sticks. The privileged round-trip proof lives in
//! `tests/netns_ac_gate.rs` (`EVPN_LINUX_NETNS=1`).
//!
//! The `IFLA_PROTINFO` attribute is hand-built via [`DefaultNla`]:
//! netlink-packet-route 0.30's typed `LinkAttribute::ProtoInfoBridge`
//! emits `IFLA_PROTINFO` *without* `NLA_F_NESTED`, which the kernel's
//! `br_setlink` would interpret through its legacy non-nested
//! "binary compatibility with old RSTP" branch — reading the first
//! byte of the nested blob as the state value. The raw encode keeps
//! the message byte-exact (pinned by a unit test below).
//!
//! Only the state attribute rides in the message, so the Gate 8b
//! flood-flag triplet on the same port is never touched by a gate
//! transition — `br_setport` applies exactly the attributes present.
//!
//! ## Idempotence + ordering
//!
//! The reconciler resolves desired-vs-**observed** port state per
//! pass (`crate::ac_gate::resolve_ac_gate_plan`) and only emits ops
//! for mismatches, so this layer doesn't dedupe. Observed-state
//! diffing (rather than a remembered plan) is required because the
//! kernel rewrites port state on carrier transitions
//! (`br_port_carrier_check` again — the same helper that invalidates
//! the `set_port` shape above).

use netlink_packet_core::DefaultNla;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use rtnetlink::Handle;

use crate::ac_gate::{BR_STATE_DISABLED, BR_STATE_FORWARDING};
use crate::error::DataplaneError;

/// `IFLA_PROTINFO` — the per-family protocol-info attribute on link
/// messages; for `AF_BRIDGE` it nests the `IFLA_BRPORT_*` set.
const IFLA_PROTINFO: u16 = 12;
/// `NLA_F_NESTED` — must be set on `IFLA_PROTINFO` or `br_setlink`
/// takes the legacy non-nested branch (see module docs).
const NLA_F_NESTED: u16 = 1 << 15;
/// `IFLA_BRPORT_STATE` nested attribute type.
const IFLA_BRPORT_STATE: u16 = 1;

/// Build the nested `IFLA_PROTINFO` payload: one `IFLA_BRPORT_STATE`
/// attribute carrying the `BR_STATE_*` scalar, padded to the 4-byte
/// netlink attribute alignment.
fn protinfo_state_payload(state: u8) -> Vec<u8> {
    let [type_lo, type_hi] = IFLA_BRPORT_STATE.to_le_bytes();
    vec![
        5, 0, // nla_len = NLA_HDRLEN (4) + 1 value byte
        type_lo, type_hi, // nla_type = IFLA_BRPORT_STATE
        state,   // BR_STATE_* scalar
        0, 0, 0, // NLA_ALIGNTO padding
    ]
}

/// Build the full `RTM_SETLINK` link message for one gate transition.
/// Pure — pinned byte-exact by the unit tests; sent by
/// [`apply_ac_port_state`].
fn build_ac_port_state_message(ifindex: u32, blocked: bool) -> LinkMessage {
    let state = if blocked {
        BR_STATE_DISABLED
    } else {
        BR_STATE_FORWARDING
    };
    let mut message = LinkMessage::default();
    message.header.interface_family = AddressFamily::Bridge;
    message.header.index = ifindex;
    message
        .attributes
        .push(LinkAttribute::Other(DefaultNla::new(
            IFLA_PROTINFO | NLA_F_NESTED,
            protinfo_state_payload(state),
        )));
    message
}

/// Set the bridge port at `ifindex` to `BR_STATE_DISABLED`
/// (`blocked`) or `BR_STATE_FORWARDING` via a single
/// `RTM_SETLINK`/`AF_BRIDGE`. Returns `Ok(())` on `NLM_F_ACK`,
/// classified [`DataplaneError`] otherwise.
pub(crate) async fn apply_ac_port_state(
    handle: &Handle,
    ifindex: u32,
    blocked: bool,
) -> Result<(), DataplaneError> {
    if ifindex == 0 {
        return Err(DataplaneError::InvalidArgument(
            "SetAcPortState ifindex 0 is invalid".to_string(),
        ));
    }

    handle
        .link()
        .set(build_ac_port_state_message(ifindex, blocked))
        .execute()
        .await
        .map_err(|e| classify_set_state_error(&e.to_string(), ifindex))
}

/// Classify the stringified rtnetlink error — same
/// substring-dispatch approach as the BUM filter's
/// `classify_set_port_error`, with one difference: `EOPNOTSUPP` /
/// `EINVAL` here mean "the ifindex is not (or no longer) a bridge
/// port" rather than a kernel-version gap (`IFLA_BRPORT_STATE`
/// predates every kernel rustbgpd supports), so they map to
/// [`DataplaneError::InvalidArgument`] — a permanent class that
/// suppresses retries until the op shape changes (the next link-dump
/// re-resolve produces a fresh ifindex).
fn classify_set_state_error(msg: &str, ifindex: u32) -> DataplaneError {
    let lower = msg.to_lowercase();
    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("eperm")
        || lower.contains("eacces")
    {
        DataplaneError::PermissionDenied(msg.to_string())
    } else if lower.contains("no such device") || lower.contains("enodev") {
        DataplaneError::LinkNotFound {
            name: format!("AC bridge port ifindex {ifindex} ({msg})"),
        }
    } else if lower.contains("operation not supported")
        || lower.contains("eopnotsupp")
        || lower.contains("invalid argument")
        || lower.contains("einval")
    {
        DataplaneError::InvalidArgument(format!("ifindex {ifindex} is not a bridge port ({msg})"))
    } else {
        DataplaneError::Other(msg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::Emitable;

    use super::*;

    // The full netlink round-trip lives in the privileged netns test
    // at `tests/netns_ac_gate.rs`. Pinned here: the exact message
    // bytes (the load-bearing NLA_F_NESTED + nested-state shape) and
    // the error classification operators see when something goes
    // wrong.

    /// The message must encode byte-for-byte what iproute2's
    /// `bridge link set dev <port> state <s>` sends: an `AF_BRIDGE`
    /// header, then `IFLA_PROTINFO | NLA_F_NESTED` nesting exactly
    /// one `IFLA_BRPORT_STATE` u8 attribute.
    #[test]
    fn message_encodes_nested_protinfo_state() {
        let message = build_ac_port_state_message(42, true);
        let mut buf = vec![0u8; message.buffer_len()];
        message.emit(&mut buf);

        // ifinfomsg header: family AF_BRIDGE (7), pad, type, flags,
        // index 42, change mask.
        assert_eq!(buf[0], 7, "ifi_family must be AF_BRIDGE");
        assert_eq!(&buf[4..8], &42u32.to_ne_bytes(), "ifi_index");

        // One attribute after the 16-byte ifinfomsg header.
        let attr = &buf[16..];
        assert_eq!(
            u16::from_ne_bytes([attr[0], attr[1]]),
            12,
            "outer nla_len = 4 (hdr) + 8 (nested payload)"
        );
        assert_eq!(
            u16::from_ne_bytes([attr[2], attr[3]]),
            IFLA_PROTINFO | NLA_F_NESTED,
            "IFLA_PROTINFO must carry NLA_F_NESTED or br_setlink \
             takes the legacy non-nested branch"
        );
        // Nested IFLA_BRPORT_STATE attribute.
        let nested = &attr[4..12];
        assert_eq!(u16::from_ne_bytes([nested[0], nested[1]]), 5, "nla_len");
        assert_eq!(
            u16::from_ne_bytes([nested[2], nested[3]]),
            IFLA_BRPORT_STATE,
            "nested type"
        );
        assert_eq!(nested[4], BR_STATE_DISABLED, "blocked => disabled");
        assert_eq!(&nested[5..8], &[0, 0, 0], "alignment padding");
    }

    #[test]
    fn unblock_encodes_forwarding_state() {
        let message = build_ac_port_state_message(7, false);
        let mut buf = vec![0u8; message.buffer_len()];
        message.emit(&mut buf);
        assert_eq!(buf[16 + 4 + 4], BR_STATE_FORWARDING);
    }

    #[test]
    fn classifies_eperm_as_permission_denied() {
        let err = classify_set_state_error("Operation not permitted (EPERM)", 10);
        assert!(matches!(err, DataplaneError::PermissionDenied(_)));
    }

    #[test]
    fn classifies_enodev_as_link_not_found_with_ifindex_in_name() {
        let err = classify_set_state_error("No such device (ENODEV)", 42);
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
    fn classifies_not_a_bridge_port_as_invalid_argument() {
        // EOPNOTSUPP / EINVAL on this path mean "not a bridge port"
        // (e.g. the link was unenslaved between snapshot and apply) —
        // a permanent class, NOT KernelTooOld: IFLA_BRPORT_STATE
        // predates every kernel rustbgpd supports.
        for msg in [
            "Operation not supported (EOPNOTSUPP)",
            "Invalid argument (EINVAL)",
        ] {
            let err = classify_set_state_error(msg, 10);
            match err {
                DataplaneError::InvalidArgument(detail) => {
                    assert!(
                        detail.contains("not a bridge port"),
                        "expected the not-a-bridge-port hint, got {detail}"
                    );
                }
                other => panic!("expected InvalidArgument, got {other:?}"),
            }
        }
    }

    #[test]
    fn classifies_other_as_other() {
        let err = classify_set_state_error("some unfamiliar error", 10);
        assert!(matches!(err, DataplaneError::Other(_)));
    }
}
