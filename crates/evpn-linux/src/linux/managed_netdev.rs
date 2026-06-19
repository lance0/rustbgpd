//! ADR-0091 managed-netdev bridge lifecycle helpers.
//!
//! The reconciler decides when a bridge is desired or safely orphaned.
//! This module owns the Linux netlink mechanics: create the bridge,
//! apply the durable `IFLA_ALT_IFNAME` ownership stamp, and delete only
//! after a fresh dump proves the expected stamp is still present.

use rtnetlink::{Handle, LinkBridge};
use rustbgpd_evpn::parse_ownership_stamp;

use crate::dataplane::DataplaneOp;
use crate::error::DataplaneError;

use super::links::{self, BridgeLink};

const ERRNO_EEXIST: i32 = libc::EEXIST;
const ERRNO_ENODEV: i32 = libc::ENODEV;
const ERRNO_ENOENT: i32 = libc::ENOENT;

pub(super) async fn apply_managed_netdev_op(
    handle: &Handle,
    op: &DataplaneOp,
) -> Option<Result<(), DataplaneError>> {
    match op {
        DataplaneOp::CreateManagedBridge {
            name,
            vlan_filtering,
            ownership_stamp,
        } => Some(create_bridge(handle, name, *vlan_filtering, ownership_stamp).await),
        DataplaneOp::RemoveManagedBridge {
            name,
            ownership_stamp,
        } => Some(remove_bridge(handle, name, ownership_stamp).await),
        _ => None,
    }
}

async fn create_bridge(
    handle: &Handle,
    name: &str,
    vlan_filtering: bool,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let mut fresh = fresh_bridge_state(handle, name).await?;
    if let Some(bridge) = fresh.bridge.as_ref() {
        return ensure_exact_owned_bridge(name, bridge, vlan_filtering, ownership_stamp);
    }
    if fresh.name_exists {
        return Err(foreign_link_collision(name));
    }

    let create_result = handle
        .link()
        .add(LinkBridge::new(name).vlan_filtering(vlan_filtering).build())
        .execute()
        .await;
    let created = match create_result {
        Ok(()) => true,
        Err(err) if is_errno(&err, ERRNO_EEXIST) => false,
        Err(err) => return Err(classify_link_apply_error(&err, "managed bridge create")),
    };

    fresh = fresh_bridge_state(handle, name).await?;
    let Some(bridge) = fresh.bridge.as_ref() else {
        return if fresh.name_exists {
            Err(foreign_link_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed bridge {name} vanished after create"
            )))
        };
    };

    if !created {
        return ensure_exact_owned_bridge(name, bridge, vlan_filtering, ownership_stamp);
    }
    if bridge.altnames.iter().any(|alt| alt == ownership_stamp) {
        return ensure_exact_owned_bridge(name, bridge, vlan_filtering, ownership_stamp);
    }

    let stamp_result = handle
        .link()
        .property_add(bridge.ifindex)
        .alt_ifname(&[ownership_stamp])
        .execute()
        .await;
    match stamp_result {
        Ok(()) => {}
        Err(err) if is_errno(&err, ERRNO_EEXIST) => {}
        Err(err) => {
            return Err(classify_link_apply_error(
                &err,
                "managed bridge altname stamp",
            ));
        }
    }

    let fresh = fresh_bridge_state(handle, name).await?;
    let Some(bridge) = fresh.bridge else {
        return if fresh.name_exists {
            Err(foreign_link_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed bridge {name} vanished after stamp"
            )))
        };
    };
    ensure_exact_owned_bridge(name, &bridge, vlan_filtering, ownership_stamp)
}

async fn remove_bridge(
    handle: &Handle,
    name: &str,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let Some(bridge) = fresh_bridge_state(handle, name).await?.bridge else {
        return Ok(());
    };
    ensure_exact_stamp(name, &bridge, ownership_stamp)?;

    match handle.link().del(bridge.ifindex).execute().await {
        Ok(()) => Ok(()),
        Err(err) if is_errno(&err, ERRNO_ENODEV) || is_errno(&err, ERRNO_ENOENT) => Ok(()),
        Err(err) => Err(classify_link_apply_error(&err, "managed bridge remove")),
    }
}

struct FreshBridgeState {
    bridge: Option<BridgeLink>,
    name_exists: bool,
}

async fn fresh_bridge_state(
    handle: &Handle,
    name: &str,
) -> Result<FreshBridgeState, DataplaneError> {
    let cache = links::dump_links(handle).await?;
    Ok(FreshBridgeState {
        bridge: cache.bridges.get(name).cloned(),
        name_exists: cache.all_link_names.contains(name),
    })
}

fn ensure_exact_owned_bridge(
    name: &str,
    bridge: &BridgeLink,
    vlan_filtering: bool,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_exact_stamp(name, bridge, ownership_stamp)?;
    if bridge.vlan_filtering != vlan_filtering {
        return Err(unsafe_managed_bridge(format!(
            "managed bridge {name} vlan_filtering changed during apply: observed {}, desired {}",
            bridge.vlan_filtering, vlan_filtering
        )));
    }
    Ok(())
}

fn ensure_exact_stamp(
    name: &str,
    bridge: &BridgeLink,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let stamps: Vec<_> = bridge
        .altnames
        .iter()
        .filter_map(|altname| parse_ownership_stamp(altname))
        .collect();
    if stamps.len() == 1 && stamps[0].raw == ownership_stamp && stamps[0].name == name {
        return Ok(());
    }
    Err(unsafe_managed_bridge(format!(
        "managed bridge {name} ownership stamp changed during apply: observed {:?}, expected {ownership_stamp}",
        bridge.altnames
    )))
}

fn is_errno(err: &rtnetlink::Error, errno: i32) -> bool {
    if let rtnetlink::Error::NetlinkError(message) = err {
        i32::try_from(message.raw_code().unsigned_abs()).unwrap_or(0) == errno
    } else {
        false
    }
}

fn classify_link_apply_error(err: &rtnetlink::Error, context: &'static str) -> DataplaneError {
    if let rtnetlink::Error::NetlinkError(message) = err {
        let errno = i32::try_from(message.raw_code().unsigned_abs()).unwrap_or(0);
        let detail = format!("{context}: {}", message.to_io());
        return match errno {
            libc::EPERM | libc::EACCES => DataplaneError::PermissionDenied(detail),
            libc::EOPNOTSUPP => DataplaneError::KernelTooOld {
                feature: "managed bridge netlink lifecycle".to_string(),
            },
            libc::EINVAL => DataplaneError::InvalidArgument(detail),
            _ => DataplaneError::Other(format!("netlink errno {errno}: {detail}")),
        };
    }
    if matches!(err, rtnetlink::Error::RequestFailed) {
        return DataplaneError::Io(std::io::Error::other(format!("{context}: request failed")));
    }
    DataplaneError::Other(format!("{context}: rtnetlink: {err:?}"))
}

fn transient_link_race(message: String) -> DataplaneError {
    DataplaneError::Other(message)
}

fn foreign_link_collision(name: &str) -> DataplaneError {
    unsafe_managed_bridge(format!(
        "managed bridge {name} cannot be created: desired name is occupied by a non-bridge link"
    ))
}

fn unsafe_managed_bridge(message: String) -> DataplaneError {
    DataplaneError::InvalidArgument(message)
}
