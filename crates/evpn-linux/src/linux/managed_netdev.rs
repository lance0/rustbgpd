//! ADR-0091 managed-netdev link lifecycle helpers.
//!
//! The reconciler decides when a bridge is desired or safely orphaned.
//! This module owns the Linux netlink mechanics: create the link, apply
//! the durable `IFLA_ALT_IFNAME` ownership stamp, and delete only after a
//! fresh dump proves the expected stamp is still present.

use std::net::IpAddr;

use netlink_packet_route::link::{
    AfSpecBridge, BridgeVlanInfoFlags, BridgeVlanTunnelInfo, InfoVxlan,
};
use rtnetlink::{
    Handle, LinkBridge, LinkBridgePort, LinkBridgeVlan, LinkMessageBuilder, LinkUnspec, LinkVlan,
    LinkVrf, LinkVxlan,
};
use rustbgpd_evpn::{
    ManagedL3VxlanNetdevSpec, ManagedSvdVxlanBinding, ManagedSvdVxlanNetdevSpec,
    ManagedVlanUpperNetdevSpec, ManagedVrfNetdevSpec, ManagedVxlanNetdevSpec,
    parse_ownership_stamp,
};

use crate::dataplane::DataplaneOp;
use crate::error::DataplaneError;

use super::links::{self, BridgeLink};
use crate::snapshot::{
    KernelVlanUpperLinkInfo, KernelVrfLinkInfo, KernelVxlanLinkInfo, svd_tunnel_bindings,
    vlan_rows_contain,
};

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
        DataplaneOp::CreateManagedVxlan {
            name,
            spec,
            ownership_stamp,
        } => Some(create_vxlan(handle, name, spec, ownership_stamp).await),
        DataplaneOp::RemoveManagedVxlan {
            name,
            ownership_stamp,
        } => Some(remove_vxlan(handle, name, ownership_stamp).await),
        DataplaneOp::CreateManagedSvdVxlan {
            name,
            spec,
            ownership_stamp,
        } => Some(create_svd_vxlan(handle, name, spec, ownership_stamp).await),
        DataplaneOp::RemoveManagedSvdVxlan {
            name,
            ownership_stamp,
        } => Some(remove_svd_vxlan(handle, name, ownership_stamp).await),
        DataplaneOp::CreateManagedVrf {
            name,
            spec,
            ownership_stamp,
        } => Some(create_vrf(handle, name, spec, ownership_stamp).await),
        DataplaneOp::RemoveManagedVrf {
            name,
            ownership_stamp,
        } => Some(remove_vrf(handle, name, ownership_stamp).await),
        DataplaneOp::CreateManagedL3Vxlan {
            name,
            spec,
            ownership_stamp,
        } => Some(create_l3vxlan(handle, name, spec, ownership_stamp).await),
        DataplaneOp::RemoveManagedL3Vxlan {
            name,
            ownership_stamp,
        } => Some(remove_l3vxlan(handle, name, ownership_stamp).await),
        DataplaneOp::CreateManagedVlanUpper {
            name,
            spec,
            ownership_stamp,
        } => Some(create_vlan_upper(handle, name, spec, ownership_stamp).await),
        DataplaneOp::RemoveManagedVlanUpper {
            name,
            ownership_stamp,
        } => Some(remove_vlan_upper(handle, name, ownership_stamp).await),
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
        return adopt_existing_bridge(handle, name, bridge, vlan_filtering, ownership_stamp).await;
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

    if !created || bridge.altnames.iter().any(|alt| alt == ownership_stamp) {
        return adopt_existing_bridge(handle, name, bridge, vlan_filtering, ownership_stamp).await;
    }

    let stamped_ifindex = bridge.ifindex;
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
            let stamp_err = classify_link_apply_error(&err, "managed bridge altname stamp");
            rollback_unstamped_create(handle, bridge.ifindex, name, "managed bridge").await;
            return Err(stamp_err);
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
    ensure_stamp_landed_or_roll_back(
        handle,
        stamped_ifindex,
        bridge.ifindex,
        &bridge.altnames,
        name,
        ownership_stamp,
        "managed bridge",
    )
    .await?;
    adopt_existing_bridge(handle, name, &bridge, vlan_filtering, ownership_stamp).await
}

/// LAN-2894: adopt an exactly-ours bridge and raise it when it is
/// administratively down. Admin state is not a protected attribute
/// (ADR-0091 Decision 3), so a down link whose stamp and attributes match
/// is ours to bring up, like the VLAN upper (LAN-290).
async fn adopt_existing_bridge(
    handle: &Handle,
    name: &str,
    bridge: &BridgeLink,
    vlan_filtering: bool,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_bridge_stamp_and_attrs(name, bridge, vlan_filtering, ownership_stamp)?;
    if bridge.up {
        return Ok(());
    }
    set_link_up(handle, bridge.ifindex, "managed bridge set up")
        .await
        .map_err(retryable_completion)?;
    let fresh = fresh_bridge_state(handle, name).await?;
    let Some(bridge) = fresh.bridge else {
        return Err(transient_link_race(format!(
            "managed bridge {name} vanished after set up"
        )));
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

async fn create_vxlan(
    handle: &Handle,
    name: &str,
    spec: &ManagedVxlanNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let mut fresh = fresh_vxlan_state(handle, name).await?;
    if let Some(vxlan) = fresh.vxlan.as_ref() {
        return adopt_existing_vxlan(handle, name, vxlan, spec, ownership_stamp).await;
    }
    if fresh.name_exists {
        return Err(foreign_vxlan_collision(name));
    }

    let bridge_ifindex = fresh
        .bridges
        .get(&spec.bridge)
        .map(|bridge| bridge.ifindex)
        .ok_or_else(|| {
            missing_vxlan_bridge(
                name,
                &spec.bridge,
                fresh.all_link_names.contains(&spec.bridge),
            )
        })?;

    let mut builder = LinkVxlan::new(name, spec.vni)
        .port(spec.dstport)
        .learning(false)
        .controller(bridge_ifindex)
        .up();
    builder = match spec.local_ip {
        IpAddr::V4(addr) => builder.local(addr),
        IpAddr::V6(addr) => builder.local6(addr),
    };

    let create_result = handle.link().add(builder.build()).execute().await;
    let created = match create_result {
        Ok(()) => true,
        Err(err) if is_errno(&err, ERRNO_EEXIST) => false,
        Err(err) => return Err(classify_link_apply_error(&err, "managed VXLAN create")),
    };

    fresh = fresh_vxlan_state(handle, name).await?;
    let Some(vxlan) = fresh.vxlan.as_ref() else {
        return if fresh.name_exists {
            Err(foreign_vxlan_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed VXLAN {name} vanished after create"
            )))
        };
    };

    if !created || vxlan.altnames.iter().any(|alt| alt == ownership_stamp) {
        return adopt_existing_vxlan(handle, name, vxlan, spec, ownership_stamp).await;
    }

    let stamped_ifindex = vxlan.ifindex;
    let stamp_result = handle
        .link()
        .property_add(vxlan.ifindex)
        .alt_ifname(&[ownership_stamp])
        .execute()
        .await;
    match stamp_result {
        Ok(()) => {}
        Err(err) if is_errno(&err, ERRNO_EEXIST) => {}
        Err(err) => {
            let stamp_err = classify_link_apply_error(&err, "managed VXLAN altname stamp");
            rollback_unstamped_create(handle, vxlan.ifindex, name, "managed VXLAN").await;
            return Err(stamp_err);
        }
    }

    let fresh = fresh_vxlan_state(handle, name).await?;
    let Some(vxlan) = fresh.vxlan else {
        return if fresh.name_exists {
            Err(foreign_vxlan_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed VXLAN {name} vanished after stamp"
            )))
        };
    };
    ensure_stamp_landed_or_roll_back(
        handle,
        stamped_ifindex,
        vxlan.ifindex,
        &vxlan.altnames,
        name,
        ownership_stamp,
        "managed VXLAN",
    )
    .await?;
    adopt_existing_vxlan(handle, name, &vxlan, spec, ownership_stamp).await
}

/// LAN-2894: adopt an exactly-ours fixed-VNI VXLAN and raise it when it is
/// administratively down; see [`adopt_existing_bridge`].
async fn adopt_existing_vxlan(
    handle: &Handle,
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    spec: &ManagedVxlanNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_vxlan_stamp_and_attrs(name, vxlan, spec, ownership_stamp)?;
    if vxlan.up {
        return Ok(());
    }
    set_link_up(handle, vxlan.ifindex, "managed VXLAN set up")
        .await
        .map_err(retryable_completion)?;
    let fresh = fresh_vxlan_state(handle, name).await?;
    let Some(vxlan) = fresh.vxlan else {
        return Err(transient_link_race(format!(
            "managed VXLAN {name} vanished after set up"
        )));
    };
    ensure_exact_owned_vxlan(name, &vxlan, spec, ownership_stamp)
}

async fn remove_vxlan(
    handle: &Handle,
    name: &str,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let Some(vxlan) = fresh_vxlan_state(handle, name).await?.vxlan else {
        return Ok(());
    };
    ensure_exact_vxlan_stamp(name, &vxlan, ownership_stamp)?;

    match handle.link().del(vxlan.ifindex).execute().await {
        Ok(()) => Ok(()),
        Err(err) if is_errno(&err, ERRNO_ENODEV) || is_errno(&err, ERRNO_ENOENT) => Ok(()),
        Err(err) => Err(classify_link_apply_error(&err, "managed VXLAN remove")),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "create, stamp, stamp confirmation and binding convergence stay in one ordered sequence"
)]
async fn create_svd_vxlan(
    handle: &Handle,
    name: &str,
    spec: &ManagedSvdVxlanNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let mut fresh = fresh_vxlan_state(handle, name).await?;
    if let Some(vxlan) = fresh.vxlan.as_ref() {
        return ensure_svd_vxlan_converged(
            handle,
            name,
            vxlan,
            spec,
            ownership_stamp,
            &fresh.bridges,
        )
        .await;
    }
    if fresh.name_exists {
        return Err(foreign_svd_vxlan_collision(name));
    }

    let bridge_ifindex = fresh
        .bridges
        .get(&spec.bridge)
        .map(|bridge| bridge.ifindex)
        .ok_or_else(|| {
            missing_svd_vxlan_bridge(
                name,
                &spec.bridge,
                fresh.all_link_names.contains(&spec.bridge),
            )
        })?;

    let mut builder = LinkMessageBuilder::<LinkVxlan>::new(name)
        .port(spec.dstport)
        .learning(false)
        .collect_metadata(true)
        .append_info_data(InfoVxlan::Vnifilter(true))
        .controller(bridge_ifindex)
        .up();
    builder = match spec.local_ip {
        Some(IpAddr::V4(addr)) => builder.local(addr),
        Some(IpAddr::V6(addr)) => builder.local6(addr),
        None => builder,
    };

    let create_result = handle.link().add(builder.build()).execute().await;
    let created = match create_result {
        Ok(()) => true,
        Err(err) if is_errno(&err, ERRNO_EEXIST) => false,
        Err(err) => {
            return Err(classify_link_apply_error(&err, "managed SVD VXLAN create"));
        }
    };

    fresh = fresh_vxlan_state(handle, name).await?;
    let Some(vxlan) = fresh.vxlan.as_ref() else {
        return if fresh.name_exists {
            Err(foreign_svd_vxlan_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed SVD VXLAN {name} vanished after create"
            )))
        };
    };

    if !created {
        return ensure_svd_vxlan_converged(
            handle,
            name,
            vxlan,
            spec,
            ownership_stamp,
            &fresh.bridges,
        )
        .await;
    }
    let stamped_ifindex = vxlan.ifindex;
    if !vxlan.altnames.iter().any(|alt| alt == ownership_stamp) {
        let stamp_result = handle
            .link()
            .property_add(vxlan.ifindex)
            .alt_ifname(&[ownership_stamp])
            .execute()
            .await;
        match stamp_result {
            Ok(()) => {}
            Err(err) if is_errno(&err, ERRNO_EEXIST) => {}
            Err(err) => {
                let stamp_err = classify_link_apply_error(&err, "managed SVD VXLAN altname stamp");
                rollback_unstamped_create(handle, vxlan.ifindex, name, "managed SVD VXLAN").await;
                return Err(stamp_err);
            }
        }
    }

    fresh = fresh_vxlan_state(handle, name).await?;
    let Some(vxlan) = fresh.vxlan.as_ref() else {
        return if fresh.name_exists {
            Err(foreign_svd_vxlan_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed SVD VXLAN {name} vanished after stamp"
            )))
        };
    };
    ensure_stamp_landed_or_roll_back(
        handle,
        stamped_ifindex,
        vxlan.ifindex,
        &vxlan.altnames,
        name,
        ownership_stamp,
        "managed SVD VXLAN",
    )
    .await?;
    ensure_svd_vxlan_converged(handle, name, vxlan, spec, ownership_stamp, &fresh.bridges).await
}

async fn ensure_svd_vxlan_converged(
    handle: &Handle,
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    spec: &ManagedSvdVxlanNetdevSpec,
    ownership_stamp: &str,
    bridges: &std::collections::HashMap<String, BridgeLink>,
) -> Result<(), DataplaneError> {
    ensure_exact_owned_svd_vxlan(name, vxlan, spec, ownership_stamp, bridges)?;
    // Completion steps past this point run on a link that provably
    // carries our exact stamp; failures are retried, never suppressed.
    ensure_svd_vlan_bindings(handle, name, vxlan.ifindex, spec, bridges)
        .await
        .map_err(retryable_completion)?;
    let fresh = fresh_vxlan_state(handle, name).await?;
    let Some(vxlan) = fresh.vxlan.as_ref() else {
        return Err(transient_link_race(format!(
            "managed SVD VXLAN {name} vanished after bridge VLAN ensure"
        )));
    };
    ensure_exact_owned_svd_vxlan(name, vxlan, spec, ownership_stamp, &fresh.bridges)?;
    ensure_svd_vlan_bindings_observed(name, vxlan, spec, &fresh.bridges)
        .map_err(retryable_completion)?;
    // LAN-2951: raise an exactly-ours SVD VXLAN that is administratively
    // down; see [`adopt_existing_bridge`].
    if vxlan.up {
        return Ok(());
    }
    set_link_up(handle, vxlan.ifindex, "managed SVD VXLAN set up")
        .await
        .map_err(retryable_completion)?;
    let fresh = fresh_vxlan_state(handle, name).await?;
    let Some(vxlan) = fresh.vxlan.as_ref() else {
        return Err(transient_link_race(format!(
            "managed SVD VXLAN {name} vanished after set up"
        )));
    };
    ensure_exact_owned_svd_vxlan(name, vxlan, spec, ownership_stamp, &fresh.bridges)
}

async fn ensure_svd_vlan_bindings(
    handle: &Handle,
    name: &str,
    vxlan_ifindex: u32,
    spec: &ManagedSvdVxlanNetdevSpec,
    bridges: &std::collections::HashMap<String, BridgeLink>,
) -> Result<(), DataplaneError> {
    let bridge = bridges.get(&spec.bridge).ok_or_else(|| {
        unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} bridge {} is not observable after create",
            spec.bridge
        ))
    })?;
    handle
        .link()
        .set_port(LinkBridgePort::new(vxlan_ifindex).vlan_tunnel(true).build())
        .execute()
        .await
        .map_err(|err| classify_link_apply_error(&err, "managed SVD VXLAN vlan_tunnel enable"))?;

    if let Some(port) = bridge
        .port_vlan_inventory
        .iter()
        .find(|port| port.ifindex == vxlan_ifindex)
    {
        let observed = svd_tunnel_bindings(&port.vlan_tunnels).ok_or_else(|| {
            unsafe_managed_svd_vxlan(format!(
                "managed SVD VXLAN {name} has an invalid tunnel mapping inventory"
            ))
        })?;
        for row in observed {
            let (vid, vni) = (row.bridge_vlan, row.vni);
            if spec
                .bindings
                .iter()
                .any(|binding| binding.bridge_vlan == vid && binding.vni == vni)
            {
                continue;
            }
            let removed = !spec
                .bindings
                .iter()
                .any(|binding| binding.bridge_vlan == vid);
            // Only an old tunnel binding establishes ownership of a bridge-self VLAN.
            if removed
                && !bridge.port_vlan_inventory.iter().any(|other| {
                    other.ifindex != vxlan_ifindex && vlan_rows_contain(&other.vlans, vid)
                })
            {
                delete_svd_vlan(handle, bridge.ifindex, vid, true).await?;
            }
            handle
                .link()
                .del_with_message(
                    LinkBridgeVlan::new(vxlan_ifindex)
                        .append_af_spec(AfSpecBridge::VlanTunnelInfo(vec![
                            BridgeVlanTunnelInfo::Id(vni),
                            BridgeVlanTunnelInfo::Vid(vid),
                            BridgeVlanTunnelInfo::Flags(BridgeVlanInfoFlags::empty()),
                        ]))
                        .build(),
                )
                .execute()
                .await
                .map_err(|err| {
                    classify_link_apply_error(&err, "managed SVD VXLAN tunnel mapping delete")
                })?;
        }
        // Membership on the exactly stamped SVD belongs to this manager, including
        // the kernel's initial default VLAN; leave unrelated bridge-self rows alone.
        for vid in 1..=4094 {
            if vlan_rows_contain(&port.vlans, vid)
                && !spec
                    .bindings
                    .iter()
                    .any(|binding| binding.bridge_vlan == vid)
            {
                delete_svd_vlan(handle, vxlan_ifindex, vid, false).await?;
            }
        }
    }
    for binding in &spec.bindings {
        ensure_svd_binding(handle, bridge.ifindex, vxlan_ifindex, *binding).await?;
    }
    Ok(())
}

async fn delete_svd_vlan(
    handle: &Handle,
    ifindex: u32,
    vid: u16,
    bridge_self: bool,
) -> Result<(), DataplaneError> {
    let mut vlan = LinkBridgeVlan::new(ifindex).vlan(vid, BridgeVlanInfoFlags::empty());
    if bridge_self {
        vlan = vlan.bridge_self();
    }
    match handle.link().del_with_message(vlan.build()).execute().await {
        Ok(()) => Ok(()),
        Err(err) if is_errno(&err, ERRNO_ENOENT) => Ok(()),
        Err(err) => Err(classify_link_apply_error(&err, "managed SVD VLAN delete")),
    }
}

async fn ensure_svd_binding(
    handle: &Handle,
    bridge_ifindex: u32,
    vxlan_ifindex: u32,
    binding: ManagedSvdVxlanBinding,
) -> Result<(), DataplaneError> {
    let vlan_flags = BridgeVlanInfoFlags::empty();
    handle
        .link()
        .set(
            LinkBridgeVlan::new(bridge_ifindex)
                .bridge_self()
                .vlan(binding.bridge_vlan, vlan_flags)
                .build(),
        )
        .execute()
        .await
        .map_err(|err| classify_link_apply_error(&err, "managed SVD bridge VLAN add"))?;
    handle
        .link()
        .set(
            LinkBridgeVlan::new(vxlan_ifindex)
                .vlan(binding.bridge_vlan, vlan_flags)
                .build(),
        )
        .execute()
        .await
        .map_err(|err| classify_link_apply_error(&err, "managed SVD VXLAN VLAN add"))?;
    match handle
        .link()
        .set(
            LinkBridgeVlan::new(vxlan_ifindex)
                .append_af_spec(AfSpecBridge::VlanTunnelInfo(vec![
                    BridgeVlanTunnelInfo::Id(binding.vni),
                    BridgeVlanTunnelInfo::Vid(binding.bridge_vlan),
                    BridgeVlanTunnelInfo::Flags(vlan_flags),
                ]))
                .build(),
        )
        .execute()
        .await
    {
        Ok(()) => Ok(()),
        Err(err) if is_errno(&err, ERRNO_EEXIST) => {
            let fresh = links::dump_links(handle).await?;
            if fresh.bridges.values().any(|bridge| {
                bridge.port_vlan_inventory.iter().any(|port| {
                    port.ifindex == vxlan_ifindex
                        && svd_tunnel_bindings(&port.vlan_tunnels)
                            .is_some_and(|rows| rows.contains(&binding))
                })
            }) {
                Ok(())
            } else {
                Err(transient_link_race(
                    "managed SVD VXLAN tunnel mapping EEXIST without the desired binding"
                        .to_string(),
                ))
            }
        }
        Err(err) => Err(classify_link_apply_error(
            &err,
            "managed SVD VXLAN tunnel mapping add",
        )),
    }
}

async fn remove_svd_vxlan(
    handle: &Handle,
    name: &str,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let Some(vxlan) = fresh_vxlan_state(handle, name).await?.vxlan else {
        return Ok(());
    };
    ensure_exact_svd_vxlan_stamp(name, &vxlan, ownership_stamp)?;

    match handle.link().del(vxlan.ifindex).execute().await {
        Ok(()) => Ok(()),
        Err(err) if is_errno(&err, ERRNO_ENODEV) || is_errno(&err, ERRNO_ENOENT) => Ok(()),
        Err(err) => Err(classify_link_apply_error(&err, "managed SVD VXLAN remove")),
    }
}

async fn create_vrf(
    handle: &Handle,
    name: &str,
    spec: &ManagedVrfNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let mut fresh = fresh_vrf_state(handle, name).await?;
    if let Some(vrf) = fresh.vrf.as_ref() {
        return adopt_existing_vrf(handle, name, vrf, spec, ownership_stamp).await;
    }
    if fresh.name_exists {
        return Err(foreign_vrf_collision(name));
    }

    let create_result = handle
        .link()
        .add(LinkVrf::new(name, spec.table_id).up().build())
        .execute()
        .await;
    let created = match create_result {
        Ok(()) => true,
        Err(err) if is_errno(&err, ERRNO_EEXIST) => false,
        Err(err) => return Err(classify_link_apply_error(&err, "managed VRF create")),
    };

    fresh = fresh_vrf_state(handle, name).await?;
    let Some(vrf) = fresh.vrf.as_ref() else {
        return if fresh.name_exists {
            Err(foreign_vrf_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed VRF {name} vanished after create"
            )))
        };
    };

    if !created {
        return adopt_existing_vrf(handle, name, vrf, spec, ownership_stamp).await;
    }
    if vrf.altnames.iter().any(|alt| alt == ownership_stamp) {
        return adopt_existing_vrf(handle, name, vrf, spec, ownership_stamp).await;
    }

    let stamped_ifindex = vrf.ifindex;
    let stamp_result = handle
        .link()
        .property_add(vrf.ifindex)
        .alt_ifname(&[ownership_stamp])
        .execute()
        .await;
    match stamp_result {
        Ok(()) => {}
        Err(err) if is_errno(&err, ERRNO_EEXIST) => {}
        Err(err) => {
            let stamp_err = classify_link_apply_error(&err, "managed VRF altname stamp");
            rollback_unstamped_create(handle, vrf.ifindex, name, "managed VRF").await;
            return Err(stamp_err);
        }
    }

    let fresh = fresh_vrf_state(handle, name).await?;
    let Some(vrf) = fresh.vrf else {
        return if fresh.name_exists {
            Err(foreign_vrf_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed VRF {name} vanished after stamp"
            )))
        };
    };
    ensure_stamp_landed_or_roll_back(
        handle,
        stamped_ifindex,
        vrf.ifindex,
        &vrf.altnames,
        name,
        ownership_stamp,
        "managed VRF",
    )
    .await?;
    ensure_exact_owned_vrf(name, &vrf, spec, ownership_stamp)
}

async fn remove_vrf(
    handle: &Handle,
    name: &str,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let fresh = fresh_vrf_state(handle, name).await?;
    let Some(vrf) = fresh.vrf else {
        return Ok(());
    };
    ensure_exact_vrf_stamp(name, &vrf, ownership_stamp)?;
    if !fresh.slave_names.is_empty() {
        return Err(unsafe_managed_vrf(format!(
            "managed VRF {name} cannot be removed while slave link(s) remain attached: {:?}",
            fresh.slave_names
        )));
    }

    match handle.link().del(vrf.ifindex).execute().await {
        Ok(()) => Ok(()),
        Err(err) if is_errno(&err, ERRNO_ENODEV) || is_errno(&err, ERRNO_ENOENT) => Ok(()),
        Err(err) => Err(classify_link_apply_error(&err, "managed VRF remove")),
    }
}

/// LAN-2951: adopt an exactly-ours VRF and raise it when it is
/// administratively down; see [`adopt_existing_bridge`]. Every protected
/// attribute is checked before the link is raised.
async fn adopt_existing_vrf(
    handle: &Handle,
    name: &str,
    vrf: &KernelVrfLinkInfo,
    spec: &ManagedVrfNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    if vrf.up {
        return ensure_exact_owned_vrf(name, vrf, spec, ownership_stamp);
    }
    let mut raised = vrf.clone();
    raised.up = true;
    ensure_exact_owned_vrf(name, &raised, spec, ownership_stamp)?;
    set_link_up(handle, vrf.ifindex, "managed VRF set up")
        .await
        .map_err(retryable_completion)?;
    let Some(vrf) = fresh_vrf_state(handle, name).await?.vrf else {
        return Err(transient_link_race(format!(
            "managed VRF {name} vanished after set up"
        )));
    };
    ensure_exact_owned_vrf(name, &vrf, spec, ownership_stamp)
}

async fn create_l3vxlan(
    handle: &Handle,
    name: &str,
    spec: &ManagedL3VxlanNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let mut fresh = fresh_l3vxlan_state(handle, name).await?;
    if let Some(vxlan) = fresh.vxlan.as_ref() {
        return adopt_existing_l3vxlan(handle, name, vxlan, spec, ownership_stamp).await;
    }
    if fresh.name_exists {
        return Err(foreign_l3vxlan_collision(name));
    }

    let vrf_ifindex = fresh
        .vrfs
        .get(&spec.vrf)
        .map(|vrf| vrf.ifindex)
        .ok_or_else(|| {
            missing_l3vxlan_vrf(name, &spec.vrf, fresh.all_link_names.contains(&spec.vrf))
        })?;

    let mut builder = LinkVxlan::new(name, spec.vni)
        .port(spec.dstport)
        .learning(false)
        .controller(vrf_ifindex)
        .address(spec.router_mac.octets().to_vec())
        .up();
    builder = match spec.local_ip {
        IpAddr::V4(addr) => builder.local(addr),
        IpAddr::V6(addr) => builder.local6(addr),
    };

    let create_result = handle.link().add(builder.build()).execute().await;
    let created = match create_result {
        Ok(()) => true,
        Err(err) if is_errno(&err, ERRNO_EEXIST) => false,
        Err(err) => return Err(classify_link_apply_error(&err, "managed L3VXLAN create")),
    };

    fresh = fresh_l3vxlan_state(handle, name).await?;
    let Some(vxlan) = fresh.vxlan.as_ref() else {
        return if fresh.name_exists {
            Err(foreign_l3vxlan_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed L3VXLAN {name} vanished after create"
            )))
        };
    };

    if !created {
        return adopt_existing_l3vxlan(handle, name, vxlan, spec, ownership_stamp).await;
    }
    if vxlan.altnames.iter().any(|alt| alt == ownership_stamp) {
        return adopt_existing_l3vxlan(handle, name, vxlan, spec, ownership_stamp).await;
    }

    let stamped_ifindex = vxlan.ifindex;
    let stamp_result = handle
        .link()
        .property_add(vxlan.ifindex)
        .alt_ifname(&[ownership_stamp])
        .execute()
        .await;
    match stamp_result {
        Ok(()) => {}
        Err(err) if is_errno(&err, ERRNO_EEXIST) => {}
        Err(err) => {
            let stamp_err = classify_link_apply_error(&err, "managed L3VXLAN altname stamp");
            rollback_unstamped_create(handle, vxlan.ifindex, name, "managed L3VXLAN").await;
            return Err(stamp_err);
        }
    }

    let fresh = fresh_l3vxlan_state(handle, name).await?;
    let Some(vxlan) = fresh.vxlan else {
        return if fresh.name_exists {
            Err(foreign_l3vxlan_collision(name))
        } else {
            Err(transient_link_race(format!(
                "managed L3VXLAN {name} vanished after stamp"
            )))
        };
    };
    ensure_stamp_landed_or_roll_back(
        handle,
        stamped_ifindex,
        vxlan.ifindex,
        &vxlan.altnames,
        name,
        ownership_stamp,
        "managed L3VXLAN",
    )
    .await?;
    ensure_exact_owned_l3vxlan(name, &vxlan, spec, ownership_stamp)
}

async fn remove_l3vxlan(
    handle: &Handle,
    name: &str,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let Some(vxlan) = fresh_l3vxlan_state(handle, name).await?.vxlan else {
        return Ok(());
    };
    ensure_exact_vxlan_stamp(name, &vxlan, ownership_stamp)?;

    match handle.link().del(vxlan.ifindex).execute().await {
        Ok(()) => Ok(()),
        Err(err) if is_errno(&err, ERRNO_ENODEV) || is_errno(&err, ERRNO_ENOENT) => Ok(()),
        Err(err) => Err(classify_link_apply_error(&err, "managed L3VXLAN remove")),
    }
}

/// LAN-2951: adopt an exactly-ours L3VXLAN and raise it when it is
/// administratively down; see [`adopt_existing_vrf`].
async fn adopt_existing_l3vxlan(
    handle: &Handle,
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    spec: &ManagedL3VxlanNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    if vxlan.up {
        return ensure_exact_owned_l3vxlan(name, vxlan, spec, ownership_stamp);
    }
    let mut raised = vxlan.clone();
    raised.up = true;
    ensure_exact_owned_l3vxlan(name, &raised, spec, ownership_stamp)?;
    set_link_up(handle, vxlan.ifindex, "managed L3VXLAN set up")
        .await
        .map_err(retryable_completion)?;
    let Some(vxlan) = fresh_l3vxlan_state(handle, name).await?.vxlan else {
        return Err(transient_link_race(format!(
            "managed L3VXLAN {name} vanished after set up"
        )));
    };
    ensure_exact_owned_l3vxlan(name, &vxlan, spec, ownership_stamp)
}

async fn create_vlan_upper(
    handle: &Handle,
    name: &str,
    spec: &ManagedVlanUpperNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let mut fresh = fresh_vlan_upper_state(handle, name).await?;
    if let Some(link) = fresh.vlan_upper.as_ref() {
        return adopt_existing_vlan_upper(handle, name, link, spec, ownership_stamp).await;
    }
    if fresh.name_exists {
        return Err(foreign_vlan_upper_collision(name));
    }

    let bridge_ifindex = fresh
        .bridges
        .get(&spec.bridge)
        .map(|bridge| bridge.ifindex)
        .ok_or_else(|| {
            missing_vlan_upper_bridge(
                name,
                &spec.bridge,
                fresh.all_link_names.contains(&spec.bridge),
            )
        })?;

    let create_result = handle
        .link()
        .add(LinkVlan::new(name, bridge_ifindex, spec.vlan).build())
        .execute()
        .await;
    let created = match create_result {
        Ok(()) => true,
        Err(err) if is_errno(&err, ERRNO_EEXIST) => false,
        Err(err) => {
            return Err(classify_link_apply_error(&err, "managed VLAN upper create"));
        }
    };

    fresh = fresh_vlan_upper_state(handle, name).await?;
    let Some(link) = fresh.vlan_upper.as_ref() else {
        return Err(missing_vlan_upper_after(name, &fresh, "create"));
    };

    if !created {
        return adopt_existing_vlan_upper(handle, name, link, spec, ownership_stamp).await;
    }
    if let Err(err) = ensure_vlan_upper_attrs(name, link, spec) {
        rollback_unstamped_create(handle, link.ifindex, name, "managed VLAN upper").await;
        return Err(err);
    }
    let stamped_ifindex = link.ifindex;
    if !link.altnames.iter().any(|alt| alt == ownership_stamp)
        && let Err(err) = stamp_vlan_upper(handle, link.ifindex, ownership_stamp).await
    {
        rollback_unstamped_create(handle, link.ifindex, name, "managed VLAN upper").await;
        return Err(err);
    }
    let fresh = fresh_vlan_upper_state(handle, name).await?;
    let Some(link) = fresh.vlan_upper.as_ref() else {
        return Err(missing_vlan_upper_after(name, &fresh, "stamp"));
    };
    ensure_stamp_landed_or_roll_back(
        handle,
        stamped_ifindex,
        link.ifindex,
        &link.altnames,
        name,
        ownership_stamp,
        "managed VLAN upper",
    )
    .await?;
    adopt_existing_vlan_upper(handle, name, link, spec, ownership_stamp).await
}

async fn adopt_existing_vlan_upper(
    handle: &Handle,
    name: &str,
    link: &KernelVlanUpperLinkInfo,
    spec: &ManagedVlanUpperNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_vlan_upper_stamp_and_attrs(name, link, spec, ownership_stamp)?;
    ensure_vlan_upper_up_and_owned(handle, name, link, spec, ownership_stamp).await
}

async fn ensure_vlan_upper_up_and_owned(
    handle: &Handle,
    name: &str,
    link: &KernelVlanUpperLinkInfo,
    spec: &ManagedVlanUpperNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    if link.up {
        return ensure_exact_owned_vlan_upper(name, link, spec, ownership_stamp);
    }
    // Stamp + attrs were verified above; a set-up failure is our own
    // incomplete state — keep it retryable, never permanently suppressed.
    set_link_up(handle, link.ifindex, "managed VLAN upper set up")
        .await
        .map_err(retryable_completion)?;
    let fresh = fresh_vlan_upper_state(handle, name).await?;
    let Some(link) = fresh.vlan_upper.as_ref() else {
        return Err(missing_vlan_upper_after(name, &fresh, "set up"));
    };
    ensure_exact_owned_vlan_upper(name, link, spec, ownership_stamp)
}

async fn stamp_vlan_upper(
    handle: &Handle,
    ifindex: u32,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let stamp_result = handle
        .link()
        .property_add(ifindex)
        .alt_ifname(&[ownership_stamp])
        .execute()
        .await;
    match stamp_result {
        Ok(()) => {}
        Err(err) if is_errno(&err, ERRNO_EEXIST) => {}
        Err(err) => {
            return Err(classify_link_apply_error(
                &err,
                "managed VLAN upper altname stamp",
            ));
        }
    }
    Ok(())
}

fn missing_vlan_upper_after(
    name: &str,
    fresh: &FreshVlanUpperState,
    action: &str,
) -> DataplaneError {
    if fresh.name_exists {
        foreign_vlan_upper_collision(name)
    } else {
        transient_link_race(format!("managed VLAN upper {name} vanished after {action}"))
    }
}

async fn remove_vlan_upper(
    handle: &Handle,
    name: &str,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let Some(link) = fresh_vlan_upper_state(handle, name).await?.vlan_upper else {
        return Ok(());
    };
    ensure_exact_vlan_upper_stamp(name, &link, ownership_stamp)?;
    if link.lower_ifindex.is_none() || link.bridge.is_none() || link.vlan.is_none() {
        return Err(unsafe_managed_vlan_upper(format!(
            "managed VLAN upper {name} cannot be removed: lower bridge or VLAN id is not observable"
        )));
    }

    match handle.link().del(link.ifindex).execute().await {
        Ok(()) => Ok(()),
        Err(err) if is_errno(&err, ERRNO_ENODEV) || is_errno(&err, ERRNO_ENOENT) => Ok(()),
        Err(err) => Err(classify_link_apply_error(&err, "managed VLAN upper remove")),
    }
}

struct FreshBridgeState {
    bridge: Option<BridgeLink>,
    name_exists: bool,
}

struct FreshVxlanState {
    vxlan: Option<KernelVxlanLinkInfo>,
    bridges: std::collections::HashMap<String, BridgeLink>,
    all_link_names: std::collections::HashSet<String>,
    name_exists: bool,
}

struct FreshVrfState {
    vrf: Option<KernelVrfLinkInfo>,
    slave_names: Vec<String>,
    name_exists: bool,
}

struct FreshL3VxlanState {
    vxlan: Option<KernelVxlanLinkInfo>,
    vrfs: std::collections::HashMap<String, KernelVrfLinkInfo>,
    all_link_names: std::collections::HashSet<String>,
    name_exists: bool,
}

struct FreshVlanUpperState {
    vlan_upper: Option<KernelVlanUpperLinkInfo>,
    bridges: std::collections::HashMap<String, BridgeLink>,
    all_link_names: std::collections::HashSet<String>,
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

async fn fresh_vxlan_state(handle: &Handle, name: &str) -> Result<FreshVxlanState, DataplaneError> {
    let cache = links::dump_links(handle).await?;
    Ok(FreshVxlanState {
        vxlan: cache.vxlan_links.get(name).cloned(),
        bridges: cache.bridges,
        all_link_names: cache.all_link_names.clone(),
        name_exists: cache.all_link_names.contains(name),
    })
}

async fn fresh_vrf_state(handle: &Handle, name: &str) -> Result<FreshVrfState, DataplaneError> {
    let cache = links::dump_links(handle).await?;
    Ok(FreshVrfState {
        vrf: cache.vrfs.get(name).cloned(),
        slave_names: cache
            .master_slaves_by_name
            .get(name)
            .cloned()
            .unwrap_or_default(),
        name_exists: cache.all_link_names.contains(name),
    })
}

async fn fresh_l3vxlan_state(
    handle: &Handle,
    name: &str,
) -> Result<FreshL3VxlanState, DataplaneError> {
    let cache = links::dump_links(handle).await?;
    Ok(FreshL3VxlanState {
        vxlan: cache.vxlan_links.get(name).cloned(),
        vrfs: cache.vrfs,
        all_link_names: cache.all_link_names.clone(),
        name_exists: cache.all_link_names.contains(name),
    })
}

async fn fresh_vlan_upper_state(
    handle: &Handle,
    name: &str,
) -> Result<FreshVlanUpperState, DataplaneError> {
    let cache = links::dump_links(handle).await?;
    Ok(FreshVlanUpperState {
        vlan_upper: cache.vlan_upper_link_infos.get(name).cloned(),
        bridges: cache.bridges,
        all_link_names: cache.all_link_names.clone(),
        name_exists: cache.all_link_names.contains(name),
    })
}

fn ensure_exact_owned_bridge(
    name: &str,
    bridge: &BridgeLink,
    vlan_filtering: bool,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_bridge_stamp_and_attrs(name, bridge, vlan_filtering, ownership_stamp)?;
    if !bridge.up {
        return Err(unsafe_managed_bridge(format!(
            "managed bridge {name} is administratively down after apply"
        )));
    }
    Ok(())
}

fn ensure_bridge_stamp_and_attrs(
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

fn ensure_exact_owned_vxlan(
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    spec: &ManagedVxlanNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_vxlan_stamp_and_attrs(name, vxlan, spec, ownership_stamp)?;
    if !vxlan.up {
        return Err(unsafe_managed_vxlan(format!(
            "managed VXLAN {name} is administratively down after apply"
        )));
    }
    Ok(())
}

fn ensure_vxlan_stamp_and_attrs(
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    spec: &ManagedVxlanNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_exact_vxlan_stamp(name, vxlan, ownership_stamp)?;
    if vxlan.vni != Some(spec.vni) {
        return Err(unsafe_managed_vxlan(format!(
            "managed VXLAN {name} VNI changed during apply: observed {:?}, desired {}",
            vxlan.vni, spec.vni
        )));
    }
    if vxlan.local_ip != Some(spec.local_ip) {
        return Err(unsafe_managed_vxlan(format!(
            "managed VXLAN {name} local IP changed during apply: observed {:?}, desired {}",
            vxlan.local_ip, spec.local_ip
        )));
    }
    if vxlan.dstport != Some(spec.dstport) {
        return Err(unsafe_managed_vxlan(format!(
            "managed VXLAN {name} dstport changed during apply: observed {:?}, desired {}",
            vxlan.dstport, spec.dstport
        )));
    }
    if vxlan.learning_disabled != Some(true) {
        return Err(unsafe_managed_vxlan(format!(
            "managed VXLAN {name} learning changed during apply: observed {:?}, desired nolearning",
            vxlan.learning_disabled
        )));
    }
    if vxlan.collect_metadata {
        return Err(unsafe_managed_vxlan(format!(
            "managed VXLAN {name} became collect-metadata/external during apply"
        )));
    }
    if vxlan.vnifilter {
        return Err(unsafe_managed_vxlan(format!(
            "managed VXLAN {name} enabled vnifilter during apply"
        )));
    }
    if vxlan.bridge.as_deref() != Some(spec.bridge.as_str()) {
        return Err(unsafe_managed_vxlan(format!(
            "managed VXLAN {name} bridge attachment changed during apply: observed {:?}, desired {}",
            vxlan.bridge, spec.bridge
        )));
    }
    Ok(())
}

fn ensure_exact_vxlan_stamp(
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let stamps: Vec<_> = vxlan
        .altnames
        .iter()
        .filter_map(|altname| parse_ownership_stamp(altname))
        .collect();
    if stamps.len() == 1 && stamps[0].raw == ownership_stamp && stamps[0].name == name {
        return Ok(());
    }
    Err(unsafe_managed_vxlan(format!(
        "managed VXLAN {name} ownership stamp changed during apply: observed {:?}, expected {ownership_stamp}",
        vxlan.altnames
    )))
}

fn ensure_exact_owned_svd_vxlan(
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    spec: &ManagedSvdVxlanNetdevSpec,
    ownership_stamp: &str,
    bridges: &std::collections::HashMap<String, BridgeLink>,
) -> Result<(), DataplaneError> {
    ensure_exact_svd_vxlan_stamp(name, vxlan, ownership_stamp)?;
    if !vxlan.has_no_fixed_vni() {
        return Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} has fixed VNI {:?}; desired collect-metadata/external",
            vxlan.vni
        )));
    }
    if vxlan.local_ip != spec.local_ip {
        return Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} local IP changed during apply: observed {:?}, desired {:?}",
            vxlan.local_ip, spec.local_ip
        )));
    }
    if vxlan.dstport != Some(spec.dstport) {
        return Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} dstport changed during apply: observed {:?}, desired {}",
            vxlan.dstport, spec.dstport
        )));
    }
    if vxlan.learning_disabled != Some(true) {
        return Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} learning changed during apply: observed {:?}, desired nolearning",
            vxlan.learning_disabled
        )));
    }
    if !vxlan.collect_metadata {
        return Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} disabled collect-metadata/external during apply"
        )));
    }
    if !vxlan.vnifilter {
        return Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} disabled vnifilter during apply"
        )));
    }
    if vxlan.bridge.as_deref() != Some(spec.bridge.as_str()) {
        return Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} bridge attachment changed during apply: observed {:?}, desired {}",
            vxlan.bridge, spec.bridge
        )));
    }
    if !bridges.contains_key(&spec.bridge) {
        return Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} bridge {} is not observable",
            spec.bridge
        )));
    }
    Ok(())
}

fn ensure_exact_svd_vxlan_stamp(
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let stamps: Vec<_> = vxlan
        .altnames
        .iter()
        .filter_map(|altname| parse_ownership_stamp(altname))
        .collect();
    if stamps.len() == 1
        && stamps[0].raw == ownership_stamp
        && stamps[0].name == name
        && stamps[0].class == rustbgpd_evpn::ManagedNetdevClass::SvdVxlan
    {
        return Ok(());
    }
    Err(unsafe_managed_svd_vxlan(format!(
        "managed SVD VXLAN {name} ownership stamp changed during apply: observed {:?}, expected {ownership_stamp}",
        vxlan.altnames
    )))
}

fn svd_vlan_bindings_present(
    bridge: &BridgeLink,
    vxlan_ifindex: u32,
    vxlan_name: &str,
    bindings: &[ManagedSvdVxlanBinding],
) -> bool {
    let Some(port) = bridge.port_vlan_inventory.iter().find(|port| {
        port.is_vxlan && (port.ifindex == vxlan_ifindex || port.name.as_deref() == Some(vxlan_name))
    }) else {
        return false;
    };
    let Some(observed) = crate::snapshot::svd_tunnel_bindings(&port.vlan_tunnels) else {
        return false;
    };
    if observed.len() != bindings.len()
        || (1..=4094).any(|vid| {
            vlan_rows_contain(&port.vlans, vid)
                != bindings.iter().any(|binding| binding.bridge_vlan == vid)
        })
    {
        return false;
    }
    bindings.iter().all(|binding| {
        vlan_rows_contain(&bridge.vlans, binding.bridge_vlan)
            && vlan_rows_contain(&port.vlans, binding.bridge_vlan)
            && observed.contains(binding)
    })
}

fn ensure_svd_vlan_bindings_observed(
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    spec: &ManagedSvdVxlanNetdevSpec,
    bridges: &std::collections::HashMap<String, BridgeLink>,
) -> Result<(), DataplaneError> {
    let Some(bridge) = bridges.get(&spec.bridge) else {
        return Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} bridge {} is not observable after bridge VLAN ensure",
            spec.bridge
        )));
    };
    if svd_vlan_bindings_present(bridge, vxlan.ifindex, &vxlan.name, &spec.bindings) {
        Ok(())
    } else {
        Err(unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} bridge VLAN/tunnel mappings did not converge"
        )))
    }
}

fn ensure_exact_owned_vrf(
    name: &str,
    vrf: &KernelVrfLinkInfo,
    spec: &ManagedVrfNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_exact_vrf_stamp(name, vrf, ownership_stamp)?;
    if vrf.table_id != Some(spec.table_id) {
        return Err(unsafe_managed_vrf(format!(
            "managed VRF {name} table_id changed during apply: observed {:?}, desired {}",
            vrf.table_id, spec.table_id
        )));
    }
    if !vrf.up {
        return Err(unsafe_managed_vrf(format!(
            "managed VRF {name} is administratively down after apply"
        )));
    }
    Ok(())
}

fn ensure_exact_vrf_stamp(
    name: &str,
    vrf: &KernelVrfLinkInfo,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let stamps: Vec<_> = vrf
        .altnames
        .iter()
        .filter_map(|altname| parse_ownership_stamp(altname))
        .collect();
    if stamps.len() == 1 && stamps[0].raw == ownership_stamp && stamps[0].name == name {
        return Ok(());
    }
    Err(unsafe_managed_vrf(format!(
        "managed VRF {name} ownership stamp changed during apply: observed {:?}, expected {ownership_stamp}",
        vrf.altnames
    )))
}

fn ensure_exact_owned_l3vxlan(
    name: &str,
    vxlan: &KernelVxlanLinkInfo,
    spec: &ManagedL3VxlanNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_exact_vxlan_stamp(name, vxlan, ownership_stamp)?;
    if vxlan.vni != Some(spec.vni) {
        return Err(unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} VNI changed during apply: observed {:?}, desired {}",
            vxlan.vni, spec.vni
        )));
    }
    if vxlan.local_ip != Some(spec.local_ip) {
        return Err(unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} local IP changed during apply: observed {:?}, desired {}",
            vxlan.local_ip, spec.local_ip
        )));
    }
    if vxlan.dstport != Some(spec.dstport) {
        return Err(unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} dstport changed during apply: observed {:?}, desired {}",
            vxlan.dstport, spec.dstport
        )));
    }
    if vxlan.learning_disabled != Some(true) {
        return Err(unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} learning changed during apply: observed {:?}, desired nolearning",
            vxlan.learning_disabled
        )));
    }
    if vxlan.collect_metadata {
        return Err(unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} became collect-metadata/external during apply"
        )));
    }
    if vxlan.vnifilter {
        return Err(unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} enabled vnifilter during apply"
        )));
    }
    if vxlan.master.as_deref() != Some(spec.vrf.as_str()) {
        return Err(unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} VRF attachment changed during apply: observed {:?}, desired {}",
            vxlan.master, spec.vrf
        )));
    }
    if vxlan.mac != Some(spec.router_mac) {
        return Err(unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} router MAC changed during apply: observed {:?}, desired {:?}",
            vxlan.mac, spec.router_mac
        )));
    }
    if !vxlan.up {
        return Err(unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} is administratively down after apply"
        )));
    }
    Ok(())
}

fn ensure_exact_owned_vlan_upper(
    name: &str,
    link: &KernelVlanUpperLinkInfo,
    spec: &ManagedVlanUpperNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_vlan_upper_stamp_and_attrs(name, link, spec, ownership_stamp)?;
    if !link.up {
        return Err(unsafe_managed_vlan_upper(format!(
            "managed VLAN upper {name} is administratively down after apply"
        )));
    }
    Ok(())
}

fn ensure_vlan_upper_stamp_and_attrs(
    name: &str,
    link: &KernelVlanUpperLinkInfo,
    spec: &ManagedVlanUpperNetdevSpec,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    ensure_exact_vlan_upper_stamp(name, link, ownership_stamp)?;
    ensure_vlan_upper_attrs(name, link, spec)
}

fn ensure_vlan_upper_attrs(
    name: &str,
    link: &KernelVlanUpperLinkInfo,
    spec: &ManagedVlanUpperNetdevSpec,
) -> Result<(), DataplaneError> {
    if link.bridge.as_deref() != Some(spec.bridge.as_str()) {
        return Err(unsafe_managed_vlan_upper(format!(
            "managed VLAN upper {name} bridge attachment changed during apply: observed {:?}, desired {}",
            link.bridge, spec.bridge
        )));
    }
    if link.vlan != Some(spec.vlan) {
        return Err(unsafe_managed_vlan_upper(format!(
            "managed VLAN upper {name} VLAN changed during apply: observed {:?}, desired {}",
            link.vlan, spec.vlan
        )));
    }
    Ok(())
}

fn ensure_exact_vlan_upper_stamp(
    name: &str,
    link: &KernelVlanUpperLinkInfo,
    ownership_stamp: &str,
) -> Result<(), DataplaneError> {
    let stamps: Vec<_> = link
        .altnames
        .iter()
        .filter_map(|altname| parse_ownership_stamp(altname))
        .collect();
    if stamps.len() == 1 && stamps[0].raw == ownership_stamp && stamps[0].name == name {
        return Ok(());
    }
    Err(unsafe_managed_vlan_upper(format!(
        "managed VLAN upper {name} ownership stamp changed during apply: observed {:?}, expected {ownership_stamp}",
        link.altnames
    )))
}

/// Best-effort delete of a link this operation just created but failed
/// to stamp. An unstamped link would be classified foreign-present on
/// every later pass — a self-inflicted permanent wedge — so the failed
/// create rolls its own creation back and leaves the kernel as if the
/// create never ran; the next pass retries from absent.
async fn rollback_unstamped_create(handle: &Handle, ifindex: u32, name: &str, context: &str) {
    match handle.link().del(ifindex).execute().await {
        Ok(()) => {
            tracing::debug!(name, context, "rolled back unstamped just-created link");
        }
        Err(err) if is_errno(&err, ERRNO_ENODEV) || is_errno(&err, ERRNO_ENOENT) => {}
        Err(err) => {
            tracing::warn!(
                name,
                context,
                error = ?err,
                "failed to roll back unstamped just-created link; \
                 it will be reported foreign-present until removed out of band"
            );
        }
    }
}

/// What the post-stamp lookup found for a link rustbgpd just created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostStamp {
    /// The link we stamped carries the stamp.
    Owned,
    /// The name now belongs to a different link than the one we created
    /// and stamped: ours was deleted and replaced in between.
    Replaced,
    /// Our link is there without the stamp. The altname add returned
    /// `EEXIST` because another link already holds the stamp.
    StampHeldElsewhere,
}

fn post_stamp_verdict(
    stamped_ifindex: u32,
    live_ifindex: u32,
    altnames: &[String],
    ownership_stamp: &str,
) -> PostStamp {
    if live_ifindex != stamped_ifindex {
        PostStamp::Replaced
    } else if altnames.iter().any(|alt| alt == ownership_stamp) {
        PostStamp::Owned
    } else {
        PostStamp::StampHeldElsewhere
    }
}

/// Confirm the ownership stamp landed on a link rustbgpd just created.
///
/// The stamp step tolerates `EEXIST` from the altname add, which covers
/// a stamp that is already on this link. The kernel returns the same
/// errno when another link already holds that altname, and then this
/// link stays unstamped. An unstamped link reads as foreign and is
/// never reaped, so roll the create back. The failure is transient, so
/// the create resumes on backoff once the conflicting altname is freed.
///
/// Only the link we stamped (`stamped_ifindex`) is ever deleted. If the
/// post-stamp lookup by name finds a different link, ours was replaced,
/// so delete nothing and report a transient race.
async fn ensure_stamp_landed_or_roll_back(
    handle: &Handle,
    stamped_ifindex: u32,
    live_ifindex: u32,
    altnames: &[String],
    name: &str,
    ownership_stamp: &str,
    context: &str,
) -> Result<(), DataplaneError> {
    match post_stamp_verdict(stamped_ifindex, live_ifindex, altnames, ownership_stamp) {
        PostStamp::Owned => Ok(()),
        PostStamp::Replaced => Err(transient_link_race(format!(
            "{context} {name} was replaced (ifindex {stamped_ifindex} -> {live_ifindex}) \
             after the stamp; nothing deleted"
        ))),
        PostStamp::StampHeldElsewhere => {
            rollback_unstamped_create(handle, stamped_ifindex, name, context).await;
            // Transient, not permanent: a permanent failure stays
            // suppressed while the name is desired, so freeing the
            // altname would never let the create resume.
            Err(DataplaneError::Other(format!(
                "{context} {name}: ownership stamp {ownership_stamp} is held by another link; \
                 the unstamped create was rolled back and retries on backoff"
            )))
        }
    }
}

/// Downgrade a would-be-permanent failure from a post-stamp completion
/// step to the transient class. The link provably carries our exact
/// ownership stamp at this point, so incomplete follow-on state
/// (bridge VLAN bindings, admin-up) is ours to finish — the reconciler
/// must retry the completion steps on backoff instead of permanently
/// suppressing the op until restart.
fn retryable_completion(err: DataplaneError) -> DataplaneError {
    match err.class() {
        crate::error::FailureClass::Permanent => DataplaneError::Other(err.to_string()),
        _ => err,
    }
}

async fn set_link_up(
    handle: &Handle,
    ifindex: u32,
    context: &'static str,
) -> Result<(), DataplaneError> {
    let message = LinkUnspec::new_with_index(ifindex).up().build();
    match handle.link().change(message).execute().await {
        Ok(()) => Ok(()),
        Err(err) => Err(classify_link_apply_error(&err, context)),
    }
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

fn foreign_vxlan_collision(name: &str) -> DataplaneError {
    unsafe_managed_vxlan(format!(
        "managed VXLAN {name} cannot be created: desired name is occupied by a non-VXLAN link"
    ))
}

fn missing_vxlan_bridge(name: &str, bridge: &str, bridge_name_exists: bool) -> DataplaneError {
    if bridge_name_exists {
        return unsafe_managed_vxlan(format!(
            "managed VXLAN {name} cannot be created: desired bridge name {bridge} is occupied by a non-bridge link"
        ));
    }
    transient_link_race(format!(
        "managed VXLAN {name} cannot be created: desired bridge {bridge} is absent"
    ))
}

fn unsafe_managed_vxlan(message: String) -> DataplaneError {
    DataplaneError::InvalidArgument(message)
}

fn foreign_svd_vxlan_collision(name: &str) -> DataplaneError {
    unsafe_managed_svd_vxlan(format!(
        "managed SVD VXLAN {name} cannot be created: desired name is occupied by a non-VXLAN link"
    ))
}

fn missing_svd_vxlan_bridge(name: &str, bridge: &str, bridge_name_exists: bool) -> DataplaneError {
    if bridge_name_exists {
        return unsafe_managed_svd_vxlan(format!(
            "managed SVD VXLAN {name} cannot be created: desired bridge name {bridge} is occupied by a non-bridge link"
        ));
    }
    transient_link_race(format!(
        "managed SVD VXLAN {name} cannot be created: desired bridge {bridge} is absent"
    ))
}

fn unsafe_managed_svd_vxlan(message: String) -> DataplaneError {
    DataplaneError::InvalidArgument(message)
}

fn foreign_vrf_collision(name: &str) -> DataplaneError {
    unsafe_managed_vrf(format!(
        "managed VRF {name} cannot be created: desired name is occupied by a non-VRF link"
    ))
}

fn unsafe_managed_vrf(message: String) -> DataplaneError {
    DataplaneError::InvalidArgument(message)
}

fn foreign_l3vxlan_collision(name: &str) -> DataplaneError {
    unsafe_managed_l3vxlan(format!(
        "managed L3VXLAN {name} cannot be created: desired name is occupied by a non-VXLAN link"
    ))
}

fn missing_l3vxlan_vrf(name: &str, vrf: &str, vrf_name_exists: bool) -> DataplaneError {
    if vrf_name_exists {
        return unsafe_managed_l3vxlan(format!(
            "managed L3VXLAN {name} cannot be created: desired VRF name {vrf} is occupied by a non-VRF link"
        ));
    }
    transient_link_race(format!(
        "managed L3VXLAN {name} cannot be created: desired VRF {vrf} is absent"
    ))
}

fn unsafe_managed_l3vxlan(message: String) -> DataplaneError {
    DataplaneError::InvalidArgument(message)
}

fn foreign_vlan_upper_collision(name: &str) -> DataplaneError {
    unsafe_managed_vlan_upper(format!(
        "managed VLAN upper {name} cannot be created: desired name is occupied by a non-VLAN-upper link"
    ))
}

fn missing_vlan_upper_bridge(name: &str, bridge: &str, bridge_name_exists: bool) -> DataplaneError {
    if bridge_name_exists {
        return unsafe_managed_vlan_upper(format!(
            "managed VLAN upper {name} cannot be created: desired bridge name {bridge} is occupied by a non-bridge link"
        ));
    }
    transient_link_race(format!(
        "managed VLAN upper {name} cannot be created: desired bridge {bridge} is absent"
    ))
}

fn unsafe_managed_vlan_upper(message: String) -> DataplaneError {
    DataplaneError::InvalidArgument(message)
}

#[cfg(test)]
mod tests {
    // LAN-2909 L-E4 review: only the link that was stamped is ever rolled
    // back. A same-name link with another ifindex is a replacement, and
    // deleting it would destroy someone else's device.
    #[test]
    fn post_stamp_verdict_never_rolls_back_a_replacement() {
        let stamp = "rustbgpd:bridge:leaf-1:br0";
        let stamped = vec![stamp.to_string()];
        assert_eq!(
            super::post_stamp_verdict(7, 7, &stamped, stamp),
            super::PostStamp::Owned
        );
        assert_eq!(
            super::post_stamp_verdict(7, 7, &[], stamp),
            super::PostStamp::StampHeldElsewhere
        );
        assert_eq!(
            super::post_stamp_verdict(7, 9, &[], stamp),
            super::PostStamp::Replaced
        );
        assert_eq!(
            super::post_stamp_verdict(7, 9, &stamped, stamp),
            super::PostStamp::Replaced
        );
    }
}
