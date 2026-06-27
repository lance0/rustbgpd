use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::evpn_service_client::EvpnServiceClient;
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddEvpnRouteRequest, ClearDuplicateMacQuarantineRequest, DeleteEvpnRouteRequest,
    EthernetSegmentState, EvpnInstanceReadinessState, EvpnInstanceState, EvpnRuntimeLifecycle,
    EvpnRuntimeMutationState, EvpnRuntimeState, GetEvpnRuntimeRequest, GetIpVrfRequest,
    IpVrfReadinessState, IpVrfState, ListEthernetSegmentsRequest, ListEthernetSegmentsResponse,
    ListEvpnInstancesRequest, ListEvpnNexthopsRequest, ListEvpnRequest, ListIpVrfsRequest,
    ListManagedNetdevsRequest, ManagedNetdevClass, ManagedNetdevLifecycleState, ManagedNetdevState,
    MetricsRequest, SetEthernetSegmentDrainRequest,
};

const EVPN_DIAGNOSE_METRIC_PREFIXES: &[&str] = &[
    "evpn_local_originations_total",
    "evpn_local_origination_errors_total",
    "evpn_local_observations_dropped_total",
    "evpn_duplicate_mac_moves_total",
    "evpn_duplicate_mac_first_move_timestamp_seconds",
];

fn route_type_label(t: u32) -> &'static str {
    match t {
        1 => "ead",
        2 => "mac-ip",
        3 => "imet",
        4 => "es",
        5 => "ip-prefix",
        _ => "unknown",
    }
}

pub async fn list(
    connection: Connection,
    route_type: Option<u32>,
    peer: Option<String>,
    rd: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_evpn_routes(ListEvpnRequest {
            route_type_filter: route_type.unwrap_or(0),
            peer_filter: peer.unwrap_or_default(),
            rd_filter: rd.unwrap_or_default(),
        })
        .await?
        .into_inner();

    if json {
        let out: Vec<serde_json::Value> = resp
            .routes
            .iter()
            .map(|r| {
                serde_json::json!({
                    "route_type": r.route_type,
                    "route_type_name": route_type_label(r.route_type),
                    "rd": r.rd,
                    "esi": r.esi,
                    "ethernet_tag": r.ethernet_tag,
                    "mac": r.mac,
                    "ip": r.ip,
                    "prefix": r.prefix,
                    "gateway": r.gateway,
                    "label": r.label,
                    "label2": r.label2,
                    "tunnel_type": r.tunnel_type,
                    "next_hop": r.next_hop,
                    "peer": r.peer_address,
                    "as_path": r.as_path,
                })
            })
            .collect();
        output::print_json_pretty(&out)?;
    } else if resp.routes.is_empty() {
        println!("No EVPN routes");
    } else {
        // Two distinct concepts both spell "tag" in EVPN-land: the
        // route-type label (RFC 7432 §7) is `mac-ip` / `imet` / etc.,
        // and `ethernet_tag` is the EVI/bridge-domain identifier
        // pushed into `detail` as `tag=N`. Use `route_label` for the
        // local variable so the bracket prefix and the `tag=` field
        // don't both render via something named `tag` in the same
        // function — the operator-facing column header `tag=N`
        // matches FRR / Cisco convention and stays untouched.
        for r in &resp.routes {
            let route_label = route_type_label(r.route_type);
            let mut detail = Vec::new();
            detail.push(format!("rd={}", r.rd));
            if !r.esi.is_empty() {
                detail.push(format!("esi={}", r.esi));
            }
            if !r.ethernet_tag.is_empty() {
                detail.push(format!("tag={}", r.ethernet_tag));
            }
            if !r.mac.is_empty() {
                detail.push(format!("mac={}", r.mac));
            }
            if !r.ip.is_empty() {
                detail.push(format!("ip={}", r.ip));
            }
            if !r.prefix.is_empty() {
                detail.push(format!("prefix={}", r.prefix));
            }
            if !r.gateway.is_empty() {
                detail.push(format!("gw={}", r.gateway));
            }
            if r.label != 0 {
                detail.push(format!("label={}", r.label));
            }
            if r.label2 != 0 {
                detail.push(format!("label2={}", r.label2));
            }
            if r.tunnel_type == 8 {
                detail.push("encap=vxlan".to_string());
            } else if r.tunnel_type != 0 {
                detail.push(format!("encap-type={}", r.tunnel_type));
            }
            println!(
                "[{route_label}] {} via {} from {}",
                detail.join(" "),
                r.next_hop,
                r.peer_address,
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn add_mac_ip(
    connection: Connection,
    rd: String,
    ethernet_tag: u32,
    mac: String,
    ip: String,
    label: u32,
    label2: u32,
    next_hop: String,
    route_targets: Vec<String>,
    disable_vxlan_encap: bool,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        InjectionServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .add_evpn_route(AddEvpnRouteRequest {
            route_type: 2,
            rd,
            ethernet_tag,
            mac,
            ip,
            label,
            label2,
            next_hop,
            route_targets,
            disable_vxlan_encap,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: String::new(),
        })
        .await?;
    output::print_result(json, "add_evpn", "", "EVPN Type 2 route added")
}

#[allow(clippy::too_many_arguments)]
pub async fn add_imet(
    connection: Connection,
    rd: String,
    ethernet_tag: u32,
    ip: String,
    next_hop: String,
    route_targets: Vec<String>,
    disable_vxlan_encap: bool,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        InjectionServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .add_evpn_route(AddEvpnRouteRequest {
            route_type: 3,
            rd,
            ethernet_tag,
            mac: String::new(),
            ip,
            label: 0,
            label2: 0,
            next_hop,
            route_targets,
            disable_vxlan_encap,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: String::new(),
        })
        .await?;
    output::print_result(json, "add_evpn", "", "EVPN Type 3 route added")
}

#[allow(clippy::too_many_arguments)]
pub async fn add_ip_prefix(
    connection: Connection,
    rd: String,
    ethernet_tag: u32,
    prefix: String,
    label: u32,
    next_hop: String,
    gateway: Option<String>,
    router_mac: Option<String>,
    route_targets: Vec<String>,
    disable_vxlan_encap: bool,
    json: bool,
) -> Result<(), CliError> {
    let router_mac = router_mac
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    let gateway = gateway
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    validate_ip_prefix_ethernet_tag(ethernet_tag)?;
    validate_add_ip_prefix_args(router_mac.as_deref(), &route_targets, disable_vxlan_encap)?;
    let (prefix, prefix_length) = output::parse_prefix(&prefix).map_err(CliError::Argument)?;
    let mut client =
        InjectionServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .add_evpn_route(AddEvpnRouteRequest {
            route_type: 5,
            rd,
            ethernet_tag,
            mac: String::new(),
            ip: String::new(),
            label,
            label2: 0,
            next_hop,
            route_targets,
            disable_vxlan_encap,
            prefix,
            prefix_length,
            router_mac: router_mac.unwrap_or_default(),
            gateway: gateway.unwrap_or_default(),
        })
        .await?;
    output::print_result(json, "add_evpn", "", "EVPN Type 5 route added")
}

fn validate_ip_prefix_ethernet_tag(ethernet_tag: u32) -> Result<(), CliError> {
    if ethernet_tag != 0 {
        return Err(CliError::Argument(
            "EVPN Type 5 requires --ethernet-tag 0".into(),
        ));
    }
    Ok(())
}

fn validate_add_ip_prefix_args(
    router_mac: Option<&str>,
    route_targets: &[String],
    disable_vxlan_encap: bool,
) -> Result<(), CliError> {
    let router_mac = router_mac.map(str::trim).filter(|s| !s.is_empty());
    if route_targets.is_empty() {
        return Err(CliError::Argument(
            "at least one --rt is required for EVPN Type 5 IP Prefix".into(),
        ));
    }
    match (disable_vxlan_encap, router_mac) {
        (false, None) => Err(CliError::Argument(
            "--router-mac is required unless --no-vxlan-encap is set".into(),
        )),
        (true, Some(_)) => Err(CliError::Argument(
            "--router-mac cannot be used with --no-vxlan-encap".into(),
        )),
        _ => Ok(()),
    }
}

pub async fn delete_mac_ip(
    connection: Connection,
    rd: String,
    ethernet_tag: u32,
    mac: String,
    ip: String,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        InjectionServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_evpn_route(DeleteEvpnRouteRequest {
            route_type: 2,
            rd,
            ethernet_tag,
            mac,
            ip,
            prefix: String::new(),
            prefix_length: 0,
        })
        .await?;
    output::print_result(json, "delete_evpn", "", "EVPN Type 2 route deleted")
}

pub async fn delete_imet(
    connection: Connection,
    rd: String,
    ethernet_tag: u32,
    ip: String,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        InjectionServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_evpn_route(DeleteEvpnRouteRequest {
            route_type: 3,
            rd,
            ethernet_tag,
            mac: String::new(),
            ip,
            prefix: String::new(),
            prefix_length: 0,
        })
        .await?;
    output::print_result(json, "delete_evpn", "", "EVPN Type 3 route deleted")
}

pub async fn delete_ip_prefix(
    connection: Connection,
    rd: String,
    ethernet_tag: u32,
    prefix: String,
    json: bool,
) -> Result<(), CliError> {
    validate_ip_prefix_ethernet_tag(ethernet_tag)?;
    let (prefix, prefix_length) = output::parse_prefix(&prefix).map_err(CliError::Argument)?;
    let mut client =
        InjectionServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_evpn_route(DeleteEvpnRouteRequest {
            route_type: 5,
            rd,
            ethernet_tag,
            mac: String::new(),
            ip: String::new(),
            prefix,
            prefix_length,
        })
        .await?;
    output::print_result(json, "delete_evpn", "", "EVPN Type 5 route deleted")
}

/// Clear one RFC 7432 duplicate-MAC local-origin quarantine.
pub async fn clear_duplicate_mac(
    connection: Connection,
    vni: u32,
    mac: String,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .clear_duplicate_mac_quarantine(ClearDuplicateMacQuarantineRequest {
            vni,
            mac: mac.clone(),
        })
        .await?
        .into_inner();
    if json {
        output::print_json_pretty(&serde_json::json!({
                "vni": vni,
                "mac": mac,
                "cleared": resp.cleared,
                "message": resp.message,
        }))?;
    } else if resp.cleared {
        println!("EVPN duplicate-MAC quarantine cleared: {mac} on VNI {vni}");
    } else {
        println!("No active EVPN duplicate-MAC quarantine: {mac} on VNI {vni}");
    }
    Ok(())
}

/// Drain or undrain one configured Ethernet Segment (ADR-0084).
///
/// Draining withdraws the ES's Type 4 + EAD routes and the member
/// VNIs' local Type 2 routes ahead of access-circuit maintenance;
/// undraining re-originates and replays. This command owns the
/// `operator` drain reason only (ADR-0085): a segment whose bound
/// attachment-circuit link is down keeps its `link` reason — and
/// stays drained — across an operator undrain. The response reports
/// the composed state and the reason set. Drain state is in-memory:
/// a daemon restart clears it (bound segments re-evaluate carrier at
/// startup).
pub async fn set_es_drain(
    connection: Connection,
    esi: String,
    drained: bool,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .set_ethernet_segment_drain(SetEthernetSegmentDrainRequest {
            esi: esi.clone(),
            drained,
        })
        .await?
        .into_inner();
    if json {
        output::print_json_pretty(&serde_json::json!({
                "esi": esi,
                "drained": resp.drained,
                "changed": resp.changed,
                "member_vni_count": resp.member_vni_count,
                "reasons": resp.reasons,
                "message": resp.message,
        }))?;
    } else {
        println!("{}", resp.message);
    }
    Ok(())
}

/// List configured Ethernet Segments joined with live multi-homing state.
pub async fn list_ethernet_segments(
    connection: Connection,
    esi: Option<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let filter = esi.unwrap_or_default();
    let resp = client
        .list_ethernet_segments(ListEthernetSegmentsRequest {
            esi: filter.clone(),
        })
        .await?
        .into_inner();

    if json {
        output::print_json_pretty(&ethernet_segments_to_json(&resp))?;
    } else if resp.segments.is_empty() {
        if filter.is_empty() {
            println!("No Ethernet Segments configured");
        } else {
            println!("No Ethernet Segment matching {filter}");
        }
    } else {
        for segment in &resp.segments {
            println!("{}", format_ethernet_segment_human(segment));
        }
    }
    Ok(())
}

/// Read the committed ADR-0063 EVPN runtime generation.
pub async fn runtime(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let state = client
        .get_evpn_runtime(GetEvpnRuntimeRequest {})
        .await?
        .into_inner();

    if json {
        output::print_json_pretty(&runtime_to_json(&state))?;
    } else {
        println!(
            "EVPN runtime generation={} lifecycle={} mutation={} l2-instances={} ip-vrfs={} ethernet-segments={} es-member-vnis={}",
            state.generation,
            runtime_lifecycle_label(state.lifecycle),
            runtime_mutation_label(state.mutation_state),
            state.evpn_instances_count,
            state.evpn_ip_vrfs_count,
            state.ethernet_segments_count,
            state.ethernet_segment_member_vnis_count,
        );
        if !state.message.is_empty() {
            println!("{}", state.message);
        }
    }
    Ok(())
}

/// List local EVPN instances (Phase 2 VTEP foundation).
///
/// Read-only. Surfaces the daemon's resolved `EvpnInstanceTable` —
/// the same data the operator put in `[[evpn_instances]]` blocks,
/// already normalized through RD/RT parsing and uniqueness checks,
/// joined with the latest L2 dataplane readiness report when present.
pub async fn list_instances(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_evpn_instances(ListEvpnInstancesRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<serde_json::Value> =
            resp.instances.iter().map(evpn_instance_to_json).collect();
        output::print_json_pretty(&out)?;
    } else if resp.instances.is_empty() {
        println!("No local EVPN instances configured");
    } else {
        for inst in &resp.instances {
            let mut detail = vec![
                format!("vni={}", inst.vni),
                format!("rd={}", inst.rd),
                format!("vtep={}", inst.local_vtep_ip),
                format!("rts=[{}]", inst.route_targets.join(",")),
                format!(
                    "readiness={}",
                    evpn_instance_readiness_label(inst.readiness_state)
                ),
            ];
            if !inst.bridge.is_empty() {
                detail.push(format!("bridge={}", inst.bridge));
            }
            if let Some(bridge_vlan) = inst.bridge_vlan {
                detail.push(format!("bridge-vlan={bridge_vlan}"));
            }
            if inst.advertise_svi_mac {
                detail.push("advertise-svi-mac".to_string());
            }
            detail.push(format!(
                "originated-local-macs={}",
                inst.originated_local_macs_count
            ));
            if !inst.not_ready_reason.is_empty() {
                detail.push(format!("reason=[{}]", inst.not_ready_reason));
            }
            println!("{}", detail.join(" "));
        }
    }
    Ok(())
}

fn evpn_instance_readiness_label(state: i32) -> &'static str {
    match EvpnInstanceReadinessState::try_from(state) {
        Ok(EvpnInstanceReadinessState::EvpnInstanceReadinessReady) => "ready",
        Ok(EvpnInstanceReadinessState::EvpnInstanceReadinessNotReady) => "not-ready",
        Ok(EvpnInstanceReadinessState::EvpnInstanceReadinessUnbound) => "unbound",
        Ok(EvpnInstanceReadinessState::EvpnInstanceReadinessUnknown) | Err(_) => "unknown",
    }
}

fn evpn_instance_to_json(instance: &EvpnInstanceState) -> serde_json::Value {
    serde_json::json!({
        "vni": instance.vni,
        "rd": instance.rd,
        "route_targets": instance.route_targets,
        "local_vtep_ip": instance.local_vtep_ip,
        "bridge": instance.bridge,
        "bridge_vlan": instance
            .bridge_vlan
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "advertise_svi_mac": instance.advertise_svi_mac,
        "originated_local_macs_count": instance.originated_local_macs_count,
        "readiness": evpn_instance_readiness_label(instance.readiness_state),
        "not_ready_reason": instance.not_ready_reason,
    })
}

/// List ADR-0091 managed EVPN netdev status rows.
///
/// Read-only. Surfaces the configured `[managed_netdevs]` bridge rows
/// joined with the latest Linux link snapshot, plus rustbgpd-stamped
/// orphan rows observed by the dataplane actor.
pub async fn list_managed_netdevs(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_managed_netdevs(ListManagedNetdevsRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<serde_json::Value> = resp.netdevs.iter().map(managed_netdev_to_json).collect();
        output::print_json_pretty(&out)?;
    } else if resp.netdevs.is_empty() {
        println!("No managed EVPN netdevs configured or observed");
    } else {
        for row in &resp.netdevs {
            let mut detail = vec![
                format!("class={}", managed_netdev_class_label(row.class)),
                format!("name={}", row.name),
                format!("state={}", managed_netdev_state_label(row.state)),
                format!("desired={}", row.desired),
            ];
            if !row.ownership_stamp.is_empty() {
                detail.push(format!("stamp={}", row.ownership_stamp));
            }
            if let Some(ifindex) = row.ifindex {
                detail.push(format!("ifindex={ifindex}"));
            }
            if let Some(vlan_filtering) = row.observed_vlan_filtering {
                detail.push(format!("vlan-filtering={vlan_filtering}"));
            }
            if let Some(vni) = row.observed_vni {
                detail.push(format!("vni={vni}"));
            }
            if let Some(vlan) = row.observed_vlan {
                detail.push(format!("vlan={vlan}"));
            }
            if let Some(local) = row.observed_local.as_deref() {
                detail.push(format!("local={local}"));
            }
            if let Some(dstport) = row.observed_dstport {
                detail.push(format!("dstport={dstport}"));
            }
            if let Some(learning_disabled) = row.observed_learning_disabled {
                detail.push(format!("learning-disabled={learning_disabled}"));
            }
            if let Some(collect_metadata) = row.observed_collect_metadata {
                detail.push(format!("collect-metadata={collect_metadata}"));
            }
            if let Some(vnifilter) = row.observed_vnifilter {
                detail.push(format!("vnifilter={vnifilter}"));
            }
            if let Some(bridge) = row.observed_bridge.as_deref() {
                detail.push(format!("bridge={bridge}"));
            }
            if let Some(table_id) = row.observed_table_id {
                detail.push(format!("table-id={table_id}"));
            }
            if let Some(up) = row.observed_up {
                detail.push(format!("up={up}"));
            }
            if let Some(master) = row.observed_master.as_deref() {
                detail.push(format!("master={master}"));
            }
            if let Some(router_mac) = row.observed_router_mac.as_deref() {
                detail.push(format!("router-mac={router_mac}"));
            }
            if !row.observed_stamps.is_empty() {
                detail.push(format!(
                    "observed-stamps=[{}]",
                    row.observed_stamps.join(",")
                ));
            }
            if !row.reason.is_empty() {
                detail.push(format!("reason=[{}]", row.reason));
            }
            println!("{}", detail.join(" "));
        }
    }
    Ok(())
}

fn managed_netdev_class_label(class: i32) -> &'static str {
    match ManagedNetdevClass::try_from(class) {
        Ok(ManagedNetdevClass::Bridge) => "bridge",
        Ok(ManagedNetdevClass::Vxlan) => "vxlan",
        Ok(ManagedNetdevClass::SvdVxlan) => "svd-vxlan",
        Ok(ManagedNetdevClass::Vrf) => "vrf",
        Ok(ManagedNetdevClass::L3vxlan) => "l3vxlan",
        Ok(ManagedNetdevClass::VlanUpper) => "vlan-upper",
        Ok(ManagedNetdevClass::Unknown) | Err(_) => "unknown",
    }
}

fn managed_netdev_state_label(state: i32) -> &'static str {
    match ManagedNetdevLifecycleState::try_from(state) {
        Ok(ManagedNetdevLifecycleState::ManagedNetdevStateDesiredAbsent) => "desired-absent",
        Ok(ManagedNetdevLifecycleState::ManagedNetdevStateOwnedSafe) => "owned-safe",
        Ok(ManagedNetdevLifecycleState::ManagedNetdevStateForeignPresent) => "foreign-present",
        Ok(ManagedNetdevLifecycleState::ManagedNetdevStateOwnedUnsafe) => "owned-unsafe",
        Ok(ManagedNetdevLifecycleState::ManagedNetdevStateOrphaned) => "orphaned",
        Ok(ManagedNetdevLifecycleState::ManagedNetdevStateUnknown) | Err(_) => "unknown",
    }
}

fn managed_netdev_to_json(row: &ManagedNetdevState) -> serde_json::Value {
    serde_json::json!({
        "class": managed_netdev_class_label(row.class),
        "name": row.name,
        "desired": row.desired,
        "ownership_stamp": if row.ownership_stamp.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(row.ownership_stamp.clone())
        },
        "state": managed_netdev_state_label(row.state),
        "reason": row.reason,
        "ifindex": row
            .ifindex
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_vlan_filtering": row
            .observed_vlan_filtering
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_vni": row
            .observed_vni
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_vlan": row
            .observed_vlan
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_local": row
            .observed_local
            .as_ref()
            .map_or(serde_json::Value::Null, |value| serde_json::Value::String(value.clone())),
        "observed_dstport": row
            .observed_dstport
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_learning_disabled": row
            .observed_learning_disabled
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_collect_metadata": row
            .observed_collect_metadata
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_vnifilter": row
            .observed_vnifilter
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_bridge": row
            .observed_bridge
            .as_ref()
            .map_or(serde_json::Value::Null, |value| serde_json::Value::String(value.clone())),
        "observed_table_id": row
            .observed_table_id
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_up": row
            .observed_up
            .map_or(serde_json::Value::Null, serde_json::Value::from),
        "observed_master": row
            .observed_master
            .as_ref()
            .map_or(serde_json::Value::Null, |value| serde_json::Value::String(value.clone())),
        "observed_router_mac": row
            .observed_router_mac
            .as_ref()
            .map_or(serde_json::Value::Null, |value| serde_json::Value::String(value.clone())),
        "observed_stamps": row.observed_stamps,
    })
}

/// List owned ADR-0059 FDB nexthop groups.
///
/// Read-only. Surfaces the reconciler's actor-owned view of FDB-NHG
/// groups, per-VTEP member IDs, MAC refs, and orphan / pending-delete
/// cleanup counters. Empty in RR-only deployments and on VTEPs with no
/// multi-homed Type 2 state currently installed.
pub async fn list_nexthops(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_evpn_nexthops(ListEvpnNexthopsRequest {})
        .await?
        .into_inner();

    if json {
        output::print_json_pretty(&fdb_nexthops_to_json(&resp))?;
    } else {
        // Print the latch directly rather than label it as
        // "enabled" / "disabled" — `drift_recovery_disabled = false`
        // is also the default state of an empty snapshot (RR-only,
        // non-Linux build, pre-first-report) where no drift loop is
        // running at all, so a derived "enabled" label would
        // misrepresent those cases.
        println!(
            "FDB nexthop groups: {} orphan-nexthops={} pending-deletes={} drift-recovery-disabled={}",
            resp.groups.len(),
            resp.orphan_nexthops_count,
            resp.pending_delete_count,
            resp.drift_recovery_disabled,
        );
        if resp.groups.is_empty() {
            println!("No owned FDB nexthop groups");
        } else {
            for group in &resp.groups {
                // Use `nh_id=N via <gw>` per-member so IPv6 gateways
                // (which contain colons natively) don't collide with
                // any `gateway:nh_id` delimiter.
                let members = group
                    .members
                    .iter()
                    .map(|m| format!("nh_id={} via {}", m.nexthop_id, m.gateway))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "vni={} esi={} tag={} group-id={} members=[{}] mac-refs=[{}]",
                    group.vni,
                    group.esi,
                    group.ethernet_tag,
                    group.group_id,
                    members,
                    group.ref_macs.join(","),
                );
            }
        }
    }
    Ok(())
}

fn fdb_nexthops_to_json(resp: &crate::proto::ListEvpnNexthopsResponse) -> serde_json::Value {
    let groups: Vec<serde_json::Value> = resp
        .groups
        .iter()
        .map(|g| {
            serde_json::json!({
                "vni": g.vni,
                "esi": g.esi,
                "ethernet_tag": g.ethernet_tag,
                "group_id": g.group_id,
                "members": g.members.iter().map(|m| {
                    serde_json::json!({
                        "gateway": m.gateway,
                        "nexthop_id": m.nexthop_id,
                    })
                }).collect::<Vec<_>>(),
                "ref_macs": g.ref_macs,
            })
        })
        .collect();
    serde_json::json!({
        "groups": groups,
        "orphan_nexthops_count": resp.orphan_nexthops_count,
        "pending_delete_count": resp.pending_delete_count,
        "drift_recovery_disabled": resp.drift_recovery_disabled,
    })
}

fn ethernet_segments_to_json(resp: &ListEthernetSegmentsResponse) -> serde_json::Value {
    let segments: Vec<serde_json::Value> = resp
        .segments
        .iter()
        .map(|segment| {
            serde_json::json!({
                "esi": segment.esi,
                "member_vnis": segment.member_vnis,
                "redundancy_mode": segment.redundancy_mode,
                "df_algorithm": segment.df_algorithm,
                "df_preference": segment.df_preference,
                "df_dont_preempt": segment.df_dont_preempt,
                "originator_ip": segment.originator_ip,
                "drained": segment.drained,
                "drain_reasons": segment.drain_reasons,
                "members": segment.members.iter().map(|member| {
                    serde_json::json!({
                        "vni": member.vni,
                        "df_role": member.df_role,
                        "bum_forwarding_action": member.bum_forwarding_action,
                        "bridge": member.bridge,
                        "same_esi_bias_eligible": member.same_esi_bias_eligible,
                    })
                }).collect::<Vec<_>>(),
                "ac_gate_state": segment.ac_gate_state,
                "ac_gate_interface": segment.ac_gate_interface,
                "fdb_nexthop_groups_count": segment.fdb_nexthop_groups_count,
                "fdb_nexthop_ref_macs_count": segment.fdb_nexthop_ref_macs_count,
            })
        })
        .collect();
    serde_json::json!({ "segments": segments })
}

fn format_ethernet_segment_human(segment: &EthernetSegmentState) -> String {
    let reasons = if segment.drain_reasons.is_empty() {
        "none".to_string()
    } else {
        segment.drain_reasons.join(",")
    };
    let ac_gate = if segment.ac_gate_state.is_empty() {
        "none".to_string()
    } else if segment.ac_gate_interface.is_empty() {
        segment.ac_gate_state.clone()
    } else {
        format!("{}:{}", segment.ac_gate_state, segment.ac_gate_interface)
    };
    let members = segment
        .members
        .iter()
        .map(format_ethernet_segment_member_human)
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "esi={} mode={} df-alg={} df-pref={} dont-preempt={} originator={} drained={} reasons=[{}] ac-gate={} fdb-groups={} fdb-mac-refs={} members=[{}]",
        segment.esi,
        segment.redundancy_mode,
        segment.df_algorithm,
        segment.df_preference,
        segment.df_dont_preempt,
        segment.originator_ip,
        segment.drained,
        reasons,
        ac_gate,
        segment.fdb_nexthop_groups_count,
        segment.fdb_nexthop_ref_macs_count,
        members,
    )
}

fn format_ethernet_segment_member_human(
    member: &crate::proto::EthernetSegmentMemberState,
) -> String {
    let mut parts = vec![format!("vni={}", member.vni)];
    if !member.df_role.is_empty() {
        parts.push(format!("role={}", member.df_role));
    }
    if !member.bum_forwarding_action.is_empty() {
        parts.push(format!("bum={}", member.bum_forwarding_action));
    }
    if !member.bridge.is_empty() {
        parts.push(format!("bridge={}", member.bridge));
    }
    if member.same_esi_bias_eligible {
        parts.push("same-esi-bias".to_string());
    }
    parts.join("/")
}

fn runtime_to_json(state: &EvpnRuntimeState) -> serde_json::Value {
    serde_json::json!({
        "generation": state.generation,
        "lifecycle": runtime_lifecycle_label(state.lifecycle),
        "mutation_state": runtime_mutation_label(state.mutation_state),
        "evpn_instances_count": state.evpn_instances_count,
        "evpn_ip_vrfs_count": state.evpn_ip_vrfs_count,
        "ethernet_segments_count": state.ethernet_segments_count,
        "ethernet_segment_member_vnis_count": state.ethernet_segment_member_vnis_count,
        "message": state.message,
    })
}

fn runtime_lifecycle_label(state: i32) -> &'static str {
    match EvpnRuntimeLifecycle::try_from(state) {
        Ok(EvpnRuntimeLifecycle::Active) => "active",
        Ok(EvpnRuntimeLifecycle::Activating) => "activating",
        Ok(EvpnRuntimeLifecycle::Deleting) => "deleting",
        Ok(EvpnRuntimeLifecycle::Degraded) => "degraded",
        Ok(EvpnRuntimeLifecycle::Unknown) | Err(_) => "unknown",
    }
}

fn runtime_mutation_label(state: i32) -> &'static str {
    match EvpnRuntimeMutationState::try_from(state) {
        Ok(EvpnRuntimeMutationState::EvpnRuntimeMutationDisabled) => "disabled",
        Ok(EvpnRuntimeMutationState::EvpnRuntimeMutationIdle) => "idle",
        Ok(EvpnRuntimeMutationState::EvpnRuntimeMutationInProgress) => "in-progress",
        Ok(EvpnRuntimeMutationState::EvpnRuntimeMutationFailed) => "failed",
        Ok(EvpnRuntimeMutationState::EvpnRuntimeMutationUnknown) | Err(_) => "unknown",
    }
}

/// List configured IP-VRFs and their readiness (Gate 9, ADR-0058).
///
/// Read-only. Returns one row per `[[evpn_ip_vrfs]]` entry the daemon
/// has resolved, joined with the latest readiness verdict from the
/// reconcile actor's `probe_ip_vrfs` pass. Deployments without any
/// `[[evpn_ip_vrfs]]` get an empty list; deployments that have IP-VRFs
/// configured but no reconcile actor running (RR-only mode) see each
/// row with `readiness=unknown` and the config fields populated.
pub async fn list_ip_vrfs(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_ip_vrfs(ListIpVrfsRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<serde_json::Value> = resp.ip_vrfs.iter().map(ip_vrf_to_json).collect();
        output::print_json_pretty(&out)?;
    } else if resp.ip_vrfs.is_empty() {
        println!("No IP-VRFs configured");
    } else {
        for vrf in &resp.ip_vrfs {
            println!("{}", format_ip_vrf_human(vrf));
        }
    }
    Ok(())
}

/// Fetch one IP-VRF by name (Gate 9, ADR-0058). Returns `NotFound`
/// if the operator-facing handle isn't in the resolved table.
pub async fn get_ip_vrf(connection: Connection, name: String, json: bool) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let vrf = client
        .get_ip_vrf(GetIpVrfRequest { name })
        .await?
        .into_inner();

    if json {
        output::print_json_pretty(&ip_vrf_to_json(&vrf))?;
    } else {
        println!("{}", format_ip_vrf_human(&vrf));
        // In the detail view we also print each not-ready reason on
        // its own indented line so operators can scan the failures
        // without parsing the parenthesized list.
        if !vrf.not_ready_reasons.is_empty() {
            for reason in &vrf.not_ready_reasons {
                println!("  - {reason}");
            }
        }
    }
    Ok(())
}

fn readiness_label(state: i32) -> &'static str {
    match IpVrfReadinessState::try_from(state) {
        Ok(IpVrfReadinessState::IpVrfReadinessReady) => "ready",
        Ok(IpVrfReadinessState::IpVrfReadinessNotReady) => "not-ready",
        Ok(IpVrfReadinessState::IpVrfReadinessUnknown) => "unknown",
        Err(_) => "unknown",
    }
}

fn ip_vrf_to_json(vrf: &IpVrfState) -> serde_json::Value {
    serde_json::json!({
        "name": vrf.name,
        "vni": vrf.vni,
        "rd": vrf.rd,
        "route_targets": vrf.route_targets,
        "local_vtep_ip": vrf.local_vtep_ip,
        "router_mac": vrf.router_mac,
        "vrf_device": vrf.vrf_device,
        "l3vxlan_device": vrf.l3vxlan_device,
        "table_id": vrf.table_id,
        "readiness": readiness_label(vrf.readiness_state),
        "vrf_ifindex": vrf.vrf_ifindex,
        "l3vxlan_ifindex": vrf.l3vxlan_ifindex,
        "not_ready_reasons": vrf.not_ready_reasons,
        "originated_routes_count": vrf.originated_routes_count,
        "installed_routes_count": vrf.installed_routes_count,
        "remote_prefix_drop_counts": vrf.remote_prefix_drop_counts.iter().map(|row| {
            serde_json::json!({
                "reason": row.reason,
                "count": row.count,
            })
        }).collect::<Vec<_>>(),
    })
}

fn format_ip_vrf_human(vrf: &IpVrfState) -> String {
    let mut parts = vec![
        format!("name={}", vrf.name),
        format!("vni={}", vrf.vni),
        format!("rd={}", vrf.rd),
        format!("rts=[{}]", vrf.route_targets.join(",")),
        format!("vtep={}", vrf.local_vtep_ip),
        format!("router-mac={}", vrf.router_mac),
        format!("vrf-device={}", vrf.vrf_device),
        format!("l3vxlan-device={}", vrf.l3vxlan_device),
        format!("table-id={}", vrf.table_id),
        format!("readiness={}", readiness_label(vrf.readiness_state)),
    ];
    if matches!(
        IpVrfReadinessState::try_from(vrf.readiness_state),
        Ok(IpVrfReadinessState::IpVrfReadinessReady)
    ) {
        parts.push(format!("vrf-ifindex={}", vrf.vrf_ifindex));
        parts.push(format!("l3vxlan-ifindex={}", vrf.l3vxlan_ifindex));
    }
    if !vrf.not_ready_reasons.is_empty() {
        parts.push(format!("reasons=[{}]", vrf.not_ready_reasons.join("; ")));
    }
    parts.push(format!("originated-routes={}", vrf.originated_routes_count));
    parts.push(format!("installed-routes={}", vrf.installed_routes_count));
    if !vrf.remote_prefix_drop_counts.is_empty() {
        let drops = vrf
            .remote_prefix_drop_counts
            .iter()
            .map(|row| format!("{}={}", row.reason, row.count))
            .collect::<Vec<_>>()
            .join(",");
        parts.push(format!("remote-prefix-drops=[{drops}]"));
    }
    parts.join(" ")
}

/// Read-only EVPN alpha health summary.
pub async fn diagnose(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut evpn_client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let instances = evpn_client
        .list_evpn_instances(ListEvpnInstancesRequest {})
        .await?
        .into_inner()
        .instances;

    let mut rib_client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let type2_routes = rib_client
        .list_evpn_routes(ListEvpnRequest {
            route_type_filter: 2,
            peer_filter: String::new(),
            rd_filter: String::new(),
        })
        .await?
        .into_inner()
        .routes;
    let type3_routes = rib_client
        .list_evpn_routes(ListEvpnRequest {
            route_type_filter: 3,
            peer_filter: String::new(),
            rd_filter: String::new(),
        })
        .await?
        .into_inner()
        .routes;

    let mut control_client =
        ControlServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let metrics = control_client
        .get_metrics(MetricsRequest {})
        .await?
        .into_inner()
        .prometheus_text;
    let key_metrics = extract_key_evpn_metric_lines(&metrics);

    let originated_local_macs: u64 = instances
        .iter()
        .map(|i| i.originated_local_macs_count)
        .sum();

    if json {
        output::print_json_pretty(&serde_json::json!({
                "instance_count": instances.len(),
                "originated_local_macs_count": originated_local_macs,
                "type2_route_count": type2_routes.len(),
                "type2_present": !type2_routes.is_empty(),
                "type3_route_count": type3_routes.len(),
                "type3_present": !type3_routes.is_empty(),
                "key_metrics": key_metrics,
        }))?;
    } else {
        println!("EVPN diagnose");
        println!("Instances: {}", instances.len());
        println!("Originated local MACs: {originated_local_macs}");
        println!(
            "Type 2 routes: {} ({})",
            type2_routes.len(),
            if type2_routes.is_empty() {
                "missing"
            } else {
                "present"
            }
        );
        println!(
            "Type 3 IMET routes: {} ({})",
            type3_routes.len(),
            if type3_routes.is_empty() {
                "missing"
            } else {
                "present"
            }
        );
        println!("Key EVPN metrics:");
        if key_metrics.is_empty() {
            println!("  none observed");
        } else {
            for line in key_metrics {
                println!("  {line}");
            }
        }
    }

    Ok(())
}

fn extract_key_evpn_metric_lines(prometheus_text: &str) -> Vec<String> {
    prometheus_text
        .lines()
        .filter(|line| {
            !line.starts_with('#')
                && EVPN_DIAGNOSE_METRIC_PREFIXES
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    //! End-to-end integration tests for the EVPN VTEP foundation slice.
    //!
    //! Drives a *real* `rustbgpd_api::EvpnService` (not a mock) over a
    //! UDS, backed by an `EvpnInstanceTable` populated from the same
    //! domain types operator config resolves into. Asserts both the
    //! gRPC wire shape (via the generated client) and that the CLI
    //! command function (`list_instances`) exits cleanly against a
    //! real server. Together this proves the seam from the resolved
    //! domain table → gRPC service → wire serialization → CLI client
    //! → CLI render works end-to-end.
    //!
    //! The remaining seam — daemon binary `main()` wiring through to
    //! `ServeConfig.evpn_instances` — is pinned by
    //! `tests/evpn_instances_binary.rs`: it boots the real daemon binary
    //! and drives `rbgp evpn instances` as a subprocess before
    //! kernel reconciliation grows the internals (see
    //! `docs/evpn-enablement.md` Gate 7b).
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::Request;
    use tonic::transport::Server;
    use tower::service_fn;

    use rustbgpd_api::EvpnService;
    use rustbgpd_api::proto::evpn_service_server::EvpnServiceServer;
    use rustbgpd_evpn::{BridgeVlan, EvpnInstance, EvpnInstanceId, EvpnInstanceTable, RouteTarget};
    use rustbgpd_wire::RouteDistinguisher;

    use crate::proto::ListEvpnInstancesRequest;
    use crate::proto::evpn_service_client::EvpnServiceClient;

    /// Build a realistic `EvpnInstanceTable` covering the field surface
    /// operators actually use: minimal instance, instance with bridge,
    /// instance with `advertise_svi_mac`, multi-RT instance.
    fn fixture_table() -> EvpnInstanceTable {
        let mut t = EvpnInstanceTable::new();
        t.insert(
            EvpnInstance::new(
                EvpnInstanceId::new(100).unwrap(),
                "65000:100".parse::<RouteDistinguisher>().unwrap(),
                vec!["65000:100".parse().unwrap()],
                "10.0.0.10".parse().unwrap(),
                None,
                false,
            )
            .unwrap(),
        )
        .unwrap();
        t.insert(
            EvpnInstance::new(
                EvpnInstanceId::new(200).unwrap(),
                "65000:200".parse::<RouteDistinguisher>().unwrap(),
                vec![
                    "65000:200".parse::<RouteTarget>().unwrap(),
                    "65000:201".parse().unwrap(),
                ],
                "10.0.0.10".parse().unwrap(),
                Some("br200".into()),
                true,
            )
            .unwrap()
            .with_bridge_vlan(Some(BridgeVlan::new(20).unwrap())),
        )
        .unwrap();
        t
    }

    fn unique_uds_path() -> (TempDir, PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix("rustbgpd-cli-evpn-it-")
            .tempdir()
            .unwrap();
        let path = dir.path().join("evpn.sock");
        (dir, path)
    }

    /// Spawn a real `EvpnServiceServer` over the given UDS path with the
    /// supplied table, returning a shutdown oneshot. The caller drops
    /// the sender to terminate the server.
    fn spawn_real_evpn_server(path: PathBuf, table: Arc<EvpnInstanceTable>) -> oneshot::Sender<()> {
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::UnixListener::from_std(listener).unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let svc = EvpnService::new(table);
        tokio::spawn(async move {
            Server::builder()
                .add_service(EvpnServiceServer::new(svc))
                .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        shutdown_tx
    }

    /// Wait briefly for the server to start accepting connections so
    /// the test isn't racy on cold startup.
    async fn wait_for_uds(path: &std::path::Path) {
        for _ in 0..50 {
            if path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("UDS at {} did not appear within 500ms", path.display());
    }

    /// Build a tonic channel hitting the given UDS path. Mirrors the
    /// production `connection::connect` UDS path without the auth /
    /// rendering layers.
    async fn uds_channel(path: PathBuf) -> tonic::transport::Channel {
        let connector = service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        });
        tonic::transport::Endpoint::try_from("http://[::]:0")
            .unwrap()
            .connect_with_connector(connector)
            .await
            .unwrap()
    }

    /// Direct gRPC-client integration: asserts the wire shape end-to-end
    /// (resolved domain table → tonic service → proto bytes → generated
    /// client → deserialized response). This is the structural test —
    /// every operator-visible field lives at exactly the expected
    /// position with the expected canonical formatting.
    #[tokio::test]
    async fn evpn_service_returns_resolved_table_over_grpc() {
        let (_dir, path) = unique_uds_path();
        let table = Arc::new(fixture_table());
        let _shutdown = spawn_real_evpn_server(path.clone(), table);
        wait_for_uds(&path).await;

        let channel = uds_channel(path.clone()).await;
        let mut client = EvpnServiceClient::new(channel);
        let resp = client
            .list_evpn_instances(Request::new(ListEvpnInstancesRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(resp.instances.len(), 2, "fixture installs two instances");

        // Sorted by VNI ascending — pin the contract that EvpnService
        // surfaces in stable VNI order so CLI output and any
        // diff-against-prior tooling stays deterministic.
        let row100 = &resp.instances[0];
        assert_eq!(row100.vni, 100);
        assert_eq!(row100.rd, "65000:100");
        assert_eq!(row100.local_vtep_ip, "10.0.0.10");
        assert_eq!(row100.route_targets, vec!["65000:100"]);
        assert!(row100.bridge.is_empty(), "no bridge on minimal instance");
        assert!(!row100.advertise_svi_mac);
        assert_eq!(row100.originated_local_macs_count, 0);
        assert_eq!(
            row100.readiness_state,
            crate::proto::EvpnInstanceReadinessState::EvpnInstanceReadinessUnbound as i32
        );
        assert!(row100.not_ready_reason.is_empty());

        let row200 = &resp.instances[1];
        assert_eq!(row200.vni, 200);
        assert_eq!(row200.rd, "65000:200");
        assert_eq!(row200.bridge, "br200");
        assert_eq!(row200.bridge_vlan, Some(20));
        assert!(row200.advertise_svi_mac);
        assert_eq!(row200.originated_local_macs_count, 0);
        assert_eq!(
            row200.readiness_state,
            crate::proto::EvpnInstanceReadinessState::EvpnInstanceReadinessUnknown as i32
        );
        // RTs preserved in the canonicalized order EvpnInstance::new
        // produces (sorted + deduped).
        assert_eq!(row200.route_targets, vec!["65000:200", "65000:201"]);

        let _ = std::fs::remove_file(&path);
    }

    /// CLI render integration: drives the real `list_instances` command
    /// function against the real server. Doesn't assert stdout (would
    /// require redirection plumbing the existing CLI tests don't have)
    /// — proves the command's gRPC client construction, request
    /// serialization, response deserialization, and render branches all
    /// execute without panic / error against a populated table.
    #[tokio::test]
    async fn list_instances_command_runs_against_real_service() {
        let (_dir, path) = unique_uds_path();
        let table = Arc::new(fixture_table());
        let _shutdown = spawn_real_evpn_server(path.clone(), table);
        wait_for_uds(&path).await;

        let addr = format!("unix://{}", path.display());
        let connection = crate::connection::connect(&addr, None).await.unwrap();

        // Both render branches: human and JSON.
        super::list_instances(connection, false).await.unwrap();
        let connection = crate::connection::connect(&addr, None).await.unwrap();
        super::list_instances(connection, true).await.unwrap();

        let _ = std::fs::remove_file(&path);
    }

    /// Empty-table case: `[[evpn_instances]]` is empty (RR-only
    /// deployment). The service must surface an empty list cleanly,
    /// not error or panic on the empty Arc.
    #[tokio::test]
    async fn empty_table_returns_empty_list() {
        let (_dir, path) = unique_uds_path();
        let table = Arc::new(EvpnInstanceTable::new());
        let _shutdown = spawn_real_evpn_server(path.clone(), table);
        wait_for_uds(&path).await;

        let channel = uds_channel(path.clone()).await;
        let mut client = EvpnServiceClient::new(channel);
        let resp = client
            .list_evpn_instances(Request::new(ListEvpnInstancesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.instances.is_empty());

        // CLI render of empty list shouldn't error either.
        let connection = crate::connection::connect(&format!("unix://{}", path.display()), None)
            .await
            .unwrap();
        super::list_instances(connection, false).await.unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn diagnose_metric_filter_keeps_only_key_evpn_samples() {
        let text = r#"
# HELP evpn_local_originations_total help
evpn_local_originations_total{action="inject"} 3
bgp_messages_sent_total{peer="10.0.0.1",type="update"} 4
evpn_duplicate_mac_first_move_timestamp_seconds{vni="100",mac="02:aa:bb:cc:dd:01"} 1778188000
evpn_duplicate_mac_moves_total{vni="100",mac="02:aa:bb:cc:dd:01"} 2
"#;

        assert_eq!(
            super::extract_key_evpn_metric_lines(text),
            vec![
                "evpn_local_originations_total{action=\"inject\"} 3",
                "evpn_duplicate_mac_first_move_timestamp_seconds{vni=\"100\",mac=\"02:aa:bb:cc:dd:01\"} 1778188000",
                "evpn_duplicate_mac_moves_total{vni=\"100\",mac=\"02:aa:bb:cc:dd:01\"} 2",
            ]
        );
    }

    #[tokio::test]
    async fn diagnose_command_runs_against_real_mock_services() {
        let server = crate::test_support::spawn_mock_server(None).await;
        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::diagnose(connection, false).await.unwrap();

        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::diagnose(connection, true).await.unwrap();
    }

    #[tokio::test]
    async fn runtime_command_runs_against_mock_service() {
        let server = crate::test_support::spawn_mock_server(None).await;
        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::runtime(connection, false).await.unwrap();

        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::runtime(connection, true).await.unwrap();
    }

    #[tokio::test]
    async fn list_nexthops_command_runs_against_mock_service() {
        let server = crate::test_support::spawn_mock_server(None).await;
        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::list_nexthops(connection, false).await.unwrap();

        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::list_nexthops(connection, true).await.unwrap();
    }

    #[tokio::test]
    async fn list_managed_netdevs_command_runs_against_mock_service() {
        let server = crate::test_support::spawn_mock_server(None).await;
        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::list_managed_netdevs(connection, false)
            .await
            .unwrap();

        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::list_managed_netdevs(connection, true).await.unwrap();
    }

    #[test]
    fn managed_netdev_json_shape_is_stable() {
        let value = super::managed_netdev_to_json(&crate::proto::ManagedNetdevState {
            class: crate::proto::ManagedNetdevClass::Bridge as i32,
            name: "br100".to_string(),
            desired: true,
            ownership_stamp: "rustbgpd:bridge:leaf-1:br100".to_string(),
            state: crate::proto::ManagedNetdevLifecycleState::ManagedNetdevStateOwnedSafe as i32,
            reason: String::new(),
            ifindex: Some(10),
            observed_vlan_filtering: Some(false),
            observed_stamps: vec!["rustbgpd:bridge:leaf-1:br100".to_string()],
            observed_vni: None,
            observed_vlan: None,
            observed_local: None,
            observed_dstport: None,
            observed_learning_disabled: None,
            observed_collect_metadata: None,
            observed_vnifilter: None,
            observed_bridge: None,
            observed_table_id: None,
            observed_up: None,
            observed_master: None,
            observed_router_mac: None,
        });

        assert_eq!(value["class"], "bridge");
        assert_eq!(value["name"], "br100");
        assert_eq!(value["desired"], true);
        assert_eq!(value["ownership_stamp"], "rustbgpd:bridge:leaf-1:br100");
        assert_eq!(value["state"], "owned-safe");
        assert_eq!(value["ifindex"], 10);
        assert_eq!(value["observed_vlan_filtering"], false);
        assert!(value["observed_vni"].is_null());
        assert_eq!(value["observed_stamps"][0], "rustbgpd:bridge:leaf-1:br100");

        let vxlan = super::managed_netdev_to_json(&crate::proto::ManagedNetdevState {
            class: crate::proto::ManagedNetdevClass::Vxlan as i32,
            name: "vxlan100".to_string(),
            desired: true,
            ownership_stamp: "rustbgpd:vxlan:leaf-1:vxlan100".to_string(),
            state: crate::proto::ManagedNetdevLifecycleState::ManagedNetdevStateOwnedSafe as i32,
            reason: String::new(),
            ifindex: Some(20),
            observed_vlan_filtering: None,
            observed_stamps: vec!["rustbgpd:vxlan:leaf-1:vxlan100".to_string()],
            observed_vni: Some(100),
            observed_vlan: None,
            observed_local: Some("10.0.0.1".to_string()),
            observed_dstport: Some(4789),
            observed_learning_disabled: Some(true),
            observed_collect_metadata: Some(false),
            observed_vnifilter: Some(false),
            observed_bridge: Some("br100".to_string()),
            observed_table_id: None,
            observed_up: None,
            observed_master: None,
            observed_router_mac: None,
        });
        assert_eq!(vxlan["class"], "vxlan");
        assert_eq!(vxlan["observed_vni"], 100);
        assert_eq!(vxlan["observed_local"], "10.0.0.1");
        assert_eq!(vxlan["observed_dstport"], 4789);
        assert_eq!(vxlan["observed_learning_disabled"], true);
        assert_eq!(vxlan["observed_collect_metadata"], false);
        assert_eq!(vxlan["observed_vnifilter"], false);
        assert_eq!(vxlan["observed_bridge"], "br100");

        let vrf = super::managed_netdev_to_json(&crate::proto::ManagedNetdevState {
            class: crate::proto::ManagedNetdevClass::Vrf as i32,
            name: "vrf100".to_string(),
            desired: true,
            ownership_stamp: "rustbgpd:vrf:leaf-1:vrf100".to_string(),
            state: crate::proto::ManagedNetdevLifecycleState::ManagedNetdevStateOwnedSafe as i32,
            reason: String::new(),
            ifindex: Some(30),
            observed_vlan_filtering: None,
            observed_stamps: vec!["rustbgpd:vrf:leaf-1:vrf100".to_string()],
            observed_vni: None,
            observed_vlan: None,
            observed_local: None,
            observed_dstport: None,
            observed_learning_disabled: None,
            observed_collect_metadata: None,
            observed_vnifilter: None,
            observed_bridge: None,
            observed_table_id: Some(5000),
            observed_up: Some(true),
            observed_master: None,
            observed_router_mac: None,
        });
        assert_eq!(vrf["class"], "vrf");
        assert_eq!(vrf["observed_table_id"], 5000);
        assert_eq!(vrf["observed_up"], true);

        let l3vxlan = super::managed_netdev_to_json(&crate::proto::ManagedNetdevState {
            class: crate::proto::ManagedNetdevClass::L3vxlan as i32,
            name: "l3vxlan100".to_string(),
            desired: true,
            ownership_stamp: "rustbgpd:l3vxlan:leaf-1:l3vxlan100".to_string(),
            state: crate::proto::ManagedNetdevLifecycleState::ManagedNetdevStateOwnedSafe as i32,
            reason: String::new(),
            ifindex: Some(40),
            observed_vlan_filtering: None,
            observed_stamps: vec!["rustbgpd:l3vxlan:leaf-1:l3vxlan100".to_string()],
            observed_vni: Some(5000),
            observed_vlan: None,
            observed_local: Some("10.0.0.1".to_string()),
            observed_dstport: Some(4789),
            observed_learning_disabled: Some(true),
            observed_collect_metadata: Some(false),
            observed_vnifilter: Some(false),
            observed_bridge: None,
            observed_table_id: None,
            observed_up: Some(true),
            observed_master: Some("vrf100".to_string()),
            observed_router_mac: Some("02:00:00:00:00:01".to_string()),
        });
        assert_eq!(l3vxlan["class"], "l3vxlan");
        assert_eq!(l3vxlan["observed_master"], "vrf100");
        assert_eq!(l3vxlan["observed_router_mac"], "02:00:00:00:00:01");

        let vlan_upper = super::managed_netdev_to_json(&crate::proto::ManagedNetdevState {
            class: crate::proto::ManagedNetdevClass::VlanUpper as i32,
            name: "br100.10".to_string(),
            desired: true,
            ownership_stamp: "rustbgpd:vlan-upper:leaf-1:br100.10".to_string(),
            state: crate::proto::ManagedNetdevLifecycleState::ManagedNetdevStateOwnedSafe as i32,
            reason: String::new(),
            ifindex: Some(50),
            observed_vlan_filtering: None,
            observed_stamps: vec!["rustbgpd:vlan-upper:leaf-1:br100.10".to_string()],
            observed_vni: None,
            observed_vlan: Some(10),
            observed_local: None,
            observed_dstport: None,
            observed_learning_disabled: None,
            observed_collect_metadata: None,
            observed_vnifilter: None,
            observed_bridge: Some("br100".to_string()),
            observed_table_id: None,
            observed_up: Some(true),
            observed_master: None,
            observed_router_mac: None,
        });
        assert_eq!(vlan_upper["class"], "vlan-upper");
        assert_eq!(vlan_upper["observed_bridge"], "br100");
        assert_eq!(vlan_upper["observed_vlan"], 10);
        assert_eq!(vlan_upper["observed_up"], true);
    }

    #[tokio::test]
    async fn clear_duplicate_mac_command_runs_against_mock_service() {
        let server = crate::test_support::spawn_mock_server(None).await;
        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::clear_duplicate_mac(connection, 100, "aa:bb:cc:dd:ee:ff".to_string(), false)
            .await
            .unwrap();

        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::clear_duplicate_mac(connection, 100, "aa:bb:cc:dd:ee:ff".to_string(), true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn es_drain_commands_run_against_mock_service() {
        let server = crate::test_support::spawn_mock_server(None).await;
        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::set_es_drain(
            connection,
            "00:11:22:33:44:55:66:77:88:99".to_string(),
            true,
            false,
        )
        .await
        .unwrap();

        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::set_es_drain(
            connection,
            "00:11:22:33:44:55:66:77:88:99".to_string(),
            false,
            true,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn es_list_command_runs_against_mock_service() {
        let server = crate::test_support::spawn_mock_server(None).await;
        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::list_ethernet_segments(connection, None, false)
            .await
            .unwrap();

        let connection = crate::connection::connect(&server.addr, None)
            .await
            .unwrap();
        super::list_ethernet_segments(
            connection,
            Some("03:00:00:00:00:00:00:00:00:07".to_string()),
            true,
        )
        .await
        .unwrap();
    }

    #[test]
    fn fdb_nexthops_json_shape_is_stable() {
        let value = super::fdb_nexthops_to_json(&crate::proto::ListEvpnNexthopsResponse {
            groups: vec![crate::proto::EvpnFdbNexthopGroup {
                vni: 100,
                esi: "03:00:00:00:00:00:00:00:00:07".to_string(),
                ethernet_tag: "0".to_string(),
                group_id: 0x4000_0001,
                members: vec![crate::proto::EvpnFdbNexthopMember {
                    gateway: "10.0.0.2".to_string(),
                    nexthop_id: 0x3000_0001,
                }],
                ref_macs: vec!["02:aa:bb:cc:dd:01".to_string()],
            }],
            orphan_nexthops_count: 2,
            pending_delete_count: 1,
            drift_recovery_disabled: true,
        });

        assert_eq!(value["orphan_nexthops_count"], 2);
        assert_eq!(value["pending_delete_count"], 1);
        assert_eq!(value["drift_recovery_disabled"], true);
        assert_eq!(value["groups"][0]["vni"], 100);
        assert_eq!(value["groups"][0]["esi"], "03:00:00:00:00:00:00:00:00:07");
        assert_eq!(value["groups"][0]["ethernet_tag"], "0");
        assert_eq!(value["groups"][0]["group_id"], 0x4000_0001);
        assert_eq!(value["groups"][0]["members"][0]["gateway"], "10.0.0.2");
        assert_eq!(value["groups"][0]["members"][0]["nexthop_id"], 0x3000_0001);
        assert_eq!(value["groups"][0]["ref_macs"][0], "02:aa:bb:cc:dd:01");
    }

    #[test]
    fn ethernet_segments_json_shape_is_stable() {
        let value = super::ethernet_segments_to_json(&crate::proto::ListEthernetSegmentsResponse {
            segments: vec![crate::proto::EthernetSegmentState {
                esi: "03:00:00:00:00:00:00:00:00:07".to_string(),
                member_vnis: vec![100],
                redundancy_mode: "single-active".to_string(),
                df_algorithm: "highest-preference".to_string(),
                df_preference: 500,
                df_dont_preempt: true,
                originator_ip: "10.0.0.1".to_string(),
                drained: true,
                drain_reasons: vec!["operator".to_string(), "link".to_string()],
                members: vec![crate::proto::EthernetSegmentMemberState {
                    vni: 100,
                    df_role: "nondf".to_string(),
                    bum_forwarding_action: "suppress".to_string(),
                    bridge: "br100".to_string(),
                    same_esi_bias_eligible: false,
                }],
                ac_gate_state: "blocked".to_string(),
                ac_gate_interface: "eth1".to_string(),
                fdb_nexthop_groups_count: 1,
                fdb_nexthop_ref_macs_count: 2,
            }],
        });

        assert_eq!(value["segments"][0]["esi"], "03:00:00:00:00:00:00:00:00:07");
        assert_eq!(value["segments"][0]["member_vnis"][0], 100);
        assert_eq!(value["segments"][0]["redundancy_mode"], "single-active");
        assert_eq!(value["segments"][0]["df_algorithm"], "highest-preference");
        assert_eq!(value["segments"][0]["drained"], true);
        assert_eq!(value["segments"][0]["drain_reasons"][0], "operator");
        assert_eq!(value["segments"][0]["members"][0]["df_role"], "nondf");
        assert_eq!(value["segments"][0]["members"][0]["bridge"], "br100");
        assert_eq!(value["segments"][0]["ac_gate_state"], "blocked");
        assert_eq!(value["segments"][0]["fdb_nexthop_ref_macs_count"], 2);
    }

    #[test]
    fn ip_vrf_json_shape_includes_route_counts_and_readiness() {
        let value = super::ip_vrf_to_json(&crate::proto::IpVrfState {
            name: "blue".to_string(),
            vni: 5000,
            rd: "65000:5000".to_string(),
            route_targets: vec!["65000:5000".to_string()],
            local_vtep_ip: "10.0.0.1".to_string(),
            router_mac: "02:00:00:00:00:01".to_string(),
            vrf_device: "vrf-blue".to_string(),
            l3vxlan_device: "vni5000".to_string(),
            table_id: 5000,
            readiness_state: crate::proto::IpVrfReadinessState::IpVrfReadinessReady as i32,
            vrf_ifindex: 11,
            l3vxlan_ifindex: 12,
            not_ready_reasons: vec![],
            originated_routes_count: 3,
            installed_routes_count: 2,
            remote_prefix_drop_counts: vec![crate::proto::IpVrfRemotePrefixDropCount {
                reason: "unresolved_overlay_index_gateway".to_string(),
                count: 4,
            }],
        });

        assert_eq!(value["name"], "blue");
        assert_eq!(value["vni"], 5000);
        assert_eq!(value["readiness"], "ready");
        assert_eq!(value["originated_routes_count"], 3);
        assert_eq!(value["installed_routes_count"], 2);
        assert_eq!(
            value["remote_prefix_drop_counts"][0]["reason"],
            "unresolved_overlay_index_gateway"
        );
        assert_eq!(value["remote_prefix_drop_counts"][0]["count"], 4);
    }

    #[test]
    fn evpn_instance_json_shape_includes_readiness() {
        let value = super::evpn_instance_to_json(&crate::proto::EvpnInstanceState {
            vni: 100,
            rd: "65000:100".to_string(),
            route_targets: vec!["65000:100".to_string()],
            local_vtep_ip: "10.0.0.1".to_string(),
            bridge: "br100".to_string(),
            bridge_vlan: Some(10),
            advertise_svi_mac: true,
            originated_local_macs_count: 5,
            readiness_state: crate::proto::EvpnInstanceReadinessState::EvpnInstanceReadinessNotReady
                as i32,
            not_ready_reason: "bridge br100 is VLAN-aware (vlan_filtering=1)".to_string(),
        });

        assert_eq!(value["vni"], 100);
        assert_eq!(value["bridge"], "br100");
        assert_eq!(value["bridge_vlan"], 10);
        assert_eq!(value["advertise_svi_mac"], true);
        assert_eq!(value["originated_local_macs_count"], 5);
        assert_eq!(value["readiness"], "not-ready");
        assert_eq!(
            value["not_ready_reason"],
            "bridge br100 is VLAN-aware (vlan_filtering=1)"
        );
    }

    #[test]
    fn add_ip_prefix_args_require_route_target_and_router_mac_for_vxlan() {
        let rt = vec!["65000:5000".to_string()];

        let err = super::validate_add_ip_prefix_args(None, &rt, false).unwrap_err();
        assert!(err.to_string().contains("--router-mac"));

        let err = super::validate_add_ip_prefix_args(Some("   "), &rt, false).unwrap_err();
        assert!(err.to_string().contains("--router-mac"));

        let err =
            super::validate_add_ip_prefix_args(Some("02:00:00:00:50:00"), &[], false).unwrap_err();
        assert!(err.to_string().contains("--rt"));

        let err =
            super::validate_add_ip_prefix_args(Some("02:00:00:00:50:00"), &rt, true).unwrap_err();
        assert!(err.to_string().contains("--no-vxlan-encap"));

        super::validate_add_ip_prefix_args(None, &rt, true).unwrap();
        super::validate_add_ip_prefix_args(Some("02:00:00:00:50:00"), &rt, false).unwrap();
    }

    #[test]
    fn ip_prefix_args_reject_nonzero_ethernet_tag() {
        let err = super::validate_ip_prefix_ethernet_tag(100).unwrap_err();
        assert!(err.to_string().contains("--ethernet-tag 0"));
        super::validate_ip_prefix_ethernet_tag(0).unwrap();
    }
}
