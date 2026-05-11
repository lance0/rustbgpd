use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::evpn_service_client::EvpnServiceClient;
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddEvpnRouteRequest, DeleteEvpnRouteRequest, GetIpVrfRequest, IpVrfReadinessState, IpVrfState,
    ListEvpnInstancesRequest, ListEvpnRequest, ListIpVrfsRequest, MetricsRequest,
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
        println!(
            "{}",
            serde_json::to_string_pretty(&out)
                .expect("failed to serialize EVPN route list as JSON")
        );
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
        })
        .await?;
    output::print_result(json, "add_evpn", "", "EVPN Type 2 route added");
    Ok(())
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
        })
        .await?;
    output::print_result(json, "add_evpn", "", "EVPN Type 3 route added");
    Ok(())
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
        })
        .await?;
    output::print_result(json, "delete_evpn", "", "EVPN Type 2 route deleted");
    Ok(())
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
        })
        .await?;
    output::print_result(json, "delete_evpn", "", "EVPN Type 3 route deleted");
    Ok(())
}

/// List local EVPN instances (Phase 2 VTEP foundation).
///
/// Read-only. Surfaces the daemon's resolved `EvpnInstanceTable` —
/// the same data the operator put in `[[evpn_instances]]` blocks,
/// already normalized through RD/RT parsing and uniqueness checks.
pub async fn list_instances(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        EvpnServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_evpn_instances(ListEvpnInstancesRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<serde_json::Value> = resp
            .instances
            .iter()
            .map(|i| {
                serde_json::json!({
                    "vni": i.vni,
                    "rd": i.rd,
                    "route_targets": i.route_targets,
                    "local_vtep_ip": i.local_vtep_ip,
                    "bridge": i.bridge,
                    "advertise_svi_mac": i.advertise_svi_mac,
                    "originated_local_macs_count": i.originated_local_macs_count,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out)
                .expect("failed to serialize EVPN instance list as JSON")
        );
    } else if resp.instances.is_empty() {
        println!("No local EVPN instances configured");
    } else {
        for inst in &resp.instances {
            let mut detail = vec![
                format!("vni={}", inst.vni),
                format!("rd={}", inst.rd),
                format!("vtep={}", inst.local_vtep_ip),
                format!("rts=[{}]", inst.route_targets.join(",")),
            ];
            if !inst.bridge.is_empty() {
                detail.push(format!("bridge={}", inst.bridge));
            }
            if inst.advertise_svi_mac {
                detail.push("advertise-svi-mac".to_string());
            }
            detail.push(format!(
                "originated-local-macs={}",
                inst.originated_local_macs_count
            ));
            println!("{}", detail.join(" "));
        }
    }
    Ok(())
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
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize IP-VRF list as JSON")
        );
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
        println!(
            "{}",
            serde_json::to_string_pretty(&ip_vrf_to_json(&vrf))
                .expect("failed to serialize IP-VRF as JSON")
        );
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
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "instance_count": instances.len(),
                "originated_local_macs_count": originated_local_macs,
                "type2_route_count": type2_routes.len(),
                "type2_present": !type2_routes.is_empty(),
                "type3_route_count": type3_routes.len(),
                "type3_present": !type3_routes.is_empty(),
                "key_metrics": key_metrics,
            }))
            .expect("failed to serialize EVPN diagnose output as JSON")
        );
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
    //! and drives `rustbgpctl evpn instances` as a subprocess before
    //! kernel reconciliation grows the internals (see
    //! `docs/evpn-enablement.md` Gate 7b).
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::Request;
    use tonic::transport::Server;
    use tower::service_fn;

    use rustbgpd_api::EvpnService;
    use rustbgpd_api::proto::evpn_service_server::EvpnServiceServer;
    use rustbgpd_evpn::{EvpnInstance, EvpnInstanceId, EvpnInstanceTable, RouteTarget};
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
            .unwrap(),
        )
        .unwrap();
        t
    }

    fn unique_uds_path() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustbgpd-cli-evpn-it-{suffix}.sock"))
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
        let path = unique_uds_path();
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

        let row200 = &resp.instances[1];
        assert_eq!(row200.vni, 200);
        assert_eq!(row200.rd, "65000:200");
        assert_eq!(row200.bridge, "br200");
        assert!(row200.advertise_svi_mac);
        assert_eq!(row200.originated_local_macs_count, 0);
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
        let path = unique_uds_path();
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
        let path = unique_uds_path();
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
}
