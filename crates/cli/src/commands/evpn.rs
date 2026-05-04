use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::evpn_service_client::EvpnServiceClient;
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    AddEvpnRouteRequest, DeleteEvpnRouteRequest, ListEvpnInstancesRequest, ListEvpnRequest,
};

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
            println!("{}", detail.join(" "));
        }
    }
    Ok(())
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

        let row200 = &resp.instances[1];
        assert_eq!(row200.vni, 200);
        assert_eq!(row200.rd, "65000:200");
        assert_eq!(row200.bridge, "br200");
        assert!(row200.advertise_svi_mac);
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
}
