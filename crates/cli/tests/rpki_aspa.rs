//! Real CLI request, output, and pre-connect argument contracts for ASPA reads.
use rustbgpd_api::proto::{
    self,
    rpki_service_server::{RpkiService, RpkiServiceServer},
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

#[derive(Clone)]
struct Backend;

#[tonic::async_trait]
impl RpkiService for Backend {
    async fn list_caches(
        &self,
        _: Request<proto::ListRpkiCachesRequest>,
    ) -> Result<Response<proto::ListRpkiCachesResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn validate_route_origin(
        &self,
        _: Request<proto::ValidateRouteOriginRequest>,
    ) -> Result<Response<proto::ValidateRouteOriginResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn lookup_aspa(
        &self,
        request: Request<proto::LookupAspaRequest>,
    ) -> Result<Response<proto::LookupAspaResponse>, Status> {
        let customer_asn = request.into_inner().customer_asn;
        if customer_asn == 2 {
            return Err(Status::permission_denied("observer required"));
        }
        if customer_asn == 3 {
            return Err(Status::failed_precondition(
                "no authoritative ASPA snapshot",
            ));
        }
        assert_eq!(customer_asn, 65_002);
        Ok(Response::new(proto::LookupAspaResponse {
            customer_asn,
            found: true,
            provider_asns: vec![0, 65_001],
            complete: false,
            omitted: 1,
        }))
    }
    async fn verify_as_path(
        &self,
        request: Request<proto::VerifyAsPathRequest>,
    ) -> Result<Response<proto::VerifyAsPathResponse>, Status> {
        let request = request.into_inner();
        assert_eq!(request.neighbor_asn, 65_001);
        assert_eq!(request.local_role, proto::AspaLocalRole::RsClient as i32);
        if request.segments.is_empty() {
            return Ok(Response::new(proto::VerifyAsPathResponse {
                validation: proto::RouteAspaValidation::Invalid as i32,
                invalid_hop: None,
            }));
        }
        assert_eq!(
            request.segments,
            vec![
                proto::AspaPathSegment {
                    kind: proto::AspaSegmentKind::Sequence as i32,
                    asns: vec![65_002, 65_002]
                },
                proto::AspaPathSegment {
                    kind: proto::AspaSegmentKind::Set as i32,
                    asns: vec![65_003, 65_004]
                },
            ]
        );
        Ok(Response::new(proto::VerifyAsPathResponse {
            validation: proto::RouteAspaValidation::Invalid as i32,
            invalid_hop: None,
        }))
    }
}

async fn run(address: &str, args: &[&str]) -> std::process::Output {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_rbgp"))
            .args(["--addr", address])
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("CLI response deadline")
    .expect("launch rbgp")
}

#[tokio::test]
async fn aspa_real_cli_preserves_requests_json_and_operational_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(RpkiServiceServer::new(Backend))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let lookup = run(&address, &["--json", "rpki", "aspa", "65002"]).await;
    assert!(
        lookup.status.success(),
        "{}",
        String::from_utf8_lossy(&lookup.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&lookup.stdout).unwrap(),
        serde_json::json!({"customer_asn":65002,"found":true,"provider_asns":[0,65001],"complete":false,"omitted":1})
    );
    let lookup = run(&address, &["rpki", "aspa", "65002"]).await;
    assert!(lookup.status.success());
    assert_eq!(
        String::from_utf8(lookup.stdout).unwrap(),
        "Customer ASN: 65002\nProviders: 0 65001\nListing: incomplete (1 omitted)\n"
    );
    let verdict = run(
        &address,
        &[
            "--json",
            "rpki",
            "verify-path",
            "--neighbor-asn",
            "65001",
            "--role",
            "rs-client",
            "65002 65002 {65003 65004}",
        ],
    )
    .await;
    assert!(
        verdict.status.success(),
        "{}",
        String::from_utf8_lossy(&verdict.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verdict.stdout).unwrap(),
        serde_json::json!({"validation":"invalid","invalid_hop":null})
    );
    let empty = run(
        &address,
        &[
            "--json",
            "rpki",
            "verify-path",
            "--neighbor-asn",
            "65001",
            "--role",
            "rs-client",
            "",
        ],
    )
    .await;
    assert!(
        empty.status.success(),
        "{}",
        String::from_utf8_lossy(&empty.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&empty.stdout).unwrap(),
        serde_json::json!({"validation":"invalid","invalid_hop":null})
    );
    for command in [
        vec!["rpki", "aspa", "65002"],
        vec![
            "rpki",
            "verify-path",
            "--neighbor-asn",
            "65001",
            "--role",
            "rs-client",
            "65002 65002 {65003 65004}",
        ],
    ] {
        let mut args = vec!["--json"];
        args.extend_from_slice(&command);
        let plain = run(&address, &args).await;
        assert!(plain.status.success());
        let payload: serde_json::Value = serde_json::from_slice(&plain.stdout).unwrap();
        args.extend(["--json-version", "1"]);
        let versioned = run(&address, &args).await;
        assert!(
            versioned.status.success(),
            "{}",
            String::from_utf8_lossy(&versioned.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&versioned.stdout).unwrap(),
            serde_json::json!({"format":"rbgp-json","format_version":"1.1","data":payload})
        );
    }
    for (customer, message) in [
        ("2", "observer required"),
        ("3", "no authoritative ASPA snapshot"),
    ] {
        let output = run(&address, &["rpki", "aspa", customer]).await;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(message));
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn aspa_bad_arguments_fail_before_connecting() {
    // This endpoint cannot connect; argument errors must retain usage exit 2.
    for args in [
        vec!["rpki", "aspa", "0"],
        vec![
            "rpki",
            "verify-path",
            "--neighbor-asn",
            "0",
            "--role",
            "peer",
            "1",
        ],
        vec![
            "rpki",
            "verify-path",
            "--neighbor-asn",
            "1",
            "--role",
            "peer",
            "{1",
        ],
        vec![
            "rpki",
            "verify-path",
            "--neighbor-asn",
            "1",
            "--role",
            "peer",
            "0",
        ],
        vec!["rpki", "verify-path", "--neighbor-asn", "1", "1"],
        vec!["rpki", "verify-path", "--role", "peer", "1"],
        vec![
            "rpki",
            "verify-path",
            "--neighbor-asn",
            "1",
            "--role",
            "bogus",
            "1",
        ],
    ] {
        let output = run("http://127.0.0.1:0", &args).await;
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
    }
}
