//! Real transport regressions without a daemon or privileged networking.
use super::*;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tonic::Response;
use tonic::transport::{Server, ServerTlsConfig};

fn adapter(channel: Channel) -> RustbgpdMcp {
    let mut adapter = RustbgpdMcp::new(InterceptedService::new(
        channel,
        BearerInterceptor::new(None),
    ));
    adapter.read_timeout = Duration::from_secs(2);
    adapter
}

// Consume the entire request so a body-stall test cannot accidentally pass
// because connection readiness or request transmission used up the budget.
async fn stall_response(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    headers: bool,
    reached: tokio::sync::oneshot::Sender<()>,
) {
    stream
        .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let stream_id = loop {
        let mut frame = [0; 9];
        stream.read_exact(&mut frame).await.unwrap();
        let length = u32::from_be_bytes([0, frame[0], frame[1], frame[2]]) as usize;
        stream.read_exact(&mut vec![0; length]).await.unwrap();
        let stream_id = [frame[5], frame[6], frame[7], frame[8]];
        if stream_id != [0; 4] && matches!(frame[3], 0 | 1) && frame[4] & 1 != 0 {
            break stream_id;
        }
    };
    if headers {
        // HPACK :status=200, content-type=application/grpc; END_HEADERS only.
        let block = b"\x88\x5f\x10application/grpc";
        let mut frame = vec![0, 0, 19, 1, 4];
        frame.extend(stream_id);
        frame.extend(block);
        stream.write_all(&frame).await.unwrap();
    }
    reached.send(()).unwrap();
    // The client must terminate the RPC. Keep the socket alive meanwhile.
    std::future::pending::<()>().await;
}

#[tokio::test]
async fn tcp_complete_response_deadline_before_and_after_headers() {
    for headers in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            parse_daemon_endpoint(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stall_response(stream, headers, reached_tx).await;
        });
        let mcp = adapter(TlsOptions::default().channel(&endpoint).unwrap());
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            mcp.get_health(Parameters(NoParams {})),
        )
        .await
        .expect("the read deadline must finish before the test watchdog");
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        reached_rx
            .await
            .expect("the mock reached the requested response phase before the deadline");
        assert!(
            result
                .err()
                .expect("stalled RPC must fail")
                .message
                .contains("daemon read response timed out")
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn uds_complete_response_deadline_before_and_after_headers() {
    for headers in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("grpc.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stall_response(stream, headers, reached_tx).await;
        });
        let mcp = adapter(
            TlsOptions::default()
                .channel(&DaemonEndpoint::Uds(path))
                .unwrap(),
        );
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            mcp.get_health(Parameters(NoParams {})),
        )
        .await
        .expect("the read deadline must finish before the test watchdog");

        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        reached_rx
            .await
            .expect("the mock reached the requested response phase before the deadline");
        assert!(
            result
                .err()
                .expect("stalled RPC must fail")
                .message
                .contains("daemon read response timed out")
        );
    }
}

#[derive(Default)]
struct Health;

#[tonic::async_trait]
impl proto::control_service_server::ControlService for Health {
    async fn get_health(
        &self,
        request: Request<proto::HealthRequest>,
    ) -> Result<Response<proto::HealthResponse>, Status> {
        assert!(
            request.peer_certs().is_some_and(|certs| !certs.is_empty()),
            "mutual TLS must present a client certificate"
        );
        Ok(Response::new(proto::HealthResponse {
            healthy: true,
            ..Default::default()
        }))
    }
    async fn get_metrics(
        &self,
        _: Request<proto::MetricsRequest>,
    ) -> Result<Response<proto::MetricsResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn shutdown(
        &self,
        _: Request<proto::ShutdownRequest>,
    ) -> Result<Response<proto::ShutdownResponse>, Status> {
        panic!("read-only adapter must never invoke shutdown")
    }
    async fn trigger_mrt_dump(
        &self,
        _: Request<proto::TriggerMrtDumpRequest>,
    ) -> Result<Response<proto::TriggerMrtDumpResponse>, Status> {
        panic!("read-only adapter must never invoke a dump")
    }
}

fn authority() -> (rcgen::Certificate, Issuer<'static, KeyPair>) {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert, Issuer::new(params, key))
}

fn leaf(issuer: &Issuer<'static, KeyPair>, usage: ExtendedKeyUsagePurpose) -> (String, String) {
    let mut params = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    params.extended_key_usages.push(usage);
    let key = KeyPair::generate().unwrap();
    (
        params.signed_by(&key, issuer).unwrap().pem(),
        key.serialize_pem(),
    )
}

#[tokio::test]
async fn mtls_health_requires_trusted_server_and_client_identity() {
    let directory = tempfile::tempdir().unwrap();
    let (ca, issuer) = authority();
    let (server_cert, server_key) = leaf(&issuer, ExtendedKeyUsagePurpose::ServerAuth);
    let (client_cert, client_key) = leaf(&issuer, ExtendedKeyUsagePurpose::ClientAuth);
    let mut options = TlsOptions {
        ca_file: Some(directory.path().join("ca.pem")),
        cert_file: Some(directory.path().join("client.pem")),
        key_file: Some(directory.path().join("client.key")),
        server_name: Some("localhost".into()),
    };
    std::fs::write(options.ca_file.as_ref().unwrap(), ca.pem()).unwrap();
    std::fs::write(options.cert_file.as_ref().unwrap(), &client_cert).unwrap();
    std::fs::write(options.key_file.as_ref().unwrap(), &client_key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint =
        parse_daemon_endpoint(&format!("https://{}", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(
        Server::builder()
            .tls_config(
                ServerTlsConfig::new()
                    .identity(Identity::from_pem(server_cert, server_key))
                    .client_ca_root(Certificate::from_pem(ca.pem())),
            )
            .unwrap()
            .add_service(proto::control_service_server::ControlServiceServer::new(
                Health,
            ))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let result = adapter(options.channel(&endpoint).unwrap())
        .get_health(Parameters(NoParams {}))
        .await;
    assert!(result.unwrap().0.healthy);
    options.server_name = None;
    assert!(
        adapter(options.channel(&endpoint).unwrap())
            .get_health(Parameters(NoParams {}))
            .await
            .unwrap()
            .0
            .healthy
    );

    let (foreign_ca, foreign_issuer) = authority();
    std::fs::write(options.ca_file.as_ref().unwrap(), foreign_ca.pem()).unwrap();
    assert!(
        adapter(options.channel(&endpoint).unwrap())
            .get_health(Parameters(NoParams {}))
            .await
            .is_err()
    );
    std::fs::write(options.ca_file.as_ref().unwrap(), ca.pem()).unwrap();
    let (foreign_cert, foreign_key) = leaf(&foreign_issuer, ExtendedKeyUsagePurpose::ClientAuth);
    std::fs::write(options.cert_file.as_ref().unwrap(), foreign_cert).unwrap();
    std::fs::write(options.key_file.as_ref().unwrap(), foreign_key).unwrap();
    assert!(
        adapter(options.channel(&endpoint).unwrap())
            .get_health(Parameters(NoParams {}))
            .await
            .is_err()
    );
    std::fs::write(options.cert_file.as_ref().unwrap(), client_cert).unwrap();
    std::fs::write(options.key_file.as_ref().unwrap(), client_key).unwrap();
    let wrong_name = TlsOptions {
        server_name: Some("wrong.invalid".into()),
        ..options
    };
    assert!(
        adapter(wrong_name.channel(&endpoint).unwrap())
            .get_health(Parameters(NoParams {}))
            .await
            .is_err()
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[test]
fn tls_options_require_https_and_complete_credentials() {
    let https = parse_daemon_endpoint("https://localhost:50051").unwrap();
    for mask in 0..8 {
        let options = TlsOptions {
            ca_file: (mask & 1 != 0).then(|| "ca.pem".into()),
            cert_file: (mask & 2 != 0).then(|| "client.pem".into()),
            key_file: (mask & 4 != 0).then(|| "client.key".into()),
            server_name: None,
        };
        assert_eq!(options.validate(&https).is_ok(), mask == 7);
        for endpoint in [
            DaemonEndpoint::Tcp("http://localhost:50051".into()),
            DaemonEndpoint::Uds("/tmp/grpc.sock".into()),
        ] {
            assert_eq!(options.validate(&endpoint).is_ok(), mask == 0);
        }
    }
    let options = TlsOptions {
        server_name: Some("localhost".into()),
        ..Default::default()
    };
    assert!(
        options
            .validate(&DaemonEndpoint::Tcp("http://localhost:50051".into()))
            .is_err()
    );
    assert!(options.validate(&https).is_err());
}

#[test]
fn printed_mtls_config_preserves_options_without_credential_paths() {
    let mut options = TlsOptions {
        ca_file: Some("private-ca.pem".into()),
        cert_file: Some("private-client.pem".into()),
        key_file: Some("private-client.key".into()),
        server_name: Some("daemon.example".into()),
    };
    let printed = print_config("rustbgpd-mcp", "https://127.0.0.1:50051", false, &options);
    assert!(!printed.contains("private-"));
    let config: serde_json::Value = serde_json::from_str(&printed).unwrap();
    assert_eq!(
        config["mcpServers"]["rustbgpd"]["args"],
        serde_json::json!([
            "--grpc-addr",
            "https://127.0.0.1:50051",
            "--grpc-tls-ca-file",
            "/path/to/ca.pem",
            "--grpc-tls-cert-file",
            "/path/to/client.crt",
            "--grpc-tls-key-file",
            "/path/to/client.key",
            "--grpc-tls-server-name",
            "daemon.example"
        ])
    );
    options.server_name = Some(" ".into());
    assert!(
        options
            .validate(&DaemonEndpoint::Tcp("https://localhost:50051".into()))
            .is_err()
    );
}
