use std::net::SocketAddr;

use prometheus::{Encoder, TextEncoder};
use rustbgpd_telemetry::BgpMetrics;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{error, info};

pub async fn serve_metrics(addr: SocketAddr, metrics: BgpMetrics) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            info!(%addr, "metrics server listening");
            l
        }
        Err(e) => {
            error!(%addr, error = %e, "failed to bind metrics server");
            return;
        }
    };

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "metrics server accept error");
                continue;
            }
        };

        let body = gather(&metrics);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );

        if let Err(e) = stream.write_all(response.as_bytes()).await {
            error!(%peer, error = %e, "metrics server write error");
        }
    }
}

fn gather(metrics: &BgpMetrics) -> String {
    let encoder = TextEncoder::new();
    let families = metrics.registry().gather();
    let mut buf = Vec::new();
    encoder.encode(&families, &mut buf).expect("encode metrics");
    String::from_utf8(buf).expect("prometheus text is UTF-8")
}
