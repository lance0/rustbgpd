use std::net::SocketAddr;
use std::time::Duration;

use prometheus::{Encoder, TextEncoder};
use rustbgpd_telemetry::BgpMetrics;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{debug, error, info};

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

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
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "metrics server accept error");
                continue;
            }
        };

        let metrics = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &metrics).await {
                debug!(%peer, error = %e, "metrics connection error");
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    metrics: &BgpMetrics,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Read the HTTP request line
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    // Parse path from "GET /path HTTP/1.x"
    let path = request_line.split_whitespace().nth(1).unwrap_or("");

    let response = if path == "/metrics" {
        let body = gather(metrics);
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        )
    } else {
        let body = "Not Found\n";
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        )
    };

    // Write with timeout to prevent slow-client stalls
    tokio::time::timeout(WRITE_TIMEOUT, writer.write_all(response.as_bytes())).await??;

    Ok(())
}

fn gather(metrics: &BgpMetrics) -> String {
    let encoder = TextEncoder::new();
    let families = metrics.registry().gather();
    let mut buf = Vec::new();
    encoder.encode(&families, &mut buf).expect("encode metrics");
    String::from_utf8(buf).expect("prometheus text is UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    async fn start_server() -> SocketAddr {
        let metrics = BgpMetrics::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let m = metrics.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, &m).await;
                });
            }
        });

        addr
    }

    #[tokio::test]
    async fn get_metrics_returns_200() {
        let addr = start_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn get_other_path_returns_404() {
        let addr = start_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    }
}
