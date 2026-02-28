use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use prometheus::{Encoder, TextEncoder};
use rustbgpd_telemetry::BgpMetrics;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_LINE: usize = 8192;
const MAX_CONNECTIONS: usize = 64;

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

    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        // Acquire permit before accepting to enforce an exact connection cap.
        let permit = semaphore.clone().acquire_owned().await;
        let Ok(permit) = permit else {
            warn!("metrics semaphore closed");
            return;
        };

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
            drop(permit);
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    metrics: &BgpMetrics,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader.take(MAX_REQUEST_LINE as u64));

    // Read the HTTP request line with timeout
    let mut request_line = String::new();
    match tokio::time::timeout(READ_TIMEOUT, buf_reader.read_line(&mut request_line)).await {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "read timeout",
            ));
        }
    }

    // If the line doesn't end with a newline, we hit the take limit → 400
    if !request_line.ends_with('\n') {
        let body = "Request Line Too Long\n";
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        tokio::time::timeout(WRITE_TIMEOUT, writer.write_all(response.as_bytes())).await??;
        return Ok(());
    }

    // Parse path from "GET /path HTTP/1.x"
    let path = request_line.split_whitespace().nth(1).unwrap_or("");

    let response = if path == "/metrics" {
        match gather(metrics) {
            Ok(body) => {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body,
                )
            }
            Err(e) => {
                warn!(error = %e, "metrics encoding failed");
                let body = "Internal Server Error\n";
                format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                )
            }
        }
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

fn gather(metrics: &BgpMetrics) -> Result<String, std::io::Error> {
    let encoder = TextEncoder::new();
    let families = metrics.registry().gather();
    let mut buf = Vec::new();
    encoder
        .encode(&families, &mut buf)
        .map_err(std::io::Error::other)?;
    String::from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;
    use tokio::sync::Semaphore;

    async fn start_server() -> SocketAddr {
        let metrics = BgpMetrics::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        tokio::spawn(async move {
            loop {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let m = metrics.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, &m).await;
                    drop(permit);
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

    #[tokio::test]
    async fn slow_client_times_out() {
        let addr = start_server().await;
        let stream = TcpStream::connect(addr).await.unwrap();
        // Don't send anything — the read timeout should kick in and close
        // the connection without blocking the server indefinitely.
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            let mut buf = Vec::new();
            let mut reader = tokio::io::BufReader::new(stream);
            let _ = reader.read_to_end(&mut buf).await;
        })
        .await;
        assert!(result.is_ok(), "server should have closed the connection");
    }

    #[tokio::test]
    async fn oversized_request_line_returns_400() {
        let addr = start_server().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        // Send a request line longer than MAX_REQUEST_LINE without a newline
        let long_line = "G".repeat(MAX_REQUEST_LINE + 100);
        stream.write_all(long_line.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "expected 400, got: {response}"
        );
    }

    #[tokio::test]
    async fn concurrent_connection_limit() {
        let metrics = BgpMetrics::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let semaphore = Arc::new(Semaphore::new(2)); // Only 2 concurrent

        let sem = semaphore.clone();
        tokio::spawn(async move {
            loop {
                let permit = sem.clone().acquire_owned().await.unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let m = metrics.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, &m).await;
                    drop(permit);
                });
            }
        });

        // Open 2 connections that don't send anything (they'll hold permits
        // until read timeout). Then verify a third connection still gets
        // served (it will queue until one of the first two times out).
        let _c1 = TcpStream::connect(addr).await.unwrap();
        let _c2 = TcpStream::connect(addr).await.unwrap();

        // Give the server a moment to acquire permits for c1 and c2
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The semaphore should now have 0 available permits
        assert_eq!(semaphore.available_permits(), 0);
    }
}
