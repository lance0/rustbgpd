use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_api::accept_backoff::AcceptBackoff;
use rustbgpd_api::health_probe::{CORE_READINESS_DEADLINE, CoreReadinessProbe};
use rustbgpd_api::metrics_render::render_text;
use rustbgpd_evpn_linux::worker_progress::WorkerProgressState;
use rustbgpd_telemetry::BgpMetrics;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot, watch};
use tokio::time::Instant;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::{Stream, StreamExt};
use tracing::{debug, info, warn};

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_LINE: usize = 8192;
const MAX_CONNECTIONS: usize = 64;
/// Scrapes in flight at once: waiting, rendering or writing their response.
/// Scrapes queue behind one render, so without this cap they could hold every
/// connection permit and keep `/livez` and `/readyz` from being accepted. A
/// scrape over the cap is rejected with 503 at once, holding its permit only
/// to write that reply.
const MAX_SCRAPES: usize = MAX_CONNECTIONS - 8;
/// How long a connection may wait to send its request line before a full
/// connection budget evicts it. Clients send the request line with the
/// connection, so this only closes idle or slow-sending clients.
const IDLE_EVICTION_GRACE: Duration = Duration::from_millis(250);

/// Fixed startup worker inventory: at most FIB, EVPN intent and EVPN kernel.
/// A missing receiver means a configured worker could not be constructed.
#[derive(Clone)]
pub(crate) struct DataplaneWorkerProbe {
    pub name: &'static str,
    pub progress: Option<watch::Receiver<WorkerProgressState>>,
    pub freshness: Duration,
}

impl DataplaneWorkerProbe {
    pub(crate) fn failure(&self) -> Option<&'static str> {
        let Some(progress) = &self.progress else {
            return Some("unavailable");
        };
        if progress.has_changed().is_err() {
            return Some("closed");
        }
        let state = *progress.borrow();
        if !state.initialized {
            return Some("starting");
        }
        if state.observed_at.elapsed() > self.freshness {
            return Some("stale progress");
        }
        None
    }
}

fn dataplane_response(workers: &[DataplaneWorkerProbe]) -> String {
    if workers.is_empty() {
        return text_response("503 Service Unavailable", "dataplane not configured\n");
    }
    for worker in workers {
        if let Some(reason) = worker.failure() {
            return text_response(
                "503 Service Unavailable",
                &format!("dataplane not ready: {} {reason}\n", worker.name),
            );
        }
    }
    text_response("200 OK", "dataplane workers ready\n")
}

pub struct MetricsListener {
    addr: SocketAddr,
    listener: TcpListener,
}

#[derive(Debug, thiserror::Error)]
#[error("address {addr}: {source}")]
pub struct MetricsListenerBindError {
    addr: SocketAddr,
    #[source]
    source: std::io::Error,
}

impl MetricsListener {
    pub async fn bind(addr: SocketAddr) -> Result<Self, MetricsListenerBindError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| MetricsListenerBindError { addr, source })?;
        let addr = listener.local_addr().unwrap_or(addr);
        Ok(Self { addr, listener })
    }

    /// Fault injection for the daemon supervision test: shutting down a
    /// listening socket makes the next accept fail with EINVAL, the
    /// unusable-socket path that ends the accept loop.
    pub fn shut_down_for_test(&self) {
        if let Err(error) =
            socket2::SockRef::from(&self.listener).shutdown(std::net::Shutdown::Read)
        {
            warn!(error = %error, "injected metrics listener shutdown failed");
        }
    }
}

pub async fn serve_metrics(
    server: MetricsListener,
    metrics: BgpMetrics,
    readiness_probe: CoreReadinessProbe,
    dataplane_probe: Option<Vec<DataplaneWorkerProbe>>,
) {
    let MetricsListener { addr, listener } = server;
    info!(%addr, "metrics server listening");
    serve_incoming(
        TcpListenerStream::new(listener),
        format!("metrics {addr}"),
        metrics,
        readiness_probe,
        dataplane_probe,
    )
    .await;
}

async fn serve_incoming<S>(
    incoming: S,
    name: String,
    metrics: BgpMetrics,
    readiness_probe: CoreReadinessProbe,
    dataplane_probe: Option<Vec<DataplaneWorkerProbe>>,
) where
    S: Stream<Item = std::io::Result<TcpStream>> + Unpin,
{
    // Delays the next accept after EMFILE-class errors and logs them
    // rate-limited; a bare retry would spin on a still-readable listener.
    let mut incoming = AcceptBackoff::new(incoming, name);
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let scrape_slots = Arc::new(Semaphore::new(MAX_SCRAPES));
    // Connections still waiting for their request line, oldest first, with
    // their accept time. A connection drops its receiver once the line is
    // read, closing the sender; dropping a live sender evicts it.
    let mut unclassified: VecDeque<(Instant, oneshot::Sender<()>)> = VecDeque::new();

    loop {
        // Acquire permit before accepting to enforce an exact connection cap.
        // While the budget is full, a connection that has not sent its request
        // line within IDLE_EVICTION_GRACE of being accepted is closed, so idle
        // or slow-sending clients cannot keep `/livez` and `/readyz` out.
        // Every other permit holder is classified: scrapes are capped below
        // the budget, and every other response fits in the socket send buffer.
        let permit = loop {
            unclassified.retain(|(_, evict)| !evict.is_closed());
            let evict_at = unclassified
                .front()
                .map(|(accepted, _)| *accepted + IDLE_EVICTION_GRACE);
            tokio::select! {
                biased;
                permit = semaphore.clone().acquire_owned() => break permit,
                () = tokio::time::sleep_until(evict_at.unwrap_or_else(Instant::now)),
                    if evict_at.is_some() =>
                {
                    unclassified.pop_front();
                    debug!("metrics connection budget full; closed oldest idle connection");
                }
            }
        };
        let Ok(permit) = permit else {
            warn!("metrics semaphore closed");
            return;
        };

        let stream = match incoming.next().await {
            Some(Ok(stream)) => stream,
            Some(Err(_)) => continue,
            None => return,
        };
        let (evict, evicted) = oneshot::channel();
        unclassified.push_back((Instant::now(), evict));

        let peer = stream.peer_addr().ok();
        let metrics = metrics.clone();
        let readiness_probe = readiness_probe.clone();
        let dataplane_probe = dataplane_probe.clone();
        let scrape_slots = scrape_slots.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                evicted,
                &metrics,
                &readiness_probe,
                dataplane_probe.as_deref(),
                &scrape_slots,
            )
            .await
            {
                debug!(client = ?peer, error = %e, "metrics connection error");
            }
            drop(permit);
        });
    }
}

/// `evicted` resolves when the accept loop needs this connection's permit;
/// it is honoured only until the request line has been read.
async fn handle_connection(
    stream: TcpStream,
    evicted: impl std::future::Future,
    metrics: &BgpMetrics,
    readiness_probe: &CoreReadinessProbe,
    dataplane_probe: Option<&[DataplaneWorkerProbe]>,
    scrape_slots: &Semaphore,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader.take(MAX_REQUEST_LINE as u64));

    // Read the HTTP request line with timeout
    let mut request_line = String::new();
    let read = tokio::time::timeout(READ_TIMEOUT, buf_reader.read_line(&mut request_line));
    let read = tokio::select! {
        biased;
        read = read => read,
        _ = evicted => return Ok(()),
    };
    match read {
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

    // Held until the response is written, so a slow scrape reader also
    // counts against the scrape cap.
    let mut scrape_slot = None;
    let response = match path {
        "/metrics" => match scrape_slots.try_acquire() {
            Ok(slot) => {
                scrape_slot = Some(slot);
                metrics_response(render_text(metrics).await)
            }
            Err(_) => text_response("503 Service Unavailable", "too many concurrent scrapes\n"),
        },
        "/livez" => text_response("200 OK", "ok\n"),
        "/dp-readyz" if dataplane_probe.is_some() => {
            dataplane_response(dataplane_probe.unwrap_or_default())
        }
        "/readyz" => {
            // Reject a successful probe observed after the shared deadline.
            // After a runtime stall, a queued reply can be polled before the
            // expired timer; the elapsed guard prevents certifying that late
            // success. Scheduling and response delivery can still delay the
            // HTTP response beyond the deadline.
            let started = std::time::Instant::now();
            match tokio::time::timeout(CORE_READINESS_DEADLINE, readiness_probe.check()).await {
                Ok(Ok(())) if started.elapsed() <= CORE_READINESS_DEADLINE => {
                    text_response("200 OK", "ready\n")
                }
                Ok(Err(error)) => {
                    warn!(%error, "readiness probe failed");
                    text_response("503 Service Unavailable", &format!("not ready: {error}\n"))
                }
                Ok(Ok(())) | Err(_) => {
                    warn!("readiness probe deadline exceeded");
                    text_response(
                        "503 Service Unavailable",
                        "not ready: readiness probe deadline exceeded\n",
                    )
                }
            }
        }
        _ => text_response("404 Not Found", "Not Found\n"),
    };

    // Write with timeout to prevent slow-client stalls
    tokio::time::timeout(WRITE_TIMEOUT, writer.write_all(response.as_bytes())).await??;
    drop(scrape_slot);

    Ok(())
}

fn metrics_response(rendered: std::io::Result<String>) -> String {
    match rendered {
        Ok(body) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            warn!(error = %e, "metrics render deadline exceeded");
            text_response(
                "503 Service Unavailable",
                "metrics render deadline exceeded\n",
            )
        }
        Err(e) => {
            warn!(error = %e, "metrics encoding failed");
            text_response("500 Internal Server Error", "Internal Server Error\n")
        }
    }
}

fn text_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rustbgpd_api::peer_types::PeerManagerCommand;
    use rustbgpd_rib::RibUpdate;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;
    use tokio::sync::{Semaphore, mpsc};

    fn unused_probe() -> CoreReadinessProbe {
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        CoreReadinessProbe::new(peer_tx, rib_tx)
    }

    async fn start_server(readiness_probe: CoreReadinessProbe) -> SocketAddr {
        start_server_with_dataplane(readiness_probe, None).await
    }

    pub(crate) async fn start_server_with_dataplane(
        readiness_probe: CoreReadinessProbe,
        dataplane_probe: Option<Vec<DataplaneWorkerProbe>>,
    ) -> SocketAddr {
        let metrics = BgpMetrics::new();
        let server = MetricsListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = server.listener.local_addr().unwrap();
        assert_eq!(server.addr, addr);
        tokio::spawn(async move {
            serve_metrics(server, metrics, readiness_probe, dataplane_probe).await;
        });

        addr
    }

    pub(crate) async fn request(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn get_metrics_returns_200() {
        let addr = start_server(unused_probe()).await;

        let response = request(addr, "/metrics").await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
    }

    /// Stands in for a slow whole-registry render: `collect()` reports entry,
    /// then blocks until the test releases it.
    struct GatedCollector {
        gauge: prometheus::IntGauge,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl prometheus::core::Collector for GatedCollector {
        fn desc(&self) -> Vec<&prometheus::core::Desc> {
            prometheus::core::Collector::desc(&self.gauge)
        }

        fn collect(&self) -> Vec<prometheus::proto::MetricFamily> {
            let _ = self.entered.send(());
            // Bounded so a failing test cannot wedge the process.
            let _ = self
                .release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30));
            prometheus::core::Collector::collect(&self.gauge)
        }
    }

    /// Serves `/metrics` on a dedicated current-thread runtime whose registry
    /// holds a [`GatedCollector`]. A render on that runtime's only worker
    /// stalls every other request on the server.
    fn start_gated_server() -> (
        SocketAddr,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let metrics = BgpMetrics::new();
                let gauge = prometheus::IntGauge::new("test_gated_render", "test").unwrap();
                metrics
                    .registry()
                    .register(Box::new(GatedCollector {
                        gauge,
                        entered: entered_tx,
                        release: std::sync::Mutex::new(release_rx),
                    }))
                    .unwrap();
                let server = MetricsListener::bind("127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
                addr_tx.send(server.addr).unwrap();
                serve_metrics(server, metrics, unused_probe(), None).await;
            });
        });
        (addr_rx.recv().unwrap(), entered_rx, release_tx)
    }

    /// Blocking client with a read timeout, so a stalled server fails the
    /// request instead of hanging the test.
    fn blocking_request(addr: SocketAddr, path: &str) -> std::io::Result<String> {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    #[test]
    fn livez_answers_while_metrics_render_is_blocked() {
        let (addr, entered, release) = start_gated_server();
        let scrape = std::thread::spawn(move || blocking_request(addr, "/metrics"));
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("metrics render must start");

        let livez = blocking_request(addr, "/livez");
        release.send(()).unwrap();
        let livez = livez.expect("/livez must answer while a /metrics render is in flight");
        assert!(livez.starts_with("HTTP/1.1 200 OK"), "{livez}");

        let scrape = scrape.join().unwrap().unwrap();
        assert!(scrape.starts_with("HTTP/1.1 200 OK"), "{scrape}");
        assert!(scrape.contains("test_gated_render 0\n"), "{scrape}");
    }

    #[test]
    fn livez_answers_while_scrapes_fill_the_connection_budget() {
        use rustbgpd_api::metrics_render::RENDER_DEADLINE;
        use std::io::{Read, Write};

        let (addr, entered, release) = start_gated_server();
        let send_scrape = || {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            stream
        };
        let mut scrapes = vec![send_scrape()];
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("first render must start");
        // One scrape per connection permit, all behind the held render. The
        // accept queue is FIFO, so the server takes every scrape before it
        // can take the probe connected after them.
        scrapes.extend((1..MAX_CONNECTIONS).map(|_| send_scrape()));

        let livez = (|| {
            let mut stream = std::net::TcpStream::connect(addr)?;
            // Below the render deadline: the probe must not depend on queued
            // scrapes timing out to get a connection permit.
            stream.set_read_timeout(Some(RENDER_DEADLINE / 2))?;
            stream.write_all(b"GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            std::io::Result::Ok(response)
        })();
        for _ in 0..MAX_SCRAPES {
            release.send(()).unwrap();
        }
        let livez = livez.expect("/livez must answer while scrapes fill the connection budget");
        assert!(livez.starts_with("HTTP/1.1 200 OK"), "{livez}");

        let (mut served, mut rejected) = (0, 0);
        for mut stream in scrapes {
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            if response.starts_with("HTTP/1.1 200 OK") {
                served += 1;
            } else {
                assert!(
                    response.starts_with("HTTP/1.1 503 Service Unavailable")
                        && response.ends_with("too many concurrent scrapes\n"),
                    "{response}"
                );
                rejected += 1;
            }
        }
        assert_eq!(
            (served, rejected),
            (MAX_SCRAPES, MAX_CONNECTIONS - MAX_SCRAPES)
        );
    }

    #[test]
    fn livez_answers_while_idle_clients_fill_the_connection_budget() {
        use std::io::{Read, Write};

        let (addr, _entered, _release) = start_gated_server();
        // Connections that never send a request line, one per permit. The
        // accept queue is FIFO, so the server takes every idle connection
        // before it can take the probe connected after them.
        let mut idle: Vec<_> = (0..MAX_CONNECTIONS)
            .map(|_| std::net::TcpStream::connect(addr).unwrap())
            .collect();

        let livez = (|| {
            let mut stream = std::net::TcpStream::connect(addr)?;
            // Below the request-line timeout: the probe must not depend on
            // idle clients timing out to get a connection permit.
            stream.set_read_timeout(Some(READ_TIMEOUT / 2))?;
            stream.write_all(b"GET /livez HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            std::io::Result::Ok(response)
        })();
        let livez = livez.expect("/livez must answer while idle clients fill the budget");
        assert!(livez.starts_with("HTTP/1.1 200 OK"), "{livez}");

        // The probe displaced the oldest idle connection, closed without a reply.
        let oldest = &mut idle[0];
        oldest.set_read_timeout(Some(READ_TIMEOUT / 2)).unwrap();
        let mut buf = Vec::new();
        oldest
            .read_to_end(&mut buf)
            .expect("oldest idle connection must be closed");
        assert!(buf.is_empty(), "{buf:?}");
    }

    #[test]
    fn metrics_render_deadline_maps_to_503() {
        let response = metrics_response(Err(std::io::ErrorKind::TimedOut.into()));
        assert!(
            response.starts_with("HTTP/1.1 503 Service Unavailable"),
            "{response}"
        );
        let response = metrics_response(Err(std::io::Error::other("encode")));
        assert!(
            response.starts_with("HTTP/1.1 500 Internal Server Error"),
            "{response}"
        );
    }

    #[test]
    fn concurrent_metrics_scrapes_render_one_at_a_time_and_both_succeed() {
        let (addr, entered, release) = start_gated_server();
        let first = std::thread::spawn(move || blocking_request(addr, "/metrics"));
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("first render must start");
        let second = std::thread::spawn(move || blocking_request(addr, "/metrics"));

        // The second scrape waits for the render slot instead of starting a
        // second render beside the blocked one.
        assert!(
            entered.recv_timeout(Duration::from_millis(300)).is_err(),
            "a second render started while the first was in flight"
        );
        release.send(()).unwrap();
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("second render must start after the first finishes");
        release.send(()).unwrap();

        for scrape in [first, second] {
            let response = scrape.join().unwrap().unwrap();
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        }
    }

    #[tokio::test]
    async fn dataplane_probe_distinguishes_disabled_unconfigured_and_unavailable() {
        let disabled = start_server(unused_probe()).await;
        assert!(
            request(disabled, "/dp-readyz")
                .await
                .starts_with("HTTP/1.1 404")
        );
        let unconfigured = start_server_with_dataplane(unused_probe(), Some(Vec::new())).await;
        let response = request(unconfigured, "/dp-readyz").await;
        assert!(response.starts_with("HTTP/1.1 503"));
        assert!(response.ends_with("dataplane not configured\n"));
        // A configured worker with no handle includes failed netlink setup;
        // it must not disappear from the startup worker inventory.
        let unavailable = start_server_with_dataplane(
            unused_probe(),
            Some(vec![DataplaneWorkerProbe {
                name: "fib",
                progress: None,
                freshness: crate::fib_runtime::READINESS_FRESHNESS,
            }]),
        )
        .await;
        let response = request(unavailable, "/dp-readyz").await;
        assert!(response.starts_with("HTTP/1.1 503"));
        assert!(response.ends_with("fib unavailable\n"));
    }

    #[tokio::test(start_paused = true)]
    async fn dataplane_progress_uses_worker_cadence_and_original_observation() {
        use rustbgpd_evpn_linux::worker_progress::WorkerProgress;
        for (name, cadence, freshness) in [
            (
                "fib",
                Duration::from_secs(30),
                crate::fib_runtime::READINESS_FRESHNESS,
            ),
            (
                "evpn intent",
                Duration::from_secs(5),
                Duration::from_secs(10),
            ),
            (
                "evpn kernel",
                Duration::from_secs(60),
                Duration::from_secs(120),
            ),
        ] {
            let worker = WorkerProgress::default();
            let probe = DataplaneWorkerProbe {
                name,
                progress: Some(worker.subscribe()),
                freshness,
            };
            assert_eq!(probe.failure(), Some("starting"));
            worker.checkpoint();
            assert_eq!(probe.failure(), Some("starting"));
            worker.complete_pass();
            for _ in 0..3 {
                tokio::time::advance(cadence).await;
                assert_eq!(probe.failure(), None, "healthy idle {name}");
                worker.complete_pass();
            }
            // Copying an old observation is not new worker progress.
            let cached = *probe.progress.as_ref().unwrap().borrow();
            let (forward_tx, forward_rx) = watch::channel(cached);
            let forwarded = DataplaneWorkerProbe {
                progress: Some(forward_rx),
                ..probe.clone()
            };
            tokio::time::advance(freshness + Duration::from_millis(1)).await;
            forward_tx.send_replace(cached);
            assert_eq!(forwarded.failure(), Some("stale progress"));
            assert_eq!(probe.failure(), Some("stale progress"));
            worker.checkpoint();
            assert_eq!(probe.failure(), None);
            drop(worker);
            assert_eq!(probe.failure(), Some("closed"));
        }
    }

    #[tokio::test]
    async fn get_other_path_returns_404() {
        let addr = start_server(unused_probe()).await;

        let response = request(addr, "/other").await;
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn get_livez_returns_200() {
        let addr = start_server(unused_probe()).await;

        let response = request(addr, "/livez").await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("ok\n"));
    }

    #[tokio::test]
    async fn get_readyz_returns_200_when_core_actors_respond() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let addr = start_server(CoreReadinessProbe::new(peer_tx, rib_tx)).await;

        tokio::spawn(async move {
            if let Some(PeerManagerCommand::Ping { reply }) = peer_rx.recv().await {
                let _ = reply.send(());
            }
        });
        tokio::spawn(async move {
            if let Some(RibUpdate::QueryLocRibCount { reply }) = rib_rx.recv().await {
                let _ = reply.send(0);
            }
        });

        let response = request(addr, "/readyz").await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("ready\n"));
    }

    #[tokio::test]
    async fn get_readyz_returns_503_when_peer_manager_drops_reply() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let addr = start_server(CoreReadinessProbe::new(peer_tx, rib_tx)).await;

        tokio::spawn(async move {
            if let Some(PeerManagerCommand::Ping { reply }) = peer_rx.recv().await {
                drop(reply);
            }
        });

        let response = request(addr, "/readyz").await;
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.ends_with("not ready: peer manager dropped reply\n"));
    }

    #[tokio::test]
    async fn get_readyz_fails_closed_when_rib_probe_reaches_deadline() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let addr = start_server(CoreReadinessProbe::new(peer_tx, rib_tx)).await;

        tokio::spawn(async move {
            if let Some(PeerManagerCommand::Ping { reply }) = peer_rx.recv().await {
                let _ = reply.send(());
            }
        });
        tokio::spawn(async move {
            if let Some(RibUpdate::QueryLocRibCount { reply }) = rib_rx.recv().await {
                tokio::time::sleep(Duration::from_secs(1)).await;
                drop(reply);
            }
        });

        let response = request(addr, "/readyz").await;
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        let body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("HTTP response must contain a header/body boundary");
        // The HTTP guard and the actor probe intentionally share the same
        // 200 ms deadline. Either timer may win under scheduler load; both
        // exact bodies are fail-closed, while the status above must stay 503.
        assert!(
            matches!(
                body,
                "not ready: RIB manager probe timed out (200ms deadline)\n"
                    | "not ready: readiness probe deadline exceeded\n"
            ),
            "unexpected readiness deadline response: {body:?}"
        );
    }

    #[tokio::test]
    async fn get_readyz_returns_503_within_deadline_when_rib_reply_stalls() {
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let addr = start_server(CoreReadinessProbe::new(peer_tx, rib_tx)).await;

        tokio::spawn(async move {
            if let Some(PeerManagerCommand::Ping { reply }) = peer_rx.recv().await {
                let _ = reply.send(());
            }
        });
        tokio::spawn(async move {
            if let Some(RibUpdate::QueryLocRibCount { reply }) = rib_rx.recv().await {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let _ = reply.send(0);
            }
        });

        let started = std::time::Instant::now();
        let response = request(addr, "/readyz").await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a stalled RIB actor must not delay the /readyz response past the deadline"
        );
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
    }

    #[tokio::test]
    async fn get_readyz_rejects_late_success_when_runtime_stall_outlives_deadline() {
        // R1 from docs/perf/actor-ceiling-1m-2026-07.md: a wedged runtime
        // holds the probe past the deadline, and on unpark the queued
        // actor reply is polled before the expired probe timer, so the
        // probe completes successfully. Without the response-side elapsed
        // guard this is certified as a late 200.
        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let (wedge_tx, mut wedge_rx) = mpsc::channel::<Duration>(1);
        let (engaged_tx, engaged_rx) = tokio::sync::oneshot::channel();
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();

        // The server runs on its own single-threaded runtime so the test
        // can wedge exactly the worker that owns the probe timers.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let metrics = BgpMetrics::new();
                let probe = CoreReadinessProbe::new(peer_tx, rib_tx);
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                tokio::spawn(async move {
                    if let Some(stall) = wedge_rx.recv().await {
                        let _ = engaged_tx.send(());
                        // No await between the signal and the sleep, so the
                        // worker is wedged before the reply can be polled.
                        std::thread::sleep(stall);
                    }
                });
                let (stream, _) = listener.accept().await.unwrap();
                let _ = handle_connection(
                    stream,
                    std::future::pending::<()>(),
                    &metrics,
                    &probe,
                    None,
                    &Semaphore::new(MAX_SCRAPES),
                )
                .await;
            });
        });

        let addr = addr_rx.await.unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        // Answer the peer half, then hold the RIB reply until the wedge is
        // in place so it is already queued when the runtime unparks well
        // past the deadline.
        if let Some(PeerManagerCommand::Ping { reply }) = peer_rx.recv().await {
            let _ = reply.send(());
        }
        let Some(RibUpdate::QueryLocRibCount { reply }) = rib_rx.recv().await else {
            panic!("expected QueryLocRibCount");
        };
        wedge_tx.send(Duration::from_millis(600)).await.unwrap();
        engaged_rx.await.unwrap();
        let _ = reply.send(0);

        let response = tokio::time::timeout(Duration::from_secs(5), async {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        })
        .await
        .expect("response within 5s");
        assert!(
            response.starts_with("HTTP/1.1 503 Service Unavailable"),
            "late probe success must not be certified as ready: {response}"
        );
        assert!(response.ends_with("not ready: readiness probe deadline exceeded\n"));
    }

    #[tokio::test]
    async fn get_readyz_returns_503_when_daemon_gate_is_tripped() {
        // LAN-286: bind failure / coordinated shutdown trips the daemon
        // gate — /readyz must go red without consulting the core actors.
        use rustbgpd_api::health_probe::DaemonGate;

        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let gate = DaemonGate::new();
        let addr =
            start_server(CoreReadinessProbe::new(peer_tx, rib_tx).with_gate(gate.clone())).await;

        gate.begin_shutdown();

        let response = request(addr, "/readyz").await;
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.ends_with("not ready: daemon is shutting down\n"));
    }

    #[tokio::test]
    async fn slow_client_times_out() {
        let addr = start_server(unused_probe()).await;
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
        let addr = start_server(unused_probe()).await;
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
                let probe = unused_probe();
                tokio::spawn(async move {
                    let _ = handle_connection(
                        stream,
                        std::future::pending::<()>(),
                        &m,
                        &probe,
                        None,
                        &Semaphore::new(1),
                    )
                    .await;
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

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn persistent_emfile_backs_off_instead_of_spinning() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A listener stuck at EMFILE: every poll fails at once. The stream
        // ends after 1000 polls so a missing backoff fails the assertion
        // instead of hanging the test.
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let incoming = tokio_stream::iter(std::iter::from_fn(move || {
            (counter.fetch_add(1, Ordering::SeqCst) < 1000)
                .then(|| Err(std::io::Error::from_raw_os_error(libc::EMFILE)))
        }));
        let served = tokio::time::timeout(
            Duration::from_secs(10),
            serve_incoming(
                incoming,
                "metrics test".into(),
                BgpMetrics::new(),
                unused_probe(),
                None,
            ),
        )
        .await;
        assert!(served.is_err(), "backoff must keep the accept loop waiting");
        // 0, 100, 300, 700, 1500 ms, then once per second up to 9500 ms.
        assert_eq!(polls.load(Ordering::SeqCst), 13);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn unusable_listener_socket_stops_the_accept_loop() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let polls = Arc::new(AtomicUsize::new(0));
        let counter = polls.clone();
        let incoming = tokio_stream::iter(std::iter::from_fn(move || {
            (counter.fetch_add(1, Ordering::SeqCst) < 1000)
                .then(|| Err(std::io::Error::from_raw_os_error(libc::EBADF)))
        }));
        let start = tokio::time::Instant::now();
        serve_incoming(
            incoming,
            "metrics test".into(),
            BgpMetrics::new(),
            unused_probe(),
            None,
        )
        .await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }
}
