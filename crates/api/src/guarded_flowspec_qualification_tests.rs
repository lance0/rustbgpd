//! Qualification of the guarded `FlowSpec` contract (ADR-0144) against
//! request delay, client timeout, delayed retry and renewal, foreign refusals
//! and the window cap. Each case runs a guarded mutation and, as its negative
//! control, the same delay or order under the legacy leased contract.
//!
//! Everything is in process: the real `InjectionService` and `RibManager`,
//! and for the transport cases a real HTTP/2 server on an in-memory duplex
//! pipe, on a paused clock. Orderings come from handshakes, never sleeps: a
//! relay hands the test each update the service queues for the RIB, and a
//! gate holds a call before its handler until the test releases it. Time
//! moves only by `tokio::time::advance`.
//!
//! The gate stops a call before its handler, which is where a network or
//! proxy delay lands; it does not reproduce delay on the wire itself.

use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use rustbgpd_rib::RibUpdate;
use rustbgpd_rib::injection_lease::{ExpiryExit, InjectionLeases};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tonic::transport::{Channel, Endpoint, Server, Uri};
use tonic::{Code, Request, Status};

use crate::injection_service::InjectionService;
use crate::proto;
use crate::proto::injection_service_client::InjectionServiceClient;
use crate::proto::injection_service_server::{InjectionService as _, InjectionServiceServer};
use crate::proto::rib_service_server::RibService as _;
use crate::rib_service::RibService;
use crate::server::AccessMode;

/// `google.rpc.Status`, as a client decodes `grpc-status-details-bin`.
#[derive(Clone, PartialEq, prost::Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<prost_types::Any>,
}

/// `google.rpc.ErrorInfo` without `metadata`.
#[derive(Clone, PartialEq, prost::Message)]
struct ErrorInfo {
    #[prost(string, tag = "1")]
    reason: String,
    #[prost(string, tag = "2")]
    domain: String,
}

/// The status code and, for a refusal that carries one, its `ErrorInfo`
/// reason: what a controller branches on.
fn outcome<T>(result: &Result<T, Status>) -> (Code, String) {
    use prost::Message as _;
    let Err(status) = result else {
        return (Code::Ok, String::new());
    };
    let reason = RpcStatus::decode(status.details())
        .ok()
        .and_then(|details| details.details.into_iter().next())
        .and_then(|any| ErrorInfo::decode(any.value.as_slice()).ok())
        .map(|info| info.reason)
        .unwrap_or_default();
    (status.code(), reason)
}

fn refused(reason: &str) -> (Code, String) {
    (Code::FailedPrecondition, reason.to_string())
}

fn ok() -> (Code, String) {
    (Code::Ok, String::new())
}

/// A discard rule for one destination prefix.
fn rule(destination: &str) -> proto::AddFlowSpecRequest {
    proto::AddFlowSpecRequest {
        afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
        components: vec![proto::FlowSpecComponent {
            r#type: 1,
            prefix: destination.into(),
            value: String::new(),
            offset: 0,
        }],
        actions: vec![proto::FlowSpecAction {
            action: Some(proto::flow_spec_action::Action::TrafficRate(
                proto::FlowSpecTrafficRate { rate: 0.0 },
            )),
        }],
        communities: vec![],
        extended_communities: vec![],
        ipv6_extended_communities: vec![],
    }
}

fn lease(owner: &str, lease_seconds: u32) -> proto::InjectionLease {
    proto::InjectionLease {
        owner: owner.into(),
        lease_seconds,
    }
}

fn guarded_add(
    destination: &str,
    owner: &str,
    lease_seconds: u32,
    window: proto::MutationWindow,
    revision: u64,
) -> proto::AddGuardedFlowSpecRequest {
    proto::AddGuardedFlowSpecRequest {
        rule: Some(rule(destination)),
        lease: Some(lease(owner, lease_seconds)),
        window: Some(window),
        revision,
    }
}

fn leased_add(
    destination: &str,
    owner: &str,
    lease_seconds: u32,
) -> proto::AddLeasedFlowSpecRequest {
    proto::AddLeasedFlowSpecRequest {
        rule: Some(rule(destination)),
        lease: Some(lease(owner, lease_seconds)),
    }
}

fn guarded_delete(
    destination: &str,
    owner: &str,
    revision: u64,
) -> proto::DeleteGuardedFlowSpecRequest {
    proto::DeleteGuardedFlowSpecRequest {
        afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
        components: rule(destination).components,
        owner: owner.into(),
        revision,
    }
}

fn leased_delete(destination: &str, owner: &str) -> proto::DeleteFlowSpecRequest {
    proto::DeleteFlowSpecRequest {
        afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
        components: rule(destination).components,
        allow_missing: false,
        owner: owner.into(),
        override_owner: false,
    }
}

/// A real RIB with its lease table and expiry task, and an injection
/// service whose RIB channel is direct.
struct Rig {
    direct: InjectionService,
    rib: RibService,
    leases: Arc<InjectionLeases>,
    rib_tx: mpsc::Sender<RibUpdate>,
    manager: tokio::task::JoinHandle<()>,
    cancel_expiry: oneshot::Sender<()>,
    expiry: tokio::task::JoinHandle<ExpiryExit>,
}

impl Rig {
    fn start() -> Self {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let leases = manager.injection_leases();
        let manager = tokio::spawn(manager.run());
        let (cancel_expiry, cancel_rx) = oneshot::channel();
        let expiry = tokio::spawn(Arc::clone(&leases).run_expiry(rib_tx.clone(), cancel_rx));
        Self {
            direct: self_service(rib_tx.clone(), &leases),
            rib: RibService::new(rib_tx.clone()).with_injection_leases(Arc::clone(&leases)),
            leases,
            rib_tx,
            manager,
            cancel_expiry,
            expiry,
        }
    }

    /// A service sharing this lease table whose RIB updates the test relays
    /// by hand: each update it queues arrives on the returned receiver.
    fn relayed(&self) -> (InjectionService, mpsc::Receiver<RibUpdate>) {
        let (relay_tx, relay_rx) = mpsc::channel(8);
        (self_service(relay_tx, &self.leases), relay_rx)
    }

    /// A service for a transport server whose RIB updates are forwarded at
    /// once. The server task outlives the test body and keeps its service;
    /// aborting the returned forwarder releases its hold on the RIB channel
    /// so the RIB can stop.
    fn forwarded(&self) -> (InjectionService, tokio::task::JoinHandle<()>) {
        let (service, mut relay) = self.relayed();
        let rib_tx = self.rib_tx.clone();
        let forwarder = tokio::spawn(async move {
            while let Some(update) = relay.recv().await {
                if rib_tx.send(update).await.is_err() {
                    return;
                }
            }
        });
        (service, forwarder)
    }

    async fn stop(self) {
        let _ = self.cancel_expiry.send(());
        assert_eq!(self.expiry.await.unwrap(), ExpiryExit::Cancelled);
        drop((self.direct, self.rib, self.rib_tx));
        self.manager.await.unwrap();
    }

    async fn window(&self, owner: &str, window_seconds: u32) -> proto::MutationWindow {
        self.direct
            .issue_mutation_window(Request::new(proto::IssueMutationWindowRequest {
                owner: owner.into(),
                window_seconds,
            }))
            .await
            .unwrap()
            .into_inner()
            .window
            .unwrap()
    }

    /// The local rules: destination, owner and admission revision.
    async fn rules(&self) -> Vec<(String, String, Option<u64>)> {
        let mut rules: Vec<_> = self
            .rib
            .list_flow_spec_routes(Request::new(proto::ListFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                received_peer_address: "0.0.0.0".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .received_routes
            .into_iter()
            .filter_map(|row| row.route)
            .map(|route| {
                (
                    route.components[0].prefix.clone(),
                    route.injection_owner,
                    route.admission_revision,
                )
            })
            .collect();
        rules.sort();
        rules
    }

    /// `owner`'s lease row, if any: generation sequence and remaining ms.
    async fn lease(&self, owner: &str) -> Option<(u64, u32)> {
        self.direct
            .list_injection_leases(Request::new(proto::ListInjectionLeasesRequest {
                owner: owner.into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .leases
            .first()
            .map(|row| (row.generation.unwrap().sequence, row.lease_remaining_ms))
    }
}

fn self_service(
    rib_tx: mpsc::Sender<RibUpdate>,
    leases: &Arc<InjectionLeases>,
) -> InjectionService {
    InjectionService::new(rib_tx, AccessMode::ReadWrite, Arc::clone(leases))
}

fn rule_row(
    destination: &str,
    owner: &str,
    revision: Option<u64>,
) -> (String, String, Option<u64>) {
    (destination.to_string(), owner.to_string(), revision)
}

/// Holds every call before its handler until released: the test learns that
/// a call arrived, moves time, then lets it run.
#[derive(Clone)]
struct Gate {
    arrived: mpsc::UnboundedSender<()>,
    release: Arc<Semaphore>,
}

impl Gate {
    fn new() -> (Self, mpsc::UnboundedReceiver<()>) {
        let (arrived, arrivals) = mpsc::unbounded_channel();
        (
            Self {
                arrived,
                release: Arc::new(Semaphore::new(0)),
            },
            arrivals,
        )
    }

    fn release_one(&self) {
        self.release.add_permits(1);
    }
}

/// A client of `service` over a real HTTP/2 connection, optionally behind
/// `gate`.
async fn connect(service: InjectionService, gate: Option<Gate>) -> InjectionServiceClient<Channel> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let held = tower::util::option_layer(gate.map(|gate| {
        tower::util::MapFutureLayer::new(move |handler| {
            let gate = gate.clone();
            async move {
                gate.arrived.send(()).unwrap();
                gate.release.acquire().await.unwrap().forget();
                handler.await
            }
        })
    }));
    tokio::spawn(
        Server::builder()
            .layer(held)
            .add_service(InjectionServiceServer::new(service))
            .serve_with_incoming(tokio_stream::once(Ok::<_, std::io::Error>(server_io))),
    );
    let mut client_io = Some(client_io);
    let channel = Endpoint::from_static("http://guarded-qualification.test")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let io = client_io.take();
            async move {
                io.map(TokioIo::new)
                    .ok_or_else(|| std::io::Error::other("reused"))
            }
        }))
        .await
        .unwrap();
    InjectionServiceClient::new(channel)
}

/// Let the expiry task and the RIB act on time that just advanced.
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// The client's deadline passed before any reply. tonic's server reports an
/// expired `grpc-timeout` as `CANCELLED`; a client-side deadline is
/// `DEADLINE_EXCEEDED`. Either way the outcome is unknown to the client.
#[track_caller]
fn assert_client_gave_up<T: std::fmt::Debug>(result: &Result<T, Status>) {
    assert!(
        matches!(outcome(result).0, Code::DeadlineExceeded | Code::Cancelled),
        "{result:?}"
    );
}

fn with_deadline<T>(message: T, deadline: Duration) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(deadline);
    request
}

/// Case 2. A call whose client deadline passes while it waits in the RIB
/// queue still commits when the RIB reaches it. A guarded add whose window
/// expired by then is refused at commit and leaves nothing; one whose window
/// is still live commits, and reading back its revision resolves the
/// client's unknown outcome. Control: a legacy leased add in the same queue
/// commits after its client gave up.
#[tokio::test(start_paused = true)]
async fn a_call_queued_past_the_client_deadline_commits_only_inside_its_window() {
    let rig = Rig::start();
    let (service, mut queued) = rig.relayed();
    let client = connect(service, None).await;
    let deadline = Duration::from_secs(1);

    // Guarded, window 2 s: the RIB reaches the add at 3 s.
    let window = rig.window("ctl", 2).await;
    let call = tokio::spawn({
        let mut client = client.clone();
        async move {
            client
                .add_guarded_flow_spec(with_deadline(
                    guarded_add("203.0.113.1/32", "ctl", 60, window, 1),
                    deadline,
                ))
                .await
        }
    });
    let update = queued.recv().await.unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_client_gave_up(&call.await.unwrap());
    rig.rib_tx.send(update).await.unwrap();
    assert_eq!(
        rig.rules().await,
        vec![],
        "the late guarded add left a rule"
    );
    assert_eq!(
        rig.lease("guarded:ctl").await,
        None,
        "the late guarded add started a lease"
    );

    // Guarded, window 10 s: the same delay commits, and the read-back
    // resolves the timed-out client's unknown outcome.
    let window = rig.window("ctl", 10).await;
    let call = tokio::spawn({
        let mut client = client.clone();
        async move {
            client
                .add_guarded_flow_spec(with_deadline(
                    guarded_add("203.0.113.2/32", "ctl", 60, window, 7),
                    deadline,
                ))
                .await
        }
    });
    let update = queued.recv().await.unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_client_gave_up(&call.await.unwrap());
    rig.rib_tx.send(update).await.unwrap();
    assert_eq!(
        rig.rules().await,
        vec![rule_row("203.0.113.2/32", "guarded:ctl", Some(7))]
    );

    // Control: a legacy leased add queued the same way commits.
    let call = tokio::spawn({
        let mut client = client.clone();
        async move {
            client
                .add_leased_flow_spec(with_deadline(
                    leased_add("203.0.113.3/32", "legacy", 60),
                    deadline,
                ))
                .await
        }
    });
    let update = queued.recv().await.unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_client_gave_up(&call.await.unwrap());
    rig.rib_tx.send(update).await.unwrap();
    assert!(
        rig.rules()
            .await
            .contains(&rule_row("203.0.113.3/32", "legacy", None)),
        "control: the late legacy add committed"
    );
    assert!(
        rig.lease("legacy").await.is_some(),
        "control: it started a lease"
    );
    rig.stop().await;
}

/// Case 3. A guarded add held before its handler until its window expired
/// is refused with `WINDOW_NOT_LIVE` and changes nothing. Control: a legacy
/// leased add held the same way commits.
///
/// Break-to-red: without the window-liveness check at admission, the held
/// guarded add commits.
#[tokio::test(start_paused = true)]
async fn a_call_held_before_its_handler_past_its_window_is_refused() {
    let rig = Rig::start();
    let (gate, mut arrivals) = Gate::new();
    let (service, forwarder) = rig.forwarded();
    let client = connect(service, Some(gate.clone())).await;

    let window = rig.window("ctl", 2).await;
    let call = tokio::spawn({
        let mut client = client.clone();
        async move {
            client
                .add_guarded_flow_spec(guarded_add("203.0.113.1/32", "ctl", 60, window, 1))
                .await
        }
    });
    arrivals.recv().await.unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    gate.release_one();
    assert_eq!(outcome(&call.await.unwrap()), refused("WINDOW_NOT_LIVE"));
    assert_eq!(rig.rules().await, vec![]);
    assert_eq!(rig.lease("guarded:ctl").await, None);

    // Control: the same hold on a legacy leased add.
    let call = tokio::spawn({
        let mut client = client.clone();
        async move {
            client
                .add_leased_flow_spec(leased_add("203.0.113.3/32", "legacy", 60))
                .await
        }
    });
    arrivals.recv().await.unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    gate.release_one();
    assert_eq!(outcome(&call.await.unwrap()), ok());
    assert_eq!(
        rig.rules().await,
        vec![rule_row("203.0.113.3/32", "legacy", None)]
    );
    forwarder.abort();
    rig.stop().await;
}

/// Case 4. Delayed renewals and retries in different orders never carry a
/// guarded lease past the latest window issued, and a late retry revives
/// nothing. Controls: a delayed legacy renewal extends to arrival plus the
/// lease, and a delayed legacy re-add after expiry starts a new generation.
#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "three orders and their legacy controls on one clock"
)]
async fn delayed_renewals_and_retries_never_outlive_the_latest_window() {
    let rig = Rig::start();
    let renew = |owner: &str, generation, lease_seconds, window| {
        rig.direct
            .renew_guarded_lease(Request::new(proto::RenewGuardedLeaseRequest {
                owner: owner.into(),
                generation,
                lease_seconds,
                window: Some(window),
            }))
    };
    let add = |request| rig.direct.add_guarded_flow_spec(Request::new(request));

    // (a) The window ends before the renewal and the retry arrive: the rule
    // is withdrawn at the window-capped deadline and nothing comes back.
    let w1 = rig.window("a", 20).await;
    let generation = add(guarded_add("203.0.113.1/32", "a", 60, w1, 1))
        .await
        .unwrap()
        .into_inner()
        .generation;
    assert_eq!(rig.lease("guarded:a").await.unwrap().1, 20_000);
    tokio::time::advance(Duration::from_secs(21)).await;
    settle().await;
    assert_eq!(
        rig.rules().await,
        vec![],
        "(a) withdrawn at the window-capped deadline"
    );
    assert_eq!(
        outcome(&renew("a", generation, 60, w1).await),
        refused("WINDOW_NOT_LIVE")
    );
    assert_eq!(
        outcome(&add(guarded_add("203.0.113.1/32", "a", 60, w1, 1)).await),
        refused("WINDOW_NOT_LIVE")
    );
    assert_eq!(
        rig.rules().await,
        vec![],
        "(a) the late retry revived nothing"
    );
    assert_eq!(rig.lease("guarded:a").await, None);

    // (b) The renewal lands first, under a newer window; then a retry under
    // the expired first window is refused and the deadline does not move.
    let w1 = rig.window("b", 10).await;
    let generation = add(guarded_add("203.0.113.2/32", "b", 60, w1, 1))
        .await
        .unwrap()
        .into_inner()
        .generation;
    tokio::time::advance(Duration::from_secs(5)).await;
    let w2 = rig.window("b", 30).await;
    let renewed = renew("b", generation, 60, w2).await.unwrap().into_inner();
    assert_eq!(
        renewed.lease_remaining_ms, 30_000,
        "(b) capped at the newer window"
    );
    tokio::time::advance(Duration::from_secs(7)).await;
    assert_eq!(
        outcome(&add(guarded_add("203.0.113.2/32", "b", 60, w1, 1)).await),
        refused("WINDOW_NOT_LIVE")
    );
    assert_eq!(
        rig.lease("guarded:b").await.unwrap().1,
        23_000,
        "(b) deadline unchanged"
    );

    // (c) A retry with a live window and the same revision is UNCHANGED and
    // keeps the deadline, which stays within the latest window.
    let retried = add(guarded_add("203.0.113.2/32", "b", 60, w2, 1))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        retried.result.unwrap().outcome(),
        proto::FlowSpecInjectOutcome::Unchanged
    );
    assert_eq!(retried.generation, generation);
    assert_eq!(
        rig.lease("guarded:b").await.unwrap().1,
        23_000,
        "(c) deadline unchanged"
    );

    // Controls under the legacy contract.
    let legacy = rig
        .direct
        .add_leased_flow_spec(Request::new(leased_add("203.0.113.3/32", "legacy", 20)))
        .await
        .unwrap()
        .into_inner()
        .generation;
    tokio::time::advance(Duration::from_secs(5)).await;
    let renewed = rig
        .direct
        .renew_lease(Request::new(proto::RenewLeaseRequest {
            owner: "legacy".into(),
            generation: legacy,
            lease_seconds: 60,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        renewed.lease_remaining_ms, 60_000,
        "control: a delayed legacy renewal extends to arrival plus the lease"
    );
    tokio::time::advance(Duration::from_secs(61)).await;
    settle().await;
    assert!(
        !rig.rules().await.iter().any(|row| row.1 == "legacy"),
        "control: the legacy rule expired"
    );
    let revived = rig
        .direct
        .add_leased_flow_spec(Request::new(leased_add("203.0.113.3/32", "legacy", 20)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        revived.result.unwrap().outcome(),
        proto::FlowSpecInjectOutcome::Created,
        "control: a late legacy re-add revives the rule"
    );
    assert_ne!(revived.generation, legacy, "control: in a new generation");
    rig.stop().await;
}

/// Case 6. With a sibling key live, a foreign owner's add and delete and a
/// delete or add at another revision are refused and change nothing; a
/// delete delayed past a newer admission of the same key is refused.
/// Control: under the legacy contract the same late delete removes the
/// newer admission.
///
/// Break-to-red: without the revision check on the delete path, the late
/// delete removes the newer admission.
#[tokio::test(start_paused = true)]
async fn foreign_and_stale_mutations_are_refused_while_a_sibling_lives() {
    let rig = Rig::start();
    let svc = &rig.direct;
    let window = rig.window("ctl", 120).await;
    let other = rig.window("other", 120).await;
    let add = |request| svc.add_guarded_flow_spec(Request::new(request));
    let delete = |request| svc.delete_guarded_flow_spec(Request::new(request));
    add(guarded_add("203.0.113.1/32", "ctl", 60, window, 1))
        .await
        .unwrap();
    add(guarded_add("203.0.113.2/32", "ctl", 60, window, 1))
        .await
        .unwrap();
    let before = (rig.rules().await, rig.lease("guarded:ctl").await);

    let refusals = [
        outcome(&add(guarded_add("203.0.113.1/32", "other", 60, other, 1)).await),
        outcome(&delete(guarded_delete("203.0.113.1/32", "other", 1)).await),
        outcome(&delete(guarded_delete("203.0.113.1/32", "ctl", 2)).await),
        outcome(&add(guarded_add("203.0.113.1/32", "ctl", 60, window, 2)).await),
    ];
    assert_eq!(
        refusals,
        [
            refused("OWNER_MISMATCH"),
            refused("OWNER_MISMATCH"),
            refused("REVISION_MISMATCH"),
            refused("REVISION_MISMATCH"),
        ]
    );
    assert_eq!(
        (rig.rules().await, rig.lease("guarded:ctl").await),
        before,
        "the refusals changed the rules or the lease"
    );

    // A delete of revision 1 delivered again after the key was deleted and
    // re-added at revision 2.
    assert_eq!(
        outcome(&delete(guarded_delete("203.0.113.1/32", "ctl", 1)).await),
        ok()
    );
    add(guarded_add("203.0.113.1/32", "ctl", 60, window, 2))
        .await
        .unwrap();
    assert_eq!(
        outcome(&delete(guarded_delete("203.0.113.1/32", "ctl", 1)).await),
        refused("REVISION_MISMATCH")
    );
    assert_eq!(
        rig.rules().await,
        vec![
            rule_row("203.0.113.1/32", "guarded:ctl", Some(2)),
            rule_row("203.0.113.2/32", "guarded:ctl", Some(1)),
        ]
    );

    // Control: the same sequence under the legacy contract.
    let legacy_delete =
        || svc.delete_flow_spec(Request::new(leased_delete("203.0.113.3/32", "legacy")));
    svc.add_leased_flow_spec(Request::new(leased_add("203.0.113.3/32", "legacy", 60)))
        .await
        .unwrap();
    assert_eq!(outcome(&legacy_delete().await), ok());
    svc.add_leased_flow_spec(Request::new(leased_add("203.0.113.3/32", "legacy", 60)))
        .await
        .unwrap();
    assert_eq!(
        outcome(&legacy_delete().await),
        ok(),
        "control: the late legacy delete removes the newer admission"
    );
    assert!(!rig.rules().await.iter().any(|row| row.1 == "legacy"));
    rig.stop().await;
}

/// Case 7. An owner's 65th live window is `RESOURCE_EXHAUSTED` and changes
/// nothing: its first window still admits, another owner can still issue,
/// and once the windows expire the owner can issue again. Control: legacy
/// leased adds are unaffected by the exhausted cap.
#[tokio::test(start_paused = true)]
async fn the_window_cap_is_resource_exhausted_and_changes_nothing() {
    let rig = Rig::start();
    let issue = |owner: &str| {
        rig.direct
            .issue_mutation_window(Request::new(proto::IssueMutationWindowRequest {
                owner: owner.into(),
                window_seconds: 30,
            }))
    };
    let first = issue("ctl").await.unwrap().into_inner().window.unwrap();
    for _ in 1..64 {
        issue("ctl").await.unwrap();
    }
    assert_eq!(outcome(&issue("ctl").await).0, Code::ResourceExhausted);
    assert_eq!(
        outcome(
            &rig.direct
                .add_guarded_flow_spec(Request::new(guarded_add(
                    "203.0.113.1/32",
                    "ctl",
                    60,
                    first,
                    1
                )))
                .await
        ),
        ok(),
        "the refusal invalidated an issued window"
    );
    assert_eq!(outcome(&issue("other").await), ok());
    assert_eq!(
        outcome(
            &rig.direct
                .add_leased_flow_spec(Request::new(leased_add("203.0.113.3/32", "legacy", 60)))
                .await
        ),
        ok(),
        "control: legacy adds are unaffected"
    );
    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(outcome(&issue("ctl").await), ok());
    rig.stop().await;
}
