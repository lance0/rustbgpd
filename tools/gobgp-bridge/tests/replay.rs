//! Replay ordering and capacity against a scripted daemon: an unban during an
//! outage is retried after it, a replay never reinstalls a withdrawn path, and
//! the tracking cap is checked before the daemon sees a new ban.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use rustbgpd_gobgp_bridge::gobgp::{self, gobgp_api_server::GobgpApi};
use rustbgpd_gobgp_bridge::rustbgpd::{
    self as rbgp,
    injection_service_server::{InjectionService, InjectionServiceServer},
};
use rustbgpd_gobgp_bridge::{Bridge, daemon_channel};
use tokio::sync::Notify;
use tonic::{Code, Request, Response, Status};

#[derive(Default)]
struct Script {
    /// Local routes the scripted daemon holds, by prefix.
    routes: BTreeSet<String>,
    /// Every call in arrival order, as "add P" or "delete P".
    calls: Vec<String>,
    /// Answer every call with UNAVAILABLE.
    down: bool,
    /// Park the next AddPath until notified.
    hold_add: Option<Arc<Notify>>,
    /// Signalled when an AddPath parks.
    parked: Option<Arc<Notify>>,
}

#[derive(Clone, Default)]
struct Daemon(Arc<Mutex<Script>>);

#[tonic::async_trait]
impl InjectionService for Daemon {
    async fn add_path(
        &self,
        request: Request<rbgp::AddPathRequest>,
    ) -> Result<Response<rbgp::AddPathResponse>, Status> {
        let prefix = request.into_inner().prefix;
        let (hold, parked) = {
            let mut script = self.0.lock().unwrap();
            if script.down {
                return Err(Status::unavailable("scripted outage"));
            }
            (script.hold_add.take(), script.parked.take())
        };
        if let Some(hold) = hold {
            parked.unwrap().notify_one();
            hold.notified().await;
        }
        let mut script = self.0.lock().unwrap();
        script.calls.push(format!("add {prefix}"));
        let created = script.routes.insert(prefix);
        Ok(Response::new(rbgp::AddPathResponse {
            outcome: if created {
                rbgp::PathInjectOutcome::Created
            } else {
                rbgp::PathInjectOutcome::Unchanged
            } as i32,
        }))
    }

    async fn delete_path(
        &self,
        request: Request<rbgp::DeletePathRequest>,
    ) -> Result<Response<rbgp::DeletePathResponse>, Status> {
        let req = request.into_inner();
        assert!(req.allow_missing, "withdrawals must be idempotent");
        let mut script = self.0.lock().unwrap();
        if script.down {
            return Err(Status::unavailable("scripted outage"));
        }
        script.calls.push(format!("delete {}", req.prefix));
        script.routes.remove(&req.prefix);
        Ok(Response::new(rbgp::DeletePathResponse::default()))
    }
}

async fn bridge(max_tracked: usize) -> (Bridge, Daemon) {
    let daemon = Daemon::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = InjectionServiceServer::new(daemon.clone());
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
    );
    let channel = daemon_channel(&format!("http://{addr}").parse().unwrap()).unwrap();
    (Bridge::new(channel, None, max_tracked), daemon)
}

/// A host-route ban or unban for 203.0.113.`host`.
fn ban(host: u8, withdraw: bool) -> Request<gobgp::AddPathRequest> {
    Request::new(gobgp::AddPathRequest {
        table_type: gobgp::TableType::Global as i32,
        vrf_id: String::new(),
        path: Some(gobgp::Path {
            family: Some(gobgp::Family {
                afi: gobgp::family::Afi::Ip as i32,
                safi: gobgp::family::Safi::Unicast as i32,
            }),
            nlri_binary: vec![32, 203, 0, 113, host],
            pattrs_binary: vec![vec![0x40, 3, 4, 192, 0, 2, 1]],
            is_withdraw: withdraw,
            ..Default::default()
        }),
    })
}

fn held(daemon: &Daemon) -> Vec<String> {
    daemon.0.lock().unwrap().routes.iter().cloned().collect()
}

#[tokio::test]
async fn replay_restores_bans_a_restarted_daemon_lost() {
    let (bridge, daemon) = bridge(8).await;
    bridge.add_path(ban(1, false)).await.unwrap();
    bridge.add_path(ban(2, false)).await.unwrap();
    // The daemon restarts with nothing.
    daemon.0.lock().unwrap().routes.clear();
    bridge.reconcile().await;
    assert_eq!(held(&daemon), ["203.0.113.1", "203.0.113.2"]);
}

#[tokio::test]
async fn unban_during_an_outage_is_retried_and_never_replayed() {
    let (bridge, daemon) = bridge(8).await;
    bridge.add_path(ban(1, false)).await.unwrap();
    bridge.add_path(ban(2, false)).await.unwrap();

    daemon.0.lock().unwrap().down = true;
    let err = bridge.add_path(ban(1, true)).await.unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
    assert!(err.message().contains("retries this withdrawal"), "{err:?}");
    // A pass during the outage changes nothing.
    bridge.reconcile().await;

    daemon.0.lock().unwrap().down = false;
    daemon.0.lock().unwrap().calls.clear();
    bridge.reconcile().await;
    // The pending delete goes first, and the withdrawn path is not re-added.
    assert_eq!(
        daemon.0.lock().unwrap().calls,
        ["delete 203.0.113.1", "add 203.0.113.2"]
    );
    assert_eq!(held(&daemon), ["203.0.113.2"]);

    // The retry is done: the next pass sends no delete.
    daemon.0.lock().unwrap().calls.clear();
    bridge.reconcile().await;
    assert_eq!(daemon.0.lock().unwrap().calls, ["add 203.0.113.2"]);
}

#[tokio::test]
async fn a_replay_in_flight_never_reinstalls_a_later_withdrawal() {
    let (bridge, daemon) = bridge(8).await;
    bridge.add_path(ban(1, false)).await.unwrap();

    // Park the replay's AddPath inside the daemon, then send the unban.
    let hold = Arc::new(Notify::new());
    let parked = Arc::new(Notify::new());
    {
        let mut script = daemon.0.lock().unwrap();
        script.hold_add = Some(hold.clone());
        script.parked = Some(parked.clone());
    }
    let replay = tokio::spawn({
        let bridge = bridge.clone();
        async move { bridge.reconcile().await }
    });
    parked.notified().await;
    let unban = tokio::spawn({
        let bridge = bridge.clone();
        async move { bridge.add_path(ban(1, true)).await }
    });
    // Not needed for the pass: it gives an implementation that lets the
    // unban overtake the parked replay the time to do so and fail below.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    hold.notify_one();
    replay.await.unwrap();
    unban.await.unwrap().unwrap();
    assert_eq!(
        daemon.0.lock().unwrap().calls,
        ["add 203.0.113.1", "add 203.0.113.1", "delete 203.0.113.1"]
    );
    assert_eq!(held(&daemon), Vec::<String>::new());
    bridge.reconcile().await;
    assert_eq!(held(&daemon), Vec::<String>::new());
}

#[tokio::test]
async fn the_cap_is_checked_before_the_daemon_sees_a_new_ban() {
    let (bridge, daemon) = bridge(1).await;
    bridge.add_path(ban(1, false)).await.unwrap();
    // A repeat of a tracked ban needs no new slot.
    bridge.add_path(ban(1, false)).await.unwrap();
    let err = bridge.add_path(ban(2, false)).await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(
        held(&daemon),
        ["203.0.113.1"],
        "the rejected ban never reached the daemon"
    );

    bridge.add_path(ban(1, true)).await.unwrap();
    bridge.add_path(ban(2, false)).await.unwrap();
    assert_eq!(held(&daemon), ["203.0.113.2"]);
}
