//! Replay ordering and capacity against a scripted daemon: an unban during an
//! outage is retried after it, a cancelled unban is still retried, a replay
//! never reinstalls a withdrawn path, a daemon that stops answering does not
//! hold the bridge, the tracking cap is checked before the daemon sees a
//! new ban, and a liveness probe that sees the daemon come back, or answer
//! with a new incarnation, replays at once and then signals replay complete
//! for that incarnation.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustbgpd_gobgp_bridge::gobgp::{self, gobgp_api_server::GobgpApi};
use rustbgpd_gobgp_bridge::rustbgpd::{
    self as rbgp,
    control_service_server::{ControlService, ControlServiceServer},
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
    /// Signalled when an AddPath or DeletePath parks.
    parked: Option<Arc<Notify>>,
    /// Park the next DeletePath until notified.
    hold_delete: Option<Arc<Notify>>,
    /// Accept every call and never answer.
    stalled: bool,
    /// Answer AddPath with UNAVAILABLE while other calls succeed.
    refuse_add: bool,
    /// The incarnation CheckLiveness reports.
    incarnation: u64,
    /// CheckLiveness calls answered.
    probes: usize,
    /// Refuse the next MarkReplayComplete with FAILED_PRECONDITION.
    stale_mark: bool,
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
        let (hold, parked, stalled) = {
            let mut script = self.0.lock().unwrap();
            if script.down || script.refuse_add {
                return Err(Status::unavailable("scripted outage"));
            }
            let hold = script.hold_add.take();
            let parked = hold.is_some().then(|| script.parked.take()).flatten();
            (hold, parked, script.stalled)
        };
        if stalled {
            std::future::pending::<()>().await;
        }
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
        let (hold, parked, stalled) = {
            let mut script = self.0.lock().unwrap();
            if script.down {
                return Err(Status::unavailable("scripted outage"));
            }
            let hold = script.hold_delete.take();
            let parked = hold.is_some().then(|| script.parked.take()).flatten();
            (hold, parked, script.stalled)
        };
        if stalled {
            std::future::pending::<()>().await;
        }
        if let Some(hold) = hold {
            parked.unwrap().notify_one();
            hold.notified().await;
        }
        let mut script = self.0.lock().unwrap();
        script.calls.push(format!("delete {}", req.prefix));
        script.routes.remove(&req.prefix);
        Ok(Response::new(rbgp::DeletePathResponse::default()))
    }

    async fn mark_replay_complete(
        &self,
        request: Request<rbgp::MarkReplayCompleteRequest>,
    ) -> Result<Response<rbgp::MarkReplayCompleteResponse>, Status> {
        let req = request.into_inner();
        let mut script = self.0.lock().unwrap();
        if script.down {
            return Err(Status::unavailable("scripted outage"));
        }
        if std::mem::take(&mut script.stale_mark) {
            script
                .calls
                .push(format!("stale {} {}", req.owner, req.incarnation));
            return Err(Status::failed_precondition("scripted stale incarnation"));
        }
        script
            .calls
            .push(format!("mark {} {}", req.owner, req.incarnation));
        Ok(Response::new(rbgp::MarkReplayCompleteResponse {
            outcome: rbgp::ReplayCompleteOutcome::Released as i32,
            awaiting: vec![],
        }))
    }
}

#[tonic::async_trait]
impl ControlService for Daemon {
    async fn check_liveness(
        &self,
        _request: Request<rbgp::CheckLivenessRequest>,
    ) -> Result<Response<rbgp::CheckLivenessResponse>, Status> {
        let mut script = self.0.lock().unwrap();
        if script.down {
            return Err(Status::unavailable("scripted outage"));
        }
        script.probes += 1;
        Ok(Response::new(rbgp::CheckLivenessResponse {
            incarnation: script.incarnation,
        }))
    }
}

async fn bridge(max_tracked: usize) -> (Bridge, Daemon) {
    bridge_with_deadline(max_tracked, rustbgpd_gobgp_bridge::DAEMON_RPC_TIMEOUT).await
}

async fn bridge_with_deadline(max_tracked: usize, rpc_timeout: Duration) -> (Bridge, Daemon) {
    let daemon = Daemon::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = InjectionServiceServer::new(daemon.clone());
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(service)
            .add_service(ControlServiceServer::new(daemon.clone()))
            .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
    );
    let channel = daemon_channel(&format!("http://{addr}").parse().unwrap(), rpc_timeout).unwrap();
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

#[tokio::test]
async fn a_cancelled_unban_is_still_retried() {
    let (bridge, daemon) = bridge(8).await;
    bridge.add_path(ban(1, false)).await.unwrap();

    // Park the unban's DeletePath, then drop the handler, as tonic does when
    // the detector's deadline expires or it disconnects.
    let hold = Arc::new(Notify::new());
    let parked = Arc::new(Notify::new());
    {
        let mut script = daemon.0.lock().unwrap();
        script.hold_delete = Some(hold);
        script.parked = Some(parked.clone());
    }
    let unban = tokio::spawn({
        let bridge = bridge.clone();
        async move { bridge.add_path(ban(1, true)).await }
    });
    parked.notified().await;
    unban.abort();
    assert!(unban.await.unwrap_err().is_cancelled());
    assert_eq!(
        held(&daemon),
        ["203.0.113.1"],
        "the parked delete never completed"
    );

    daemon.0.lock().unwrap().calls.clear();
    bridge.reconcile().await;
    assert_eq!(daemon.0.lock().unwrap().calls, ["delete 203.0.113.1"]);
    assert_eq!(held(&daemon), Vec::<String>::new());
    daemon.0.lock().unwrap().calls.clear();
    bridge.reconcile().await;
    assert_eq!(daemon.0.lock().unwrap().calls, Vec::<String>::new());
}

#[tokio::test]
async fn a_daemon_that_stops_answering_does_not_hold_the_bridge() {
    let deadline = Duration::from_millis(200);
    let (bridge, daemon) = bridge_with_deadline(8, deadline).await;
    bridge.add_path(ban(1, false)).await.unwrap();
    bridge.add_path(ban(2, false)).await.unwrap();

    daemon.0.lock().unwrap().stalled = true;
    // A reconcile pass ends at the first deadline instead of holding the lock.
    tokio::time::timeout(Duration::from_secs(5), bridge.reconcile())
        .await
        .expect("reconcile must not wait on a stalled daemon");
    // So does an unban, which stays pending.
    let err = tokio::time::timeout(Duration::from_secs(5), bridge.add_path(ban(1, true)))
        .await
        .expect("an unban must not wait on a stalled daemon")
        .unwrap_err();
    assert!(err.message().contains("retries this withdrawal"), "{err:?}");

    daemon.0.lock().unwrap().stalled = false;
    // A later ban proceeds, and the next pass applies the pending unban.
    bridge.add_path(ban(3, false)).await.unwrap();
    bridge.reconcile().await;
    assert_eq!(held(&daemon), ["203.0.113.2", "203.0.113.3"]);
}

/// Poll until the scripted daemon holds `want`, or give up after 5 s.
async fn wait_held(daemon: &Daemon, want: &[&str]) -> bool {
    for _ in 0..100 {
        if held(daemon) == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn a_probe_that_sees_the_daemon_come_back_replays_at_once() {
    let (bridge, daemon) = bridge(8).await;
    // No periodic pass: only the restart watch can replay.
    bridge.spawn_restart_watch(Duration::from_millis(20));
    bridge.add_path(ban(1, false)).await.unwrap();
    // The daemon goes away with its routes, a probe sees it down, then it
    // comes back.
    {
        let mut script = daemon.0.lock().unwrap();
        script.down = true;
        script.routes.clear();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    daemon.0.lock().unwrap().down = false;
    assert!(
        wait_held(&daemon, &["203.0.113.1"]).await,
        "{:?}",
        held(&daemon)
    );
}

#[tokio::test]
async fn a_restart_between_two_probes_replays_at_once() {
    let (bridge, daemon) = bridge(8).await;
    daemon.0.lock().unwrap().incarnation = 1;
    bridge.spawn_restart_watch(Duration::from_millis(20));
    bridge.add_path(ban(1, false)).await.unwrap();
    // Let the watch see the first incarnation.
    for _ in 0..100 {
        if daemon.0.lock().unwrap().probes >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // The daemon restarts with nothing between two probes: every probe is
    // answered, only the incarnation changes.
    {
        let mut script = daemon.0.lock().unwrap();
        assert!(script.probes >= 2, "the watch never probed");
        script.routes.clear();
        script.incarnation = 2;
    }
    assert!(
        wait_held(&daemon, &["203.0.113.1"]).await,
        "{:?}",
        held(&daemon)
    );
}

#[tokio::test]
async fn a_daemon_that_stays_up_is_not_replayed_by_the_watch() {
    let (bridge, daemon) = bridge(8).await;
    bridge.spawn_restart_watch(Duration::from_millis(20));
    bridge.add_path(ban(1, false)).await.unwrap();
    // Routes vanish while every probe is answered: the watch leaves them to
    // the periodic pass.
    daemon.0.lock().unwrap().routes.clear();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(held(&daemon).is_empty(), "{:?}", held(&daemon));
}

#[tokio::test]
async fn an_unfinished_pass_after_the_daemon_returns_is_retried() {
    let (bridge, daemon) = bridge(8).await;
    bridge.spawn_restart_watch(Duration::from_millis(20));
    bridge.add_path(ban(1, false)).await.unwrap();
    {
        let mut script = daemon.0.lock().unwrap();
        script.down = true;
        script.routes.clear();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The daemon answers probes again but still refuses injections, so the
    // first passes fail.
    {
        let mut script = daemon.0.lock().unwrap();
        script.down = false;
        script.refuse_add = true;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(held(&daemon).is_empty(), "{:?}", held(&daemon));
    daemon.0.lock().unwrap().refuse_add = false;
    assert!(
        wait_held(&daemon, &["203.0.113.1"]).await,
        "{:?}",
        held(&daemon)
    );
}

async fn wait_calls(daemon: &Daemon, done: impl Fn(&[String]) -> bool) -> Vec<String> {
    for _ in 0..100 {
        let calls = daemon.0.lock().unwrap().calls.clone();
        if done(&calls) {
            return calls;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    daemon.0.lock().unwrap().calls.clone()
}

/// After the daemon restarts, the watch replays every ban and only then
/// signals replay complete, as the bridge's owner, for the incarnation its
/// probe saw. A refused signal (the daemon restarted again) is retried after
/// another full pass. A daemon that stays up is never signalled.
#[tokio::test]
async fn a_complete_post_restart_pass_signals_replay_complete() {
    let (bridge, daemon) = bridge(8).await;
    daemon.0.lock().unwrap().incarnation = 1;
    bridge.spawn_restart_watch(Duration::from_millis(20));
    bridge.add_path(ban(1, false)).await.unwrap();
    bridge.add_path(ban(2, false)).await.unwrap();
    for _ in 0..100 {
        if daemon.0.lock().unwrap().probes >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    {
        let mut script = daemon.0.lock().unwrap();
        assert!(script.probes >= 2, "the watch never probed");
        assert!(
            !script.calls.iter().any(|call| call.starts_with("mark")),
            "signalled without a restart: {:?}",
            script.calls
        );
        script.calls.clear();
        script.routes.clear();
        script.incarnation = 2;
        script.stale_mark = true;
    }
    let owner = rustbgpd_gobgp_bridge::REPLAY_OWNER;
    let calls = wait_calls(&daemon, |calls| {
        calls.iter().any(|call| call.starts_with("mark"))
    })
    .await;
    // Pass, refused signal, a second full pass, accepted signal.
    let replay = ["add 203.0.113.1", "add 203.0.113.2"];
    let mut pass: Vec<&str> = calls[..2].iter().map(String::as_str).collect();
    pass.sort_unstable();
    assert_eq!(pass, replay, "{calls:?}");
    assert_eq!(calls[2], format!("stale {owner} 2"), "{calls:?}");
    let mut pass: Vec<&str> = calls[3..5].iter().map(String::as_str).collect();
    pass.sort_unstable();
    assert_eq!(pass, replay, "{calls:?}");
    assert_eq!(calls[5..], [format!("mark {owner} 2")], "{calls:?}");
}
