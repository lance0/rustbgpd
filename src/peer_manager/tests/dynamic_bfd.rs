//! Single-hop BFD for sessions accepted through a `[[dynamic_neighbors]]`
//! range: each accepted session registers its BFD session through the
//! runtime-registered membership interface-only bindings use, and removes it
//! on every path by which the session ends.

use super::inbound_admission::localhost_inbound_stream;
use super::*;

use crate::bfd_runtime::{BfdReloadCommand, BfdRuntimeConfig, BfdStateChange};
use crate::peer_manager::DynamicBfdSocketOutcome;
use rustbgpd_transport::{SessionEndRetention, SessionRole};

const MEMBER: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));

/// The dynamic test config, its `127.0.0.0/8` range running BFD with the
/// `fast` profile; a `slow` one is defined too.
fn range_bfd_config() -> Config {
    let mut config = make_dynamic_manager_config();
    for (name, interval, multiplier) in [("fast", 300, 3), ("slow", 1000, 5)] {
        config.bfd_profiles.push(crate::config::BfdProfileConfig {
            name: name.to_string(),
            min_tx_interval: interval,
            min_rx_interval: interval,
            multiplier,
        });
    }
    config.dynamic_neighbors[0].bfd = Some(range_bfd("fast"));
    config
}

fn range_bfd(profile: &str) -> crate::config::BfdConfig {
    crate::config::BfdConfig {
        profile: profile.to_string(),
        enabled: true,
        strict: false,
        multihop: false,
    }
}

struct Lab {
    mgr: PeerManager,
    /// The desired set as the BFD actor sees it, by either publication.
    desired: watch::Receiver<BfdRuntimeConfig>,
    /// Every set the fake actor took through the acknowledged path.
    applied: mpsc::UnboundedReceiver<BfdRuntimeConfig>,
    /// The fake actor takes the next acknowledged change but drops its reply.
    drop_next_reply: Arc<AtomicBool>,
    clients: Vec<TcpStream>,
}

/// A coupled manager over `config`, on a running RIB, with a fake BFD actor
/// that acknowledges every acknowledged membership change.
fn lab(config: Config) -> Lab {
    let (rib_tx, rib_rx) = mpsc::channel(256);
    let (_query_tx, query_rx) = mpsc::channel(4);
    tokio::spawn(
        rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new()).run(),
    );
    let mgr = PeerManager::new_with_config(
        mpsc::channel(16).1,
        mpsc::channel(1).1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    );
    let (desired_tx, desired) = watch::channel(BfdRuntimeConfig::default());
    let (_state_tx, state_rx) = crate::bfd_runtime::state_change_channel();
    let (reload_tx, mut reload_rx) = mpsc::channel::<BfdReloadCommand>(1);
    let (applied_tx, applied) = mpsc::unbounded_channel();
    let drop_next_reply = Arc::new(AtomicBool::new(false));
    let drop_next = Arc::clone(&drop_next_reply);
    tokio::spawn(async move {
        while let Some(command) = reload_rx.recv().await {
            let _ = applied_tx.send(command.desired.clone());
            if drop_next.swap(false, Ordering::SeqCst) {
                continue;
            }
            let acks = command
                .desired
                .sessions
                .iter()
                .filter(|params| params.enabled)
                .map(|params| BfdStateChange {
                    revision: params.revision,
                    peer: params.peer,
                    state: rustbgpd_bfd::SessionState::Down,
                    diagnostic: rustbgpd_bfd::Diagnostic::None,
                    remote_admin_down: false,
                    resync: true,
                })
                .collect();
            let _ = command.reply.send(acks);
        }
    });
    let mgr = mgr
        .with_bfd_coupling(desired_tx, state_rx, HashMap::new())
        .with_bfd_reload(reload_tx);
    Lab {
        mgr,
        desired,
        applied,
        drop_next_reply,
        clients: Vec::new(),
    }
}

impl Lab {
    /// Apply `candidate` as a SIGHUP reload generation with no session actions.
    async fn generation(&mut self, candidate: Config) -> ReloadGenerationOutcome {
        Box::pin(self.mgr.apply_reload_generation(
            candidate,
            Vec::new(),
            crate::config::PreparedDatasetGeneration::default(),
        ))
        .await
    }

    async fn accept(&mut self, addr: IpAddr) {
        let (server, client) = localhost_inbound_stream().await;
        self.mgr
            .handle_inbound(server, sock(addr), None, None)
            .await;
        self.clients.push(client);
    }

    /// The published sessions: (peer, label, enabled).
    fn published(&self) -> Vec<(IpAddr, String, bool)> {
        let mut sessions: Vec<_> = self
            .desired
            .borrow()
            .sessions
            .iter()
            .map(|params| (params.peer, params.peer_label.clone(), params.enabled))
            .collect();
        sessions.sort();
        sessions
    }

    fn member(&self, peer: IpAddr) -> Option<&crate::bfd_runtime::BfdSessionParams> {
        self.mgr.bfd_coupling.as_ref()?.configured.get(&peer)
    }

    fn assert_unregistered(&self, peer: IpAddr) {
        let coupling = self.mgr.bfd_coupling.as_ref().unwrap();
        assert!(!coupling.configured.contains_key(&peer), "{peer} member");
        assert!(!coupling.bound.contains(&peer), "{peer} bound");
        assert!(!coupling.held_down.contains(&peer), "{peer} hold");
        assert!(
            !self
                .published()
                .iter()
                .any(|(published, ..)| *published == peer),
            "{peer} published"
        );
    }

    /// The session at `addr` ends after reporting `end`.
    async fn idle(&mut self, addr: IpAddr, end: SessionEndRetention) {
        let managed = &self.mgr.peers[&key(addr)];
        managed.handle().publish_session_end_retention(end);
        let session_id = managed.session_id();
        self.mgr
            .handle_session_notification(SessionNotification::BackToIdle {
                session_id,
                role: SessionRole::Primary,
                peer_addr: addr,
            })
            .await;
    }
}

const ENDED: SessionEndRetention = SessionEndRetention {
    established: true,
    theirs: false,
    ours_for: None,
};

/// An accepted session registers a single-hop session to its source address,
/// labelled by that address, without waiting on the BFD actor; its auto-
/// removal at session end removes it. A second session is untouched.
#[tokio::test]
async fn an_accepted_session_registers_its_bfd_session_and_auto_removal_removes_it() {
    let mut lab = lab(range_bfd_config());
    // Mutation-red: without `register_dynamic_bfd` nothing is published.
    lab.accept(MEMBER).await;
    lab.accept(OTHER).await;
    assert_eq!(
        lab.published(),
        [
            (MEMBER, MEMBER.to_string(), true),
            (OTHER, OTHER.to_string(), true)
        ]
    );
    let member = lab.member(MEMBER).unwrap();
    assert_eq!(
        (
            member.multihop,
            member.strict,
            member.scope_id,
            member.detect_mult
        ),
        (false, false, None, 3)
    );
    assert!(
        lab.mgr
            .bfd_coupling
            .as_ref()
            .unwrap()
            .bound
            .contains(&MEMBER)
    );

    // Mutation-red: without `release_dynamic_bfd` on auto-removal the
    // session's BFD session outlives it.
    lab.idle(MEMBER, ENDED).await;
    assert!(!lab.mgr.peers.contains_key(&key(MEMBER)), "auto-removed");
    lab.assert_unregistered(MEMBER);
    assert_eq!(lab.published(), [(OTHER, OTHER.to_string(), true)]);

    // A reconnect registers again, under a fresh revision.
    let first = lab.member(OTHER).unwrap().revision;
    lab.accept(MEMBER).await;
    assert!(lab.member(MEMBER).unwrap().revision > first);
}

/// A session that ends while graceful restart retains its identity removes
/// its BFD session too: the retained identity has no session to tear down.
#[tokio::test]
async fn a_retained_identitys_bfd_session_ends_with_its_session() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    assert!(lab.member(MEMBER).is_some(), "registered");
    // Validate the OPEN so the identity can be retained.
    let managed = &lab.mgr.peers[&key(MEMBER)];
    managed
        .transport_config
        .rib_peer
        .resolve(|| rustbgpd_rib::PeerEndpoint::new(MEMBER, None), 65002);
    lab.idle(
        MEMBER,
        SessionEndRetention {
            established: true,
            theirs: false,
            ours_for: Some(Duration::from_secs(120)),
        },
    )
    .await;
    assert!(
        lab.mgr.retained_dynamic.contains_key(&key(MEMBER)),
        "the identity is retained"
    );
    lab.assert_unregistered(MEMBER);
}

/// A genuine BFD Down tears the dynamic session down through the same
/// `BfdDown` command a static neighbor gets (Cease/10, RFC 9384, with the GR
/// purge the FSM applies). Its session then ends, which removes the BFD
/// session and its hold: the next connection is a new session.
#[tokio::test]
async fn bfd_down_tears_down_a_dynamic_session_and_its_end_releases_the_hold() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    let (tx, mut commands) = mpsc::channel::<PeerCommand>(8);
    let session_id = lab.mgr.peers[&key(MEMBER)].session_id();
    lab.mgr.peers.replace_handle(
        &key(MEMBER),
        PeerHandle::from_parts(tx, tokio::spawn(async { Ok(()) })),
        session_id,
    );
    let revision = lab.member(MEMBER).unwrap().revision;
    lab.mgr
        .handle_bfd_state_change(BfdStateChange {
            revision,
            peer: MEMBER,
            state: rustbgpd_bfd::SessionState::Down,
            diagnostic: rustbgpd_bfd::Diagnostic::ControlDetectionTimeExpired,
            remote_admin_down: false,
            resync: false,
        })
        .await;
    assert!(matches!(commands.try_recv(), Ok(PeerCommand::BfdDown)));
    assert!(lab.mgr.bfd_withholding(&MEMBER));

    lab.mgr
        .handle_session_notification(SessionNotification::BackToIdle {
            session_id,
            role: SessionRole::Primary,
            peer_addr: MEMBER,
        })
        .await;
    lab.assert_unregistered(MEMBER);
    assert!(!lab.mgr.bfd_withholding(&MEMBER));
    lab.accept(MEMBER).await;
    assert!(lab.mgr.peers.contains_key(&key(MEMBER)), "accepted again");
    assert!(lab.member(MEMBER).unwrap().revision > revision);
}

/// A connection refused at the dynamic-neighbor limit registers nothing.
#[tokio::test]
async fn a_connection_refused_at_the_range_limit_registers_no_bfd_session() {
    let mut config = range_bfd_config();
    config.global.dynamic_neighbor_limit = Some(1);
    let mut lab = lab(config);
    lab.accept(MEMBER).await;
    lab.accept(OTHER).await;
    assert!(!lab.mgr.peers.contains_key(&key(OTHER)), "refused");
    lab.assert_unregistered(OTHER);
    assert_eq!(lab.published(), [(MEMBER, MEMBER.to_string(), true)]);
}

/// A dynamic peer reaped because no current range admits it (a rolled-back
/// config transaction) removes its BFD session.
#[tokio::test]
async fn a_reaped_dynamic_peer_removes_its_bfd_session() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    assert!(lab.member(MEMBER).is_some(), "registered");
    lab.mgr.dynamic_ranges.clear();
    assert_eq!(
        lab.mgr
            .reap_dynamic_peers_not_allowed_by_current_ranges()
            .await,
        1
    );
    lab.assert_unregistered(MEMBER);
}

/// A reload generation applies a range's `bfd` edit to its running sessions:
/// a profile change replaces each session's BFD session, removing `bfd`
/// removes it while BGP keeps running, and adding it registers it.
#[tokio::test]
async fn a_generation_applies_a_range_bfd_edit_to_running_sessions() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    let revision = lab.member(MEMBER).unwrap().revision;

    let same = lab.mgr.current_config.clone();
    assert!(matches!(
        lab.generation(same).await,
        ReloadGenerationOutcome::Applied(_)
    ));
    assert_eq!(lab.member(MEMBER).unwrap().revision, revision, "unchanged");

    let mut slower = lab.mgr.current_config.clone();
    slower.dynamic_neighbors[0].bfd = Some(range_bfd("slow"));
    assert!(matches!(
        lab.generation(slower.clone()).await,
        ReloadGenerationOutcome::Applied(_)
    ));
    let replaced = lab.member(MEMBER).unwrap();
    assert_eq!(replaced.detect_mult, 5);
    assert!(replaced.revision > revision, "replaced");
    assert_eq!(lab.published(), [(MEMBER, MEMBER.to_string(), true)]);

    let mut without = slower.clone();
    without.dynamic_neighbors[0].bfd = None;
    assert!(matches!(
        lab.generation(without).await,
        ReloadGenerationOutcome::Applied(_)
    ));
    assert!(
        lab.mgr.peers.contains_key(&key(MEMBER)),
        "BGP keeps running"
    );
    lab.assert_unregistered(MEMBER);

    assert!(matches!(
        lab.generation(slower).await,
        ReloadGenerationOutcome::Applied(_)
    ));
    assert!(
        lab.member(MEMBER).is_some(),
        "registered for the running session"
    );
}

/// A range `bfd` edit whose socket preflight fails is rejected with no
/// effect: the running config and BFD membership stay, and a new connection
/// still registers under the running range.
#[tokio::test]
async fn a_failed_socket_preflight_rejects_a_range_bfd_edit_with_no_effect() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    let before = lab.member(MEMBER).unwrap().clone();
    let running = lab.mgr.current_config.clone();
    let mut slower = running.clone();
    slower.dynamic_neighbors[0].bfd = Some(range_bfd("slow"));
    lab.mgr.bfd_coupling.as_mut().unwrap().socket_preflight = Some(Err("address in use".into()));
    let outcome = lab.generation(slower).await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::RejectedNoEffect(ref error)
            if error.contains("BFD socket preflight")),
        "{outcome:?}"
    );
    assert_eq!(lab.mgr.current_config, running, "the running config stays");
    assert_eq!(lab.member(MEMBER), Some(&before), "the member stays");
    assert!(lab.applied.try_recv().is_err(), "nothing reached the actor");
    lab.accept(OTHER).await;
    assert_eq!(
        lab.member(OTHER).unwrap().detect_mult,
        3,
        "accepts still register"
    );
}

/// A range `bfd` edit whose acknowledgement is lost fences the generation
/// instead of reporting it applied, and an identical retry reconciles the
/// actor with the new membership.
#[tokio::test]
async fn a_lost_range_bfd_acknowledgement_fences_and_a_retry_reconciles() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    let mut slower = lab.mgr.current_config.clone();
    slower.dynamic_neighbors[0].bfd = Some(range_bfd("slow"));
    lab.drop_next_reply.store(true, Ordering::SeqCst);
    let outcome = lab.generation(slower.clone()).await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::CompensationAmbiguous(_)),
        "{outcome:?}"
    );
    let taken = lab.applied.try_recv().expect("the actor took the change");
    assert_eq!(taken.sessions[0].detect_mult, 5);
    // Fenced: no new BFD session registers until the membership settles.
    assert!(lab.mgr.bfd_coupling.as_ref().unwrap().reloading);

    // Mutation-red: a retry that skips an unchanged-looking membership never
    // reaches the actor.
    assert!(matches!(
        lab.generation(slower).await,
        ReloadGenerationOutcome::Applied(_)
    ));
    let retried = lab.applied.try_recv().expect("the retry reaches the actor");
    assert_eq!(
        retried
            .sessions
            .iter()
            .map(|params| (params.peer, params.detect_mult))
            .collect::<Vec<_>>(),
        [(MEMBER, 5)]
    );
    assert_eq!(lab.desired.borrow().sessions[0].detect_mult, 5, "published");
    assert!(!lab.mgr.bfd_coupling.as_ref().unwrap().reloading, "settled");
}

/// An accept never opens a BFD socket: in a family no startup or reload has
/// opened, the connection is refused and counted as `bfd_unavailable`.
#[tokio::test]
async fn an_accept_in_an_unopened_bfd_family_is_refused_and_counted() {
    let mut lab = lab(range_bfd_config());
    lab.mgr
        .bfd_coupling
        .as_mut()
        .unwrap()
        .opened
        .sessions
        .clear();
    // Mutation-red: an uncounted refusal leaves the series at 0.
    lab.accept(MEMBER).await;
    assert!(!lab.mgr.peers.contains_key(&key(MEMBER)), "refused");
    lab.assert_unregistered(MEMBER);
    assert_eq!(
        inbound_drop_metric(&lab.mgr.metrics, "bfd_unavailable"),
        Some(1.0)
    );
}

/// A reload that opens a range's socket family while no BFD session exists
/// yet still hands the sockets to the actor and records the family as open:
/// the commit's no-membership shortcut must not drop them.
#[tokio::test]
async fn sockets_prepared_for_a_range_without_sessions_reach_the_actor() {
    let mut lab = lab(make_dynamic_manager_config());
    let probes = crate::bfd_runtime::dynamic_range_socket_probes(&range_bfd_config()).unwrap();
    let coupling = lab.mgr.bfd_coupling.as_mut().unwrap();
    assert_eq!(coupling.opened.sessions.len(), 0, "no family is open yet");
    coupling.pending = Some(HashMap::new());
    coupling.pending_probes = probes;
    coupling.reloading = true;
    // Mutation-red: with the shortcut taken, the family is never recorded.
    lab.mgr
        .commit_bfd_reload(Some(crate::bfd_runtime::PreparedRuntime::default()))
        .await
        .unwrap();
    let opened = &lab.mgr.bfd_coupling.as_ref().unwrap().opened.sessions;
    assert!(
        opened
            .iter()
            .any(|params| params.peer.is_ipv4() && !params.multihop),
        "the IPv4 single-hop family is open"
    );
}

/// Runtime range CRUD cannot remove a range that runs BFD, and a config
/// transaction cannot change a range's `bfd`: both belong to startup and
/// SIGHUP.
#[test]
fn runtime_crud_and_transactions_cannot_change_range_bfd() {
    let config = range_bfd_config();
    let mut mgr = PeerManager::new_with_config(
        mpsc::channel(16).1,
        mpsc::channel(1).1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        mpsc::channel(1).0,
        None,
        None,
        config.clone(),
    );
    let error = mgr.delete_dynamic_range("127.0.0.0/8").unwrap_err();
    assert!(error.to_string().contains("runs BFD"), "{error}");
    assert_eq!(mgr.current_config.dynamic_neighbors.len(), 1);

    let unchanged = super::super::bfd::dynamic_range_bfd_unchanged;
    assert_eq!(unchanged(&config, &config), Ok(()));
    let mut edited = config.clone();
    edited.dynamic_neighbors[0].description = Some("renamed".to_string());
    assert_eq!(unchanged(&config, &edited), Ok(()), "a non-BFD edit passes");
    let changes: [fn(&mut Config); 3] = [
        |c: &mut Config| c.dynamic_neighbors[0].bfd = None,
        |c: &mut Config| c.dynamic_neighbors.clear(),
        |c: &mut Config| c.dynamic_neighbors[0].prefix = "127.0.0.0/16".to_string(),
    ];
    for change in changes {
        let mut candidate = config.clone();
        change(&mut candidate);
        assert!(unchanged(&config, &candidate).is_err());
    }
}

/// Other membership changes keep a running dynamic session's BFD session: a
/// reload generation rebuilds it from the candidate's range unchanged, and an
/// interface-only binding change does not prune it as a stale binding.
#[tokio::test]
async fn a_generation_reload_and_a_binding_change_keep_dynamic_members() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    let revision = lab.member(MEMBER).unwrap().revision;

    // Mutation-red: without the dynamic rebuild a generation drops it.
    let candidate = lab.mgr.current_config.clone();
    let prepared = lab.mgr.prepare_bfd_reload(&candidate).unwrap();
    lab.mgr.commit_bfd_reload(prepared).await.unwrap();
    assert_eq!(lab.member(MEMBER).unwrap().revision, revision, "unchanged");
    assert!(
        lab.mgr
            .bfd_coupling
            .as_ref()
            .unwrap()
            .bound
            .contains(&MEMBER)
    );

    // Mutation-red: pruning by interface-only bindings alone drops it.
    lab.mgr
        .set_bound_bfd_session("fe80::1".parse().unwrap(), None)
        .await
        .unwrap();
    assert_eq!(lab.member(MEMBER).unwrap().revision, revision, "kept");
    assert_eq!(lab.published(), [(MEMBER, MEMBER.to_string(), true)]);
}

/// The dynamic test config with no range, and the range `range_bfd_config`
/// adds.
fn without_ranges() -> Config {
    let mut config = range_bfd_config();
    config.dynamic_neighbors.clear();
    config
}

/// A sequential SIGHUP that adds a BFD range opens its socket family before
/// its first effect, through the acknowledged commit with the membership
/// unchanged, so the range's first accept registers in the same reload.
#[tokio::test]
async fn a_reload_that_adds_a_bfd_range_opens_its_socket_family() {
    let mut lab = lab(without_ranges());
    let candidate = range_bfd_config();
    lab.mgr.bfd_coupling.as_mut().unwrap().socket_preflight =
        Some(Ok(Some(crate::bfd_runtime::PreparedRuntime::default())));
    // Mutation-red: reporting Ready without the commit leaves the family
    // closed, and the accept below is refused.
    assert_eq!(
        lab.mgr.open_dynamic_bfd_sockets(&candidate).await,
        DynamicBfdSocketOutcome::Ready
    );
    let taken = lab
        .applied
        .try_recv()
        .expect("the sockets reached the actor");
    assert_eq!(taken.sessions.len(), 0, "the membership is unchanged");
    // The sequential route then swaps the candidate in.
    lab.mgr.current_config = candidate;
    lab.mgr.dynamic_ranges = PeerManager::parse_dynamic_ranges(&lab.mgr.current_config);
    lab.accept(MEMBER).await;
    assert!(lab.member(MEMBER).is_some(), "the first accept registers");

    // With the family open, a later add needs no sockets.
    assert_eq!(
        lab.mgr.open_dynamic_bfd_sockets(&range_bfd_config()).await,
        DynamicBfdSocketOutcome::Ready
    );
    assert!(lab.applied.try_recv().is_err(), "nothing to open");
}

/// A family that cannot open rejects the adding reload with no effect, and a
/// lost acknowledgement of the prepared sockets fences BFD.
#[tokio::test]
async fn a_bfd_range_add_rejects_on_preflight_failure_and_fences_on_a_lost_ack() {
    let mut lab = lab(without_ranges());
    let candidate = range_bfd_config();
    lab.mgr.bfd_coupling.as_mut().unwrap().socket_preflight = Some(Err("address in use".into()));
    assert!(matches!(
        lab.mgr.open_dynamic_bfd_sockets(&candidate).await,
        DynamicBfdSocketOutcome::Rejected(error) if error.contains("address in use")
    ));
    let coupling = lab.mgr.bfd_coupling.as_ref().unwrap();
    assert!(!coupling.reloading, "no effect");
    assert_eq!(coupling.opened.sessions.len(), 0);
    assert!(lab.applied.try_recv().is_err(), "nothing reached the actor");

    lab.mgr.bfd_coupling.as_mut().unwrap().socket_preflight =
        Some(Ok(Some(crate::bfd_runtime::PreparedRuntime::default())));
    lab.drop_next_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        lab.mgr.open_dynamic_bfd_sockets(&candidate).await,
        DynamicBfdSocketOutcome::Ambiguous(_)
    ));
    assert!(lab.mgr.bfd_coupling.as_ref().unwrap().reloading, "fenced");
}

/// Removing a BFD range in one sequential reload leaves its running session
/// with its BFD session, and a later unrelated generation keeps it.
#[tokio::test]
async fn a_removed_bfd_ranges_session_keeps_its_bfd_through_a_later_generation() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    let revision = lab.member(MEMBER).unwrap().revision;
    // The sequential route swaps the candidate in: future accepts stop.
    lab.mgr.current_config.dynamic_neighbors.clear();
    lab.mgr.dynamic_ranges.clear();
    assert!(
        lab.mgr.peers.contains_key(&key(MEMBER)),
        "the session runs on"
    );
    assert_eq!(lab.member(MEMBER).unwrap().revision, revision);

    // Mutation-red: rebuilding only from the candidate's ranges drops it.
    let mut unrelated = lab.mgr.current_config.clone();
    unrelated
        .peer_groups
        .get_mut("ix-members")
        .unwrap()
        .hold_time = Some(120);
    assert!(matches!(
        lab.generation(unrelated).await,
        ReloadGenerationOutcome::Applied(_)
    ));
    assert_eq!(lab.member(MEMBER).unwrap().revision, revision, "kept");
    assert_eq!(lab.published(), [(MEMBER, MEMBER.to_string(), true)]);
}

/// A session that ends while a generation is staged, which then aborts,
/// leaves no BFD admission state behind for a reconnect.
#[tokio::test]
async fn a_session_ending_mid_generation_leaves_no_hold_after_an_abort() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    let (tx, _commands) = mpsc::channel::<PeerCommand>(8);
    let session_id = lab.mgr.peers[&key(MEMBER)].session_id();
    lab.mgr.peers.replace_handle(
        &key(MEMBER),
        PeerHandle::from_parts(tx, tokio::spawn(async { Ok(()) })),
        session_id,
    );
    let revision = lab.member(MEMBER).unwrap().revision;
    lab.mgr
        .handle_bfd_state_change(BfdStateChange {
            revision,
            peer: MEMBER,
            state: rustbgpd_bfd::SessionState::Down,
            diagnostic: rustbgpd_bfd::Diagnostic::ControlDetectionTimeExpired,
            remote_admin_down: false,
            resync: false,
        })
        .await;
    assert!(lab.mgr.bfd_withholding(&MEMBER));
    let candidate = lab.mgr.current_config.clone();
    let _prepared = lab.mgr.prepare_bfd_reload(&candidate).unwrap();
    lab.mgr
        .handle_session_notification(SessionNotification::BackToIdle {
            session_id,
            role: SessionRole::Primary,
            peer_addr: MEMBER,
        })
        .await;
    // Mutation-red: keeping the ended session's saved hold restores it here.
    lab.mgr.abort_bfd_reload();
    assert!(
        !lab.mgr.bfd_withholding(&MEMBER),
        "no hold survives the abort"
    );
    lab.assert_unregistered(MEMBER);
    lab.accept(MEMBER).await;
    assert!(lab.member(MEMBER).is_some(), "the reconnect registers");
    assert!(!lab.mgr.bfd_withholding(&MEMBER), "and starts clean");
}

/// A session that ends while a generation stages its first BFD attachment,
/// before the commit, leaves no member, desired entry or actor session.
#[tokio::test]
async fn a_session_ending_before_its_first_bfd_commit_leaves_nothing() {
    let mut plain = range_bfd_config();
    plain.dynamic_neighbors[0].bfd = None;
    let mut lab = lab(plain);
    lab.accept(MEMBER).await;
    lab.assert_unregistered(MEMBER);
    lab.mgr.bfd_coupling.as_mut().unwrap().socket_preflight =
        Some(Ok(Some(crate::bfd_runtime::PreparedRuntime::default())));
    let prepared = lab.mgr.prepare_bfd_reload(&range_bfd_config()).unwrap();
    assert!(
        !lab.mgr
            .bfd_coupling
            .as_ref()
            .unwrap()
            .bound
            .contains(&MEMBER),
        "staged only"
    );
    lab.idle(MEMBER, ENDED).await;
    // Mutation-red: releasing only bound members lets the commit bind it.
    lab.mgr.commit_bfd_reload(prepared).await.unwrap();
    let taken = lab
        .applied
        .try_recv()
        .expect("the commit reached the actor");
    assert!(
        !taken.sessions.iter().any(|params| params.peer == MEMBER),
        "no actor session"
    );
    lab.assert_unregistered(MEMBER);
}
