//! Single-hop BFD for sessions accepted through a `[[dynamic_neighbors]]`
//! range: each accepted session registers its BFD session through the
//! runtime-registered membership interface-only bindings use, and removes it
//! on every path by which the session ends.

use super::inbound_admission::localhost_inbound_stream;
use super::*;

use crate::bfd_runtime::{BfdReloadCommand, BfdRuntimeConfig, BfdStateChange};
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
    _rib_rx: mpsc::Receiver<RibUpdate>,
    clients: Vec<TcpStream>,
}

/// A coupled manager over `config` with a fake BFD actor that acknowledges
/// every acknowledged membership change and mirrors it into `desired`.
fn lab(config: Config) -> Lab {
    let (rib_tx, rib_rx) = mpsc::channel(256);
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
    tokio::spawn(async move {
        while let Some(command) = reload_rx.recv().await {
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
        _rib_rx: rib_rx,
        clients: Vec::new(),
    }
}

impl Lab {
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

/// A reload that edits the range's profile replaces each running session's
/// BFD session; one that removes the range's `bfd`, or the range, removes it
/// while the BGP session keeps running; one that adds it registers it.
#[tokio::test]
async fn a_reload_replaces_removes_and_registers_running_sessions_bfd() {
    let mut lab = lab(range_bfd_config());
    lab.accept(MEMBER).await;
    let revision = lab.member(MEMBER).unwrap().revision;

    // Unchanged: nothing moves.
    let same = lab.mgr.current_config.clone();
    lab.mgr.adopt_config_snapshot(same).await;
    assert_eq!(lab.member(MEMBER).unwrap().revision, revision);

    let mut slower = lab.mgr.current_config.clone();
    slower.dynamic_neighbors[0].bfd = Some(range_bfd("slow"));
    lab.mgr.adopt_config_snapshot(slower.clone()).await;
    let replaced = lab.member(MEMBER).unwrap();
    assert_eq!(replaced.detect_mult, 5);
    assert!(replaced.revision > revision, "replaced");
    assert_eq!(lab.published(), [(MEMBER, MEMBER.to_string(), true)]);

    let mut without = slower.clone();
    without.dynamic_neighbors[0].bfd = None;
    lab.mgr.adopt_config_snapshot(without.clone()).await;
    assert!(
        lab.mgr.peers.contains_key(&key(MEMBER)),
        "BGP keeps running"
    );
    lab.assert_unregistered(MEMBER);

    lab.mgr.adopt_config_snapshot(slower.clone()).await;
    assert!(
        lab.member(MEMBER).is_some(),
        "registered for the running session"
    );

    let mut deleted = slower;
    deleted.dynamic_neighbors.clear();
    lab.mgr.adopt_config_snapshot(deleted).await;
    assert!(
        lab.mgr.peers.contains_key(&key(MEMBER)),
        "BGP keeps running"
    );
    lab.assert_unregistered(MEMBER);
}

/// An accept never opens a BFD socket: in a family no startup or reload has
/// opened, the connection is refused. Once the family is open, a reload
/// that gives the range BFD registers the running session.
#[tokio::test]
async fn an_accept_in_an_unopened_bfd_family_is_refused() {
    let mut lab = lab(make_dynamic_manager_config());
    lab.accept(MEMBER).await;
    lab.assert_unregistered(MEMBER);
    let accepted = lab.mgr.peers[&key(MEMBER)]
        .accepted_dynamic_range
        .clone()
        .unwrap();
    let with_bfd = range_bfd_config();
    // Not yet adopted: the range runs no BFD.
    assert_eq!(lab.mgr.dynamic_bfd_admission(&accepted, OTHER), Ok(None));
    lab.mgr.current_config.bfd_profiles = with_bfd.bfd_profiles.clone();
    lab.mgr.current_config.dynamic_neighbors[0].bfd = Some(range_bfd("fast"));
    let refused = lab.mgr.dynamic_bfd_admission(&accepted, OTHER);
    assert_eq!(
        refused,
        Err("the range's BFD socket family is not open".to_string()),
        "an accept never opens a socket"
    );
    // Opening a real socket would bind the BFD port in the test, so the
    // family is marked open as a reload leaves it.
    lab.mgr
        .bfd_coupling
        .as_mut()
        .unwrap()
        .opened
        .sessions
        .extend(crate::bfd_runtime::dynamic_range_socket_probes(&with_bfd).unwrap());
    lab.mgr.adopt_config_snapshot(with_bfd).await;
    assert!(lab.member(MEMBER).is_some());
    assert!(matches!(
        lab.mgr.dynamic_bfd_admission(&accepted, OTHER),
        Ok(Some(_))
    ));
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
