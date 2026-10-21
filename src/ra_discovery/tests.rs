use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use super::engine::{
    DiscoveryConfig, DiscoveryEvent, Endpoint, Engine, LIFETIME_ZERO_HOLD, LinkEvent, LinkState,
    MAX_CANDIDATES_PER_INTERFACE, MAX_RA_INTERVAL_SECS, MIN_RA_INTERVAL_SECS, RaTiming, Transmit,
};
use super::packet::DropReason;

const IF: &str = "swp1";
const IDX: u32 = 7;

fn ll(n: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n)
}

fn ep(n: u16) -> Endpoint {
    Endpoint {
        address: ll(n),
        ifindex: IDX,
    }
}

fn not_own(_: &str, _: Ipv6Addr) -> bool {
    false
}

fn link(state: LinkState, ifindex: u32) -> LinkEvent {
    LinkEvent {
        ifindex,
        name: IF.to_owned(),
        state,
    }
}

fn engine(send: bool, now: Instant) -> Engine {
    let mut e = Engine::new(
        DiscoveryConfig {
            send,
            timing: RaTiming::default(),
        },
        42,
    );
    e.start(IF);
    e.on_link(&link(LinkState::Up, IDX), now);
    e.events.clear();
    e.transmits.clear();
    e
}

/// The link generation of `IF`'s current socket (0 while confirmed down).
fn generation(e: &Engine) -> u64 {
    e.bound_interfaces().next().map_or(0, |(_, _, g)| g)
}

fn ra(e: &mut Engine, n: u16, lifetime: u16, now: Instant) -> Result<(), DropReason> {
    let g = generation(e);
    e.on_router_advertisement(IDX, g, ll(n), lifetime, now, not_own)
}

fn bindings(e: &mut Engine) -> Vec<(Option<Endpoint>, Option<Endpoint>)> {
    e.events
        .drain(..)
        .filter_map(|ev| match ev {
            DiscoveryEvent::BindingChanged {
                previous, current, ..
            } => Some((previous, current)),
            _ => None,
        })
        .collect()
}

#[test]
fn own_address_ra_is_rejected() {
    let t0 = Instant::now();
    let mut e = engine(true, t0);
    let mut asked = Vec::new();
    let g = generation(&e);
    let result = e.on_router_advertisement(IDX, g, ll(1), 30, t0, |name, src| {
        asked.push((name.to_owned(), src));
        true
    });
    assert_eq!(result, Err(DropReason::OwnAddress));
    assert_eq!(asked, vec![(IF.to_owned(), ll(1))]);
    assert_eq!(e.events, vec![], "own RA must not become a candidate");
    assert_eq!(
        e.next_deadline(),
        Some(t0),
        "only the pending RA, no expiry"
    );
}

#[test]
fn candidate_that_becomes_a_local_address_is_dropped_on_refresh() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    ra(&mut e, 1, 30, t0).unwrap();
    ra(&mut e, 2, 30, t0).unwrap();
    e.events.clear();
    // fe80::1 is now assigned to the interface (a local radvd, say).
    let g = generation(&e);
    let t1 = t0 + Duration::from_secs(5);
    assert_eq!(
        e.on_router_advertisement(IDX, g, ll(1), 30, t1, |_, src| src == ll(1)),
        Err(DropReason::OwnAddress)
    );
    assert_eq!(
        e.events,
        vec![
            DiscoveryEvent::CandidateExpired {
                interface: IF.into(),
                address: ll(1)
            },
            DiscoveryEvent::BindingChanged {
                interface: IF.into(),
                previous: Some(ep(1)),
                current: Some(ep(2))
            },
        ]
    );
    // Further RAs from it are dropped, not refreshed or relearned.
    e.events.clear();
    assert_eq!(
        e.on_router_advertisement(IDX, g, ll(1), 30, t1, |_, src| src == ll(1)),
        Err(DropReason::OwnAddress)
    );
    assert_eq!(e.events, vec![]);
}

#[test]
fn first_source_binds_and_second_is_a_sticky_conflict() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    ra(&mut e, 5, 30, t0).unwrap();
    assert_eq!(
        e.events,
        vec![
            DiscoveryEvent::CandidateLearned {
                interface: IF.into(),
                address: ll(5)
            },
            DiscoveryEvent::BindingChanged {
                interface: IF.into(),
                previous: None,
                current: Some(ep(5))
            },
        ]
    );
    e.events.clear();
    // A lower address arriving later does not take over a live binding.
    ra(&mut e, 1, 30, t0).unwrap();
    assert_eq!(
        e.events,
        vec![
            DiscoveryEvent::CandidateLearned {
                interface: IF.into(),
                address: ll(1)
            },
            DiscoveryEvent::Conflict {
                interface: IF.into(),
                bound: ll(5),
                other: ll(1)
            },
        ]
    );
    e.events.clear();
    // Refreshing either source reports nothing again.
    ra(&mut e, 1, 30, t0 + Duration::from_secs(1)).unwrap();
    ra(&mut e, 5, 30, t0 + Duration::from_secs(1)).unwrap();
    assert_eq!(e.events, vec![]);
}

#[test]
fn forced_rebind_picks_lowest_live_whatever_the_arrival_order() {
    let orders: [[u16; 3]; 6] = [
        [3, 1, 2],
        [3, 2, 1],
        [1, 3, 2],
        [2, 1, 3],
        [1, 2, 3],
        [2, 3, 1],
    ];
    for order in orders {
        let t0 = Instant::now();
        let mut e = engine(false, t0);
        // fe80::9 binds first and expires first.
        ra(&mut e, 9, 10, t0).unwrap();
        for n in order {
            ra(&mut e, n, 60, t0).unwrap();
        }
        e.events.clear();
        e.poll(t0 + Duration::from_secs(10));
        assert_eq!(
            bindings(&mut e),
            vec![(Some(ep(9)), Some(ep(1)))],
            "order {order:?}"
        );
    }
}

#[test]
fn candidate_expires_at_router_lifetime_and_refresh_extends_it() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    ra(&mut e, 1, 30, t0).unwrap();
    e.events.clear();
    e.poll(t0 + Duration::from_millis(29_999));
    assert_eq!(e.events, vec![]);
    ra(&mut e, 1, 30, t0 + Duration::from_secs(20)).unwrap();
    e.poll(t0 + Duration::from_secs(49));
    assert_eq!(e.events, vec![], "refresh moved expiry to t0+50s");
    assert_eq!(e.next_deadline(), Some(t0 + Duration::from_secs(50)));
    e.poll(t0 + Duration::from_secs(50));
    assert_eq!(
        e.events,
        vec![
            DiscoveryEvent::CandidateExpired {
                interface: IF.into(),
                address: ll(1)
            },
            DiscoveryEvent::BindingChanged {
                interface: IF.into(),
                previous: Some(ep(1)),
                current: None
            },
        ]
    );
}

#[test]
fn lifetime_zero_is_held_for_thirty_seconds() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    ra(&mut e, 1, 0, t0).unwrap();
    assert_eq!(bindings(&mut e), vec![(None, Some(ep(1)))]);
    assert_eq!(LIFETIME_ZERO_HOLD, Duration::from_secs(30));
    e.poll(t0 + Duration::from_millis(29_999));
    assert_eq!(
        e.events,
        vec![],
        "lifetime 0 is not an immediate withdrawal"
    );
    e.poll(t0 + LIFETIME_ZERO_HOLD);
    assert_eq!(bindings(&mut e), vec![(Some(ep(1)), None)]);
}

#[test]
fn discovery_never_moves_an_established_binding() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    ra(&mut e, 5, 10, t0).unwrap();
    e.session_established(IF);
    e.events.clear();
    ra(&mut e, 1, 60, t0).unwrap();
    e.poll(t0 + Duration::from_secs(10));
    // The bound source expired and a lower live one exists: still no move.
    let events = std::mem::take(&mut e.events);
    assert!(events.contains(&DiscoveryEvent::Conflict {
        interface: IF.into(),
        bound: ll(5),
        other: ll(1)
    }));
    assert!(events.contains(&DiscoveryEvent::CandidateExpired {
        interface: IF.into(),
        address: ll(5)
    }));
    assert!(
        !events
            .iter()
            .any(|ev| matches!(ev, DiscoveryEvent::BindingChanged { .. })),
        "{events:?}"
    );
    // Only the explicit session-failed input releases it.
    e.session_failed(IF);
    assert_eq!(bindings(&mut e), vec![(Some(ep(5)), Some(ep(1)))]);
}

#[test]
fn established_binding_with_no_replacement_unbinds_only_after_failure() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    ra(&mut e, 5, 10, t0).unwrap();
    e.session_established(IF);
    e.events.clear();
    e.poll(t0 + Duration::from_secs(10));
    assert_eq!(bindings(&mut e), vec![]);
    // The bound source comes back while Established: no conflict, no move.
    ra(&mut e, 5, 10, t0 + Duration::from_secs(11)).unwrap();
    assert!(
        !e.events
            .iter()
            .any(|ev| matches!(ev, DiscoveryEvent::Conflict { .. }))
    );
    e.poll(t0 + Duration::from_secs(21));
    e.session_failed(IF);
    assert_eq!(bindings(&mut e), vec![(Some(ep(5)), None)]);
}

#[test]
fn session_failure_keeps_a_live_binding() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    ra(&mut e, 5, 30, t0).unwrap();
    ra(&mut e, 1, 30, t0).unwrap();
    e.session_established(IF);
    e.session_failed(IF);
    assert_eq!(
        bindings(&mut e),
        vec![(None, Some(ep(5)))],
        "only the first bind"
    );
}

#[test]
fn unknown_link_state_clears_nothing() {
    let t0 = Instant::now();
    let mut e = engine(true, t0);
    ra(&mut e, 1, 30, t0).unwrap();
    e.session_established(IF);
    e.events.clear();
    e.on_link(&link(LinkState::Unknown, IDX), t0);
    e.on_link(&link(LinkState::Unknown, IDX + 1), t0);
    assert_eq!(e.events, vec![]);
    assert_eq!(e.transmits, vec![]);
    // Still bound on the original ifindex and still Established.
    e.poll(t0 + Duration::from_secs(30));
    assert_eq!(bindings(&mut e), vec![]);
    e.session_failed(IF);
    assert_eq!(bindings(&mut e), vec![(Some(ep(1)), None)]);
}

#[test]
fn carrier_down_and_removal_clear_candidates_and_binding() {
    for state in [LinkState::Down, LinkState::Removed] {
        let t0 = Instant::now();
        let mut e = engine(false, t0);
        ra(&mut e, 1, 30, t0).unwrap();
        ra(&mut e, 2, 30, t0).unwrap();
        e.session_established(IF);
        e.events.clear();
        e.on_link(&link(state, IDX), t0);
        assert_eq!(
            e.events,
            vec![
                DiscoveryEvent::CandidateExpired {
                    interface: IF.into(),
                    address: ll(1)
                },
                DiscoveryEvent::CandidateExpired {
                    interface: IF.into(),
                    address: ll(2)
                },
                DiscoveryEvent::BindingChanged {
                    interface: IF.into(),
                    previous: Some(ep(1)),
                    current: None
                },
            ],
            "{state:?}"
        );
        assert_eq!(e.next_deadline(), None);
        // Confirmed down ended the session: the next RA binds immediately.
        e.events.clear();
        e.on_link(&link(LinkState::Up, IDX), t0);
        ra(&mut e, 2, 30, t0).unwrap();
        assert_eq!(bindings(&mut e), vec![(None, Some(ep(2)))], "{state:?}");
    }
}

#[test]
fn recreated_interface_starts_fresh_on_the_new_ifindex() {
    let t0 = Instant::now();
    let mut e = engine(true, t0);
    ra(&mut e, 1, 30, t0).unwrap();
    e.events.clear();
    e.on_link(&link(LinkState::Up, IDX + 1), t0);
    assert_eq!(bindings(&mut e), vec![(Some(ep(1)), None)]);
    assert!(
        e.transmits
            .contains(&Transmit::RouterSolicitation { ifindex: IDX + 1 }),
        "a recreated link is a link-up"
    );
    // Late RAs read from the old socket are ignored.
    ra(&mut e, 3, 30, t0).unwrap();
    assert_eq!(e.events, vec![]);
    let g = generation(&e);
    e.on_router_advertisement(IDX + 1, g, ll(1), 30, t0, not_own)
        .unwrap();
    let new = Some(Endpoint {
        address: ll(1),
        ifindex: IDX + 1,
    });
    assert_eq!(bindings(&mut e), vec![(None, new)]);
    assert_eq!(
        e.bound_interfaces()
            .map(|(n, i, _)| (n, i))
            .collect::<Vec<_>>(),
        vec![(IF, IDX + 1)]
    );
}

#[test]
fn ra_queued_before_carrier_loss_does_not_bind_after_it() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    // Read off the socket before the loss, processed after it.
    let queued = generation(&e);
    e.on_link(&link(LinkState::Down, IDX), t0);
    assert_eq!(e.bound_interfaces().count(), 0, "socket closes while down");
    assert_eq!(
        e.on_router_advertisement(IDX, queued, ll(1), 30, t0, not_own),
        Err(DropReason::StaleLink)
    );
    assert_eq!(e.events, vec![]);
    assert_eq!(e.next_deadline(), None, "no candidate was recorded");
}

#[test]
fn ra_from_a_previous_link_generation_is_discarded_after_down_up() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    let old = generation(&e);
    ra(&mut e, 1, 30, t0).unwrap();
    e.on_link(&link(LinkState::Down, IDX), t0);
    e.on_link(&link(LinkState::Up, IDX), t0);
    let new = generation(&e);
    assert_ne!(old, new, "Down->Up starts a new generation");
    e.events.clear();
    assert_eq!(
        e.on_router_advertisement(IDX, old, ll(1), 30, t0, not_own),
        Err(DropReason::StaleLink)
    );
    assert_eq!(e.events, vec![], "stale state is not restored");
    e.on_router_advertisement(IDX, new, ll(2), 30, t0, not_own)
        .unwrap();
    assert_eq!(bindings(&mut e), vec![(None, Some(ep(2)))]);
    // Unknown and a repeated Up keep the generation.
    e.on_link(&link(LinkState::Unknown, IDX), t0);
    e.on_link(&link(LinkState::Up, IDX), t0);
    assert_eq!(generation(&e), new);
}

#[test]
fn candidate_table_is_bounded() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    for n in 1..=u16::try_from(MAX_CANDIDATES_PER_INTERFACE).unwrap() {
        ra(&mut e, n, 30, t0).unwrap();
    }
    assert_eq!(ra(&mut e, 999, 30, t0), Err(DropReason::CandidateLimit));
    // Known sources still refresh.
    assert_eq!(ra(&mut e, 1, 30, t0), Ok(()));
}

#[test]
fn router_lifetime_and_interval_bounds() {
    assert!(RaTiming::new(MIN_RA_INTERVAL_SECS - 1).is_err());
    assert!(RaTiming::new(MAX_RA_INTERVAL_SECS + 1).is_err());
    assert!(RaTiming::new(0).is_err());
    let default = RaTiming::default();
    assert_eq!(default, RaTiming::new(10).unwrap());
    assert_eq!(default.router_lifetime_secs(), 30);
    assert_eq!(default.min_interval(), Duration::from_millis(3300));
    assert_eq!(
        RaTiming::new(4).unwrap().min_interval(),
        Duration::from_secs(3)
    );
    for secs in MIN_RA_INTERVAL_SECS..=MAX_RA_INTERVAL_SECS {
        let t = RaTiming::new(secs).unwrap();
        let max = t.max_interval();
        let lifetime = Duration::from_secs(u64::from(t.router_lifetime_secs()));
        // RFC 4861 §6.2.1: MinRtrAdvInterval in 3 s..=0.75 x Max,
        // AdvDefaultLifetime in Max..=9000 s.
        assert!(t.min_interval() >= Duration::from_secs(3), "{secs}");
        assert!(t.min_interval() <= max * 3 / 4, "{secs}");
        assert_eq!(lifetime, max * 3, "{secs}");
        assert!(lifetime >= max && lifetime.as_secs() <= 9000);
    }
}

/// Drive the engine to `until`, returning (time, transmit) pairs.
fn run_until(e: &mut Engine, until: Instant) -> Vec<(Instant, Transmit)> {
    let mut sent = Vec::new();
    while let Some(at) = e.next_deadline().filter(|at| *at <= until) {
        e.poll(at);
        sent.extend(e.transmits.drain(..).map(|t| (at, t)));
    }
    sent
}

#[test]
fn link_up_sends_rs_then_randomized_ras_within_bounds() {
    let t0 = Instant::now();
    let timing = RaTiming::new(30).unwrap();
    let mut e = Engine::new(DiscoveryConfig { send: true, timing }, 7);
    e.start(IF);
    e.on_link(&link(LinkState::Up, IDX), t0);
    assert_eq!(
        std::mem::take(&mut e.transmits),
        vec![Transmit::RouterSolicitation { ifindex: IDX }]
    );
    let sent = run_until(&mut e, t0 + Duration::from_secs(3600));
    assert!(sent.len() > 100);
    assert_eq!(sent[0].0, t0, "first RA right at link-up");
    for (_, t) in &sent {
        assert_eq!(
            *t,
            Transmit::RouterAdvertisement {
                ifindex: IDX,
                router_lifetime_secs: 90
            }
        );
    }
    let gaps: Vec<Duration> = sent.windows(2).map(|w| w[1].0 - w[0].0).collect();
    for gap in &gaps[3..] {
        assert!(*gap >= timing.min_interval() && *gap <= timing.max_interval());
    }
    // RFC 4861 §6.2.4: the first three intervals are capped at 16 s.
    assert!(gaps[..3].iter().all(|g| *g <= Duration::from_secs(16)));
    // Randomized, not fixed.
    assert!(gaps.iter().any(|g| *g != gaps[3]));
}

#[test]
fn sending_opt_out_sends_nothing_but_still_receives() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    e.on_link(&link(LinkState::Down, IDX), t0);
    e.on_link(&link(LinkState::Up, IDX), t0);
    let g = generation(&e);
    e.on_router_solicitation(IDX, g, t0);
    assert_eq!(run_until(&mut e, t0 + Duration::from_secs(600)), vec![]);
    ra(&mut e, 1, 30, t0).unwrap();
    assert_eq!(bindings(&mut e), vec![(None, Some(ep(1)))]);
    e.stop(IF);
    assert_eq!(e.transmits, vec![], "no final RA when not advertising");
}

#[test]
fn router_solicitation_is_answered_within_half_a_second_but_rate_limited() {
    let t0 = Instant::now();
    let mut e = engine(true, t0);
    // The link-up RA goes at t0.
    assert_eq!(run_until(&mut e, t0).len(), 1);
    let t1 = t0 + Duration::from_secs(5);
    let g = generation(&e);
    e.on_router_solicitation(IDX, g, t1);
    let answer = e.next_deadline().unwrap();
    assert!(answer >= t1 && answer <= t1 + Duration::from_millis(500));
    assert_eq!(run_until(&mut e, answer).len(), 1);
    // A second RS right after: no RA sooner than 3 s after the last one.
    let g = generation(&e);
    e.on_router_solicitation(IDX, g, answer);
    assert!(e.next_deadline().unwrap() >= answer + Duration::from_secs(3));
}

#[test]
fn stop_sends_a_final_lifetime_zero_ra() {
    let t0 = Instant::now();
    let mut e = engine(true, t0);
    e.stop(IF);
    assert_eq!(
        e.transmits,
        vec![Transmit::RouterAdvertisement {
            ifindex: IDX,
            router_lifetime_secs: 0
        }]
    );
    assert_eq!(e.bound_interfaces().count(), 0);
}

#[test]
fn ra_on_an_unstarted_interface_is_ignored() {
    let t0 = Instant::now();
    let mut e = engine(false, t0);
    e.on_router_advertisement(IDX + 9, 1, ll(1), 30, t0, not_own)
        .unwrap();
    assert_eq!(e.events, vec![]);
}

/// Privileged: two network namespaces joined by a veth pair, one discovery
/// actor in each. Run through
/// `crates/evpn-linux/tests/docker/run-netns-tests.sh ra_discovery`.
#[cfg(target_os = "linux")]
mod netns {
    use std::net::Ipv6Addr;
    use std::process::Command;
    use std::time::Duration;

    use nix::sched::{CloneFlags, setns};
    use tokio::sync::{mpsc, oneshot};

    use super::super::{
        DiscoveryConfig, DiscoveryEvent, Endpoint, LinkEvent, LinkState, RaDiscovery, RaTiming,
    };

    const IF_A: &str = "rdisa";
    const IF_B: &str = "rdisb";
    const WAIT: Duration = Duration::from_secs(15);

    fn addr_a() -> Ipv6Addr {
        "fe80::a".parse().unwrap()
    }

    fn addr_b() -> Ipv6Addr {
        "fe80::b".parse().unwrap()
    }

    fn run(args: &[&str]) {
        let out = Command::new("ip").args(args).output().expect("spawn ip");
        assert!(
            out.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    struct Netns(String);

    impl Netns {
        fn create(tag: &str) -> Self {
            let name = format!("rustbgpd-ra-{tag}-{}", std::process::id());
            let _ = Command::new("ip").args(["netns", "delete", &name]).output();
            run(&["netns", "add", &name]);
            Self(name)
        }
    }

    impl Drop for Netns {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["netns", "delete", &self.0])
                .output();
        }
    }

    /// A veth pair with only the fixed link-local addresses (no EUI-64, no
    /// DAD), so the assertions can name them.
    fn create_veth(a: &Netns, b: &Netns) {
        run(&["link", "add", IF_A, "type", "veth", "peer", "name", IF_B]);
        for (ns, ifname, addr) in [(a, IF_A, "fe80::a/64"), (b, IF_B, "fe80::b/64")] {
            run(&["link", "set", ifname, "netns", &ns.0]);
            run(&["-n", &ns.0, "link", "set", ifname, "addrgenmode", "none"]);
            run(&["-n", &ns.0, "addr", "add", addr, "dev", ifname, "nodad"]);
            run(&["-n", &ns.0, "link", "set", ifname, "up"]);
        }
    }

    /// What a link monitor would report: ifindex and carrier from the kernel.
    fn link_event(ns: &Netns, ifname: &str) -> LinkEvent {
        let out = Command::new("ip")
            .args(["-j", "-n", &ns.0, "link", "show", "dev", ifname])
            .output()
            .expect("spawn ip");
        assert!(out.status.success(), "{ifname} missing in {}", ns.0);
        let links: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let link = &links[0];
        let lower_up = link["flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "LOWER_UP");
        LinkEvent {
            ifindex: u32::try_from(link["ifindex"].as_u64().unwrap()).unwrap(),
            name: ifname.to_owned(),
            state: if lower_up {
                LinkState::Up
            } else {
                LinkState::Down
            },
        }
    }

    /// Carrier on a veth follows its peer asynchronously: wait for it.
    async fn wait_state(ns: &Netns, ifname: &str, want: LinkState) -> LinkEvent {
        for _ in 0..100 {
            let event = link_event(ns, ifname);
            if event.state == want {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{ifname} in {} never reported {want:?}", ns.0);
    }

    async fn up_event(ns: &Netns, ifname: &str) -> LinkEvent {
        wait_state(ns, ifname, LinkState::Up).await
    }

    struct Side {
        discovery: Option<RaDiscovery>,
        events: mpsc::UnboundedReceiver<DiscoveryEvent>,
        seen: Vec<DiscoveryEvent>,
        stop: Option<oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Side {
        /// Run an actor on a thread inside `ns`, so its sockets live there.
        fn spawn(ns: &Netns) -> Self {
            let path = format!("/run/netns/{}", ns.0);
            let (tx, rx) = std::sync::mpsc::channel();
            let (stop, stop_rx) = oneshot::channel::<()>();
            let thread = std::thread::spawn(move || {
                let file = std::fs::File::open(path).unwrap();
                setns(&file, CloneFlags::CLONE_NEWNET).unwrap();
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async move {
                    let config = DiscoveryConfig {
                        send: true,
                        timing: RaTiming::new(4).unwrap(),
                    };
                    tx.send(RaDiscovery::spawn(config)).unwrap();
                    let _ = stop_rx.await;
                });
            });
            let (discovery, events) = rx.recv().unwrap().expect("CAP_NET_RAW in the harness");
            Self {
                discovery: Some(discovery),
                events,
                seen: Vec::new(),
                stop: Some(stop),
                thread: Some(thread),
            }
        }

        fn d(&self) -> &RaDiscovery {
            self.discovery.as_ref().unwrap()
        }

        async fn wait_binding(&mut self, want: Option<Endpoint>) {
            let found = tokio::time::timeout(WAIT, async {
                while let Some(event) = self.events.recv().await {
                    self.seen.push(event.clone());
                    if let DiscoveryEvent::BindingChanged { current, .. } = event
                        && current == want
                    {
                        return;
                    }
                }
            })
            .await;
            assert!(found.is_ok(), "no binding to {want:?}; saw {:?}", self.seen);
        }

        async fn shutdown(&mut self) {
            self.discovery.take().unwrap().shutdown().await;
            let _ = self.stop.take().unwrap().send(());
            self.thread.take().unwrap().join().unwrap();
        }
    }

    #[test]
    fn veth_peers_discover_each_other_follow_carrier_and_recreation() {
        if std::env::var("EVPN_LINUX_NETNS").as_deref() != Ok("1") {
            eprintln!("skipping: set EVPN_LINUX_NETNS=1 (privileged netns harness)");
            return;
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let ns_a = Netns::create("a");
            let ns_b = Netns::create("b");
            create_veth(&ns_a, &ns_b);
            let mut a = Side::spawn(&ns_a);
            let mut b = Side::spawn(&ns_b);

            // 1. Each side learns the other's link-local address.
            let ev_a = up_event(&ns_a, IF_A).await;
            let ev_b = up_event(&ns_b, IF_B).await;
            assert_eq!(ev_a.state, LinkState::Up);
            let (idx_a, idx_b) = (ev_a.ifindex, ev_b.ifindex);
            a.d().start(IF_A);
            b.d().start(IF_B);
            a.d().link_event(ev_a);
            b.d().link_event(ev_b);
            a.wait_binding(Some(Endpoint {
                address: addr_b(),
                ifindex: idx_a,
            }))
            .await;
            b.wait_binding(Some(Endpoint {
                address: addr_a(),
                ifindex: idx_b,
            }))
            .await;

            // 2. Carrier loss: B's end goes admin-down, A's carrier drops.
            run(&["-n", &ns_b.0, "link", "set", IF_B, "down"]);
            // The kernel reports carrier loss on A.
            a.d()
                .link_event(wait_state(&ns_a, IF_A, LinkState::Down).await);
            b.d()
                .link_event(wait_state(&ns_b, IF_B, LinkState::Down).await);
            a.wait_binding(None).await;
            assert!(a.seen.contains(&DiscoveryEvent::CandidateExpired {
                interface: IF_A.into(),
                address: addr_b()
            }));

            // Carrier returns: the link-up RS/RA rediscovers within seconds.
            // Admin down flushed B's address (keep_addr_on_down=0); restore it.
            run(&["-n", &ns_b.0, "link", "set", IF_B, "up"]);
            run(&[
                "-n",
                &ns_b.0,
                "addr",
                "replace",
                "fe80::b/64",
                "dev",
                IF_B,
                "nodad",
            ]);
            a.d().link_event(up_event(&ns_a, IF_A).await);
            b.d().link_event(up_event(&ns_b, IF_B).await);
            a.wait_binding(Some(Endpoint {
                address: addr_b(),
                ifindex: idx_a,
            }))
            .await;

            // 3. Recreation: the pair is deleted and rebuilt with new ifindexes.
            run(&["-n", &ns_a.0, "link", "del", IF_A]);
            for (side, ifname, idx) in [(&a, IF_A, idx_a), (&b, IF_B, idx_b)] {
                side.d().link_event(LinkEvent {
                    ifindex: idx,
                    name: ifname.into(),
                    state: LinkState::Removed,
                });
            }
            a.wait_binding(None).await;
            create_veth(&ns_a, &ns_b);
            let ev_a = up_event(&ns_a, IF_A).await;
            let ev_b = up_event(&ns_b, IF_B).await;
            let (new_a, new_b) = (ev_a.ifindex, ev_b.ifindex);
            assert_ne!(new_a, idx_a, "recreated interface has a new ifindex");
            a.d().link_event(ev_a);
            b.d().link_event(ev_b);
            a.wait_binding(Some(Endpoint {
                address: addr_b(),
                ifindex: new_a,
            }))
            .await;
            b.wait_binding(Some(Endpoint {
                address: addr_a(),
                ifindex: new_b,
            }))
            .await;

            // Own advertisements never became candidates on either side.
            for (side, own) in [(&a, addr_a()), (&b, addr_b())] {
                assert!(!side.seen.iter().any(|ev| matches!(ev,
                    DiscoveryEvent::CandidateLearned { address, .. } if *address == own)));
            }

            a.shutdown().await;
            b.shutdown().await;
        });
    }
}
