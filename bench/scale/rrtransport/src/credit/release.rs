//! Report-only selection releases with continuously reading loopback receivers.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cell {
    Mixed,
    Timer,
    Single(Family),
}

impl Cell {
    fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "release-mixed" => Self::Mixed,
            "release-timer" => Self::Timer,
            "release-vpn4" => Self::Single(Family::Vpn),
            "release-vpn6" => Self::Single(Family::Vpn6),
            "release-labeled4" => Self::Single(Family::Labeled4),
            "release-labeled6" => Self::Single(Family::Labeled6),
            _ => bail!("unknown release cell {name}"),
        })
    }
}

const RECEIVERS: usize = 2;
const FLIPS: &str = "bgp_rib_outbound_owing_flips_total";

pub(super) async fn barrier(rib: &mpsc::Sender<RibUpdate>) -> Result<()> {
    let (reply, count) = oneshot::channel();
    rib.send(RibUpdate::QueryLocRibCount { reply }).await?;
    count.await?;
    Ok(())
}

pub(super) fn family_metric(
    snapshot: &Snapshot,
    metric: &str,
    family: Family,
    reason: Option<&str>,
) -> f64 {
    let (afi, safi) = family.afi_safi();
    let label = rustbgpd_wire::family_label(afi, safi).expect("fixture family");
    snapshot
        .series(metric)
        .into_iter()
        .flatten()
        .filter_map(|(labels, value)| {
            (labels.get("family")?.as_str() == label
                && labels.get("reason").map(String::as_str) == reason)
                .then_some(value)
        })
        .fold(0.0, |sum, value| sum + value)
}

// Read both families from the same receiver. Keep reading through a quiet
// interval after convergence so an extra marker or late row stays observable.
async fn collect(
    mut rx: mpsc::Receiver<Message>,
    families: Vec<Family>,
    reference: Arc<Reference>,
) -> Vec<(Family, WireState)> {
    let mut states: Vec<_> = families
        .into_iter()
        .map(|family| {
            (
                family,
                WireState::with_reference(
                    family.wire().expect("fixture family"),
                    Arc::clone(&reference),
                ),
            )
        })
        .collect();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut until = deadline;
    while let Ok(message) = tokio::time::timeout_at(until, rx.recv()).await {
        let Some(message) = message else {
            for (_, state) in &mut states {
                state.closed();
            }
            break;
        };
        for (family, state) in &mut states {
            // Body NLRI belongs to the unicast observer on this mixed session.
            // Keep all MP attributes together, including EVPN announcements and markers.
            let mp_only;
            let message = match (&message, family) {
                (Message::Update(update), Family::Evpn) => {
                    mp_only = Message::Update(rustbgpd_wire::UpdateMessage {
                        withdrawn_routes: Default::default(),
                        nlri: Default::default(),
                        path_attributes: update.path_attributes.clone(),
                    });
                    &mp_only
                }
                _ => &message,
            };
            state.apply(message, Instant::now());
        }
        if states.iter().all(|(_, state)| state.exact()) {
            until = deadline.min(tokio::time::Instant::now() + QUIET);
        }
    }
    states
}

pub async fn run(name: &str, output: &Path, options: &Options) -> Result<bool> {
    let cell = Cell::parse(name)?;
    ensure!(
        options.pause.is_none() && options.seconds.is_none(),
        "these release cells take --reduced or --correctness-only"
    );
    let timer = cell == Cell::Timer;
    let (timeout, reason) = if timer { (6, "timer") } else { (60, "all_eor") };
    let families = match cell {
        Cell::Mixed => vec![Family::Unicast, Family::Evpn],
        Cell::Timer => vec![Family::Unicast],
        Cell::Single(family) => vec![family],
    };
    let rows = if options.reduced { 16 } else { 64 };
    let negotiated: Vec<_> = families.iter().map(|family| family.afi_safi()).collect();
    let earliest_expiry = Instant::now() + Duration::from_secs(timeout);
    let mut fixture = Fixture::start(
        options,
        Some(SelectionDeferralConfig {
            timeout: Duration::from_secs(timeout),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: PeerId::from_ipv4(SOURCE).into(),
                families: negotiated.clone(),
            }],
        }),
    );
    // Include setup and actor queries in the timeout. A stuck registration
    // still releases every transport session before this command returns.
    let sampling = MemorySampling::start(fixture.metrics.clone());
    let observe = async {
        fixture
            .sources
            .push(source_up(&fixture.rib, SOURCE, negotiated.clone()).await?);
        let policy = (cell != Cell::Mixed).then(private_unicast_policy);
        fixture
            .connect(
                vec![(negotiated, policy); RECEIVERS],
                Duration::from_secs(15),
            )
            .await?;
        let reference = Arc::new(Reference::uniform(rows, BURST_VERSION));
        let mut collectors = tokio::task::JoinSet::new();
        let mut groups = BTreeMap::new();
        for receiver in &mut fixture.receivers {
            let rx = receiver.rx.take().expect("receiver stream");
            let readers = families.clone();
            let reference = Arc::clone(&reference);
            let ip = receiver.ip;
            collectors.spawn(async move { (ip, collect(rx, readers, reference).await) });
            // FSM establishment can precede RIB registration.
            loop {
                let (reply, accepted) = oneshot::channel();
                fixture
                    .rib
                    .send(RibUpdate::QueryPeerUpdateGroup {
                        peer: PeerId::from_ipv4(ip),
                        reply,
                    })
                    .await?;
                let group = accepted.await?;
                if !group.is_empty() {
                    groups.insert(ip, group);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        for &family in &families {
            fixture
                .rib
                .send(release_source_update(family, 0..rows))
                .await?;
        }
        barrier(&fixture.rib).await?;
        let before = Snapshot::take(&fixture.metrics);
        let t0 = Instant::now();
        let mut flips = Vec::new();
        let mut triggers = BTreeMap::new();
        if !timer {
            let mut previous = before.total(FLIPS);
            for family in &families {
                let (afi, safi) = family.afi_safi();
                triggers.insert(family.name(), Instant::now());
                fixture
                    .rib
                    .send(RibUpdate::EndOfRib {
                        peer: PeerId::from_ipv4(SOURCE),
                        session_id: 1,
                        afi,
                        safi,
                    })
                    .await?;
                barrier(&fixture.rib).await?;
                if cell == Cell::Mixed {
                    let current = Snapshot::take(&fixture.metrics).total(FLIPS);
                    flips.push(current.zip(previous).map(|(end, start)| end - start));
                    previous = current;
                }
            }
        } else {
            triggers.insert(Family::Unicast.name(), earliest_expiry);
        }
        let mut markers_after_trigger = true;
        let mut exact = true;
        let mut ordered = true;
        let mut no_resets = true;
        let mut markers = Vec::new();
        let mut receivers = BTreeMap::new();
        while let Some(result) = collectors.join_next().await {
            let (ip, states) = result?;
            let mut wire = BTreeMap::new();
            for (family, state) in states {
                exact &=
                    state.exact() && (!matches!(cell, Cell::Single(_)) || state.withdrawals == 0);
                ordered &= Trigger::Restart.eor_ordered(&state);
                no_resets &= state.resets == 0;
                let eor_ms = state
                    .eor_at
                    .and_then(|eor| eor.checked_duration_since(t0))
                    .map(|elapsed| elapsed.as_secs_f64() * 1000.0);
                let trigger_ms = state
                    .eor_at
                    .and_then(|eor| eor.checked_duration_since(triggers[family.name()]))
                    .map(|duration| duration.as_secs_f64() * 1_000.0);
                markers_after_trigger &= trigger_ms.is_some();
                markers.push(eor_ms);
                wire.insert(
                    family.name(),
                    json!({
                        "eors": state.eors,
                        "missing": state.missing(),
                        "announced": state.announced,
                        "withdrawals": state.withdrawals,
                        "before_eor": state.routes_before_eor,
                        "after_eor": state.routes_after_eor,
                        "decode_failures": state.decode_failures,
                        "outside": state.outside,
                        "resets": state.resets,
                        "eor_ms": eor_ms,
                        "since_trigger_ms": trigger_ms,
                    }),
                );
            }
            receivers.insert(ip.to_string(), wire);
        }
        let after = Snapshot::take(&fixture.metrics);
        let mut released = true;
        let mut armed = true;
        let mut observations = BTreeMap::new();
        for &family in &families {
            let active = family_metric(&before, "bgp_selection_deferral_active", family, None);
            let waiters = family_metric(&before, "bgp_selection_deferral_waiters", family, None);
            let releases = family_metric(
                &after,
                "bgp_selection_deferral_releases_total",
                family,
                Some(reason),
            );
            let timeouts = family_metric(
                &after,
                "bgp_selection_deferral_timeouts_total",
                family,
                None,
            );
            armed &= active == 1.0 && waiters == 1.0;
            released &= releases == 1.0 && timeouts == f64::from(timer);
            observations.insert(
                family.name(),
                json!({
                    "active_before": active,
                    "waiters_before": waiters,
                    "expected_reason": reason,
                    "releases_with_expected_reason": releases,
                    "timeouts": timeouts,
                }),
            );
        }
        let ownership = if cell == Cell::Mixed {
            let first = &groups[&receiver_ip(0)];
            first.starts_with("group:")
                && groups.values().all(|group| group == first)
                && flips == [Some(0.0), Some(RECEIVERS as f64)]
        } else {
            groups.values().all(|group| group == "policy_peer_context")
        };
        let release_ms = markers
            .iter()
            .all(Option::is_some)
            .then(|| markers.into_iter().flatten().fold(0.0, f64::max));
        Ok::<_, anyhow::Error>(json!({
            "cell": name,
            "report_only": true,
            "rows_per_family": rows,
            "reduced": options.reduced,
            "mode": if options.correctness_only { "correctness" } else { "measured" },
            "selection_timeout_secs": timeout,
            "release_ms": release_ms,
            "groups": groups,
            "mixed_release_owing_flip_deltas": flips,
            "families": observations,
            "receivers": receivers,
            "checks": {
                "armed_after_staging": armed,
                "release_reason": released,
                "ownership": ownership,
                "wire_exact": exact,
                "eor_order": ordered,
                "all_markers_after_trigger": markers_after_trigger,
                "sessions_established": no_resets && fixture.not_established().await.is_empty(),
            }
        }))
    };
    let observation = tokio::time::timeout(Duration::from_secs(45), observe).await;
    let memory = sampling.finish().await;
    fixture.close().await?;
    let mut report = observation.context("release observation timed out")??;
    report["memory"] = memory?;
    write_result(output, &format!("{name}.json"), &report)?;
    Ok(recorded_pass(&report))
}
