//! A GR source replays SAFI 4 while selection and receiver reads are held.
use super::*;

const REPLACEMENT: u64 = 2;
const RELEASE_HELPER: Ipv4Addr = Ipv4Addr::new(127, 254, 0, 3);
const SEQUENCE: u32 = 1;
const FLIPS: &str = "bgp_rib_outbound_owing_flips_total";

fn eor(source: Ipv4Addr, session_id: u64, family: Family) -> RibUpdate {
    let (afi, safi) = family.afi_safi();
    RibUpdate::EndOfRib {
        peer: PeerId::from_ipv4(source),
        session_id,
        afi,
        safi,
    }
}

// Enqueue the EoR and the real unrelated UPDATE between two polls of the same
// RIB future. The actor cannot finish the release before the probe is admitted.
pub(super) struct ReleaseProbe {
    family: Family,
    trigger: oneshot::Receiver<()>,
    admitted: oneshot::Sender<Result<(Instant, Instant)>>,
}

impl ReleaseProbe {
    pub(super) async fn run(self, manager: RibManager, rib: mpsc::Sender<RibUpdate>) {
        let mut actor = std::pin::pin!(manager.run());
        tokio::select! {
            () = &mut actor => return,
            trigger = self.trigger => {
                if trigger.is_ok() {
                    let update = churn_update(SEQUENCE);
                    let pair = (|| {
                        let release = Instant::now();
                        rib.try_send(eor(RELEASE_HELPER, 1, self.family))?;
                        let admission = Instant::now();
                        rib.try_send(update)?;
                        Ok((release, admission))
                    })();
                    let _ = self.admitted.send(pair);
                }
            }
        }
        drop(rib);
        actor.await;
    }
}

async fn replay(
    rib: &mpsc::Sender<RibUpdate>,
    family: Family,
    rows: usize,
    session_id: u64,
    med: u32,
) -> Result<()> {
    for start in (0..rows).step_by(CHUNK) {
        rib.send(labeled_source_update(
            family,
            start..(start + CHUNK).min(rows),
            session_id,
            med,
        ))
        .await?;
    }
    Ok(())
}

async fn received_table(rib: &mpsc::Sender<RibUpdate>) -> Result<(u64, bool)> {
    let (reply, result) = oneshot::channel();
    rib.send(RibUpdate::QueryLabeledRoutesPage {
        scope: rustbgpd_rib::update::RouteQueryScope::Received {
            peer: Some(PeerId::from_ipv4(SOURCE)),
        },
        filter: None,
        after: None,
        expected_version: None,
        page_size: 1,
        reply,
    })
    .await?;
    let table = result
        .await?
        .map_err(|e| anyhow::anyhow!("labeled input table: {e:?}"))?;
    Ok((
        table.total,
        table.routes.first().is_some_and(|r| r.is_stale),
    ))
}

// Observe the production lookup on the primary channel. Its reply time is an
// upper bound on installation, independent of the receiver's wire clock.
async fn matching_winner(rib: &mpsc::Sender<RibUpdate>) -> Result<Instant> {
    let prefix = Prefix::V4(Ipv4Prefix::new(CHURN_PREFIX, 24));
    loop {
        let (reply, result) = oneshot::channel();
        rib.send(RibUpdate::LookupBestPath { prefix, reply })
            .await?;
        if result
            .await?
            .and_then(|view| view.best)
            .is_some_and(|best| {
                best.prefix == prefix
                    && best.peer == PeerId::from_ipv4(CHURN_SOURCE)
                    && best.med() == SEQUENCE
            })
        {
            return Ok(Instant::now());
        }
        tokio::task::yield_now().await;
    }
}

// Keep the healthy stream open until every receiver has completed. Dropping
// it after the probe would close the stub reader on the next KEEPALIVE.
async fn healthy_wire(
    mut rx: mpsc::Receiver<Message>,
    mut stop: watch::Receiver<bool>,
) -> ChurnState {
    let mut state = ChurnState::default();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            msg = rx.recv() => match msg {
                Some(msg) => state.apply(&msg, Instant::now()),
                None => { state.resets += 1; break; }
            }
        }
    }
    state
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    Eor,
    Withdrawal,
}

async fn collect(
    mut rx: mpsc::Receiver<Message>,
    mut state: WireState,
    progress: mpsc::Sender<Progress>,
    mut stop: watch::Receiver<bool>,
) -> (WireState, bool) {
    let mut initial_exact = false;
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            msg = rx.recv() => {
                let Some(msg) = msg else { state.closed(); break };
                let first_eor = state.eors == 0;
                let first_withdrawal = state.withdrawals == 0;
                state.apply(&msg, Instant::now());
                if first_eor && state.eors == 1 {
                    initial_exact = state.exact() && !state.eor_premature && state.duplicates_before_eor == 0;
                    if initial_exact { state.expect_labeled_withdrawal(0); }
                    let _ = progress.send(Progress::Eor).await;
                }
                if first_withdrawal && state.withdrawals > 0 {
                    let _ = progress.send(Progress::Withdrawal).await;
                }
            }
        }
    }
    (state, initial_exact)
}

async fn wait_for_receivers(
    rx: &mut mpsc::Receiver<Progress>,
    count: usize,
    expected: Progress,
    until: tokio::time::Instant,
) -> bool {
    for _ in 0..count {
        let Ok(Some(event)) = tokio::time::timeout_at(until, rx.recv()).await else {
            return false;
        };
        if event != expected {
            return false;
        }
    }
    true
}

fn poll_count(metrics: &BgpMetrics) -> u64 {
    buckets(metrics, "bgp_rib_actor_slice_seconds", "stage")
        .get("actor_poll")
        .map_or(0, |(count, _)| *count)
}

pub async fn run(family: Family, output: &Path, options: &Options) -> Result<bool> {
    ensure!(
        matches!(family, Family::Labeled4 | Family::Labeled6) && options.seconds.is_none(),
        "labeled restart requires SAFI 4 and a fixed deadline"
    );
    let (receivers, rows, pause, cap) = if options.reduced {
        (
            4,
            4_096,
            Duration::from_millis(500),
            Duration::from_secs(120),
        )
    } else {
        (
            150,
            150_000,
            Trigger::Restart.pause(),
            Duration::from_secs(900),
        )
    };
    let pause = options.pause.unwrap_or(pause);
    check_read_hold(pause)?;
    let families = vec![family.afi_safi()];
    // The second waiter keeps the local startup hold active across the actual
    // source departure. The returning speaker sets Restart State, so only the
    // surviving helper can release local selection when it completes.
    let config = SelectionDeferralConfig {
        timeout: Duration::from_secs(3_600),
        waiters: [SOURCE, RELEASE_HELPER]
            .into_iter()
            .map(|ip| SelectionDeferralWaiterConfig {
                peer: PeerId::from_ipv4(ip).into(),
                families: families.clone(),
            })
            .collect(),
    };
    let (trigger, trigger_rx) = oneshot::channel();
    let (admitted, stamps) = oneshot::channel();
    let mut fixture = Fixture::start_with_probe(
        options,
        Some(config),
        Some(ReleaseProbe {
            family,
            trigger: trigger_rx,
            admitted,
        }),
    );
    let watching = StopOnDrop(Arc::new(AtomicBool::new(false)));
    let compiler = source_burst::watch_compilers(Arc::clone(&watching.0));
    let observe = async {
        fixture
            .sources
            .push(source_up(&fixture.rib, CHURN_SOURCE, Vec::new()).await?);
        fixture
            .sources
            .push(source_up(&fixture.rib, RELEASE_HELPER, families.clone()).await?);
        fixture
            .sources
            .push(source_up(&fixture.rib, SOURCE, families.clone()).await?);
        let mut specs = vec![(families.clone(), Some(private_unicast_policy())); receivers];
        specs.push((vec![(Afi::Ipv4, Safi::Unicast)], Some(healthy_policy())));
        fixture.connect(specs, Duration::from_secs(120)).await?;
        // Established is ahead of RIB registration. Each receiver must already
        // own a private table when the source restarts and releases its rows.
        for r in &fixture.receivers {
            loop {
                let (reply, rx) = oneshot::channel();
                fixture
                    .rib
                    .send(RibUpdate::QueryPeerUpdateGroup {
                        peer: PeerId::from_ipv4(r.ip),
                        reply,
                    })
                    .await?;
                let reason = rx.await?;
                if !reason.is_empty() {
                    if r.ip != fixture.receivers[receivers].ip {
                        ensure!(
                            reason == "policy_peer_context",
                            "receiver {} registered as {reason}",
                            r.ip
                        );
                    }
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        let reference = Arc::new(Reference::uniform(rows, BURST_VERSION));
        let (stop, stop_rx) = watch::channel(false);
        let (progress, mut events) = mpsc::channel(2 * receivers);
        let mut collectors = tokio::task::JoinSet::new();
        for r in &mut fixture.receivers[..receivers] {
            let state = WireState::with_reference(family.wire()?, Arc::clone(&reference));
            let (rx, ip) = (r.rx.take().expect("labeled stream"), r.ip);
            let stream = collect(rx, state, progress.clone(), stop_rx.clone());
            collectors.spawn(async move { (ip, stream.await) });
        }
        drop(progress);
        let healthy = fixture.receivers[receivers]
            .rx
            .take()
            .expect("healthy stream");
        replay(&fixture.rib, family, rows, 1, BURST_VERSION - 1).await?;
        let old = received_table(&fixture.rib).await?;
        fixture
            .rib
            .send(RibUpdate::PeerGracefulRestart {
                peer: PeerId::from_ipv4(SOURCE),
                session_id: 1,
                restart_time: 3600,
                stale_routes_time: 3600,
                gr_families: families.clone(),
                peer_llgr_capable: false,
                peer_llgr_families: vec![],
                llgr_stale_time: 0,
            })
            .await?;
        let stale = received_table(&fixture.rib).await?;
        fixture.sources.push(
            source_session_up(&fixture.rib, SOURCE, REPLACEMENT, true, families.clone()).await?,
        );
        replay(&fixture.rib, family, rows, REPLACEMENT, BURST_VERSION).await?;
        fixture.rib.send(eor(SOURCE, REPLACEMENT, family)).await?;
        let replayed = received_table(&fixture.rib).await?;
        fixture.set_paused(0..receivers, true).await?;
        let mut setup = BTreeMap::new();
        let before = fold_slice_maxima(&fixture.metrics, &mut setup);
        let base_polls = poll_count(&fixture.metrics);
        let base_flips = before.total(FLIPS).context("missing owed-family counter")?;
        let active = release::family_metric(&before, "bgp_selection_deferral_active", family, None);
        let waiters =
            release::family_metric(&before, "bgp_selection_deferral_waiters", family, None);
        let t0 = Instant::now();
        let since = |t: Instant| t.duration_since(t0).as_secs_f64() * 1e3;
        let until = tokio::time::Instant::now() + cap;
        let healthy_probe = tokio::spawn(healthy_wire(healthy, stop_rx));
        trigger
            .send(())
            .map_err(|()| anyhow::anyhow!("RIB ended before release"))?;
        let (release_at, admitted_at) = stamps.await??;
        // Start the query right after admission so it can observe the first matching
        // answer while the paused-reader drain proceeds on the other runtime.
        let r = fixture.rib.clone();
        let winner_probe = tokio::spawn(async move { matching_winner(&r).await });
        tokio::time::sleep_until(tokio::time::Instant::from_std(release_at + pause)).await;
        // A primary FIFO barrier confirms release dispatch while readers are
        // still paused. The flip delta witnesses an owed-family transition per receiver.
        release::barrier(&fixture.rib).await?;
        let held = Snapshot::take(&fixture.metrics);
        let flips = held
            .total(FLIPS)
            .context("missing release owed-family counter")?
            - base_flips;
        let releases = release::family_metric(
            &held,
            "bgp_selection_deferral_releases_total",
            family,
            Some("all_eor"),
        );
        let resume = Instant::now();
        fixture.set_paused(0..receivers, false).await?;
        let all_eors = wait_for_receivers(&mut events, receivers, Progress::Eor, until).await;
        let mut slice = BTreeMap::new();
        drop(fold_slice_maxima(&fixture.metrics, &mut slice));
        let polls = poll_count(&fixture.metrics).saturating_sub(base_polls);
        let poll_end = Instant::now();
        let winner = tokio::time::timeout_at(until, winner_probe).await???;
        let mut drained = false;
        if all_eors {
            let (prefix, _) = labeled_destination(family.afi_safi().0, 0);
            fixture
                .rib
                .send(RibUpdate::LabeledRoutesReceived {
                    peer: PeerId::from_ipv4(SOURCE),
                    session_id: REPLACEMENT,
                    announced: vec![],
                    withdrawn: vec![rustbgpd_rib::LabeledRibRouteKey { prefix, path_id: 0 }],
                })
                .await?;
            drained = wait_for_receivers(&mut events, receivers, Progress::Withdrawal, until).await;
        }
        tokio::time::sleep(QUIET).await;
        let _ = stop.send(true);
        let healthy = healthy_probe.await?;
        let received = match healthy.arrivals.as_slice() {
            [(SEQUENCE, at)] => Some(*at),
            _ => None,
        };
        let mut wire = BTreeMap::new();
        let mut all_exact = true;
        let mut ordered = true;
        let mut withdrawals = drained;
        let mut payload = true;
        let mut eors = Vec::new();
        let mut resets = 0;
        while let Some(report) = collectors.join_next().await {
            let (ip, (s, initial)) = report?;
            let at = s
                .eor_at
                .and_then(|t| t.checked_duration_since(t0))
                .map(|d| d.as_secs_f64() * 1e3);
            if let Some(t) = at {
                eors.push(t);
            }
            all_exact &= initial && s.exact();
            ordered &= initial
                && s.eors == 1
                && s.routes_after_eor == 0
                && s.routes_before_eor == rows as u64;
            withdrawals &=
                s.churned_after_eor == 1 && s.withdrawals == 1 && s.withdrawn_survivors() == 0;
            payload &= s.labeled_announced == s.announced
                && s.labeled_announced == rows as u64
                && s.labeled_withdrawn == s.withdrawals
                && s.labeled_withdrawn == 1;
            resets += s.resets;
            wire.insert(
                ip.to_string(),
                json!({
                    "peer": ip.to_string(),
                    "eor_ms": at,
                    "eors": s.eors,
                    "exact_at_eor": initial,
                    "exact": s.exact(),
                    "missing": s.missing(),
                    "announced": s.announced,
                    "withdrawals": s.withdrawals,
                    "labeled_announced": s.labeled_announced,
                    "labeled_withdrawn": s.labeled_withdrawn,
                    "routes_before_eor": s.routes_before_eor,
                    "routes_after_eor": s.routes_after_eor,
                    "post_eor_sentinel_changes": s.churned_after_eor,
                    "outside": s.outside,
                    "decode_failures": s.decode_failures,
                    "resets": s.resets,
                }),
            );
        }
        let last = (eors.len() == receivers).then(|| eors.into_iter().fold(0.0, f64::max));
        let down = fixture.not_established().await;
        Ok::<_, anyhow::Error>(json!({
            "schema": "rrtransport-credit/1",
            "cell": "restart",
            "family": family.name(),
            "report_only": true,
            "mode": if options.correctness_only { "correctness" } else { "measured" },
            "shape": {
                "receivers": receivers,
                "rows_per_receiver": rows,
                "pause_ms": pause.as_secs_f64() * 1000.0,
                "chunk_rows": CHUNK,
                "trigger": Trigger::Restart.name(),
                "registered_peers": fixture.receivers.len() + 3,
                "receiver_rcvbuf_bytes": RECEIVER_RCVBUF,
            },
            "source": {
                "peer": SOURCE.to_string(),
                "release_helper": RELEASE_HELPER.to_string(),
                "restart_state": true,
                "old_session": 1,
                "new_session": REPLACEMENT,
                "old_rows": old.0,
                "old_sample_stale": old.1,
                "retained_rows": stale.0,
                "retained_sample_stale": stale.1,
                "replayed_rows": replayed.0,
                "replayed_sample_stale": replayed.1,
            },
            "actor": {
                "poll_count": polls,
                "slice_max_us": slice,
                "from_ms": 0.0,
                "to_ms": since(poll_end),
            },
            "unaffected": {
                "peer": CHURN_SOURCE.to_string(),
                "release_update_sequence": SEQUENCE,
                "release_update_admitted_ms": since(admitted_at),
                "release_update_winner_ms": since(winner),
                "release_update_received_ms": received.map(since),
                "release_update_wait_ms": (winner - admitted_at).as_secs_f64() * 1000.0,
                "release_update_wire_ms": received.and_then(|t| t.checked_duration_since(admitted_at))
                    .map(|d| d.as_secs_f64() * 1000.0),
            },
            "timing": {
                "release_sent_ms": since(release_at),
                "resume_issued_ms": since(resume),
                "last_eor_ms": last,
                "release_to_last_eor_ms": last.map(|ms| ms - since(release_at)),
            },
            "witness": {
                "active_before_release": active,
                "waiters_before_release": waiters,
                "all_eor_releases": releases,
                "owing_flip_delta_while_paused": flips,
            },
            "checks": {
                "selection_held": active == 1.0 && waiters == 1.0,
                "selection_released": releases == 1.0,
                "owed_at_release": flips == receivers as f64,
                "source_restart": old == (rows as u64, false) && stale == (rows as u64, true)
                    && replayed == (rows as u64, false),
                "final_state_exact": all_exact,
                "eor_after_every_route": all_eors && ordered,
                "post_release_withdrawal": withdrawals,
                "labeled_payload_counted": payload,
                "physical_poll_observed": polls > 0 && slice.get("actor_poll").is_some_and(|&v| v > 0.0),
                "release_update_delivered": admitted_at >= release_at && winner >= admitted_at
                    && received.is_some_and(|t| t >= admitted_at)
                    && healthy.decode_failures == 0 && healthy.unexpected_updates == 0,
                "no_session_resets": resets == 0 && healthy.resets == 0 && down.is_empty(),
            },
            "receivers": wire.into_values().collect::<Vec<_>>(),
        }))
    };
    let result = tokio::time::timeout(cap + Duration::from_secs(240), observe).await;
    let closed = fixture.close().await;
    drop(watching);
    compiler.thread().unpark();
    let c = compiler
        .join()
        .map_err(|_| anyhow::anyhow!("compiler watcher failed"))?;
    closed?;
    let mut report = result.context("labeled restart timed out")??;
    let memory = json!({
        "cgroup": cgroup().map(|p| p.display().to_string()),
        "cgroup_memory_peak_bytes": cgroup_peak_bytes(),
        "cgroup_memory_max": cgroup_value("memory.max"),
        "cgroup_swap_max": cgroup_value("memory.swap.max"),
        "cgroup_oom_kill": cgroup_oom_kill(),
    });
    report["checks"]["memory_fenced"] = json!(
        memory["cgroup_swap_max"] == "0"
            && memory["cgroup_oom_kill"] == "0"
            && memory["cgroup_memory_peak_bytes"]
                .as_u64()
                .is_some_and(|p| p > 0)
    );
    report["memory"] = memory;
    report["host"] = json!({
        "compiler_watch": {
            "every_ms": source_burst::COMPILER_WATCH_EVERY.as_millis(),
            "samples": c.samples,
            "observed": c.observed,
            "first": c.first,
            "unavailable": c.unavailable,
        },
    });
    write_result(output, &format!("restart-{}.json", family.name()), &report)?;
    Ok(recorded_pass(&report))
}
