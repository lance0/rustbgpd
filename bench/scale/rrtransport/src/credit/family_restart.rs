//! A GR source replays labeled unicast or VPN routes while selection and receiver reads are held.
use super::*;

const REPLACEMENT: u64 = 2;
const RELEASE_HELPER: Ipv4Addr = Ipv4Addr::new(127, 254, 0, 3);
const SEQUENCE: u32 = 1;
// Long enough for the full parent to produce its whole-family sends and
// for the candidate's row credit to bind before the readers resume.
const FULL_PAUSE: Duration = Duration::from_secs(90);
const STEP_HISTOGRAM: &str = "bgp_rib_outbound_owed_drain_step_seconds";
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
    finish: oneshot::Receiver<FinalScrape>,
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
        FinalScrape::serve(actor, self.finish).await;
    }
}

struct FinalScrape {
    metrics: BgpMetrics,
    reply: oneshot::Sender<FinalSample>,
}

struct FinalSample {
    slice: BTreeMap<String, f64>,
    polls: u64,
    poll_end: Instant,
    steps_end: Buckets,
}

impl FinalSample {
    fn read(metrics: &BgpMetrics) -> Self {
        let poll_end = Instant::now();
        let mut slice = BTreeMap::new();
        drop(fold_slice_maxima(metrics, &mut slice));
        Self {
            slice,
            polls: poll_count(metrics),
            poll_end,
            steps_end: buckets(metrics, STEP_HISTOGRAM, "scope"),
        }
    }
}

impl FinalScrape {
    // The poll that offers the last EoR can still be running when the stub
    // decodes it. TimedActor publishes its duration only after the poll returns.
    async fn serve(actor: impl std::future::Future<Output = ()>, finish: oneshot::Receiver<Self>) {
        tokio::pin!(actor);
        tokio::select! {
            biased;
            request = finish => {
                if let Ok(request) = request {
                    let _ = request.reply.send(FinalSample::read(&request.metrics));
                }
            }
            () = &mut actor => return,
        }
        actor.await;
    }

    async fn request(finish: oneshot::Sender<Self>, metrics: &BgpMetrics) -> Result<FinalSample> {
        let (reply, result) = oneshot::channel();
        finish
            .send(Self {
                metrics: metrics.clone(),
                reply,
            })
            .map_err(|_| anyhow::anyhow!("RIB ended before the final poll sample"))?;
        Ok(result.await?)
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
        let indices = start..(start + CHUNK).min(rows);
        let update = if family.afi_safi().1 == Safi::MplsVpn {
            RibUpdate::VpnRoutesReceived {
                peer: PeerId::from_ipv4(SOURCE),
                session_id,
                announced: indices
                    .map(|i| restart_vpn_route(family.afi_safi().0, i, med))
                    .collect(),
                withdrawn: vec![],
            }
        } else {
            labeled_source_update(family, indices, session_id, med)
        };
        rib.send(update).await?;
    }
    Ok(())
}

async fn received_table(rib: &mpsc::Sender<RibUpdate>, family: Family) -> Result<(u64, bool)> {
    let scope = rustbgpd_rib::update::RouteQueryScope::Received {
        peer: Some(PeerId::from_ipv4(SOURCE)),
    };
    if family.afi_safi().1 == Safi::MplsVpn {
        let (reply, result) = oneshot::channel();
        rib.send(RibUpdate::QueryVpnRoutesPage {
            scope,
            filter: None,
            after: None,
            expected_version: None,
            page_size: 1,
            reply,
        })
        .await?;
        let table = result
            .await?
            .map_err(|e| anyhow::anyhow!("VPN input table: {e:?}"))?;
        return Ok((
            table.total,
            table.routes.first().is_some_and(|r| r.is_stale),
        ));
    }
    let (reply, result) = oneshot::channel();
    rib.send(RibUpdate::QueryLabeledRoutesPage {
        scope,
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

fn private_vpn_policy() -> PolicyChain {
    let mut rt = statement(None, None);
    rt.match_community = vec![rustbgpd_policy::CommunityMatch::RouteTarget {
        global: LOCAL_AS,
        local: 100,
    }];
    rt.action = PolicyAction::Permit;
    PolicyChain::new(vec![Policy {
        entries: vec![
            statement(
                None,
                Some(NeighborSetMatch {
                    addresses: vec![],
                    remote_asns: vec![65_099],
                    peer_groups: vec![],
                }),
            ),
            rt,
        ],
        default_action: PolicyAction::Deny,
    }])
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
) -> (WireState, bool, usize) {
    let mut initial_exact = false;
    let mut max_backlog = 0;
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            msg = rx.recv() => {
                let Some(msg) = msg else { state.closed(); break };
                // Messages waiting in the decoded stub channel at dequeue.
                // Bytes retained by those messages are not exposed here.
                max_backlog = max_backlog.max(rx.len());
                let first_eor = state.eors == 0;
                let first_withdrawal = state.withdrawals == 0;
                state.apply(&msg, Instant::now());
                if first_eor && state.eors == 1 {
                    initial_exact = state.exact() && !state.eor_premature && state.duplicates_before_eor == 0;
                    state.expect_restart_withdrawal(0);
                    let _ = progress.send(Progress::Eor).await;
                }
                if first_withdrawal && state.withdrawals > 0 {
                    let _ = progress.send(Progress::Withdrawal).await;
                }
            }
        }
    }
    (state, initial_exact, max_backlog)
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

/// Keep a zero for each exported idle scope; an unexported scope stays absent.
fn drain_step_deltas(before: &Buckets, after: &Buckets) -> Value {
    let mut delta = longest(before, after);
    let scopes = delta.as_object_mut().expect("brackets by scope");
    for scope in after.keys() {
        scopes.entry(scope).or_insert_with(|| {
            json!({
                "observations": 0,
                "above_ms": null,
                "at_most_ms": null,
            })
        });
    }
    delta
}

pub async fn run(family: Family, output: &Path, options: &Options) -> Result<bool> {
    ensure!(
        matches!(family.afi_safi().1, Safi::LabeledUnicast | Safi::MplsVpn)
            && options.seconds.is_none(),
        "restart requires labeled unicast or VPN and a fixed deadline"
    );
    let (receivers, rows, pause, cap) = if options.reduced {
        (
            4,
            4_096,
            Duration::from_millis(500),
            Duration::from_secs(120),
        )
    } else {
        (150, 150_000, FULL_PAUSE, Duration::from_secs(900))
    };
    let pause = options.pause.unwrap_or(pause);
    check_read_hold(pause)?;
    let families = vec![family.afi_safi()];
    let vpn = family.afi_safi().1 == Safi::MplsVpn;
    let name = if family == Family::Vpn {
        "vpn4"
    } else {
        family.name()
    };
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
    let (finish, finish_rx) = oneshot::channel();
    let mut fixture = Fixture::start_with_probe(
        options,
        Some(config),
        Some(ReleaseProbe {
            family,
            trigger: trigger_rx,
            admitted,
            finish: finish_rx,
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
        let policy = if vpn {
            private_vpn_policy()
        } else {
            private_unicast_policy()
        };
        let mut specs = vec![(families.clone(), Some(policy)); receivers];
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
        let mut rtc_negotiated = false;
        if vpn {
            for r in &fixture.receivers[..receivers] {
                let state = r
                    .session
                    .query_state_timeout(Duration::from_secs(5))
                    .await
                    .context("could not read receiver OPEN capabilities")?;
                let negotiated = state
                    .negotiated_session
                    .context("missing receiver OPEN capabilities")?;
                ensure!(
                    negotiated.families.contains(&family.afi_safi()),
                    "receiver {} did not negotiate VPN",
                    r.ip
                );
                rtc_negotiated |= negotiated
                    .families
                    .contains(&(Afi::Ipv4, Safi::RtConstrain));
            }
        }
        let reference = Arc::new(Reference::uniform(rows, BURST_VERSION));
        let (stop, stop_rx) = watch::channel(false);
        let (progress, mut events) = mpsc::channel(2 * receivers);
        let mut collectors = tokio::task::JoinSet::new();
        let stub_capacity = fixture.receivers[0]
            .rx
            .as_ref()
            .expect("receiver stream")
            .max_capacity();
        for r in &mut fixture.receivers[..receivers] {
            let state = WireState::with_restart_reference(family.wire()?, Arc::clone(&reference));
            let (rx, ip) = (r.rx.take().expect("receiver stream"), r.ip);
            let stream = collect(rx, state, progress.clone(), stop_rx.clone());
            collectors.spawn(async move { (ip, stream.await) });
        }
        drop(progress);
        let healthy = fixture.receivers[receivers]
            .rx
            .take()
            .expect("healthy stream");
        replay(&fixture.rib, family, rows, 1, BURST_VERSION - 1).await?;
        let old = received_table(&fixture.rib, family).await?;
        fixture
            .rib
            .send(RibUpdate::PeerGracefulRestart {
                peer: PeerId::from_ipv4(SOURCE),
                session_id: 1,
                restart_time: 3600,
                stale_routes_time: 3600,
                gr_families: families.clone(),
                peer_notification_gr: false,
                peer_llgr_capable: false,
                peer_llgr_families: vec![],
                llgr_stale_time: 0,
            })
            .await?;
        let stale = received_table(&fixture.rib, family).await?;
        fixture.sources.push(
            source_session_up(&fixture.rib, SOURCE, REPLACEMENT, true, families.clone()).await?,
        );
        replay(&fixture.rib, family, rows, REPLACEMENT, BURST_VERSION).await?;
        fixture.rib.send(eor(SOURCE, REPLACEMENT, family)).await?;
        let replayed = received_table(&fixture.rib, family).await?;
        fixture.set_paused(0..receivers, true).await?;
        let mut setup = BTreeMap::new();
        let before = fold_slice_maxima(&fixture.metrics, &mut setup);
        let base_polls = poll_count(&fixture.metrics);
        let base_flips = before.total(FLIPS).context("missing owed-family counter")?;
        let steps_before = buckets(&fixture.metrics, STEP_HISTOGRAM, "scope");
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
        let steps_while_paused = buckets(&fixture.metrics, STEP_HISTOGRAM, "scope");
        let resume = Instant::now();
        fixture.set_paused(0..receivers, false).await?;
        let all_eors = wait_for_receivers(&mut events, receivers, Progress::Eor, until).await;
        let FinalSample {
            slice,
            polls,
            poll_end,
            steps_end,
        } = FinalScrape::request(finish, &fixture.metrics).await?;
        let polls = polls.saturating_sub(base_polls);
        let winner = tokio::time::timeout_at(until, winner_probe).await???;
        let mut drained = false;
        if all_eors {
            let peer = PeerId::from_ipv4(SOURCE);
            let afi = family.afi_safi().0;
            let update = if vpn {
                RibUpdate::VpnRoutesReceived {
                    peer,
                    session_id: REPLACEMENT,
                    announced: vec![],
                    withdrawn: vec![restart_vpn_route(afi, 0, BURST_VERSION).key()],
                }
            } else {
                let (prefix, _) = indexed_destination(afi, 0);
                RibUpdate::LabeledRoutesReceived {
                    peer,
                    session_id: REPLACEMENT,
                    announced: vec![],
                    withdrawn: vec![rustbgpd_rib::LabeledRibRouteKey { prefix, path_id: 0 }],
                }
            };
            fixture.rib.send(update).await?;
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
            let (ip, (s, initial, backlog)) = report?;
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
            let (announced, withdrawn) = if vpn {
                (s.vpn_announced, s.vpn_withdrawn)
            } else {
                (s.labeled_announced, s.labeled_withdrawn)
            };
            payload &= announced == s.announced
                && announced == rows as u64
                && withdrawn == s.withdrawals
                && withdrawn == 1;
            resets += s.resets;
            let mut receiver = json!({
                "peer": ip.to_string(),
                "eor_ms": at,
                "eors": s.eors,
                "exact_at_eor": initial,
                "exact": s.exact(),
                "missing": s.missing(),
                "announced": s.announced,
                "withdrawals": s.withdrawals,
                "routes_before_eor": s.routes_before_eor,
                "routes_after_eor": s.routes_after_eor,
                "post_eor_sentinel_changes": s.churned_after_eor,
                "max_observed_stub_backlog_messages": backlog,
                "outside": s.outside,
                "decode_failures": s.decode_failures,
                "resets": s.resets,
            });
            if vpn {
                let sibling = s.restart_rd_sibling_present();
                withdrawals &= sibling;
                receiver["withdrawal_rd_sibling_present"] = json!(sibling);
                receiver["vpn_announced"] = json!(announced);
                receiver["vpn_withdrawn"] = json!(withdrawn);
            } else {
                receiver["labeled_announced"] = json!(announced);
                receiver["labeled_withdrawn"] = json!(withdrawn);
            }
            wire.insert(ip.to_string(), receiver);
        }
        let duration_from = |clock: Instant| -> Option<f64> {
            let start_ms = since(clock);
            (eors.len() == receivers && eors.iter().all(|&at| at >= start_ms))
                .then(|| eors.iter().copied().fold(0.0, f64::max) - start_ms)
        };
        let resume_to_last_eor = duration_from(resume);
        let down = fixture.not_established().await;
        let mut report = json!({
            "schema": "rrtransport-credit/1",
            "cell": "restart",
            "family": name,
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
                "stub_backlog_capacity_messages": stub_capacity,
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
                "setup_slice_max_us": setup,
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
                "last_eor_ms": duration_from(t0),
                "release_to_last_eor_ms": duration_from(release_at),
                "resume_to_last_eor_ms": resume_to_last_eor,
            },
            "witness": {
                "active_before_release": active,
                "waiters_before_release": waiters,
                "all_eor_releases": releases,
                "owing_flip_delta_while_paused": flips,
                "owed_steps_while_paused": drain_step_deltas(&steps_before, &steps_while_paused),
                "owed_steps_to_last_eor": drain_step_deltas(&steps_before, &steps_end),
            },
            "checks": {
                "selection_held": active == 1.0 && waiters == 1.0,
                "selection_released": releases == 1.0,
                "owed_at_release": flips == receivers as f64,
                "source_restart": old == (rows as u64, false) && stale == (rows as u64, true)
                    && replayed == (rows as u64, false),
                "final_state_exact": all_exact,
                "eor_after_every_route": all_eors && ordered && resume_to_last_eor.is_some(),
                "post_release_withdrawal": withdrawals,
                "physical_poll_observed": polls > 0 && slice.get("actor_poll").is_some_and(|&v| v > 0.0),
                "release_update_delivered": admitted_at >= release_at && winner >= admitted_at
                    && received.is_some_and(|t| t >= admitted_at)
                    && healthy.decode_failures == 0 && healthy.unexpected_updates == 0,
                "no_session_resets": resets == 0 && healthy.resets == 0 && down.is_empty(),
            },
            "receivers": wire.into_values().collect::<Vec<_>>(),
        });
        if vpn {
            report["shape"]["rtc_negotiated"] = json!(rtc_negotiated);
            report["shape"]["export_policy"] = json!("permit matching RT, default deny");
            report["shape"]["route_target"] = json!("64512:100");
            report["checks"]["vpn_payload_counted"] = json!(payload);
            report["checks"]["no_rtc"] = json!(!rtc_negotiated);
        } else {
            report["checks"]["labeled_payload_counted"] = json!(payload);
        }
        Ok::<_, anyhow::Error>(report)
    };
    let result = tokio::time::timeout(cap + Duration::from_secs(240), observe).await;
    let closed = fixture.close().await;
    drop(watching);
    compiler.thread().unpark();
    let c = compiler
        .join()
        .map_err(|_| anyhow::anyhow!("compiler watcher failed"))?;
    closed?;
    let mut report = result.context("family restart timed out")??;
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
    write_result(output, &format!("restart-{name}.json"), &report)?;
    Ok(recorded_pass(&report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn final_scrape_waits_for_the_poll_that_sent_the_decoded_eor() {
        use rustbgpd_telemetry::metrics::RibActorSliceStage;
        use std::future::Future;
        use std::task::{Context, Waker};

        let metrics = BgpMetrics::new();
        let mut recorder = metrics.rib_actor_slice_recorder();
        let (sent, decoded) = oneshot::channel();
        let (end_poll, held) = std::sync::mpsc::channel::<()>();
        let (shutdown, stopped) = oneshot::channel::<()>();
        let actor = async move {
            sent.send(()).unwrap();
            // The test observer has the marker while this physical poll is open.
            // Dropping end_poll on a failed assertion also releases this worker.
            let _ = held.recv();
            recorder.observe(RibActorSliceStage::ActorPoll, Duration::from_millis(17));
            recorder.flush();
            let _ = stopped.await;
        };
        let (finish, requested) = oneshot::channel();
        let worker = tokio::spawn(FinalScrape::serve(actor, requested));
        decoded.await.unwrap();
        let mut scrape = std::pin::pin!(FinalScrape::request(finish, &metrics));
        assert!(scrape
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        end_poll.send(()).unwrap();
        let sample = scrape.await.unwrap();
        assert_eq!(sample.polls, 1);
        assert_eq!(sample.slice["actor_poll"], 17_000.0);
        shutdown.send(()).unwrap();
        worker.await.unwrap();
    }

    #[test]
    fn step_witness_distinguishes_a_missing_scope_from_an_idle_one() {
        let before = Buckets::from([
            ("whole".into(), (3, vec![(0.001, 3)])),
            ("keyed".into(), (1, vec![(0.001, 1)])),
        ]);
        let after = Buckets::from([
            ("cursor".into(), (2, vec![(0.001, 1), (0.005, 2)])),
            ("keyed".into(), (1, vec![(0.001, 1)])),
        ]);
        let delta = drain_step_deltas(&before, &after);
        assert!(delta.get("whole").is_none());
        assert_eq!(
            delta["keyed"],
            json!({"observations": 0, "above_ms": null, "at_most_ms": null})
        );
        assert_eq!(
            delta["cursor"],
            json!({"observations": 2, "above_ms": 1.0, "at_most_ms": 5.0})
        );
    }
}
