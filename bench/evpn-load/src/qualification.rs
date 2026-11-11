//! Controlled actual-socket recovery workload; the Python runner owns policy
//! changes and observes the daemon. Nothing here declares a dirty/marker witness.

use super::{
    Afi, Arc, Args, AtomicBool, Client, Duration, Message, MpUnreachNlri, Ordering, Path,
    PathAttribute, Safi, Shape, UpdateMessage, announce_window, check, churn, converge, converged,
    finish, send_all,
};
use std::io::{BufWriter, Write};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Raw UPDATE bytes, with BGP framing; bounded independently for each receiver.
pub(super) struct WireCapture {
    output: BufWriter<std::fs::File>,
    bytes: u64,
}

impl WireCapture {
    pub(super) fn new(directory: &Path, peer: u32) -> std::io::Result<Self> {
        Ok(Self {
            output: BufWriter::new(std::fs::File::create_new(
                directory.join(format!("peer-{peer}.bgp")),
            )?),
            bytes: 0,
        })
    }

    pub(super) fn update(&mut self, update: &UpdateMessage) -> anyhow::Result<()> {
        let bytes = rustbgpd_wire::encode_message(&Message::Update(update.clone()))?;
        self.bytes += u64::try_from(bytes.len())?;
        anyhow::ensure!(
            self.bytes <= 128 * 1024 * 1024,
            "receiver wire capture exceeded 128 MiB"
        );
        self.output.write_all(&bytes)?;
        Ok(())
    }

    fn position(&mut self) -> std::io::Result<u64> {
        self.output.flush()?;
        Ok(self.bytes)
    }
}

fn boundary(name: &str, clients: &[Client]) -> anyhow::Result<serde_json::Value> {
    // One lock per receiver covers both readings: an End-of-RIB processed
    // between them would be counted but absent from the capture prefix.
    let (offsets, eors): (Vec<_>, Vec<_>) = clients
        .iter()
        .map(|client| {
            let mut view = client
                .view
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let offset = view
                .capture
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("missing wire capture"))?
                .position()?;
            anyhow::Ok((offset, view.eors))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    Ok(serde_json::json!({"boundary": name, "offsets": offsets,
                         "eors": eors,
                         "shifts": clients.iter().map(|client| client.shifts).collect::<Vec<_>>()}))
}

fn policies_match(clients: &[Client], generation: &str) -> bool {
    clients.iter().all(|client| {
        let view = client
            .view
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let expected = if client.index == 1 || (client.index >= 2 && generation == "b") {
            2000
        } else {
            1000
        };
        view.qualification_communities
            .as_ref()
            .is_some_and(|communities| {
                communities
                    .iter()
                    .enumerate()
                    .all(|(bit, value)| !view.has(bit) || *value == expected)
            })
    })
}

fn eors(clients: &[Client]) -> Vec<u64> {
    clients
        .iter()
        .map(|client| {
            client
                .view
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .eors
        })
        .collect()
}

async fn drained(clients: &mut [Client]) -> anyhow::Result<()> {
    for client in clients {
        client
            .io_control
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("missing I/O controller"))?
            .drain_writes(client.submitted_messages)
            .await?;
    }
    Ok(())
}

async fn pause(clients: &mut [Client], paused: bool) -> anyhow::Result<()> {
    for client in clients {
        client
            .io_control
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("missing I/O controller"))?
            .set_reads_paused(paused)
            .await?;
    }
    Ok(())
}

async fn source_barrier(clients: &mut [Client]) -> anyhow::Result<()> {
    let marker = Message::Update(UpdateMessage::build(
        &[],
        &[],
        &[PathAttribute::MpUnreachNlri(Box::new(MpUnreachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            vpn_withdrawn: vec![],
            labeled_withdrawn: vec![],
            rtc_withdrawn: vec![],
            vpn_flowspec_withdrawn: vec![],
        }))],
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    ));
    for client in &mut *clients {
        send_all(client, vec![marker.clone()]).await;
    }
    drained(clients).await
}

async fn churn_round(
    shape: Shape,
    clients: &mut [Client],
    overlap: bool,
) -> anyhow::Result<(u64, u128, u128)> {
    let started = super::wall_us();
    let mut events = 0;
    let count = clients.len();
    for (index, client) in clients.iter_mut().enumerate() {
        events += churn(shape, client).await;
        if overlap {
            drained(std::slice::from_mut(client)).await?;
            if index + 1 < count {
                // Keep a bounded incremental sequence observable at 20 Hz.
                // Recovery timing starts only after the later resume fence.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    drained(clients).await?;
    Ok((events, started, super::wall_us()))
}

async fn wait_until(
    cap: Duration,
    lost: &AtomicBool,
    ready: impl Fn() -> bool,
) -> anyhow::Result<()> {
    tokio::time::timeout(cap, async {
        while !ready() {
            anyhow::ensure!(
                !lost.load(Ordering::SeqCst),
                "receiver session lost while waiting"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        anyhow::Ok(())
    })
    .await??;
    Ok(())
}

async fn received_refresh(
    clients: &[Client],
    before: &[u64],
    lost: &AtomicBool,
    cap: Duration,
) -> anyhow::Result<()> {
    wait_until(cap, lost, || {
        eors(clients)
            .iter()
            .zip(before)
            .all(|(after, prior)| after > prior)
    })
    .await
}

async fn settle_clients(
    shape: Shape,
    clients: &[Client],
    lost: &Arc<AtomicBool>,
    cap: Duration,
    refresh_before: Option<&[u64]>,
) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let (ok, result, _) = converge(shape, clients, lost, cap).await;
    anyhow::ensure!(
        ok,
        "controlled inventory did not converge: invalid={} parse_errors={} self_reflected={}",
        result.invalid,
        result.parse_errors,
        result.self_reflected
    );
    if let Some(before) = refresh_before {
        received_refresh(clients, before, lost, cap.saturating_sub(started.elapsed())).await?;
    }
    Ok(())
}

/// Primary-lane probe: client 0 announces one Type 5 route from the unused
/// half of its pool, the cycle waits until client 1 holds it, then withdraws
/// it and waits until no receiver holds it. Only clients 0 and 1 keep their
/// export policy across the controlled reloads, so neither end moves.
struct Probe {
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<anyhow::Result<(Vec<serde_json::Value>, u64)>>,
}

impl Probe {
    fn start(
        shape: Shape,
        clients: &[Client],
        lost: &Arc<AtomicBool>,
        cap: Duration,
    ) -> anyhow::Result<Self> {
        let index = shape.pool5() - 1;
        anyhow::ensure!(
            clients.len() >= 2 && !shape.window5(clients[0].shifts).any(|live| live == index),
            "probe route overlaps the source's live window"
        );
        let tx = clients[0]
            .tx
            .clone()
            .ok_or_else(|| anyhow::anyhow!("probe source has no session"))?;
        let views: Vec<_> = clients[1..]
            .iter()
            .map(|client| client.view.clone())
            .collect();
        let bit = (shape.pool2() + index) as usize;
        let route = super::type5_route(0, index);
        let (stop, lost) = (Arc::new(AtomicBool::new(false)), lost.clone());
        let stopping = stop.clone();
        let task = tokio::spawn(async move {
            let holds = |view: &Arc<std::sync::Mutex<super::View>>| {
                view.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .has(bit)
            };
            let (mut samples, mut messages) = (Vec::new(), 0_u64);
            // One more cycle after the stop request, so the train always
            // ends after the caller's closing witness.
            let mut final_cycle = false;
            while !final_cycle {
                final_cycle = stopping.load(Ordering::SeqCst);
                let sent = super::wall_us();
                tx.send(super::build_update(0, vec![route.clone()], vec![]))
                    .await
                    .map_err(|_| anyhow::anyhow!("probe source writer closed"))?;
                let seen = wait_until(cap, &lost, || holds(&views[0]))
                    .await
                    .ok()
                    .map(|()| super::wall_us());
                tx.send(super::build_update(0, vec![], vec![route.clone()]))
                    .await
                    .map_err(|_| anyhow::anyhow!("probe source writer closed"))?;
                messages += 2;
                let withdrawn = wait_until(cap, &lost, || !views.iter().any(&holds))
                    .await
                    .is_ok();
                samples.push(
                    serde_json::json!({"sent_us": sent, "seen_us": seen, "withdrawn": withdrawn}),
                );
                if seen.is_none() || !withdrawn {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok((samples, messages))
        });
        Ok(Self { stop, task })
    }

    async fn finish(self, source: &mut Client) -> anyhow::Result<serde_json::Value> {
        self.stop.store(true, Ordering::SeqCst);
        let (samples, messages) = self.task.await??;
        // The writer counts probe messages too; later drains must wait for them.
        source.submitted_messages += messages;
        Ok(serde_json::json!({"samples": samples}))
    }
}

/// Commands are acknowledged after actual work, never merely queue admission.
/// `connected` precedes all route injection so the runner can prove both groups
/// exist before the bench constructor's initial-registration window closes.
#[expect(
    clippy::too_many_lines,
    reason = "the controlled workload keeps command-state guards and acknowledgements in one dispatcher"
)]
pub(super) async fn run(
    args: &Args,
    shape: Shape,
    clients: &mut [Client],
    lost: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut input = BufReader::new(tokio::io::stdin()).lines();
    let (mut loaded, mut paused, mut rounds) = (false, false, 0_u32);
    let mut refresh_before = None;
    let mut input_barrier_generation = 0_u64;
    let mut probe: Option<(String, Probe)> = None;
    println!(
        "evpn_control {}",
        serde_json::json!({"command": "connected", "clients": shape.clients})
    );
    loop {
        let command = tokio::time::timeout(Duration::from_secs(300), input.next_line())
            .await??
            .ok_or_else(|| anyhow::anyhow!("qualification controller closed before finish"))?;
        anyhow::ensure!(
            !lost.load(Ordering::SeqCst),
            "qualification lost a receiver session"
        );
        let fields: Vec<_> = command.split_whitespace().collect();
        let result = match fields.as_slice() {
            ["load"] if !loaded => {
                for client in &mut *clients {
                    announce_window(shape, client).await;
                }
                drained(clients).await?;
                settle_clients(
                    shape,
                    clients,
                    lost,
                    Duration::from_secs(args.initial_cap_secs),
                    None,
                )
                .await?;
                loaded = true;
                boundary("loaded", clients)?
            }
            ["pause"] if loaded && !paused => {
                pause(clients, true).await?;
                paused = true;
                serde_json::json!({"socket_read_acks": clients.len()})
            }
            [kind @ ("churn" | "churn-overlap")] if loaded => {
                let (events, started, drained_at) =
                    churn_round(shape, clients, *kind == "churn-overlap").await?;
                rounds += 1;
                serde_json::json!({"round": rounds, "events": events, "writers_drained": clients.len(),
                                  "write_started_us": started, "writers_drained_us": drained_at})
            }
            ["source-barrier"] if loaded => {
                source_barrier(clients).await?;
                input_barrier_generation += 1;
                serde_json::json!({"input_barrier_generation": input_barrier_generation,
                                  "writers_drained": clients.len()})
            }
            ["refresh"] if loaded => {
                refresh_before = Some(eors(clients));
                for client in &mut *clients {
                    send_all(
                        client,
                        vec![Message::RouteRefresh(
                            rustbgpd_wire::RouteRefreshMessage::new(Afi::L2Vpn, Safi::Evpn),
                        )],
                    )
                    .await;
                }
                drained(clients).await?;
                serde_json::json!({"refreshes": clients.len(), "writers_drained": clients.len(),
                                  "eor_baseline": refresh_before})
            }
            ["refresh-settle"] if loaded && !paused => {
                let before = refresh_before
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("refresh not issued"))?;
                received_refresh(
                    clients,
                    before,
                    lost,
                    Duration::from_secs(args.converge_cap_secs),
                )
                .await?;
                boundary("refresh", clients)?
            }
            ["probe-start", generation @ ("a" | "b")] if loaded && !paused && probe.is_none() => {
                let cap = Duration::from_secs(args.converge_cap_secs);
                probe = Some((
                    (*generation).to_string(),
                    Probe::start(shape, clients, lost, cap)?,
                ));
                serde_json::json!({"probe": generation})
            }
            ["probe-stop", generation]
                if probe
                    .as_ref()
                    .is_some_and(|(started, _)| started == generation) =>
            {
                let (_, running) = probe.take().expect("checked above");
                running.finish(&mut clients[0]).await?
            }
            ["policy", generation @ ("a" | "b")] if loaded && !paused && probe.is_none() => {
                wait_until(Duration::from_secs(args.converge_cap_secs), lost, || {
                    policies_match(clients, generation)
                })
                .await?;
                anyhow::ensure!(
                    converged(&check(shape, clients), shape),
                    "regroup changed route inventory"
                );
                boundary(&format!("regroup-{generation}"), clients)?
            }
            ["resume"] if loaded && paused => {
                pause(clients, false).await?;
                paused = false;
                serde_json::json!({"socket_read_acks": clients.len()})
            }
            ["settle"] if loaded && !paused => {
                settle_clients(
                    shape,
                    clients,
                    lost,
                    Duration::from_secs(args.converge_cap_secs),
                    refresh_before.as_deref(),
                )
                .await?;
                boundary("settled", clients)?
            }
            ["mark", name] if loaded => boundary(name, clients)?,
            ["finish"] if loaded && !paused && probe.is_none() => {
                let result = boundary("finished", clients)?;
                anyhow::ensure!(
                    converged(&check(shape, clients), shape),
                    "final inventory changed"
                );
                finish(args, shape, clients).await;
                println!(
                    "evpn_control {}",
                    serde_json::json!({"command": "finish", "result": result})
                );
                return Ok(());
            }
            _ => anyhow::bail!("invalid qualification command or state: {command}"),
        };
        println!(
            "evpn_control {}",
            serde_json::json!({"command": command, "result": result})
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Mutex, View, build_update, type2_route};
    use rustbgpd_wire::attribute::PathAttribute;

    #[test]
    fn policy_completion_checks_every_live_key_and_preserves_anchors() {
        let shape = Shape {
            clients: 3,
            type2: 1,
            type5: 1,
            shift2: 1,
            shift5: 1,
        };
        let clients: Vec<_> = (0..shape.clients)
            .map(|index| {
                let mut view = View::new(shape);
                view.qualification_communities =
                    Some(vec![0; shape.clients as usize * shape.block()]);
                for origin in 0..shape.clients {
                    if origin != index {
                        view.apply(index, shape, &type2_route(origin, 0), true);
                        view.qualification_communities.as_mut().unwrap()
                            [origin as usize * shape.block()] =
                            if index == 1 { 2000 } else { 1000 };
                    }
                }
                Client {
                    index,
                    tx: None,
                    view: Arc::new(Mutex::new(view)),
                    up: Arc::new(AtomicBool::new(true)),
                    expect_down: Arc::new(AtomicBool::new(false)),
                    shifts: 0,
                    io_control: None,
                    submitted_messages: 0,
                }
            })
            .collect();
        assert!(policies_match(&clients, "a"));
        assert!(!policies_match(&clients, "b"));
        {
            let mut view = clients[2].view.lock().unwrap();
            view.qualification_communities.as_mut().unwrap()[0] = 2000;
        }
        assert!(
            !policies_match(&clients, "b"),
            "one updated route must not complete regroup"
        );
        {
            let mut view = clients[2].view.lock().unwrap();
            view.qualification_communities.as_mut().unwrap()[shape.block()] = 2000;
        }
        assert!(policies_match(&clients, "b"));
        assert!(!policies_match(&clients, "a"));
    }

    fn probe_clients(shape: Shape) -> (Vec<Client>, tokio::sync::mpsc::Receiver<Message>) {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let clients = (0..shape.clients)
            .map(|index| Client {
                index,
                tx: (index == 0).then(|| tx.clone()),
                view: Arc::new(Mutex::new(View::new(shape))),
                up: Arc::new(AtomicBool::new(true)),
                expect_down: Arc::new(AtomicBool::new(false)),
                shifts: 0,
                io_control: None,
                submitted_messages: 0,
            })
            .collect();
        (clients, rx)
    }

    #[tokio::test]
    async fn probe_records_arrival_and_withdrawal_and_marks_a_lost_route_unseen() {
        let shape = Shape {
            clients: 3,
            type2: 2,
            type5: 2,
            shift2: 1,
            shift5: 1,
        };
        let lost = Arc::new(AtomicBool::new(false));
        // A reflector that delivers every probe UPDATE to both receivers.
        let (mut clients, mut rx) = probe_clients(shape);
        let views: Vec<_> = clients[1..].iter().map(|c| c.view.clone()).collect();
        tokio::spawn(async move {
            while let Some(Message::Update(update)) = rx.recv().await {
                let parsed = update.parse(true, false, &[]).unwrap();
                for attribute in &parsed.attributes {
                    let (routes, present) = match attribute {
                        PathAttribute::MpReachNlri(mp) => (&mp.evpn_announced, true),
                        PathAttribute::MpUnreachNlri(mp) => (&mp.evpn_withdrawn, false),
                        _ => continue,
                    };
                    for view in &views {
                        for route in routes {
                            view.lock().unwrap().apply(
                                view_owner(&views, view),
                                shape,
                                route,
                                present,
                            );
                        }
                    }
                }
            }
        });
        let probe = Probe::start(shape, &clients, &lost, Duration::from_secs(5)).unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        let result = probe.finish(&mut clients[0]).await.unwrap();
        let samples = result["samples"].as_array().unwrap();
        assert!(samples.len() >= 2, "{result}");
        for sample in samples {
            assert!(sample["seen_us"].as_u64().unwrap() >= sample["sent_us"].as_u64().unwrap());
            assert_eq!(sample["withdrawn"], true);
        }
        assert_eq!(clients[0].submitted_messages, 2 * samples.len() as u64);

        // Nothing delivers the probe: the sample records it unseen and ends the train.
        let (mut clients, _rx) = probe_clients(shape);
        let probe = Probe::start(shape, &clients, &lost, Duration::from_millis(50)).unwrap();
        let result = probe.finish(&mut clients[0]).await.unwrap();
        let samples = result["samples"].as_array().unwrap();
        assert_eq!(samples.len(), 1);
        assert!(samples[0]["seen_us"].is_null());
    }

    fn view_owner(views: &[Arc<Mutex<View>>], view: &Arc<Mutex<View>>) -> u32 {
        1 + u32::try_from(views.iter().position(|v| Arc::ptr_eq(v, view)).unwrap()).unwrap()
    }

    #[test]
    fn wire_capture_preserves_original_update_attribute_bytes() {
        let directory =
            std::env::temp_dir().join(format!("evpn-wire-capture-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let mut capture = WireCapture::new(&directory, 0).unwrap();
        let Message::Update(update) = build_update(1, vec![type2_route(1, 3)], vec![]) else {
            unreachable!();
        };
        capture.update(&update).unwrap();
        let expected = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
        assert_eq!(
            capture.position().unwrap(),
            u64::try_from(expected.len()).unwrap()
        );
        assert_eq!(
            std::fs::read(directory.join("peer-0.bgp")).unwrap(),
            expected
        );
        drop(capture);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
