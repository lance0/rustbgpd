//! Whole-run unrelated-UPDATE wait probe (`RELOADSTALL_UPDATE_WAIT=1`).
//!
//! Two extra sessions, outside the measured fleet: a source (stub index
//! `n_peers`) announces a prefix nobody else touches every 20 ms, each UPDATE
//! carrying its sequence number as MED, and a witness (`n_peers + 1`) records
//! when each one arrives. The wait is the quantity rrharness's cold-join
//! marker train reports: the time from handing the UPDATE to the daemon's
//! ordinary input path until an already converged witness receives it. A
//! sample is stamped when the 20 ms ticker fires, immediately before the
//! source writes it (rrharness stamps at its FIFO admission), so a stalled
//! socket lengthens the wait rather than delaying the stamp.
//!
//! The scenario generator (`GEN_UPDATE_WAIT=1`) isolates the pair by its own
//! route-server policy. The witness's export chain admits only the probe
//! prefix and the source's admits nothing, so neither session ever queues
//! fleet rows: no table, flap fan-out or reload re-export. Fleet chains get no
//! probe term: an export denial in a member's update group rules out the
//! daemon's clean shared reload transition, so the probe would change the
//! path it measures. Members therefore receive the probe prefix, one small
//! UPDATE per tick each; their readers strip it before any other accounting
//! and count it as `member_probe_updates` (report-only). Both pair chains are
//! identical in every policy generation, so a reload that changes every member
//! leaves the pair alone. The witness counts every other UPDATE it receives
//! (`witness_other_updates`), and a nonzero count fails the run.
//!
//! Each UPDATE replaces the previous one, so the daemon may send only the
//! newest pending path. A receipt of sequence `s` completes every earlier
//! sample still waiting, at that receipt time; those count as `coalesced`.
//! Samples are charged to the phase in which they were sent.

use std::sync::Mutex;

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::*;

pub(crate) const INTERVAL: Duration = Duration::from_millis(20);
/// A recorded sample with no receipt this long after the probe stops fails the run.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24)
}

struct Sample {
    sent_us: u64,
    phase: usize,
    arrived_us: Option<u64>,
    direct: bool,
}

#[derive(Default)]
struct State {
    phases: Vec<String>,
    samples: Vec<Sample>,
    /// Index of the first sample with no receipt.
    pending: usize,
    /// Witness receipts that named a sequence never sent, or carried no MED.
    invalid: u64,
    /// Witness UPDATEs carrying anything but the probe prefix (End-of-RIB excepted).
    witness_other: u64,
    /// Fleet UPDATEs carrying the probe prefix (report-only).
    member_receipts: u64,
    session_error: Option<String>,
}

pub(crate) struct WaitProbe {
    pub(crate) source: u32,
    pub(crate) witness: u32,
    state: Mutex<State>,
    /// Set by [`finish`]: the train stops between samples.
    stop: watch::Sender<bool>,
}

/// The probe prefix in one daemon UPDATE.
#[derive(Debug, PartialEq)]
pub(crate) enum Seen {
    Announced(Option<u32>),
    Withdrawn,
}

impl WaitProbe {
    /// The pair takes the two stub indexes after the fleet.
    pub(crate) fn new(n_peers: u32) -> Self {
        let probe = Self {
            source: n_peers,
            witness: n_peers + 1,
            state: Mutex::default(),
            stop: watch::channel(false).0,
        };
        probe.set_phase("warmup".to_owned());
        probe
    }

    pub(crate) fn set_phase(&self, label: String) {
        self.state.lock().unwrap().phases.push(label);
    }

    /// Record a sample before its UPDATE is written; returns its sequence (from 1).
    fn sent(&self, at_us: u64) -> u32 {
        let mut state = self.state.lock().unwrap();
        let phase = state.phases.len() - 1;
        state.samples.push(Sample {
            sent_us: at_us,
            phase,
            arrived_us: None,
            direct: false,
        });
        u32::try_from(state.samples.len()).unwrap()
    }

    /// Witness side. A receipt older than one already recorded changes nothing.
    fn arrived(&self, med: Option<u32>, at_us: u64) {
        let mut state = self.state.lock().unwrap();
        let Some(seq) = med.map(|seq| seq as usize) else {
            state.invalid += 1;
            return;
        };
        if seq == 0 || seq > state.samples.len() {
            state.invalid += 1;
            return;
        }
        let pending = state.pending;
        for (index, sample) in state.samples[..seq].iter_mut().enumerate().skip(pending) {
            sample.arrived_us = Some(at_us);
            sample.direct = index + 1 == seq;
        }
        state.pending = state.pending.max(seq);
    }

    fn witness_other(&self) {
        self.state.lock().unwrap().witness_other += 1;
    }

    /// A fleet member received the probe prefix.
    pub(crate) fn member_receipt(&self) {
        self.state.lock().unwrap().member_receipts += 1;
    }

    fn session_error(&self, error: String) {
        self.state
            .lock()
            .unwrap()
            .session_error
            .get_or_insert(error);
    }

    fn outstanding(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.samples.len() - state.pending
    }

    /// Remove the probe prefix from a decoded UPDATE so no other accounting sees it.
    pub(crate) fn take(nlri: &mut UnicastNlri, attributes: &[PathAttribute]) -> Option<Seen> {
        let probe = prefix();
        let (announced, withdrawn) = (nlri.v4_ann.len(), nlri.v4_wd.len());
        nlri.v4_ann.retain(|p| *p != probe);
        nlri.v4_wd.retain(|p| *p != probe);
        if nlri.v4_ann.len() != announced {
            let med = attributes.iter().find_map(|attribute| match attribute {
                PathAttribute::Med(med) => Some(*med),
                _ => None,
            });
            Some(Seen::Announced(med))
        } else {
            (nlri.v4_wd.len() != withdrawn).then_some(Seen::Withdrawn)
        }
    }

    /// One JSON object, and the reason the run fails, if any.
    fn summary(&self) -> (String, Option<String>) {
        let state = self.state.lock().unwrap();
        let waits: Vec<(u64, usize, usize)> = state
            .samples
            .iter()
            .enumerate()
            .filter_map(|(index, s)| s.arrived_us.map(|at| (at - s.sent_us, index + 1, s.phase)))
            .collect();
        let coalesced = state
            .samples
            .iter()
            .filter(|s| s.arrived_us.is_some() && !s.direct)
            .count();
        let unarrived = state.samples.len() - waits.len();
        let mut phases = Vec::new();
        for (index, label) in state.phases.iter().enumerate() {
            let mut sorted: Vec<u64> = waits
                .iter()
                .filter(|(_, _, phase)| *phase == index)
                .map(|(wait, _, _)| *wait)
                .collect();
            if sorted.is_empty() {
                continue;
            }
            sorted.sort_unstable();
            phases.push(format!(
                "{{\"phase\":\"{label}\",\"n\":{},\"max_us\":{},\"p99_us\":{}}}",
                sorted.len(),
                sorted[sorted.len() - 1],
                percentile(&sorted, 0.99)
            ));
        }
        let worst = waits
            .iter()
            .max_by_key(|(wait, seq, _)| (*wait, std::cmp::Reverse(*seq)));
        let mut sorted: Vec<u64> = waits.iter().map(|(wait, _, _)| *wait).collect();
        sorted.sort_unstable();
        let json = format!(
            "{{\"source\":{},\"witness\":{},\"interval_ms\":{},\"sent\":{},\"arrived\":{},\
             \"unarrived\":{unarrived},\"coalesced\":{coalesced},\"invalid\":{},\
             \"witness_other_updates\":{},\"member_probe_updates\":{},\
             \"max_us\":{},\"max_seq\":{},\"max_phase\":\"{}\",\"p99_us\":{},\"p50_us\":{},\
             \"phases\":[{}]}}",
            self.source,
            self.witness,
            INTERVAL.as_millis(),
            state.samples.len(),
            waits.len(),
            state.invalid,
            state.witness_other,
            state.member_receipts,
            worst.map_or(0, |w| w.0),
            worst.map_or(0, |w| w.1),
            worst.map_or("none", |w| state.phases[w.2].as_str()),
            percentile(&sorted, 0.99),
            percentile(&sorted, 0.50),
            phases.join(",")
        );
        let error = if let Some(error) = &state.session_error {
            Some(format!("probe session failed: {error}"))
        } else if waits.is_empty() {
            Some("no sample reached the witness".to_owned())
        } else if unarrived > 0 {
            Some(format!("{unarrived} sample(s) never reached the witness"))
        } else if state.invalid > 0 {
            Some(format!("{} invalid probe receipt(s)", state.invalid))
        } else if state.witness_other > 0 {
            Some(format!(
                "pair not isolated: witness received {} other UPDATE(s)",
                state.witness_other
            ))
        } else {
            None
        };
        (json, error)
    }
}

/// Nearest-rank over ascending values, matching [`pct`]'s index rule.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

pub(crate) fn set_phase(ctx: &Ctx, label: impl Into<String>) {
    if let Some(probe) = ctx.wait_probe.as_ref() {
        probe.set_phase(label.into());
    }
}

pub(crate) struct Sessions {
    writers: Vec<tokio::task::JoinHandle<Result<OwnedWriteHalf, String>>>,
    readers: Vec<tokio::task::JoinHandle<()>>,
}

async fn open_session(ctx: &Ctx, i: u32) -> Result<TcpStream, String> {
    let open = stub_open(i, stub_asn(i), dualstack());
    let bytes = encode_message(&Message::Open(open)).map_err(|e| format!("open encode: {e}"))?;
    let keepalive = encode_message(&Message::Keepalive).unwrap();
    let local = stub_addr(i);
    establish_stream_with_retry(
        ctx.daemon,
        local,
        &bytes,
        &keepalive,
        CONNECT_WINDOW,
        required_families(dualstack()),
    )
    .await
    .map(|(stream, _, _)| stream)
    .map_err(|error| format!("stub {i} ({local}): {error}; the scenario needs GEN_UPDATE_WAIT=1"))
}

/// Decode daemon messages until EOF, handing each UPDATE to `on_update`.
async fn read_updates(
    mut reader: OwnedReadHalf,
    mut on_update: impl FnMut(&UpdateMessage) -> Result<(), String>,
) -> Result<(), String> {
    let mut frame = BytesMut::with_capacity(1 << 16);
    let mut tmp = vec![0u8; 1 << 16];
    loop {
        let n = reader
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("daemon closed the session".into());
        }
        frame.extend_from_slice(&tmp[..n]);
        while let Some(total) = peek_message_length(&frame, MAX_MESSAGE_LEN)
            .map_err(|e| e.to_string())?
            .map(usize::from)
            .filter(|total| frame.len() >= *total)
        {
            let mut bytes = frame.split_to(total).freeze();
            match decode_message(&mut bytes, MAX_MESSAGE_LEN).map_err(|e| e.to_string())? {
                Message::Update(update) => on_update(&update)?,
                Message::Notification(n) => {
                    return Err(format!("NOTIFICATION {:?}/{}", n.code, n.subcode))
                }
                _ => {}
            }
        }
    }
}

/// Keepalives, plus the 20 ms train on the source, until [`finish`] stops it.
/// Returns the write half so the session stays up while samples drain.
async fn write_loop(
    ctx: Arc<Ctx>,
    mut writer: OwnedWriteHalf,
    train: Option<Vec<PathAttribute>>,
) -> Result<OwnedWriteHalf, String> {
    let probe = ctx.wait_probe.as_ref().unwrap();
    let mut stop = probe.stop.subscribe();
    let keepalive = encode_message(&Message::Keepalive).unwrap();
    let mut ka = tokio::time::interval(Duration::from_secs(u64::from(HOLD_TIME) / 3));
    let mut tick = tokio::time::interval(INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *stop.borrow_and_update() {
            return Ok(writer);
        }
        tokio::select! {
            biased;
            _ = stop.changed() => {}
            _ = ka.tick() => writer.write_all(&keepalive).await.map_err(|e| format!("keepalive: {e}"))?,
            _ = tick.tick(), if train.is_some() => {
                let mut attrs = train.clone().unwrap();
                let seq = probe.sent(now_us(&ctx));
                attrs.push(PathAttribute::Med(seq));
                let message = announce_msgs_packed(&attrs, &[prefix()], 1, false).pop().unwrap();
                let bytes = encode_message(&message).map_err(|e| format!("encode: {e}"))?;
                writer.write_all(&bytes).await.map_err(|e| format!("write: {e}"))?;
            }
        }
    }
}

/// Establish the source and witness sessions and start the train.
pub(crate) async fn start(ctx: &Arc<Ctx>) -> Option<Sessions> {
    let probe = ctx.wait_probe.as_ref()?;
    let mut sessions = Sessions {
        writers: Vec::new(),
        readers: Vec::new(),
    };
    for (index, train) in [
        (probe.witness, None),
        (probe.source, Some(base_attrs(probe.source))),
    ] {
        let stream = open_session(ctx, index).await.unwrap_or_else(|error| {
            eprintln!("FAIL: update-wait probe session: {error}");
            std::process::exit(1);
        });
        let (reader, writer) = stream.into_split();
        let witness = train.is_none();
        let rctx = Arc::clone(ctx);
        let (eor_tx, eor_rx) = tokio::sync::oneshot::channel();
        let mut eor_tx = Some(eor_tx);
        sessions.readers.push(tokio::spawn(async move {
            let probe = rctx.wait_probe.as_ref().unwrap();
            let result = read_updates(reader, |update| {
                if update.withdrawn_routes.is_empty()
                    && update.path_attributes.is_empty()
                    && update.nlri.is_empty()
                {
                    if let Some(tx) = eor_tx.take() {
                        let _ = tx.send(());
                    }
                    return Ok(());
                }
                if !witness {
                    return Ok(());
                }
                let parsed = update.parse(true, false, &[]).map_err(|e| e.to_string())?;
                let mut nlri = split_unicast_families(&parsed);
                if let Some(Seen::Announced(med)) = WaitProbe::take(&mut nlri, &parsed.attributes) {
                    probe.arrived(med, now_us(&rctx));
                }
                if nlri.families() != 0 {
                    probe.witness_other();
                }
                Ok(())
            })
            .await;
            if let Err(error) = result {
                probe.session_error(format!("stub {index} reader: {error}"));
            }
        }));
        // Sample only once the daemon has finished this session's start-up
        // (its End-of-RIB), so the train never measures our own PeerUp.
        if !matches!(
            tokio::time::timeout(CONNECT_WINDOW, eor_rx).await,
            Ok(Ok(()))
        ) {
            eprintln!("FAIL: update-wait probe session: stub {index} sent no End-of-RIB");
            std::process::exit(1);
        }
        sessions
            .writers
            .push(tokio::spawn(write_loop(Arc::clone(ctx), writer, train)));
    }
    Some(sessions)
}

/// Stop the train, let recorded samples land, print the summary line, then
/// close both sessions.
pub(crate) async fn finish(ctx: &Ctx, sessions: Option<Sessions>) {
    let (Some(probe), Some(sessions)) = (ctx.wait_probe.as_ref(), sessions) else {
        return;
    };
    probe.stop.send_replace(true);
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    let mut writers = Vec::new();
    for mut task in sessions.writers {
        match tokio::time::timeout_at(deadline.into(), &mut task).await {
            Ok(Ok(Ok(writer))) => writers.push(writer),
            Ok(Ok(Err(error))) => probe.session_error(format!("writer: {error}")),
            Ok(Err(error)) => probe.session_error(format!("writer task: {error}")),
            Err(_) => {
                task.abort();
                probe.session_error("writer did not stop before the drain deadline".into());
            }
        }
    }
    while probe.outstanding() > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (json, error) = probe.summary();
    println!("update_wait_summary {json}");
    let cease = encode_message(&Message::Notification(NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_SHUTDOWN,
        bytes::Bytes::new(),
    )))
    .unwrap();
    for mut writer in writers {
        let _ = writer.write_all(&cease).await;
        let _ = writer.shutdown().await;
    }
    for reader in sessions.readers {
        reader.abort();
    }
    if let Some(error) = error {
        eprintln!("FAIL: update-wait probe: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary_field<'a>(json: &'a str, key: &str) -> &'a str {
        let start = json.find(&format!("\"{key}\":")).unwrap() + key.len() + 3;
        let end = json[start..].find([',', '}']).unwrap() + start;
        &json[start..end]
    }

    #[test]
    fn a_receipt_completes_every_earlier_pending_sample_at_its_time() {
        let probe = WaitProbe::new(12);
        assert_eq!((probe.source, probe.witness), (12, 13));
        assert_eq!(probe.sent(1_000), 1);
        probe.sent(21_000);
        probe.set_phase("reload1".to_owned());
        assert_eq!(probe.sent(41_000), 3);
        // A long turn holds 1 and 2; the daemon sends only the newest path.
        probe.arrived(Some(2), 300_000);
        // An older receipt after a newer one changes nothing.
        probe.arrived(Some(1), 400_000);
        assert_eq!(probe.outstanding(), 1);
        probe.arrived(Some(3), 42_500);
        assert_eq!(probe.outstanding(), 0);
        let (json, error) = probe.summary();
        assert_eq!(error, None, "{json}");
        assert_eq!(summary_field(&json, "max_us"), "299000");
        assert_eq!(summary_field(&json, "max_seq"), "1");
        assert_eq!(summary_field(&json, "max_phase"), "\"warmup\"");
        assert_eq!(summary_field(&json, "coalesced"), "1");
        assert!(
            json.contains("{\"phase\":\"warmup\",\"n\":2,\"max_us\":299000,"),
            "{json}"
        );
        assert!(
            json.contains("{\"phase\":\"reload1\",\"n\":1,\"max_us\":1500,"),
            "{json}"
        );
    }

    #[test]
    fn a_missing_receipt_or_an_unsent_sequence_fails_the_probe() {
        let probe = WaitProbe::new(12);
        assert!(probe.summary().1.is_some(), "no samples is not a pass");
        probe.sent(0);
        probe.sent(20_000);
        probe.arrived(Some(1), 5_000);
        assert_eq!(
            probe.summary().1.as_deref(),
            Some("1 sample(s) never reached the witness")
        );
        probe.arrived(Some(2), 25_000);
        assert_eq!(probe.summary().1, None);
        probe.arrived(Some(9), 30_000);
        probe.arrived(None, 30_000);
        let (json, error) = probe.summary();
        assert_eq!(summary_field(&json, "invalid"), "2");
        assert!(error.is_some());
    }

    #[test]
    fn a_sample_recorded_but_never_received_fails_the_probe() {
        // The train records a sample before writing it, so a sample still in
        // flight when the probe stops is outstanding, never absent.
        let probe = WaitProbe::new(12);
        probe.sent(0);
        probe.arrived(Some(1), 2_000);
        probe.sent(20_000);
        assert_eq!(probe.outstanding(), 1);
        let (json, error) = probe.summary();
        assert_eq!(summary_field(&json, "sent"), "2");
        assert_eq!(
            error.as_deref(),
            Some("1 sample(s) never reached the witness")
        );
    }

    #[test]
    fn witness_traffic_or_a_session_error_fails_the_probe() {
        let clean = || {
            let probe = WaitProbe::new(12);
            probe.sent(0);
            probe.arrived(Some(1), 2_000);
            assert_eq!(probe.summary().1, None);
            probe
        };
        let probe = clean();
        probe.witness_other();
        let (json, error) = probe.summary();
        assert_eq!(summary_field(&json, "witness_other_updates"), "1");
        assert!(error.unwrap().starts_with("pair not isolated"));
        let probe = clean();
        probe.member_receipt();
        assert_eq!(
            summary_field(&probe.summary().0, "member_probe_updates"),
            "1"
        );
        assert_eq!(probe.summary().1, None, "member receipts are report-only");
        let probe = clean();
        probe.session_error("stub 13 reader: daemon closed the session".into());
        assert!(probe
            .summary()
            .1
            .unwrap()
            .starts_with("probe session failed"));
    }

    #[test]
    fn take_strips_the_probe_prefix_and_reads_its_sequence() {
        let other = base_prefix(7);
        let mut nlri = UnicastNlri {
            v4_ann: vec![prefix()],
            v4_wd: vec![other],
            ..UnicastNlri::default()
        };
        let attrs = [PathAttribute::Origin(Origin::Igp), PathAttribute::Med(41)];
        assert_eq!(
            WaitProbe::take(&mut nlri, &attrs),
            Some(Seen::Announced(Some(41)))
        );
        assert!(nlri.v4_ann.is_empty());
        assert_eq!(nlri.v4_wd, vec![other]);
        assert_eq!(WaitProbe::take(&mut nlri, &attrs), None);
        let mut probe_only = UnicastNlri {
            v4_wd: vec![prefix()],
            ..UnicastNlri::default()
        };
        assert_eq!(WaitProbe::take(&mut probe_only, &[]), Some(Seen::Withdrawn));
        assert_eq!(probe_only.families(), 0);
    }
}
