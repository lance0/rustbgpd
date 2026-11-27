//! Whole-run unrelated-UPDATE wait probe (`RELOADSTALL_UPDATE_WAIT=1`).
//!
//! One stable stub announces a prefix nobody else touches every 20 ms, each
//! UPDATE carrying its sequence number as MED. A second stable stub records
//! when each one arrives. The wait is the quantity rrharness's cold-join
//! marker train reports: the time from handing the UPDATE to the daemon's
//! ordinary input path until an already converged witness receives it. Here
//! the input path is the source session's socket, and the send time is taken
//! immediately before the writer writes the encoded UPDATE.
//!
//! Both stubs sit below the churners and above every flapped or reload-changed
//! member, so neither the source nor the witness has a table transfer or
//! re-export of its own queued: a long wait is time the UPDATE spent behind
//! other work in the daemon, not in its own session's backlog.
//!
//! Each UPDATE replaces the previous one, so the daemon may send only the
//! newest pending path. A receipt of sequence `s` completes every earlier
//! sample still waiting, at that receipt time; those count as `coalesced`.
//! Samples are charged to the phase in which they were sent.

use std::sync::Mutex;

use super::*;

pub(crate) const INTERVAL: Duration = Duration::from_millis(20);
/// A sent sample with no receipt this long after the probe stops fails the run.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 0), 24)
}

/// The probe's source and witness: the two highest stubs below the churners.
/// Stub 0 is the max-prefix trip member, and reload mode changes the first
/// `changed_peers`, so both must lie above `max(1, flapped or changed)`.
pub(crate) fn stubs(
    n_peers: u32,
    changed_peers: u32,
    flapstorm: Option<u32>,
) -> Option<(u32, u32)> {
    let source = n_peers.checked_sub(CHURNERS + 1)?;
    let observer = source.checked_sub(1)?;
    let floor = flapstorm.unwrap_or(changed_peers).max(1);
    (observer >= floor).then_some((source, observer))
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
}

pub(crate) struct WaitProbe {
    pub(crate) source: u32,
    pub(crate) observer: u32,
    state: Mutex<State>,
}

/// The probe prefix in one daemon UPDATE.
#[derive(Debug, PartialEq)]
pub(crate) enum Seen {
    Announced(Option<u32>),
    Withdrawn,
}

impl WaitProbe {
    pub(crate) fn new(source: u32, observer: u32) -> Self {
        let probe = Self {
            source,
            observer,
            state: Mutex::default(),
        };
        probe.set_phase("warmup".to_owned());
        probe
    }

    pub(crate) fn set_phase(&self, label: String) {
        self.state.lock().unwrap().phases.push(label);
    }

    /// Writer side, immediately before the write. Sequences start at 1.
    pub(crate) fn sent(&self, seq: u32, at_us: u64) {
        let mut state = self.state.lock().unwrap();
        if seq as usize != state.samples.len() + 1 {
            state.invalid += 1;
            return;
        }
        let phase = state.phases.len() - 1;
        state.samples.push(Sample {
            sent_us: at_us,
            phase,
            arrived_us: None,
            direct: false,
        });
    }

    /// Witness side. A receipt older than one already recorded changes nothing.
    pub(crate) fn arrived(&self, med: Option<u32>, at_us: u64) {
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

    /// One JSON object; `None` when the run measured nothing it can stand on.
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
            "{{\"source\":{},\"observer\":{},\"interval_ms\":{},\"sent\":{},\"arrived\":{},\
             \"unarrived\":{unarrived},\"coalesced\":{coalesced},\"invalid\":{},\
             \"max_us\":{},\"max_seq\":{},\"max_phase\":\"{}\",\"p99_us\":{},\"p50_us\":{},\
             \"phases\":[{}]}}",
            self.source,
            self.observer,
            INTERVAL.as_millis(),
            state.samples.len(),
            waits.len(),
            state.invalid,
            worst.map_or(0, |w| w.0),
            worst.map_or(0, |w| w.1),
            worst.map_or("none", |w| state.phases[w.2].as_str()),
            percentile(&sorted, 0.99),
            percentile(&sorted, 0.50),
            phases.join(",")
        );
        let error = if waits.is_empty() {
            Some("no sample reached the witness".to_owned())
        } else if unarrived > 0 {
            Some(format!("{unarrived} sample(s) never reached the witness"))
        } else if state.invalid > 0 {
            Some(format!(
                "{} invalid probe write(s) or receipt(s)",
                state.invalid
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

/// Start the 20 ms train through the source stub's writer.
pub(crate) fn start(ctx: &Arc<Ctx>, stubs: &[Stub]) -> Option<tokio::task::JoinHandle<()>> {
    let probe = ctx.wait_probe.as_ref()?;
    let tx = stubs[probe.source as usize].tx.clone();
    let base = base_attrs(probe.source);
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        for seq in 1u32.. {
            tick.tick().await;
            let mut attrs = base.clone();
            attrs.push(PathAttribute::Med(seq));
            let mut message = announce_msgs_packed(&attrs, &[prefix()], 1, false);
            let outbound = Outbound {
                message: message.pop().unwrap(),
                replay: None,
                probe: Some(seq),
            };
            if tx.send(outbound).await.is_err() {
                return;
            }
        }
    }))
}

/// Stop the train, let in-flight samples land, and print the summary line.
pub(crate) async fn finish(ctx: &Ctx, task: Option<tokio::task::JoinHandle<()>>) {
    let (Some(probe), Some(task)) = (ctx.wait_probe.as_ref(), task) else {
        return;
    };
    task.abort();
    let _ = task.await;
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    while probe.outstanding() > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (json, error) = probe.summary();
    println!("update_wait_summary {json}");
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
        let probe = WaitProbe::new(3, 2);
        probe.sent(1, 1_000);
        probe.sent(2, 21_000);
        probe.set_phase("reload1".to_owned());
        probe.sent(3, 41_000);
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
        let probe = WaitProbe::new(3, 2);
        assert!(probe.summary().1.is_some(), "no samples is not a pass");
        probe.sent(1, 0);
        probe.sent(2, 20_000);
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

    #[test]
    fn probe_stubs_avoid_churners_flapped_changed_and_trip_members() {
        // 700 peers: churners are 692..700.
        assert_eq!(stubs(700, 600, None), Some((691, 690)));
        assert_eq!(stubs(700, 700, Some(50)), Some((691, 690)));
        assert_eq!(
            stubs(700, 700, None),
            None,
            "every observer changes on reload"
        );
        assert_eq!(stubs(12, 2, None), Some((3, 2)));
        assert_eq!(stubs(12, 3, None), None);
        assert_eq!(stubs(11, 0, Some(0)), Some((2, 1)));
        assert_eq!(stubs(10, 0, Some(0)), None, "stub 0 is the trip member");
        assert_eq!(stubs(8, 0, Some(0)), None);
    }
}
