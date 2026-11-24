//! Ordinary primary-FIFO admission through receipt of the same UPDATE at the witness.
use std::{
    io,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use rustbgpd_rib::update::RibUpdate;
use tokio::{
    sync::{mpsc, watch, Notify},
    time,
};

use super::marker_prefix;
use crate::{empty_routes_received, invalid_stat, route, source_addr, INGRESS_FLOOD};

const SPACING: Duration = Duration::from_millis(5);
const MARKER_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) struct Sample {
    pub(super) seq: u16,
    admitted: Instant,
    arrived: Instant,
}

pub(super) async fn send(
    tx: &mpsc::Sender<RibUpdate>,
    arrivals: &mut mpsc::UnboundedReceiver<(u16, Instant)>,
    seq: u16,
) -> io::Result<(Instant, Instant)> {
    let source = source_addr(INGRESS_FLOOD);
    let update = empty_routes_received(
        IpAddr::V4(source),
        vec![route(marker_prefix(seq), source, 100)],
    );
    time::timeout(MARKER_TIMEOUT, async {
        let slot = tx
            .reserve()
            .await
            .map_err(|_| invalid_stat("RIB input closed"))?;
        let admitted = Instant::now();
        slot.send(update);
        let (seen, arrived) = arrivals
            .recv()
            .await
            .ok_or_else(|| invalid_stat("marker witness closed"))?;
        if seen != seq || arrived < admitted {
            return Err(invalid_stat(format!(
                "expected witness marker {seq} after admission, received {seen}"
            )));
        }
        Ok((admitted, arrived))
    })
    .await
    .map_err(|_| invalid_stat(format!("timed out admitting or witnessing marker {seq}")))?
}

pub(super) async fn train(
    tx: mpsc::Sender<RibUpdate>,
    mut arrivals: mpsc::UnboundedReceiver<(u16, Instant)>,
    mut stop: watch::Receiver<bool>,
    first_page: Arc<Notify>,
) -> io::Result<(Vec<Sample>, mpsc::UnboundedReceiver<(u16, Instant)>)> {
    let mut samples = Vec::new();
    while !*stop.borrow_and_update() {
        let seq = u16::try_from(samples.len() + 1)
            .ok()
            .filter(|seq| *seq < u16::MAX)
            .ok_or_else(|| invalid_stat("marker train reached the final fence sequence"))?;
        // Once sent, the witness must account for this sample even if the joiner
        // observes EoR first. The stop watch only interrupts the inter-marker wait.
        let (admitted, arrived) = send(&tx, &mut arrivals, seq).await?;
        samples.push(Sample {
            seq,
            admitted,
            arrived,
        });
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            changed = stop.changed() => {
                changed.map_err(|_| invalid_stat("marker stop watch closed before EoR"))?;
            }
            // The joiner uses notify_one, retaining a permit during an outstanding send.
            () = first_page.notified() => {}
            () = time::sleep_until((arrived + SPACING).into()) => {}
        }
    }
    Ok((samples, arrivals))
}

#[derive(Default)]
struct Waits {
    count: usize,
    max: (Duration, u16),
}

impl Waits {
    fn add(&mut self, sample: &Sample) {
        self.count += 1;
        self.max = self.max.max((sample.arrived - sample.admitted, sample.seq));
    }
}

#[derive(Default)]
struct Window {
    build: Waits,
    replay: Waits,
    whole: Waits,
    inflight_at_eor: usize,
}

impl Window {
    fn observe(
        &mut self,
        sample: &Sample,
        start: Instant,
        first: Instant,
        eor: Instant,
    ) -> &'static str {
        // Charge the full latency whenever the wait overlaps the join, including
        // a marker already outstanding at PeerUp or still outstanding at EoR.
        if sample.admitted < eor && (sample.admitted >= start || sample.arrived > start) {
            self.whole.add(sample);
            self.inflight_at_eor += usize::from(sample.arrived > eor);
        }
        if sample.admitted < start {
            "pre"
        } else if sample.admitted < first {
            self.build.add(sample);
            "build"
        } else if sample.admitted < eor {
            self.replay.add(sample);
            "replay"
        } else {
            "post"
        }
    }

    fn validate(&self, paced: bool) -> io::Result<()> {
        if self.build.count == 0 || (paced && self.replay.count == 0) {
            return Err(invalid_stat(format!(
                "missing marker admission during cold join (build={}, replay={}, paced={paced})",
                self.build.count, self.replay.count
            )));
        }
        Ok(())
    }
}

fn offset(start: Instant, at: Instant) -> String {
    if at < start {
        format!("-{}", (start - at).as_micros())
    } else {
        (at - start).as_micros().to_string()
    }
}

pub(super) fn report(
    samples: &[Sample],
    start: Instant,
    first: Instant,
    eor: Instant,
    paced: bool,
) -> (Duration, io::Result<()>) {
    if first < start || eor < first {
        return (
            Duration::ZERO,
            Err(invalid_stat("first route or EoR outside cold join window")),
        );
    }
    let mut window = Window::default();
    for sample in samples {
        let phase = window.observe(sample, start, first, eor);
        println!(
            "cold_join_marker seq={} phase={phase} admit_us={} arrived_us={} wait_us={}",
            sample.seq,
            offset(start, sample.admitted),
            offset(start, sample.arrived),
            (sample.arrived - sample.admitted).as_micros()
        );
    }
    let Window {
        build,
        replay,
        whole,
        inflight_at_eor,
    } = &window;
    println!("cold_join_marker_train markers={} first_us={} eor_us={} build_n={} build_max_wait_us={} build_max_seq={} replay_n={} replay_max_wait_us={} replay_max_seq={} admitted_pre_eor={} inflight_at_eor={} whole_n={} join_max_wait_us={} join_max_seq={}",
        samples.len(), offset(start, first), offset(start, eor), build.count, build.max.0.as_micros(), build.max.1,
        replay.count, replay.max.0.as_micros(), replay.max.1, build.count + replay.count, inflight_at_eor,
        whole.count, whole.max.0.as_micros(), whole.max.1);
    (whole.max.0, window.validate(paced))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(points: &[(u64, u64)]) -> Window {
        let origin = Instant::now();
        let at = |ms| origin + Duration::from_millis(ms);
        let mut window = Window::default();
        for (i, &(admit, recv)) in points.iter().enumerate() {
            let sample = Sample {
                seq: u16::try_from(i + 1).unwrap(),
                admitted: at(admit),
                arrived: at(recv),
            };
            window.observe(&sample, at(10), at(20), at(30));
        }
        window
    }

    #[test]
    fn whole_window_includes_the_full_wait_across_eor_and_excludes_post_join_work() {
        let w = window(&[(2, 3), (4, 11), (12, 18), (20, 63), (64, 999)]);
        assert!(w.validate(true).is_ok());
        assert_eq!(
            (
                w.build.count,
                w.replay.count,
                w.whole.count,
                w.inflight_at_eor
            ),
            (1, 1, 3, 1)
        );
        assert_eq!(w.whole.max, (Duration::from_millis(43), 4));
    }

    #[test]
    fn a_build_wait_outlasting_eor_does_not_prove_a_paced_replay_was_probed() {
        let w = window(&[(11, 40), (41, 42)]);
        assert_eq!(w.inflight_at_eor, 1);
        assert!(w.validate(false).is_ok());
        assert!(w.validate(true).is_err());
        assert!(window(&[(5, 9), (30, 41)]).validate(false).is_err());
    }
}
