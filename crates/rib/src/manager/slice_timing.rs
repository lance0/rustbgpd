//! Direct measurement of synchronous RIB actor slices.
//!
//! [`TimedActor`] times every poll of the actor future, which is how long the
//! actor holds a runtime worker without yielding. Within a poll, the
//! timeline is also cut at every [`SAMPLE_EVERY`]th readiness checkpoint and
//! at the poll end; each piece is one slice, labelled by the most recent
//! checkpoint at or before its end. The tail after a cut keeps the cut
//! checkpoint's label, so work after the last checkpoint is never dropped. Checkpoints fire per item in long loops, so a clock read on
//! every one measurably slowed full-table work: an unsampled checkpoint costs
//! one thread-local cell update. A long gap between two checkpoints stays
//! inside one slice, so a stall is never split. The recorder flushes to the
//! shared metrics once per poll.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use rustbgpd_telemetry::metrics::{RibActorSliceRecorder, RibActorSliceStage};

/// Checkpoints per sampled clock read.
const SAMPLE_EVERY: u32 = 64;

struct Active {
    recorder: Box<RibActorSliceRecorder>,
    /// Start of the open slice.
    mark: Instant,
}

/// A checkpoint's name; `None` for an unnamed checkpoint.
type Stage = Option<&'static str>;

#[derive(Clone, Copy)]
struct Countdown {
    /// Checkpoints left before the next cut; 0 outside a timed poll.
    remaining: u32,
    /// The most recent checkpoint in this poll, if any; it labels the
    /// poll-end slice.
    last: Option<Stage>,
}

const IDLE: Countdown = Countdown {
    remaining: 0,
    last: None,
};

thread_local! {
    /// Set only while this thread is inside a [`TimedActor`] poll.
    static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) };
    static COUNTDOWN: Cell<Countdown> = const { Cell::new(IDLE) };
}

/// Note a readiness checkpoint. Outside a timed actor poll (direct
/// unit-test calls, other threads) this records nothing.
#[inline]
pub(super) fn checkpoint(stage: Stage) {
    COUNTDOWN.with(|countdown| match countdown.get().remaining {
        0 => {}
        1 => {
            countdown.set(Countdown {
                remaining: SAMPLE_EVERY,
                last: Some(stage),
            });
            cut(stage, Instant::now());
        }
        remaining => countdown.set(Countdown {
            remaining: remaining - 1,
            last: Some(stage),
        }),
    });
}

#[cold]
fn cut(stage: Stage, now: Instant) {
    ACTIVE.with_borrow_mut(|active| {
        if let Some(active) = active {
            let elapsed = now.duration_since(active.mark);
            active.mark = now;
            let stage = stage.map_or(RibActorSliceStage::Other, classify);
            active.recorder.observe(stage, elapsed);
        }
    });
}

/// Collapse a checkpoint name into the closed `stage` label set.
fn classify(name: &str) -> RibActorSliceStage {
    if name.starts_with("selection_") {
        RibActorSliceStage::Selection
    } else if name.starts_with("flowspec_") {
        RibActorSliceStage::Flowspec
    } else if name == "refresh" {
        RibActorSliceStage::Refresh
    } else if name.contains("retirement")
        || name.contains("retain")
        || name.contains("cleanup")
        || name.ends_with("_gc")
        || name.starts_with("peer_down_")
    {
        RibActorSliceStage::Retirement
    } else if matches!(
        name,
        "family_commit"
            | "shared_inventory"
            | "fallback_baseline"
            | "dataset_staging"
            | "initial_group_replay"
            | "group_prior_materialization"
    ) || name.starts_with("staging_")
        || name.starts_with("capture_")
        || name.starts_with("summary_")
    {
        RibActorSliceStage::UpdateGroup
    } else {
        RibActorSliceStage::Other
    }
}

/// Times each poll of the wrapped actor future.
pub(super) struct TimedActor<F> {
    inner: Pin<Box<F>>,
    recorder: Option<Box<RibActorSliceRecorder>>,
}

impl<F> TimedActor<F> {
    pub(super) fn new(inner: F, recorder: RibActorSliceRecorder) -> Self {
        Self {
            inner: Box::pin(inner),
            recorder: Some(Box::new(recorder)),
        }
    }
}

/// Clears the thread-local state even if the actor poll panics.
struct ClearOnDrop;

impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        COUNTDOWN.set(IDLE);
        ACTIVE.with_borrow_mut(Option::take);
    }
}

impl<F: Future> Future for TimedActor<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = &mut *self;
        let Some(recorder) = this.recorder.take() else {
            return this.inner.as_mut().poll(cx);
        };
        let started = Instant::now();
        ACTIVE.with_borrow_mut(|active| {
            *active = Some(Active {
                recorder,
                mark: started,
            });
        });
        COUNTDOWN.set(Countdown {
            remaining: SAMPLE_EVERY,
            last: None,
        });
        let guard = ClearOnDrop;
        let output = this.inner.as_mut().poll(cx);
        let ended = Instant::now();
        if let Some(stage) = COUNTDOWN.get().last {
            cut(stage, ended);
        }
        let active = ACTIVE.with_borrow_mut(Option::take);
        drop(guard);
        if let Some(mut active) = active {
            active
                .recorder
                .observe(RibActorSliceStage::ActorPoll, ended.duration_since(started));
            active.recorder.flush();
            this.recorder = Some(active.recorder);
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_telemetry::BgpMetrics;

    /// Retirement samples above 60 ms, and the published retirement maximum.
    fn retirement_stall(metrics: &BgpMetrics) -> (u64, f64) {
        metrics.publish_render_window_maxima();
        let families = metrics.registry().gather();
        let series = |name: &str| {
            families
                .iter()
                .find(|family| family.name() == name)
                .and_then(|family| {
                    family
                        .get_metric()
                        .iter()
                        .find(|metric| metric.get_label()[0].value() == "retirement")
                })
                .expect("pre-initialised retirement series")
        };
        let histogram = series("bgp_rib_actor_slice_seconds").get_histogram();
        let at = |bound: f64| {
            histogram
                .get_bucket()
                .iter()
                .find(|bucket| (bucket.upper_bound() - bound).abs() < 1e-9)
                .expect("configured bucket edge")
                .cumulative_count()
        };
        let max = series("bgp_rib_actor_slice_max_microseconds")
            .get_gauge()
            .get_value();
        (at(2.0) - at(0.06), max / 1e6)
    }

    /// Exactly `SAMPLE_EVERY` quick checkpoints put the poll's only cut on
    /// the last one; the stall after it must still reach that stage.
    #[tokio::test]
    async fn stall_after_a_boundary_checkpoint_keeps_its_stage() {
        let metrics = BgpMetrics::new();
        TimedActor::new(
            async {
                for _ in 0..SAMPLE_EVERY {
                    checkpoint(Some("peer_adj_out_retirement"));
                }
                std::thread::sleep(std::time::Duration::from_millis(70));
            },
            metrics.rib_actor_slice_recorder(),
        )
        .await;
        let (samples, max) = retirement_stall(&metrics);
        assert_eq!(samples, 1, "the tail stall is a retirement slice");
        assert!((0.07..2.0).contains(&max), "retirement max {max}");
    }

    #[test]
    fn checkpoint_names_collapse_into_the_closed_stage_set() {
        for (name, stage) in [
            ("selection_recompute", RibActorSliceStage::Selection),
            ("flowspec_validation", RibActorSliceStage::Flowspec),
            ("refresh", RibActorSliceStage::Refresh),
            ("peer_adj_out_retirement", RibActorSliceStage::Retirement),
            ("terminal_cleanup", RibActorSliceStage::Retirement),
            ("peer_attribute_gc", RibActorSliceStage::Retirement),
            ("admitted_prior_retain", RibActorSliceStage::Retirement),
            ("peer_down_key_collection", RibActorSliceStage::Retirement),
            ("family_commit", RibActorSliceStage::UpdateGroup),
            ("staging_evpn", RibActorSliceStage::UpdateGroup),
            ("capture_evpn", RibActorSliceStage::UpdateGroup),
            ("summary_terminal", RibActorSliceStage::UpdateGroup),
            ("outbound_limits", RibActorSliceStage::Other),
        ] {
            assert_eq!(classify(name), stage, "{name}");
        }
    }
}
