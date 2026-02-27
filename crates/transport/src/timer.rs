use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rustbgpd_fsm::TimerType;
use tokio::time::Sleep;

/// Manages the three BGP session timers (connect-retry, hold, keepalive).
///
/// Each timer is an `Option<Pin<Box<Sleep>>>` — `None` means the timer is
/// stopped, `Some` means it is running.
#[derive(Debug, Default)]
pub struct Timers {
    pub connect_retry: Option<Pin<Box<Sleep>>>,
    pub hold: Option<Pin<Box<Sleep>>>,
    pub keepalive: Option<Pin<Box<Sleep>>>,
}

impl Timers {
    /// Start (or restart) a timer with the given duration in seconds.
    pub fn start(&mut self, timer_type: TimerType, secs: u32) {
        let slot = self.slot_mut(timer_type);
        *slot = Some(Box::pin(tokio::time::sleep(Duration::from_secs(u64::from(secs)))));
    }

    /// Stop a running timer.
    pub fn stop(&mut self, timer_type: TimerType) {
        *self.slot_mut(timer_type) = None;
    }

    /// Stop all timers.
    pub fn stop_all(&mut self) {
        self.connect_retry = None;
        self.hold = None;
        self.keepalive = None;
    }

    fn slot_mut(&mut self, timer_type: TimerType) -> &mut Option<Pin<Box<Sleep>>> {
        match timer_type {
            TimerType::ConnectRetry => &mut self.connect_retry,
            TimerType::Hold => &mut self.hold,
            TimerType::Keepalive => &mut self.keepalive,
        }
    }
}

/// A future that resolves when the timer fires, or pends forever if `None`.
///
/// This is a freestanding function (not a method) so it can be used in
/// `tokio::select!` without conflicting with other `&mut self` borrows.
pub fn poll_timer(
    timer: &mut Option<Pin<Box<Sleep>>>,
) -> PollTimer<'_> {
    PollTimer { timer }
}

/// Future returned by [`poll_timer`].
pub struct PollTimer<'a> {
    timer: &'a mut Option<Pin<Box<Sleep>>>,
}

impl Future for PollTimer<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        match this.timer.as_mut() {
            Some(sleep) => sleep.as_mut().poll(cx),
            None => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_and_stop_timer() {
        let mut timers = Timers::default();
        assert!(timers.connect_retry.is_none());

        timers.start(TimerType::ConnectRetry, 30);
        assert!(timers.connect_retry.is_some());

        timers.stop(TimerType::ConnectRetry);
        assert!(timers.connect_retry.is_none());
    }

    #[tokio::test]
    async fn stop_all_clears_everything() {
        let mut timers = Timers::default();
        timers.start(TimerType::ConnectRetry, 10);
        timers.start(TimerType::Hold, 90);
        timers.start(TimerType::Keepalive, 30);

        timers.stop_all();
        assert!(timers.connect_retry.is_none());
        assert!(timers.hold.is_none());
        assert!(timers.keepalive.is_none());
    }

    #[tokio::test]
    async fn poll_timer_fires() {
        let mut timer: Option<Pin<Box<Sleep>>> =
            Some(Box::pin(tokio::time::sleep(Duration::from_millis(1))));
        poll_timer(&mut timer).await;
        // Completed without hanging
    }

    #[tokio::test]
    async fn poll_timer_none_pends() {
        let mut timer: Option<Pin<Box<Sleep>>> = None;
        // Should pend forever — use select to prove it doesn't fire
        tokio::select! {
            () = poll_timer(&mut timer) => {
                panic!("poll_timer(None) should not resolve");
            }
            () = tokio::time::sleep(Duration::from_millis(10)) => {
                // Expected: the sleep won, poll_timer pended
            }
        }
    }
}
