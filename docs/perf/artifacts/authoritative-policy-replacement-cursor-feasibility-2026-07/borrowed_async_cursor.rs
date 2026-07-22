use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct Actor {
    canonical: HashMap<u64, u64>,
    readiness_observations: usize,
}

impl Actor {
    async fn run_borrowed_cursor(&mut self) {
        let mut cursor = self.canonical.iter();
        while cursor.next().is_some() {
            self.readiness_observations += self.canonical.len();
            YieldOnce(false).await;
        }
    }
}

fn main() {
    let mut actor = Actor {
        canonical: HashMap::from([(7, 70), (9, 90)]),
        readiness_observations: 0,
    };
    let _future = actor.run_borrowed_cursor();
}
