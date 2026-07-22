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
    adj_rib_out: HashMap<u64, u64>,
    readiness_observations: usize,
}

impl Actor {
    async fn resync_and_commit(&mut self) {
        let mut cursor = self.adj_rib_out.iter();
        while let Some((&key, _)) = cursor.next() {
            self.readiness_observations += 1;
            YieldOnce(false).await;
            self.adj_rib_out.remove(&key);
        }
    }
}

fn main() {
    let mut actor = Actor {
        adj_rib_out: HashMap::from([(7, 70), (9, 90)]),
        readiness_observations: 0,
    };
    let _future = actor.resync_and_commit();
}
