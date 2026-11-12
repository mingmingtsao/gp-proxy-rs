//! Bounded admission around futures-util's caller-driven Shared future.
use super::{CacheTime, MAX_DNS_WAITERS_PER_NAME};
use futures_util::future::{BoxFuture, FutureExt, Shared, WeakShared};
use std::{
    future::Future,
    io,
    net::Ipv4Addr,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

#[derive(Clone)]
pub(super) struct Answer {
    addresses: Vec<Ipv4Addr>,
    received: CacheTime,
    ttl: Duration,
}

impl Answer {
    pub(super) fn new(addresses: Vec<Ipv4Addr>, ttl: u32, received: CacheTime) -> Self {
        Self {
            addresses,
            received,
            ttl: Duration::from_secs(u64::from(ttl.min(300))),
        }
    }

    fn fresh(&self) -> bool {
        // TTL zero is valid for callers of this transaction, but never for a
        // new transaction or the cache. The common ten-second budget remains.
        if self.ttl.is_zero() {
            return true;
        }
        let now = CacheTime::now();
        now.monotonic
            .saturating_duration_since(self.received.monotonic)
            < self.ttl
            && now
                .wall
                .duration_since(self.received.wall)
                .is_ok_and(|elapsed| elapsed < self.ttl)
    }
}

type Query = BoxFuture<'static, Result<Answer, io::ErrorKind>>;

pub(super) struct Entry {
    query: WeakShared<Query>,
    slots: Weak<Semaphore>,
    changed: Weak<Notify>,
    deadline: Instant,
}

impl Entry {
    pub(super) fn new(
        deadline: Instant,
        future: impl Future<Output = io::Result<Answer>> + Send + 'static,
    ) -> (Self, Lookup) {
        let query = future
            .map(|result| result.map_err(|error| error.kind()))
            .boxed()
            .shared();
        let slots = Arc::new(Semaphore::new(MAX_DNS_WAITERS_PER_NAME));
        let changed = Arc::new(Notify::new());
        let permit = slots.clone().try_acquire_owned().unwrap();
        (
            Self {
                query: query.downgrade().unwrap(),
                slots: Arc::downgrade(&slots),
                changed: Arc::downgrade(&changed),
                deadline,
            },
            Lookup {
                query: Some(query),
                _permit: permit,
                changed,
                deadline,
            },
        )
    }

    pub(super) fn is_pending(&self) -> bool {
        self.query
            .upgrade()
            .is_some_and(|query| query.peek().is_none())
    }

    pub(super) fn join(&self) -> Option<io::Result<Lookup>> {
        let query = self.query.upgrade()?;
        // A paused subscriber can retain completed output past TTL. New callers
        // must use the cache or start a fresh transaction.
        if query.peek().is_some() {
            return None;
        }
        let slots = self.slots.upgrade()?;
        let changed = self.changed.upgrade()?;
        Some(
            slots
                .try_acquire_owned()
                .map(|permit| Lookup {
                    query: Some(query),
                    _permit: permit,
                    changed,
                    deadline: self.deadline,
                })
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "too many callers waiting for the same tunnel DNS query",
                    )
                }),
        )
    }
}

pub(super) struct Lookup {
    query: Option<Shared<Query>>,
    _permit: OwnedSemaphorePermit,
    changed: Arc<Notify>,
    deadline: Instant,
}

impl Drop for Lookup {
    fn drop(&mut self) {
        // Shared can wake a follower while another task is still polling it.
        // If that driver is then cancelled, its queued wake disappears. Remove
        // our Shared subscription before asking the remaining tasks to repoll.
        // The final subscription also drops the query and its I/O synchronously.
        drop(self.query.take());
        self.changed.notify_waiters();
    }
}

impl Lookup {
    pub(super) async fn run(mut self) -> io::Result<Vec<Ipv4Addr>> {
        let timed_out =
            || io::Error::new(io::ErrorKind::TimedOut, "tunnel DNS lookup result expired");
        let answer = loop {
            if Instant::now() >= self.deadline {
                return Err(timed_out());
            }
            let changed = self.changed.notified();
            tokio::pin!(changed);
            // Register before polling Shared: cancellation may happen between
            // its POLLING response and our return to the executor.
            changed.as_mut().enable();
            tokio::select! {
                biased;
                answer = self.query.as_mut().unwrap() => break answer,
                _ = &mut changed => {}
            }
        }
        .map_err(|kind| io::Error::new(kind, "tunnel DNS lookup failed"))?;
        if Instant::now() >= self.deadline || !answer.fresh() {
            return Err(timed_out());
        }
        // Retain admission through completion/cancellation. No task owns work.
        Ok(answer.addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn first_waiter_has_no_unique_ownership_and_completion_releases_future() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let guard = DropCount(dropped.clone());
        let (send, receive) = tokio::sync::oneshot::channel();
        let (entry, first) = Entry::new(Instant::now() + Duration::from_secs(10), async move {
            let _guard = guard;
            receive.await.unwrap();
            Ok(Answer::new(vec![Ipv4Addr::LOCALHOST], 30, CacheTime::now()))
        });
        let next = entry.join().unwrap().unwrap();
        drop(first);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        send.send(()).unwrap();
        assert_eq!(next.run().await.unwrap(), [Ipv4Addr::LOCALHOST]);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(entry.query.upgrade().is_none());
    }

    #[tokio::test]
    async fn completed_results_cannot_be_rejoined_while_an_original_waiter_is_parked() {
        for ttl in [0, 30] {
            let (entry, first) = Entry::new(Instant::now() + Duration::from_secs(10), async move {
                Ok(Answer::new(
                    vec![Ipv4Addr::LOCALHOST],
                    ttl,
                    CacheTime::now(),
                ))
            });
            let parked = entry.join().unwrap().unwrap();
            first.run().await.unwrap();
            assert!(entry.query.upgrade().is_some());
            assert!(!entry.is_pending());
            assert!(entry.join().is_none());
            drop(parked);
            assert!(entry.query.upgrade().is_none());
        }
    }

    #[tokio::test]
    async fn last_waiter_drop_releases_an_unpolled_future_and_its_captures() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let guard = DropCount(dropped.clone());
        let (entry, first) = Entry::new(Instant::now() + Duration::from_secs(10), async move {
            let _guard = guard;
            std::future::pending::<io::Result<Answer>>().await
        });
        let last = entry.join().unwrap().unwrap();
        drop(first);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(last);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(entry.query.upgrade().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelling_a_polling_driver_reawakens_a_follower_that_consumed_its_wake() {
        use std::{
            future::poll_fn,
            sync::{mpsc, Mutex},
            task::{Poll, Waker},
        };

        let dropped = Arc::new(AtomicUsize::new(0));
        let guard = DropCount(dropped.clone());
        let (entered_send, entered_receive) = tokio::sync::oneshot::channel();
        let mut entered_send = Some(entered_send);
        let (release_send, release_receive) = mpsc::channel();
        let deferred = Arc::new(Mutex::new(None::<Waker>));
        let saved = deferred.clone();
        let mut inner_polls = 0;
        let (entry, follower_lookup) = Entry::new(
            Instant::now() + Duration::from_secs(10),
            poll_fn(move |context| {
                let _retain_until_completion = &guard;
                inner_polls += 1;
                match inner_polls {
                    1 => Poll::Pending,
                    2 => {
                        *saved.lock().unwrap() = Some(context.waker().clone());
                        entered_send.take().unwrap().send(()).unwrap();
                        // A bounded gate holds Shared in POLLING while another
                        // Tokio worker consumes an asynchronous I/O notification.
                        release_receive
                            .recv_timeout(Duration::from_secs(2))
                            .unwrap();
                        Poll::Pending
                    }
                    _ => Poll::Ready(Ok(Answer::new(
                        vec![Ipv4Addr::LOCALHOST],
                        30,
                        CacheTime::now(),
                    ))),
                }
            }),
        );
        let driver_lookup = entry.join().unwrap().unwrap();
        let (registered_send, registered_receive) = tokio::sync::oneshot::channel();
        let mut registered_send = Some(registered_send);
        let (repolled_send, repolled_receive) = tokio::sync::oneshot::channel();
        let mut repolled_send = Some(repolled_send);
        let mut follower_future = Box::pin(follower_lookup.run());
        let mut follower_polls = 0;
        let mut follower = tokio::spawn(poll_fn(move |context| {
            follower_polls += 1;
            let result = follower_future.as_mut().poll(context);
            if follower_polls == 1 {
                registered_send.take().unwrap().send(()).unwrap();
            }
            if follower_polls == 2 {
                assert!(result.is_pending());
                repolled_send.take().unwrap().send(()).unwrap();
            }
            result
        }));
        tokio::time::timeout(Duration::from_secs(2), registered_receive)
            .await
            .unwrap()
            .unwrap();
        let driver = tokio::spawn(driver_lookup.run());
        tokio::time::timeout(Duration::from_secs(2), entered_receive)
            .await
            .unwrap()
            .unwrap();
        let notifier = deferred.lock().unwrap().take().unwrap();
        notifier.wake_by_ref();
        tokio::time::timeout(Duration::from_secs(2), repolled_receive)
            .await
            .unwrap()
            .unwrap();
        driver.abort();
        release_send.send(()).unwrap();
        assert!(driver.await.unwrap_err().is_cancelled());
        let result = tokio::time::timeout(Duration::from_secs(1), &mut follower).await;
        if result.is_err() {
            // Clean up even on the regression's red version and demonstrate
            // that the underlying result was ready, rather than unavailable.
            notifier.wake();
            let answer = tokio::time::timeout(Duration::from_secs(1), follower)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(answer, [Ipv4Addr::LOCALHOST]);
            panic!("follower lost its wake after driver cancellation; manual wake recovered it");
        }
        assert_eq!(result.unwrap().unwrap().unwrap(), [Ipv4Addr::LOCALHOST]);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(entry.query.upgrade().is_none());
    }
}
