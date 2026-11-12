//! Conservative session clocks: neither suspend nor an observed wall-clock
//! regression may extend a known gateway lease. This is not a trusted clock.
use std::{
    future::{poll_fn, Future},
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{sleep, Instant},
};
use tokio_util::sync::CancellationToken;

const RECHECK: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Sample {
    pub monotonic: Instant,
    pub wall: SystemTime,
}

impl Sample {
    pub(crate) fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Deadline {
    monotonic: Instant,
    wall: SystemTime,
}

impl Deadline {
    pub(crate) fn earliest(self, other: Self) -> Self {
        Self {
            monotonic: self.monotonic.min(other.monotonic),
            wall: self.wall.min(other.wall),
        }
    }
    pub(crate) fn after(sample: Sample, duration: Duration) -> Result<Self, Failure> {
        Ok(Self {
            monotonic: sample
                .monotonic
                .checked_add(duration)
                .ok_or(Failure::ClockUncertain)?,
            wall: sample
                .wall
                .checked_add(duration)
                .ok_or(Failure::ClockUncertain)?,
        })
    }

    fn reached(self, now: Sample) -> bool {
        now.monotonic >= self.monotonic || now.wall >= self.wall
    }

    fn remaining(self, now: Sample) -> Duration {
        self.monotonic
            .saturating_duration_since(now.monotonic)
            .min(self.wall.duration_since(now.wall).unwrap_or_default())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    Expired,
    ClockUncertain,
    Renewal,
}

struct State {
    deadline: Option<Deadline>,
    last_wall: SystemTime,
    failure: Option<Failure>,
    #[cfg(test)]
    clock: Option<TestClock>,
}

impl State {
    fn sample(&self) -> Sample {
        #[cfg(test)]
        if let Some(clock) = &self.clock {
            return *clock.0.lock().unwrap();
        }
        Sample::now()
    }

    fn check(&mut self) -> Result<Sample, Failure> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        // Sample while holding this session's lock. Sampling before acquiring
        // it would confuse concurrent callers arriving in a different order.
        let now = self.sample();
        let failure = if now.wall < self.last_wall {
            Some(Failure::ClockUncertain)
        } else if self.deadline.is_some_and(|deadline| deadline.reached(now)) {
            Some(Failure::Expired)
        } else {
            None
        };
        self.last_wall = now.wall;
        self.failure = failure;
        failure.map_or(Ok(now), Err)
    }
}

#[derive(Clone)]
pub(crate) struct Lease(Arc<Mutex<State>>);

impl Lease {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            deadline: None,
            last_wall: SystemTime::now(),
            failure: None,
            #[cfg(test)]
            clock: None,
        })))
    }

    /// Remaining lifetime is anchored before requesting configuration. An
    /// omitted field never removes a prior deadline, and neither clock extends.
    pub(crate) fn observe(
        &self,
        anchor: Sample,
        duration: Option<Duration>,
    ) -> Result<(), Failure> {
        let mut state = self.0.lock().unwrap();
        let now = state.check()?;
        if now.wall < anchor.wall {
            state.failure = Some(Failure::ClockUncertain);
            return Err(Failure::ClockUncertain);
        }
        if let Some(duration) = duration {
            let deadline = Deadline::after(anchor, duration)
                .inspect_err(|failure| state.failure = Some(*failure))?;
            state.deadline = Some(match state.deadline {
                None => deadline,
                Some(old) => old.earliest(deadline),
            });
        }
        state.check().map(|_| ())
    }

    pub(crate) fn check(&self) -> Result<(), Failure> {
        self.0.lock().unwrap().check().map(|_| ())
    }

    /// One checked sample can anchor several deadlines to the same admission.
    pub(crate) fn sample(&self) -> Result<Sample, Failure> {
        self.0.lock().unwrap().check()
    }

    pub(crate) fn remaining(&self, deadline: Deadline) -> Result<Duration, Failure> {
        let mut state = self.0.lock().unwrap();
        let now = state.check()?;
        Ok(state
            .deadline
            .map_or(deadline, |end| end.earliest(deadline))
            .remaining(now))
    }

    /// Use this session's checked clock for local operation/period deadlines.
    /// In particular, tests and all production consumers observe one clock,
    /// rather than mixing a fresh OS sample with the injected/latched clock.
    pub(crate) fn deadline_after(&self, duration: Duration) -> Result<Deadline, Failure> {
        let mut state = self.0.lock().unwrap();
        let now = state.check()?;
        Deadline::after(now, duration).inspect_err(|failure| state.failure = Some(*failure))
    }

    pub(crate) fn until(&self, deadline: Option<Deadline>) -> Result<bool, Failure> {
        let now = self.0.lock().unwrap().check()?;
        Ok(deadline.is_some_and(|deadline| deadline.reached(now)))
    }

    /// Tokio's timer is only a wake-up mechanism. Recheck wall time at bounded
    /// intervals; I/O and admission checks do not wait for this task to run.
    pub(crate) async fn wait(&self, deadline: Option<Deadline>) -> Result<(), Failure> {
        loop {
            let delay = {
                let mut state = self.0.lock().unwrap();
                let now = state.check()?;
                if deadline.is_some_and(|deadline| deadline.reached(now)) {
                    return Ok(());
                }
                [state.deadline, deadline]
                    .into_iter()
                    .flatten()
                    .fold(RECHECK, |delay, deadline| {
                        delay.min(deadline.remaining(now))
                    })
            };
            sleep(delay).await;
        }
    }

    /// Check on every poll and after Ready, not merely before the first await.
    /// The independent timer also cancels a completely stalled operation.
    pub(crate) async fn run<T>(&self, operation: impl Future<Output = T>) -> Result<T, Failure> {
        self.run_until(None, operation).await
    }

    pub(crate) async fn run_until<T>(
        &self,
        deadline: Option<Deadline>,
        operation: impl Future<Output = T>,
    ) -> Result<T, Failure> {
        tokio::pin!(operation);
        let guarded = poll_fn(|cx| {
            if self.until(deadline)? {
                return Poll::Ready(Err(Failure::Renewal));
            }
            match operation.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(value) => Poll::Ready(self.until(deadline).and_then(|elapsed| {
                    if elapsed {
                        Err(Failure::Renewal)
                    } else {
                        Ok(value)
                    }
                })),
            }
        });
        tokio::select! {
            biased;
            result = self.wait(deadline) => result.and(Err(Failure::Renewal)),
            result = guarded => result,
        }
    }

    #[cfg(test)]
    pub(crate) fn deadline(&self) -> Option<Deadline> {
        self.0.lock().unwrap().deadline
    }
}

/// Check each actual stream poll, including a partially written GP frame
/// resumed after suspend. A whole-frame precheck alone would miss that case.
pub(crate) struct GuardedIo<T> {
    inner: T,
    lease: Lease,
    renewal: Option<Deadline>,
    cancel: CancellationToken,
}

impl<T> GuardedIo<T> {
    pub(crate) fn new(
        inner: T,
        lease: Lease,
        renewal: Option<Deadline>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            inner,
            lease,
            renewal,
            cancel,
        }
    }

    fn check(&self) -> io::Result<()> {
        if self.cancel.is_cancelled() || self.lease.until(self.renewal) != Ok(false) {
            self.cancel.cancel();
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "GlobalProtect session unavailable",
            ))
        } else {
            Ok(())
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for GuardedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check()?;
        let filled = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if let Err(error) = self.check() {
            buffer.set_filled(filled);
            return Poll::Ready(Err(error));
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for GuardedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check()?;
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        self.check()?;
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        self.check()?;
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.check()?;
        result
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestClock(Arc<Mutex<Sample>>);

#[cfg(test)]
impl TestClock {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(Sample {
            monotonic: Instant::now(),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
        })))
    }
    pub(crate) fn sample(&self) -> Sample {
        *self.0.lock().unwrap()
    }
    pub(crate) fn advance(&self, monotonic: Duration, wall: Duration) {
        let mut now = self.0.lock().unwrap();
        now.monotonic += monotonic;
        now.wall += wall;
    }
    pub(crate) fn rollback(&self, duration: Duration) {
        self.0.lock().unwrap().wall -= duration;
    }
    pub(crate) fn lease(&self, duration: Option<Duration>) -> Lease {
        let anchor = self.sample();
        let lease = Lease(Arc::new(Mutex::new(State {
            deadline: None,
            last_wall: anchor.wall,
            failure: None,
            clock: Some(self.clone()),
        })));
        lease.observe(anchor, duration).unwrap();
        lease
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn suspend_expires_wall_deadline_without_advancing_monotonic() {
        let clock = TestClock::new();
        let lease = clock.lease(Some(Duration::from_secs(60)));
        let old_monotonic_deadline = clock.sample().monotonic + Duration::from_secs(60);
        clock.advance(Duration::ZERO, Duration::from_secs(3600));
        assert!(
            clock.sample().monotonic < old_monotonic_deadline,
            "legacy monotonic-only check still accepts this session"
        );
        assert_eq!(lease.check(), Err(Failure::Expired));
        assert_eq!(lease.wait(None).await, Err(Failure::Expired));
    }

    #[test]
    fn wall_regression_is_latched_even_after_clock_recovers() {
        let clock = TestClock::new();
        let lease = clock.lease(Some(Duration::from_secs(60)));
        clock.rollback(Duration::from_secs(1));
        assert_eq!(lease.check(), Err(Failure::ClockUncertain));
        clock.advance(Duration::ZERO, Duration::from_secs(2));
        assert_eq!(lease.check(), Err(Failure::ClockUncertain));
        assert_eq!(
            lease.observe(clock.sample(), Some(Duration::from_secs(600))),
            Err(Failure::ClockUncertain)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn operation_is_checked_before_poll_and_after_ready() {
        let clock = TestClock::new();
        let lease = clock.lease(Some(Duration::from_secs(60)));
        assert_eq!(
            lease
                .run(async {
                    clock.advance(Duration::ZERO, Duration::from_secs(60));
                    7
                })
                .await,
            Err(Failure::Expired)
        );
        let polled = AtomicBool::new(false);
        assert_eq!(
            lease
                .run(async {
                    polled.store(true, Ordering::SeqCst);
                })
                .await,
            Err(Failure::Expired)
        );
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn partially_blocked_write_cannot_resume_expired() {
        let clock = TestClock::new();
        let lease = clock.lease(Some(Duration::from_secs(60)));
        let cancel = CancellationToken::new();
        let (stream, mut peer) = tokio::io::duplex(1);
        let mut stream = GuardedIo::new(stream, lease, None, cancel.clone());
        stream.write_all(b"a").await.unwrap();
        let mut blocked = Box::pin(stream.write_all(b"b"));
        assert!(matches!(
            blocked
                .as_mut()
                .poll(&mut Context::from_waker(std::task::Waker::noop())),
            Poll::Pending
        ));
        clock.advance(Duration::ZERO, Duration::from_secs(60));
        assert_eq!(peer.read_u8().await.unwrap(), b'a');
        assert!(blocked.await.is_err());
        assert!(cancel.is_cancelled());
        drop(stream);
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn buffered_read_and_tunnel_renewal_check_before_underlying_io() {
        for renewal in [false, true] {
            let clock = TestClock::new();
            let lease = clock.lease(Some(Duration::from_secs(if renewal { 600 } else { 60 })));
            let renew_at =
                renewal.then(|| Deadline::after(clock.sample(), Duration::from_secs(60)).unwrap());
            let cancel = CancellationToken::new();
            let (stream, mut peer) = tokio::io::duplex(8);
            let mut stream = GuardedIo::new(stream, lease.clone(), renew_at, cancel.clone());
            peer.write_all(b"buffered").await.unwrap();
            clock.advance(Duration::ZERO, Duration::from_secs(60));
            let mut buffer = [0; 8];
            assert!(stream.read(&mut buffer).await.is_err());
            assert_eq!(
                buffer, [0; 8],
                "expired capability exposed buffered application data"
            );
            assert!(stream.write_all(b"new data").await.is_err());
            assert!(cancel.is_cancelled());
            assert_eq!(
                lease.check(),
                if renewal {
                    Ok(())
                } else {
                    Err(Failure::Expired)
                }
            );
        }
    }

    #[test]
    fn request_anchor_detects_expired_or_regressed_buffered_response() {
        for rollback in [false, true] {
            let clock = TestClock::new();
            let anchor = clock.sample();
            if rollback {
                clock.rollback(Duration::from_secs(1));
            } else {
                clock.advance(Duration::ZERO, Duration::from_secs(3600));
            }
            // Construct the login guard only after the response was received,
            // as startup does. Checking against its creation time is too late.
            let lease = clock.lease(None);
            assert_eq!(
                lease.observe(anchor, Some(Duration::from_secs(60))),
                Err(if rollback {
                    Failure::ClockUncertain
                } else {
                    Failure::Expired
                })
            );
        }
    }

    #[test]
    fn observations_can_shorten_each_deadline_but_never_extend() {
        let clock = TestClock::new();
        let lease = clock.lease(Some(Duration::from_secs(120)));
        let original = lease.0.lock().unwrap().deadline;
        clock.advance(Duration::from_secs(10), Duration::from_secs(20));
        lease
            .observe(clock.sample(), Some(Duration::from_secs(120)))
            .unwrap();
        lease.observe(clock.sample(), None).unwrap();
        assert_eq!(lease.0.lock().unwrap().deadline, original);
        lease
            .observe(clock.sample(), Some(Duration::from_secs(10)))
            .unwrap();
        assert_eq!(
            lease.0.lock().unwrap().deadline,
            Some(Deadline::after(clock.sample(), Duration::from_secs(10)).unwrap())
        );
    }
}
