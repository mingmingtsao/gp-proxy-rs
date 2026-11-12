//! Suspend and clock correction are simulated; no host clock is changed.
use super::*;
use crate::lease::TestClock;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test(start_paused = true)]
async fn initial_period_is_anchored_before_the_first_future_poll() {
    let clock = TestClock::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let maintenance = maintain_hip(clock.lease(None), Duration::from_secs(60), move || {
        observed.fetch_add(1, Ordering::SeqCst);
        async { Ok(HipStatus::NotRequested) }
    });
    clock.advance(Duration::ZERO, Duration::from_secs(7200));
    let task = tokio::spawn(maintenance);
    tokio::task::yield_now().await;
    let count = calls.load(Ordering::SeqCst);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        count, 1,
        "deferred polling restarted an already elapsed period"
    );
}

#[tokio::test(start_paused = true)]
async fn wall_only_missed_period_triggers_one_refresh_after_resume() {
    let clock = TestClock::new();
    let lease = clock.lease(None);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let maintenance = tokio::spawn(maintain_hip(lease, Duration::from_secs(60), move || {
        observed.fetch_add(1, Ordering::SeqCst);
        async { Ok(HipStatus::NotRequested) }
    }));
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    clock.advance(Duration::ZERO, Duration::from_secs(7200));
    // Wake the bounded wall-clock observer, without advancing the injected
    // monotonic clock or reaching the old 60-second Tokio timer.
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "missed periods caused a burst"
    );
    clock.advance(Duration::ZERO, Duration::from_secs(59));
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "period was not reset from actual request start"
    );
    clock.advance(Duration::ZERO, Duration::from_secs(1));
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    maintenance.abort();
    assert!(maintenance.await.unwrap_err().is_cancelled());
}

struct InFlight(Arc<AtomicUsize>);
impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn held_check(
    lease: Lease,
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<Result<(), GpError>> {
    tokio::spawn(maintain_hip(lease, Duration::from_secs(60), move || {
        let calls = calls.clone();
        let active = active.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                active.fetch_add(1, Ordering::SeqCst),
                0,
                "overlapping HIP requests"
            );
            let _in_flight = InFlight(active);
            pending().await
        }
    }))
}

#[tokio::test(start_paused = true)]
async fn wall_only_inflight_timeout_drops_request_without_catchup() {
    let clock = TestClock::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let task = held_check(clock.lease(None), calls.clone(), active.clone());
    tokio::task::yield_now().await;
    clock.advance(Duration::ZERO, Duration::from_secs(60));
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(active.load(Ordering::SeqCst), 1);
    clock.advance(Duration::ZERO, Duration::from_secs(7200));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(task.await.unwrap(), Err(GpError::Timeout)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn rollback_during_request_is_terminal_and_never_retried() {
    let clock = TestClock::new();
    let lease = clock.lease(None);
    let calls = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let task = held_check(lease.clone(), calls.clone(), active.clone());
    tokio::task::yield_now().await;
    clock.advance(Duration::ZERO, Duration::from_secs(60));
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(active.load(Ordering::SeqCst), 1);
    clock.rollback(Duration::from_secs(1));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(task.await.unwrap(), Err(GpError::Authentication)));
    clock.advance(Duration::ZERO, Duration::from_secs(2));
    assert_eq!(lease.check(), Err(LeaseFailure::ClockUncertain));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn login_expiry_wins_over_due_period_before_request_is_created() {
    let clock = TestClock::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let task = held_check(
        clock.lease(Some(Duration::from_secs(60))),
        calls.clone(),
        active.clone(),
    );
    tokio::task::yield_now().await;
    clock.advance(Duration::ZERO, Duration::from_secs(60));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(task.await.unwrap(), Err(GpError::Authentication)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn ready_hip_result_cannot_hide_wall_request_timeout() {
    let clock = TestClock::new();
    let lease = clock.lease(None);
    let response_clock = clock.clone();
    let task = tokio::spawn(maintain_hip(lease, Duration::from_secs(60), move || {
        response_clock.advance(Duration::ZERO, HIP_REQUEST_TIMEOUT);
        async { Ok(HipStatus::NotRequested) }
    }));
    tokio::task::yield_now().await;
    clock.advance(Duration::ZERO, Duration::from_secs(60));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(task.await.unwrap(), Err(GpError::Timeout)));
}
