//! Bounded acknowledgement of managed lifecycle writes, outside Tokio's pool.
//!
//! Kernel filesystem work cannot be cancelled. Timeout leaves its outcome
//! unobserved and detaches the worker; process exit still owns the runtime lock.
//! These two entry points are used once each by managed startup and shutdown.
use crate::{
    control::StopReport,
    lease::Lease,
    managed_runtime::{self, RunStamp},
};
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use tokio::sync::oneshot;

const ACKNOWLEDGEMENT: Duration = Duration::from_secs(5);
static BEGUN: AtomicBool = AtomicBool::new(false);
static FINISHED: AtomicBool = AtomicBool::new(false);

fn once(slot: &AtomicBool) -> io::Result<()> {
    if slot.swap(true, Ordering::AcqRel) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "lifecycle file operation already attempted",
        ));
    }
    Ok(())
}

/// Attempt once per process, before admitting authentication. A failure or
/// cancellation consumes the attempt; retry would obscure a possibly late write.
pub async fn begin(instance: [u8; 16]) -> io::Result<RunStamp> {
    once(&BEGUN)?;
    file_work(Lease::new(), ACKNOWLEDGEMENT, move || {
        managed_runtime::begin_current_incarnation(instance)
    })
    .await
}

/// Attempt once after all local workers have joined. Success acknowledges
/// persistence only, not delivery of the separate IPC stop response.
pub async fn finish(stamp: RunStamp, report: StopReport) -> io::Result<()> {
    once(&FINISHED)?;
    file_work(Lease::new(), ACKNOWLEDGEMENT, move || {
        managed_runtime::finish_current_incarnation(&stamp, &report)
    })
    .await
}

async fn file_work<T: Send + 'static>(
    lease: Lease,
    duration: Duration,
    work: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let deadline = lease
        .deadline_after(duration)
        .map_err(|_| io::ErrorKind::TimedOut)?;
    let (sender, receiver) = oneshot::channel();
    // Do not spawn_blocking: Tokio runtime teardown would then wait for an
    // uninterruptible fsync. Dropping JoinHandle does not join an OS thread.
    let owner = thread::Builder::new()
        .name("gp-lifecycle".into())
        .spawn(move || {
            let result = work();
            let _ = sender.send(result);
        })?;
    drop(owner);
    lease
        .run_until(Some(deadline), receiver)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "lifecycle write acknowledgement timed out",
            )
        })?
        .map_err(|_| io::Error::other("lifecycle write acknowledgement lost"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::TestClock;
    use std::sync::mpsc;

    #[tokio::test]
    async fn success_and_filesystem_error_are_distinct() {
        assert_eq!(
            file_work(Lease::new(), ACKNOWLEDGEMENT, || Ok(42))
                .await
                .unwrap(),
            42
        );
        assert_eq!(
            file_work::<()>(Lease::new(), ACKNOWLEDGEMENT, || Err(
                io::ErrorKind::PermissionDenied.into()
            ))
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn blocked_write_times_out_without_join_or_late_success() {
        let clock = TestClock::new();
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let work = tokio::spawn(file_work(clock.lease(None), ACKNOWLEDGEMENT, move || {
            let _ = entered_tx.send(());
            let outcome = release_rx
                .recv()
                .map_err(|_| io::Error::from(io::ErrorKind::Interrupted));
            let _ = done_tx.send(());
            outcome
        }));
        entered_rx.await.unwrap();
        clock.advance(Duration::ZERO, Duration::from_secs(6));
        assert_eq!(
            work.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        // Only now release the actual synchronous work. The asynchronous
        // consumer already returned failure, so this cannot grant admission.
        release_tx.send(()).unwrap();
        done_rx.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_wait_does_not_block_async_runtime_or_cancel_kernel_work() {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let work = tokio::spawn(file_work(Lease::new(), ACKNOWLEDGEMENT, move || {
            let _ = entered_tx.send(());
            let result = release_rx
                .recv()
                .map_err(|_| io::Error::from(io::ErrorKind::Interrupted));
            let _ = done_tx.send(());
            result
        }));
        entered_rx.await.unwrap();
        work.abort();
        assert!(work.await.unwrap_err().is_cancelled());
        release_tx.send(()).unwrap();
        done_rx.await.unwrap();
    }

    #[tokio::test]
    async fn observed_clock_regression_does_not_accept_late_result() {
        let clock = TestClock::new();
        let worker_clock = clock.clone();
        assert_eq!(
            file_work(clock.lease(None), ACKNOWLEDGEMENT, move || {
                worker_clock.rollback(Duration::from_secs(1));
                Ok(())
            })
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn blocked_worker_process_helper() {
        if std::env::var("GP_LIFECYCLE_BLOCKED_HELPER").as_deref() != Ok("1") {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (entered_tx, entered_rx) = oneshot::channel();
            let work = tokio::spawn(file_work(Lease::new(), ACKNOWLEDGEMENT, move || {
                use std::io::Read;
                let _ = entered_tx.send(());
                // The parent retains its writer until this process exits.
                // Neither an injected byte nor EOF is a successful write.
                let _ = io::stdin().read_exact(&mut [0; 1]);
                Err::<(), _>(io::ErrorKind::Interrupted.into())
            }));
            entered_rx.await.unwrap();
            work.abort();
            assert!(work.await.unwrap_err().is_cancelled());
        });
        // The synchronous worker is still blocked. A Tokio blocking-pool
        // implementation would hang here and trip the parent's watchdog.
        drop(runtime);
        std::process::exit(0);
    }

    #[tokio::test]
    async fn process_exits_with_blocked_file_worker_after_runtime_drop() {
        use std::process::Stdio;
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "managed_io::tests::blocked_worker_process_helper",
                "--nocapture",
            ])
            .env_clear()
            .env("GP_LIFECYCLE_BLOCKED_HELPER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        // Keep this outside Child: Child::wait closes its own stdin first.
        let input = child.stdin.take().unwrap();
        let outcome = tokio::time::timeout(ACKNOWLEDGEMENT, child.wait()).await;
        if outcome.is_err() {
            child.start_kill().unwrap();
            let reaped = tokio::time::timeout(ACKNOWLEDGEMENT, child.wait()).await;
            assert!(matches!(reaped, Ok(Ok(_))), "owned helper reap unconfirmed");
        }
        drop(input);
        assert!(outcome
            .expect("runtime drop waited for a blocked worker")
            .unwrap()
            .success());
    }
}
