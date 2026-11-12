use super::*;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Condvar, Mutex,
    },
    time::Duration,
};

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.changed.wait(open).unwrap();
        }
    }

    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct ReleaseOnDrop(Arc<Gate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn address() -> SocketAddr {
    "127.0.0.1:443".parse().unwrap()
}

async fn reclaimed(workers: &Capacity, count: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while workers.workers.available_permits() != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("resolver permit remained occupied after lookup returned");
}

#[tokio::test]
async fn numeric_origins_do_not_need_a_resolver_slot() {
    let pool = Capacity::new(0);
    for host in ["127.0.0.1", "::1"] {
        let addresses = resolve_on(host, 7777, pool.clone()).await.unwrap();
        assert_eq!(addresses, [SocketAddr::new(host.parse().unwrap(), 7777)]);
    }
    assert_eq!(
        resolve_on("never-resolved.invalid", 443, pool)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn address_limit_rejects_empty_and_overflow_without_silent_truncation() {
    assert!(bounded_addresses(std::iter::empty()).is_err());
    let addresses: Vec<_> = (1..=MAX_ADDRESSES)
        .map(|port| SocketAddr::from(([127, 0, 0, 1], port as u16)))
        .collect();
    assert_eq!(
        bounded_addresses(addresses.iter().copied()).unwrap(),
        addresses
    );
    assert!(bounded_addresses(std::iter::repeat_n(address(), MAX_ADDRESSES + 1)).is_err());
}

#[tokio::test]
async fn cancelled_calls_retain_all_worker_slots_until_actual_completion() {
    let pool = Capacity::new(MAX_WORKERS);
    let gate = Arc::new(Gate::default());
    let cleanup = ReleaseOnDrop(gate.clone());
    let completed = Arc::new(AtomicUsize::new(0));
    for _ in 0..MAX_WORKERS {
        let (started, running) = oneshot::channel();
        let hold = gate.clone();
        let completed = completed.clone();
        let caller = tokio::spawn(resolve_with(pool.clone(), move || {
            started.send(()).unwrap();
            hold.wait();
            completed.fetch_add(1, Ordering::SeqCst);
            Ok(vec![address()])
        }));
        tokio::time::timeout(Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
    }
    assert_eq!(pool.workers.available_permits(), 0);
    let extra_started = Arc::new(AtomicBool::new(false));
    let extra = extra_started.clone();
    let error = resolve_with(pool.clone(), move || {
        extra.store(true, Ordering::SeqCst);
        Ok(vec![address()])
    })
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(!extra_started.load(Ordering::SeqCst));
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    drop(cleanup);
    reclaimed(&pool, MAX_WORKERS).await;
    assert_eq!(completed.load(Ordering::SeqCst), MAX_WORKERS);
    assert_eq!(
        resolve_with(pool.clone(), || Ok(vec![address()]))
            .await
            .unwrap(),
        [address()]
    );
    reclaimed(&pool, MAX_WORKERS).await;
}

#[tokio::test]
async fn resolver_errors_release_capacity_and_never_invent_an_address() {
    let pool = Capacity::new(1);
    let error = resolve_with(pool.clone(), || Err(io::ErrorKind::NotFound.into()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    reclaimed(&pool, 1).await;
    assert_eq!(
        resolve_with(pool.clone(), || Ok(vec![address()]))
            .await
            .unwrap(),
        [address()]
    );
    reclaimed(&pool, 1).await;
}

#[tokio::test]
async fn a_short_burst_waits_for_the_existing_worker_instead_of_failing() {
    let pool = Capacity::new(1);
    let gate = Arc::new(Gate::default());
    let cleanup = ReleaseOnDrop(gate.clone());
    let (started, running) = oneshot::channel();
    let first = tokio::spawn(resolve_with(pool.clone(), move || {
        started.send(()).unwrap();
        gate.wait();
        Ok(vec![address()])
    }));
    tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap();
    let next_started = Arc::new(AtomicBool::new(false));
    let observed = next_started.clone();
    let second = tokio::spawn(resolve_with(pool.clone(), move || {
        observed.store(true, Ordering::SeqCst);
        Ok(vec![address()])
    }));
    tokio::time::timeout(ADMISSION_WAIT, async {
        while pool.waiters.available_permits() == MAX_WAITERS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!next_started.load(Ordering::SeqCst));
    assert!(!second.is_finished());
    drop(cleanup);
    assert_eq!(first.await.unwrap().unwrap(), [address()]);
    assert_eq!(second.await.unwrap().unwrap(), [address()]);
    assert!(next_started.load(Ordering::SeqCst));
    reclaimed(&pool, 1).await;
    assert_eq!(pool.waiters.available_permits(), MAX_WAITERS);
}

#[tokio::test(start_paused = true)]
async fn waiting_capacity_is_bounded_and_cancellation_removes_queued_work() {
    let pool = Capacity::new(0);
    let mut callers = Vec::new();
    for _ in 0..MAX_WAITERS {
        callers.push(tokio::spawn(resolve_with(pool.clone(), || {
            panic!("queued cancelled lookup must never start")
        })));
    }
    while pool.waiters.available_permits() != 0 {
        tokio::task::yield_now().await;
    }
    // The queue itself has no hidden unbounded waiting path.
    let error = resolve_with(pool.clone(), || panic!("excess lookup started"))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    for caller in &callers {
        assert!(!caller.is_finished());
        caller.abort();
    }
    for caller in callers {
        assert!(caller.await.unwrap_err().is_cancelled());
    }
    assert_eq!(pool.waiters.available_permits(), MAX_WAITERS);
    pool.workers.add_permits(1);
    // Acquire directly here: a real worker result arriving on an OS thread
    // should not depend on Tokio's automatically advancing paused clock.
    let permit = pool.acquire().await.unwrap();
    assert_eq!(pool.workers.available_permits(), 0);
    drop(permit);
    assert_eq!(pool.workers.available_permits(), 1);
}

#[test]
fn a_stuck_resolver_does_not_hold_a_library_callers_runtime_open() {
    let pool = Capacity::new(1);
    let gate = Arc::new(Gate::default());
    let cleanup = ReleaseOnDrop(gate.clone());
    let (dropping, about_to_drop) = std::sync::mpsc::channel();
    let (finished, dropped) = std::sync::mpsc::channel();
    let worker_pool = pool.clone();
    let owner = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (started, running) = oneshot::channel();
            let caller = tokio::spawn(resolve_with(worker_pool, move || {
                started.send(()).unwrap();
                gate.wait();
                Ok(vec![address()])
            }));
            tokio::time::timeout(Duration::from_secs(3), running)
                .await
                .unwrap()
                .unwrap();
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
        });
        dropping.send(()).unwrap();
        drop(runtime);
        let _ = finished.send(());
    });
    let started = about_to_drop.recv_timeout(Duration::from_secs(5)).is_ok();
    let returned_while_resolver_blocked = dropped.recv_timeout(Duration::from_secs(1)).is_ok();
    let occupied_while_blocked = pool.workers.available_permits() == 0;
    // Even the regressed implementation is released before asserting, so a
    // failing test never strands its runtime owner or synthetic OS call.
    drop(cleanup);
    owner.join().unwrap();
    assert!(started, "runtime owner failed before reaching shutdown");
    assert!(
        returned_while_resolver_blocked,
        "runtime drop waited for resolver"
    );
    assert!(
        occupied_while_blocked,
        "caller cancellation released a live worker slot"
    );
    let limit = std::time::Instant::now() + Duration::from_secs(3);
    while pool.workers.available_permits() != 1 {
        assert!(std::time::Instant::now() < limit);
        std::thread::yield_now();
    }
}
