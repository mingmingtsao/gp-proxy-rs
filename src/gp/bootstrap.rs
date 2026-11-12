//! Host DNS is only for the configured GP origin, never a business destination.
//!
//! An OS resolver call cannot be cancelled safely. Keep it outside Tokio's
//! blocking pool (whose shutdown waits for started calls), and retain a global
//! permit until the actual call returns. Cancelling an async caller must not
//! make room for another possibly stuck resolver thread.
use crate::lease::Lease;
use std::{
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

const MAX_WORKERS: usize = 4;
const MAX_WAITERS: usize = 32;
const ADMISSION_WAIT: Duration = Duration::from_millis(250);
const MAX_ADDRESSES: usize = 64;

#[derive(Clone)]
struct Capacity {
    workers: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
}

impl Capacity {
    fn new(workers: usize) -> Self {
        Self {
            workers: Arc::new(Semaphore::new(workers)),
            waiters: Arc::new(Semaphore::new(MAX_WAITERS)),
        }
    }

    async fn acquire(&self) -> io::Result<OwnedSemaphorePermit> {
        if let Ok(permit) = self.workers.clone().try_acquire_owned() {
            return Ok(permit);
        }
        // Absorb short concurrent bursts without adding OS resolver threads.
        // Queue capacity and waiting time are both bounded. Cancelling here
        // releases the queue slot and the pending semaphore acquisition.
        let _waiting = self
            .waiters
            .clone()
            .try_acquire_owned()
            .map_err(|_| exhausted())?;
        let budget = Lease::new();
        let end = budget
            .deadline_after(ADMISSION_WAIT)
            .map_err(|_| exhausted())?;
        budget
            .run_until(Some(end), self.workers.clone().acquire_owned())
            .await
            .map_err(|_| exhausted())?
            .map_err(|_| exhausted())
    }
}

fn capacity() -> Capacity {
    static CAPACITY: OnceLock<Capacity> = OnceLock::new();
    CAPACITY.get_or_init(|| Capacity::new(MAX_WORKERS)).clone()
}

fn exhausted() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "gateway bootstrap resolver capacity exhausted",
    )
}

pub(super) async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    resolve_on(host, port, capacity()).await
}

async fn resolve_on(host: &str, port: u16, capacity: Capacity) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let host = host.to_owned();
    resolve_with(capacity, move || {
        let addresses = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| io::Error::new(error.kind(), "gateway bootstrap resolution failed"))?;
        bounded_addresses(addresses)
    })
    .await
}

fn bounded_addresses(addresses: impl Iterator<Item = SocketAddr>) -> io::Result<Vec<SocketAddr>> {
    let addresses: Vec<_> = addresses.take(MAX_ADDRESSES + 1).collect();
    if addresses.is_empty() || addresses.len() > MAX_ADDRESSES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gateway bootstrap address count outside supported bounds",
        ));
    }
    Ok(addresses)
}

async fn resolve_with(
    capacity: Capacity,
    lookup: impl FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
) -> io::Result<Vec<SocketAddr>> {
    let permit = capacity.acquire().await?;
    let (sender, receiver) = oneshot::channel();
    // Deliberately detached. The worker owns only the public origin and its
    // permit, never a session/credential/socket. A blocked OS call may outlive
    // its request or a library caller's runtime, but cannot delay runtime drop.
    // At most MAX_WORKERS exist process-wide; process exit ends them as well.
    std::thread::Builder::new()
        .name("gp-bootstrap-dns".into())
        .spawn(move || {
            let _permit = permit;
            if !sender.is_closed() {
                let _ = sender.send(lookup());
            }
        })?;
    receiver
        .await
        .map_err(|_| io::Error::other("gateway bootstrap resolver worker stopped"))?
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;
