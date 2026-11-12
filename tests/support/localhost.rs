//! Listen on the first address the synthetic `localhost` TLS origin will dial.
use std::io;
use tokio::net::{lookup_host, TcpListener};

pub async fn bind() -> io::Result<TcpListener> {
    let address = lookup_host(("localhost", 0))
        .await?
        .next()
        .ok_or_else(|| io::Error::other("synthetic localhost resolved no addresses"))?;
    if !address.ip().is_loopback() {
        return Err(io::Error::other(
            "synthetic localhost must resolve to a loopback address",
        ));
    }
    // An IPv4-only listener leaves an IPv6-first client waiting for a failed
    // connection before every request, consuming unrelated test deadlines.
    TcpListener::bind(address).await
}
