//! Shared bounded GP/TLS adapter for the existing in-memory IP echo peer.
//! Parent fixtures supply their crate-local `gp` and `echo_peer` modules.
use super::{echo_peer, gp};
use std::{
    io,
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

pub(crate) async fn run(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    seed: u64,
) -> io::Result<()> {
    let stop = CancellationToken::new();
    let _cancel = stop.clone().drop_guard();
    tls.write_all(b"START_TUNNEL").await?;
    tls.flush().await?;
    let (input, incoming) = mpsc::channel(64);
    let (output, mut outgoing) = mpsc::channel(64);
    let (mut reader, mut writer) = tokio::io::split(tls);
    let mut tasks = JoinSet::new();
    tasks.spawn(echo_peer::run_peer(
        incoming,
        output,
        stop.clone(),
        Arc::new(Mutex::new(echo_peer::PeerStats::default())),
        Arc::new(AtomicBool::new(false)),
        4,
        seed,
    ));
    let stopping = stop.clone();
    tasks.spawn(async move {
        loop {
            tokio::select! {
                _ = stopping.cancelled() => break,
                frame = gp::read_frame(&mut reader, 1400) => match frame {
                    Ok(gp::Frame::Ip(packet)) => if input.send(packet).await.is_err() { break; },
                    Ok(gp::Frame::Keepalive) => {},
                    Err(_) => break,
                }
            }
        }
        Ok::<_, io::Error>(())
    });
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            result = tasks.join_next() => { let _ = result.unwrap().unwrap(); break; },
            packet = outgoing.recv() => match packet {
                Some(packet) => if gp::write_frame(&mut writer, &gp::Frame::Ip(packet), 1400).await.is_err() { break; },
                None => break,
            },
        }
    }
    stop.cancel();
    let _ = timeout(Duration::from_secs(6), writer.shutdown()).await;
    while let Some(result) = tasks.join_next().await {
        let _ = result.unwrap();
    }
    Ok(())
}
