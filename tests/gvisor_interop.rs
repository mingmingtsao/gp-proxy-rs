//! Opt-in interoperability against the separately built, pinned gVisor peer.
//! Only pipes and memory IP channels are used. No host socket or virtual NIC.
#[allow(dead_code)]
#[path = "support/dataplane.rs"]
mod dataplane;

use dataplane::{assert_bounded, run_link, Impairment, LinkStats, ADDRESS};
use gp_proxy::stack::{self, StackConfig, StackHandle};
use std::{
    collections::VecDeque,
    io,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::mpsc,
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

fn error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn echo(
    stack: StackHandle,
    bytes: usize,
    seed: usize,
    wait_for_window: Option<Arc<Mutex<LinkStats>>>,
) -> io::Result<usize> {
    let stream = stack.connect(ADDRESS.parse().unwrap()).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let payload: Vec<u8> = (0..bytes)
        .map(|offset| ((offset * 37 + seed * 19 + offset / 251) % 251) as u8)
        .collect();
    let send = async {
        writer.write_all(&payload).await?;
        // EOF must propagate in both directions, including an empty FIN.
        writer.shutdown().await
    };
    let receive = async {
        if let Some(stats) = &wait_for_window {
            timeout(Duration::from_secs(10), async {
                while stats.lock().unwrap().tcp_zero_window_advertisements == 0 {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .map_err(|_| error("slow reader never closed the client TCP window"))?;
        }
        let mut echoed = Vec::with_capacity(bytes);
        let mut buffer = [0; 4096];
        loop {
            let length = reader.read(&mut buffer).await?;
            if length == 0 {
                break;
            }
            if echoed.len() + length > bytes {
                return Err(error("gVisor sent extra or duplicated bytes"));
            }
            echoed.extend_from_slice(&buffer[..length]);
            if wait_for_window.is_some() {
                sleep(Duration::from_millis(3)).await;
            }
        }
        if echoed != payload {
            return Err(error("gVisor echo corrupted, reordered or truncated"));
        }
        Ok(())
    };
    tokio::try_join!(send, receive)?;
    Ok(bytes)
}

async fn exercise(
    stack: &StackHandle,
    seed: usize,
    uplink: &Arc<Mutex<LinkStats>>,
) -> io::Result<usize> {
    let mut workers = JoinSet::new();
    for index in 0..4 {
        workers.spawn(echo(
            stack.clone(),
            256 * 1024,
            seed + index,
            (index == 0).then(|| uplink.clone()),
        ));
    }
    let mut checked = 0;
    while let Some(result) = workers.join_next().await {
        checked += result.map_err(|_| error("interop echo worker panicked"))??;
    }
    for (index, length) in [0, 1, 1360, 12913].into_iter().enumerate() {
        checked += echo(stack.clone(), length, seed + index + 4, None).await?;
    }
    Ok(checked)
}

async fn scenario(settings: Impairment) {
    let executable = std::env::var_os("GP_PROXY_GVISOR_PEER")
        .expect("build tests/interop/gvisor, then set GP_PROXY_GVISOR_PEER to its binary");
    let mut child = Command::new(executable)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start development-only gVisor pipe peer");
    let pid = child.id().unwrap();
    eprintln!(
        "{}",
        serde_json::json!({"event":"gvisor_peer_started", "pid":pid})
    );
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap().take(64 * 1024);
    let mut diagnostics = JoinSet::new();
    diagnostics.spawn(async move {
        let mut text = String::new();
        stderr.read_to_string(&mut text).await.map(|_| text)
    });
    let readiness = timeout(Duration::from_secs(10), output.read_u16()).await;
    if !matches!(readiness, Ok(Ok(0))) {
        // kill_on_drop is only a last-resort guard, not proof of reaping.
        let _ = child.kill().await;
        let status = child
            .wait()
            .await
            .expect("reap peer after failed readiness");
        let diagnostic = timeout(Duration::from_secs(3), diagnostics.join_next()).await;
        panic!("gVisor readiness failed: {readiness:?}; exit={status}; stderr={diagnostic:?}");
    }
    let stop = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop(stop.clone());
    let (to_stack, incoming) = mpsc::channel(64);
    let (outgoing, from_stack) = mpsc::channel(64);
    let (to_peer, mut peer_input) = mpsc::channel::<Vec<u8>>(64);
    let (peer_output, from_peer) = mpsc::channel(64);
    let (stack, mut stack_task) = stack::spawn(
        StackConfig {
            ipv4: "10.77.0.2".parse().unwrap(),
            ipv6: None,
            mtu: 1400,
            max_connections: 8,
            connect_timeout: Duration::from_secs(12),
            idle_timeout: Duration::from_secs(80),
            random_seed: settings.seed,
        },
        incoming,
        outgoing,
        stop.clone(),
    )
    .unwrap();
    let uplink = Arc::new(Mutex::new(LinkStats::default()));
    let downlink = Arc::new(Mutex::new(LinkStats::default()));
    let mut tasks = JoinSet::new();
    for (receive, send, impairment, stats) in [
        (from_stack, to_peer, settings, uplink.clone()),
        (
            from_peer,
            to_stack,
            Impairment {
                seed: settings.seed.wrapping_add(31),
                ..settings
            },
            downlink.clone(),
        ),
    ] {
        tasks.spawn(run_link(
            receive,
            send,
            impairment,
            stop.clone(),
            stats,
            Arc::new(Mutex::new(VecDeque::new())),
        ));
    }
    let writing = stop.clone();
    tasks.spawn(async move {
        let result = async {
            while let Some(packet) = peer_input.recv().await {
                input.write_u16(packet.len() as u16).await?;
                input.write_all(&packet).await?;
            }
            Ok::<_, io::Error>(())
        };
        tokio::select! {
            _ = writing.cancelled() => Ok(()),
            result = result => result,
        }
    });
    let reading = stop.clone();
    tasks.spawn(async move {
        let result = async {
            loop {
                let length = output.read_u16().await?;
                if !(20..=1400).contains(&length) {
                    return Err(error("gVisor output exceeded IP packet bound"));
                }
                let mut packet = vec![0; usize::from(length)];
                output.read_exact(&mut packet).await?;
                if peer_output.send(packet).await.is_err() {
                    return Ok(());
                }
            }
        };
        tokio::select! {
            biased;
            _ = reading.cancelled() => Ok(()),
            result = result => result,
        }
    });
    let result = timeout(
        Duration::from_secs(70),
        exercise(&stack, settings.seed as usize, &uplink),
    )
    .await;
    // Give final FIN ACKs time to cross the impaired link before shutting it.
    sleep(Duration::from_millis(200)).await;
    let before = stack.stats();
    stop.cancel();
    let stack_result = timeout(Duration::from_secs(3), &mut stack_task).await;
    if stack_result.is_err() {
        stack_task.abort();
        let _ = stack_task.await;
    }
    let pipe_result = timeout(Duration::from_secs(3), async {
        while let Some(task) = tasks.join_next().await {
            task.expect("interop pipe task panicked")?;
        }
        Ok::<_, io::Error>(())
    })
    .await;
    let status = match timeout(Duration::from_secs(5), child.wait()).await {
        Ok(status) => status.expect("wait for gVisor child"),
        Err(_) => {
            child.kill().await.expect("kill stalled gVisor child");
            child.wait().await.expect("reap stalled gVisor child");
            panic!("gVisor peer did not exit after pipe EOF");
        }
    };
    let diagnostic = timeout(Duration::from_secs(3), diagnostics.join_next())
        .await
        .expect("gVisor diagnostics did not close")
        .unwrap()
        .unwrap()
        .unwrap();
    let after = stack.stats();
    eprintln!(
        "{}",
        serde_json::json!({"event":"gvisor_interop", "impairment":settings,
            "peer_pid":pid, "peer_exit":status.code(), "peer_summary":diagnostic,
            "result":format!("{result:?}"), "before_cleanup":before,"after_cleanup":after,
            "uplink":*uplink.lock().unwrap(), "downlink":*downlink.lock().unwrap()})
    );
    assert_bounded(&before, 8);
    if let Err(error) = stack_result
        .expect("interop stack cleanup timeout")
        .expect("interop stack task panicked")
    {
        // Cancellation and packet-channel closure can win in either order.
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    }
    pipe_result
        .expect("interop pipe cleanup timeout")
        .expect("interop pipe failed");
    assert!(status.success(), "gVisor peer failed: {diagnostic}");
    let checked = result
        .expect("interop transfer exceeded 70 seconds")
        .unwrap();
    assert_eq!(checked, 4 * 256 * 1024 + 1 + 1360 + 12913);
    let peer: serde_json::Value = serde_json::from_str(&diagnostic).unwrap();
    assert_eq!(peer["opened"], 8);
    assert_eq!(peer["closed"], 8);
    assert_eq!(peer["errors"], 0);
    assert_eq!(peer["echoed_bytes"], checked);
    for stats in [&uplink, &downlink] {
        assert!(
            stats.lock().unwrap().tcp_zero_window_advertisements > 0,
            "the slow-reader scenario did not actually close a TCP window"
        );
    }
    assert_eq!(
        after.socket_count
            + after.tcp_buffer_capacity_bytes
            + after.command_queue
            + after.incoming_queue
            + after.outgoing_queue,
        0
    );
    if settings.drop_every > 0 {
        for stats in [&uplink, &downlink] {
            let stats = stats.lock().unwrap();
            assert!(
                stats.dropped > 0 && stats.duplicated > 0 && stats.reordered_original_packets > 0
            );
            assert!(stats.peak_queued <= 64);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the separately built, pinned development-only gVisor peer"]
async fn gvisor_tcp_echo_half_close_and_impaired_link() {
    scenario(Impairment::default()).await;
    for seed in [17, 503] {
        scenario(Impairment {
            seed,
            drop_every: 97,
            duplicate_every: 53,
            reorder_every: 37,
            delay_ms: 2,
            reorder_delay_ms: 25,
            drop_first_syn: true,
        })
        .await;
    }
}
