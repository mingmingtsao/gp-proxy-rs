#[path = "support/dataplane.rs"]
mod dataplane;

use dataplane::{assert_bounded, wait_for_stats, Harness, Impairment, ADDRESS, DNS};
use gp_proxy::stack::StackHandle;
use serde::Serialize;
use std::{
    io,
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
    time::{timeout, Instant},
};
use tokio_util::sync::CancellationToken;

async fn exchange(
    stack: &StackHandle,
    payload_bytes: usize,
    rounds: usize,
    seed: u64,
) -> io::Result<u64> {
    exchange_observed(stack, payload_bytes, rounds, seed, |_| {}).await
}

enum Phase {
    Connected,
    Verified(usize),
    Closing,
}

async fn exchange_observed(
    stack: &StackHandle,
    payload_bytes: usize,
    rounds: usize,
    seed: u64,
    mut observe: impl FnMut(Phase),
) -> io::Result<u64> {
    let stream = stack.connect(ADDRESS.parse().unwrap()).await?;
    observe(Phase::Connected);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut verified = 0;
    for round in 0..rounds {
        let payload: Vec<u8> = (0..payload_bytes)
            .map(|i| ((i as u64 + seed.wrapping_mul(31) + round as u64 * 17) % 251) as u8)
            .collect();
        let mut echoed = vec![0; payload.len()];
        timeout(Duration::from_secs(30), async {
            tokio::try_join!(async { writer.write_all(&payload).await }, async {
                reader.read_exact(&mut echoed).await.map(|_| ())
            })
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "one echo round trip made insufficient progress for 30 seconds",
            )
        })??;
        if echoed != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP byte stream was corrupted, duplicated or reordered",
            ));
        }
        verified += payload.len() as u64;
        observe(Phase::Verified(payload.len()));
    }
    observe(Phase::Closing);
    writer.shutdown().await?;
    let mut trailing = [0];
    if timeout(Duration::from_secs(30), reader.read(&mut trailing))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "FIN exchange did not finish within 30 seconds",
            )
        })??
        != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected trailing bytes after echo",
        ));
    }
    Ok(verified)
}

#[tokio::test]
async fn tcp_recovers_from_syn_loss_packet_loss_delay_reordering_and_duplicates() {
    let settings = Impairment {
        seed: 17,
        drop_every: 97,
        duplicate_every: 23,
        reorder_every: 7,
        delay_ms: 1,
        reorder_delay_ms: 9,
        drop_first_syn: true,
    };
    let harness = Harness::new(8, settings);
    let result = timeout(
        // Each echo round and FIN already has a 30 s deadline, and connect is
        // bounded by 12 s. The envelope must allow all those bounded phases.
        Duration::from_secs(105),
        exchange(&harness.stack, 256 * 1024, 2, 42),
    )
    .await;
    if !matches!(result, Ok(Ok(_))) {
        eprintln!(
            "{}",
            serde_json::json!({"event":"fault_transfer_failed", "result":format!("{result:?}"), "resources":harness.report(), "uplink_trace":&*harness.uplink_trace.lock().unwrap(), "downlink_trace":&*harness.downlink_trace.lock().unwrap()})
        );
    }
    let verified = result.expect("impaired TCP transfer timed out").unwrap();
    assert_eq!(verified, 512 * 1024);
    let before = harness.report();
    assert!(before.uplink.dropped >= 1 && before.downlink.dropped >= 1);
    assert!(before.uplink.duplicated > 0 && before.downlink.duplicated > 0);
    assert!(before.uplink.reorder_delayed > 0 && before.downlink.reorder_delayed > 0);
    assert!(
        before.uplink.reordered_original_packets > 0
            && before.downlink.reordered_original_packets > 0
    );
    assert!(before.peer.tcp_bytes_received >= verified);
    assert_bounded(&before.stack, 8);
    let report = harness.close().await;
    eprintln!("{}", serde_json::to_string(&report).unwrap());
}

#[tokio::test]
async fn dropping_blocked_application_releases_zero_window_flow_promptly() {
    let harness = Harness::new(4, Impairment::default());
    harness.pause_peer_reads.store(true, Ordering::Relaxed);
    let mut stream = harness
        .stack
        .connect(ADDRESS.parse().unwrap())
        .await
        .unwrap();
    let writer = tokio::spawn(async move { stream.write_all(&vec![0x63; 2 * 1024 * 1024]).await });
    timeout(Duration::from_secs(2), async {
        while harness.report().downlink.tcp_zero_window_advertisements == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("peer did not advertise a zero TCP receive window");
    assert!(
        !writer.is_finished(),
        "peer should advertise a zero receive window"
    );
    assert_eq!(harness.stack.stats().active_tcp, 1);
    writer.abort();
    let _ = writer.await;
    let stats = wait_for_stats(&harness.stack, |stats| stats.active_tcp == 0).await;
    assert_eq!(stats.tcp_flows_released, 1);
    assert_bounded(&stats, 4);
    harness.close().await;
}

#[tokio::test(start_paused = true)]
async fn time_wait_budget_recovers_repeatedly_and_does_not_starve_udp_dns() {
    let harness = Harness::new(1, Impairment::default());
    for cycle in 0..12 {
        for connection in 0..2 {
            exchange(&harness.stack, 257, 1, cycle * 2 + connection)
                .await
                .unwrap();
        }
        wait_for_stats(&harness.stack, |stats| {
            stats.active_tcp == 0 && stats.time_wait == 2
        })
        .await;
        assert_eq!(
            harness
                .stack
                .connect(ADDRESS.parse().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let answer = harness
            .stack
            .udp_exchange(DNS.parse().unwrap(), b"DNS remains available".to_vec())
            .await
            .unwrap();
        assert_eq!(answer, b"DNS remains available");
        // smoltcp 0.14 currently retains TIME_WAIT for 10 s. Advance the runtime
        // clock; packets still traverse the normal actor/link/peer machinery.
        tokio::time::advance(Duration::from_secs(11)).await;
        wait_for_stats(&harness.stack, |stats| {
            stats.time_wait == 0 && stats.active_udp == 0
        })
        .await;
    }
    let stats = harness.stack.stats();
    assert_eq!(stats.tcp_connects_established, 24);
    assert_eq!(stats.tcp_admission_rejections, 12);
    assert_eq!(stats.udp_requests, 12);
    assert_eq!(stats.udp_admission_rejections, 0);
    assert_bounded(&stats, 1);
    harness.close().await;
}

#[tokio::test]
async fn cancelled_pending_connects_release_slots_and_transport_loss_closes_live_streams() {
    let blackhole = Harness::new(
        2,
        Impairment {
            drop_every: 1,
            ..Impairment::default()
        },
    );
    for _ in 0..16 {
        let stack = blackhole.stack.clone();
        let pending = tokio::spawn(async move { stack.connect(ADDRESS.parse().unwrap()).await });
        wait_for_stats(&blackhole.stack, |stats| stats.pending_tcp == 1).await;
        pending.abort();
        let _ = pending.await;
        wait_for_stats(&blackhole.stack, |stats| stats.active_tcp == 0).await;
    }
    assert_eq!(blackhole.stack.stats().tcp_connect_requests, 16);
    blackhole.close().await;

    let harness = Harness::new(4, Impairment::default());
    let mut streams = vec![];
    for _ in 0..4 {
        streams.push(
            harness
                .stack
                .connect(ADDRESS.parse().unwrap())
                .await
                .unwrap(),
        );
    }
    harness.link.cancel();
    timeout(Duration::from_secs(2), async {
        while !harness.stack.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for mut stream in streams {
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    assert_eq!(
        harness
            .stack
            .connect(ADDRESS.parse().unwrap())
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    harness.close().await;
}

#[tokio::test]
async fn oversized_udp_is_rejected_before_queueing() {
    let harness = Harness::new(1, Impairment::default());
    assert_eq!(
        harness
            .stack
            .udp_exchange(DNS.parse().unwrap(), vec![0; 1400])
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(harness.stack.stats().udp_requests, 0);
    assert_eq!(harness.stack.stats().command_queue, 0);
    harness.close().await;
}

#[derive(Clone, Default, Serialize)]
struct WorkStats {
    successful_connections: u64,
    completed_round_trips: u64,
    verified_payload_bytes: u64,
    admission_backpressure: u64,
    unexpected_errors: u64,
    cancelled_operations: u64,
    workers: Vec<WorkerProgress>,
}

#[derive(Clone, Default, Serialize)]
struct WorkerProgress {
    phase: &'static str,
    last_progress_ms: u128,
    completed_rounds: u64,
}

fn env_number(name: &str, default: u64, range: std::ops::RangeInclusive<u64>) -> u64 {
    let number = std::env::var(name)
        .map(|s| s.parse::<u64>().expect("soak option must be an integer"))
        .unwrap_or(default);
    assert!(range.contains(&number), "{name} is out of range");
    number
}

#[derive(Default, Serialize)]
struct Aggregate {
    generations: u64,
    packets_sent: u64,
    packets_received: u64,
    injected_drops: u64,
    injected_duplicates: u64,
    delayed_for_reordering: u64,
    reordered_original_packets: u64,
    peak_tcp_buffer_capacity_bytes: usize,
    peak_link_queue: usize,
    max_generation_cleanup_ms: u128,
}

/// Opt-in wall-clock soak. All endpoints are in-process raw-IP stacks; no
/// enterprise gateway, host destination socket, DNS setting or interface exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "wall-clock stress run; set GP_SOAK_SECONDS and use --ignored --nocapture"]
async fn dataplane_soak() {
    let seconds = env_number("GP_SOAK_SECONDS", 60, 1..=86400);
    let concurrency = env_number("GP_SOAK_CONCURRENCY", 4, 1..=32) as usize;
    let generation_seconds = env_number("GP_SOAK_GENERATION_SECONDS", 20, 1..=3600);
    let payload_bytes = env_number("GP_SOAK_PAYLOAD_BYTES", 16384, 1..=1048576) as usize;
    let long_rounds = env_number("GP_SOAK_LONG_ROUNDS", 8, 1..=1_000_000) as usize;
    let settings = Impairment {
        seed: env_number("GP_SOAK_SEED", 17, 0..=u32::MAX as u64),
        drop_every: env_number("GP_SOAK_DROP_EVERY", 97, 0..=100000),
        duplicate_every: env_number("GP_SOAK_DUPLICATE_EVERY", 23, 0..=100000),
        reorder_every: env_number("GP_SOAK_REORDER_EVERY", 7, 0..=100000),
        delay_ms: env_number("GP_SOAK_DELAY_MS", 1, 0..=1000),
        reorder_delay_ms: env_number("GP_SOAK_REORDER_DELAY_MS", 9, 0..=1000),
        drop_first_syn: true,
    };
    eprintln!(
        "{}",
        serde_json::json!({"event":"start", "seconds":seconds, "concurrency":concurrency, "generation_seconds":generation_seconds, "payload_bytes":payload_bytes, "long_rounds":long_rounds, "impairment":settings})
    );
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let work = Arc::new(Mutex::new(WorkStats {
        workers: vec![WorkerProgress::default(); concurrency],
        ..WorkStats::default()
    }));
    let mut aggregate = Aggregate::default();
    while Instant::now() < deadline {
        let max_connections = concurrency * 4 + 8;
        let harness = Harness::new(
            max_connections,
            Impairment {
                seed: settings.seed.wrapping_add(aggregate.generations),
                ..settings
            },
        );
        let workers_stop = CancellationToken::new();
        let mut workers = JoinSet::new();
        for worker in 0..concurrency {
            let stack = harness.stack.clone();
            let work = work.clone();
            let stop = workers_stop.clone();
            let uplink_trace = harness.uplink_trace.clone();
            let downlink_trace = harness.downlink_trace.clone();
            workers.spawn(async move {
                let mut iteration = 0;
                loop {
                    let rounds = if worker % 2 == 0 { long_rounds } else { 1 };
                    { let mut stats = work.lock().unwrap(); stats.workers[worker] = WorkerProgress { phase: "connect", last_progress_ms: started.elapsed().as_millis(), completed_rounds: 0 }; }
                    let observed = |phase| {
                        let mut stats = work.lock().unwrap();
                        match phase {
                            Phase::Connected => stats.workers[worker].phase = "echo_round",
                            Phase::Verified(bytes) => { stats.completed_round_trips += 1; stats.verified_payload_bytes += bytes as u64; stats.workers[worker].completed_rounds += 1; },
                            Phase::Closing => stats.workers[worker].phase = "fin",
                        }
                        stats.workers[worker].last_progress_ms = started.elapsed().as_millis();
                    };
                    let result = tokio::select! {
                        biased;
                        _ = stop.cancelled() => { work.lock().unwrap().cancelled_operations += 1; return; },
                        result = exchange_observed(&stack, payload_bytes, rounds, worker as u64 * 1000 + iteration, observed) => result,
                    };
                    match result {
                        Ok(_) => work.lock().unwrap().successful_connections += 1,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => { work.lock().unwrap().admission_backpressure += 1; tokio::time::sleep(Duration::from_millis(25)).await; }
                        failure => { let progress = { let mut stats = work.lock().unwrap(); stats.unexpected_errors += 1; stats.workers[worker].clone() }; eprintln!("{}", serde_json::json!({"event":"unexpected_error", "worker":worker, "elapsed_ms":started.elapsed().as_millis(), "progress":progress, "stack":stack.stats(), "detail":format!("{failure:?}"), "uplink_trace":&*uplink_trace.lock().unwrap(), "downlink_trace":&*downlink_trace.lock().unwrap()})); tokio::time::sleep(Duration::from_millis(25)).await; }
                    }
                    iteration += 1;
                }
            });
        }
        let generation_end = deadline.min(Instant::now() + Duration::from_secs(generation_seconds));
        let mut progress = tokio::time::interval(Duration::from_secs(10));
        progress.tick().await;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(generation_end) => break,
                _ = progress.tick() => {
                    let report = harness.report(); assert_bounded(&report.stack, max_connections);
                    eprintln!("{}", serde_json::json!({"event":"progress", "elapsed_seconds":started.elapsed().as_secs_f64(), "work":&*work.lock().unwrap(), "resources":report}));
                }
            }
        }
        let cleanup_started = Instant::now();
        workers_stop.cancel();
        harness.session.cancel();
        timeout(Duration::from_secs(2), async {
            while let Some(result) = workers.join_next().await {
                result.unwrap();
            }
        })
        .await
        .expect("workload tasks did not stop promptly");
        let report = harness.close().await;
        assert_bounded(&report.stack, max_connections);
        aggregate.generations += 1;
        aggregate.packets_sent += report.stack.ip_packets_sent;
        aggregate.packets_received += report.stack.ip_packets_received;
        aggregate.injected_drops += report.uplink.dropped + report.downlink.dropped;
        aggregate.injected_duplicates += report.uplink.duplicated + report.downlink.duplicated;
        aggregate.delayed_for_reordering +=
            report.uplink.reorder_delayed + report.downlink.reorder_delayed;
        aggregate.reordered_original_packets +=
            report.uplink.reordered_original_packets + report.downlink.reordered_original_packets;
        aggregate.peak_tcp_buffer_capacity_bytes = aggregate
            .peak_tcp_buffer_capacity_bytes
            .max(report.stack.peak_tcp_buffer_capacity_bytes);
        aggregate.peak_link_queue = aggregate
            .peak_link_queue
            .max(report.uplink.peak_queued)
            .max(report.downlink.peak_queued);
        aggregate.max_generation_cleanup_ms = aggregate
            .max_generation_cleanup_ms
            .max(cleanup_started.elapsed().as_millis());
        eprintln!(
            "{}",
            serde_json::json!({"event":"generation_stopped", "generation":aggregate.generations, "elapsed_seconds":started.elapsed().as_secs_f64(), "resources":report})
        );
    }
    let elapsed = started.elapsed().as_secs_f64();
    let work = work.lock().unwrap().clone();
    eprintln!(
        "{}",
        serde_json::json!({"event":"complete", "elapsed_seconds":elapsed, "verified_payload_mib_per_second":work.verified_payload_bytes as f64 / 1048576.0 / elapsed, "work":work, "aggregate":aggregate})
    );
    assert_eq!(
        work.unexpected_errors, 0,
        "soak observed unexpected network errors; inspect JSON events"
    );
    assert!(
        work.successful_connections > 0,
        "soak did not complete a verified TCP connection"
    );
}
