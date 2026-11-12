//! Opt-in, bounded raw-IP throughput baseline. No host sockets or VPN gateway.
//! Run the release build with --ignored --nocapture --test-threads=1. Four
//! persistent streams exclude short-connection/TIME_WAIT admission effects.
#[allow(dead_code)]
#[path = "support/dataplane.rs"]
mod dataplane;

use dataplane::{assert_bounded, Harness, Impairment, ADDRESS};
use serde::Serialize;
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::Barrier,
    task::JoinSet,
    time::{timeout, Instant},
};

const CONNECTIONS: usize = 4;
const PAYLOAD_BYTES: usize = 256 * 1024;
const MEASUREMENT: Duration = Duration::from_secs(10);
const ROUND_TIMEOUT: Duration = Duration::from_secs(10);
const LATENCY_SAMPLE_LIMIT: usize = 4096;

#[derive(Default)]
struct Latencies {
    count: u64,
    total_us: u128,
    minimum_us: Option<u64>,
    maximum_us: u64,
    samples_us: Vec<u64>,
}

#[derive(Serialize)]
struct LatencySummary {
    count: u64,
    minimum_ms: f64,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    maximum_ms: f64,
    retained_samples: usize,
    samples_truncated: bool,
}

impl Latencies {
    fn record(&mut self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap();
        self.count += 1;
        self.total_us += u128::from(micros);
        self.minimum_us = Some(self.minimum_us.map_or(micros, |old| old.min(micros)));
        self.maximum_us = self.maximum_us.max(micros);
        if self.samples_us.len() < LATENCY_SAMPLE_LIMIT {
            self.samples_us.push(micros);
        }
    }

    fn summary(&self) -> LatencySummary {
        assert!(self.count > 0);
        let mut samples = self.samples_us.clone();
        samples.sort_unstable();
        let percentile =
            |percent: usize| samples[(samples.len() * percent).div_ceil(100) - 1] as f64 / 1000.0;
        LatencySummary {
            count: self.count,
            minimum_ms: self.minimum_us.unwrap() as f64 / 1000.0,
            mean_ms: self.total_us as f64 / self.count as f64 / 1000.0,
            p50_ms: percentile(50),
            p95_ms: percentile(95),
            maximum_ms: self.maximum_us as f64 / 1000.0,
            retained_samples: samples.len(),
            samples_truncated: samples.len() as u64 != self.count,
        }
    }
}

struct CompletedWorker {
    worker: usize,
    stream: DuplexStream,
    latencies: Latencies,
    finished_at: Instant,
}

async fn transfer(
    worker: usize,
    stream: DuplexStream,
    ready: Arc<Barrier>,
    deadline: Instant,
) -> io::Result<CompletedWorker> {
    // A different worker pattern and monotonically changing round prefix also
    // detect stale echoes; a correct length alone is insufficient validation.
    let mut payload: Vec<u8> = (0..PAYLOAD_BYTES)
        .map(|offset| ((offset + worker * 31) % 251) as u8)
        .collect();
    let mut echoed = vec![0; PAYLOAD_BYTES];
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut latencies = Latencies::default();
    ready.wait().await;
    while Instant::now() < deadline {
        payload[..8].copy_from_slice(&latencies.count.to_le_bytes());
        let round_started = Instant::now();
        timeout(ROUND_TIMEOUT, async {
            tokio::try_join!(async { writer.write_all(&payload).await }, async {
                reader.read_exact(&mut echoed).await.map(|_| ())
            })
        })
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "baseline echo round exceeded 10 s")
        })??;
        if echoed != payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "baseline echo was corrupted, duplicated, reordered or stale",
            ));
        }
        // Includes the full equality check, rather than reporting unchecked I/O.
        latencies.record(round_started.elapsed());
    }
    Ok(CompletedWorker {
        worker,
        stream: reader.unsplit(writer),
        latencies,
        finished_at: Instant::now(),
    })
}

async fn scenario(delay_ms: u64) {
    let scenario_started = Instant::now();
    let impairment = Impairment {
        delay_ms,
        ..Impairment::default()
    };
    let harness = Harness::new(CONNECTIONS, impairment);
    let mut connecting = JoinSet::new();
    for worker in 0..CONNECTIONS {
        let stack = harness.stack.clone();
        connecting.spawn(async move {
            let started = Instant::now();
            let stream = stack.connect(ADDRESS.parse().unwrap()).await?;
            Ok::<_, io::Error>((worker, stream, started.elapsed()))
        });
    }
    let mut connections = Vec::with_capacity(CONNECTIONS);
    let mut connect_latencies = Latencies::default();
    while let Some(result) = connecting.join_next().await {
        let (worker, stream, elapsed) = result.expect("baseline connect task panicked").unwrap();
        connect_latencies.record(elapsed);
        connections.push((worker, stream));
    }
    let before = harness.report();
    assert_eq!(before.stack.active_tcp, CONNECTIONS);
    let ready = Arc::new(Barrier::new(CONNECTIONS + 1));
    let started = Instant::now();
    let deadline = started + MEASUREMENT;
    let mut transfers = JoinSet::new();
    for (worker, stream) in connections {
        transfers.spawn(transfer(worker, stream, ready.clone(), deadline));
    }
    ready.wait().await;
    eprintln!(
        "{}",
        serde_json::json!({"event":"baseline_started", "impairment":impairment,
            "connections":CONNECTIONS, "round_payload_bytes":PAYLOAD_BYTES,
            "nominal_window_seconds":MEASUREMENT.as_secs(), "tokio_worker_threads":2})
    );
    let mut completed = Vec::with_capacity(CONNECTIONS);
    while let Some(result) = transfers.join_next().await {
        match result.expect("baseline transfer task panicked") {
            Ok(worker) => completed.push(worker),
            Err(error) => {
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"baseline_failure", "delay_ms":delay_ms,
                        "error":error.to_string(), "resources":harness.report()})
                );
                panic!("no-fault baseline transfer failed: {error}");
            }
        }
    }
    completed.sort_unstable_by_key(|worker| worker.worker);
    let finished = completed
        .iter()
        .map(|worker| worker.finished_at)
        .max()
        .unwrap();
    let transfer_elapsed = finished.duration_since(started);
    let verified_bytes: u64 = completed
        .iter()
        .map(|worker| worker.latencies.count * PAYLOAD_BYTES as u64)
        .sum();
    // Statistics are published by another task. Wait for its final snapshot
    // without adding that observation delay to the transfer measurement.
    let measured = timeout(Duration::from_secs(2), async {
        loop {
            let report = harness.report();
            if report.peer.tcp_bytes_received == verified_bytes
                && report.peer.tcp_bytes_echoed == verified_bytes
            {
                break report;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer counters did not publish the verified byte totals");
    let per_connection: Vec<_> = completed
        .iter()
        .map(|worker| {
            assert!(worker.latencies.count > 0, "one stream made no progress");
            serde_json::json!({"worker":worker.worker,
                "verified_payload_bytes":worker.latencies.count * PAYLOAD_BYTES as u64,
                "echo_round_latency":worker.latencies.summary()})
        })
        .collect();
    assert_bounded(&measured.stack, CONNECTIONS);
    assert_eq!(measured.stack.tcp_connects_established, CONNECTIONS as u64);
    assert_eq!(measured.stack.tcp_admission_rejections, 0);
    assert_eq!(measured.peer.tcp_bytes_received, verified_bytes);
    assert_eq!(measured.peer.tcp_bytes_echoed, verified_bytes);

    let closing_started = Instant::now();
    let mut closing = JoinSet::new();
    for mut worker in completed {
        closing.spawn(async move {
            worker.stream.shutdown().await?;
            let mut trailing = [0];
            if worker.stream.read(&mut trailing).await? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trailing echo bytes",
                ));
            }
            Ok::<_, io::Error>(())
        });
    }
    timeout(Duration::from_secs(5), async {
        while let Some(result) = closing.join_next().await {
            result.expect("baseline FIN task panicked").unwrap();
        }
    })
    .await
    .expect("no-fault baseline FIN exchange exceeded 5 s");
    let fin_elapsed = closing_started.elapsed();
    let resources = harness.close().await;
    for link in [&resources.uplink, &resources.downlink] {
        assert_eq!(link.dropped + link.duplicated + link.reorder_delayed, 0);
        assert_eq!(link.reordered_original_packets, 0);
    }
    assert_eq!(resources.stack.tcp_flows_released, CONNECTIONS as u64);
    eprintln!(
        "{}",
        serde_json::json!({"event":"baseline_complete", "delay_ms_each_direction":delay_ms,
            "impairment":impairment, "connections":CONNECTIONS,
            "measurement_elapsed_seconds":transfer_elapsed.as_secs_f64(),
            "scenario_elapsed_seconds":scenario_started.elapsed().as_secs_f64(),
            "verified_payload_bytes":verified_bytes,
            "verified_payload_mib_per_second":verified_bytes as f64 / 1048576.0 / transfer_elapsed.as_secs_f64(),
            "bidirectional_application_bytes":verified_bytes * 2,
            "measurement_ip_packets_sent":measured.stack.ip_packets_sent - before.stack.ip_packets_sent,
            "measurement_ip_packets_received":measured.stack.ip_packets_received - before.stack.ip_packets_received,
            "measurement_ip_bytes_sent":measured.stack.ip_bytes_sent - before.stack.ip_bytes_sent,
            "measurement_ip_bytes_received":measured.stack.ip_bytes_received - before.stack.ip_bytes_received,
            "connect_latency":connect_latencies.summary(), "per_connection":per_connection,
            "fin_elapsed_seconds":fin_elapsed.as_secs_f64(), "resources_after_close":resources})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "30 s local throughput measurement; use release --ignored --nocapture --test-threads=1"]
async fn no_fault_dataplane_baseline() {
    timeout(Duration::from_secs(120), async {
        for delay_ms in [0, 1, 20] {
            scenario(delay_ms).await;
        }
    })
    .await
    .expect("bounded baseline suite exceeded 120 s");
}
