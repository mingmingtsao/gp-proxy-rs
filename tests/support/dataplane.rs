//! Bounded, in-process IP link and independent smoltcp echo peer. No host sockets.
use gp_proxy::stack::{self, StackConfig, StackHandle, StackStats};
use std::{
    collections::VecDeque,
    io,
    net::Ipv4Addr,
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

#[path = "echo_peer.rs"]
mod echo_peer;
pub(crate) use echo_peer::run_peer;
pub use echo_peer::PeerStats;

const PACKETS: usize = 64;
pub const ADDRESS: &str = "10.77.0.1:443";
pub const DNS: &str = "10.77.0.1:53";

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Impairment {
    pub seed: u64,
    pub drop_every: u64,
    pub duplicate_every: u64,
    pub reorder_every: u64,
    pub delay_ms: u64,
    pub reorder_delay_ms: u64,
    pub drop_first_syn: bool,
}

impl Default for Impairment {
    fn default() -> Self {
        Self {
            seed: 17,
            drop_every: 0,
            duplicate_every: 0,
            reorder_every: 0,
            delay_ms: 0,
            reorder_delay_ms: 0,
            drop_first_syn: false,
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct LinkStats {
    pub received: u64,
    pub forwarded: u64,
    pub dropped: u64,
    pub duplicated: u64,
    pub reorder_delayed: u64,
    pub reordered_original_packets: u64,
    pub tcp_zero_window_advertisements: u64,
    pub peak_queued: usize,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PacketTrace {
    elapsed_ms: u128,
    event: &'static str,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    window: u16,
    payload_bytes: usize,
}
pub type Traces = Arc<Mutex<VecDeque<PacketTrace>>>;

fn trace_packet(trace: &Traces, packet: &[u8], started: Instant, event: &'static str) {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return;
    }
    let ip = (packet[0] as usize & 15) * 4;
    let Some(tcp) = packet.get(ip..) else {
        return;
    };
    if tcp.len() < 20 {
        return;
    }
    let offset = (tcp[12] as usize >> 4) * 4;
    if offset > tcp.len() {
        return;
    }
    let entry = PacketTrace {
        elapsed_ms: started.elapsed().as_millis(),
        event,
        source_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        destination_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        sequence: u32::from_be_bytes(tcp[4..8].try_into().unwrap()),
        acknowledgement: u32::from_be_bytes(tcp[8..12].try_into().unwrap()),
        flags: tcp[13],
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        payload_bytes: tcp.len() - offset,
    };
    let mut trace = trace.lock().unwrap();
    if trace.len() >= 512 {
        trace.pop_front();
    }
    trace.push_back(entry);
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub stack: StackStats,
    pub uplink: LinkStats,
    pub downlink: LinkStats,
    pub peer: PeerStats,
}

pub struct Harness {
    pub stack: StackHandle,
    pub session: CancellationToken,
    pub link: CancellationToken,
    pub pause_peer_reads: Arc<AtomicBool>,
    stop: CancellationToken,
    stack_task: Option<JoinHandle<io::Result<()>>>,
    tasks: JoinSet<io::Result<()>>,
    uplink: Arc<Mutex<LinkStats>>,
    downlink: Arc<Mutex<LinkStats>>,
    peer: Arc<Mutex<PeerStats>>,
    pub uplink_trace: Traces,
    pub downlink_trace: Traces,
}

impl Harness {
    pub fn new(max_connections: usize, impairment: Impairment) -> Self {
        let stop = CancellationToken::new();
        let session = stop.child_token();
        let link = stop.child_token();
        let (client_tx, client_rx) = mpsc::channel(PACKETS);
        let (stack_tx, stack_rx) = mpsc::channel(PACKETS);
        let (peer_tx, peer_rx) = mpsc::channel(PACKETS);
        let (peer_out, peer_packets) = mpsc::channel(PACKETS);
        let (stack, stack_task) = stack::spawn(
            StackConfig {
                ipv4: Ipv4Addr::new(10, 77, 0, 2),
                ipv6: None,
                mtu: 1400,
                max_connections,
                connect_timeout: Duration::from_secs(12),
                idle_timeout: Duration::from_secs(60),
                random_seed: impairment.seed,
            },
            client_rx,
            stack_tx,
            session.clone(),
        )
        .unwrap();
        let uplink = Arc::new(Mutex::new(LinkStats::default()));
        let downlink = Arc::new(Mutex::new(LinkStats::default()));
        let peer = Arc::new(Mutex::new(PeerStats::default()));
        let pause_peer_reads = Arc::new(AtomicBool::new(false));
        let mut tasks = JoinSet::new();
        let uplink_trace = Arc::new(Mutex::new(VecDeque::new()));
        let downlink_trace = Arc::new(Mutex::new(VecDeque::new()));
        tasks.spawn(run_link(
            stack_rx,
            peer_tx,
            impairment,
            link.clone(),
            uplink.clone(),
            uplink_trace.clone(),
        ));
        let reverse = Impairment {
            seed: impairment.seed.wrapping_add(31),
            ..impairment
        };
        tasks.spawn(run_link(
            peer_packets,
            client_tx,
            reverse,
            link.clone(),
            downlink.clone(),
            downlink_trace.clone(),
        ));
        tasks.spawn(run_peer(
            peer_rx,
            peer_out,
            stop.clone(),
            peer.clone(),
            pause_peer_reads.clone(),
            (max_connections * 2 + 2).clamp(4, 128),
            impairment.seed,
        ));
        Self {
            stack,
            session,
            link,
            pause_peer_reads,
            stop,
            stack_task: Some(stack_task),
            tasks,
            uplink,
            downlink,
            peer,
            uplink_trace,
            downlink_trace,
        }
    }

    pub fn report(&self) -> Report {
        Report {
            stack: self.stack.stats(),
            uplink: self.uplink.lock().unwrap().clone(),
            downlink: self.downlink.lock().unwrap().clone(),
            peer: self.peer.lock().unwrap().clone(),
        }
    }

    pub async fn close(mut self) -> Report {
        self.stop.cancel();
        let result = tokio::time::timeout(Duration::from_secs(3), self.stack_task.take().unwrap())
            .await
            .expect("stack cancellation exceeded 3 seconds")
            .expect("stack task panicked");
        if let Err(error) = result {
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(result) = self.tasks.join_next().await {
                result
                    .expect("link or peer task panicked")
                    .expect("link or peer failed");
            }
        })
        .await
        .expect("harness cancellation exceeded 3 seconds");
        let report = self.report();
        assert_eq!(
            report.stack.active_tcp
                + report.stack.active_udp
                + report.stack.time_wait
                + report.stack.socket_count
                + report.stack.command_queue
                + report.stack.incoming_queue
                + report.stack.outgoing_queue
                + report.stack.tcp_buffer_capacity_bytes,
            0,
            "actor exit did not clear resource gauges"
        );
        report
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.cancel();
        self.tasks.abort_all();
        if let Some(task) = self.stack_task.take() {
            task.abort();
        }
    }
}

fn every(sequence: u64, period: u64) -> bool {
    period != 0 && sequence.is_multiple_of(period)
}
fn initial_syn(packet: &[u8]) -> bool {
    packet.len() >= 40 && packet[0] >> 4 == 4 && packet[9] == 6 && {
        let header = (packet[0] as usize & 15) * 4;
        packet
            .get(header + 13)
            .is_some_and(|flags| flags & 0x12 == 0x02)
    }
}

fn zero_tcp_window(packet: &[u8]) -> bool {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return false;
    }
    let header = (packet[0] as usize & 15) * 4;
    packet
        .get(header + 13)
        .is_some_and(|flags| flags & 0x10 != 0)
        && packet
            .get(header + 14..header + 16)
            .is_some_and(|window| window == [0, 0])
}

struct Scheduled {
    due: Instant,
    sequence: u64,
    duplicate: bool,
    packet: Vec<u8>,
}

pub(crate) async fn run_link(
    mut input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    settings: Impairment,
    stop: CancellationToken,
    shared: Arc<Mutex<LinkStats>>,
    trace: Traces,
) -> io::Result<()> {
    let mut queued: VecDeque<Scheduled> = VecDeque::new();
    let mut stats = LinkStats::default();
    let mut first_syn_dropped = false;
    let mut highest_original_delivered = 0;
    let started = Instant::now();
    'link: loop {
        while queued
            .front()
            .is_some_and(|packet| packet.due <= Instant::now())
        {
            let scheduled = queued.pop_front().unwrap();
            trace_packet(
                &trace,
                &scheduled.packet,
                started,
                if scheduled.duplicate {
                    "duplicate"
                } else {
                    "deliver"
                },
            );
            tokio::select! {
                _ = stop.cancelled() => break 'link,
                result = output.send(scheduled.packet) => { if result.is_err() { break 'link; } stats.forwarded += 1; }
            }
            if !scheduled.duplicate {
                if scheduled.sequence < highest_original_delivered {
                    stats.reordered_original_packets += 1;
                }
                highest_original_delivered = highest_original_delivered.max(scheduled.sequence);
            }
        }
        *shared.lock().unwrap() = stats.clone();
        let deadline = queued
            .front()
            .map(|packet| packet.due)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
        tokio::select! {
            _ = stop.cancelled() => break 'link,
            _ = tokio::time::sleep_until(deadline), if !queued.is_empty() => {},
            packet = input.recv(), if queued.len() < PACKETS => {
                let Some(packet) = packet else { break 'link; };
                stats.received += 1;
                if zero_tcp_window(&packet) { stats.tcp_zero_window_advertisements += 1; }
                let sequence = stats.received.wrapping_add(settings.seed);
                let syn_loss = settings.drop_first_syn && !first_syn_dropped && initial_syn(&packet);
                if syn_loss { first_syn_dropped = true; }
                if syn_loss || every(sequence, settings.drop_every) { stats.dropped += 1; trace_packet(&trace, &packet, started, "drop"); continue; }
                let reorder = every(sequence, settings.reorder_every);
                if reorder { stats.reorder_delayed += 1; }
                let delay = settings.delay_ms + if reorder { settings.reorder_delay_ms } else { 0 };
                let due = Instant::now() + Duration::from_millis(delay);
                if every(sequence, settings.duplicate_every) && queued.len() + 2 <= PACKETS {
                    let duplicate_due = due + Duration::from_millis(1);
                    let position = queued.iter().position(|packet| packet.due > duplicate_due).unwrap_or(queued.len());
                    queued.insert(position, Scheduled { due: duplicate_due, sequence: stats.received, duplicate: true, packet: packet.clone() });
                    stats.duplicated += 1;
                }
                let position = queued.iter().position(|packet| packet.due > due).unwrap_or(queued.len());
                queued.insert(position, Scheduled { due, sequence: stats.received, duplicate: false, packet });
                stats.peak_queued = stats.peak_queued.max(queued.len());
            }
        }
    }
    *shared.lock().unwrap() = stats;
    Ok(())
}

pub fn assert_bounded(stats: &StackStats, connections: usize) {
    assert_eq!(
        stats.socket_count,
        stats.active_tcp + stats.active_udp + stats.time_wait,
        "smoltcp socket is not owned by an active/retired flow"
    );
    assert!(stats.peak_socket_count <= connections + (connections * 2).min(512));
    assert!(stats.active_tcp + stats.active_udp <= connections);
    assert!(stats.peak_active_tcp <= connections);
    assert!(stats.peak_active_udp <= connections);
    assert!(stats.peak_time_wait <= (connections * 2).min(512));
    assert!(stats.peak_command_queue <= connections.min(128));
    assert!(stats.peak_incoming_queue <= PACKETS);
    assert!(stats.peak_outgoing_queue <= PACKETS);
    let buffer_budget =
        connections * (64 * 1024 * 2 + 32 * 1024 * 2) + (connections * 2).min(512) * 64 * 1024 * 2;
    assert!(stats.peak_tcp_buffer_capacity_bytes <= buffer_budget);
}

pub async fn wait_for_stats(
    stack: &StackHandle,
    predicate: impl Fn(&StackStats) -> bool,
) -> StackStats {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let stats = stack.stats();
            if predicate(&stats) {
                return stats;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("expected stack resource state was not reached within 2 seconds")
}
