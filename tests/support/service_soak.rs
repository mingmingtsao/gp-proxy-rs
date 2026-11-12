//! Opt-in combined service/IPC/proxy/generation resource soak.
//! Only fixed synthetic identities, loopback TLS and in-memory IP peers are used.
//! The parent gateway caps workers at 8, events at 256 and tunnel queues at 64.
use super::*;
use crate::{control, control_local, session::proxy_lifecycle_tests::GenerationProbe};
use futures_util::FutureExt;
use std::{net::SocketAddr, path::PathBuf, sync::atomic::AtomicU64};
use tokio::time::Instant;

const FLOW_BYTES: usize = 8192;
const BUSINESS_LIMIT: usize = 8;
const STACK_LIMIT: usize = BUSINESS_LIMIT + crate::dns::MAX_DNS_SERVERS + 4;

#[derive(Default, serde::Serialize)]
struct Metrics {
    episodes: u64,
    rejected_logins: u64,
    cancelled_late_cookies: u64,
    logouts: u64,
    generations_released: u64,
    transport_recoveries: u64,
    live_flows_revoked: u64,
    pending_connects_failed: u64,
    stale_capabilities_rejected: u64,
    idle_ipc_expired: u64,
    periodic_hip_checks: u64,
    peak_stack_sockets: usize,
    peak_stack_buffer_bytes: usize,
    peak_stack_command_queue: usize,
    peak_stack_incoming_queue: usize,
    peak_stack_outgoing_queue: usize,
    largest_episode_events: usize,
    fd_idle_baseline: Option<usize>,
    fd_idle_max: Option<usize>,
}

#[derive(Default)]
struct Traffic {
    long_rounds: AtomicU64,
    short_connections: AtomicU64,
    verified_bytes: AtomicU64,
}
impl Traffic {
    fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "long_rounds": self.long_rounds.load(Ordering::SeqCst),
            "short_connections": self.short_connections.load(Ordering::SeqCst),
            "verified_payload_bytes": self.verified_bytes.load(Ordering::SeqCst),
        })
    }
}

enum ClientResult {
    Long(TcpStream),
    Short,
}

struct Local {
    directory: PathBuf,
    stop: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}
impl Local {
    fn start(gateway: &Gateway, running: &Running) -> Self {
        let directory = PathBuf::from(format!("/tmp/gp-soak-{:016x}", rand::random::<u64>()));
        let listener = control_local::LocalListener::bind(&directory).unwrap();
        let stop = CancellationToken::new();
        let task = tokio::spawn(control::serve(
            listener,
            gateway.origin.clone(),
            running.handle.clone(),
            stop.clone(),
        ));
        Self {
            directory,
            stop,
            task: Some(task),
        }
    }
    async fn authenticate(&self) -> io::Result<()> {
        let ready = control::preflight(&self.directory).await?;
        timeout(
            STEP,
            control::authenticate(
                &self.directory,
                ready,
                control::Authentication::Password {
                    user: Zeroizing::new("synthetic-user".into()),
                    password: Zeroizing::new("synthetic-password".into()),
                    computer: "synthetic-client".into(),
                },
            ),
        )
        .await
        .unwrap()
    }
    async fn hello(&self) -> (control_local::LocalStream, serde_json::Value) {
        timeout(STEP, async {
            let mut connection = control_local::connect(&self.directory).await.unwrap();
            let length = connection.stream.read_u32().await.unwrap() as usize;
            assert!((1..=4096).contains(&length));
            let mut bytes = vec![0; length];
            connection.stream.read_exact(&mut bytes).await.unwrap();
            let hello: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(hello["instance"], serde_json::json!(connection.instance_id));
            (connection.stream, hello)
        })
        .await
        .unwrap()
    }
    async fn submitted(&self) -> control_local::LocalStream {
        let (mut stream, hello) = self.hello().await;
        assert_eq!(hello["phase"], "waiting");
        let frame = serde_json::to_vec(&serde_json::json!({
            "op": "authenticate", "version": control::PROTOCOL_VERSION, "interactive": false, "instance": hello["instance"], "challenge": hello["challenge"],
            "binding": hello["binding"], "authentication": {
                "kind": "password", "user": "synthetic-user", "password": "synthetic-password",
                "computer": "synthetic-client"
            }
        }))
        .unwrap();
        timeout(STEP, async {
            stream.write_u32(frame.len() as u32).await.unwrap();
            stream.write_all(&frame).await.unwrap();
        })
        .await
        .unwrap();
        stream
    }
    async fn close(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            timeout(STEP, task).await.unwrap().unwrap().unwrap();
        }
        let mut entries: Vec<_> = std::fs::read_dir(&self.directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["lock", "owner"]);
        // This random directory was created by this fixture; no recursive
        // cleanup is performed until its exact permanent entry set is checked.
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
impl Drop for Local {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn descriptors() -> Option<usize> {
    let path = if cfg!(target_os = "macos") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    };
    std::fs::read_dir(path).ok().map(|entries| entries.count())
}

fn zero_status(running: &Running) {
    let status = running.connector.status();
    assert!(!status.available);
    assert_eq!(
        status.active_tcp
            + status.pending_tcp
            + status.active_udp
            + status.closing_tcp
            + status.command_queue
            + status.incoming_packets
            + status.outgoing_packets,
        0
    );
}

async fn ended(stream: &mut (impl tokio::io::AsyncRead + Unpin + ?Sized)) {
    let mut byte = [0; 1];
    assert!(matches!(
        timeout(STEP, stream.read(&mut byte)).await.unwrap(),
        Ok(0) | Err(_)
    ));
}

async fn begin_proxy(address: SocketAddr, socks: bool, target: [u8; 4]) -> TcpStream {
    timeout(STEP, async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        if socks {
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            stream.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            let [a, b, c, d] = target;
            stream
                .write_all(&[5, 1, 0, 1, a, b, c, d, 1, 187])
                .await
                .unwrap();
        } else {
            let ip = std::net::Ipv4Addr::from(target);
            stream
                .write_all(
                    format!("CONNECT {ip}:443 HTTP/1.1\r\nHost: {ip}:443\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
        }
        stream
    })
    .await
    .unwrap()
}
async fn proxy_result(stream: &mut TcpStream, socks: bool) -> u16 {
    if socks {
        let mut reply = [0; 10];
        timeout(STEP, stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[0], 5);
        u16::from(reply[1])
    } else {
        let header = http_header(stream).await;
        std::str::from_utf8(&header)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    }
}
async fn connected(address: SocketAddr, socks: bool) -> TcpStream {
    let mut stream = begin_proxy(address, socks, [10, 77, 0, 1]).await;
    assert_eq!(
        proxy_result(&mut stream, socks).await,
        if socks { 0 } else { 200 }
    );
    stream
}
async fn offline(addresses: (SocketAddr, SocketAddr)) {
    let mut http = begin_proxy(addresses.0, false, [10, 77, 0, 1]).await;
    let mut socks = begin_proxy(addresses.1, true, [10, 77, 0, 1]).await;
    let (h, s) = tokio::join!(
        proxy_result(&mut http, false),
        proxy_result(&mut socks, true)
    );
    assert_eq!((h, s), (502, 1));
}

async fn echo_round(
    stream: &mut TcpStream,
    id: u64,
    sequence: u64,
    traffic: &Traffic,
) -> io::Result<()> {
    let mut sent = [0x5a; FLOW_BYTES];
    sent[..8].copy_from_slice(&id.to_be_bytes());
    sent[8..16].copy_from_slice(&sequence.to_be_bytes());
    let mut received = [0; FLOW_BYTES];
    timeout(STEP, async {
        stream.write_all(&sent).await?;
        stream.read_exact(&mut received).await?;
        if sent != received {
            return Err(io::Error::other("synthetic soak payload mismatch"));
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    traffic
        .verified_bytes
        .fetch_add(FLOW_BYTES as u64, Ordering::SeqCst);
    Ok(())
}

async fn traffic_phase(
    clients: &mut JoinSet<io::Result<ClientResult>>,
    addresses: (SocketAddr, SocketAddr),
    duration: Duration,
    traffic: Arc<Traffic>,
    episode: u64,
) -> [TcpStream; 2] {
    assert!(clients.is_empty());
    let until = Instant::now() + duration;
    for (index, (address, socks)) in [(addresses.0, false), (addresses.1, true)]
        .into_iter()
        .enumerate()
    {
        let stream = connected(address, socks).await;
        let traffic = traffic.clone();
        clients.spawn(async move {
            let mut stream = stream;
            let mut sequence = 0;
            while Instant::now() < until || sequence == 0 {
                echo_round(&mut stream, episode * 8 + index as u64, sequence, &traffic).await?;
                traffic.long_rounds.fetch_add(1, Ordering::SeqCst);
                sequence += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok(ClientResult::Long(stream))
        });
    }
    let short_traffic = traffic.clone();
    clients.spawn(async move {
        // At most 24 short flows per generation. This exercises repeated FIN
        // cleanup without exceeding the deliberately small closing-slot budget.
        let spacing = duration / 12;
        for pair in 0..12u64 {
            if Instant::now() >= until {
                break;
            }
            let one = |address, socks, identity| {
                let traffic = short_traffic.clone();
                async move {
                    let mut stream = connected(address, socks).await;
                    echo_round(&mut stream, identity, pair, &traffic).await?;
                    timeout(STEP, async {
                        stream.shutdown().await?;
                        let mut byte = [0; 1];
                        let read = stream.read(&mut byte).await?;
                        if read != 0 {
                            return Err(io::Error::other("synthetic short-flow trailing byte"));
                        }
                        Ok::<_, io::Error>(())
                    })
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
                    traffic.short_connections.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, io::Error>(())
                }
            };
            let (http, socks) = tokio::join!(
                one(addresses.0, false, episode * 8 + 2),
                one(addresses.1, true, episode * 8 + 3)
            );
            http?;
            socks?;
            tokio::time::sleep(spacing).await;
        }
        Ok(ClientResult::Short)
    });
    let mut streams = Vec::with_capacity(2);
    let mut ticker = tokio::time::interval(Duration::from_secs(10));
    ticker.tick().await;
    while !clients.is_empty() {
        tokio::select! {
            result = clients.join_next() => match result.unwrap().unwrap().unwrap() {
                ClientResult::Long(stream) => streams.push(stream),
                ClientResult::Short => {},
            },
            _ = ticker.tick() => eprintln!("SERVICE_SOAK {}", serde_json::json!({
                "event": "flow_progress", "episode": episode, "traffic": traffic.snapshot()
            })),
        }
    }
    streams.try_into().ok().unwrap()
}

async fn release_probe(probe: &mut GenerationProbe, metrics: &mut Metrics) {
    let stats = probe.release_stack();
    assert!(stats.peak_socket_count <= STACK_LIMIT * 3);
    assert!(stats.peak_tcp_buffer_capacity_bytes <= STACK_LIMIT * 3 * 2 * 65536);
    assert!(stats.peak_command_queue <= STACK_LIMIT);
    assert!(stats.peak_incoming_queue <= 64 && stats.peak_outgoing_queue <= 64);
    metrics.peak_stack_sockets = metrics.peak_stack_sockets.max(stats.peak_socket_count);
    metrics.peak_stack_buffer_bytes = metrics
        .peak_stack_buffer_bytes
        .max(stats.peak_tcp_buffer_capacity_bytes);
    metrics.peak_stack_command_queue = metrics
        .peak_stack_command_queue
        .max(stats.peak_command_queue);
    metrics.peak_stack_incoming_queue = metrics
        .peak_stack_incoming_queue
        .max(stats.peak_incoming_queue);
    metrics.peak_stack_outgoing_queue = metrics
        .peak_stack_outgoing_queue
        .max(stats.peak_outgoing_queue);
    wait(|| !probe.generation_alive()).await;
    metrics.generations_released += 1;
}

async fn busy(local: &Local, running: &Running, gateway: &Gateway) {
    assert_ne!(running.handle.phase(), ServicePhase::Waiting);
    assert_eq!(
        control::preflight(&local.directory)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        running
            .handle
            .try_authenticate(password(), &gateway.origin, CancellationToken::new())
            .err(),
        Some(StartError::Busy)
    );
}

async fn finish_logout(gateway: &Gateway, running: &Running, local: &Local, index: usize) {
    wait(|| gateway.state.has(&Event::LogoutStart(index))).await;
    assert_eq!(gateway.state.active_tunnels.load(Ordering::SeqCst), 0);
    busy(local, running, gateway).await;
    // Keep the flag true until completion: LogoutStart is recorded before the
    // worker checks the flag. Clearing it earlier can leave an unused permit
    // that would silently bypass a later episode's gate.
    gateway.state.logout_gate.add_permits(1);
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    gateway.state.hold_logout.store(false, Ordering::SeqCst);
    assert!(gateway.state.has(&Event::LogoutDone(index)));
}

#[allow(clippy::too_many_arguments)]
async fn episode(
    gateway: &Gateway,
    running: &Running,
    local: &Local,
    clients: &mut JoinSet<io::Result<ClientResult>>,
    addresses: (SocketAddr, SocketAddr),
    traffic: Arc<Traffic>,
    metrics: &mut Metrics,
    long: bool,
) {
    assert_eq!(running.handle.phase(), ServicePhase::Waiting);
    assert!(gateway.state.events.lock().unwrap().is_empty());
    let before = gateway.state.logins.load(Ordering::SeqCst);
    let (mut slow, _) = local.hello().await;
    slow.write_u32(32).await.unwrap();
    slow.write_all(b"{").await.unwrap(); // Deliberately incomplete, no credentials.

    gateway.state.reject_login.store(true, Ordering::SeqCst);
    assert!(local.authenticate().await.is_err());
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    gateway.state.reject_login.store(false, Ordering::SeqCst);
    metrics.rejected_logins += 1;

    gateway.state.hold_login.store(true, Ordering::SeqCst);
    gateway.state.hold_logout.store(true, Ordering::SeqCst);
    let mut cancelled = local.submitted().await;
    wait(|| gateway.state.has(&Event::Login(before + 2))).await;
    busy(local, running, gateway).await;
    cancelled.shutdown().await.unwrap();
    ended(&mut *cancelled).await;
    drop(cancelled);
    gateway.state.login_gate.add_permits(1);
    finish_logout(gateway, running, local, before + 2).await;
    gateway.state.hold_login.store(false, Ordering::SeqCst);
    metrics.cancelled_late_cookies += 1;

    gateway
        .state
        .lifetime
        .store(if long { 70 } else { 8 }, Ordering::SeqCst);
    gateway.state.hold_logout.store(true, Ordering::SeqCst);
    local.authenticate().await.unwrap();
    wait(|| running.connector.status().available).await;
    let index = before + 3;
    busy(local, running, gateway).await;
    let mut first = GenerationProbe::capture(&running.connector);
    let mut live = traffic_phase(
        clients,
        addresses,
        Duration::from_secs(if long { 62 } else { 2 }),
        traffic.clone(),
        metrics.episodes,
    )
    .await;
    if long {
        let hips = gateway
            .state
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == Event::Hip(index))
            .count();
        assert!(
            hips >= 2,
            "long phase must complete an actual periodic HIP request"
        );
        metrics.periodic_hip_checks += (hips - 1) as u64;
    }
    let connector = running.connector.clone();
    let stale = connector.connect(Target::new("10.77.0.1", 443).unwrap());
    let mut pending_http = begin_proxy(addresses.0, false, [10, 77, 0, 99]).await;
    let mut pending_socks = begin_proxy(addresses.1, true, [10, 77, 0, 99]).await;
    wait(|| first.stats().pending_tcp == 2).await;
    gateway.state.hold_config.store(true, Ordering::SeqCst);
    gateway
        .state
        .tunnel
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .cancel();
    wait(|| first.is_closed() && !running.connector.status().available).await;
    for stream in &mut live {
        ended(stream).await;
    }
    drop(live);
    let (h, s) = tokio::join!(
        proxy_result(&mut pending_http, false),
        proxy_result(&mut pending_socks, true)
    );
    assert_eq!((h, s), (502, 1));
    drop((pending_http, pending_socks));
    metrics.live_flows_revoked += 2;
    metrics.pending_connects_failed += 2;
    offline(addresses).await;
    assert!(pac_document(addresses.0)
        .await
        .contains("remembered.corp.example"));
    wait(|| {
        gateway
            .state
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == Event::Config(index))
            .count()
            == 2
    })
    .await;
    assert!(!running.connector.status().available);
    gateway.state.config_gate.add_permits(1);
    wait(|| running.connector.status().available).await;
    gateway.state.hold_config.store(false, Ordering::SeqCst);
    assert_eq!(
        stale.await.err().unwrap().kind(),
        io::ErrorKind::NotConnected
    );
    metrics.stale_capabilities_rejected += 1;
    release_probe(&mut first, metrics).await;
    metrics.transport_recoveries += 1;
    let mut second = GenerationProbe::capture(&running.connector);
    let mut live = traffic_phase(
        clients,
        addresses,
        Duration::from_secs(2),
        traffic,
        metrics.episodes,
    )
    .await;
    wait(|| gateway.state.has(&Event::LogoutStart(index))).await;
    for stream in &mut live {
        ended(stream).await;
    }
    drop(live);
    release_probe(&mut second, metrics).await;
    metrics.live_flows_revoked += 2;
    finish_logout(gateway, running, local, index).await;
    ended(&mut *slow).await;
    drop(slow);
    metrics.idle_ipc_expired += 1;
    wait(|| gateway.state.active_workers.load(Ordering::SeqCst) == 0).await;
    assert_eq!(gateway.state.active_tunnels.load(Ordering::SeqCst), 0);
    assert!(gateway.state.tunnel.lock().unwrap().is_none());
    assert_eq!(gateway.state.login_gate.available_permits(), 0);
    assert_eq!(gateway.state.config_gate.available_permits(), 0);
    assert_eq!(gateway.state.logout_gate.available_permits(), 0);
    zero_status(running);
    offline(addresses).await;
    assert!(pac_document(addresses.0)
        .await
        .contains("remembered.corp.example"));
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), before + 3);

    // Do not truncate evidence in flight. First prove all requests have joined,
    // validate every event and exact once cleanup, then reuse the fixed buffer.
    let mut events = gateway.state.events.lock().unwrap();
    let count = |expected: Event| events.iter().filter(|event| **event == expected).count();
    assert_eq!(count(Event::Prelogin), 3);
    assert_eq!(count(Event::Config(before + 1)), 0);
    assert_eq!(count(Event::Config(before + 2)), 0);
    assert_eq!(count(Event::Config(index)), 2);
    assert_eq!(count(Event::LogoutStart(before + 1)), 0);
    for cookie in [before + 2, index] {
        assert_eq!(count(Event::LogoutStart(cookie)), 1);
        assert_eq!(count(Event::LogoutDone(cookie)), 1);
    }
    assert_eq!(
        count(Event::TunnelOpen(before + 1)) + count(Event::TunnelOpen(before + 2)),
        0
    );
    assert_eq!(count(Event::TunnelOpen(index)), 2);
    assert_eq!(count(Event::TunnelClosed(index)), 2);
    let done = events
        .iter()
        .position(|event| *event == Event::LogoutDone(before + 2))
        .unwrap();
    let next = events
        .iter()
        .position(|event| *event == Event::Login(index))
        .unwrap();
    assert!(done < next);
    metrics.largest_episode_events = metrics.largest_episode_events.max(events.len());
    assert!(events.len() <= 256);
    events.clear();
    drop(events);
    metrics.logouts += 2;
    metrics.episodes += 1;
    if let Some(fd) = descriptors() {
        let baseline = *metrics.fd_idle_baseline.get_or_insert(fd);
        // Exact-filtered single-test runs make this meaningful; allow two
        // transient runtime descriptors but reject cumulative per-episode growth.
        assert!(
            fd <= baseline + 2,
            "idle descriptor count grew across episodes: baseline={baseline} current={fd}"
        );
        metrics.fd_idle_max = Some(metrics.fd_idle_max.unwrap_or(0).max(fd));
    }
    eprintln!(
        "SERVICE_SOAK {}",
        serde_json::json!({"event": "episode_complete", "metrics": metrics})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "bounded explicit service/IPC/long-flow soak; run alone with --test-threads=1"]
async fn bounded_mixed_service_ipc_generation_soak() {
    let seconds = std::env::var("GP_PROXY_SERVICE_SOAK_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>().expect("invalid service soak duration"))
        .unwrap_or(300);
    assert!((20..=86400).contains(&seconds));
    let long = seconds >= 90;
    let started = Instant::now();
    let local_addresses = timeout(STEP, tokio::net::lookup_host(("localhost", 0)))
        .await
        .unwrap()
        .unwrap()
        .collect::<Vec<_>>();
    assert!(
        !local_addresses.is_empty()
            && local_addresses
                .iter()
                .all(|address| address.ip().is_loopback())
    );
    let fd_before = descriptors();
    let gateway = Gateway::new().await;
    let running = Running::configured(
        &gateway,
        Config {
            gateway: gateway.origin.clone(),
            domains: vec!["local.corp.example".into()],
            networks: vec!["10.77.0.0/24".parse().unwrap()],
            trust_gateway_routes: true,
            max_connections: BUSINESS_LIMIT,
            reconnect_max_secs: 1,
            connect_timeout_secs: 12,
            idle_timeout_secs: 20,
            hip_check_interval_secs: 60,
            ..Config::default()
        },
        CancellationToken::new(),
    );
    let mut local = Local::start(&gateway, &running);
    let proxy = ProxyServer::bind(ProxyConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        socks_addr: "127.0.0.1:0".parse().unwrap(),
        max_connections: 8,
        handshake_timeout: Duration::from_secs(12),
        idle_timeout: Duration::from_secs(20),
    })
    .await
    .unwrap();
    let addresses = proxy.local_addrs();
    let (proxy_stop, stopping) = watch::channel(false);
    let proxy_task =
        tokio::spawn(proxy.serve(running.connector.clone(), running.pac.clone(), stopping));
    let mut clients = JoinSet::new();
    let traffic = Arc::new(Traffic::default());
    let mut metrics = Metrics::default();
    eprintln!(
        "SERVICE_SOAK {}",
        serde_json::json!({
            "event": "started", "pid": std::process::id(), "requested_seconds": seconds,
            "long_hip_phase_enabled": long, "gateway_workers": 8, "gateway_event_capacity": 256,
            "peer_tcp_listeners": 4, "packet_queue_per_direction": 64, "proxy_clients": 8,
            "client_tasks": 3, "business_limit": BUSINESS_LIMIT, "stack_limit": STACK_LIMIT,
        })
    );
    let result = std::panic::AssertUnwindSafe(timeout(Duration::from_secs(seconds + 30), async {
        while started.elapsed() < Duration::from_secs(seconds) || metrics.episodes < 2 {
            let first_long = long && metrics.episodes == 0;
            episode(
                &gateway,
                &running,
                &local,
                &mut clients,
                addresses,
                traffic.clone(),
                &mut metrics,
                first_long,
            )
            .await;
        }
        // Cross a transport backoff interval after the last cookie is gone;
        // there must be no password replay or timer-driven new login.
        let logins = gateway.state.logins.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), logins);
        assert!(gateway.state.events.lock().unwrap().is_empty());
        if long {
            assert!(metrics.periodic_hip_checks >= 1);
        }
    }))
    .catch_unwind()
    .await;

    // This cleanup is outside the caught work future. It also runs after an
    // assertion or total deadline: release synthetic gates, cancel, abort/join
    // clients, then join all servers. Runtime destruction is the last resort
    // only if this separate bounded cleanup itself fails.
    gateway.state.hold_login.store(false, Ordering::SeqCst);
    gateway.state.hold_config.store(false, Ordering::SeqCst);
    gateway.state.hold_logout.store(false, Ordering::SeqCst);
    gateway.state.login_gate.add_permits(8);
    gateway.state.config_gate.add_permits(8);
    gateway.state.logout_gate.add_permits(8);
    running.stop.cancel();
    local.stop.cancel();
    proxy_stop.send_replace(true);
    clients.abort_all();
    while let Some(joined) = clients.join_next().await {
        if let Err(error) = joined {
            assert!(error.is_cancelled() || result.is_err());
        }
    }
    let connector = running.connector.clone();
    let state = gateway.state.clone();
    timeout(Duration::from_secs(30), async {
        local.close().await;
        running.close().await;
        timeout(STEP, proxy_task).await.unwrap().unwrap().unwrap();
        gateway.close().await;
    })
    .await
    .expect("service soak cleanup exceeded separate deadline");
    assert_eq!(state.active_workers.load(Ordering::SeqCst), 0);
    assert_eq!(state.active_tunnels.load(Ordering::SeqCst), 0);
    assert!(!connector.status().available);
    let fd_after = descriptors();
    if result.as_ref().is_ok_and(|work| work.is_ok()) {
        assert_eq!(
            fd_before, fd_after,
            "owned service descriptors did not return to warmed baseline"
        );
    }
    let _http = TcpListener::bind(addresses.0).await.unwrap();
    let _socks = TcpListener::bind(addresses.1).await.unwrap();
    eprintln!(
        "SERVICE_SOAK {}",
        serde_json::json!({
            "event": "cleaned", "elapsed_seconds": started.elapsed().as_secs_f64(),
            "work_succeeded": result.as_ref().is_ok_and(|work| work.is_ok()), "metrics": metrics,
            "traffic": traffic.snapshot(), "fd_before": fd_before, "fd_after": fd_after,
            "all_owned_tasks_joined": true, "proxy_ports_rebound": true,
        })
    );
    match result {
        Ok(result) => result.expect("service soak work exceeded total deadline"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
