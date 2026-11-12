//! Repeated mixed challenge/service/IPC episodes on one stable daemon.
//! All authentication is synthetic; business packets stay in the memory peer.
use super::*;
use crate::{
    proxy::{Connector, ProxyConfig, ProxyServer, Target},
    session::proxy_lifecycle_tests::GenerationProbe,
};
use futures_util::FutureExt;
use std::net::SocketAddr;
use tokio::net::TcpStream;

const BUSINESS: usize = 8;
const STACK: usize = BUSINESS + crate::dns::MAX_DNS_SERVERS + 4;
const PAYLOAD: usize = 8192;

#[derive(Default, serde::Serialize)]
struct Metrics {
    cycles: u64,
    authentications: u64,
    prompts_cancelled: u64,
    answer_tls_cancelled: u64,
    late_cookies_cleaned: u64,
    rejected: u64,
    round_limits: u64,
    stale_nonces_rejected: u64,
    nonce_checks: u64,
    password_posts: u64,
    answer_posts: u64,
    generations_released: u64,
    old_connects_rejected_after_new_generation: u64,
    live_flows_revoked: u64,
    pending_connects_failed: u64,
    verified_payload_bytes: u64,
    echo_rounds: u64,
    logouts: u64,
    max_cycle_requests: usize,
    peak_stack_sockets: usize,
    peak_stack_buffer_bytes: usize,
    peak_stack_command_queue: usize,
    peak_stack_incoming_queue: usize,
    peak_stack_outgoing_queue: usize,
    idle_fd_baseline: Option<usize>,
    idle_fd_peak: Option<usize>,
}
#[derive(Default)]
struct Nonces {
    previous: Vec<[u8; 16]>,
    current: Vec<[u8; 16]>,
}
impl Nonces {
    fn begin(&mut self) {
        assert!(self.current.is_empty());
    }
    fn observe(&mut self, challenge: &Value, metrics: &mut Metrics) {
        let nonce: [u8; 16] = serde_json::from_value(challenge["round_nonce"].clone()).unwrap();
        assert!(!self.previous.contains(&nonce) && !self.current.contains(&nonce));
        assert!(self.current.len() < 4);
        self.current.push(nonce);
        metrics.nonce_checks += 1;
    }
    fn finish(&mut self) {
        if !self.current.is_empty() {
            self.previous = std::mem::take(&mut self.current);
        }
        assert!(self.previous.len() <= 4);
    }
}
struct Expected {
    answers: Vec<String>,
    activated: bool,
    logout: bool,
}
fn descriptors() -> usize {
    std::fs::read_dir(if cfg!(target_os = "macos") {
        "/dev/fd"
    } else {
        "/proc/self/fd"
    })
    .expect("supported native soak must be able to sample its own descriptor directory")
    .fold(0, |count, entry| {
        entry.expect("owned descriptor entry must be readable");
        count + 1
    })
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
fn setup(gateway: &Gateway) -> (Running, watch::Receiver<Arc<Policy>>) {
    let config = Config {
        gateway: gateway.origin.clone(),
        domains: vec!["synthetic-challenge.invalid".into()],
        networks: vec!["10.77.0.0/24".parse().unwrap()],
        max_connections: BUSINESS,
        connect_timeout_secs: 12,
        idle_timeout_secs: 20,
        reconnect_max_secs: 1,
        ..Config::default()
    };
    let stop = CancellationToken::new();
    let connector = Arc::new(TunnelConnector::default());
    let (pac_send, pac) = watch::channel(Arc::new(
        Policy::new(config.domains.clone(), config.networks.clone()).unwrap(),
    ));
    let (handle, service) = new(
        config,
        gateway.client.clone(),
        connector.clone(),
        pac_send,
        stop.clone(),
    )
    .unwrap();
    (
        Running {
            handle,
            connector,
            stop,
            task: Some(tokio::spawn(service.run())),
        },
        pac,
    )
}
async fn idle(gateway: &Gateway, running: &Running) {
    wait(|| running.handle.phase() == ServicePhase::Waiting && gateway.state.workers() == 0).await;
    assert_eq!(gateway.state.tunnels(), 0);
    zero_status(running);
}
async fn busy(ipc: &Ipc, running: &Running) {
    assert_ne!(running.handle.phase(), ServicePhase::Waiting);
    assert_eq!(
        control::preflight(&ipc.directory)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}
async fn disconnect(mut stream: control_local::LocalStream) {
    stream.shutdown().await.unwrap();
    closed(stream).await; // Server has observed EOF and cancelled this operation.
}
async fn answer(
    stream: &mut control_local::LocalStream,
    hello: &Value,
    challenge: &Value,
    epoch: usize,
    authentication: usize,
    expected: &mut Expected,
) {
    let round = challenge["round"].as_u64().unwrap();
    let secret = format!("soak-answer-{epoch}-{authentication}-{round}");
    expected.answers.push(secret.clone());
    assert!(expected.answers.len() <= 4);
    let mut frame = response(hello, challenge);
    frame["answer"] = json!(secret);
    timeout(STEP, stream.write_all(&encode(&frame)))
        .await
        .unwrap()
        .unwrap();
}
async fn next_prompt(
    stream: &mut control_local::LocalStream,
    nonces: &mut Nonces,
    metrics: &mut Metrics,
) -> Value {
    let prompt = raw_challenge(stream).await;
    assert_eq!(
        prompt["round"].as_u64().unwrap() as usize,
        nonces.current.len() + 1
    );
    nonces.observe(&prompt, metrics);
    prompt
}
async fn failed(stream: &mut control_local::LocalStream) {
    assert_eq!(receive(stream).await["result"], "failed");
}
fn plan(gateway: &Gateway, nonces: &mut Nonces, outcomes: &[Outcome]) -> Expected {
    gateway.state.plan(outcomes);
    nonces.begin();
    Expected {
        answers: Vec::with_capacity(4),
        activated: false,
        logout: false,
    }
}
async fn finish_plan(
    gateway: &Gateway,
    running: &Running,
    nonces: &mut Nonces,
    remaining: &[Outcome],
) {
    idle(gateway, running).await;
    gateway.state.finish_plan(remaining);
    nonces.finish();
}

async fn proxy_start(address: SocketAddr, socks: bool, host: u8) -> TcpStream {
    timeout(STEP, async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        if socks {
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut reply = [0; 2];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0]);
            stream
                .write_all(&[5, 1, 0, 1, 10, 77, 0, host, 1, 187])
                .await
                .unwrap();
        } else {
            stream
                .write_all(
                    format!(
                        "CONNECT 10.77.0.{host}:443 HTTP/1.1\r\nHost: 10.77.0.{host}:443\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
        stream
    })
    .await
    .unwrap()
}
async fn proxy_reply(stream: &mut TcpStream, socks: bool) -> u16 {
    timeout(STEP, async {
        if socks {
            let mut reply = [0; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 5);
            u16::from(reply[1])
        } else {
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 4096);
                header.push(stream.read_u8().await.unwrap());
            }
            std::str::from_utf8(&header)
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap()
        }
    })
    .await
    .unwrap()
}
async fn ended(stream: &mut TcpStream) {
    assert!(matches!(
        timeout(STEP, stream.read(&mut [0; 1])).await.unwrap(),
        Ok(0) | Err(_)
    ));
}
async fn offline(addresses: (SocketAddr, SocketAddr)) {
    let mut http = proxy_start(addresses.0, false, 1).await;
    let mut socks = proxy_start(addresses.1, true, 1).await;
    assert_eq!(
        tokio::join!(proxy_reply(&mut http, false), proxy_reply(&mut socks, true)),
        (502, 1)
    );
}
async fn echo(stream: &mut TcpStream, epoch: usize, seq: usize) {
    let mut sent = [0x37; PAYLOAD];
    sent[..8].copy_from_slice(&(epoch as u64).to_be_bytes());
    sent[8..16].copy_from_slice(&(seq as u64).to_be_bytes());
    let mut received = [0; PAYLOAD];
    timeout(STEP, async {
        stream.write_all(&sent).await.unwrap();
        stream.read_exact(&mut received).await.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(sent, received);
}
async fn traffic(
    addresses: (SocketAddr, SocketAddr),
    epoch: usize,
    metrics: &mut Metrics,
) -> [TcpStream; 2] {
    let mut http = proxy_start(addresses.0, false, 1).await;
    let mut socks = proxy_start(addresses.1, true, 1).await;
    assert_eq!(
        tokio::join!(proxy_reply(&mut http, false), proxy_reply(&mut socks, true)),
        (200, 0)
    );
    let start = Instant::now();
    let mut sequence = 0;
    while start.elapsed() < Duration::from_millis(650) || sequence == 0 {
        tokio::join!(
            echo(&mut http, epoch, sequence * 2),
            echo(&mut socks, epoch, sequence * 2 + 1)
        );
        metrics.verified_payload_bytes += (PAYLOAD * 2) as u64;
        metrics.echo_rounds += 2;
        sequence += 1;
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    // The long flows remain alive until generation expiry; one extra short FIN
    // flow per generation exercises cleanup without unbounded TIME_WAIT load.
    let mut short = proxy_start(addresses.0, false, 1).await;
    assert_eq!(proxy_reply(&mut short, false).await, 200);
    echo(&mut short, epoch, usize::MAX).await;
    metrics.verified_payload_bytes += PAYLOAD as u64;
    metrics.echo_rounds += 1;
    short.shutdown().await.unwrap();
    ended(&mut short).await;
    [http, socks]
}
fn retired(probe: &mut GenerationProbe, metrics: &mut Metrics) {
    let stats = probe.release_stack(); // Nine live resource gauges must all be zero.
    assert!(stats.peak_socket_count <= STACK * 3);
    assert!(stats.peak_tcp_buffer_capacity_bytes <= STACK * 3 * 2 * 65536);
    assert!(stats.peak_command_queue <= STACK);
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
}
async fn expire(
    gateway: &Gateway,
    running: &Running,
    ipc: &Ipc,
    addresses: (SocketAddr, SocketAddr),
    live: &mut [TcpStream; 2],
    probe: &mut GenerationProbe,
    metrics: &mut Metrics,
) {
    let previous = gateway.state.count(LOGOUT);
    let mut pending_http = proxy_start(addresses.0, false, 99).await;
    let mut pending_socks = proxy_start(addresses.1, true, 99).await;
    wait(|| probe.stats().pending_tcp == 2).await;
    wait(|| gateway.state.count(LOGOUT) == previous + 1).await;
    assert_eq!(running.handle.phase(), ServicePhase::Cleaning);
    busy(ipc, running).await;
    wait(|| gateway.state.tunnels() == 0).await;
    for stream in live {
        ended(stream).await;
    }
    assert_eq!(
        tokio::join!(
            proxy_reply(&mut pending_http, false),
            proxy_reply(&mut pending_socks, true)
        ),
        (502, 1)
    );
    metrics.live_flows_revoked += 2;
    metrics.pending_connects_failed += 2;
    retired(probe, metrics);
    gateway.state.release_logout.add_permits(1);
    idle(gateway, running).await;
    gateway.state.hold_logout.store(false, Ordering::SeqCst);
    offline(addresses).await;
}
#[allow(clippy::too_many_arguments)]
async fn success(
    gateway: &Gateway,
    running: &Running,
    ipc: &Ipc,
    epoch: usize,
    authentication: usize,
    rounds: usize,
    nonces: &mut Nonces,
    metrics: &mut Metrics,
) -> Expected {
    let mut outcomes = (1..=rounds)
        .map(|round| Outcome::Challenge(round as u8))
        .collect::<Vec<_>>();
    outcomes.push(Outcome::Session);
    let mut expected = plan(gateway, nonces, &outcomes);
    gateway.state.hold_logout.store(true, Ordering::SeqCst);
    let (mut stream, hello) = raw_begin(ipc).await;
    for _ in 0..rounds {
        let prompt = next_prompt(&mut stream, nonces, metrics).await;
        answer(
            &mut stream,
            &hello,
            &prompt,
            epoch,
            authentication,
            &mut expected,
        )
        .await;
    }
    assert_eq!(receive(&mut stream).await["result"], "accepted");
    closed(stream).await;
    wait(|| running.connector.status().available).await;
    busy(ipc, running).await;
    expected.activated = true;
    expected.logout = true;
    expected
}
fn audit(gateway: &Gateway, epoch: usize, expected: &[Expected], metrics: &mut Metrics) {
    let requests = gateway.state.snapshot();
    assert!(requests.len() <= 64);
    let groups = requests
        .split(|request| request.path == PRELOGIN)
        .skip(1)
        .collect::<Vec<_>>();
    assert_eq!(groups.len(), expected.len());
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path == PRELOGIN)
            .count(),
        7
    );
    for (offset, (group, expected)) in groups.iter().zip(expected).enumerate() {
        let authentication = offset + 1;
        let logins = group
            .iter()
            .filter(|request| request.path == LOGIN)
            .collect::<Vec<_>>();
        assert_eq!(logins.len(), 1 + expected.answers.len());
        for (round, request) in logins.iter().enumerate() {
            assert_eq!(request.fields["user"], "original-user");
            assert_eq!(request.fields["computer"], "fixed-computer");
            assert_eq!(
                request.fields["passwd"],
                if round == 0 {
                    "initial-secret"
                } else {
                    &expected.answers[round - 1]
                }
            );
            if round == 0 {
                assert!(!request.fields.contains_key("inputStr"));
            } else {
                assert_eq!(
                    request.fields["inputStr"],
                    format!("state-{epoch}-{authentication}-{round}&opaque")
                );
            }
        }
        let count = |path: &str| group.iter().filter(|request| request.path == path).count();
        assert_eq!(count(CONFIG), usize::from(expected.activated));
        assert_eq!(
            count("/ssl-vpn/hipreportcheck.esp"),
            usize::from(expected.activated)
        );
        assert_eq!(count(TUNNEL), usize::from(expected.activated));
        assert_eq!(count(LOGOUT), usize::from(expected.logout));
        assert_eq!(
            group.len(),
            logins.len() + usize::from(expected.activated) * 3 + usize::from(expected.logout)
        );
        for request in *group {
            if request.path != LOGIN {
                assert_eq!(
                    request.fields["authcookie"],
                    format!("{}-{epoch}-{authentication}", gateway::COOKIE)
                );
            }
        }
        metrics.password_posts += 1;
        metrics.answer_posts += expected.answers.len() as u64;
        metrics.logouts += u64::from(expected.logout);
    }
    metrics.authentications += expected.len() as u64;
    metrics.max_cycle_requests = metrics.max_cycle_requests.max(requests.len());
    drop(requests);
    gateway.state.clear_checked_epoch();
}

#[allow(clippy::too_many_arguments)]
async fn cycle(
    gateway: &Gateway,
    running: &Running,
    ipc: &Ipc,
    addresses: (SocketAddr, SocketAddr),
    nonces: &mut Nonces,
    metrics: &mut Metrics,
) {
    let epoch = metrics.cycles as usize + 1;
    idle(gateway, running).await;
    gateway.state.begin_epoch(epoch);
    let mut expectations = Vec::with_capacity(7);
    // 1: disconnect while a prompt is pending, without an answer POST.
    let expected = plan(gateway, nonces, &[Outcome::Challenge(1)]);
    let (mut stream, _) = raw_begin(ipc).await;
    next_prompt(&mut stream, nonces, metrics).await;
    disconnect(stream).await;
    finish_plan(gateway, running, nonces, &[]).await;
    metrics.prompts_cancelled += 1;
    expectations.push(expected);
    // 2: an answer was submitted to IPC but not yet written through TLS.
    let mut expected = plan(gateway, nonces, &[Outcome::Challenge(1), Outcome::Session]);
    gateway
        .state
        .hold_tls_at
        .store(gateway.state.accepted() + 3, Ordering::SeqCst);
    let (mut stream, hello) = raw_begin(ipc).await;
    let prompt = next_prompt(&mut stream, nonces, metrics).await;
    answer(&mut stream, &hello, &prompt, epoch, 2, &mut expected).await;
    wait(|| gateway.state.tls_waiting.load(Ordering::SeqCst)).await;
    disconnect(stream).await;
    gateway.state.release_tls.add_permits(1);
    finish_plan(gateway, running, nonces, &[Outcome::Session]).await;
    gateway.state.hold_tls_at.store(0, Ordering::SeqCst);
    expected.answers.clear(); // IPC answer must never appear in gateway trace.
    metrics.answer_tls_cancelled += 1;
    expectations.push(expected);
    // 3: issued answer POST must finish and clean the late cookie before Waiting.
    let mut expected = plan(
        gateway,
        nonces,
        &[Outcome::Challenge(1), Outcome::HeldSession],
    );
    gateway.state.hold_logout.store(true, Ordering::SeqCst);
    let before = gateway.state.count(LOGIN);
    let (mut stream, hello) = raw_begin(ipc).await;
    let prompt = next_prompt(&mut stream, nonces, metrics).await;
    answer(&mut stream, &hello, &prompt, epoch, 3, &mut expected).await;
    wait(|| gateway.state.count(LOGIN) == before + 2).await;
    disconnect(stream).await;
    busy(ipc, running).await;
    gateway.state.release_login.add_permits(1);
    wait(|| gateway.state.count(LOGOUT) == 1).await;
    assert_eq!(running.handle.phase(), ServicePhase::Cleaning);
    busy(ipc, running).await;
    gateway.state.release_logout.add_permits(1);
    finish_plan(gateway, running, nonces, &[]).await;
    gateway.state.hold_logout.store(false, Ordering::SeqCst);
    expected.logout = true;
    metrics.late_cookies_cleaned += 1;
    expectations.push(expected);
    // 4: alternate rejection and the forbidden fifth challenge, without re-login.
    let limit = epoch.is_multiple_of(2);
    let outcomes = if limit {
        (1..=5).map(Outcome::Challenge).collect::<Vec<_>>()
    } else {
        vec![Outcome::Rejected]
    };
    let mut expected = plan(gateway, nonces, &outcomes);
    let (mut stream, hello) = raw_begin(ipc).await;
    if limit {
        for _ in 0..4 {
            let prompt = next_prompt(&mut stream, nonces, metrics).await;
            answer(&mut stream, &hello, &prompt, epoch, 4, &mut expected).await;
        }
        metrics.round_limits += 1;
    } else {
        metrics.rejected += 1;
    }
    failed(&mut stream).await;
    closed(stream).await;
    finish_plan(gateway, running, nonces, &[]).await;
    expectations.push(expected);
    // 5/6: two fully active authentications and actual proxy/IP traffic. Hold one
    // old connect capability until the next generation is live to prove it cannot rebind.
    let first_expected = success(gateway, running, ipc, epoch, 5, 2, nonces, metrics).await;
    let mut first = GenerationProbe::capture(&running.connector);
    let stale = running
        .connector
        .connect(Target::new("10.77.0.1", 443).unwrap());
    let mut live = traffic(addresses, epoch, metrics).await;
    expire(
        gateway, running, ipc, addresses, &mut live, &mut first, metrics,
    )
    .await;
    drop(live);
    finish_plan(gateway, running, nonces, &[]).await;
    expectations.push(first_expected);
    let second_expected = success(gateway, running, ipc, epoch, 6, 4, nonces, metrics).await;
    assert_eq!(
        stale.await.err().unwrap().kind(),
        io::ErrorKind::NotConnected
    );
    metrics.old_connects_rejected_after_new_generation += 1;
    wait(|| !first.generation_alive()).await;
    metrics.generations_released += 1;
    let mut second = GenerationProbe::capture(&running.connector);
    let mut live = traffic(addresses, epoch, metrics).await;
    expire(
        gateway,
        running,
        ipc,
        addresses,
        &mut live,
        &mut second,
        metrics,
    )
    .await;
    drop(live);
    finish_plan(gateway, running, nonces, &[]).await;
    wait(|| !second.generation_alive()).await;
    metrics.generations_released += 1;
    expectations.push(second_expected);
    // 7: a previous operation's nonce cannot answer a new connection's round.
    let stale_nonce = *nonces.previous.last().unwrap();
    let expected = plan(gateway, nonces, &[Outcome::Challenge(1)]);
    let (mut stream, hello) = raw_begin(ipc).await;
    let prompt = next_prompt(&mut stream, nonces, metrics).await;
    let mut stale = response(&hello, &prompt);
    stale["round_nonce"] = json!(stale_nonce);
    stream.write_all(&encode(&stale)).await.unwrap();
    closed(stream).await;
    finish_plan(gateway, running, nonces, &[]).await;
    metrics.stale_nonces_rejected += 1;
    expectations.push(expected);
    idle(gateway, running).await;
    offline(addresses).await;
    audit(gateway, epoch, &expectations, metrics);
    metrics.cycles += 1;
    {
        let fd = descriptors();
        let baseline = *metrics.idle_fd_baseline.get_or_insert(fd);
        assert!(
            fd <= baseline + 2,
            "idle descriptor growth: baseline={baseline}, current={fd}"
        );
        metrics.idle_fd_peak = Some(metrics.idle_fd_peak.unwrap_or(0).max(fd));
    }
    eprintln!(
        "CHALLENGE_SOAK {}",
        json!({"event":"cycle_complete","metrics":metrics})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "bounded mixed challenge/service/IPC soak; run exact alone with --test-threads=1"]
async fn bounded_mixed_challenge_service_ipc_soak() {
    let seconds = std::env::var("GP_PROXY_CHALLENGE_SOAK_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>().unwrap())
        .unwrap_or(300);
    assert!((20..=86400).contains(&seconds));
    // Warm only the public synthetic localhost resolver before the FD baseline.
    let addresses = tokio::net::lookup_host(("localhost", 0))
        .await
        .unwrap()
        .collect::<Vec<_>>();
    assert!(!addresses.is_empty() && addresses.iter().all(|address| address.ip().is_loopback()));
    let fd_before = descriptors();
    let gateway = Gateway::start([]).await;
    gateway.state.memory_echo.store(true, Ordering::SeqCst);
    gateway.state.lifetime.store(3, Ordering::SeqCst);
    let (running, pac) = setup(&gateway);
    let ipc = Ipc::start(&gateway, &running);
    let proxy = ProxyServer::bind(ProxyConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        socks_addr: "127.0.0.1:0".parse().unwrap(),
        max_connections: BUSINESS,
        handshake_timeout: Duration::from_secs(12),
        idle_timeout: Duration::from_secs(20),
    })
    .await
    .unwrap();
    let addresses = proxy.local_addrs();
    let (proxy_stop, stopping) = watch::channel(false);
    let proxy_task = tokio::spawn(proxy.serve(running.connector.clone(), pac, stopping));
    let started = Instant::now();
    let mut metrics = Metrics::default();
    let mut nonces = Nonces::default();
    eprintln!(
        "CHALLENGE_SOAK {}",
        json!({"event":"started","pid":std::process::id(),"requested_seconds":seconds,
        "gateway_workers":8,"gateway_trace_capacity":64,"gateway_plan_capacity":6,"packet_queue_per_direction":64,
        "memory_peer_tcp_listeners":4,"business_limit":BUSINESS,"stack_limit":STACK,"retained_old_connects":1,"retained_nonces_max":8})
    );
    let result = std::panic::AssertUnwindSafe(timeout(Duration::from_secs(seconds + 30), async {
        while started.elapsed() < Duration::from_secs(seconds) || metrics.cycles < 2 {
            cycle(
                &gateway,
                &running,
                &ipc,
                addresses,
                &mut nonces,
                &mut metrics,
            )
            .await;
        }
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(
            gateway.state.snapshot().is_empty(),
            "authentication replay appeared while idle"
        );
        assert!(metrics.rejected > 0 && metrics.round_limits > 0);
    }))
    .catch_unwind()
    .await;
    // Independent bounded cleanup still runs after an assertion or work timeout.
    gateway.state.hold_prelogin.store(false, Ordering::SeqCst);
    gateway.state.hold_logout.store(false, Ordering::SeqCst);
    gateway.state.hold_tls_at.store(0, Ordering::SeqCst);
    gateway.state.release_prelogin.add_permits(8);
    gateway.state.release_tls.add_permits(8);
    gateway.state.release_login.add_permits(8);
    gateway.state.release_logout.add_permits(8);
    running.stop.cancel();
    ipc.stop.cancel();
    proxy_stop.send_replace(true);
    let state = gateway.state.clone();
    let connector = running.connector.clone();
    timeout(Duration::from_secs(20), async {
        ipc.close().await;
        running.close().await;
        timeout(STEP, proxy_task).await.unwrap().unwrap().unwrap();
        gateway.close().await;
    })
    .await
    .expect("challenge soak cleanup deadline");
    assert_eq!(state.workers(), 0);
    assert_eq!(state.tunnels(), 0);
    assert!(!connector.status().available);
    let fd_after = descriptors();
    if result.as_ref().is_ok_and(|work| work.is_ok()) {
        assert_eq!(
            fd_before, fd_after,
            "owned descriptors failed to return to warmed baseline"
        );
    }
    let _http = tokio::net::TcpListener::bind(addresses.0).await.unwrap();
    let _socks = tokio::net::TcpListener::bind(addresses.1).await.unwrap();
    eprintln!(
        "CHALLENGE_SOAK {}",
        json!({"event":"cleaned","elapsed_seconds":started.elapsed().as_secs_f64(),"metrics":metrics,
        "fd_before":fd_before,"fd_after":fd_after,"all_owned_tasks_joined":true,"proxy_ports_rebound":true,"work_succeeded":result.as_ref().is_ok_and(|work|work.is_ok())})
    );
    match result {
        Ok(result) => result.expect("challenge soak total budget"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
