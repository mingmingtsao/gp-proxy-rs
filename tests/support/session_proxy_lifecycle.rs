//! Full supervisor + real loopback proxies + synthetic TLS GlobalProtect gateway.
//! Application TCP packets terminate in the existing in-memory smoltcp peer;
//! the only host sockets are local proxy entry points and the synthetic gateway.
//! Kept as a session child module solely to retain private generation handles
//! for post-exit resource assertions, without exposing a production test API.
//! Run: cargo test --offline --lib session::proxy_lifecycle_tests -- --nocapture
#[path = "localhost.rs"]
// Share one fixture source across unit modules and independent integration crates.
#[allow(clippy::duplicate_mod)]
mod localhost_fixture;
use super::*;
use crate::proxy::{ProxyConfig, ProxyServer};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    task::JoinHandle,
};

#[allow(dead_code)]
#[path = "echo_peer.rs"]
pub(crate) mod echo_peer;

/// A test-only observer retains the stack counters, never a strong Generation.
/// Explicitly release the observer's StackHandle before checking weak liveness.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) struct GenerationProbe {
    generation: std::sync::Weak<Generation>,
    stack: Option<StackHandle>,
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl GenerationProbe {
    pub(crate) fn capture(connector: &TunnelConnector) -> Self {
        let state = connector.state.read().unwrap();
        let generation = state.current.as_ref().expect("no current generation");
        Self {
            generation: Arc::downgrade(generation),
            stack: Some(generation.stack.clone()),
        }
    }
    pub(crate) fn stats(&self) -> crate::stack::StackStats {
        self.stack.as_ref().expect("probe already released").stats()
    }
    pub(crate) fn is_closed(&self) -> bool {
        self.stack
            .as_ref()
            .expect("probe already released")
            .is_closed()
    }
    pub(crate) fn release_stack(&mut self) -> crate::stack::StackStats {
        let stack = self.stack.take().expect("probe already released");
        assert!(stack.is_closed());
        let stats = stack.stats();
        assert_eq!(
            stats.active_tcp
                + stats.pending_tcp
                + stats.active_udp
                + stats.time_wait
                + stats.socket_count
                + stats.command_queue
                + stats.incoming_queue
                + stats.outgoing_queue
                + stats.tcp_buffer_capacity_bytes,
            0
        );
        drop(stack);
        stats
    }
    pub(crate) fn generation_alive(&self) -> bool {
        self.generation.strong_count() != 0
    }
}

const MTU: usize = 1400;
const COOKIE: &str = "synthetic-lifecycle-cookie";
const ECHO: [u8; 4] = [10, 77, 0, 1];
const BLACKHOLE: [u8; 4] = [10, 77, 0, 99];
const STEP: Duration = Duration::from_secs(4);

#[derive(Clone, Copy)]
enum Fault {
    Eof,
    TruncatedFrame,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
struct Counts {
    configs: usize,
    hips: usize,
    tunnel_attempts: usize,
    opened: usize,
    closed: usize,
    active: usize,
    peak_active: usize,
    cookie_checks: usize,
    active_workers: usize,
    peak_workers: usize,
    peer_connections: u64,
    peer_bytes_received: u64,
    peer_bytes_echoed: u64,
}

struct GatewayState {
    counts: Mutex<Counts>,
    control: Mutex<Option<(usize, mpsc::Sender<Fault>)>>,
    peers: Mutex<std::collections::VecDeque<echo_peer::PeerStats>>,
    config_gate: Semaphore,
    reject_tunnel: AtomicBool,
    lifetime_secs: Option<u64>,
}

struct Gateway {
    client: GatewayClient,
    state: Arc<GatewayState>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Gateway {
    async fn start(lifetime_secs: Option<u64>) -> Self {
        let certs = CertificateDer::pem_slice_iter(include_bytes!(
            "../../src/gp/testdata/localhost-cert.pem"
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = PrivateKeyDer::from_pem_slice(include_bytes!(
            "../../src/gp/testdata/localhost-key.pem"
        ))
        .unwrap();
        let server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        // Use the product's TLS client configuration and its actual provider.
        let client_tls = crate::tls::client_config(Some(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/gp/testdata/localhost-cert.pem"
        ))))
        .unwrap();
        let listener = localhost_fixture::bind().await.unwrap();
        let client = GatewayClient::new(
            url::Url::parse(&format!(
                "https://localhost:{}",
                listener.local_addr().unwrap().port()
            ))
            .unwrap(),
            client_tls,
            crate::gp::ResumptionPolicy::Memory {
                tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
            },
        )
        .unwrap();
        let state = Arc::new(GatewayState {
            counts: Mutex::new(Counts::default()),
            control: Mutex::new(None),
            peers: Mutex::new(std::collections::VecDeque::new()),
            config_gate: Semaphore::new(0),
            reject_tunnel: AtomicBool::new(false),
            lifetime_secs,
        });
        let stop = CancellationToken::new();
        let stopping = stop.clone();
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
            let mut tasks = JoinSet::new();
            let slots = Arc::new(Semaphore::new(8));
            loop {
                // Finished handles are bounded as well as running workers.
                while let Some(result) = tasks.try_join_next() {
                    result.unwrap();
                }
                tokio::select! {
                    _ = stopping.cancelled() => break,
                    result = tasks.join_next(), if !tasks.is_empty() => { result.unwrap().unwrap(); },
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        let permit = slots.clone().try_acquire_owned().expect("mock gateway task budget exceeded");
                        let acceptor = acceptor.clone(); let shared = shared.clone();
                        let worker = WorkerCount::new(shared.clone());
                        tasks.spawn(async move {
                            let _permit = permit;
                            let _worker = worker;
                            let tls = timeout(STEP, acceptor.accept(tcp)).await.unwrap().unwrap();
                            serve_gateway(tls, shared).await;
                        });
                    }
                }
            }
            tasks.abort_all();
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    assert!(error.is_cancelled());
                }
            }
        });
        Self {
            client,
            state,
            stop,
            task: Some(task),
        }
    }

    fn counts(&self) -> Counts {
        self.state.counts.lock().unwrap().clone()
    }
    fn allow_config(&self) {
        self.state.config_gate.add_permits(1);
    }
    async fn fault(&self, generation: usize, fault: Fault) {
        let sender = {
            let control = self.state.control.lock().unwrap();
            let (current, sender) = control.as_ref().expect("no active mock tunnel");
            assert_eq!(*current, generation);
            sender.clone()
        };
        sender.send(fault).await.unwrap();
    }
    async fn close(mut self) {
        wait(|| self.counts().active_workers == 0).await;
        assert_eq!(
            self.counts().active,
            0,
            "gateway peer still active after supervisor cleanup"
        );
        self.stop.cancel();
        timeout(STEP, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
}

struct WorkerCount(Arc<GatewayState>);
impl WorkerCount {
    fn new(state: Arc<GatewayState>) -> Self {
        {
            let mut counts = state.counts.lock().unwrap();
            counts.active_workers += 1;
            counts.peak_workers = counts.peak_workers.max(counts.active_workers);
        }
        Self(state)
    }
}
impl Drop for WorkerCount {
    fn drop(&mut self) {
        self.0.counts.lock().unwrap().active_workers -= 1;
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

async fn serve_gateway(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<GatewayState>,
) {
    let (line, body) = timeout(STEP, async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(
                bytes.len() < 16 * 1024,
                "mock request headers exceeded bound"
            );
            bytes.push(tls.read_u8().await.unwrap());
        }
        let header = String::from_utf8(bytes).unwrap();
        let length = header
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .map(|n| n.parse::<usize>().unwrap())
            .unwrap_or(0);
        assert!(length < 8192);
        let mut body = vec![0; length];
        tls.read_exact(&mut body).await.unwrap();
        (header.lines().next().unwrap().to_string(), body)
    })
    .await
    .unwrap();
    let target = line.split_whitespace().nth(1).unwrap();
    // Every observed control request must carry the same authorized cookie;
    // there is deliberately no login or prelogin endpoint in this gateway.
    let encoded = if let Some((path, query)) = target.split_once('?') {
        assert_eq!(path, "/ssl-tunnel-connect.sslvpn");
        query.as_bytes()
    } else {
        body.as_slice()
    };
    let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(encoded).collect();
    assert_eq!(
        fields.get("authcookie").map(|value| value.as_ref()),
        Some(COOKIE)
    );
    assert!(!fields.contains_key("passwd") && !fields.contains_key("password"));
    state.counts.lock().unwrap().cookie_checks += 1;
    let response = match target {
        "/ssl-vpn/getconfig.esp" => {
            let count = {
                let mut counts = state.counts.lock().unwrap();
                counts.configs += 1;
                counts.configs
            };
            if count > 1 {
                state.config_gate.acquire().await.unwrap().forget();
            }
            let lifetime = state
                .lifetime_secs
                .map(|n| format!("<lifetime>{n}</lifetime>"))
                .unwrap_or_default();
            format!("<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>1400</mtu>{lifetime}</response>")
        }
        "/ssl-vpn/hipreportcheck.esp" => {
            state.counts.lock().unwrap().hips += 1;
            "<response status='success'><hip-report-needed>no</hip-report-needed></response>".into()
        }
        target if target.starts_with("/ssl-tunnel-connect.sslvpn?") => {
            state.counts.lock().unwrap().tunnel_attempts += 1;
            if state.reject_tunnel.load(Ordering::SeqCst) {
                tls.write_all(b"HTTP/1.1 502 Session Rejected\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                tls.shutdown().await.unwrap();
            } else {
                serve_tunnel(tls, state).await;
            }
            return;
        }
        _ => panic!("unexpected control endpoint; authentication must not be replayed"),
    };
    tls.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    tls.shutdown().await.unwrap();
}

async fn serve_tunnel(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<GatewayState>,
) {
    let (control, mut commands) = mpsc::channel(1);
    let peer_stats = Arc::new(Mutex::new(echo_peer::PeerStats::default()));
    let generation = {
        let mut counts = state.counts.lock().unwrap();
        counts.opened += 1;
        counts.active += 1;
        counts.peak_active = counts.peak_active.max(counts.active);
        counts.opened - 1
    };
    assert!(state
        .control
        .lock()
        .unwrap()
        .replace((generation, control))
        .is_none());
    tls.write_all(b"START_TUNNEL").await.unwrap();
    tls.flush().await.unwrap();
    let stop = CancellationToken::new();
    let _cancel_on_drop = stop.clone().drop_guard();
    let (to_peer, peer_input) = mpsc::channel(64);
    let (peer_output, mut from_peer) = mpsc::channel(64);
    let (mut reader, mut writer) = tokio::io::split(tls);
    let mut tasks = JoinSet::new();
    tasks.spawn(echo_peer::run_peer(
        peer_input,
        peer_output,
        stop.clone(),
        peer_stats.clone(),
        Arc::new(AtomicBool::new(false)),
        8,
        generation as u64,
    ));
    let stopping = stop.clone();
    tasks.spawn(async move {
        tokio::select! {
            _ = stopping.cancelled() => Ok(()),
            _ = async {
                while let Ok(frame) = gp::read_frame(&mut reader, MTU).await {
                    if let Frame::Ip(packet) = frame { if to_peer.send(packet).await.is_err() { break; } }
                }
            } => Ok(()),
        }
    });
    loop {
        tokio::select! {
            command = commands.recv() => {
                if matches!(command, Some(Fault::TruncatedFrame)) {
                    let mut ip = vec![0u8; 20]; ip[0] = 0x45; ip[3] = 20;
                    let encoded = Frame::Ip(ip).encode(MTU).unwrap();
                    writer.write_all(&encoded[..19]).await.unwrap();
                    writer.flush().await.unwrap();
                }
                break;
            }
            packet = from_peer.recv() => {
                let Some(packet) = packet else { break };
                if gp::write_frame(&mut writer, &Frame::Ip(packet), MTU).await.is_err() { break; }
            }
            result = tasks.join_next() => { result.unwrap().unwrap().unwrap(); break; }
        }
    }
    let _ = timeout(STEP, writer.shutdown()).await;
    stop.cancel();
    timeout(STEP, async {
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
    drop(writer);
    assert_eq!(state.control.lock().unwrap().take().unwrap().0, generation);
    let peer = peer_stats.lock().unwrap().clone();
    {
        let mut peers = state.peers.lock().unwrap();
        if peers.len() == 2 {
            peers.pop_front();
        }
        peers.push_back(peer.clone());
    }
    let mut counts = state.counts.lock().unwrap();
    counts.active -= 1;
    counts.closed += 1;
    counts.peer_connections += peer.tcp_connections;
    counts.peer_bytes_received += peer.tcp_bytes_received;
    counts.peer_bytes_echoed += peer.tcp_bytes_echoed;
}

struct Service {
    connector: Arc<TunnelConnector>,
    http: SocketAddr,
    socks: SocketAddr,
    shutdown: CancellationToken,
    proxy_stop: watch::Sender<bool>,
    proxy: Option<JoinHandle<io::Result<()>>>,
    supervisor: Option<JoinHandle<Result<(), GpError>>>,
}
impl Service {
    async fn start(gateway: &Gateway) -> Self {
        let session = Session::new(
            "synthetic-user".into(),
            COOKIE.into(),
            String::new(),
            String::new(),
            "test-computer".into(),
            None,
        )
        .unwrap();
        let initial = gateway.client.get_config(&session).await.unwrap();
        let config = Config {
            networks: vec!["10.77.0.0/24".parse().unwrap()],
            max_connections: 4,
            connect_timeout_secs: 12,
            reconnect_max_secs: 1,
            ..Config::default()
        };
        let (pac, policy) = watch::channel(Arc::new(effective_policy(&config, &initial).unwrap()));
        let server = ProxyServer::bind(ProxyConfig {
            http_addr: "127.0.0.1:0".parse().unwrap(),
            socks_addr: "127.0.0.1:0".parse().unwrap(),
            max_connections: 8,
            handshake_timeout: Duration::from_secs(12),
            idle_timeout: Duration::from_secs(20),
        })
        .await
        .unwrap();
        let (http, socks) = server.local_addrs();
        let connector = Arc::new(TunnelConnector::default());
        let shutdown = CancellationToken::new();
        let (proxy_stop, receiver) = watch::channel(false);
        let proxy = tokio::spawn(server.serve(connector.clone(), policy, receiver));
        let supervisor = tokio::spawn(supervise(
            config,
            gateway.client.clone(),
            session,
            initial,
            connector.clone(),
            pac,
            shutdown.clone(),
        ));
        let service = Self {
            connector,
            http,
            socks,
            shutdown,
            proxy_stop,
            proxy: Some(proxy),
            supervisor: Some(supervisor),
        };
        wait(|| service.connector.status().available).await;
        service
    }
    fn stack(&self) -> StackHandle {
        self.connector
            .state
            .read()
            .unwrap()
            .current
            .as_ref()
            .unwrap()
            .stack
            .clone()
    }
    fn generation(&self) -> Arc<Generation> {
        self.connector
            .state
            .read()
            .unwrap()
            .current
            .as_ref()
            .unwrap()
            .clone()
    }
    async fn close(mut self) {
        self.shutdown.cancel();
        self.proxy_stop.send_replace(true);
        if let Some(task) = self.supervisor.take() {
            let _ = timeout(STEP, task).await.unwrap().unwrap();
        }
        timeout(STEP, self.proxy.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.proxy_stop.send_replace(true);
    }
}

async fn wait(predicate: impl Fn() -> bool) {
    timeout(STEP, async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("lifecycle state did not reach expected value");
}
async fn http_start(address: SocketAddr, target: [u8; 4]) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let target = format!("{}:443", Ipv4Addr::from(target));
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    stream
}
async fn http_result(stream: &mut TcpStream) -> u16 {
    timeout(STEP, async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 1024);
            header.push(stream.read_u8().await.unwrap());
        }
        std::str::from_utf8(&header)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    })
    .await
    .unwrap()
}
async fn socks_start(address: SocketAddr, target: [u8; 4]) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    timeout(STEP, stream.read_exact(&mut greeting))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target);
    request.extend_from_slice(&443u16.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    stream
}
async fn socks_result(stream: &mut TcpStream) -> u8 {
    let mut reply = [0; 10];
    timeout(STEP, stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply[0], 5);
    reply[1]
}
async fn live_pair(service: &Service, seed: u64) -> (TcpStream, TcpStream) {
    let (mut http, mut socks) = tokio::join!(
        http_start(service.http, ECHO),
        socks_start(service.socks, ECHO)
    );
    let (http_code, socks_code) = tokio::join!(http_result(&mut http), socks_result(&mut socks));
    assert_eq!(http_code, 200);
    assert_eq!(socks_code, 0);
    for (index, stream) in [&mut http, &mut socks].into_iter().enumerate() {
        let mut payload: Vec<u8> = (0..8192)
            .map(|n| ((n as u64 + index as u64 * 47 + seed) % 251) as u8)
            .collect();
        payload[..8].copy_from_slice(&seed.to_be_bytes());
        payload[8] = index as u8;
        let mut echoed = vec![0; payload.len()];
        timeout(STEP, async {
            stream.write_all(&payload).await.unwrap();
            stream.read_exact(&mut echoed).await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(echoed, payload);
    }
    (http, socks)
}
async fn closed(stream: &mut TcpStream) {
    match timeout(STEP, stream.read(&mut [0])).await.unwrap() {
        Ok(0) | Err(_) => {}
        Ok(_) => panic!("old connection received unexpected bytes after teardown"),
    }
}
fn assert_released(stack: &StackHandle) {
    assert!(stack.is_closed());
    let stats = stack.stats();
    assert_eq!(
        stats.active_tcp
            + stats.pending_tcp
            + stats.active_udp
            + stats.time_wait
            + stats.socket_count
            + stats.command_queue
            + stats.incoming_queue
            + stats.outgoing_queue
            + stats.tcp_buffer_capacity_bytes,
        0
    );
    assert!(stats.peak_active_tcp >= 2);
    assert!(stats.peak_socket_count <= 12);
    assert!(stats.peak_command_queue <= 4);
    assert!(stats.peak_incoming_queue <= 64 && stats.peak_outgoing_queue <= 64);
}
async fn offline(service: &Service) {
    let (mut http, mut socks) = tokio::join!(
        http_start(service.http, ECHO),
        socks_start(service.socks, ECHO)
    );
    let (http_code, socks_code) = tokio::join!(http_result(&mut http), socks_result(&mut socks));
    assert_eq!(http_code, 502);
    assert_eq!(socks_code, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxies_reconnect_after_truncated_frame_and_eof_then_stop_on_cookie_rejection() {
    timeout(Duration::from_secs(35), async {
        let gateway = Gateway::start(None).await;
        let mut service = Service::start(&gateway).await;
        let mut retired = Vec::new();
        for (generation, fault) in [Fault::TruncatedFrame, Fault::Eof].into_iter().enumerate() {
            let stack = service.stack();
            let (mut http, mut socks) = live_pair(&service, generation as u64 * 23).await;
            let (mut waiting_http, mut waiting_socks) = tokio::join!(http_start(service.http, BLACKHOLE), socks_start(service.socks, BLACKHOLE));
            wait(|| stack.stats().pending_tcp == 2).await;
            gateway.fault(generation, fault).await;
            wait(|| service.connector.status().phase == Phase::RetryWait).await;
            tokio::join!(closed(&mut http), closed(&mut socks));
            let (http_code, socks_code) = tokio::join!(http_result(&mut waiting_http), socks_result(&mut waiting_socks));
            assert_eq!(http_code, 502); assert_eq!(socks_code, 1);
            assert_released(&stack); retired.push(stack);
            wait(|| gateway.counts().closed == generation + 1).await;
            offline(&service).await;
            wait(|| gateway.counts().configs == generation + 2).await;
            // The real supervisor is blocked in its next getconfig, making the
            // disconnected window deterministic rather than timing-dependent.
            assert_eq!(service.connector.status().phase, Phase::Connecting);
            offline(&service).await;
            if generation == 1 { gateway.state.reject_tunnel.store(true, Ordering::SeqCst); }
            gateway.allow_config();
            if generation == 0 { wait(|| service.connector.status().available).await; }
        }
        let result = timeout(STEP, service.supervisor.take().unwrap()).await.unwrap().unwrap();
        assert!(matches!(result, Err(GpError::Authentication)));
        service.connector.disconnect(); // main's supervisor-completion cleanup
        assert_eq!(service.connector.status().reason, Reason::AuthenticationRequired);
        assert_eq!(service.connector.status().retry_count, 2);
        offline(&service).await;
        wait(|| gateway.counts().active_workers == 0).await;
        let counts = gateway.counts();
        tokio::time::sleep(Duration::from_millis(2600)).await;
        assert_eq!(gateway.counts(), counts, "terminal authentication error retried");
        assert_eq!((counts.configs, counts.hips, counts.tunnel_attempts, counts.opened, counts.closed, counts.cookie_checks), (3, 3, 3, 2, 2, 9));
        assert_eq!(counts.peak_active, 1);
        for stack in &retired { assert_released(stack); }
        for peer in gateway.state.peers.lock().unwrap().iter() { assert_eq!(peer.tcp_bytes_received, 16_384); }
        eprintln!("lifecycle: 2 generations reclaimed; HTTP+SOCKS live and pending streams revoked; 9 same-cookie requests; no authentication replay");
        service.close().await; gateway.close().await;
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_session_expiry_closes_existing_and_pending_streams_without_reconnect() {
    timeout(Duration::from_secs(20), async {
        let gateway = Gateway::start(Some(6)).await;
        let mut service = Service::start(&gateway).await;
        let stack = service.stack();
        let (mut http, mut socks) = live_pair(&service, 91).await;
        let (mut waiting_http, mut waiting_socks) = tokio::join!(http_start(service.http, BLACKHOLE), socks_start(service.socks, BLACKHOLE));
        wait(|| stack.stats().pending_tcp == 2).await;
        let result = timeout(Duration::from_secs(8), service.supervisor.take().unwrap()).await.unwrap().unwrap();
        assert!(matches!(result, Err(GpError::Authentication)));
        assert_eq!(service.connector.status().reason, Reason::SessionExpired);
        tokio::join!(closed(&mut http), closed(&mut socks));
        let (http_code, socks_code) = tokio::join!(http_result(&mut waiting_http), socks_result(&mut waiting_socks));
        assert_eq!(http_code, 502); assert_eq!(socks_code, 1);
        assert_released(&stack); offline(&service).await;
        wait(|| gateway.counts().closed == 1).await;
        wait(|| gateway.counts().active_workers == 0).await;
        let counts = gateway.counts(); tokio::time::sleep(Duration::from_millis(2600)).await;
        assert_eq!(gateway.counts(), counts, "expired login retried");
        assert_eq!((counts.configs, counts.hips, counts.tunnel_attempts, counts.cookie_checks), (1, 1, 1, 3));
        assert_eq!(service.connector.status().retry_count, 0);
        eprintln!("lifecycle: expired login revoked HTTP+SOCKS live/pending streams; generation resources zero; no reconnect");
        service.close().await; gateway.close().await;
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_initialized_pac_history_stops_supervisor_before_publication_or_tunnel() {
    use crate::pac_history::PacHistory;
    struct TemporaryDirectory(std::path::PathBuf);
    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    timeout(Duration::from_secs(10), async {
        let directory_path = std::env::temp_dir().join(format!(
            "gp-proxy-lifecycle-history-{:016x}", rand::random::<u64>()
        ));
        std::fs::create_dir(&directory_path).unwrap();
        let directory = TemporaryDirectory(directory_path);
        let path = directory.0.join("history.json");
        let lock = directory.0.join("history.json.lock");
        let old = Arc::new(Policy::new(vec!["remembered.old.corp".into()], vec![]).unwrap());
        let history = Arc::new(PacHistory::open(&path, &old).unwrap());
        assert!(path.is_file());
        assert!(std::fs::metadata(&lock).unwrap().len() > 0);

        let gateway = Gateway::start(None).await;
        let session = Session::new("synthetic-user".into(), COOKIE.into(), String::new(), String::new(), "test-computer".into(), None).unwrap();
        let initial = gateway.client.get_config(&session).await.unwrap();
        let config = Config {
            domains: vec!["new.corp".into()],
            networks: vec!["10.77.0.0/24".parse().unwrap()],
            pac_history: Some(history.clone()),
            ..Config::default()
        };
        let (pac, observer) = watch::channel(old.clone());
        let connector = Arc::new(TunnelConnector::default());
        // Preserve the initialized sidecar and its live lock, reproducing a
        // lost history file rather than an intentionally fresh installation.
        std::fs::remove_file(&path).unwrap();
        let result = timeout(STEP, supervise(config, gateway.client.clone(), session,
            initial, connector.clone(), pac.clone(), CancellationToken::new())).await.unwrap();
        assert!(matches!(result, Err(GpError::Protocol("cannot persist PAC classification history"))));
        assert!(!observer.has_changed().unwrap(), "failed persistence published a PAC update");
        assert!(Arc::ptr_eq(&observer.borrow(), &old));
        assert!(observer.borrow().allows_host("remembered.old.corp"));
        assert!(!observer.borrow().allows_host("new.corp"));
        assert!(connector.state.read().unwrap().current.is_none());
        assert_eq!(connector.status().phase, Phase::Stopped);
        assert_eq!(connector.status().reason, Reason::ProtocolError);
        assert_eq!(connector.status().retry_count, 0);
        assert_eq!(connector.connect(Target::new("10.77.0.1", 443).unwrap()).await.err().unwrap().kind(), io::ErrorKind::NotConnected);
        wait(|| gateway.counts().active_workers == 0).await;
        assert_eq!(gateway.counts(), Counts { configs: 1, cookie_checks: 1, peak_workers: 1, ..Counts::default() });
        assert!(!path.exists(), "missing initialized history was silently recreated");
        assert!(lock.is_file());
        eprintln!("PAC history failure: Protocol terminal; old watch unchanged; no HIP/tunnel attempt, generation, or authentication replay");
        gateway.close().await;
        drop(history); // release the sidecar handle before cleanup on Windows
        std::fs::remove_dir_all(&directory.0).unwrap();
    }).await.unwrap();
}

#[derive(Default, serde::Serialize)]
struct ChurnMetrics {
    cycles: u64,
    generations_verified: u64,
    verified_echo_bytes: u64,
    live_streams_revoked: u64,
    pending_connects_failed: u64,
    offline_proxy_failures: u64,
    stale_capabilities_rejected: u64,
    status_pac_checks: u64,
    eof_faults: u64,
    partial_frame_faults: u64,
    max_teardown_ms: u128,
    peak_stack_sockets: usize,
    peak_stack_buffer_bytes: usize,
    peak_command_queue: usize,
    peak_incoming_queue: usize,
    peak_outgoing_queue: usize,
}

async fn check_local_diagnostics(service: &Service, available: bool) {
    assert_eq!(
        crate::status::query(service.http).await.unwrap().available,
        available
    );
    timeout(STEP, async {
        let mut client = TcpStream::connect(service.http).await.unwrap();
        client
            .write_all(
                format!(
                    "GET /proxy.pac HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    service.http
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client
            .take(16 * 1024 + 1)
            .read_to_end(&mut response)
            .await
            .unwrap();
        assert!(response.len() <= 16 * 1024);
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("FindProxyForURL") && !response.contains("; DIRECT"));
    })
    .await
    .unwrap();
}

/// Explicit opt-in: GP_PROXY_LIFECYCLE_SECONDS=120 (default), up to 86400.
/// No per-generation Vec grows: one mock control, two recent peer snapshots,
/// and at most the previous/current generation handles remain resident.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "opt-in complete-session churn soak; synthetic loopback gateway only"]
async fn bounded_complete_session_generation_churn_soak() {
    let seconds = std::env::var("GP_PROXY_LIFECYCLE_SECONDS")
        .ok()
        .map(|text| text.parse::<u64>().expect("invalid soak duration"))
        .unwrap_or(120);
    assert!((2..=86400).contains(&seconds));
    let duration = Duration::from_secs(seconds);
    timeout(duration + Duration::from_secs(40), async {
        let started = tokio::time::Instant::now();
        eprintln!("LIFECYCLE_SOAK {}", serde_json::json!({"event":"started", "pid":std::process::id(), "requested_seconds":seconds, "stack_connections":4, "proxy_connections":8, "gateway_worker_limit":8, "retained_peer_snapshots":2, "packet_queue_per_direction":64}));
        let gateway = Gateway::start(None).await;
        let service = Service::start(&gateway).await;
        let mut current = service.generation();
        let (mut http, mut socks) = live_pair(&service, 0).await;
        let mut metrics = ChurnMetrics { generations_verified: 1, verified_echo_bytes: 16_384, ..ChurnMetrics::default() };
        let mut last_report = started;
        check_local_diagnostics(&service, true).await;
        metrics.status_pac_checks += 1;
        while started.elapsed() < duration || metrics.cycles < 2 {
            let cycle = metrics.cycles;
            // Capture the connector future before disruption, but deliberately
            // do not poll it until a different generation is ready.
            let stale = service.connector.connect(Target::new("10.77.0.1", 443).unwrap());
            let (mut waiting_http, mut waiting_socks) = tokio::join!(http_start(service.http, BLACKHOLE), socks_start(service.socks, BLACKHOLE));
            wait(|| current.stack.stats().pending_tcp == 2).await;
            let stats = current.stack.stats();
            metrics.peak_stack_sockets = metrics.peak_stack_sockets.max(stats.peak_socket_count);
            metrics.peak_stack_buffer_bytes = metrics.peak_stack_buffer_bytes.max(stats.peak_tcp_buffer_capacity_bytes);
            metrics.peak_command_queue = metrics.peak_command_queue.max(stats.peak_command_queue);
            metrics.peak_incoming_queue = metrics.peak_incoming_queue.max(stats.peak_incoming_queue);
            metrics.peak_outgoing_queue = metrics.peak_outgoing_queue.max(stats.peak_outgoing_queue);
            let fault = if cycle.is_multiple_of(2) { metrics.partial_frame_faults += 1; Fault::TruncatedFrame } else { metrics.eof_faults += 1; Fault::Eof };
            let teardown_started = tokio::time::Instant::now();
            gateway.fault(cycle as usize, fault).await;
            wait(|| matches!(service.connector.status().phase, Phase::RetryWait | Phase::Connecting) && current.stack.is_closed()).await;
            tokio::join!(closed(&mut http), closed(&mut socks));
            let (http_code, socks_code) = tokio::join!(http_result(&mut waiting_http), socks_result(&mut waiting_socks));
            assert_eq!(http_code, 502); assert_eq!(socks_code, 1);
            metrics.live_streams_revoked += 2; metrics.pending_connects_failed += 2;
            assert_released(&current.stack);
            // A new getconfig worker may already be waiting at the gate; only
            // the retired tunnel and its children must have finished here.
            wait(|| gateway.counts().closed == cycle as usize + 1 && gateway.counts().active == 0).await;
            metrics.max_teardown_ms = metrics.max_teardown_ms.max(teardown_started.elapsed().as_millis());
            offline(&service).await;
            metrics.offline_proxy_failures += 2;
            check_local_diagnostics(&service, false).await;
            metrics.status_pac_checks += 1;
            wait(|| gateway.counts().configs == cycle as usize + 2).await;
            assert!(!service.connector.status().available);
            gateway.allow_config();
            wait(|| service.connector.status().available).await;
            let next = service.generation();
            assert!(!Arc::ptr_eq(&current, &next), "old generation was republished");
            assert_released(&current.stack);
            assert_eq!(stale.await.err().unwrap().kind(), io::ErrorKind::NotConnected);
            assert_eq!(current.stack.connect("10.77.0.1:443".parse().unwrap()).await.err().unwrap().kind(), io::ErrorKind::NotConnected);
            metrics.stale_capabilities_rejected += 2;
            (http, socks) = live_pair(&service, cycle + 1).await;
            current = next;
            metrics.cycles += 1;
            metrics.generations_verified += 1;
            metrics.verified_echo_bytes += 16_384;
            check_local_diagnostics(&service, true).await;
            metrics.status_pac_checks += 1;
            assert_eq!(service.connector.status().retry_count, metrics.cycles);
            assert!(gateway.state.peers.lock().unwrap().len() <= 2);
            assert!(gateway.counts().peak_workers <= 8);
            if last_report.elapsed() >= Duration::from_secs(10) {
                eprintln!("LIFECYCLE_SOAK {}", serde_json::json!({"event":"progress", "elapsed_seconds":started.elapsed().as_secs_f64(), "metrics":&metrics, "gateway":gateway.counts()}));
                last_report = tokio::time::Instant::now();
            }
        }
        service.close().await;
        tokio::join!(closed(&mut http), closed(&mut socks));
        metrics.live_streams_revoked += 2;
        assert_released(&current.stack);
        wait(|| gateway.counts().active_workers == 0).await;
        let counts = gateway.counts();
        assert_eq!(counts.opened, counts.closed);
        assert_eq!(counts.opened as u64, metrics.generations_verified);
        assert_eq!(counts.active, 0);
        assert_eq!(counts.peak_active, 1);
        assert_eq!(counts.cookie_checks, counts.configs + counts.hips + counts.tunnel_attempts);
        assert_eq!(counts.peer_bytes_received, metrics.verified_echo_bytes);
        assert_eq!(counts.peer_bytes_echoed, metrics.verified_echo_bytes);
        assert_eq!(counts.peer_connections, metrics.generations_verified * 2);
        assert!(gateway.state.control.lock().unwrap().is_none());
        eprintln!("LIFECYCLE_SOAK {}", serde_json::json!({"event":"completed", "elapsed_seconds":started.elapsed().as_secs_f64(), "metrics":metrics, "gateway":counts, "last_generation_resources":current.stack.stats(), "unexpected_errors":0}));
        gateway.close().await;
    }).await.unwrap();
}
