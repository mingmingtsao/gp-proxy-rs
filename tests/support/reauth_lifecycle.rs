//! Explicit reauthentication uses only public synthetic loopback TLS fixtures.
//! No actual credentials, gateway, host business socket or virtual device.
use super::*;
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[path = "reauth_churn.rs"]
mod churn_tests;
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[path = "control_authentication.rs"]
mod control_tests;
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[path = "service_soak.rs"]
mod soak_tests;
#[path = "service_tls_session.rs"]
mod tls_session_tests;
use crate::{
    gp::{self, Frame},
    proxy::{ProxyConfig, ProxyServer, Target},
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use crate::session::proxy_lifecycle_tests::echo_peer;

const STEP: Duration = Duration::from_secs(6);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Prelogin,
    Login(usize),
    Config(usize),
    Hip(usize),
    TunnelOpen(usize),
    TunnelClosed(usize),
    LogoutStart(usize),
    LogoutDone(usize),
}

struct GatewayState {
    events: Mutex<Vec<Event>>,
    record_tls: AtomicBool,
    tls_handshakes: Mutex<Vec<(String, rustls::HandshakeKind)>>,
    logins: AtomicUsize,
    active_workers: AtomicUsize,
    active_tunnels: AtomicUsize,
    hold_login: AtomicBool,
    hold_config: AtomicBool,
    hold_logout: AtomicBool,
    reject_login: AtomicBool,
    unsupported: AtomicBool,
    bad_config: AtomicBool,
    lifetime: AtomicU64,
    login_gate: Semaphore,
    config_gate: Semaphore,
    logout_gate: Semaphore,
    tunnel: Mutex<Option<CancellationToken>>,
}

impl GatewayState {
    fn event(&self, event: Event) {
        let mut events = self.events.lock().unwrap();
        assert!(events.len() < 256);
        events.push(event);
    }
    fn has(&self, event: &Event) -> bool {
        self.events.lock().unwrap().contains(event)
    }
}

struct Gateway {
    origin: String,
    client: GatewayClient,
    state: Arc<GatewayState>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl Gateway {
    async fn new() -> Self {
        Self::new_with_versions(&[&rustls::version::TLS13, &rustls::version::TLS12]).await
    }

    async fn new_with_versions(versions: &[&'static rustls::SupportedProtocolVersion]) -> Self {
        let certificates = CertificateDer::pem_slice_iter(include_bytes!(
            "../../src/gp/testdata/localhost-cert.pem"
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = PrivateKeyDer::from_pem_slice(include_bytes!(
            "../../src/gp/testdata/localhost-key.pem"
        ))
        .unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
        let client_tls = crate::tls::client_config(Some(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/gp/testdata/localhost-cert.pem"
        ))))
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let client = GatewayClient::new(
            Url::parse(&origin).unwrap(),
            client_tls,
            crate::gp::ResumptionPolicy::Memory {
                tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
            },
        )
        .unwrap();
        let state = Arc::new(GatewayState {
            events: Mutex::new(vec![]),
            record_tls: AtomicBool::new(false),
            tls_handshakes: Mutex::new(vec![]),
            logins: AtomicUsize::new(0),
            active_workers: AtomicUsize::new(0),
            active_tunnels: AtomicUsize::new(0),
            hold_login: AtomicBool::new(false),
            hold_config: AtomicBool::new(false),
            hold_logout: AtomicBool::new(false),
            reject_login: AtomicBool::new(false),
            unsupported: AtomicBool::new(false),
            bad_config: AtomicBool::new(false),
            lifetime: AtomicU64::new(60),
            login_gate: Semaphore::new(0),
            config_gate: Semaphore::new(0),
            logout_gate: Semaphore::new(0),
            tunnel: Mutex::new(None),
        });
        let shared = state.clone();
        let stop = CancellationToken::new();
        let stopping = stop.clone();
        let task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            let slots = Arc::new(Semaphore::new(8));
            let mut tasks = JoinSet::new();
            loop {
                while let Some(result) = tasks.try_join_next() {
                    result.unwrap();
                }
                tokio::select! {
                    _ = stopping.cancelled() => break,
                    result = tasks.join_next(), if !tasks.is_empty() => { result.unwrap().unwrap(); },
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let permit = slots.clone().try_acquire_owned().expect("bounded synthetic gateway workers");
                        let acceptor = acceptor.clone(); let shared = shared.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            shared.active_workers.fetch_add(1, Ordering::SeqCst);
                            struct Worker(Arc<GatewayState>);
                            impl Drop for Worker { fn drop(&mut self) { self.0.active_workers.fetch_sub(1, Ordering::SeqCst); } }
                            let _worker = Worker(shared.clone());
                            let tls = timeout(STEP, acceptor.accept(stream)).await.unwrap().unwrap();
                            serve_gateway(tls, shared).await;
                        });
                    },
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
            origin,
            client,
            state,
            stop,
            task,
        }
    }

    async fn close(self) {
        wait(|| self.state.active_workers.load(Ordering::SeqCst) == 0).await;
        assert_eq!(self.state.active_tunnels.load(Ordering::SeqCst), 0);
        self.stop.cancel();
        timeout(STEP, self.task).await.unwrap().unwrap();
    }
}

async fn wait(check: impl Fn() -> bool) {
    timeout(STEP, async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

async fn serve_gateway(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<GatewayState>,
) {
    let (target, body) = timeout(STEP, async {
        let mut header = vec![];
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 16384);
            header.push(tls.read_u8().await.unwrap());
        }
        let header = String::from_utf8(header).unwrap();
        let target = header
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        let length = header
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .map(|value| value.parse::<usize>().unwrap())
            .unwrap_or(0);
        assert!(length < 65536);
        let mut body = vec![0; length];
        tls.read_exact(&mut body).await.unwrap();
        (target, body)
    })
    .await
    .unwrap();
    if state.record_tls.load(Ordering::SeqCst) {
        let mut handshakes = state.tls_handshakes.lock().unwrap();
        assert!(handshakes.len() < 64, "bounded TLS observation fixture");
        // Record endpoint names only, never a cookie-bearing target/query.
        let path = target.split('?').next().unwrap().to_owned();
        handshakes.push((path, tls.get_ref().1.handshake_kind().unwrap()));
    }
    let encoded = if target.starts_with("/ssl-tunnel-connect.sslvpn?") {
        target.split_once('?').unwrap().1.as_bytes()
    } else {
        &body
    };
    let fields: std::collections::HashMap<_, _> = url::form_urlencoded::parse(encoded).collect();
    let cookie = || {
        fields
            .get("authcookie")
            .unwrap()
            .strip_prefix("test-cookie-")
            .unwrap()
            .parse::<usize>()
            .unwrap()
    };
    let response = if target.starts_with("/ssl-vpn/prelogin.esp?") {
        state.event(Event::Prelogin);
        if state.unsupported.load(Ordering::SeqCst) {
            "<prelogin-response><status>Success</status><saml-request>synthetic</saml-request></prelogin-response>".to_owned()
        } else {
            "<prelogin-response><status>Success</status></prelogin-response>".to_owned()
        }
    } else if target == "/ssl-vpn/login.esp" {
        assert_eq!(fields.get("user").unwrap(), "synthetic-user");
        assert_eq!(fields.get("passwd").unwrap(), "synthetic-password");
        let index = state.logins.fetch_add(1, Ordering::SeqCst) + 1;
        state.event(Event::Login(index));
        if state.hold_login.load(Ordering::SeqCst) {
            timeout(STEP, state.login_gate.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }
        if state.reject_login.load(Ordering::SeqCst) {
            "<response status='error'/>".to_owned()
        } else {
            let mut args = vec![String::new(); 15];
            args[1] = format!("test-cookie-{index}");
            args[3] = "portal".into();
            args[4] = "synthetic-user".into();
            args[7] = "domain".into();
            args[12] = "tunnel".into();
            args[14] = "4100".into();
            format!(
                "<jnlp><application-desc>{}</application-desc></jnlp>",
                args.into_iter()
                    .map(|arg| format!("<argument>{arg}</argument>"))
                    .collect::<String>()
            )
        }
    } else if target == "/ssl-vpn/getconfig.esp" {
        let index = cookie();
        state.event(Event::Config(index));
        if state.hold_config.load(Ordering::SeqCst) {
            timeout(STEP, state.config_gate.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }
        if state.bad_config.load(Ordering::SeqCst) {
            "not XML".to_owned()
        } else {
            let domain = if index == 1 {
                "old.corp.example"
            } else {
                "new.corp.example"
            };
            format!("<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>1400</mtu><lifetime>{}</lifetime><dns><member>10.77.0.1</member></dns><include-split-tunneling-domain><member>{domain}</member></include-split-tunneling-domain></response>", state.lifetime.load(Ordering::SeqCst))
        }
    } else if target == "/ssl-vpn/hipreportcheck.esp" {
        state.event(Event::Hip(cookie()));
        "<response status='success'><hip-report-needed>no</hip-report-needed></response>".to_owned()
    } else if target.starts_with("/ssl-tunnel-connect.sslvpn?") {
        let index = cookie();
        drop(fields);
        serve_tunnel(tls, state, index).await;
        return;
    } else if target == "/ssl-vpn/logout.esp" {
        let index = cookie();
        state.event(Event::LogoutStart(index));
        assert_eq!(
            state.active_tunnels.load(Ordering::SeqCst),
            0,
            "logout raced a live old tunnel"
        );
        if state.hold_logout.load(Ordering::SeqCst) {
            timeout(STEP, state.logout_gate.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }
        state.event(Event::LogoutDone(index));
        "<response status='success'/>".to_owned()
    } else {
        panic!("unexpected synthetic gateway request");
    };
    let result = tls
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            )
            .as_bytes(),
        )
        .await;
    if result.is_ok() {
        let _ = tls.shutdown().await;
    }
}

async fn serve_tunnel(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<GatewayState>,
    index: usize,
) {
    let stop = CancellationToken::new();
    let _drop_stop = stop.clone().drop_guard();
    assert!(state.tunnel.lock().unwrap().replace(stop.clone()).is_none());
    state.active_tunnels.fetch_add(1, Ordering::SeqCst);
    state.event(Event::TunnelOpen(index));
    tls.write_all(b"START_TUNNEL").await.unwrap();
    tls.flush().await.unwrap();
    let (input, incoming) = mpsc::channel(64);
    let (output, mut outgoing) = mpsc::channel(64);
    let (mut reader, mut writer) = tokio::io::split(tls);
    let peer_stats = Arc::new(Mutex::new(echo_peer::PeerStats::default()));
    let mut tasks = JoinSet::new();
    tasks.spawn(echo_peer::run_peer(
        incoming,
        output,
        stop.clone(),
        peer_stats,
        Arc::new(AtomicBool::new(false)),
        4,
        index as u64,
    ));
    let stopping = stop.clone();
    tasks.spawn(async move {
        loop {
            tokio::select! {
                _ = stopping.cancelled() => break,
                frame = gp::read_frame(&mut reader, 1400) => match frame {
                    Ok(Frame::Ip(packet)) => if input.send(packet).await.is_err() { break; },
                    Ok(Frame::Keepalive) => {},
                    Err(_) => break,
                }
            }
        }
        Ok(())
    });
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            result = tasks.join_next() => { let _ = result.unwrap().unwrap(); break; },
            packet = outgoing.recv() => match packet {
                Some(packet) => if gp::write_frame(&mut writer, &Frame::Ip(packet), 1400).await.is_err() { break; },
                None => break,
            },
        }
    }
    stop.cancel();
    let _ = timeout(STEP, writer.shutdown()).await;
    while let Some(result) = tasks.join_next().await {
        let _ = result.unwrap();
    }
    drop(writer);
    state.tunnel.lock().unwrap().take();
    state.active_tunnels.fetch_sub(1, Ordering::SeqCst);
    state.event(Event::TunnelClosed(index));
}

fn password() -> AuthInput {
    AuthInput::Password {
        user: "synthetic-user".into(),
        password: Zeroizing::new("synthetic-password".into()),
        computer: "synthetic-client".into(),
    }
}

fn imported(index: usize) -> AuthInput {
    AuthInput::Session(
        Session::new(
            "synthetic-user".into(),
            format!("test-cookie-{index}"),
            "portal".into(),
            "domain".into(),
            "synthetic-client".into(),
            None,
        )
        .unwrap(),
    )
}

struct Running {
    handle: ServiceHandle,
    connector: Arc<TunnelConnector>,
    pac: watch::Receiver<Arc<Policy>>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

impl Running {
    fn start(gateway: &Gateway) -> Self {
        let config = Config {
            gateway: gateway.origin.clone(),
            domains: vec!["local.corp.example".into()],
            networks: vec!["10.77.0.0/24".parse().unwrap()],
            trust_gateway_routes: true,
            ..Config::default()
        };
        Self::configured(gateway, config, CancellationToken::new())
    }
    fn configured(gateway: &Gateway, config: Config, stop: CancellationToken) -> Self {
        let initial =
            Arc::new(Policy::new(vec!["remembered.corp.example".into()], vec![]).unwrap());
        let (pac_send, pac) = watch::channel(initial);
        let connector = Arc::new(TunnelConnector::default());
        let (handle, service) = new(
            config,
            gateway.client.clone(),
            connector.clone(),
            pac_send,
            stop.clone(),
        )
        .unwrap();
        let task = tokio::spawn(service.run());
        Self {
            handle,
            connector,
            pac,
            stop,
            task,
        }
    }
    async fn close(self) {
        self.stop.cancel();
        timeout(STEP, self.task).await.unwrap().unwrap();
        assert_eq!(self.handle.phase(), ServicePhase::Stopped);
        assert!(!self.connector.status().available);
    }
    fn begin(&self, gateway: &Gateway, input: AuthInput) -> AuthOperation {
        self.handle
            .try_authenticate(input, &gateway.origin, CancellationToken::new())
            .unwrap()
    }
}

#[test]
fn authentication_enums_have_only_fixed_serialized_categories() {
    for phase in [
        ServicePhase::Waiting,
        ServicePhase::Authenticating,
        ServicePhase::Active,
        ServicePhase::Cleaning,
        ServicePhase::Stopped,
    ] {
        let wire = serde_json::to_string(&phase).unwrap();
        assert_eq!(serde_json::from_str::<ServicePhase>(&wire).unwrap(), phase);
    }
    assert!(serde_json::from_str::<AuthFailure>("\"private remote error\"").is_err());
}

#[tokio::test]
async fn client_disconnect_during_login_waits_for_the_cookie_and_cleans_it() {
    let gateway = Gateway::new().await;
    gateway.state.hold_login.store(true, Ordering::SeqCst);
    let running = Running::start(&gateway);
    let cancel = CancellationToken::new();
    let mut operation = running
        .handle
        .try_authenticate(password(), &gateway.origin, cancel.clone())
        .unwrap();
    wait(|| gateway.state.has(&Event::Login(1))).await;
    cancel.cancel();
    assert_eq!(
        running
            .handle
            .try_authenticate(password(), &gateway.origin, CancellationToken::new())
            .err(),
        Some(StartError::Busy)
    );
    gateway.state.login_gate.add_permits(1);
    assert_eq!(operation.prepared().await, Err(AuthFailure::Cancelled));
    assert_eq!(running.handle.phase(), ServicePhase::Waiting);
    assert!(gateway.state.has(&Event::LogoutDone(1)));
    assert!(!gateway.state.has(&Event::Config(1)));
    assert!(!gateway.state.has(&Event::TunnelOpen(1)));
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    running.close().await;
    gateway.close().await;
}

#[tokio::test]
async fn admitted_imported_session_cancelled_before_run_only_logs_out() {
    let gateway = Gateway::new().await;
    let config = Config {
        gateway: gateway.origin.clone(),
        ..Config::default()
    };
    let stop = CancellationToken::new();
    let _cancel = stop.clone().drop_guard();
    let connector = Arc::new(TunnelConnector::default());
    let (pac, _) = watch::channel(Arc::new(Policy::new(vec![], vec![]).unwrap()));
    let (handle, service) =
        new(config, gateway.client.clone(), connector, pac, stop.clone()).unwrap();
    let mut operation = handle
        .try_authenticate(imported(1), &gateway.origin, CancellationToken::new())
        .unwrap();
    // Ownership transfers only at successful admission. Once stopping starts,
    // another imported cookie or password must not be accepted or posted.
    stop.cancel();
    for input in [imported(2), password()] {
        assert_eq!(
            handle
                .try_authenticate(input, &gateway.origin, CancellationToken::new())
                .err(),
            Some(StartError::Stopped)
        );
    }
    let task = tokio::spawn(service.run());
    assert_eq!(operation.prepared().await, Err(AuthFailure::Stopped));
    timeout(STEP, task).await.unwrap().unwrap();
    assert_eq!(handle.phase(), ServicePhase::Stopped);
    assert_eq!(
        handle.completion(),
        Some(CleanupSummary {
            known_sessions: 1,
            logout_confirmed: 1,
            ..CleanupSummary::default()
        })
    );
    assert_eq!(
        *gateway.state.events.lock().unwrap(),
        [Event::LogoutStart(1), Event::LogoutDone(1)]
    );
    gateway.close().await;
}

#[tokio::test]
async fn prepared_drop_and_missing_commit_are_cleaned_without_a_tunnel() {
    let gateway = Gateway::new().await;
    let running = Running::start(&gateway);
    let mut first = running.begin(&gateway, imported(1));
    first.prepared().await.unwrap();
    assert!(!running.connector.status().available);
    assert!(running.pac.borrow().allows_host("remembered.corp.example"));
    assert!(running.pac.borrow().allows_host("old.corp.example"));
    drop(first);
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert!(gateway.state.has(&Event::LogoutDone(1)));
    assert!(running.pac.borrow().allows_host("old.corp.example"));
    assert_eq!(
        running
            .connector
            .connect(Target::new("old.corp.example", 443).unwrap())
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::NotConnected
    );
    let mut second = running.begin(&gateway, imported(2));
    second.prepared().await.unwrap();
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    assert_eq!(second.commit(), Err(AuthFailure::Stopped));
    assert!(gateway.state.has(&Event::LogoutDone(2)));
    assert!(!gateway
        .state
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| matches!(event, Event::TunnelOpen(_))));
    running.close().await;
    gateway.close().await;
}

#[tokio::test]
async fn rejected_or_unsupported_authentication_never_replays_credentials() {
    let gateway = Gateway::new().await;
    let running = Running::start(&gateway);
    assert_eq!(
        running
            .handle
            .try_authenticate(
                password(),
                "https://different.invalid",
                CancellationToken::new()
            )
            .err(),
        Some(StartError::GatewayMismatch)
    );
    assert_eq!(
        running
            .handle
            .try_authenticate(
                AuthInput::Password {
                    user: "synthetic-user".into(),
                    password: Zeroizing::new(String::new()),
                    computer: "test".into()
                },
                &gateway.origin,
                CancellationToken::new()
            )
            .err(),
        Some(StartError::InvalidInput)
    );
    assert!(gateway.state.events.lock().unwrap().is_empty());
    gateway.state.unsupported.store(true, Ordering::SeqCst);
    let mut first = running.begin(&gateway, password());
    assert_eq!(
        first.prepared().await,
        Err(AuthFailure::UnsupportedAuthentication)
    );
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 0);
    gateway.state.unsupported.store(false, Ordering::SeqCst);
    gateway.state.reject_login.store(true, Ordering::SeqCst);
    let mut second = running.begin(&gateway, password());
    assert_eq!(
        second.prepared().await,
        Err(AuthFailure::AuthenticationRequired)
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(running.handle.phase(), ServicePhase::Waiting);
    assert!(!gateway
        .state
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| matches!(event, Event::LogoutStart(_) | Event::Config(_))));
    running.close().await;
    gateway.close().await;
}

#[tokio::test]
async fn invalid_configuration_logs_out_without_publishing_policy_or_generation() {
    let gateway = Gateway::new().await;
    gateway.state.bad_config.store(true, Ordering::SeqCst);
    let running = Running::start(&gateway);
    let before = running.pac.borrow().clone();
    let mut operation = running.begin(&gateway, password());
    assert_eq!(operation.prepared().await, Err(AuthFailure::ProtocolError));
    assert_eq!(*running.pac.borrow(), before);
    assert!(gateway.state.has(&Event::LogoutDone(1)));
    assert!(!gateway.state.has(&Event::TunnelOpen(1)));
    assert_eq!(running.handle.phase(), ServicePhase::Waiting);
    assert!(!running.connector.status().available);
    running.close().await;
    gateway.close().await;
}

async fn http_header(stream: &mut TcpStream) -> Vec<u8> {
    timeout(STEP, async {
        let mut bytes = vec![];
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 8192);
            bytes.push(stream.read_u8().await.unwrap());
        }
        bytes
    })
    .await
    .unwrap()
}

async fn http_stream(address: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"CONNECT 10.77.0.1:443 HTTP/1.1\r\nHost: 10.77.0.1:443\r\n\r\n")
        .await
        .unwrap();
    assert!(http_header(&mut stream).await.starts_with(b"HTTP/1.1 200 "));
    stream
}

async fn socks_stream(address: std::net::SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    stream
        .write_all(&[5, 1, 0, 1, 10, 77, 0, 1, 1, 187])
        .await
        .unwrap();
    let mut reply = [0; 10];
    timeout(STEP, stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..2], &[5, 0]);
    stream
}

async fn proxy_echo(stream: &mut TcpStream) {
    let payload = b"synthetic application bytes stay in the userspace tunnel";
    stream.write_all(payload).await.unwrap();
    let mut received = vec![0; payload.len()];
    timeout(STEP, stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, payload);
}

async fn pac_document(address: std::net::SocketAddr) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(format!("GET /proxy.pac HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut bytes = vec![];
    timeout(STEP, stream.take(65536).read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 200 "));
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn expired_session_cleans_before_reauth_while_same_proxy_and_pac_stay_online() {
    let gateway = Gateway::new().await;
    gateway.state.lifetime.store(1, Ordering::SeqCst);
    gateway.state.hold_logout.store(true, Ordering::SeqCst);
    let running = Running::start(&gateway);
    let server = ProxyServer::bind(ProxyConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        socks_addr: "127.0.0.1:0".parse().unwrap(),
        max_connections: 4,
        handshake_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(30),
    })
    .await
    .unwrap();
    let addresses = server.local_addrs();
    let (proxy_stop, proxy_stopping) = watch::channel(false);
    let proxy = tokio::spawn(server.serve(
        running.connector.clone(),
        running.pac.clone(),
        proxy_stopping,
    ));
    let mut first = running.begin(&gateway, password());
    first.prepared().await.unwrap();
    first.commit().unwrap();
    wait(|| running.connector.status().available).await;
    let stale = running
        .connector
        .connect(Target::new("10.77.0.1", 443).unwrap());
    let mut old_http = http_stream(addresses.0).await;
    let mut old_socks = socks_stream(addresses.1).await;
    proxy_echo(&mut old_http).await;
    proxy_echo(&mut old_socks).await;
    assert!(pac_document(addresses.0).await.contains("old.corp.example"));
    assert_eq!(
        running
            .handle
            .try_authenticate(password(), &gateway.origin, CancellationToken::new())
            .err(),
        Some(StartError::Busy)
    );
    wait(|| gateway.state.has(&Event::LogoutStart(1))).await;
    assert_eq!(running.handle.phase(), ServicePhase::Cleaning);
    assert_eq!(
        running
            .handle
            .try_authenticate(password(), &gateway.origin, CancellationToken::new())
            .err(),
        Some(StartError::Busy)
    );
    let status = crate::status::query(addresses.0).await.unwrap();
    assert!(!status.available);
    assert_eq!(status.reason, Reason::SessionExpired);
    assert!(pac_document(addresses.0).await.contains("old.corp.example"));
    for stream in [&mut old_http, &mut old_socks] {
        let mut one = [0; 1];
        assert!(matches!(
            timeout(STEP, stream.read(&mut one)).await.unwrap(),
            Ok(0) | Err(_)
        ));
    }
    let mut offline = TcpStream::connect(addresses.0).await.unwrap();
    offline
        .write_all(b"CONNECT 10.77.0.1:443 HTTP/1.1\r\nHost: 10.77.0.1:443\r\n\r\n")
        .await
        .unwrap();
    assert!(http_header(&mut offline)
        .await
        .starts_with(b"HTTP/1.1 502 "));
    gateway.state.hold_logout.store(false, Ordering::SeqCst);
    gateway.state.logout_gate.add_permits(1);
    wait(|| running.handle.phase() == ServicePhase::Waiting).await;
    gateway.state.lifetime.store(60, Ordering::SeqCst);
    gateway.state.hold_login.store(true, Ordering::SeqCst);
    let mut second = running.begin(&gateway, password());
    wait(|| gateway.state.has(&Event::Login(2))).await;
    assert!(!crate::status::query(addresses.0).await.unwrap().available);
    assert!(pac_document(addresses.0).await.contains("old.corp.example"));
    gateway.state.hold_login.store(false, Ordering::SeqCst);
    gateway.state.login_gate.add_permits(1);
    second.prepared().await.unwrap();
    second.commit().unwrap();
    wait(|| running.connector.status().available).await;
    assert_eq!(
        stale.await.err().unwrap().kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(
        running
            .connector
            .connect(Target::new("old.corp.example", 443).unwrap())
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    let status = crate::status::query(addresses.0).await.unwrap();
    assert!(status.available);
    assert_eq!(status.reason, Reason::None);
    let pac = pac_document(addresses.0).await;
    assert!(
        pac.contains("old.corp.example")
            && pac.contains("new.corp.example")
            && pac.contains("remembered.corp.example")
    );
    let mut new_http = http_stream(addresses.0).await;
    let mut new_socks = socks_stream(addresses.1).await;
    proxy_echo(&mut new_http).await;
    proxy_echo(&mut new_socks).await;
    gateway
        .state
        .tunnel
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .cancel();
    wait(|| running.connector.status().phase == crate::status::Phase::RetryWait).await;
    assert_eq!(running.handle.phase(), ServicePhase::Active);
    assert_eq!(
        running
            .handle
            .try_authenticate(password(), &gateway.origin, CancellationToken::new())
            .err(),
        Some(StartError::Busy)
    );
    running.close().await;
    proxy_stop.send_replace(true);
    timeout(STEP, proxy).await.unwrap().unwrap().unwrap();
    let events = gateway.state.events.lock().unwrap().clone();
    let old_done = events
        .iter()
        .position(|event| *event == Event::LogoutDone(1))
        .unwrap();
    let new_login = events
        .iter()
        .position(|event| *event == Event::Login(2))
        .unwrap();
    assert!(old_done < new_login);
    assert!(!events[new_login..].contains(&Event::LogoutStart(1)));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::LogoutDone(_)))
            .count(),
        2
    );
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 2);
    eprintln!("reauth lifecycle: stable HTTP/SOCKS/PAC/status; old lifetime revoked streams; old logout completed before second login; old lease/future/authorization rejected; all service and mock tasks joined");
    gateway.close().await;
}

#[tokio::test]
async fn missing_initialized_history_rejects_preparation_and_keeps_old_pac() {
    let directory = std::env::temp_dir().join(format!(
        "gp-reauth-history-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Directory(directory);
    let path = directory.0.join("history.json");
    let remembered = Policy::new(vec!["remembered.corp.example".into()], vec![]).unwrap();
    let history = Arc::new(crate::pac_history::PacHistory::open(&path, &remembered).unwrap());
    std::fs::remove_file(&path).unwrap();
    let gateway = Gateway::new().await;
    let config = Config {
        gateway: gateway.origin.clone(),
        domains: vec!["local.corp.example".into()],
        trust_gateway_routes: true,
        pac_history: Some(history),
        ..Config::default()
    };
    let running = Running::configured(&gateway, config, CancellationToken::new());
    let before = running.pac.borrow().clone();
    let mut operation = running.begin(&gateway, password());
    assert_eq!(operation.prepared().await, Err(AuthFailure::ProtocolError));
    assert_eq!(*running.pac.borrow(), before);
    assert!(gateway.state.has(&Event::LogoutDone(1)));
    assert!(!gateway.state.has(&Event::Hip(1)) && !gateway.state.has(&Event::TunnelOpen(1)));
    assert!(!running.connector.status().available);
    running.close().await;
    gateway.close().await;
}

#[tokio::test]
async fn unconfirmed_logout_has_a_three_second_bound_before_admission_reopens() {
    let gateway = Gateway::new().await;
    gateway.state.hold_logout.store(true, Ordering::SeqCst);
    let running = Running::start(&gateway);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut operation = running
        .handle
        .try_authenticate(imported(1), &gateway.origin, cancel)
        .unwrap();
    wait(|| gateway.state.has(&Event::LogoutStart(1))).await;
    let started = tokio::time::Instant::now();
    assert_eq!(running.handle.phase(), ServicePhase::Cleaning);
    assert_eq!(
        running
            .handle
            .try_authenticate(password(), &gateway.origin, CancellationToken::new())
            .err(),
        Some(StartError::Busy)
    );
    assert_eq!(
        timeout(Duration::from_secs(4), operation.prepared())
            .await
            .unwrap(),
        Err(AuthFailure::Cancelled)
    );
    assert!(started.elapsed() >= Duration::from_millis(2800));
    assert_eq!(running.handle.phase(), ServicePhase::Waiting);
    assert!(!gateway.state.has(&Event::LogoutDone(1)));
    // The remote handler can finish later; the service owns no detached logout.
    gateway.state.hold_logout.store(false, Ordering::SeqCst);
    gateway.state.logout_gate.add_permits(1);
    running.close().await;
    gateway.close().await;
}

#[tokio::test]
async fn cancellation_after_cookie_acquisition_does_not_wait_for_stalled_configuration() {
    let gateway = Gateway::new().await;
    gateway.state.hold_config.store(true, Ordering::SeqCst);
    let running = Running::start(&gateway);
    let cancel = CancellationToken::new();
    let mut operation = running
        .handle
        .try_authenticate(imported(1), &gateway.origin, cancel.clone())
        .unwrap();
    wait(|| gateway.state.has(&Event::Config(1))).await;
    let mut prepared = Box::pin(operation.prepared());
    cancel.cancel();
    let result = timeout(Duration::from_secs(1), &mut prepared).await;
    let promptly = result.is_ok();
    // Release the synthetic server and join everything even in the red run.
    gateway.state.hold_config.store(false, Ordering::SeqCst);
    gateway.state.config_gate.add_permits(1);
    let result = match result {
        Ok(result) => result,
        Err(_) => prepared.await,
    };
    assert_eq!(result, Err(AuthFailure::Cancelled));
    assert!(gateway.state.has(&Event::LogoutDone(1)));
    assert!(!gateway.state.has(&Event::TunnelOpen(1)));
    running.close().await;
    gateway.close().await;
    assert!(
        promptly,
        "known Session cancellation waited for stalled getconfig before cleanup"
    );
}

#[tokio::test(start_paused = true)]
async fn authentication_budget_starts_at_admission_before_the_actor_is_polled() {
    let gateway = Gateway::new().await;
    let config = Config {
        gateway: gateway.origin.clone(),
        ..Config::default()
    };
    let stop = CancellationToken::new();
    let connector = Arc::new(TunnelConnector::default());
    let (pac, _) = watch::channel(Arc::new(Policy::new(vec![], vec![]).unwrap()));
    let (handle, service) =
        new(config, gateway.client.clone(), connector, pac, stop.clone()).unwrap();
    let mut operation = handle
        .try_authenticate(password(), &gateway.origin, CancellationToken::new())
        .unwrap();
    assert_eq!(handle.phase(), ServicePhase::Authenticating);
    // No task is driving Service yet: admission must retain this elapsed time.
    tokio::time::advance(AUTH_TIMEOUT + Duration::from_secs(1)).await;
    let task = tokio::spawn(service.run());
    assert_eq!(operation.prepared().await, Err(AuthFailure::TimedOut));
    assert_eq!(handle.phase(), ServicePhase::Waiting);
    assert!(gateway.state.events.lock().unwrap().is_empty());
    stop.cancel();
    task.await.unwrap();
    gateway.close().await;
}
