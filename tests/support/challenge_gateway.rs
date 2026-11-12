//! Fixed-capacity synthetic challenge gateway. No external authentication.
#[path = "localhost.rs"]
// Share one fixture source across unit modules and independent integration crates.
#[allow(clippy::duplicate_mod)]
mod localhost_fixture;
use crate::gp::{self, GatewayClient, ResumptionPolicy};
use crate::session::proxy_lifecycle_tests::echo_peer;
#[path = "gp_echo_tunnel.rs"]
pub(crate) mod gp_echo_tunnel;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub const STEP: Duration = Duration::from_secs(6);
pub const LOGIN: &str = "/ssl-vpn/login.esp";
pub const PRELOGIN: &str = "/ssl-vpn/prelogin.esp";
pub const CONFIG: &str = "/ssl-vpn/getconfig.esp";
pub const LOGOUT: &str = "/ssl-vpn/logout.esp";
pub const TUNNEL: &str = "/ssl-tunnel-connect.sslvpn";
pub const COOKIE: &str = "public-challenge-fixture-cookie";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Challenge(u8),
    Session,
    HeldSession,
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    Rejected,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub path: String,
    pub fields: HashMap<String, String>,
}

pub struct State {
    requests: Mutex<Vec<Request>>,
    outcomes: Mutex<VecDeque<Outcome>>,
    workers: AtomicUsize,
    accepted: AtomicUsize,
    active_tunnels: AtomicUsize,
    pub lifetime: AtomicU64,
    pub memory_echo: AtomicBool,
    epoch: AtomicUsize,
    authentication: AtomicUsize,
    issued_cookie: Mutex<Option<String>>,
    pub hold_tls_at: AtomicUsize,
    pub tls_waiting: AtomicBool,
    pub release_tls: Semaphore,
    pub hold_prelogin: AtomicBool,
    pub hold_logout: AtomicBool,
    pub release_prelogin: Semaphore,
    pub release_login: Semaphore,
    pub release_logout: Semaphore,
}
impl State {
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn workers(&self) -> usize {
        self.workers.load(Ordering::SeqCst)
    }
    pub fn tunnels(&self) -> usize {
        self.active_tunnels.load(Ordering::SeqCst)
    }
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn snapshot(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn begin_epoch(&self, epoch: usize) {
        assert!(self.memory_echo.load(Ordering::SeqCst));
        assert_eq!(self.workers(), 0);
        assert_eq!(self.tunnels(), 0);
        assert!(self.requests.lock().unwrap().is_empty());
        assert!(self.outcomes.lock().unwrap().is_empty());
        assert!(self.issued_cookie.lock().unwrap().is_none());
        self.epoch.store(epoch, Ordering::SeqCst);
        self.authentication.store(0, Ordering::SeqCst);
    }
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn plan(&self, outcomes: &[Outcome]) {
        assert_eq!(self.workers(), 0);
        assert!(outcomes.len() <= 6);
        let mut planned = self.outcomes.lock().unwrap();
        assert!(planned.is_empty());
        planned.extend(outcomes);
    }
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn finish_plan(&self, remaining: &[Outcome]) {
        assert_eq!(self.workers(), 0);
        assert_eq!(self.tunnels(), 0);
        assert!(self.issued_cookie.lock().unwrap().is_none());
        let mut planned = self.outcomes.lock().unwrap();
        assert_eq!(planned.iter().copied().collect::<Vec<_>>(), remaining);
        planned.clear();
        for gate in [
            &self.release_tls,
            &self.release_login,
            &self.release_logout,
            &self.release_prelogin,
        ] {
            assert_eq!(gate.available_permits(), 0);
        }
    }
    /// Caller validates the full bounded snapshot before reusing its storage.
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub fn clear_checked_epoch(&self) {
        assert_eq!(self.workers(), 0);
        assert_eq!(self.tunnels(), 0);
        assert!(self.outcomes.lock().unwrap().is_empty());
        assert!(self.issued_cookie.lock().unwrap().is_none());
        self.requests.lock().unwrap().clear();
    }
    pub fn requests(&self, path: &str) -> Vec<Request> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.path == path)
            .cloned()
            .collect()
    }
    pub fn count(&self, path: &str) -> usize {
        self.requests(path).len()
    }
}

pub struct Gateway {
    pub origin: String,
    pub client: GatewayClient,
    pub state: Arc<State>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Gateway {
    pub async fn start(outcomes: impl IntoIterator<Item = Outcome>) -> Self {
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
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
        let listener = localhost_fixture::bind().await.unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let client = GatewayClient::new(
            url::Url::parse(&origin).unwrap(),
            crate::tls::client_config(Some(std::path::Path::new(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/gp/testdata/localhost-cert.pem"
            ))))
            .unwrap(),
            ResumptionPolicy::Memory {
                tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
            },
        )
        .unwrap();
        let state = Arc::new(State {
            requests: Mutex::new(Vec::new()),
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            workers: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
            active_tunnels: AtomicUsize::new(0),
            lifetime: AtomicU64::new(60),
            memory_echo: AtomicBool::new(false),
            epoch: AtomicUsize::new(0),
            authentication: AtomicUsize::new(0),
            issued_cookie: Mutex::new(None),
            hold_tls_at: AtomicUsize::new(0),
            tls_waiting: AtomicBool::new(false),
            release_tls: Semaphore::new(0),
            hold_prelogin: AtomicBool::new(false),
            hold_logout: AtomicBool::new(false),
            release_prelogin: Semaphore::new(0),
            release_login: Semaphore::new(0),
            release_logout: Semaphore::new(0),
        });
        assert!(state.outcomes.lock().unwrap().len() <= 16);
        let stop = CancellationToken::new();
        let stopping = stop.clone();
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            let slots = Arc::new(Semaphore::new(8));
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopping.cancelled() => break,
                    result = workers.join_next(), if !workers.is_empty() => { result.unwrap().unwrap(); },
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        let slot = slots.clone().try_acquire_owned().expect("synthetic worker bound");
                        let acceptor = acceptor.clone();
                        let state = shared.clone();
                        let ordinal = state.accepted.fetch_add(1, Ordering::SeqCst) + 1;
                        state.workers.fetch_add(1, Ordering::SeqCst);
                        workers.spawn(async move {
                            let _slot = slot;
                            struct Worker(Arc<State>);
                            impl Drop for Worker {
                                fn drop(&mut self) { self.0.workers.fetch_sub(1, Ordering::SeqCst); }
                            }
                            let _worker = Worker(state.clone());
                            if state.hold_tls_at.load(Ordering::SeqCst) == ordinal {
                                state.tls_waiting.store(true, Ordering::SeqCst);
                                timeout(STEP, state.release_tls.acquire()).await.expect("synthetic TLS release deadline").unwrap().forget();
                                state.tls_waiting.store(false, Ordering::SeqCst);
                            }
                            // Cancellation may close a TLS connection before it has sent a request.
                            if let Ok(tls) = timeout(STEP, acceptor.accept(tcp)).await.expect("synthetic TLS deadline") {
                                let _ = timeout(STEP, serve(tls, state)).await.expect("synthetic handler deadline");
                            }
                        });
                    }
                }
            }
            workers.abort_all();
            while let Some(result) = workers.join_next().await {
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
            task: Some(task),
        }
    }
    pub async fn close(mut self) {
        wait(|| self.state.workers.load(Ordering::SeqCst) == 0).await;
        assert_eq!(self.state.tunnels(), 0);
        self.stop.cancel();
        timeout(STEP, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.state.workers.load(Ordering::SeqCst), 0);
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

pub async fn wait(check: impl Fn() -> bool) {
    timeout(STEP, async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("synthetic lifecycle observation deadline");
}

async fn serve(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<State>,
) -> io::Result<()> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 16_384);
        header.push(tls.read_u8().await?);
    }
    let header = String::from_utf8(header).unwrap();
    let target = header
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(length <= 65_536);
    let mut body = vec![0; length];
    tls.read_exact(&mut body).await?;
    let path = target.split('?').next().unwrap();
    let encoded = if path == TUNNEL {
        target.split_once('?').unwrap().1.as_bytes()
    } else {
        &body
    };
    let fields: HashMap<String, String> =
        url::form_urlencoded::parse(encoded).into_owned().collect();
    {
        let mut requests = state.requests.lock().unwrap();
        assert!(requests.len() < 64);
        requests.push(Request {
            path: path.to_owned(),
            fields: fields.clone(),
        });
    }
    let cookie = || {
        if state.memory_echo.load(Ordering::SeqCst) {
            assert_eq!(
                fields.get("authcookie"),
                state.issued_cookie.lock().unwrap().as_ref()
            );
            assert!(fields.contains_key("authcookie"));
        } else {
            assert_eq!(fields.get("authcookie").map(String::as_str), Some(COOKIE));
        }
    };
    let response = match path {
        PRELOGIN => {
            state.authentication.fetch_add(1, Ordering::SeqCst);
            if state.hold_prelogin.load(Ordering::SeqCst) {
                state.release_prelogin.acquire().await.unwrap().forget();
            }
            "<prelogin-response><status>Success</status></prelogin-response>".into()
        }
        LOGIN => {
            let outcome = state
                .outcomes
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected credential POST");
            match outcome {
                Outcome::Challenge(round) => {
                    let identity = if state.memory_echo.load(Ordering::SeqCst) {
                        format!(
                            "state-{}-{}-{round}",
                            state.epoch.load(Ordering::SeqCst),
                            state.authentication.load(Ordering::SeqCst)
                        )
                    } else {
                        format!("state-{round}")
                    };
                    format!("<challenge><user>ignored-account</user><inputstr>{identity}&amp;opaque</inputstr><respmsg>Enter answer {round}</respmsg></challenge>")
                }
                #[cfg(all(
                    any(target_os = "macos", target_os = "linux"),
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ))]
                Outcome::Rejected => "<response status='error'/>".into(),
                Outcome::Session | Outcome::HeldSession => {
                    if matches!(outcome, Outcome::HeldSession) {
                        state.release_login.acquire().await.unwrap().forget();
                    }
                    let mut args = vec![String::new(); 15];
                    args[1] = if state.memory_echo.load(Ordering::SeqCst) {
                        let cookie = format!(
                            "{COOKIE}-{}-{}",
                            state.epoch.load(Ordering::SeqCst),
                            state.authentication.load(Ordering::SeqCst)
                        );
                        assert!(state
                            .issued_cookie
                            .lock()
                            .unwrap()
                            .replace(cookie.clone())
                            .is_none());
                        cookie
                    } else {
                        COOKIE.into()
                    };
                    args[3] = "portal".into();
                    args[4] = "original-user".into();
                    args[7] = "domain".into();
                    args[12] = "tunnel".into();
                    args[14] = "4100".into();
                    format!(
                        "<jnlp><application-desc>{}</application-desc></jnlp>",
                        args.into_iter()
                            .map(|v| format!("<argument>{v}</argument>"))
                            .collect::<String>()
                    )
                }
            }
        }
        CONFIG => {
            cookie();
            format!("<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>1400</mtu><lifetime>{}</lifetime></response>", state.lifetime.load(Ordering::SeqCst))
        }
        "/ssl-vpn/hipreportcheck.esp" => {
            cookie();
            "<response status='success'><hip-report-needed>no</hip-report-needed></response>".into()
        }
        LOGOUT => {
            cookie();
            if state.hold_logout.load(Ordering::SeqCst) {
                state.release_logout.acquire().await.unwrap().forget();
            }
            if state.memory_echo.load(Ordering::SeqCst) {
                assert!(state.issued_cookie.lock().unwrap().take().is_some());
            }
            "<response status='success'/>".into()
        }
        TUNNEL => {
            cookie();
            if state.memory_echo.load(Ordering::SeqCst) {
                assert_eq!(state.active_tunnels.fetch_add(1, Ordering::SeqCst), 0);
                struct Tunnel(Arc<State>);
                impl Drop for Tunnel {
                    fn drop(&mut self) {
                        self.0.active_tunnels.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                let _tunnel = Tunnel(state.clone());
                return gp_echo_tunnel::run(
                    tls,
                    state.authentication.load(Ordering::SeqCst) as u64,
                )
                .await;
            }
            tls.write_all(b"START_TUNNEL").await?;
            tls.flush().await?;
            let mut bytes = [0; 2048];
            while tls.read(&mut bytes).await? != 0 {}
            return Ok(());
        }
        _ => panic!("unexpected synthetic endpoint"),
    };
    tls.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        )
        .as_bytes(),
    )
    .await?;
    tls.shutdown().await
}
