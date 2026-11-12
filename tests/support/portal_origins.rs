//! Two fixed-capacity, independently trusted TLS origins; public synthetic input only.
//! Shared by service child-module and actual-CLI tests via parent gp/echo_peer imports.
use super::{echo_peer, gp};
#[path = "portal_tunnel.rs"]
mod portal_tunnel;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub const STEP: Duration = Duration::from_secs(8);
pub const USER: &str = "synthetic-portal-user";
pub const PASSWORD: &str = "synthetic-portal-password-never-at-gateway";
pub const COMPUTER: &str = "synthetic-portal-computer";
pub const PORTAL_COOKIE: &str = "synthetic-portal-cookie&opaque";
pub const SESSION_COOKIE: &str = "synthetic-gateway-session-cookie";
pub const PORTAL_PRELOGIN: &str = "/global-protect/prelogin.esp";
pub const PORTAL_LOGIN: &str = "/global-protect/getconfig.esp";
pub const GATEWAY_LOGIN: &str = "/ssl-vpn/login.esp";
pub const CONFIG: &str = "/ssl-vpn/getconfig.esp";
pub const HIP: &str = "/ssl-vpn/hipreportcheck.esp";
pub const LOGOUT: &str = "/ssl-vpn/logout.esp";
pub const TUNNEL: &str = "/ssl-tunnel-connect.sslvpn";
pub fn answer(round: u8) -> String {
    format!("synthetic-fresh-portal-answer-{round}")
}

#[derive(Clone, Copy, Debug, Default)]
pub enum PolicyOutcome {
    #[default]
    Valid,
    MissingGateway,
    MissingCookie,
}
#[derive(Clone, Copy, Debug, Default)]
pub enum GatewayOutcome {
    #[default]
    Session,
    Rejected,
    Challenge,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Plan {
    pub rounds: u8,
    pub policy: PolicyOutcome,
    pub gateway: GatewayOutcome,
}
#[derive(Clone, Debug)]
pub struct Request {
    pub path: String,
    pub fields: BTreeMap<String, String>,
}

pub struct State {
    requests: Mutex<Vec<Request>>,
    pub accepted: AtomicUsize,
    pub workers: AtomicUsize,
    pub tunnels: AtomicUsize,
    pub dns_queries: AtomicUsize,
    pub tcp_packets: AtomicUsize,
    pub hold_tls_at: AtomicUsize,
    pub tls_waiting: AtomicBool,
    pub release_tls: Semaphore,
    pub hold_prelogin: AtomicBool,
    pub release_prelogin: Semaphore,
    pub hold_response: AtomicBool,
    pub response_waiting: AtomicBool,
    pub release_response: Semaphore,
    pub hold_logout: AtomicBool,
    pub release_logout: Semaphore,
    issued: AtomicBool,
}
impl State {
    fn new() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            accepted: AtomicUsize::new(0),
            workers: AtomicUsize::new(0),
            tunnels: AtomicUsize::new(0),
            dns_queries: AtomicUsize::new(0),
            tcp_packets: AtomicUsize::new(0),
            hold_tls_at: AtomicUsize::new(0),
            tls_waiting: AtomicBool::new(false),
            release_tls: Semaphore::new(0),
            hold_prelogin: AtomicBool::new(false),
            release_prelogin: Semaphore::new(0),
            hold_response: AtomicBool::new(false),
            response_waiting: AtomicBool::new(false),
            release_response: Semaphore::new(0),
            hold_logout: AtomicBool::new(false),
            release_logout: Semaphore::new(0),
            issued: AtomicBool::new(false),
        }
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
    pub fn trace(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
    pub fn has_session(&self) -> bool {
        self.issued.load(Ordering::SeqCst)
    }
}

pub struct Endpoint {
    pub origin: String,
    pub ca_file: PathBuf,
    pub state: Arc<State>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Endpoint {
    async fn start(listener: TcpListener, portal: bool, fixed_gateway: String, plan: Plan) -> Self {
        let prefix = if portal { "rsa" } else { "ecdsa" };
        let directory = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/tls-interop"
        ));
        let certificates = CertificateDer::pem_slice_iter(
            &std::fs::read(directory.join(format!("{prefix}-cert.pem"))).unwrap(),
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key =
            PrivateKeyDer::from_pem_file(directory.join(format!("{prefix}-key.pem"))).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let state = Arc::new(State::new());
        let shared = state.clone();
        let stop = CancellationToken::new();
        let stopping = stop.clone();
        let task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            let capacity = Arc::new(Semaphore::new(8));
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stopping.cancelled() => break,
                    joined = tasks.join_next(), if !tasks.is_empty() => { joined.unwrap().unwrap(); },
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        let permit = capacity.clone().try_acquire_owned().expect("portal synthetic worker bound");
                        let ordinal = shared.accepted.fetch_add(1, Ordering::SeqCst) + 1;
                        shared.workers.fetch_add(1, Ordering::SeqCst);
                        let state = shared.clone();
                        let acceptor = acceptor.clone();
                        let gateway = fixed_gateway.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            struct Worker(Arc<State>);
                            impl Drop for Worker { fn drop(&mut self) { self.0.workers.fetch_sub(1, Ordering::SeqCst); } }
                            let _worker = Worker(state.clone());
                            if state.hold_tls_at.load(Ordering::SeqCst) == ordinal {
                                state.tls_waiting.store(true, Ordering::SeqCst);
                                timeout(STEP, state.release_tls.acquire()).await.unwrap().unwrap().forget();
                                state.tls_waiting.store(false, Ordering::SeqCst);
                            }
                            // Failed trust validation or cancelled prelogin can close before HTTP.
                            if let Ok(tls) = timeout(STEP, acceptor.accept(tcp)).await.expect("portal fixture TLS deadline") {
                                let _ = timeout(Duration::from_secs(60), serve(tls, state, portal, &gateway, plan)).await
                                    .expect("portal fixture handler deadline");
                            }
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
            origin,
            ca_file: directory.join(format!("ca-{prefix}-cert.pem")),
            state,
            stop,
            task: Some(task),
        }
    }
    pub async fn idle(&self) {
        wait(|| {
            self.state.workers.load(Ordering::SeqCst) == 0
                && self.state.tunnels.load(Ordering::SeqCst) == 0
        })
        .await;
    }
    async fn close(mut self) {
        self.idle().await;
        self.stop.cancel();
        timeout(STEP, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.state.workers.load(Ordering::SeqCst), 0);
        assert_eq!(self.state.tunnels.load(Ordering::SeqCst), 0);
        assert!(!self.state.has_session());
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

pub struct DualOrigins {
    pub portal: Endpoint,
    pub gateway: Endpoint,
}
impl DualOrigins {
    pub async fn start(plan: Plan) -> Self {
        assert!(plan.rounds <= 4);
        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixed_gateway = format!(
            "localhost:{}",
            gateway_listener.local_addr().unwrap().port()
        );
        let portal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = Endpoint::start(gateway_listener, false, fixed_gateway.clone(), plan).await;
        let portal = Endpoint::start(portal_listener, true, fixed_gateway, plan).await;
        assert_ne!(portal.origin, gateway.origin);
        assert_ne!(
            std::fs::read(&portal.ca_file).unwrap(),
            std::fs::read(&gateway.ca_file).unwrap()
        );
        Self { portal, gateway }
    }
    pub async fn close(self) {
        tokio::join!(self.portal.close(), self.gateway.close());
    }
}

pub async fn wait(check: impl Fn() -> bool) {
    timeout(STEP, async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("portal synthetic observation deadline");
}
fn validate_base(fields: &BTreeMap<String, String>) {
    for (key, value) in [
        ("jnlpReady", "jnlpReady"),
        ("ok", "Login"),
        ("direct", "yes"),
        ("clientVer", "4100"),
        ("prot", "https:"),
        ("internal", "no"),
        ("ipv6-support", "no"),
        ("server", "localhost"),
        ("user", USER),
        ("computer", COMPUTER),
    ] {
        assert_eq!(
            fields.get(key).map(String::as_str),
            Some(value),
            "field {key}"
        );
    }
    assert!(!fields["os-version"].is_empty());
    let os = if cfg!(target_os = "macos") {
        "Mac"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else {
        "Linux"
    };
    assert_eq!(fields["clientos"], os);
}
async fn response_gate(state: &State) {
    if state.hold_response.load(Ordering::SeqCst) {
        state.response_waiting.store(true, Ordering::SeqCst);
        timeout(STEP, state.release_response.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        state.response_waiting.store(false, Ordering::SeqCst);
    }
}
async fn serve(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<State>,
    portal: bool,
    gateway: &str,
    plan: Plan,
) -> io::Result<()> {
    let (target, body, method) = timeout(STEP, async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 16384);
            header.push(tls.read_u8().await?);
        }
        let header = String::from_utf8(header).unwrap();
        let mut first = header.lines().next().unwrap().split_whitespace();
        let method = first.next().unwrap().to_owned();
        let target = first.next().unwrap().to_owned();
        assert!(!header
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("cookie:")));
        let lengths: Vec<_> = header
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
            .collect();
        assert!(lengths.len() <= 1);
        let length = lengths
            .first()
            .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
        assert!(length <= 65536);
        let mut body = vec![0; length];
        tls.read_exact(&mut body).await?;
        Ok::<_, io::Error>((target, body, method))
    })
    .await
    .expect("portal fixture request frame deadline")?;
    let path = target.split('?').next().unwrap();
    let encoded = if path == TUNNEL {
        assert_eq!(method, "GET");
        target.split_once('?').unwrap().1.as_bytes()
    } else {
        assert_eq!(method, "POST");
        &body
    };
    let mut fields = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(encoded).into_owned() {
        assert!(
            fields.insert(key, value).is_none(),
            "duplicate synthetic form key"
        );
    }
    {
        let mut trace = state.requests.lock().unwrap();
        assert!(trace.len() < 64);
        trace.push(Request {
            path: path.into(),
            fields: fields.clone(),
        });
    }
    let cookie = || {
        assert_eq!(
            fields.get("authcookie").map(String::as_str),
            Some(SESSION_COOKIE)
        );
        assert!(state.has_session());
    };
    let response = match (portal, path) {
        (true, PORTAL_PRELOGIN) => {
            assert!(fields.is_empty());
            if state.hold_prelogin.load(Ordering::SeqCst) {
                timeout(STEP, state.release_prelogin.acquire())
                    .await
                    .unwrap()
                    .unwrap()
                    .forget();
            }
            "<prelogin-response><status>Success</status></prelogin-response>".into()
        }
        (true, PORTAL_LOGIN) => {
            validate_base(&fields);
            let index = state.count(PORTAL_LOGIN) - 1;
            assert!(
                index <= usize::from(plan.rounds),
                "unexpected portal credential replay"
            );
            if index == 0 {
                assert_eq!(fields.len(), 13);
                assert_eq!(fields["passwd"], PASSWORD);
            } else {
                assert_eq!(fields.len(), 14);
                assert_eq!(fields["passwd"], answer(index as u8));
                assert_eq!(fields["inputStr"], format!("portal-state-{index}&opaque"));
            }
            if index < usize::from(plan.rounds) {
                let round = index + 1;
                format!("<challenge><user>ignored-label</user><inputstr>portal-state-{round}&amp;opaque</inputstr><respmsg>Portal answer {round}</respmsg></challenge>")
            } else {
                response_gate(&state).await;
                let selected = if matches!(plan.policy, PolicyOutcome::MissingGateway) {
                    "not-authorized.invalid:9443"
                } else {
                    gateway
                };
                let cookie = if matches!(plan.policy, PolicyOutcome::MissingCookie) {
                    "".into()
                } else {
                    format!(
                        "<portal-userauthcookie>{}</portal-userauthcookie>",
                        PORTAL_COOKIE.replace('&', "&amp;")
                    )
                };
                format!("<policy><gateways><external><list><entry name=\"{selected}\"><description>Public synthetic gateway</description></entry></list></external></gateways>{cookie}</policy>")
            }
        }
        (false, GATEWAY_LOGIN) => {
            validate_base(&fields);
            assert_eq!(fields.len(), 17);
            assert_eq!(state.count(GATEWAY_LOGIN), 1, "cookie credential retry");
            assert_eq!(
                fields["passwd"],
                if cfg!(target_os = "linux") {
                    "SAMLPASS"
                } else {
                    ""
                }
            );
            assert_eq!(fields["portal-userauthcookie"], PORTAL_COOKIE);
            assert_eq!(fields["portal-prelogonuserauthcookie"], "empty");
            assert_eq!(fields["prelogin-cookie"], "");
            assert_eq!(fields["token"], "");
            assert!(!fields.contains_key("inputStr"));
            assert!(fields
                .values()
                .all(|value| value != PASSWORD && !(1..=4).any(|round| *value == answer(round))));
            response_gate(&state).await;
            match plan.gateway {
                GatewayOutcome::Rejected=>"<response status='error'/>".into(),
                GatewayOutcome::Challenge=>"<challenge><inputstr>forbidden-gateway-continuation</inputstr><respmsg>New gateway credential</respmsg></challenge>".into(),
                GatewayOutcome::Session=> {
                    assert!(!state.issued.swap(true,Ordering::SeqCst));
                    let mut args=vec![String::new();15];
                    args[1]=SESSION_COOKIE.into();args[3]="synthetic-portal".into();args[4]=USER.into();args[7]="synthetic-domain".into();args[12]="tunnel".into();args[14]="4100".into();
                    format!("<jnlp><application-desc>{}</application-desc></jnlp>",args.into_iter().map(|arg|format!("<argument>{arg}</argument>")).collect::<String>())
                }
            }
        }
        (false, CONFIG) => {
            cookie();
            "<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>1400</mtu><lifetime>60</lifetime><dns><member>10.77.0.1</member></dns></response>".into()
        }
        (false, HIP) => {
            cookie();
            "<response status='success'><hip-report-needed>no</hip-report-needed></response>".into()
        }
        (false, LOGOUT) => {
            cookie();
            assert_eq!(state.count(LOGOUT), 1, "duplicate session logout");
            if state.hold_logout.load(Ordering::SeqCst) {
                timeout(STEP, state.release_logout.acquire())
                    .await
                    .unwrap()
                    .unwrap()
                    .forget();
            }
            assert!(state.issued.swap(false, Ordering::SeqCst));
            "<response status='success'/>".into()
        }
        (false, TUNNEL) => {
            cookie();
            assert_eq!(state.tunnels.fetch_add(1, Ordering::SeqCst), 0);
            struct Tunnel(Arc<State>);
            impl Drop for Tunnel {
                fn drop(&mut self) {
                    self.0.tunnels.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _tunnel = Tunnel(state.clone());
            return portal_tunnel::run(tls, state).await;
        }
        _ => panic!("request crossed a synthetic origin or used an unsupported endpoint"),
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
