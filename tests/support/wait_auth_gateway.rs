//! Fixed-capacity synthetic TLS gateway for the external CLI tests.
#[path = "localhost.rs"]
// Share one fixture source across unit modules and independent integration crates.
#[allow(clippy::duplicate_mod)]
mod localhost_fixture;
use gp_proxy::gp;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
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

#[path = "echo_peer.rs"]
mod echo_peer;
#[path = "gp_echo_tunnel.rs"]
mod gp_echo_tunnel;
const LIMIT: Duration = Duration::from_secs(6);

#[derive(Default)]
pub struct State {
    pub accepted: AtomicUsize,
    pub prelogins: AtomicUsize,
    pub logins: AtomicUsize,
    pub configs: AtomicUsize,
    pub hips: AtomicUsize,
    pub opened: AtomicUsize,
    pub closed: AtomicUsize,
    pub logouts: AtomicUsize,
    pub active_workers: AtomicUsize,
    pub active_tunnels: AtomicUsize,
    pub reject: AtomicBool,
    /// Default zero keeps the original password-only fixture unchanged.
    pub challenge_rounds: AtomicUsize,
    pub challenge_requests: Mutex<Vec<HashMap<String, String>>>,
    /// Opt-in stop lifecycle tests only; default leaves logout unchanged.
    pub logout_gate: Mutex<Option<Arc<Semaphore>>>,
    pub reject_logout: AtomicBool,
}
pub struct Gateway {
    pub origin: String,
    pub state: Arc<State>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Gateway {
    pub async fn start() -> Self {
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
        let state = Arc::new(State::default());
        let stop = CancellationToken::new();
        let shared = state.clone();
        let stopping = stop.clone();
        let task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            let slots = Arc::new(Semaphore::new(8));
            let mut workers = JoinSet::new();
            loop {
                while let Some(result) = workers.try_join_next() {
                    result.unwrap();
                }
                tokio::select! {
                    _ = stopping.cancelled() => break,
                    result = workers.join_next(), if !workers.is_empty() => { result.unwrap().unwrap(); },
                    accepted = listener.accept() => {
                        let (tcp, _) = accepted.unwrap();
                        shared.accepted.fetch_add(1, Ordering::SeqCst);
                        let permit = slots.clone().try_acquire_owned().expect("synthetic gateway worker bound");
                        let acceptor = acceptor.clone();
                        let state = shared.clone();
                        workers.spawn(async move {
                            let _permit = permit;
                            state.active_workers.fetch_add(1, Ordering::SeqCst);
                            struct Worker(Arc<State>);
                            impl Drop for Worker { fn drop(&mut self) { self.0.active_workers.fetch_sub(1, Ordering::SeqCst); } }
                            let _worker = Worker(state.clone());
                            let tls = timeout(LIMIT, acceptor.accept(tcp)).await.unwrap().unwrap();
                            serve(tls, state).await;
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
            state,
            stop,
            task: Some(task),
        }
    }
    pub async fn idle(&self) {
        timeout(LIMIT, async {
            while self.state.active_workers.load(Ordering::SeqCst) != 0
                || self.state.active_tunnels.load(Ordering::SeqCst) != 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("synthetic gateway did not observe client shutdown");
    }
    pub async fn close(mut self) {
        self.idle().await;
        self.stop.cancel();
        timeout(LIMIT, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.state.active_workers.load(Ordering::SeqCst), 0);
        assert_eq!(self.state.active_tunnels.load(Ordering::SeqCst), 0);
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

async fn serve(mut tls: tokio_rustls::server::TlsStream<TcpStream>, state: Arc<State>) {
    let (path, body) = timeout(LIMIT, async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 16_384);
            header.push(tls.read_u8().await.unwrap());
        }
        let header = String::from_utf8(header).unwrap();
        let path = header
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        let length = header
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
            .unwrap_or(0);
        assert!(length <= 65_536);
        let mut body = vec![0; length];
        tls.read_exact(&mut body).await.unwrap();
        (path, body)
    })
    .await
    .unwrap();
    let encoded = if path.starts_with("/ssl-tunnel-connect.sslvpn?") {
        path.split_once('?').unwrap().1.as_bytes()
    } else {
        &body
    };
    let fields: HashMap<_, _> = url::form_urlencoded::parse(encoded).collect();
    let cookie = || {
        assert_eq!(
            fields.get("authcookie").unwrap(),
            "synthetic-wait-auth-cookie"
        );
    };
    let response = if path.starts_with("/ssl-vpn/prelogin.esp?") {
        state.prelogins.fetch_add(1, Ordering::SeqCst);
        "<prelogin-response><status>Success</status></prelogin-response>".to_owned()
    } else if path == "/ssl-vpn/login.esp" {
        assert_eq!(fields.get("user").unwrap(), "synthetic-user");
        let attempt = state.logins.fetch_add(1, Ordering::SeqCst);
        let rounds = state.challenge_rounds.load(Ordering::SeqCst);
        assert!(rounds <= 2);
        if rounds > 0 {
            let mut requests = state.challenge_requests.lock().unwrap();
            assert!(requests.len() < 16);
            requests.push(
                fields
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
            );
            assert!(
                attempt <= rounds,
                "unexpected automatic authentication replay"
            );
            assert_eq!(
                fields.get("passwd").unwrap().as_ref(),
                if attempt == 0 {
                    "synthetic-cli-password-29483".to_owned()
                } else {
                    format!("synthetic-cli-answer-{attempt}")
                }
            );
            if attempt == 0 {
                assert!(!fields.contains_key("inputStr"));
            } else {
                assert_eq!(
                    fields.get("inputStr").unwrap().as_ref(),
                    format!("synthetic-cli-state-{attempt}")
                );
            }
        } else {
            assert_eq!(
                fields.get("passwd").unwrap(),
                "synthetic-cli-password-29483"
            );
        }
        if state.reject.load(Ordering::SeqCst) {
            "<response status='error'/>".to_owned()
        } else if attempt < rounds {
            let next = attempt + 1;
            format!("<challenge><inputstr>synthetic-cli-state-{next}</inputstr><respmsg>Enter answer {next}</respmsg></challenge>")
        } else {
            let mut args = vec![String::new(); 15];
            args[1] = "synthetic-wait-auth-cookie".into();
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
    } else if path == "/ssl-vpn/getconfig.esp" {
        cookie();
        state.configs.fetch_add(1, Ordering::SeqCst);
        "<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>1400</mtu><lifetime>60</lifetime><dns><member>10.77.0.1</member></dns></response>".to_owned()
    } else if path == "/ssl-vpn/hipreportcheck.esp" {
        cookie();
        state.hips.fetch_add(1, Ordering::SeqCst);
        "<response status='success'><hip-report-needed>no</hip-report-needed></response>".to_owned()
    } else if path.starts_with("/ssl-tunnel-connect.sslvpn?") {
        cookie();
        drop(fields);
        tunnel(tls, state).await;
        return;
    } else if path == "/ssl-vpn/logout.esp" {
        cookie();
        // Separate TLS sockets have no server-side scheduling order. Observe
        // remote tunnel completion at bounded final quiescence, not here.

        state.logouts.fetch_add(1, Ordering::SeqCst);
        let gate = state.logout_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            timeout(LIMIT, gate.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }
        if state.reject_logout.load(Ordering::SeqCst) {
            "<response status='error'/>".to_owned()
        } else {
            "<response status='success'/>".to_owned()
        }
    } else {
        panic!("unexpected synthetic gateway request");
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
    let _ = timeout(LIMIT, tls.shutdown()).await;
}

async fn tunnel(tls: tokio_rustls::server::TlsStream<TcpStream>, state: Arc<State>) {
    assert_eq!(state.active_tunnels.fetch_add(1, Ordering::SeqCst), 0);
    state.opened.fetch_add(1, Ordering::SeqCst);
    struct Tunnel(Arc<State>);
    impl Drop for Tunnel {
        fn drop(&mut self) {
            self.0.active_tunnels.fetch_sub(1, Ordering::SeqCst);
            self.0.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
    let _tunnel = Tunnel(state);
    gp_echo_tunnel::run(tls, 347).await.unwrap();
}
