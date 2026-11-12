//! Direct authentication when a server loses its reply after receiving the POST.
//! No real credentials, DNS, interfaces, or remote gateways are involved.
use super::*;
use crate::service::challenge_tests::gateway::gp_echo_tunnel;
use crate::{gp::ResumptionPolicy, proxy::Target};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
const STEP: Duration = Duration::from_secs(6);
const USER: &str = "public-disconnect-user";
const PASSWORD: &str = "public-disconnect-password";
const COMPUTER: &str = "public-disconnect-computer";
const COOKIE: &str = "public-second-explicit-session";
#[derive(Clone, Copy)]
enum Fault {
    Eof,
    TruncatedBody,
}
#[derive(Default)]
struct State {
    workers: AtomicUsize,
    prelogins: AtomicUsize,
    logins: AtomicUsize,
    configs: AtomicUsize,
    tunnels: AtomicUsize,
    active_tunnels: AtomicUsize,
    logouts: AtomicUsize,
    known_session: AtomicBool,
}
struct Gateway {
    origin: String,
    client: GatewayClient,
    state: Arc<State>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Gateway {
    async fn start(fault: Fault) -> Self {
        let certs = CertificateDer::pem_slice_iter(include_bytes!(
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
        .with_single_cert(certs, key)
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let client = GatewayClient::new(
            Url::parse(&origin).unwrap(),
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
        let state = Arc::new(State::default());
        let shared = state.clone();
        let stop = CancellationToken::new();
        let stopping = stop.clone();
        let task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            let capacity = Arc::new(Semaphore::new(8));
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    _=stopping.cancelled()=>break,
                    result=tasks.join_next(),if !tasks.is_empty()=>{result.unwrap().unwrap();},
                    accepted=listener.accept()=>{
                        let(tcp,_)=accepted.unwrap();let permit=capacity.clone().try_acquire_owned().expect("disconnect fixture worker bound");shared.workers.fetch_add(1,Ordering::SeqCst);
                        let state=shared.clone();let acceptor=acceptor.clone();
                        tasks.spawn(async move{let _permit=permit;struct Worker(Arc<State>);impl Drop for Worker{fn drop(&mut self){self.0.workers.fetch_sub(1,Ordering::SeqCst);}}let _worker=Worker(state.clone());
                            let tls=timeout(STEP,acceptor.accept(tcp)).await.unwrap().unwrap();let _=timeout(Duration::from_secs(20),serve(tls,state,fault)).await.expect("disconnect fixture handler deadline");
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
            client,
            state,
            stop,
            task: Some(task),
        }
    }
    async fn close(mut self) {
        wait(|| self.state.workers.load(Ordering::SeqCst) == 0).await;
        assert_eq!(self.state.active_tunnels.load(Ordering::SeqCst), 0);
        assert!(!self.state.known_session.load(Ordering::SeqCst));
        self.stop.cancel();
        timeout(STEP, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
async fn wait(check: impl Fn() -> bool) {
    timeout(STEP, async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("disconnect fixture observation deadline");
}
fn session(cookie: &str) -> String {
    let mut args = vec![String::new(); 15];
    args[1] = cookie.into();
    args[3] = "public-portal".into();
    args[4] = USER.into();
    args[7] = "public-domain".into();
    args[12] = "tunnel".into();
    args[14] = "4100".into();
    format!(
        "<jnlp><application-desc>{}</application-desc></jnlp>",
        args.into_iter()
            .map(|a| format!("<argument>{a}</argument>"))
            .collect::<String>()
    )
}
async fn serve(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<State>,
    fault: Fault,
) -> io::Result<()> {
    let (target, body) = timeout(STEP, async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 16384);
            header.push(tls.read_u8().await?);
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
        Ok::<_, io::Error>((target, body))
    })
    .await
    .unwrap()?;
    let path = target.split('?').next().unwrap();
    let encoded = if path == "/ssl-tunnel-connect.sslvpn" {
        target.split_once('?').unwrap().1.as_bytes()
    } else {
        &body
    };
    let mut fields = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(encoded).into_owned() {
        assert!(fields.insert(key, value).is_none());
    }
    let cookie = || {
        assert_eq!(fields.get("authcookie").map(String::as_str), Some(COOKIE));
        assert!(state.known_session.load(Ordering::SeqCst));
    };
    let response = match path {
        "/ssl-vpn/prelogin.esp" => {
            state.prelogins.fetch_add(1, Ordering::SeqCst);
            "<prelogin-response><status>Success</status></prelogin-response>".into()
        }
        "/ssl-vpn/login.esp" => {
            assert_eq!(fields["user"], USER);
            assert_eq!(fields["passwd"], PASSWORD);
            assert_eq!(fields["computer"], COMPUTER);
            assert!(!fields.contains_key("inputStr"));
            let attempt = state.logins.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(attempt <= 2, "unexpected automatic credential retry");
            if attempt == 1 {
                // Server received the entire credential POST. It may have created
                // a session, but never gives the client a complete parseable one.
                if matches!(fault, Fault::TruncatedBody) {
                    let full = session("public-unknown-first-cookie");
                    let prefix = &full.as_bytes()[..full.len() / 2];
                    tls.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            full.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                    tls.write_all(prefix).await?;
                    tls.flush().await?;
                }
                return tls.shutdown().await;
            }
            assert!(!state.known_session.swap(true, Ordering::SeqCst));
            session(COOKIE)
        }
        "/ssl-vpn/getconfig.esp" => {
            cookie();
            state.configs.fetch_add(1, Ordering::SeqCst);
            "<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>1400</mtu><lifetime>60</lifetime></response>".into()
        }
        "/ssl-vpn/hipreportcheck.esp" => {
            cookie();
            "<response status='success'><hip-report-needed>no</hip-report-needed></response>".into()
        }
        "/ssl-tunnel-connect.sslvpn" => {
            cookie();
            state.tunnels.fetch_add(1, Ordering::SeqCst);
            assert_eq!(state.active_tunnels.fetch_add(1, Ordering::SeqCst), 0);
            struct Tunnel(Arc<State>);
            impl Drop for Tunnel {
                fn drop(&mut self) {
                    self.0.active_tunnels.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _tunnel = Tunnel(state);
            return gp_echo_tunnel::run(tls, 998).await;
        }
        "/ssl-vpn/logout.esp" => {
            cookie();
            assert_eq!(state.logouts.fetch_add(1, Ordering::SeqCst), 0);
            assert!(state.known_session.swap(false, Ordering::SeqCst));
            "<response status='success'/>".into()
        }
        _ => panic!("unexpected disconnect fixture endpoint"),
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
fn password() -> AuthInput {
    AuthInput::Password {
        user: USER.into(),
        password: Zeroizing::new(PASSWORD.into()),
        computer: COMPUTER.into(),
    }
}
async fn case(fault: Fault) {
    let gateway = Gateway::start(fault).await;
    let connector = Arc::new(TunnelConnector::default());
    let stop = CancellationToken::new();
    let _cancel = stop.clone().drop_guard();
    let config = Config {
        gateway: gateway.origin.clone(),
        domains: vec![],
        networks: vec!["10.77.0.0/24".parse().unwrap()],
        max_connections: 4,
        reconnect_max_secs: 1,
        ..Config::default()
    };
    let (pac, _) = watch::channel(Arc::new(
        Policy::new(vec![], config.networks.clone()).unwrap(),
    ));
    let (handle, service) = new(
        config,
        gateway.client.clone(),
        connector.clone(),
        pac,
        stop.clone(),
    )
    .unwrap();
    let task = tokio::spawn(service.run());
    let mut first = handle
        .try_authenticate(password(), &gateway.origin, CancellationToken::new())
        .unwrap();
    assert_eq!(
        timeout(STEP, first.prepared()).await.unwrap(),
        Err(AuthFailure::TransportUnavailable)
    );
    drop(first);
    assert_eq!(handle.phase(), ServicePhase::Waiting);
    assert!(!connector.status().available);
    assert_eq!(
        connector
            .connect(Target::new("10.77.0.1", 443).unwrap())
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::NotConnected
    );
    // Longer than the configured first transport backoff including its jitter.
    // This finite quiet observation supplements the absence of any login retry loop.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(gateway.state.prelogins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.configs.load(Ordering::SeqCst), 0);
    assert_eq!(gateway.state.tunnels.load(Ordering::SeqCst), 0);
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 0);
    let mut second = handle
        .try_authenticate(password(), &gateway.origin, CancellationToken::new())
        .unwrap();
    timeout(STEP, second.prepared()).await.unwrap().unwrap();
    second.commit().unwrap();
    wait(|| connector.status().available).await;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let mut generation =
        crate::session::proxy_lifecycle_tests::GenerationProbe::capture(&connector);
    let mut stream = timeout(
        STEP,
        connector.connect(Target::new("10.77.0.1", 443).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let payload = vec![0x5a; 8192];
    timeout(STEP, async {
        stream.write_all(&payload).await.unwrap();
        let mut received = vec![0; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
    })
    .await
    .unwrap();
    stop.cancel();
    timeout(STEP, task).await.unwrap().unwrap();
    assert_eq!(handle.phase(), ServicePhase::Stopped);
    assert_eq!(
        handle.completion(),
        Some(CleanupSummary {
            known_sessions: 1,
            logout_confirmed: 1,
            logout_unconfirmed: 0,
            remote_outcome_unknown: 1,
        })
    );
    assert!(matches!(
        timeout(STEP, stream.read(&mut [0; 1])).await.unwrap(),
        Ok(0) | Err(_)
    ));
    drop(stream);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        generation.release_stack();
        wait(|| !generation.generation_alive()).await;
    }
    assert_eq!(gateway.state.prelogins.load(Ordering::SeqCst), 2);
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 2);
    assert_eq!(gateway.state.configs.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.tunnels.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
    gateway.close().await;
}
#[tokio::test]
async fn complete_password_post_then_eof_requires_new_explicit_authentication() {
    case(Fault::Eof).await;
}
#[tokio::test]
async fn truncated_session_reply_is_not_a_cookie_or_a_reason_to_replay_password() {
    case(Fault::TruncatedBody).await;
}
