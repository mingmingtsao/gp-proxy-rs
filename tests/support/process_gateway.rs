//! Bounded direct-password GP fixture with parent-process raw-IP observations.
//! No host business sockets, interfaces, or host DNS are used by the data peer.
#[path = "localhost.rs"]
// Share one fixture source across unit modules and independent integration crates.
#[allow(clippy::duplicate_mod)]
mod localhost_fixture;
use gp_proxy::gp;
#[path = "echo_peer.rs"]
mod echo_peer;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};
use std::{
    collections::HashMap,
    io,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, Semaphore},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
const STEP: Duration = Duration::from_secs(8);
pub const USER: &str = "synthetic-suspend-user";
pub const PASSWORD: &str = "synthetic-suspend-password";
pub const COMPUTER: &str = "synthetic-suspend-computer";
pub const CANARY: &[u8] = b"suspend-canary";

#[derive(Clone, Copy)]
pub struct Plan {
    pub lifetime: u64,
    pub first_timeout: Option<u64>,
}

pub struct Session {
    pub number: usize,
    pub configs: AtomicUsize,
    pub logouts: AtomicUsize,
    issued: Instant,
}
impl Session {
    fn cookie(&self) -> String {
        format!("synthetic-process-cookie-{}", self.number)
    }
}

#[derive(Default)]
pub struct Wire {
    pub session: usize,
    pub generation: usize,
    pub closed: AtomicBool,
    pub armed: AtomicBool,
    pub tcp_payload_bytes: AtomicUsize,
    pub udp_payload_bytes: AtomicUsize,
    pub blackhole_syns: AtomicUsize,
    pub late_tcp_payload_bytes: AtomicUsize,
    pub late_udp_payload_bytes: AtomicUsize,
    pub late_canaries: AtomicUsize,
}
impl Wire {
    fn observe(&self, packet: &[u8], state: &State) -> bool {
        let ip = Ipv4Packet::new_checked(packet).unwrap();
        let (payload, udp, blackhole) = match ip.next_header() {
            IpProtocol::Tcp => {
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                let blackhole = ip.dst_addr() == Ipv4Addr::new(10, 77, 0, 99);
                if blackhole && tcp.syn() {
                    self.blackhole_syns.fetch_add(1, Ordering::SeqCst);
                }
                (tcp.payload(), false, blackhole)
            }
            IpProtocol::Udp => {
                let udp = UdpPacket::new_checked(ip.payload()).unwrap();
                assert_eq!(udp.dst_port(), 53);
                (udp.payload(), true, true) // Intentionally pending in-tunnel DNS.
            }
            _ => panic!("unexpected fixture IP protocol"),
        };
        let counter = if udp {
            &self.udp_payload_bytes
        } else {
            &self.tcp_payload_bytes
        };
        counter.fetch_add(payload.len(), Ordering::SeqCst);
        let canary = payload.windows(CANARY.len()).any(|window| window == CANARY);
        if self.armed.load(Ordering::SeqCst) {
            let late = if udp {
                &self.late_udp_payload_bytes
            } else {
                &self.late_tcp_payload_bytes
            };
            late.fetch_add(payload.len(), Ordering::SeqCst);
            if canary {
                self.late_canaries.fetch_add(1, Ordering::SeqCst);
            }
        }
        if state.watch_canaries.load(Ordering::SeqCst) && canary {
            state
                .canaries_after_resume_cutoff
                .fetch_add(1, Ordering::SeqCst);
        }
        !blackhole
    }
}

#[derive(Default)]
pub struct State {
    pub prelogins: AtomicUsize,
    pub logins: AtomicUsize,
    pub workers: AtomicUsize,
    pub tunnels: AtomicUsize,
    pub watch_canaries: AtomicBool,
    pub canaries_after_resume_cutoff: AtomicUsize,
    sessions: Mutex<Vec<Arc<Session>>>,
    wires: Mutex<Vec<Arc<Wire>>>,
}
impl State {
    pub fn sessions(&self) -> Vec<Arc<Session>> {
        self.sessions.lock().unwrap().clone()
    }
    pub fn wires(&self) -> Vec<Arc<Wire>> {
        self.wires.lock().unwrap().clone()
    }
    fn session(&self, cookie: &str) -> Arc<Session> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .find(|session| session.cookie() == cookie)
            .expect("known synthetic cookie")
            .clone()
    }
}

pub struct Gateway {
    pub origin: String,
    pub state: Arc<State>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Gateway {
    pub async fn start(plan: Plan) -> Self {
        assert!((3..=120).contains(&plan.lifetime));
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
        let shared = state.clone();
        let stop = CancellationToken::new();
        let stopping = stop.clone();
        let task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            let slots = Arc::new(Semaphore::new(8));
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _=stopping.cancelled()=>break,
                    result=workers.join_next(),if !workers.is_empty()=>{result.unwrap().unwrap();},
                    result=listener.accept()=>{
                        let (socket,_)=result.unwrap();let permit=slots.clone().try_acquire_owned().expect("gateway worker bound");let acceptor=acceptor.clone();let state=shared.clone();let stop=stopping.clone();
                        workers.spawn(async move {
                            let _permit=permit;state.workers.fetch_add(1,Ordering::SeqCst);
                            struct Active(Arc<State>);impl Drop for Active{fn drop(&mut self){self.0.workers.fetch_sub(1,Ordering::SeqCst);}}
                            let _active=Active(state.clone());
                            let transport=tokio::select!{_=stop.cancelled()=>return,result=timeout(STEP,acceptor.accept(socket))=>result.unwrap().unwrap()};
                            let _=serve(transport,state,plan,stop).await;
                        });
                    }
                }
            }
            timeout(STEP, async {
                while let Some(result) = workers.join_next().await {
                    result.unwrap();
                }
            })
            .await
            .expect("fixture workers join");
        });
        Self {
            origin,
            state,
            stop,
            task: Some(task),
        }
    }
    pub async fn close(mut self) {
        // Observe peer EOF and completed workers before cancelling the idle
        // listener. Cancellation must not manufacture successful cleanup.
        timeout(STEP, async {
            while self.state.workers.load(Ordering::SeqCst) != 0
                || self.state.tunnels.load(Ordering::SeqCst) != 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("natural gateway worker shutdown");
        self.stop.cancel();
        timeout(STEP, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.state.workers.load(Ordering::SeqCst), 0);
        assert_eq!(self.state.tunnels.load(Ordering::SeqCst), 0);
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

async fn serve(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<State>,
    plan: Plan,
    stop: CancellationToken,
) -> io::Result<()> {
    let (path, body) = timeout(STEP, async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 16384);
            header.push(tls.read_u8().await?);
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
            .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
            .unwrap_or(0);
        assert!(length <= 65536);
        let mut body = vec![0; length];
        tls.read_exact(&mut body).await?;
        Ok::<_, io::Error>((path, body))
    })
    .await
    .unwrap()?;
    let encoded = path
        .split_once('?')
        .map(|(_, query)| query.as_bytes())
        .unwrap_or(&body);
    let fields: HashMap<_, _> = url::form_urlencoded::parse(encoded).collect();
    let response = if path.starts_with("/ssl-vpn/prelogin.esp?") {
        state.prelogins.fetch_add(1, Ordering::SeqCst);
        "<prelogin-response><status>Success</status></prelogin-response>".to_owned()
    } else if path == "/ssl-vpn/login.esp" {
        assert_eq!(fields.get("user").unwrap(), USER);
        assert_eq!(fields.get("passwd").unwrap(), PASSWORD);
        assert_eq!(fields.get("computer").unwrap(), COMPUTER);
        assert!(!fields.contains_key("inputStr"));
        let number = state.logins.fetch_add(1, Ordering::SeqCst) + 1;
        assert!(number <= 2, "unexpected password replay");
        let session = Arc::new(Session {
            number,
            configs: AtomicUsize::new(0),
            logouts: AtomicUsize::new(0),
            issued: Instant::now(),
        });
        state.sessions.lock().unwrap().push(session.clone());
        let mut arguments = vec![String::new(); 15];
        arguments[1] = session.cookie();
        arguments[3] = "portal".into();
        arguments[4] = USER.into();
        arguments[7] = "domain".into();
        arguments[12] = "tunnel".into();
        arguments[14] = "4100".into();
        format!(
            "<jnlp><application-desc>{}</application-desc></jnlp>",
            arguments
                .into_iter()
                .map(|arg| format!("<argument>{arg}</argument>"))
                .collect::<String>()
        )
    } else {
        let session = state.session(fields.get("authcookie").expect("cookie required"));
        match path.split('?').next().unwrap() {
            "/ssl-vpn/getconfig.esp" => {
                let config = session.configs.fetch_add(1, Ordering::SeqCst);
                assert!(config < 3);
                let lifetime = plan
                    .lifetime
                    .saturating_sub(session.issued.elapsed().as_secs())
                    .max(1);
                let timeout = plan
                    .first_timeout
                    .map(|seconds| {
                        format!(
                            "<timeout>{}</timeout>",
                            if config == 0 { seconds } else { 60 }
                        )
                    })
                    .unwrap_or_default();
                format!("<response status='success'><need-tunnel>yes</need-tunnel><ip-address>10.77.0.2</ip-address><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>1400</mtu><lifetime>{lifetime}</lifetime>{timeout}<dns><member>10.77.0.1</member></dns></response>")
            }
            "/ssl-vpn/hipreportcheck.esp" => {
                "<response status='success'><hip-report-needed>no</hip-report-needed></response>"
                    .to_owned()
            }
            "/ssl-vpn/logout.esp" => {
                assert_eq!(
                    session.logouts.fetch_add(1, Ordering::SeqCst),
                    0,
                    "each cookie is logged out once"
                );
                "<response status='success'/>".to_owned()
            }
            "/ssl-tunnel-connect.sslvpn" => {
                drop(fields);
                let wire = {
                    let mut wires = state.wires.lock().unwrap();
                    assert!(wires.len() < 6);
                    let wire = Arc::new(Wire {
                        session: session.number,
                        generation: wires.len() + 1,
                        ..Wire::default()
                    });
                    wires.push(wire.clone());
                    wire
                };
                return tunnel(tls, state, wire, stop).await;
            }
            _ => panic!("unexpected fixture endpoint"),
        }
    };
    tls.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        )
        .as_bytes(),
    )
    .await?;
    let _ = timeout(STEP, tls.shutdown()).await;
    Ok(())
}

async fn tunnel(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    state: Arc<State>,
    wire: Arc<Wire>,
    stop: CancellationToken,
) -> io::Result<()> {
    // Separate TLS connections have no remote scheduling order: the new
    // request can be accepted before the old reader observes EOF.
    assert!(state.tunnels.fetch_add(1, Ordering::SeqCst) < 2);
    struct Active(Arc<State>, Arc<Wire>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.tunnels.fetch_sub(1, Ordering::SeqCst);
            self.1.closed.store(true, Ordering::SeqCst);
        }
    }
    let _active = Active(state.clone(), wire.clone());
    tls.write_all(b"START_TUNNEL").await?;
    tls.flush().await?;
    let cancel = stop.child_token();
    let _guard = cancel.clone().drop_guard();
    let (input, incoming) = mpsc::channel(64);
    let (output, mut outgoing) = mpsc::channel(64);
    let (mut read, mut write) = tokio::io::split(tls);
    let mut tasks = JoinSet::new();
    tasks.spawn(echo_peer::run_peer(
        incoming,
        output,
        cancel.clone(),
        Arc::new(Mutex::new(echo_peer::PeerStats::default())),
        Arc::new(AtomicBool::new(false)),
        4,
        719,
    ));
    let stopping = cancel.clone();
    tasks.spawn(async move{
        loop{tokio::select!{_=stopping.cancelled()=>break,frame=gp::read_frame(&mut read,1400)=>match frame{
            Ok(gp::Frame::Ip(packet))=>if wire.observe(&packet,&state){tokio::select!{_=stopping.cancelled()=>break,result=input.send(packet)=>if result.is_err(){break}}},
            Ok(gp::Frame::Keepalive)=>{},Err(_)=>break,
        }}}
        Ok::<_,io::Error>(())
    });
    loop {
        tokio::select! {_=cancel.cancelled()=>break,result=tasks.join_next()=>{let _=result.unwrap().unwrap();break},packet=outgoing.recv()=>match packet{
            Some(packet)=>if !matches!(timeout(STEP,gp::write_frame(&mut write,&gp::Frame::Ip(packet),1400)).await,Ok(Ok(()))){break},None=>break,
        }}
    }
    cancel.cancel();
    let _ = timeout(STEP, write.shutdown()).await;
    timeout(STEP, async {
        while let Some(result) = tasks.join_next().await {
            let _ = result.unwrap();
        }
    })
    .await
    .expect("memory peer task join");
    Ok(())
}
