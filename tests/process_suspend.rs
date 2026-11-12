#![forbid(unsafe_code)]
#![cfg(all(
    any(target_os = "macos", target_os = "linux"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! SIGSTOP/SIGCONT only the gp-proxy Child owned by this test. This is not OS sleep.
//! The gateway, raw-IP observer, and independent clock remain in the parent.
#[path = "support/process_gateway.rs"]
mod gateway;
use futures_util::FutureExt;
use gateway::{Gateway, Plan, COMPUTER, PASSWORD, USER};
use gp_proxy::{control, control_local, status};
use rustix::process::{kill_process, waitid, Pid, Signal, WaitId, WaitIdOptions};
use serde_json::json;
use std::{
    fs::{self, DirBuilder},
    io::{self, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::DirBuilderExt,
    panic::AssertUnwindSafe,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};
const STEP: Duration = Duration::from_secs(8);
const REVOKE: Duration = Duration::from_secs(2);
const LITERAL: &str = "10.77.0.1";
const PENDING_DNS: &str = "suspend-canary-dns.pending.suspend.invalid";
const AFTER_STOP: &[u8] = b"suspend-canary-byte-stream-must-never-reach-any-generation";

struct Fixture {
    directory: PathBuf,
    http: SocketAddr,
    socks: SocketAddr,
    reserved: Option<[TcpListener; 2]>,
}
impl Fixture {
    fn new(gateway: &Gateway) -> Self {
        let directory = PathBuf::from(format!("/tmp/gp-suspend-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let addresses = (http.local_addr().unwrap(), socks.local_addr().unwrap());
        fs::write(directory.join("config.toml"),format!("gateway='{}'\nca_file={}\nhttp_listen='{}'\nsocks_listen='{}'\ndomains=['pending.suspend.invalid']\nnetworks=['10.77.0.0/24']\nmax_connections=12\nconnect_timeout_secs=12\nidle_timeout_secs=60\n",gateway.origin,serde_json::to_string(concat!(env!("CARGO_MANIFEST_DIR"),"/src/gp/testdata/localhost-cert.pem")).unwrap(),addresses.0,addresses.1)).unwrap();
        Self {
            directory,
            http: addresses.0,
            socks: addresses.1,
            reserved: Some([http, socks]),
        }
    }
    fn endpoint(&self) -> PathBuf {
        self.directory.join("control")
    }
    fn spawn(&self, command: &str) -> Process {
        let mut process = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
        process.current_dir(&self.directory).env_clear().args([
            "--config",
            "config.toml",
            "--control-dir",
            "control",
            command,
            "--username",
            USER,
            "--password-stdin",
            "--computer",
            COMPUTER,
        ]);
        Process::spawn(process)
    }
    fn start(&mut self) -> Process {
        self.reserved.take();
        self.spawn("run")
    }
    fn released(&mut self) {
        self.reserved.take();
        let _http = TcpListener::bind(self.http).unwrap();
        let _socks = TcpListener::bind(self.socks).unwrap();
        let listener = control_local::LocalListener::bind(&self.endpoint()).unwrap();
        drop(listener);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct Process {
    child: Option<Child>,
    stopped: bool,
}
impl Process {
    fn spawn(mut command: Command) -> Self {
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Install the kill/wait owner before any fallible stdin operation.
        let mut process = Self {
            child: Some(child),
            stopped: false,
        };
        let mut input = process.child.as_mut().unwrap().stdin.take().unwrap();
        writeln!(input, "{PASSWORD}").unwrap();
        drop(input);
        process
    }
    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
    fn pid(&self) -> Pid {
        Pid::from_raw(self.id().try_into().unwrap()).unwrap()
    }
    fn alive(&mut self) -> bool {
        self.child.as_mut().unwrap().try_wait().unwrap().is_none()
    }
    async fn suspend(&mut self) -> Instant {
        assert!(self.alive());
        kill_process(self.pid(), Signal::STOP).unwrap();
        self.stopped = true;
        timeout(Duration::from_secs(2), async {
            loop {
                let status = waitid(
                    WaitId::Pid(self.pid()),
                    WaitIdOptions::STOPPED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
                )
                .unwrap();
                if let Some(status) = status {
                    assert!(status.stopped());
                    assert_eq!(status.stopping_signal(), Some(Signal::STOP.as_raw()));
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("owned child did not enter stopped state");
        eprintln!(
            "PROCESS_SUSPEND {}",
            json!({"event":"waitid_stopped","pid":self.id(),"signal":Signal::STOP.as_raw()})
        );
        Instant::now()
    }
    fn resume(&mut self) {
        assert!(self.stopped);
        kill_process(self.pid(), Signal::CONT).unwrap();
        self.stopped = false;
    }
    async fn finish(&mut self) -> Output {
        let started = Instant::now();
        while self.alive() {
            assert!(started.elapsed() < STEP, "owned child exit deadline");
            sleep(Duration::from_millis(10)).await;
        }
        let output = self.child.take().unwrap().wait_with_output().unwrap();
        assert!(output.stdout.len() <= 65536 && output.stderr.len() <= 65536);
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(PASSWORD));
            assert!(!text.contains("synthetic-process-cookie-"));
        }
        output
    }
    async fn stop(&mut self) -> Output {
        if self.alive() {
            if self.stopped {
                self.resume();
            }
            kill_process(self.pid(), Signal::TERM).unwrap();
        }
        self.finish().await
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // A reaped Child no longer pins its numeric PID. Never send signals
            // after try_wait has returned an exit status.
            if matches!(child.try_wait(), Ok(None)) {
                if self.stopped {
                    if let Some(pid) = Pid::from_raw(child.id().try_into().unwrap()) {
                        let _ = kill_process(pid, Signal::CONT);
                    }
                }
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

async fn wait(mut ready: impl FnMut() -> bool) {
    timeout(STEP, async {
        while !ready() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("parent fixture progress deadline");
}
async fn ready(fixture: &Fixture, child: &mut Process, available: bool) {
    timeout(STEP, async {
        loop {
            assert!(child.alive(), "owned service exited before expected state");
            if let Ok(snapshot) = status::query(fixture.http).await {
                if snapshot.available == available {
                    return;
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
async fn header(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16384);
        bytes.push(stream.read_u8().await.unwrap());
    }
    bytes
}

struct Request {
    stage: &'static str,
    stream: TcpStream,
    socks: bool,
    method_pending: bool,
}
async fn request(
    fixture: &Fixture,
    socks: bool,
    host: &str,
    stopped: bool,
    early: bool,
) -> Request {
    let mut stream = TcpStream::connect(if socks { fixture.socks } else { fixture.http })
        .await
        .unwrap();
    if socks {
        let mut bytes = vec![5, 1, 0];
        if !stopped {
            stream.write_all(&bytes).await.unwrap();
            let mut method = [0; 2];
            stream.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            bytes.clear();
        }
        bytes.extend_from_slice(&[5, 1, 0]);
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        } else {
            assert!(host.len() <= 255);
            bytes.extend_from_slice(&[3, host.len() as u8]);
            bytes.extend_from_slice(host.as_bytes());
        }
        bytes.extend_from_slice(&443u16.to_be_bytes());
        if early {
            bytes.extend_from_slice(AFTER_STOP);
        }
        stream.write_all(&bytes).await.unwrap();
    } else {
        stream
            .write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        if early {
            stream.write_all(AFTER_STOP).await.unwrap();
        }
    }
    let stage = match (stopped, socks, host == "10.77.0.99", early) {
        (true, true, _, true) => "queued-socks-with-early-data",
        (true, true, _, false) => "queued-socks-without-early-data",
        (true, false, _, _) => "queued-http",
        (false, true, true, _) => "pending-socks",
        (false, false, true, _) => "pending-http",
        (false, false, false, _) if host == PENDING_DNS => "pending-dns-http",
        (_, true, _, _) => "live-socks",
        _ => "live-http",
    };
    Request {
        stage,
        stream,
        socks,
        method_pending: socks && stopped,
    }
}
impl Request {
    async fn reply(&mut self, success: bool) {
        if self.method_pending {
            let mut method = [0; 2];
            self.stream.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            self.method_pending = false;
        }
        if self.socks {
            let mut bytes = [0; 10];
            let mut received = 0;
            while received < bytes.len() {
                match self.stream.read(&mut bytes[received..]).await {
                    Ok(0) => panic!(
                        "{} SOCKS reply EOF after {} bytes: {:?}",
                        self.stage,
                        received,
                        &bytes[..received]
                    ),
                    Ok(count) => received += count,
                    Err(error) => panic!(
                        "{} SOCKS reply failed after {} bytes: {:?}; {error:?}",
                        self.stage,
                        received,
                        &bytes[..received]
                    ),
                }
            }
            assert_eq!(bytes[0], 5);
            assert_eq!(bytes[1], if success { 0 } else { 1 });
        } else {
            let response = header(&mut self.stream).await;
            if success {
                assert!(response.starts_with(b"HTTP/1.1 200 "));
            } else {
                assert!(
                    response.starts_with(b"HTTP/1.1 502 "),
                    "explicit offline proxy failure"
                );
            }
        }
    }
    async fn early_socks_refusal(&mut self) {
        assert!(self.socks && self.method_pending);
        assert_eq!(self.stage, "queued-socks-with-early-data");
        // A client that sends application bytes before CONNECT succeeds can
        // receive RST when the peer closes with those bytes still unread. Keep
        // that case distinct from the conforming queued CONNECT below.
        let expected = [5, 0, 5, 1, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut bytes = [0; 12];
        let mut received = 0;
        let outcome = loop {
            match self.stream.read(&mut bytes[received..]).await {
                Ok(0) => panic!("early SOCKS partial EOF after {received} bytes"),
                Ok(count) => {
                    received += count;
                    assert_eq!(
                        &bytes[..received],
                        &expected[..received],
                        "a successful CONNECT or arbitrary prefix is not refusal"
                    );
                    if received == expected.len() {
                        break "complete_failure_reply";
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                    assert_eq!(&bytes[..received], &expected[..received]);
                    break "connection_reset";
                }
                Err(error) => panic!("unexpected early SOCKS error: {error:?}"),
            }
        };
        eprintln!(
            "PROCESS_SUSPEND {}",
            json!({"event":"early_socks_refusal",
            "outcome":outcome,"received_prefix":&bytes[..received]})
        );
    }

    async fn echo(&mut self) {
        let data = [0x5a; 128];
        self.stream.write_all(&data).await.unwrap();
        let mut read = [0; 128];
        self.stream.read_exact(&mut read).await.unwrap();
        assert_eq!(read, data);
    }
    async fn closed(&mut self) {
        let mut byte = [0; 1];
        match self.stream.read(&mut byte).await {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("old application stream remained usable: {other:?}"),
        }
    }
}
async fn management(fixture: &Fixture) {
    let mut stream = TcpStream::connect(fixture.http).await.unwrap();
    stream
        .write_all(
            format!(
                "GET /proxy.pac HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                fixture.http
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    timeout(STEP, stream.take(65537).read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.len() <= 65536);
    let body = String::from_utf8(bytes).unwrap();
    assert!(
        body.starts_with("HTTP/1.1 200 ")
            && body.contains("pending.suspend.invalid")
            && body.contains("FindProxyForURL")
    );
    status::query(fixture.http).await.unwrap();
}

async fn exercise(fixture: &Fixture, child: &mut Process, gateway: &Gateway, expiry: bool) {
    let pid = child.id();

    ready(fixture, child, true).await;
    let identity = control_local::connect(&fixture.endpoint())
        .await
        .unwrap()
        .instance_id;
    let mut http = request(fixture, false, LITERAL, false, false).await;
    http.reply(true).await;
    http.echo().await;
    let mut socks = request(fixture, true, LITERAL, false, false).await;
    socks.reply(true).await;
    socks.echo().await;
    let mut pending_http = request(fixture, false, "10.77.0.99", false, false).await;
    let mut pending_socks = request(fixture, true, "10.77.0.99", false, false).await;
    let mut pending_dns = request(fixture, false, PENDING_DNS, false, false).await;
    let wire = gateway.state.wires()[0].clone();
    wait(|| {
        wire.blackhole_syns.load(Ordering::SeqCst) >= 2
            && wire.udp_payload_bytes.load(Ordering::SeqCst) > 0
    })
    .await;
    let snapshot = status::query(fixture.http).await.unwrap();
    assert!(snapshot.pending_tcp >= 2 && snapshot.active_udp > 0);
    let stopped = child.suspend().await;
    http.stream.write_all(AFTER_STOP).await.unwrap();
    socks.stream.write_all(AFTER_STOP).await.unwrap();
    let mut queued = if expiry {
        Some((
            request(
                fixture,
                false,
                "suspend-canary-queued.pending.suspend.invalid",
                true,
                true,
            )
            .await,
            request(fixture, true, LITERAL, true, true).await,
            request(fixture, true, LITERAL, true, false).await,
        ))
    } else {
        None
    };
    let pause = Duration::from_millis(if expiry { 5500 } else { 4500 });
    sleep(pause.saturating_sub(stopped.elapsed())).await;
    // A ready generation preceded STOP. Waiting an entire advertised lifetime
    // (or timeout) after observed STOP is a conservative independent upper bound,
    // not an assumption that server write completion equals client receipt.
    assert!(stopped.elapsed() >= pause);
    wire.armed.store(true, Ordering::SeqCst);
    gateway.state.watch_canaries.store(true, Ordering::SeqCst);
    let stopped_ms = stopped.elapsed().as_millis();
    let resumed = Instant::now();
    child.resume();
    timeout(REVOKE, async {
        http.closed().await;
        socks.closed().await;
        pending_http.reply(false).await;
        pending_socks.reply(false).await;
        pending_dns.reply(false).await;
        if let Some((http, early_socks, conforming_socks)) = &mut queued {
            http.reply(false).await;
            conforming_socks.reply(false).await;
            early_socks.early_socks_refusal().await;
        }
    })
    .await
    .expect("old streams or admitted requests survived process-resume cutoff");
    let revoke_ms = resumed.elapsed().as_millis();
    wait(|| wire.closed.load(Ordering::SeqCst)).await;
    assert_eq!(wire.late_tcp_payload_bytes.load(Ordering::SeqCst), 0);
    assert_eq!(wire.late_udp_payload_bytes.load(Ordering::SeqCst), 0);
    assert_eq!(wire.late_canaries.load(Ordering::SeqCst), 0);
    assert_eq!(
        gateway
            .state
            .canaries_after_resume_cutoff
            .load(Ordering::SeqCst),
        0
    );
    if expiry {
        ready(fixture, child, false).await;
        wait(|| gateway.state.sessions()[0].logouts.load(Ordering::SeqCst) == 1).await;
        let snapshot = status::query(fixture.http).await.unwrap();
        assert_eq!(snapshot.reason, status::Reason::SessionExpired);
        assert_eq!(
            [
                snapshot.active_tcp,
                snapshot.pending_tcp,
                snapshot.active_udp,
                snapshot.closing_tcp,
                snapshot.command_queue,
                snapshot.incoming_packets,
                snapshot.outgoing_packets,
            ],
            [0; 7]
        );
        assert_eq!(snapshot.retry_count, 0);
        management(fixture).await;
        sleep(Duration::from_millis(250)).await;
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
        let preflight = control::preflight(&fixture.endpoint()).await.unwrap();
        assert!(preflight.matches_gateway(&gateway.origin));
        let mut reauth = fixture.spawn("reauth");
        let output = reauth.finish().await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        ready(fixture, child, true).await;
        assert_eq!(child.id(), pid);
        assert_eq!(
            control_local::connect(&fixture.endpoint())
                .await
                .unwrap()
                .instance_id,
            identity
        );
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 2);
    } else {
        wait(|| gateway.state.wires().len() == 2).await;
        ready(fixture, child, true).await;
        let sessions = gateway.state.sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].configs.load(Ordering::SeqCst), 2);
        assert_eq!(sessions[0].logouts.load(Ordering::SeqCst), 0);
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
        assert!(gateway.state.wires().iter().all(|wire| wire.session == 1));
        assert_eq!(status::query(fixture.http).await.unwrap().retry_count, 0);
        management(fixture).await;
    }
    let mut new_http = request(fixture, false, LITERAL, false, false).await;
    new_http.reply(true).await;
    new_http.echo().await;
    let mut new_socks = request(fixture, true, LITERAL, false, false).await;
    new_socks.reply(true).await;
    new_socks.echo().await;
    let _ = http.stream.write_all(AFTER_STOP).await;
    let _ = socks.stream.write_all(AFTER_STOP).await;
    timeout(REVOKE, async {
        http.closed().await;
        socks.closed().await;
    })
    .await
    .unwrap();
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        gateway
            .state
            .canaries_after_resume_cutoff
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(wire.late_tcp_payload_bytes.load(Ordering::SeqCst), 0);
    assert_eq!(wire.late_udp_payload_bytes.load(Ordering::SeqCst), 0);
    eprintln!(
        "PROCESS_SUSPEND {}",
        json!({"event":"resume_checked","case":if expiry{"login_expiry"}else{"tunnel_renewal"},"pid":pid,"parent_stopped_ms":stopped_ms,"revoke_ms":revoke_ms,"old_generation":wire.generation,"old_session":wire.session,"old_udp_before":wire.udp_payload_bytes.load(Ordering::SeqCst),"late_tcp_payload":wire.late_tcp_payload_bytes.load(Ordering::SeqCst),"late_udp_payload":wire.late_udp_payload_bytes.load(Ordering::SeqCst),"late_canaries":gateway.state.canaries_after_resume_cutoff.load(Ordering::SeqCst)})
    );
}

async fn scenario(expiry: bool) {
    let plan = if expiry {
        Plan {
            lifetime: 5,
            first_timeout: None,
        }
    } else {
        Plan {
            lifetime: 60,
            first_timeout: Some(4),
        }
    };
    let gateway = Gateway::start(plan).await;
    let mut fixture = Fixture::new(&gateway);
    let mut child = fixture.start();
    let pid = child.id();
    let work = AssertUnwindSafe(timeout(
        Duration::from_secs(30),
        exercise(&fixture, &mut child, &gateway, expiry),
    ))
    .catch_unwind()
    .await;
    // This cleanup is independent of the work timeout/panic. In particular an
    // assertion while STOPPED must CONT before requesting shutdown or killing.
    let output = child.stop().await;
    let state = gateway.state.clone();
    gateway.close().await;
    fixture.released();
    eprintln!(
        "PROCESS_SUSPEND {}",
        json!({"event":"cleaned","pid":pid,"child_waited":true,"child_exit":output.status.code(),"workers":state.workers.load(Ordering::SeqCst),"tunnels":state.tunnels.load(Ordering::SeqCst),"logins":state.logins.load(Ordering::SeqCst),"sessions":state.sessions().iter().map(|session|json!({"number":session.number,"configs":session.configs.load(Ordering::SeqCst),"logouts":session.logouts.load(Ordering::SeqCst)})).collect::<Vec<_>>(),"wires":state.wires().iter().map(|wire|json!({"generation":wire.generation,"session":wire.session,"closed":wire.closed.load(Ordering::SeqCst),"late_tcp_payload":wire.late_tcp_payload_bytes.load(Ordering::SeqCst),"late_udp_payload":wire.late_udp_payload_bytes.load(Ordering::SeqCst),"late_canaries":wire.late_canaries.load(Ordering::SeqCst)})).collect::<Vec<_>>() })
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(state
        .sessions()
        .iter()
        .all(|session| session.logouts.load(Ordering::SeqCst) == 1));
    assert!(state
        .wires()
        .iter()
        .all(|wire| wire.closed.load(Ordering::SeqCst)));
    assert_eq!(state.canaries_after_resume_cutoff.load(Ordering::SeqCst), 0);
    for wire in state
        .wires()
        .iter()
        .filter(|wire| wire.armed.load(Ordering::SeqCst))
    {
        assert_eq!(wire.late_tcp_payload_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(wire.late_udp_payload_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(wire.late_canaries.load(Ordering::SeqCst), 0);
    }

    match work {
        Ok(result) => result.expect("process suspension work budget"),
        Err(error) => std::panic::resume_unwind(error),
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_process_past_login_expiry_revokes_old_and_queued_work_until_explicit_reauth() {
    scenario(true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_process_past_tunnel_timeout_renews_same_cookie_without_password_replay() {
    scenario(false).await;
}
