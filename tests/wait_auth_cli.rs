#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
//! External CLI + actual same-user IPC + synthetic TLS/GP + in-memory IP echo.
//! Every credential is a public fixed fixture; the real .env is never selected.
#[path = "support/wait_auth_gateway.rs"]
mod gateway;

use gp_proxy::{
    control_local,
    status::{self, Phase, Reason, Snapshot},
};
use std::{
    fs::{self, DirBuilder},
    io::Write,
    net::{SocketAddr, TcpListener},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

const LIMIT: Duration = Duration::from_secs(8);
const PASSWORD: &[u8] = b"synthetic-cli-password-29483\n";

struct Fixture {
    directory: PathBuf,
    http: SocketAddr,
    socks: SocketAddr,
    reserved: Option<[TcpListener; 2]>,
}
impl Fixture {
    fn new(gateway: &gateway::Gateway) -> Self {
        let directory = PathBuf::from(format!("/tmp/gp-wait-cli-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let addresses = (http.local_addr().unwrap(), socks.local_addr().unwrap());
        let ca = serde_json::to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/gp/testdata/localhost-cert.pem"
        ))
        .unwrap();
        fs::write(directory.join("config.toml"), format!(
            "gateway = '{}'\nhttp_listen = '{}'\nsocks_listen = '{}'\nca_file = {ca}\ndomains = ['synthetic-corp.invalid']\nnetworks = ['10.77.0.0/24']\nmax_connections = 4\nconnect_timeout_secs = 3\nidle_timeout_secs = 15\n",
            gateway.origin, addresses.0, addresses.1,
        )).unwrap();
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
    fn spawn(&self, args: &[&str]) -> Process {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
        command
            .current_dir(&self.directory)
            .env_clear()
            .args(["--config", "config.toml", "--control-dir", "control"])
            .args(args);
        Process::spawn(command)
    }
    fn run(&mut self) -> Process {
        self.reserved.take();
        self.spawn(&["run", "--wait-auth"])
    }
    fn assert_released(&mut self) {
        self.reserved.take();
        let _http = TcpListener::bind(self.http).unwrap();
        let _socks = TcpListener::bind(self.socks).unwrap();
        let mut entries: Vec<_> = fs::read_dir(self.endpoint())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["lock", "owner"]);
        let listener = control_local::LocalListener::bind(&self.endpoint()).unwrap();
        drop(listener); // The permanent lock is also available, not merely absent socket paths.
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct Process {
    child: Option<Child>,
    input: Option<ChildStdin>,
}
impl Process {
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take(); // wait may not turn a held-open pipe into EOF.
        Self {
            child: Some(child),
            input,
        }
    }
    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
    fn alive(&mut self) -> bool {
        self.child.as_mut().unwrap().try_wait().unwrap().is_none()
    }
    async fn finish(&mut self) -> Output {
        let started = Instant::now();
        while self.alive() {
            assert!(
                started.elapsed() < LIMIT,
                "owned CLI exceeded completion deadline while stdin remained open"
            );
            sleep(Duration::from_millis(10)).await;
        }
        self.input.take();
        let output = self.child.take().unwrap().wait_with_output().unwrap();
        assert!(output.stdout.len() <= 65_536 && output.stderr.len() <= 65_536);
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("synthetic-cli-password-29483"));
            assert!(!text.contains("synthetic-wait-auth-cookie"));
        }
        output
    }
    async fn terminate(&mut self) -> Output {
        assert!(self.alive());
        let mut command = Command::new("/bin/kill");
        command.args(["-TERM", &self.id().to_string()]).env_clear();
        let mut signal = Self::spawn(command);
        assert!(signal.finish().await.status.success());
        self.finish().await
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn await_state(fixture: &Fixture, process: &mut Process, available: bool) -> Snapshot {
    timeout(LIMIT, async {
        loop {
            if !process.alive() {
                let output = process.finish().await;
                panic!(
                    "service exited before readiness: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if let Ok(snapshot) = status::query(fixture.http).await {
                if snapshot.available == available
                    && (available || snapshot.reason == Reason::AuthenticationRequired)
                {
                    return snapshot;
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("waiting service did not publish expected status without password input")
}
async fn header(stream: &mut TcpStream) -> Vec<u8> {
    timeout(LIMIT, async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 16_384);
            bytes.push(stream.read_u8().await.unwrap());
        }
        bytes
    })
    .await
    .unwrap()
}
async fn pac(fixture: &Fixture) {
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
    timeout(LIMIT, stream.take(65_537).read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.len() <= 65_536);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 "));
    assert!(text.contains("synthetic-corp.invalid") && text.contains("FindProxyForURL"));
    assert!(text.contains(&format!("PROXY {}", fixture.http)));
}
async fn proxy_stream(fixture: &Fixture, socks: bool, success: bool) -> TcpStream {
    timeout(LIMIT, async {
        let mut stream = TcpStream::connect(if socks { fixture.socks } else { fixture.http })
            .await
            .unwrap();
        if socks {
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            stream.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            stream
                .write_all(&[5, 1, 0, 1, 10, 77, 0, 1, 1, 187])
                .await
                .unwrap();
            let mut reply = [0; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..2], &[5, if success { 0 } else { 1 }]);
        } else {
            stream
                .write_all(b"CONNECT 10.77.0.1:443 HTTP/1.1\r\nHost: 10.77.0.1:443\r\n\r\n")
                .await
                .unwrap();
            assert!(header(&mut stream).await.starts_with(if success {
                b"HTTP/1.1 200 "
            } else {
                b"HTTP/1.1 502 "
            }));
        }
        stream
    })
    .await
    .unwrap()
}
async fn unavailable(fixture: &Fixture) {
    let (http, socks) = tokio::join!(
        proxy_stream(fixture, false, false),
        proxy_stream(fixture, true, false)
    );
    drop((http, socks));
}
async fn echo(stream: &mut TcpStream, marker: u8) {
    let payload = [marker; 8192];
    let mut received = [0; 8192];
    timeout(LIMIT, async {
        stream.write_all(&payload).await.unwrap();
        stream.read_exact(&mut received).await.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(payload, received);
}
fn no_gateway(gateway: &gateway::Gateway) {
    assert_eq!(
        gateway.state.accepted.load(Ordering::SeqCst),
        0,
        "offline waiting contacted synthetic gateway"
    );
}

#[tokio::test]
async fn waiting_startup_needs_no_stdin_or_gateway_and_releases_resources() {
    let gateway = gateway::Gateway::start().await;
    let mut fixture = Fixture::new(&gateway);
    let mut service = fixture.run();
    let status = await_state(&fixture, &mut service, false).await;
    assert_eq!(status.phase, Phase::Stopped);
    assert_eq!(status.reason, Reason::AuthenticationRequired);
    assert_eq!(status.retry_count, 0);
    assert!(service.input.is_some());
    no_gateway(&gateway);
    // A same-user process can close immediately after connecting. That must
    // not turn a transient peer error into a fatal listener/service failure.
    for _ in 0..8 {
        let ready = timeout(LIMIT, control_local::connect(&fixture.endpoint()))
            .await
            .unwrap()
            .unwrap();
        drop(ready);
        sleep(Duration::from_millis(40)).await;
        if !service.alive() {
            let output = service.finish().await;
            panic!(
                "early IPC close stopped waiting service, exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    pac(&fixture).await;
    unavailable(&fixture).await;
    sleep(Duration::from_millis(1400)).await;
    no_gateway(&gateway);
    assert!(service.alive());
    assert_eq!(
        status::query(fixture.http).await.unwrap().reason,
        Reason::AuthenticationRequired
    );
    let output = service.terminate().await;
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Password"));
    fixture.assert_released();
    no_gateway(&gateway);
    gateway.close().await;
}

#[tokio::test]
async fn wait_auth_conflicts_reject_before_nonexistent_secret_or_config_reads() {
    let gateway = gateway::Gateway::start().await;
    let mut fixture = Fixture::new(&gateway);
    fs::remove_file(fixture.directory.join("config.toml")).unwrap();
    for arguments in [
        vec!["run", "--wait-auth", "--username", "synthetic-user"],
        vec!["run", "--wait-auth", "--password-stdin"],
        vec![
            "run",
            "--wait-auth",
            "--session-file",
            "does-not-exist.synthetic",
        ],
        vec![
            "--env-file",
            "does-not-exist.synthetic",
            "run",
            "--wait-auth",
        ],
        vec![
            "run",
            "--wait-auth",
            "--env-file",
            "does-not-exist.synthetic",
        ],
    ] {
        let mut command = fixture.spawn(&arguments);
        let output = command.finish().await;
        assert_eq!(
            output.status.code(),
            Some(2),
            "argument conflict reached file/runtime setup"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("--wait-auth"));
        assert!(!fixture.endpoint().exists());
        assert!(!fixture.directory.join("config.pac-history.json").exists());
        no_gateway(&gateway);
    }
    fixture.reserved.take();
    let _http = TcpListener::bind(fixture.http).unwrap();
    let _socks = TcpListener::bind(fixture.socks).unwrap();
    gateway.close().await;
}

#[tokio::test]
async fn real_reauth_cli_rejection_then_activation_keeps_same_service_and_logs_out() {
    let gateway = gateway::Gateway::start().await;
    let mut fixture = Fixture::new(&gateway);
    let mut service = fixture.run();
    await_state(&fixture, &mut service, false).await;
    let pid = service.id();
    let instance = fs::read(fixture.endpoint().join("instance")).unwrap();
    no_gateway(&gateway);
    gateway.state.reject.store(true, Ordering::SeqCst);
    let mut rejected =
        fixture.spawn(&["reauth", "--username", "synthetic-user", "--password-stdin"]);
    rejected
        .input
        .as_mut()
        .unwrap()
        .write_all(PASSWORD)
        .unwrap();
    rejected.input.take();
    assert!(!rejected.finish().await.status.success());
    await_state(&fixture, &mut service, false).await;
    unavailable(&fixture).await;
    pac(&fixture).await;
    sleep(Duration::from_millis(1400)).await;
    assert_eq!(gateway.state.prelogins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.configs.load(Ordering::SeqCst), 0);
    assert_eq!(gateway.state.opened.load(Ordering::SeqCst), 0);
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(fixture.endpoint().join("instance")).unwrap(),
        instance
    );
    gateway.state.reject.store(false, Ordering::SeqCst);
    let mut accepted =
        fixture.spawn(&["reauth", "--username", "synthetic-user", "--password-stdin"]);
    accepted
        .input
        .as_mut()
        .unwrap()
        .write_all(PASSWORD)
        .unwrap();
    accepted.input.take();
    let output = accepted.finish().await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Authentication accepted"));
    await_state(&fixture, &mut service, true).await;
    assert_eq!(service.id(), pid);
    assert_eq!(
        fs::read(fixture.endpoint().join("instance")).unwrap(),
        instance
    );
    assert_eq!(gateway.state.prelogins.load(Ordering::SeqCst), 2);
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 2);
    assert_eq!(gateway.state.configs.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.hips.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.opened.load(Ordering::SeqCst), 1);
    let (mut http, mut socks) = tokio::join!(
        proxy_stream(&fixture, false, true),
        proxy_stream(&fixture, true, true)
    );
    tokio::join!(echo(&mut http, 0x31), echo(&mut socks, 0x62));
    pac(&fixture).await;
    let output = service.terminate().await;
    assert!(output.status.success());
    for stream in [&mut http, &mut socks] {
        assert!(matches!(
            timeout(LIMIT, stream.read(&mut [0; 1])).await.unwrap(),
            Ok(0) | Err(_)
        ));
    }
    gateway.idle().await;
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.closed.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.active_tunnels.load(Ordering::SeqCst), 0);
    fixture.assert_released();
    gateway.close().await;
}
