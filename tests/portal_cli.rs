#![cfg(all(
    any(target_os = "macos", target_os = "linux"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! Actual CLI -> v3 IPC -> independently trusted portal/gateway -> memory IP.
//! No real credential file, network gateway, or OS network configuration is used.
use futures_util::FutureExt;
use gp_proxy::{control, control_local, gp, status};
#[path = "support/echo_peer.rs"]
mod echo_peer;
// Shared fixture exposes additional gates for the service lifecycle test suite.
#[allow(dead_code)]
#[path = "support/portal_origins.rs"]
mod origins;
use origins::{DualOrigins, Plan, COMPUTER, PASSWORD, USER};
use std::{
    fs::{self, DirBuilder},
    io::Write,
    net::{SocketAddr, TcpListener},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    panic::AssertUnwindSafe,
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
const LIMIT: Duration = Duration::from_secs(10);

struct Fixture {
    directory: PathBuf,
    http: SocketAddr,
    socks: SocketAddr,
    reserved: Option<[TcpListener; 2]>,
}
impl Fixture {
    fn new(origins: &DualOrigins) -> Self {
        let directory = PathBuf::from(format!("/tmp/gp-portal-cli-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let addresses = (http.local_addr().unwrap(), socks.local_addr().unwrap());
        fs::write(directory.join("config.toml"),format!(
            "gateway = '{}'\nportal = '{}'\nca_file = {}\nportal_ca_file = {}\nhttp_listen = '{}'\nsocks_listen = '{}'\ndomains = ['synthetic-portal.invalid']\nnetworks = ['10.77.0.0/24']\nmax_connections = 4\nconnect_timeout_secs = 3\nidle_timeout_secs = 15\n",
            origins.gateway.origin,origins.portal.origin,
            serde_json::to_string(&origins.gateway.ca_file).unwrap(),serde_json::to_string(&origins.portal.ca_file).unwrap(),addresses.0,addresses.1)).unwrap();
        fs::write(
            directory.join("synthetic.portal"),
            format!(
                "GP_USER={USER}\nGP_PASSWORD={PASSWORD}\nGP_PORTAL={}\n",
                origins.portal.origin
            ),
        )
        .unwrap();
        fs::set_permissions(
            directory.join("synthetic.portal"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
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
    fn start(&mut self, waiting: bool) -> Process {
        self.reserved.take();
        let mut process = if waiting {
            self.spawn(&["run", "--wait-auth"])
        } else {
            self.spawn(&[
                "run",
                "--username",
                USER,
                "--password-stdin",
                "--computer",
                COMPUTER,
            ])
        };
        if !waiting {
            process.password();
        }
        process
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
        let input = child.stdin.take();
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
    fn password(&mut self) {
        writeln!(self.input.as_mut().unwrap(), "{PASSWORD}").unwrap();
        self.input.take();
    }
    async fn finish(&mut self) -> Output {
        let started = Instant::now();
        while self.alive() {
            assert!(started.elapsed() < LIMIT, "owned CLI deadline");
            sleep(Duration::from_millis(10)).await;
        }
        self.input.take();
        let output = self.child.take().unwrap().wait_with_output().unwrap();
        assert!(output.stdout.len() <= 65536 && output.stderr.len() <= 65536);
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            for secret in [PASSWORD, origins::PORTAL_COOKIE, origins::SESSION_COOKIE] {
                assert!(!text.contains(secret));
            }
        }
        output
    }
    async fn stop(&mut self) -> Output {
        if self.alive() {
            let mut command = Command::new("/bin/kill");
            command.env_clear().args(["-TERM", &self.id().to_string()]);
            let mut signal = Self::spawn(command);
            assert!(signal.finish().await.status.success());
        }
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

async fn ready(fixture: &Fixture, service: &mut Process, available: bool) {
    timeout(LIMIT, async {
        loop {
            assert!(service.alive(), "service exited");
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
async fn echo(fixture: &Fixture, socks: bool) {
    timeout(LIMIT,async{
        let mut stream=TcpStream::connect(if socks{fixture.socks}else{fixture.http}).await.unwrap();
        if socks {
            stream.write_all(&[5,1,0]).await.unwrap();let mut method=[0;2];stream.read_exact(&mut method).await.unwrap();assert_eq!(method,[5,0]);
            let name=b"app.synthetic-portal.invalid";let mut request=vec![5,1,0,3,name.len() as u8];request.extend_from_slice(name);request.extend_from_slice(&443u16.to_be_bytes());stream.write_all(&request).await.unwrap();
            let mut reply=[0;10];stream.read_exact(&mut reply).await.unwrap();assert_eq!(&reply[..2],&[5,0]);
        } else {
            stream.write_all(b"CONNECT app.synthetic-portal.invalid:443 HTTP/1.1\r\nHost: app.synthetic-portal.invalid:443\r\n\r\n").await.unwrap();
            assert!(header(&mut stream).await.starts_with(b"HTTP/1.1 200 "));
        }
        let payload=vec![if socks{0x55}else{0xa3};32768];stream.write_all(&payload).await.unwrap();
        let mut received=vec![0;payload.len()];stream.read_exact(&mut received).await.unwrap();assert_eq!(received,payload);
        stream.shutdown().await.unwrap();let mut end=[0;1];assert_eq!(stream.read(&mut end).await.unwrap(),0);
    }).await.unwrap();
}

async fn successful_cli(waiting: bool) {
    let origins = DualOrigins::start(Plan::default()).await;
    let mut fixture = Fixture::new(&origins);
    let mut service = fixture.start(waiting);
    let pid = service.id();
    let work = AssertUnwindSafe(timeout(Duration::from_secs(20), async {
        if waiting {
            ready(&fixture, &mut service, false).await;
            let preflight = control::preflight(&fixture.endpoint()).await.unwrap();
            assert_eq!(
                preflight.binding().portal_origin(),
                Some(origins.portal.origin.as_str())
            );
            assert_eq!(origins.portal.state.accepted.load(Ordering::SeqCst), 0);
            assert_eq!(origins.gateway.state.accepted.load(Ordering::SeqCst), 0);
            let mut reauth = fixture.spawn(&[
                "reauth",
                "--portal-env-file",
                "synthetic.portal",
                "--computer",
                COMPUTER,
            ]);
            let output = reauth.finish().await;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("Authentication accepted"));
        }
        ready(&fixture, &mut service, true).await;
        assert_eq!(service.id(), pid);
        echo(&fixture, false).await;
        echo(&fixture, true).await;
        assert!(origins.gateway.state.dns_queries.load(Ordering::SeqCst) > 0);
        assert!(origins.gateway.state.tcp_packets.load(Ordering::SeqCst) > 0);
        assert_eq!(origins.portal.state.count(origins::PORTAL_PRELOGIN), 1);
        assert_eq!(origins.portal.state.count(origins::PORTAL_LOGIN), 1);
        assert_eq!(origins.gateway.state.count(origins::GATEWAY_LOGIN), 1);
        let gateway = origins.gateway.state.requests(origins::GATEWAY_LOGIN);
        assert_ne!(gateway[0].fields.get("passwd").unwrap(), PASSWORD);
        assert!(origins.gateway.state.trace().iter().all(|request| request
            .fields
            .values()
            .all(|value| !value.contains(PASSWORD))));
    }))
    .catch_unwind()
    .await;
    let output = service.stop().await;
    let gateway_state = origins.gateway.state.clone();
    origins.close().await;
    fixture.released();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(gateway_state.count(origins::LOGOUT), 1);
    assert!(!gateway_state.has_session());
    match work {
        Ok(result) => result.expect("CLI work budget"),
        Err(error) => std::panic::resume_unwind(error),
    }
}

#[tokio::test]
async fn initial_portal_password_run_uses_independent_roots_and_dns_proxy_echo() {
    successful_cli(false).await;
}
#[tokio::test]
async fn waiting_daemon_accepts_explicit_portal_file_over_actual_ipc() {
    successful_cli(true).await;
}

#[tokio::test]
async fn portal_check_validates_both_roots_without_any_network_or_secret_file() {
    let origins = DualOrigins::start(Plan::default()).await;
    let fixture = Fixture::new(&origins);
    fs::remove_file(fixture.directory.join("synthetic.portal")).unwrap();
    let mut check = fixture.spawn(&["check"]);
    let output = check.finish().await;
    let portal = origins.portal.state.clone();
    let gateway = origins.gateway.state.clone();
    origins.close().await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(portal.accepted.load(Ordering::SeqCst), 0);
    assert_eq!(gateway.accepted.load(Ordering::SeqCst), 0);
}
