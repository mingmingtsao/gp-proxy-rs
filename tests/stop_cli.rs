#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
//! Actual CLI stop receipts against owned processes and synthetic TLS/IP peers.
//! No real credentials, system service manager, signals or external gateway.
#[path = "support/wait_auth_gateway.rs"]
mod gateway;

use gp_proxy::{control, control_local, status};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use std::{
    fs::{self, DirBuilder},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::{sleep, timeout},
};

const STEP: Duration = Duration::from_secs(5);
const CASE: Duration = Duration::from_secs(20);
const MAX_OUTPUT: usize = 65_536;

struct Process {
    child: Child,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
impl Process {
    fn spawn(mut command: Command) -> Self {
        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        fcntl_setfl(
            child.stdout.as_ref().unwrap(),
            fcntl_getfl(child.stdout.as_ref().unwrap()).unwrap() | OFlags::NONBLOCK,
        )
        .unwrap();
        fcntl_setfl(
            child.stderr.as_ref().unwrap(),
            fcntl_getfl(child.stderr.as_ref().unwrap()).unwrap() | OFlags::NONBLOCK,
        )
        .unwrap();
        Self {
            child,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }
    fn drain(&mut self) {
        fn read(source: &mut impl Read, output: &mut Vec<u8>) {
            let mut bytes = [0; 4096];
            loop {
                match source.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(size) => {
                        assert!(
                            size <= MAX_OUTPUT - output.len(),
                            "owned child output bound"
                        );
                        output.extend_from_slice(&bytes[..size]);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => panic!("owned child pipe failed: {e}"),
                }
            }
        }
        read(self.child.stdout.as_mut().unwrap(), &mut self.stdout);
        read(self.child.stderr.as_mut().unwrap(), &mut self.stderr);
    }
    fn alive(&mut self) -> bool {
        self.drain();
        self.child.try_wait().unwrap().is_none()
    }
    async fn finish(&mut self) -> ExitStatus {
        timeout(STEP, async {
            loop {
                self.drain();
                if let Some(status) = self.child.try_wait().unwrap() {
                    self.drain();
                    for bytes in [&self.stdout, &self.stderr] {
                        let text = String::from_utf8_lossy(bytes);
                        assert!(!text.contains("synthetic-cli-password-29483"));
                        assert!(!text.contains("synthetic-wait-auth-cookie"));
                    }
                    return status;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("owned CLI must exit within five seconds")
    }
    fn report(&self, known: u64, confirmed: u64, unconfirmed: u64) {
        let value: serde_json::Value = serde_json::from_slice(&self.stdout).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "local_cleanup_complete": true,
                "cleanup": {
                    "known_sessions": known,
                    "logout_confirmed": confirmed,
                    "logout_unconfirmed": unconfirmed,
                    "remote_outcome_unknown": 0,
                }
            })
        );
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

struct Fixture {
    directory: PathBuf,
    http: SocketAddr,
    socks: SocketAddr,
    reservations: Option<[TcpListener; 2]>,
}
impl Fixture {
    fn new(gateway: &gateway::Gateway) -> Self {
        let directory = PathBuf::from(format!("/tmp/gp-stop-cli-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        fs::create_dir(directory.join("cwd")).unwrap();
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let addresses = (http.local_addr().unwrap(), socks.local_addr().unwrap());
        let ca = serde_json::to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/gp/testdata/localhost-cert.pem"
        ))
        .unwrap();
        fs::write(directory.join("config.toml"), format!(
            "gateway = '{}'\nhttp_listen = '{}'\nsocks_listen = '{}'\nca_file = {ca}\nnetworks = ['10.77.0.0/24']\ndomains = ['synthetic-corp.invalid']\nmax_connections = 4\nconnect_timeout_secs = 3\nidle_timeout_secs = 15\n",
            gateway.origin, addresses.0, addresses.1)).unwrap();
        Self {
            directory,
            http: addresses.0,
            socks: addresses.1,
            reservations: Some([http, socks]),
        }
    }
    fn endpoint(&self) -> PathBuf {
        self.directory.join("control")
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
        command
            .env_clear()
            .current_dir(self.directory.join("cwd"))
            .arg("--config")
            .arg(self.directory.join("config.toml"))
            .arg("--control-dir")
            .arg(self.endpoint())
            .stdin(Stdio::null());
        command
    }
    fn run(&mut self) -> Process {
        self.reservations.take();
        let mut command = self.command();
        command.args(["run", "--wait-auth"]);
        Process::spawn(command)
    }
    fn stop(&self, instance: Option<[u8; 16]>) -> Process {
        let mut command = self.command();
        command.arg("stop");
        if let Some(instance) = instance {
            let hex: String = instance.iter().map(|byte| format!("{byte:02x}")).collect();
            command.args(["--instance", &hex]);
        }
        Process::spawn(command)
    }
    async fn authenticate(&self) {
        let mut command = self.command();
        command
            .args(["reauth", "--username", "synthetic-user", "--password-stdin"])
            .stdin(Stdio::piped());
        let mut child = Process::spawn(command);
        child
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(b"synthetic-cli-password-29483\n")
            .unwrap();
        assert_eq!(child.finish().await.code(), Some(0));
    }
    async fn ready(&self, child: &mut Process, available: bool) {
        timeout(STEP, async {
            loop {
                assert!(child.alive(), "service stopped before readiness");
                if let Ok(snapshot) = status::query(self.http).await {
                    if snapshot.available == available {
                        if !available {
                            assert_eq!(snapshot.reason, status::Reason::AuthenticationRequired);
                        }
                        return;
                    }
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    fn released(&self, previous: [u8; 16]) {
        let _http = TcpListener::bind(self.http).unwrap();
        let _socks = TcpListener::bind(self.socks).unwrap();
        let replacement = control_local::LocalListener::bind(&self.endpoint()).unwrap();
        assert_ne!(replacement.instance_id(), previous);
        drop(replacement);
        let mut entries: Vec<_> = fs::read_dir(self.endpoint())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["lock", "owner"]);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

async fn stream(f: &Fixture, socks: bool) -> TcpStream {
    timeout(STEP, async {
        let mut stream = TcpStream::connect(if socks { f.socks } else { f.http })
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
            assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        } else {
            stream
                .write_all(b"CONNECT 10.77.0.1:443 HTTP/1.1\r\nHost: 10.77.0.1:443\r\n\r\n")
                .await
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 16384);
                header.push(stream.read_u8().await.unwrap());
            }
            assert!(header.starts_with(b"HTTP/1.1 200 "));
        }
        stream
    })
    .await
    .unwrap()
}
async fn echo(stream: &mut TcpStream, value: u8) {
    timeout(STEP, async {
        let sent = [value; 8192];
        let mut received = [0; 8192];
        stream.write_all(&sent).await.unwrap();
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, sent);
    })
    .await
    .unwrap();
}
async fn closed(stream: &mut TcpStream) -> bool {
    matches!(
        timeout(Duration::from_secs(1), stream.read(&mut [0; 1])).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test]
async fn offline_stop_returns_zero_session_report_and_releases_endpoints() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let mut daemon = fixture.run();
        fixture.ready(&mut daemon, false).await;
        let identity = control::inspect(&fixture.endpoint()).await.unwrap();
        assert!(identity.supports_stop);
        sleep(Duration::from_millis(150)).await;
        let mut stop = fixture.stop(Some(identity.instance));
        let stop_exit = stop.finish().await;
        fixture.released(identity.instance);
        let daemon_exit = daemon.finish().await;
        gateway.idle().await;
        let accepted = gateway.state.accepted.load(Ordering::SeqCst);
        gateway.close().await;
        assert_eq!(stop_exit.code(), Some(0));
        assert_eq!(daemon_exit.code(), Some(0));
        stop.report(0, 0, 0);
        assert_eq!(accepted, 0);
        eprintln!(concat!(
            "STOP offline gateway_connections=0 report=0/0/0 ",
            "children_reaped=true endpoints_released=true"
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stop_waits_for_logout_and_namespace_release_wrong_instance_is_harmless() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let mut daemon = fixture.run();
        fixture.ready(&mut daemon, false).await;
        fixture.authenticate().await;
        fixture.ready(&mut daemon, true).await;
        let identity = control::inspect(&fixture.endpoint()).await.unwrap();
        let (mut http, mut socks) = tokio::join!(stream(&fixture, false), stream(&fixture, true));
        tokio::join!(echo(&mut http, 31), echo(&mut socks, 47));
        let mut wrong = identity.instance;
        wrong[0] ^= 1;
        let mut rejected = fixture.stop(Some(wrong));
        let rejected_exit = rejected.finish().await;
        let retained_identity = control::inspect(&fixture.endpoint()).await.unwrap();
        let still_available = status::query(fixture.http).await.unwrap().available;
        tokio::join!(echo(&mut http, 61), echo(&mut socks, 79));
        let premature_logouts = gateway.state.logouts.load(Ordering::SeqCst);
        let gate = Arc::new(Semaphore::new(0));
        *gateway.state.logout_gate.lock().unwrap() = Some(gate.clone());
        let mut stop = fixture.stop(Some(identity.instance));
        timeout(STEP, async {
            while gateway.state.logouts.load(Ordering::SeqCst) == 0 {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let held_at = Instant::now();
        sleep(Duration::from_millis(200)).await;
        let still_running = stop.alive() && daemon.alive();
        let no_early_report = stop.stdout.is_empty();
        let namespace_held = control_local::LocalListener::bind(&fixture.endpoint()).is_err();
        let (http_closed, socks_closed) = tokio::join!(closed(&mut http), closed(&mut socks));
        let held_ms = held_at.elapsed().as_millis();
        gate.add_permits(1);
        let stop_exit = stop.finish().await;
        fixture.released(identity.instance);
        let daemon_exit = daemon.finish().await;
        gateway.idle().await;
        let counts = (
            gateway.state.logins.load(Ordering::SeqCst),
            gateway.state.logouts.load(Ordering::SeqCst),
            gateway.state.opened.load(Ordering::SeqCst),
            gateway.state.closed.load(Ordering::SeqCst),
        );
        gateway.close().await;
        assert_eq!(rejected_exit.code(), Some(1));
        assert!(rejected.stdout.is_empty());
        assert!(still_available);
        assert_eq!(retained_identity.instance, identity.instance);
        assert_eq!(premature_logouts, 0);
        assert!(still_running && no_early_report && namespace_held && http_closed && socks_closed);
        assert_eq!(stop_exit.code(), Some(0));
        assert_eq!(daemon_exit.code(), Some(0));
        stop.report(1, 1, 0);
        assert_eq!(counts, (1, 1, 1, 1));
        eprintln!(
            concat!(
                "STOP ready echo_bytes=32768 wrong_instance_exit=1 held_ms={} ",
                "premature_report=false namespace_held=true old_streams_closed=true ",
                "report=1/1/0 children_reaped=true endpoints_released=true"
            ),
            held_ms
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unconfirmed_remote_logout_reports_exit_three_after_local_cleanup() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        gateway.state.reject_logout.store(true, Ordering::SeqCst);
        let mut fixture = Fixture::new(&gateway);
        let mut daemon = fixture.run();
        fixture.ready(&mut daemon, false).await;
        fixture.authenticate().await;
        fixture.ready(&mut daemon, true).await;
        let identity = control::inspect(&fixture.endpoint()).await.unwrap();
        let mut stop = fixture.stop(Some(identity.instance));
        let stop_exit = stop.finish().await;
        fixture.released(identity.instance);
        let daemon_exit = daemon.finish().await;
        gateway.idle().await;
        let counts = (
            gateway.state.logins.load(Ordering::SeqCst),
            gateway.state.logouts.load(Ordering::SeqCst),
        );
        gateway.close().await;
        assert_eq!(stop_exit.code(), Some(3));
        assert_eq!(daemon_exit.code(), Some(0));
        stop.report(1, 0, 1);
        assert_eq!(counts, (1, 1));
        eprintln!(concat!(
            "STOP unconfirmed report=1/0/1 cli_exit=3 daemon_exit=0 ",
            "children_reaped=true endpoints_released=true"
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stop_rejects_credential_source_before_reading_missing_config_or_secret() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
    let absent = PathBuf::from(format!(
        "/tmp/gp-stop-never-created-{:016x}",
        rand::random::<u64>()
    ));
    command
        .env_clear()
        .arg("--config")
        .arg(absent.join("config.toml"))
        .arg("--env-file")
        .arg(absent.join("synthetic-secret"))
        .arg("--control-dir")
        .arg(absent.join("control"))
        .arg("stop")
        .stdin(Stdio::null());
    let mut child = Process::spawn(command);
    let status = child.finish().await;
    assert_eq!(status.code(), Some(2));
    assert!(child.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&child.stderr).contains("stop does not accept credential files")
    );
    assert!(!absent.exists());
}
