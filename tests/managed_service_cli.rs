#![cfg(target_os = "macos")]
//! Actual managed entry point and static runtime lease in owned child sessions.
//! This is not a launchd test. All authentication and IP peers are synthetic.
#[path = "support/wait_auth_gateway.rs"]
mod gateway;

use gp_proxy::{
    control, control_local,
    managed_protocol::ManagedIdentity,
    managed_release::{hexadecimal, Source},
    managed_runtime::{self, Gate, Maintenance},
    status,
};
use rustix::{
    fs::{fcntl_getfl, fcntl_setfl, Mode, OFlags},
    process,
};
use std::{
    fs::{self, DirBuilder},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::{fs::DirBuilderExt, fs::PermissionsExt, process::CommandExt},
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

const STEP: Duration = Duration::from_secs(8);
const CASE: Duration = Duration::from_secs(30);
const MAX_OUTPUT: usize = 65_536;
const CHILD_MODE: &str = "GP_MANAGED_CLI_OWNED_CHILD";

#[test]
fn managed_child_session() {
    if std::env::var(CHILD_MODE).as_deref() != Ok("exec") {
        return;
    }
    process::setsid().unwrap();
    assert_eq!(process::getsid(None).unwrap(), process::getpid());
    assert_eq!(process::getpgrp(), process::getpid());
    assert_eq!(io::stdin().read(&mut [0; 1]).unwrap(), 0);
    assert!(rustix::fs::open(
        "/dev/tty",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty()
    )
    .is_err());
    let binary = std::env::var_os("GP_MANAGED_CLI_BINARY").unwrap();
    let args: Vec<String> =
        serde_json::from_str(&std::env::var("GP_MANAGED_CLI_ARGS").unwrap()).unwrap();
    let error = Command::new(binary).env_clear().args(args).exec();
    panic!("owned managed exec failed: {error}");
}

struct Process {
    child: Child,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
impl Process {
    fn spawn(mut command: Command, capture_stdout: bool) -> Self {
        command.stdout(if capture_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let child = command.stderr(Stdio::piped()).spawn().unwrap();
        if let Some(stdout) = &child.stdout {
            fcntl_setfl(stdout, fcntl_getfl(stdout).unwrap() | OFlags::NONBLOCK).unwrap();
        }
        let stderr = child.stderr.as_ref().unwrap();
        fcntl_setfl(stderr, fcntl_getfl(stderr).unwrap() | OFlags::NONBLOCK).unwrap();
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
                        assert!(size <= MAX_OUTPUT - output.len(), "owned output bound");
                        output.extend_from_slice(&bytes[..size]);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => panic!("owned pipe failed: {e}"),
                }
            }
        }
        if let Some(stdout) = &mut self.child.stdout {
            read(stdout, &mut self.stdout);
        }
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
        .expect("owned CLI must terminate")
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
    gate: Gate,
    maintenance: Maintenance,
    http: SocketAddr,
    socks: SocketAddr,
    reservations: Option<[TcpListener; 2]>,
}
impl Fixture {
    fn new(gateway: &gateway::Gateway, write_config: bool) -> Self {
        let path = PathBuf::from(format!(
            "/tmp/gp-managed-run-{:016x}",
            rand::random::<u64>()
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        // current_exe resolves /tmp on macOS; the recorded executable path must
        // describe those exact bytes at the same canonical location.
        let directory = path.canonicalize().unwrap();
        fs::create_dir(directory.join("cwd")).unwrap();
        fs::write(
            directory.join("cwd/gp-proxy.toml"),
            b"invalid default config {{{",
        )
        .unwrap();
        let binary = directory.join("gp-proxy");
        fs::copy(env!("CARGO_BIN_EXE_gp-proxy"), &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let source = Source::open(&binary).unwrap();
        let release = source.digest();
        source.verify().unwrap();
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let addresses = (http.local_addr().unwrap(), socks.local_addr().unwrap());
        let gate = Gate {
            version: 2,
            identity: ManagedIdentity {
                installation: rand::random(),
                generation: 1,
                release,
            },
            enabled: false,
            binary,
            config: directory.join("config.toml"),
            control: directory.join("control"),
            logs: directory.join("logs"),
        };
        if write_config {
            let ca = serde_json::to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/gp/testdata/localhost-cert.pem"
            ))
            .unwrap();
            fs::write(&gate.config, format!(
                "gateway = '{}'\nhttp_listen = '{}'\nsocks_listen = '{}'\nca_file = {ca}\nnetworks = ['10.77.0.0/24']\ndomains = ['synthetic-corp.invalid']\nmax_connections = 4\nconnect_timeout_secs = 3\nidle_timeout_secs = 15\n",
                gateway.origin, addresses.0, addresses.1)).unwrap();
        }
        let maintenance = managed_runtime::initialize(&directory.join("runtime"), &gate).unwrap();
        Self {
            directory,
            gate,
            maintenance,
            http: addresses.0,
            socks: addresses.1,
            reservations: Some([http, socks]),
        }
    }
    fn enable(&mut self) {
        self.gate.identity.generation += 1;
        self.gate.enabled = true;
        self.maintenance.set_gate(&self.gate).unwrap();
    }
    fn close_gate(&mut self) {
        self.gate.enabled = false;
        self.maintenance.set_gate(&self.gate).unwrap();
    }
    fn args(&self, identity: ManagedIdentity) -> Vec<String> {
        vec![
            "managed-run".into(),
            "--runtime-dir".into(),
            self.directory.join("runtime").to_str().unwrap().into(),
            "--installation".into(),
            hexadecimal(&identity.installation),
            "--generation".into(),
            identity.generation.to_string(),
            "--release".into(),
            hexadecimal(&identity.release),
        ]
    }
    fn start(&mut self, identity: ManagedIdentity, extra: &[&str]) -> Process {
        self.reservations.take();
        let mut args = self.args(identity);
        args.extend(extra.iter().map(|s| s.to_string()));
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .env(CHILD_MODE, "exec")
            .env("GP_MANAGED_CLI_BINARY", &self.gate.binary)
            .env("GP_MANAGED_CLI_ARGS", serde_json::to_string(&args).unwrap())
            .args([
                "--exact",
                "managed_child_session",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(self.directory.join("cwd"))
            .stdin(Stdio::null());
        Process::spawn(command, false)
    }
    fn command(&self) -> Command {
        let mut command = Command::new(&self.gate.binary);
        command
            .env_clear()
            .current_dir(self.directory.join("cwd"))
            .arg("--config")
            .arg(&self.gate.config)
            .arg("--control-dir")
            .arg(&self.gate.control)
            .stdin(Stdio::null());
        command
    }
    async fn authenticate(&self) {
        let mut command = self.command();
        command
            .args(["reauth", "--username", "synthetic-user", "--password-stdin"])
            .stdin(Stdio::piped());
        let mut child = Process::spawn(command, true);
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
                assert!(child.alive(), "managed child failed before readiness");
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
    fn runtime_busy(&self) -> bool {
        match self.maintenance.try_runtime() {
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                true
            }
            Ok(_) => false,
        }
    }
    fn no_startup_side_effects(&self) {
        assert!(!self.gate.config.exists());
        assert!(!self.gate.logs.exists());
        assert!(!self.gate.control.exists());
        drop(TcpListener::bind(self.http).unwrap());
        drop(TcpListener::bind(self.socks).unwrap());
        drop(self.maintenance.try_runtime().unwrap());
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

#[tokio::test]
async fn managed_identity_authentication_and_maintenance_lock_follow_real_process_lifecycle() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway, true);
        fixture.enable();
        let mut daemon = fixture.start(fixture.gate.identity, &[]);
        fixture.ready(&mut daemon, false).await;
        let identity = control::inspect(&fixture.gate.control).await.unwrap();
        assert_eq!(identity.managed, Some(fixture.gate.identity));
        assert!(identity.supports_stop && fixture.runtime_busy());
        sleep(Duration::from_millis(150)).await;
        assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
        fixture.authenticate().await;
        fixture.ready(&mut daemon, true).await;
        let (mut http, mut socks) = tokio::join!(stream(&fixture, false), stream(&fixture, true));
        tokio::join!(echo(&mut http, 31), echo(&mut socks, 47));
        fixture.close_gate();
        assert_eq!(fixture.maintenance.read_gate().unwrap(), fixture.gate);
        assert_eq!(control::inspect(&fixture.gate.control).await.unwrap().managed, identity.managed);
        assert!(fixture.runtime_busy());
        let logout = Arc::new(Semaphore::new(0));
        *gateway.state.logout_gate.lock().unwrap() = Some(logout.clone());
        let mut command = fixture.command();
        command.args(["stop", "--instance", &hexadecimal(&identity.instance)]);
        let mut stop = Process::spawn(command, true);
        timeout(STEP, async {
            while gateway.state.logouts.load(Ordering::SeqCst) == 0 { sleep(Duration::from_millis(5)).await; }
        }).await.unwrap();
        let held_at = Instant::now();
        sleep(Duration::from_millis(200)).await;
        let held = stop.alive() && daemon.alive() && stop.stdout.is_empty() && fixture.runtime_busy();
        let namespace_held = control_local::LocalListener::bind(&fixture.gate.control).is_err();
        let old_http = timeout(STEP, http.read(&mut [0; 1])).await.unwrap();
        let old_socks = timeout(STEP, socks.read(&mut [0; 1])).await.unwrap();
        let held_ms = held_at.elapsed().as_millis();
        logout.add_permits(1);
        let stop_exit = stop.finish().await;
        let report: control::StopReport = serde_json::from_slice(&stop.stdout).unwrap();
        // The public stop protocol intentionally does not gate logger/process
        // teardown. Do not turn an unobserved receipt-to-exit interval into a
        // timing assertion; the independent static-lease test covers retention.
        let live_when_report_observed = daemon.alive();
        let daemon_exit = daemon.finish().await;
        let _retired = fixture.maintenance.try_runtime().unwrap();
        drop(TcpListener::bind(fixture.http).unwrap());
        drop(TcpListener::bind(fixture.socks).unwrap());
        let rebound = control_local::LocalListener::bind(&fixture.gate.control).unwrap();
        assert_ne!(rebound.instance_id(), identity.instance);
        drop(rebound);
        let counts = (gateway.state.logins.load(Ordering::SeqCst), gateway.state.logouts.load(Ordering::SeqCst), gateway.state.opened.load(Ordering::SeqCst), gateway.state.closed.load(Ordering::SeqCst));
        gateway.close().await;
        assert!(held && namespace_held);
        assert!(matches!(old_http, Ok(0) | Err(_)) && matches!(old_socks, Ok(0) | Err(_)));
        assert_eq!(stop_exit.code(), Some(0)); assert_eq!(daemon_exit.code(), Some(0));
        assert!(report.local_cleanup_complete);
        assert_eq!((report.cleanup.known_sessions, report.cleanup.logout_confirmed, report.cleanup.logout_unconfirmed, report.cleanup.remote_outcome_unknown), (1, 1, 0, 0));
        assert_eq!(counts, (1, 1, 1, 1));
        eprintln!("MANAGED real_identity=true generation=2 echo_bytes=16384 offline_gateway=0 held_ms={held_ms} cleanup_runtime_busy=true report_live_observed={live_when_report_observed} post_exit_runtime_acquired=true children_reaped=true");
    }).await.unwrap();
}

#[tokio::test]
async fn denied_admission_never_initializes_config_logs_control_or_authentication() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        for case in ["closed", "generation", "release", "binary_digest"] {
            let mut fixture = Fixture::new(&gateway, false);
            if case != "closed" {
                if case == "binary_digest" { fixture.gate.identity.release[0] ^= 1; }
                fixture.enable();
            }
            let mut supplied = fixture.gate.identity;
            match case { "generation" => supplied.generation += 1, "release" => supplied.release[0] ^= 1, _ => {} }
            let mut child = fixture.start(supplied, &[]);
            let exit = child.finish().await;
            fixture.no_startup_side_effects();
            assert_eq!(exit.code(), Some(1), "{case}");
            assert!(child.stderr.is_empty(), "{case}: admission must precede logger initialization");
        }
        let accepted = gateway.state.accepted.load(Ordering::SeqCst);
        gateway.close().await;
        assert_eq!(accepted, 0);
        eprintln!("MANAGED denied_cases=4 gateway_connections=0 no_logs=true no_control=true runtime_released=true");
    }).await.unwrap();
}

#[tokio::test]
async fn managed_entry_rejects_credentials_and_startup_path_overrides() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway, false);
        fixture.enable();
        for extra in [
            vec!["--env-file", "nonexistent-secrets"], vec!["--portal-env-file", "nonexistent-secrets"],
            vec!["--username", "synthetic-user"], vec!["--password-stdin"], vec!["--session-file", "nonexistent-session"],
            vec!["--config", "nonexistent-config"], vec!["--control-dir", "nonexistent-control"],
        ] {
            let mut child = fixture.start(fixture.gate.identity, &extra);
            assert_eq!(child.finish().await.code(), Some(2), "{extra:?}");
            fixture.no_startup_side_effects();
        }
        let accepted = gateway.state.accepted.load(Ordering::SeqCst);
        gateway.close().await;
        assert_eq!(accepted, 0);
        eprintln!("MANAGED credential_or_path_conflicts=7 exit=2 gateway_connections=0 no_startup_side_effects=true");
    }).await.unwrap();
}
