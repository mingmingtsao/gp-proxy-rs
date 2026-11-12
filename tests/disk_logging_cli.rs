#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
//! Real owned CLI processes, synthetic TLS, and fixed-capacity disk logging.
//! No user TTY, real credentials, external gateway or system service manager.
#[path = "support/wait_auth_gateway.rs"]
mod gateway;

use gp_proxy::{control, control_local, status};
use rustix::{
    fs::{fcntl_getfl, fcntl_setfl, Mode, OFlags},
    process,
};
use std::{
    fs::{self, DirBuilder},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    os::{
        fd::AsFd,
        unix::{
            fs::{DirBuilderExt, MetadataExt, PermissionsExt},
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

const STEP: Duration = Duration::from_secs(5);
const CASE: Duration = Duration::from_secs(60);
const CAP: u64 = 65_536;
const MAX_OUTPUT: usize = 65_536;
const MODE: &str = "GP_DISK_LOG_CHILD";
const FILTER: &str = "info,gp_proxy::proxy=debug";
const OBSERVER_READY: &[u8] = b"GP_DISK_OBSERVER_READY\n";
const SOCKS_DIAGNOSTIC: &[u8] = b"SOCKS proxy connection ended";

fn observe_service_pipes() -> ! {
    // The observer is a sibling of the service, never its parent. Its stdin
    // and stderr are the service's two pipe read ends; stdout is a separate
    // readiness channel back to the owning test process.
    let input = io::stdin();
    let errors = io::stderr();
    for descriptor in [input.as_fd(), errors.as_fd()] {
        assert!(fcntl_getfl(descriptor).unwrap().contains(OFlags::NONBLOCK));
    }
    io::stdout().write_all(OBSERVER_READY).unwrap();
    io::stdout().flush().unwrap();
    let deadline = Instant::now() + CASE;
    let mut consumed = 0;
    let mut bytes = [0; 4096];
    while Instant::now() < deadline {
        for descriptor in [input.as_fd(), errors.as_fd()] {
            match rustix::io::read(descriptor, &mut bytes) {
                Ok(0) => panic!("service pipe closed before owned observer termination"),
                Ok(size) => {
                    assert!(size <= MAX_OUTPUT - consumed, "observer output bound");
                    consumed += size;
                }
                Err(error)
                    if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::INTR => {}
                Err(error) => panic!("observer pipe read failed: {error}"),
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("owning test did not terminate the observer within its deadline");
}

#[test]
fn disk_log_child() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    if mode == "observer" {
        observe_service_pipes();
    }
    assert!(mode == "wait" || mode == "password");
    process::setsid().unwrap();
    assert_eq!(process::getsid(None).unwrap(), process::getpid());
    assert_eq!(process::getpgrp(), process::getpid());
    assert!(rustix::fs::open(
        "/dev/tty",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty()
    )
    .is_err());
    if mode == "wait" {
        assert_eq!(io::stdin().read(&mut [0; 1]).unwrap(), 0);
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
    command
        .env_clear()
        .env("RUST_LOG", FILTER)
        .arg("--config")
        .arg(std::env::var_os("GP_DISK_CONFIG").unwrap())
        .arg("--control-dir")
        .arg(std::env::var_os("GP_DISK_CONTROL").unwrap())
        .arg("run")
        .arg("--log-dir")
        .arg(std::env::var_os("GP_DISK_DIRECTORY").unwrap());
    if let Some(cap) = std::env::var_os("GP_DISK_CAP") {
        command.arg("--log-file-bytes").arg(cap);
    }
    if mode == "wait" {
        command.arg("--wait-auth");
    } else {
        command.args(["--username", "synthetic-user", "--password-stdin"]);
    }
    let error = command.exec();
    panic!("owned disk-log CLI exec failed: {error}");
}

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
        Self::from_child(child)
    }
    fn from_child(child: Child) -> Self {
        let process = Self {
            child,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        for descriptor in [
            process.child.stdout.as_ref().map(AsFd::as_fd),
            process.child.stderr.as_ref().map(AsFd::as_fd),
        ]
        .into_iter()
        .flatten()
        {
            fcntl_setfl(
                descriptor,
                fcntl_getfl(descriptor).unwrap() | OFlags::NONBLOCK,
            )
            .unwrap();
        }
        process
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
        // An observer may own the pipe read ends. Absence means transferred,
        // not EOF or proof that the service never wrote to that stream.
        if let Some(source) = self.child.stdout.as_mut() {
            read(source, &mut self.stdout);
        }
        if let Some(source) = self.child.stderr.as_mut() {
            read(source, &mut self.stderr);
        }
    }
    fn alive(&mut self) -> bool {
        self.drain();
        self.child.try_wait().unwrap().is_none()
    }
    async fn observer_for(daemon: &mut Self, directory: &Path) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .env(MODE, "observer")
            .args([
                "--exact",
                "disk_log_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(directory)
            .stdin(Stdio::from(daemon.child.stdout.take().unwrap()))
            .stderr(Stdio::from(daemon.child.stderr.take().unwrap()))
            .stdout(Stdio::piped());
        let mut observer = Self::from_child(command.spawn().unwrap());
        // Command retains custom Stdio after spawn. Close those parent-side
        // copies now so the observer has the only remaining pipe read ends.
        drop(command);
        assert!(daemon.child.stdout.is_none() && daemon.child.stderr.is_none());
        timeout(STEP, async {
            loop {
                assert!(observer.alive(), "owned observer exited before readiness");
                if observer
                    .stdout
                    .windows(OBSERVER_READY.len())
                    .any(|bytes| bytes == OBSERVER_READY)
                {
                    return;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("owned observer readiness deadline");
        observer
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
        let directory = PathBuf::from(format!("/tmp/gp-disk-cli-{:016x}", rand::random::<u64>()));
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
        fs::write(directory.join("config.toml"),format!(
            "gateway = '{}'\nhttp_listen = '{}'\nsocks_listen = '{}'\nca_file = {ca}\nnetworks = ['10.77.0.0/24']\ndomains = ['synthetic-corp.invalid']\nmax_connections = 8\nconnect_timeout_secs = 3\nidle_timeout_secs = 15\n",
            gateway.origin,addresses.0,addresses.1)).unwrap();
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
    fn logs(&self) -> PathBuf {
        self.directory.join("logs")
    }
    fn run(&mut self, logs: &Path, cap: Option<u64>, password: bool) -> Process {
        self.reservations.take();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .args([
                "--exact",
                "disk_log_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MODE, if password { "password" } else { "wait" })
            .env("GP_DISK_CONFIG", self.directory.join("config.toml"))
            .env("GP_DISK_CONTROL", self.endpoint())
            .env("GP_DISK_DIRECTORY", logs)
            .current_dir(self.directory.join("cwd"));
        if let Some(cap) = cap {
            command.env("GP_DISK_CAP", cap.to_string());
        }
        command.stdin(if password {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        Process::spawn(command)
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
        command
            .env_clear()
            .arg("--config")
            .arg(self.directory.join("config.toml"))
            .arg("--control-dir")
            .arg(self.endpoint())
            .current_dir(self.directory.join("cwd"))
            .stdin(Stdio::null());
        command
    }
    async fn ready(&self, child: &mut Process, available: bool) {
        timeout(STEP, async {
            loop {
                assert!(child.alive(), "owned service exited before readiness");
                if let Ok(snapshot) = status::query(self.http).await {
                    if snapshot.available == available {
                        assert_eq!(snapshot.log_write_errors, 0);
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
    async fn stop(&self, daemon: &mut Process, known: u64) {
        let identity = control::inspect(&self.endpoint()).await.unwrap();
        let hex: String = identity
            .instance
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut command = self.command();
        command.args(["stop", "--instance", &hex]);
        let mut stop = Process::spawn(command);
        let stop_status = stop.finish().await;
        // The service stop receipt does not include the logger lifecycle. A
        // restart may acquire the log lock only after the old daemon exits.
        let daemon_status = daemon.finish().await;
        assert_eq!(stop_status.code(), Some(0));
        assert_eq!(daemon_status.code(), Some(0));
        stop.report(known, known, 0);
        assert!(
            daemon.stderr.is_empty(),
            "captured disk logger output must not tee to stderr"
        );
        let _http = TcpListener::bind(self.http).unwrap();
        let _socks = TcpListener::bind(self.socks).unwrap();
        let replacement = control_local::LocalListener::bind(&self.endpoint()).unwrap();
        assert_ne!(replacement.instance_id(), identity.instance);
        drop(replacement);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[derive(Debug)]
struct Store {
    generation: [u64; 4],
    inode: [u64; 4],
    bytes: u64,
    store_id: String,
}
impl Store {
    fn contains(directory: &Path, needle: &[u8]) -> bool {
        assert!(!needle.is_empty());
        (0..4).any(|slot| {
            let mut content = Vec::new();
            fs::File::open(directory.join(format!("log-{slot}.txt")))
                .unwrap()
                .take(CAP + 1)
                .read_to_end(&mut content)
                .unwrap();
            assert!(content.len() as u64 <= CAP);
            content.windows(needle.len()).any(|bytes| bytes == needle)
        })
    }
    fn read(directory: &Path) -> Option<Self> {
        let mut names: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "lock",
                "log-0.txt",
                "log-1.txt",
                "log-2.txt",
                "log-3.txt",
                "owner"
            ]
        );
        let mut metadata = 0;
        for name in ["owner", "lock"] {
            let meta = fs::symlink_metadata(directory.join(name)).unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            metadata += meta.len();
        }
        assert!(metadata <= 8192);
        let mut generation = [0; 4];
        let mut inode = [0; 4];
        let mut bytes = 0;
        let mut identity = None;
        for slot in 0..4 {
            let path = directory.join(format!("log-{slot}.txt"));
            let meta = fs::symlink_metadata(&path).unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            assert!(meta.len() <= CAP);
            bytes += meta.len();
            inode[slot] = meta.ino();
            let content = fs::read(path).unwrap();
            assert!(content.len() as u64 <= CAP);
            assert!(!content
                .windows(b"synthetic-cli-password-29483".len())
                .any(|p| p == b"synthetic-cli-password-29483"));
            assert!(!content
                .windows(b"synthetic-wait-auth-cookie".len())
                .any(|p| p == b"synthetic-wait-auth-cookie"));
            // Rotation truncates and rewrites one fixed inode. A snapshot may
            // catch that bounded in-progress header; retry, never count it.
            let end = content.iter().position(|byte| *byte == b'\n')?;
            let header = std::str::from_utf8(&content[..end]).unwrap();
            let fields: Vec<_> = header.split(' ').collect();
            assert_eq!(fields.len(), 4);
            assert_eq!(fields[0], "gp-proxy-log-v1");
            assert_eq!(fields[1].len(), 32);
            assert!(fields[1]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            assert_eq!(fields[2], slot.to_string());
            assert_eq!(fields[3].len(), 20);
            assert!(fields[3].bytes().all(|b| b.is_ascii_digit()));
            generation[slot] = fields[3].parse().unwrap();
            assert_eq!(generation[slot] % 4, slot as u64);
            if let Some(expected) = &identity {
                assert_eq!(expected, fields[1]);
            } else {
                identity = Some(fields[1].to_owned());
            }
        }
        assert!(bytes <= 4 * CAP);
        Some(Self {
            generation,
            inode,
            bytes,
            store_id: identity.unwrap(),
        })
    }
    async fn stable(directory: &Path) -> Self {
        timeout(STEP, async {
            loop {
                if let Some(store) = Self::read(directory) {
                    return store;
                }
                sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap()
    }
}

async fn bad_greeting(address: SocketAddr) {
    timeout(STEP, async {
        let mut socket = TcpStream::connect(address).await.unwrap();
        socket.write_all(&[4, 0]).await.unwrap();
        let result = socket.read(&mut [0; 1]).await;
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "malformed greeting unexpectedly received application bytes"
        );
    })
    .await
    .unwrap();
}
async fn flood(
    fixture: &Fixture,
    daemon: &mut Process,
    initial: &Store,
    advances: u64,
) -> (usize, Store) {
    let mut requests = 0;
    for _ in 0..256 {
        // Four concurrent local handshakes, sixteen groups per observation.
        for _ in 0..16 {
            tokio::join!(
                bad_greeting(fixture.socks),
                bad_greeting(fixture.socks),
                bad_greeting(fixture.socks),
                bad_greeting(fixture.socks)
            );
            requests += 4;
        }
        assert!(daemon.alive());
        let observed = Store::stable(&fixture.logs()).await;
        assert_eq!(observed.inode, initial.inode);
        assert_eq!(observed.store_id, initial.store_id);
        let state = status::query(fixture.http).await.unwrap();
        assert!(!state.available);
        assert_eq!(state.log_write_errors, 0);
        if (0..4).all(|i| observed.generation[i] >= initial.generation[i] + advances) {
            return (requests, observed);
        }
        sleep(Duration::from_millis(2)).await;
    }
    panic!("bounded real SOCKS log load did not reach the required observed generations");
}
async fn stream(fixture: &Fixture, socks: bool) -> TcpStream {
    timeout(STEP, async {
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
        assert_eq!(sent, received);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn actual_cli_keeps_disk_logging_after_pipe_observer_exits() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let logs = fixture.logs();
        let mut daemon = fixture.run(&logs, Some(CAP), false);
        fixture.ready(&mut daemon, false).await;
        let daemon_pid = daemon.child.id();
        let identity = control::inspect(&fixture.endpoint()).await.unwrap();
        let initial = Store::stable(&logs).await;
        assert!(!Store::contains(&logs, SOCKS_DIAGNOSTIC));
        assert!(!Store::contains(&logs, b"gateway logout confirmed"));

        let mut observer = Process::observer_for(&mut daemon, &fixture.directory).await;
        assert_ne!(observer.child.id(), daemon_pid);
        observer.child.kill().unwrap();
        assert_eq!(observer.finish().await.signal(), Some(9));
        assert!(observer.child.try_wait().unwrap().is_some());
        assert!(daemon.alive());
        assert_eq!(daemon.child.id(), daemon_pid);
        assert_eq!(
            control::inspect(&fixture.endpoint())
                .await
                .unwrap()
                .instance,
            identity.instance
        );
        let after_observer = Store::stable(&logs).await;
        // No SOCKS request has occurred yet. This diagnostic cannot have been
        // queued before the observer died; growth alone would not prove that.
        assert!(!Store::contains(&logs, SOCKS_DIAGNOSTIC));
        assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);

        fixture.authenticate().await;
        fixture.ready(&mut daemon, true).await;
        let (mut http, mut socks) = tokio::join!(stream(&fixture, false), stream(&fixture, true));
        tokio::join!(echo(&mut http, 61), echo(&mut socks, 113));
        drop((http, socks));
        bad_greeting(fixture.socks).await;
        timeout(STEP, async {
            while !Store::contains(&logs, SOCKS_DIAGNOSTIC) {
                assert!(daemon.alive());
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("post-observer diagnostic must reach the disk store");
        let after_business = Store::stable(&logs).await;
        assert!(after_business.bytes > after_observer.bytes);
        assert_eq!(after_business.inode, initial.inode);
        assert_eq!(after_business.store_id, initial.store_id);
        assert_eq!(
            status::query(fixture.http).await.unwrap().log_write_errors,
            0
        );
        assert!(daemon.alive());
        assert_eq!(daemon.child.id(), daemon_pid);
        assert_eq!(
            control::inspect(&fixture.endpoint())
                .await
                .unwrap()
                .instance,
            identity.instance
        );
        fixture.stop(&mut daemon, 1).await;
        gateway.idle().await;
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.state.active_workers.load(Ordering::SeqCst), 0);
        assert_eq!(gateway.state.active_tunnels.load(Ordering::SeqCst), 0);
        let final_store = Store::stable(&logs).await;
        assert_eq!(final_store.inode, initial.inode);
        assert_eq!(final_store.store_id, initial.store_id);
        assert!(Store::contains(&logs, b"gateway logout confirmed"));
        gateway.close().await;
        eprintln!(
            concat!(
                "DISK observer_exit signal=9 observer_reaped=true sole_pipe_readers_closed=true ",
                "service_parent_retained=true instance_unchanged=true echo_bytes=16384 ",
                "disk_bytes_after_observer={} disk_bytes_after_business={} final_bytes={} ",
                "new_diagnostic=true logout=1 stop_receipt=1/1/0 ports_control_released=true ",
                "children_reaped=true"
            ),
            after_observer.bytes, after_business.bytes, final_store.bytes
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn actual_headless_cli_rotates_two_rounds_then_authenticates_and_stops() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let logs = fixture.logs();
        let mut daemon = fixture.run(&logs, Some(CAP), false);
        fixture.ready(&mut daemon, false).await;
        let initial = Store::stable(&logs).await;
        let (requests, observed) = flood(&fixture, &mut daemon, &initial, 8).await;
        assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
        fixture.authenticate().await;
        fixture.ready(&mut daemon, true).await;
        let (mut http, mut socks) = tokio::join!(stream(&fixture, false), stream(&fixture, true));
        tokio::join!(echo(&mut http, 37), echo(&mut socks, 83));
        drop((http, socks));
        fixture.stop(&mut daemon, 1).await;
        gateway.idle().await;
        let counts = (
            gateway.state.logins.load(Ordering::SeqCst),
            gateway.state.logouts.load(Ordering::SeqCst),
        );
        let final_store = Store::stable(&logs).await;
        gateway.close().await;
        assert_eq!(counts, (1, 1));
        assert_eq!(final_store.inode, initial.inode);
        eprintln!(
            concat!(
                "DISK rotation requests={} initial={:?} observed={:?} bytes={} ",
                "final_bytes={} echo_bytes=16384 logout=1 no_tty=true children_reaped=true"
            ),
            requests, initial.generation, observed.generation, observed.bytes, final_store.bytes
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn restart_reuses_fixed_capacity_and_waits_without_credentials() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let logs = fixture.logs();
        let mut first = fixture.run(&logs, Some(CAP), false);
        fixture.ready(&mut first, false).await;
        let first_id = control::inspect(&fixture.endpoint())
            .await
            .unwrap()
            .instance;
        fixture.stop(&mut first, 0).await;
        let old = Store::stable(&logs).await;
        let mut second = fixture.run(&logs, None, false);
        fixture.ready(&mut second, false).await;
        let second_id = control::inspect(&fixture.endpoint())
            .await
            .unwrap()
            .instance;
        sleep(Duration::from_millis(200)).await;
        let restarted = Store::stable(&logs).await;
        let _ = flood(&fixture, &mut second, &restarted, 4).await;
        fixture.stop(&mut second, 0).await;
        let current = Store::stable(&logs).await;
        let calls = gateway.state.accepted.load(Ordering::SeqCst);
        gateway.close().await;
        assert_eq!(calls, 0);
        assert_ne!(first_id, second_id);
        assert_eq!(old.inode, current.inode);
        assert_eq!(old.store_id, current.store_id);
        assert!(current.generation.iter().max() > old.generation.iter().max());
        eprintln!(concat!(
            "DISK restart same_store=true ",
            "new_instance=true gateway_connections=0 reused_capacity=65536 children_reaped=true"
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn competing_directory_fails_before_reading_password_and_keeps_owner_usable() {
    timeout(CASE,async {
        let gateway=gateway::Gateway::start().await; let mut owner=Fixture::new(&gateway); let logs=owner.logs();
        let mut daemon=owner.run(&logs,Some(CAP),false); owner.ready(&mut daemon,false).await;
        let before=Store::stable(&logs).await; let mut other=Fixture::new(&gateway);
        // Its stdin pipe stays open and empty: a credential read would hang.
        let mut contender=other.run(&logs,Some(CAP),true); let result=contender.finish().await;
        let calls_before_auth=gateway.state.accepted.load(Ordering::SeqCst);
        assert_eq!(result.code(),Some(1)); assert_eq!(calls_before_auth,0);
        assert!(daemon.alive()); assert_eq!(Store::stable(&logs).await.inode,before.inode);
        owner.authenticate().await; owner.ready(&mut daemon,true).await;
        let (mut http,mut socks)=tokio::join!(stream(&owner,false),stream(&owner,true));
        tokio::join!(echo(&mut http,59),echo(&mut socks,97)); drop((http,socks));
        owner.stop(&mut daemon,1).await; gateway.close().await;
        eprintln!(concat!("DISK competition exit=1 ",
            "password_stdin_unread=true gateway_before_rejection=0 owner_echo_bytes=16384 children_reaped=true"));
    }).await.unwrap();
}

#[tokio::test]
async fn replaced_slot_and_unknown_directory_are_preserved_before_secret_read() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let logs = fixture.logs();
        let mut daemon = fixture.run(&logs, Some(CAP), false);
        fixture.ready(&mut daemon, false).await;
        fixture.stop(&mut daemon, 0).await;
        let slot = logs.join("log-2.txt");
        let original = fs::read(&slot).unwrap();
        let old_inode = fs::metadata(&slot).unwrap().ino();
        fs::rename(&slot, fixture.directory.join("original-slot")).unwrap();
        fs::write(&slot, &original).unwrap();
        fs::set_permissions(&slot, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(fs::metadata(&slot).unwrap().ino(), old_inode);
        let mut rejected = fixture.run(&logs, None, true);
        let result = rejected.finish().await;
        assert_eq!(result.code(), Some(1));
        assert_eq!(fs::read(&slot).unwrap(), original);
        let unknown = fixture.directory.join("unknown-logs");
        DirBuilder::new().mode(0o700).create(&unknown).unwrap();
        fs::write(
            unknown.join("keep"),
            b"synthetic sentinel must stay untouched",
        )
        .unwrap();
        let mut rejected = fixture.run(&unknown, Some(CAP), true);
        let result = rejected.finish().await;
        let names: Vec<_> = fs::read_dir(&unknown)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let calls = gateway.state.accepted.load(Ordering::SeqCst);
        gateway.close().await;
        assert_eq!(result.code(), Some(1));
        assert_eq!(names, ["keep"]);
        assert_eq!(
            fs::read(unknown.join("keep")).unwrap(),
            b"synthetic sentinel must stay untouched"
        );
        assert_eq!(calls, 0);
        eprintln!(concat!(
            "DISK corrupt_slot_preserved=true unknown_entry_preserved=true ",
            "password_stdin_unread=true gateway_connections=0 children_reaped=true"
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn runtime_directory_fault_latches_logging_but_not_business_or_stop() {
    timeout(CASE, async {
        let gateway = gateway::Gateway::start().await;
        let mut fixture = Fixture::new(&gateway);
        let logs = fixture.logs();
        let mut daemon = fixture.run(&logs, Some(CAP), false);
        fixture.ready(&mut daemon, false).await;
        fixture.authenticate().await;
        fixture.ready(&mut daemon, true).await;
        let (mut http, mut socks) = tokio::join!(stream(&fixture, false), stream(&fixture, true));
        tokio::join!(echo(&mut http, 43), echo(&mut socks, 71));
        let original = Store::stable(&logs).await;
        let unexpected = logs.join("unexpected-entry");
        fs::write(&unexpected, b"synthetic owned-directory fault").unwrap();
        bad_greeting(fixture.socks).await;
        let first_errors = timeout(STEP, async {
            loop {
                let snapshot = status::query(fixture.http).await.unwrap();
                assert!(snapshot.available);
                if snapshot.log_write_errors > 0 {
                    break snapshot.log_write_errors;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        fn contents(directory: &Path) -> [Vec<u8>; 4] {
            std::array::from_fn(|slot| {
                let mut bytes = Vec::new();
                fs::File::open(directory.join(format!("log-{slot}.txt")))
                    .unwrap()
                    .take(CAP + 1)
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert!(bytes.len() as u64 <= CAP);
                bytes
            })
        }
        let frozen = contents(&logs);
        assert_eq!(
            fs::read(&unexpected).unwrap(),
            b"synthetic owned-directory fault"
        );
        fs::remove_file(&unexpected).unwrap();
        for _ in 0..4 {
            tokio::join!(bad_greeting(fixture.socks), bad_greeting(fixture.socks));
        }
        let later_errors = timeout(STEP, async {
            loop {
                let snapshot = status::query(fixture.http).await.unwrap();
                assert!(snapshot.available);
                if snapshot.log_write_errors > first_errors {
                    break snapshot.log_write_errors;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            contents(&logs),
            frozen,
            "removing the fault must not restart the disabled writer"
        );
        tokio::join!(echo(&mut http, 109), echo(&mut socks, 127));
        drop((http, socks));
        fixture.stop(&mut daemon, 1).await;
        let final_store = Store::stable(&logs).await;
        let counts = (
            gateway.state.logins.load(Ordering::SeqCst),
            gateway.state.logouts.load(Ordering::SeqCst),
        );
        gateway.close().await;
        assert_eq!(counts, (1, 1));
        assert_eq!(final_store.inode, original.inode);
        assert_eq!(contents(&logs), frozen);
        eprintln!(
            concat!(
                "DISK runtime_fault first_errors={} later_errors={} writer_latched=true ",
                "stderr_fallback=false echo_bytes=32768 logout=1 children_reaped=true"
            ),
            first_errors, later_errors
        );
    })
    .await
    .unwrap();
}
