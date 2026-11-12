#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
//! Own-session CLI processes, null stdin, synthetic TLS and raw-IP memory echo.
//! No service manager, user terminal, real credentials or external gateway.
#[path = "support/wait_auth_gateway.rs"]
mod gateway;

use gp_proxy::{control_local, status};
use rustix::{
    fs::{fcntl_getfl, fcntl_setfl, Mode, OFlags},
    process::{self, Pid, Signal},
};
use std::{
    fs::{self, DirBuilder},
    io::{self, PipeReader, PipeWriter, Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::{fs::DirBuilderExt, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

const STEP: Duration = Duration::from_secs(8);
const PASSWORD: &[u8] = b"synthetic-cli-password-29483\n";
const MAX_OUTPUT: usize = 2 * 1024 * 1024;
const CHILD_MODE: &str = "GP_PROXY_HEADLESS_CHILD";
const BINARY: &str = "GP_PROXY_HEADLESS_BINARY";

// The exact-test child executes only with the parent's explicit synthetic env.
// setsid detaches this owned child, never the test runner or user's terminal.
#[test]
fn headless_child() {
    if std::env::var(CHILD_MODE).as_deref() != Ok("run") {
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
    let binary = std::env::var_os(BINARY).unwrap();
    let config = std::env::var_os("GP_PROXY_HEADLESS_CONFIG").unwrap();
    let control = std::env::var_os("GP_PROXY_HEADLESS_CONTROL").unwrap();
    let error = Command::new(binary)
        .env_clear()
        .arg("--config")
        .arg(config)
        .arg("--control-dir")
        .arg(control)
        .args(["run", "--wait-auth"])
        .exec();
    panic!("owned headless exec failed: {error}");
}

fn binary() -> PathBuf {
    std::env::var_os(BINARY)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_gp-proxy")))
}

struct Fixture {
    directory: PathBuf,
    http: SocketAddr,
    socks: SocketAddr,
    reserved: Option<[TcpListener; 2]>,
}
impl Fixture {
    fn new(gateway: &gateway::Gateway) -> Self {
        let directory = PathBuf::from(format!("/tmp/gp-headless-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        fs::create_dir(directory.join("unrelated-cwd")).unwrap();
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
    fn run(&mut self) -> Running {
        self.run_with_backpressure(false).0
    }
    fn run_with_backpressure(&mut self, fill_stderr: bool) -> (Running, usize) {
        self.reserved.take();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "headless_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(CHILD_MODE, "run")
            .env(BINARY, binary())
            .env(
                "GP_PROXY_HEADLESS_CONFIG",
                self.directory.join("config.toml"),
            )
            .env("GP_PROXY_HEADLESS_CONTROL", self.endpoint())
            .current_dir(self.directory.join("unrelated-cwd"))
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        Running::spawn_with_backpressure(command, fill_stderr)
    }
    async fn authenticate(&self) {
        let mut command = Command::new(binary());
        command
            .env_clear()
            .current_dir(self.directory.join("unrelated-cwd"))
            .arg("--config")
            .arg(self.directory.join("config.toml"))
            .arg("--control-dir")
            .arg(self.endpoint())
            .args(["reauth", "--username", "synthetic-user", "--password-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null());
        let mut operation = Running::spawn(command);
        operation
            .child
            .as_mut()
            .unwrap()
            .stdin
            .take()
            .unwrap()
            .write_all(PASSWORD)
            .unwrap();
        assert!(operation.finish(true).await.success());
        operation.assert_redacted();
    }
    fn assert_released(&self) {
        let _http = TcpListener::bind(self.http).unwrap();
        let _socks = TcpListener::bind(self.socks).unwrap();
        let listener = control_local::LocalListener::bind(&self.endpoint()).unwrap();
        drop(listener);
        let mut entries: Vec<_> = fs::read_dir(self.endpoint())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
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

struct Running {
    child: Option<Child>,
    stderr: PipeReader,
    filler: PipeWriter,
    captured: Vec<u8>,
}
impl Running {
    fn spawn(command: Command) -> Self {
        Self::spawn_with_backpressure(command, false).0
    }
    fn spawn_with_backpressure(mut command: Command, fill_stderr: bool) -> (Self, usize) {
        let (stderr, filler) = io::pipe().unwrap();
        fcntl_setfl(&stderr, fcntl_getfl(&stderr).unwrap() | OFlags::NONBLOCK).unwrap();
        let mut process = Self {
            child: None,
            stderr,
            filler,
            captured: Vec::new(),
        };
        let filled = if fill_stderr {
            process.fill_stderr()
        } else {
            0
        };
        command.stderr(Stdio::from(process.filler.try_clone().unwrap()));
        process.child = Some(command.spawn().unwrap());
        (process, filled)
    }
    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
    fn alive(&mut self) -> bool {
        self.child.as_mut().unwrap().try_wait().unwrap().is_none()
    }
    fn drain(&mut self) {
        let mut buffer = [0; 4096];
        loop {
            match self.stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => {
                    assert!(
                        size <= MAX_OUTPUT - self.captured.len(),
                        "owned stderr capture bound"
                    );
                    self.captured.extend_from_slice(&buffer[..size]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("owned stderr read failed: {error}"),
            }
        }
    }
    fn fill_stderr(&mut self) -> usize {
        self.drain();
        let flags = fcntl_getfl(&self.filler).unwrap();
        fcntl_setfl(&self.filler, flags | OFlags::NONBLOCK).unwrap();
        struct Restore<'a>(&'a PipeWriter, OFlags);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                fcntl_setfl(self.0, self.1).unwrap();
            }
        }
        let restore = Restore(&self.filler, flags);
        let mut filled = 0;
        // After bulk writes stop, fill remaining space byte-by-byte so even a
        // short logout log cannot fit. This is only the parent's owned pipe.
        for chunk in [&[b'~'; 4096][..], &[b'~'][..]] {
            loop {
                match (&self.filler).write(chunk) {
                    Ok(0) => panic!("owned stderr fill made no progress"),
                    Ok(size) => {
                        filled += size;
                        assert!(filled <= 1024 * 1024, "unexpected pipe capacity");
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => panic!("owned stderr fill failed: {error}"),
                }
            }
        }
        drop(restore); // Restore blocking mode before TERM on the old binary.
        assert!(filled > 0);
        // F_GETFL may expose additional kernel-managed bits after the first
        // pipe write (observed on macOS before the child has even spawned).
        // Only O_NONBLOCK was changed by this fixture; verify that exact bit.
        assert_eq!(
            fcntl_getfl(&self.filler)
                .unwrap()
                .contains(OFlags::NONBLOCK),
            flags.contains(OFlags::NONBLOCK)
        );
        filled
    }
    fn terminate(&mut self) {
        assert!(self.alive());
        process::kill_process(Pid::from_raw(self.id() as i32).unwrap(), Signal::TERM).unwrap();
    }
    async fn finish(&mut self, drain: bool) -> ExitStatus {
        self.exit_within(drain, STEP)
            .await
            .expect("owned CLI did not exit within deadline")
    }
    async fn exit_within(&mut self, drain: bool, deadline: Duration) -> Option<ExitStatus> {
        timeout(deadline, async {
            loop {
                if drain {
                    self.drain();
                }
                if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                    self.child.take().unwrap().wait().unwrap();
                    self.drain();
                    return status;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .ok()
    }
    fn assert_redacted(&self) {
        let text = String::from_utf8_lossy(&self.captured);
        assert!(!text.contains("synthetic-cli-password-29483"));
        assert!(!text.contains("synthetic-wait-auth-cookie"));
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

async fn ready(fixture: &Fixture, process: &mut Running, available: bool) {
    timeout(STEP, async {
        loop {
            process.drain();
            assert!(process.alive(), "headless process exited before readiness");
            if let Ok(state) = status::query(fixture.http).await {
                if state.available == available {
                    if !available {
                        assert_eq!(state.phase, status::Phase::Stopped);
                        assert_eq!(state.reason, status::Reason::AuthenticationRequired);
                        assert_eq!(state.retry_count, 0);
                    }
                    return;
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("headless readiness deadline");
}
async fn header(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16384);
        bytes.push(stream.read_u8().await.unwrap());
    }
    bytes
}
async fn pac(fixture: &Fixture) {
    timeout(STEP, async {
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
        stream.take(65537).read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.len() <= 65536);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 "));
        assert!(text.contains("FindProxyForURL") && text.contains("synthetic-corp.invalid"));
    })
    .await
    .unwrap();
}
async fn proxy(fixture: &Fixture, socks: bool, success: bool) -> TcpStream {
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
            assert_eq!(
                reply,
                [5, if success { 0 } else { 1 }, 0, 1, 0, 0, 0, 0, 0, 0]
            );
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
async fn echo(stream: &mut TcpStream, value: u8) {
    let sent = [value; 8192];
    let mut received = [0; 8192];
    timeout(STEP, async {
        stream.write_all(&sent).await.unwrap();
        stream.read_exact(&mut received).await.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(sent, received);
}
async fn closed(stream: &mut TcpStream) {
    let result = timeout(STEP, stream.read(&mut [0; 1])).await.unwrap();
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "old stream delivered unexpected bytes"
    );
}
async fn offline(fixture: &Fixture, process: &mut Running, gateway: &gateway::Gateway) {
    ready(fixture, process, false).await;
    pac(fixture).await;
    drop(tokio::join!(
        proxy(fixture, false, false),
        proxy(fixture, true, false)
    ));
    sleep(Duration::from_millis(250)).await;
    assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn null_stdin_no_controlling_terminal_waits_offline_and_exits_on_term() {
    let gateway = gateway::Gateway::start().await;
    let mut fixture = Fixture::new(&gateway);
    let mut process = fixture.run();
    let pid = process.id();
    offline(&fixture, &mut process, &gateway).await;
    process.terminate();
    assert!(process.finish(true).await.success());
    process.assert_redacted();
    assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
    fixture.assert_released();
    gateway.close().await;
    eprintln!("HEADLESS offline pid={pid} null_stdin=true own_session=true gateway_connections=0 child_reaped=true endpoints_released=true");
}

#[tokio::test]
async fn full_stderr_before_start_does_not_block_missing_configuration_exit() {
    let gateway = gateway::Gateway::start().await;
    let mut fixture = Fixture::new(&gateway);
    // This path belongs to the synthetic fixture; no other input is selected.
    fs::remove_file(fixture.directory.join("config.toml")).unwrap();
    let (mut process, filled) = fixture.run_with_backpressure(true);
    let pid = process.id();
    let started = Instant::now();
    let (status, needed_drain) =
        if let Some(status) = process.exit_within(false, Duration::from_secs(2)).await {
            (status, false)
        } else {
            (process.finish(true).await, true)
        };
    process.assert_redacted();
    let _http = TcpListener::bind(fixture.http).unwrap();
    let _socks = TcpListener::bind(fixture.socks).unwrap();
    assert!(!fixture.endpoint().exists());
    assert!(!fixture.directory.join("config.pac-history.json").exists());
    assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
    gateway.close().await;
    eprintln!("HEADLESS fatal pid={pid} pipe_fill_bytes={filled} exit={:?} elapsed_ms={} drain_before_exit={needed_drain} gateway_connections=0 child_reaped=true", status.code(), started.elapsed().as_millis());
    assert_eq!(status.code(), Some(1));
    assert!(
        !needed_drain,
        "fatal configuration error blocked on full stderr"
    );
}

// Retained opt-in characterization of the old synchronous logging defect.
// The final non-ignored regression below must pass without draining stderr.
#[tokio::test]
#[ignore = "pre-fix characterization; run only against the recorded old binary"]
async fn characterize_full_stderr_blocks_exit_after_logout_until_parent_drains() {
    authenticated_shutdown(true).await;
}

#[tokio::test]
async fn full_stderr_does_not_block_headless_logout_and_exit() {
    authenticated_shutdown(false).await;
}

async fn authenticated_shutdown(expect_old_stall: bool) {
    let gateway = gateway::Gateway::start().await;
    let mut fixture = Fixture::new(&gateway);
    let mut process = fixture.run();
    let pid = process.id();
    offline(&fixture, &mut process, &gateway).await;
    let instance = fs::read(fixture.endpoint().join("instance")).unwrap();
    fixture.authenticate().await;
    ready(&fixture, &mut process, true).await;
    assert_eq!(process.id(), pid);
    assert_eq!(
        fs::read(fixture.endpoint().join("instance")).unwrap(),
        instance
    );
    let (mut http, mut socks) =
        tokio::join!(proxy(&fixture, false, true), proxy(&fixture, true, true));
    tokio::join!(echo(&mut http, 0x52), echo(&mut socks, 0xa3));
    pac(&fixture).await;
    let filled = process.fill_stderr();
    let started = Instant::now();
    process.terminate();
    timeout(STEP, async {
        while gateway.state.logouts.load(Ordering::SeqCst) != 1 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("synthetic gateway did not observe logout despite stderr backpressure");
    tokio::join!(closed(&mut http), closed(&mut socks));
    gateway.idle().await;
    if expect_old_stall {
        sleep(Duration::from_secs(3)).await;
        assert!(
            process.alive(),
            "old binary did not reproduce synchronous stderr blockage"
        );
        eprintln!("HEADLESS defect pid={pid} pipe_fill_bytes={filled} logout=1 gateway_workers=0 still_alive_ms={} no_stderr_drain=true", started.elapsed().as_millis());
    }
    let (status, needed_drain) = if expect_old_stall {
        (process.finish(true).await, true)
    } else if let Some(status) = process.exit_within(false, Duration::from_secs(2)).await {
        (status, false)
    } else {
        // Preserve the regression failure, but unblock and join owned work
        // before asserting. A failed test must not leave the old daemon alive.
        (process.finish(true).await, true)
    };
    assert!(status.success());
    process.assert_redacted();
    assert_eq!(gateway.state.prelogins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.configs.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.opened.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.closed.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
    fixture.assert_released();
    gateway.close().await;
    eprintln!("HEADLESS completed pid={pid} pipe_fill_bytes={filled} authentication_submissions=1 echo_bytes=16384 logout=1 elapsed_ms={} drain_before_exit={needed_drain} child_reaped=true endpoints_released=true", started.elapsed().as_millis());
    assert_eq!(
        needed_drain, expect_old_stall,
        "logout completed but full stderr still prevented exit within two seconds"
    );
}
