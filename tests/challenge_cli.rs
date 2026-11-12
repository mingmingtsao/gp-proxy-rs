#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
//! Actual CLI/IPC/TTY/TLS/IP path; every credential and terminal is synthetic.
#[path = "support/wait_auth_gateway.rs"]
mod gateway;

use gp_proxy::{control, control_local, status};
use rustix::{
    fd::OwnedFd,
    fs::{self as rfs, Mode, OFlags},
    io::{self as rio, Errno, FdFlags},
    process,
    pty::{self, OpenptFlags},
    termios,
};
use std::{
    fs::{self, DirBuilder},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::{fs::DirBuilderExt, process::CommandExt},
    path::PathBuf,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

const STEP: Duration = Duration::from_secs(8);
const PASSWORD: &str = "synthetic-cli-password-29483";
const PASSWORD_PROMPT: &str = "GlobalProtect password: ";
const ANSWER_PROMPTS: [&str; 2] = [
    "GlobalProtect challenge 1: Enter answer 1 Answer: ",
    "GlobalProtect challenge 2: Enter answer 2 Answer: ",
];
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    directory: PathBuf,
    http: SocketAddr,
    socks: SocketAddr,
    ports: Option<[TcpListener; 2]>,
}
impl Fixture {
    fn new(gateway: &gateway::Gateway) -> Self {
        let directory = PathBuf::from(format!(
            "/tmp/gp-challenge-cli-{:016x}",
            rand::random::<u64>()
        ));
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
            ports: Some([http, socks]),
        }
    }
    fn endpoint(&self) -> PathBuf {
        self.directory.join("control")
    }
    fn spawn(&mut self, args: &[&str], tty: bool) -> OwnedProcess {
        if args[0] == "run" {
            self.ports.take();
        }
        let arguments: Vec<String> = ["--config", "config.toml", "--control-dir", "control"]
            .into_iter()
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect();
        OwnedProcess::spawn(self, arguments, tty)
    }
    fn released(&self) {
        let _http = TcpListener::bind(self.http).unwrap();
        let _socks = TcpListener::bind(self.socks).unwrap();
        let mut entries: Vec<_> = fs::read_dir(self.endpoint())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["lock", "owner"]);
        drop(control_local::LocalListener::bind(&self.endpoint()).unwrap());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Only explicitly spawned helper sessions can reach the actual /dev/tty API.
#[test]
fn cli_terminal_child() {
    if std::env::var("GP_CHALLENGE_OWNED_PTY").as_deref() != Ok("1") {
        return;
    }
    let session = process::setsid().unwrap();
    assert_eq!(session, process::getpid());
    let path = std::env::var("GP_CHALLENGE_SLAVE").unwrap();
    let dev: u64 = std::env::var("GP_CHALLENGE_DEV").unwrap().parse().unwrap();
    let ino: u64 = std::env::var("GP_CHALLENGE_INO").unwrap().parse().unwrap();
    let slave = rfs::open(
        path.as_str(),
        OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .unwrap();
    let stat = rfs::fstat(&slave).unwrap();
    #[allow(clippy::unnecessary_cast)]
    {
        assert_eq!((stat.st_dev as u64, stat.st_ino as u64), (dev, ino));
    }
    process::ioctl_tiocsctty(&slave).unwrap();
    termios::tcsetpgrp(&slave, process::getpgrp()).unwrap();
    assert_eq!(termios::tcgetsid(&slave).unwrap(), session);
    let arguments: Vec<String> =
        serde_json::from_str(&std::env::var("GP_CHALLENGE_ARGUMENTS").unwrap()).unwrap();
    assert!(arguments.len() <= 16 && arguments.iter().all(|argument| argument.len() <= 128));
    // Safe exec preserves this owned session and piped stdio. No unsafe pre_exec.
    let error = Command::new(env!("CARGO_BIN_EXE_gp-proxy"))
        .env_clear()
        .args(arguments)
        .exec();
    panic!("owned CLI exec failed: {error}");
}

struct OwnedProcess {
    child: Option<Child>,
    input: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: ChildStderr,
    master: Option<OwnedFd>,
    slave: Option<OwnedFd>,
    original: Option<String>,
    output: Vec<u8>,
    errors: Vec<u8>,
    terminal: Vec<u8>,
}
fn nonblocking(fd: &impl std::os::fd::AsFd) {
    rfs::fcntl_setfl(fd, rfs::fcntl_getfl(fd).unwrap() | OFlags::NONBLOCK).unwrap();
}
fn collect(reader: &mut impl Read, bytes: &mut Vec<u8>) {
    let mut chunk = [0; 2048];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return,
            Ok(size) => bytes.extend_from_slice(&chunk[..size]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => panic!("synthetic child output: {error}"),
        }
        assert!(bytes.len() <= 131_072, "owned child output exceeded bound");
    }
}
impl OwnedProcess {
    fn spawn(fixture: &Fixture, arguments: Vec<String>, tty: bool) -> Self {
        let mut master = None;
        let mut slave = None;
        let mut original = None;
        let mut command = if tty {
            let owner = pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            rio::fcntl_setfd(&owner, FdFlags::CLOEXEC).unwrap();
            nonblocking(&owner);
            pty::grantpt(&owner).unwrap();
            pty::unlockpt(&owner).unwrap();
            let path = pty::ptsname(&owner, Vec::new()).unwrap();
            let terminal = rfs::open(
                &*path,
                OFlags::RDWR | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let stat = rfs::fstat(&terminal).unwrap();
            original = Some(format!("{:?}", termios::tcgetattr(&terminal).unwrap()));
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .env_clear()
                .args([
                    "--exact",
                    "cli_terminal_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("GP_CHALLENGE_OWNED_PTY", "1")
                .env("GP_CHALLENGE_SLAVE", path.to_str().unwrap())
                .env(
                    "GP_CHALLENGE_ARGUMENTS",
                    serde_json::to_string(&arguments).unwrap(),
                );
            #[allow(clippy::unnecessary_cast)]
            {
                command
                    .env("GP_CHALLENGE_DEV", (stat.st_dev as u64).to_string())
                    .env("GP_CHALLENGE_INO", (stat.st_ino as u64).to_string());
            }
            master = Some(owner);
            slave = Some(terminal);
            command
        } else {
            let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
            command.env_clear().args(arguments);
            command
        };
        let mut child = command
            .current_dir(&fixture.directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        nonblocking(&stdout);
        nonblocking(&stderr);
        Self {
            child: Some(child),
            input,
            stdout,
            stderr,
            master,
            slave,
            original,
            output: Vec::new(),
            errors: Vec::new(),
            terminal: Vec::new(),
        }
    }
    fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
    fn pump(&mut self) {
        collect(&mut self.stdout, &mut self.output);
        collect(&mut self.stderr, &mut self.errors);
        if let Some(master) = &self.master {
            let mut chunk = [0; 1024];
            loop {
                match rio::read(master, &mut chunk) {
                    Ok(0) | Err(Errno::AGAIN | Errno::IO) => break,
                    Ok(size) => self.terminal.extend_from_slice(&chunk[..size]),
                    Err(Errno::INTR) => continue,
                    Err(error) => panic!("owned PTY output: {error}"),
                }
                assert!(self.terminal.len() <= 16_384);
            }
        }
    }
    fn alive(&mut self) -> bool {
        self.child.as_mut().unwrap().try_wait().unwrap().is_none()
    }
    async fn prompt(&mut self, expected: &str) {
        let until = Instant::now() + STEP;
        loop {
            self.pump();
            if self
                .terminal
                .windows(expected.len())
                .any(|window| window == expected.as_bytes())
            {
                return;
            }
            assert!(
                self.alive(),
                "CLI exited before synthetic prompt: {}",
                String::from_utf8_lossy(&self.errors)
            );
            assert!(Instant::now() < until, "synthetic terminal prompt deadline");
            sleep(Duration::from_millis(5)).await;
        }
    }
    async fn type_bytes(&mut self, mut bytes: &[u8]) {
        let until = Instant::now() + STEP;
        while !bytes.is_empty() {
            match rio::write(self.master.as_ref().unwrap(), bytes) {
                Ok(0) => panic!("owned PTY input closed"),
                Ok(size) => bytes = &bytes[size..],
                Err(Errno::AGAIN | Errno::INTR) => sleep(Duration::from_millis(2)).await,
                Err(error) => panic!("owned PTY input: {error}"),
            }
            assert!(Instant::now() < until);
        }
    }
    fn password_stdin(&mut self) {
        self.input
            .as_mut()
            .unwrap()
            .write_all(format!("{PASSWORD}\n").as_bytes())
            .unwrap();
        self.input.take();
    }
    fn restored(&self) {
        assert_eq!(
            format!(
                "{:?}",
                termios::tcgetattr(self.slave.as_ref().unwrap()).unwrap()
            ),
            *self.original.as_ref().unwrap()
        );
    }
    fn safe_output(&self) {
        for bytes in [&self.output, &self.errors, &self.terminal] {
            let text = String::from_utf8_lossy(bytes);
            for secret in [
                PASSWORD,
                "synthetic-cli-answer-1",
                "synthetic-cli-answer-2",
                "synthetic-cli-state-",
                "synthetic-wait-auth-cookie",
                "synthetic-partial-answer",
            ] {
                assert!(!text.contains(secret), "synthetic credential was printed");
            }
        }
    }
    async fn finish(&mut self) -> ExitStatus {
        let pid = self.id();
        let until = Instant::now() + STEP;
        loop {
            self.pump();
            if !self.alive() {
                break;
            }
            assert!(Instant::now() < until, "owned CLI completion deadline");
            sleep(Duration::from_millis(5)).await;
        }
        self.input.take();
        let status = self.child.take().unwrap().wait().unwrap();
        self.pump();
        self.safe_output();
        eprintln!(
            "challenge_cli pid={pid} joined=true exit={:?}",
            status.code()
        );
        status
    }
    async fn terminate(&mut self) -> ExitStatus {
        process::kill_process(
            process::Pid::from_raw(self.id() as i32).unwrap(),
            process::Signal::TERM,
        )
        .unwrap();
        self.finish().await
    }
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        self.master.take(); // Avoid session-leader output drain during abnormal exit.
        self.input.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn state(fixture: &Fixture, service: &mut OwnedProcess, ready: bool) {
    timeout(STEP, async {
        loop {
            service.pump();
            assert!(
                service.alive(),
                "service exited: {}",
                String::from_utf8_lossy(&service.errors)
            );
            if let Ok(snapshot) = status::query(fixture.http).await {
                if snapshot.available == ready {
                    return;
                }
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("synthetic service status deadline");
}
async fn echo_both(fixture: &Fixture) {
    async fn echo(fixture: &Fixture, socks: bool) {
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
            assert_eq!(&reply[..2], &[5, 0]);
        } else {
            stream
                .write_all(b"CONNECT 10.77.0.1:443 HTTP/1.1\r\nHost: 10.77.0.1:443\r\n\r\n")
                .await
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 4096);
                header.push(stream.read_u8().await.unwrap());
            }
            assert!(header.starts_with(b"HTTP/1.1 200 "));
        }
        let payload = [if socks { 0x69 } else { 0x37 }; 2048];
        let mut received = [0; 2048];
        stream.write_all(&payload).await.unwrap();
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(payload, received);
        stream.shutdown().await.unwrap();
    }
    timeout(STEP, async {
        tokio::join!(echo(fixture, false), echo(fixture, true));
    })
    .await
    .unwrap();
}
async fn answers(process: &mut OwnedProcess) {
    for (index, prompt) in ANSWER_PROMPTS.iter().enumerate() {
        process.prompt(prompt).await;
        process
            .type_bytes(format!("synthetic-cli-answer-{}\n", index + 1).as_bytes())
            .await;
    }
}
fn authenticated(gateway: &gateway::Gateway) {
    assert_eq!(gateway.state.prelogins.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 3);
    assert_eq!(gateway.state.challenge_requests.lock().unwrap().len(), 3);
    assert_eq!(gateway.state.configs.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.hips.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.opened.load(Ordering::SeqCst), 1);
}
async fn stopped(fixture: &Fixture, gateway: &gateway::Gateway) {
    gateway.idle().await;
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
    assert_eq!(gateway.state.closed.load(Ordering::SeqCst), 1);
    fixture.released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hidden_run_password_then_two_challenges_echoes_and_logs_out() {
    let _serial = SERIAL.lock().await;
    let gateway = gateway::Gateway::start().await;
    gateway.state.challenge_rounds.store(2, Ordering::SeqCst);
    let mut fixture = Fixture::new(&gateway);
    let mut service = fixture.spawn(&["run", "--username", "synthetic-user"], true);
    service.prompt(PASSWORD_PROMPT).await;
    assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
    service.type_bytes(format!("{PASSWORD}\n").as_bytes()).await;
    answers(&mut service).await;
    state(&fixture, &mut service, true).await;
    service.restored(); // Still-live session; no impossible post-revocation ioctl.
    assert_eq!(
        service.terminal,
        format!(
            "{PASSWORD_PROMPT}{}{}",
            ANSWER_PROMPTS[0], ANSWER_PROMPTS[1]
        )
        .as_bytes()
    );
    authenticated(&gateway);
    echo_both(&fixture).await;
    assert!(service.terminate().await.success());
    stopped(&fixture, &gateway).await;
    gateway.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_reauth_stdin_plus_private_tty_crosses_ipc_and_preserves_daemon() {
    let _serial = SERIAL.lock().await;
    let gateway = gateway::Gateway::start().await;
    gateway.state.challenge_rounds.store(2, Ordering::SeqCst);
    let mut fixture = Fixture::new(&gateway);
    let mut service = fixture.spawn(&["run", "--wait-auth"], false);
    state(&fixture, &mut service, false).await;
    let pid = service.id();
    let instance = fs::read(fixture.endpoint().join("instance")).unwrap();
    let mut client = fixture.spawn(
        &[
            "reauth",
            "--username",
            "synthetic-user",
            "--password-stdin",
            "--interactive",
        ],
        true,
    );
    client.password_stdin();
    answers(&mut client).await;
    assert!(client.finish().await.success());
    assert_eq!(
        client.terminal,
        format!("{}{}", ANSWER_PROMPTS[0], ANSWER_PROMPTS[1]).as_bytes()
    );
    state(&fixture, &mut service, true).await;
    assert_eq!(service.id(), pid);
    assert_eq!(
        fs::read(fixture.endpoint().join("instance")).unwrap(),
        instance
    );
    authenticated(&gateway);
    echo_both(&fixture).await;
    assert!(service.terminate().await.success());
    stopped(&fixture, &gateway).await;
    gateway.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_reauth_typed_cancel_and_eof_leave_daemon_waiting_without_replay() {
    let _serial = SERIAL.lock().await;
    for cancellation in [3, 4] {
        let gateway = gateway::Gateway::start().await;
        gateway.state.challenge_rounds.store(2, Ordering::SeqCst);
        let mut fixture = Fixture::new(&gateway);
        let mut service = fixture.spawn(&["run", "--wait-auth"], false);
        state(&fixture, &mut service, false).await;
        let pid = service.id();
        let instance = fs::read(fixture.endpoint().join("instance")).unwrap();
        let mut client = fixture.spawn(
            &[
                "reauth",
                "--username",
                "synthetic-user",
                "--password-stdin",
                "--interactive",
            ],
            true,
        );
        client.password_stdin();
        client.prompt(ANSWER_PROMPTS[0]).await;
        client.type_bytes(b"synthetic-partial-answer").await;
        client.type_bytes(&[cancellation]).await;
        assert_eq!(client.finish().await.success(), cancellation == 3);
        timeout(STEP, async {
            while control::preflight(&fixture.endpoint()).await.is_err() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("cancelled authentication did not release admission");
        state(&fixture, &mut service, false).await;
        sleep(Duration::from_millis(1200)).await;
        assert_eq!(service.id(), pid);
        assert_eq!(
            fs::read(fixture.endpoint().join("instance")).unwrap(),
            instance
        );
        assert_eq!(gateway.state.prelogins.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.state.configs.load(Ordering::SeqCst), 0);
        assert_eq!(gateway.state.opened.load(Ordering::SeqCst), 0);
        assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 0);
        assert!(service.terminate().await.success());
        fixture.released();
        gateway.close().await;
    }
}
