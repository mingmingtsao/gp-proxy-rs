#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
//! Real run processes stop at a held-open password pipe. No login is allowed.
use gp_proxy::control_local::LocalListener;
use std::{
    fs::{self, DirBuilder},
    net::{SocketAddr, TcpListener},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Child, ChildStdin, Command, Output, Stdio},
    time::{Duration, Instant},
};

const LIMIT: Duration = Duration::from_secs(4);

struct Fixture {
    directory: PathBuf,
    gateway: TcpListener,
    http: SocketAddr,
    socks: SocketAddr,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            PathBuf::from("/tmp").join(format!("gp-rec-cli-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let gateway = TcpListener::bind("127.0.0.1:0").unwrap();
        gateway.set_nonblocking(true).unwrap();
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let http = http.local_addr().unwrap();
        let socks = socks.local_addr().unwrap();
        fs::write(directory.join("config.toml"), format!(
            "gateway = 'https://{}'\nhttp_listen = '{http}'\nsocks_listen = '{socks}'\ndomains = ['synthetic-corp.invalid']\n",
            gateway.local_addr().unwrap()
        )).unwrap();
        Self {
            directory,
            gateway,
            http,
            socks,
        }
    }

    fn endpoint(&self) -> PathBuf {
        self.directory.join("control")
    }

    fn spawn(&self) -> Running {
        let mut child = Command::new(env!("CARGO_BIN_EXE_gp-proxy"))
            .current_dir(&self.directory)
            .env_clear()
            .args([
                "--config",
                "config.toml",
                "--control-dir",
                "control",
                "run",
                "--username",
                "synthetic-user",
                "--password-stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        Running {
            child: Some(child),
            input,
        }
    }

    fn no_gateway(&self) {
        assert_eq!(
            self.gateway.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "pre-prompt control setup must not contact the synthetic gateway"
        );
    }

    fn proxy_ports_free(&self) {
        let _http = TcpListener::bind(self.http).unwrap();
        let _socks = TcpListener::bind(self.socks).unwrap();
    }

    async fn wait_reserved(&self, running: &mut Running, previous: Option<&[u8]>) -> Vec<u8> {
        let started = Instant::now();
        loop {
            assert!(
                running
                    .child
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "run exited before the password prompt"
            );
            self.no_gateway();
            if let Ok(instance) = fs::read(self.endpoint().join("instance")) {
                if instance.len() == 32
                    && instance.iter().all(u8::is_ascii_hexdigit)
                    && previous != Some(instance.as_slice())
                    && self.endpoint().join("control.sock").exists()
                {
                    assert!(TcpListener::bind(self.http).is_err());
                    assert!(TcpListener::bind(self.socks).is_err());
                    return instance;
                }
            }
            assert!(
                started.elapsed() < LIMIT,
                "control endpoint was not reserved while stdin remained open"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct Running {
    child: Option<Child>,
    input: Option<ChildStdin>,
}
impl Running {
    async fn finish(&mut self) -> Output {
        let started = Instant::now();
        loop {
            if self.child.as_mut().unwrap().try_wait().unwrap().is_some() {
                self.input.take();
                return self.child.take().unwrap().wait_with_output().unwrap();
            }
            assert!(
                started.elapsed() < LIMIT,
                "run consumed or waited for password input before detecting control conflict"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    fn kill(&mut self) {
        self.child.as_mut().unwrap().kill().unwrap();
        self.child.as_mut().unwrap().wait().unwrap();
        self.child.take();
        self.input.take();
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[tokio::test]
async fn unknown_control_directory_fails_before_password_or_gateway_contact() {
    let fixture = Fixture::new();
    DirBuilder::new()
        .mode(0o700)
        .create(fixture.endpoint())
        .unwrap();
    fs::write(fixture.endpoint().join("unrelated"), b"must remain intact").unwrap();
    let mut run = fixture.spawn();
    let output = run.finish().await;
    assert!(!output.status.success());
    assert_eq!(
        fs::read(fixture.endpoint().join("unrelated")).unwrap(),
        b"must remain intact"
    );
    assert_eq!(fs::read_dir(fixture.endpoint()).unwrap().count(), 1);
    fixture.no_gateway();
    fixture.proxy_ports_free();
}

#[tokio::test]
async fn occupied_control_lock_fails_before_password_or_gateway_contact() {
    let fixture = Fixture::new();
    let held = LocalListener::bind(&fixture.endpoint()).unwrap();
    let instance = fs::read(fixture.endpoint().join("instance")).unwrap();
    let mut run = fixture.spawn();
    let output = run.finish().await;
    assert!(!output.status.success());
    assert_eq!(
        fs::read(fixture.endpoint().join("instance")).unwrap(),
        instance
    );
    assert_eq!(held.instance_id().len(), 16);
    fixture.no_gateway();
    fixture.proxy_ports_free();
}

#[tokio::test]
async fn killing_a_password_prompt_allows_restart_without_manual_directory_removal() {
    let fixture = Fixture::new();
    let mut first = fixture.spawn();
    let before = fixture.wait_reserved(&mut first, None).await;
    let owner = fs::read(fixture.endpoint().join("owner")).unwrap();
    first.kill();
    fixture.proxy_ports_free();
    assert_eq!(
        fs::read(fixture.endpoint().join("instance")).unwrap(),
        before
    );
    let mut second = fixture.spawn();
    let after = fixture.wait_reserved(&mut second, Some(&before)).await;
    assert_ne!(
        after, before,
        "crash recovery must publish a fresh instance identity"
    );
    assert_eq!(fs::read(fixture.endpoint().join("owner")).unwrap(), owner);
    second.kill();
    let mut third = fixture.spawn();
    let third_instance = fixture.wait_reserved(&mut third, Some(&after)).await;
    assert_ne!(third_instance, after);
    third.kill();
    fixture.no_gateway();
    fixture.proxy_ports_free();
}

#[tokio::test]
async fn invalid_initial_input_releases_the_control_lock_for_immediate_retry() {
    let fixture = Fixture::new();
    for _ in 0..2 {
        let mut run = fixture.spawn();
        fixture.wait_reserved(&mut run, None).await;
        // EOF is deliberate only in this case: the empty password is rejected
        // locally after admission validation, without a single gateway request.
        run.input.take();
        let output = run.finish().await;
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("initial authentication could not start"));
        let mut entries: Vec<_> = fs::read_dir(fixture.endpoint())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["lock", "owner"]);
        fixture.no_gateway();
        fixture.proxy_ports_free();
    }
}
