//! Real CLI, synthetic credentials and owned loopback listeners only.
use std::{
    fs,
    io::{self, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

// The CLI accepts addresses, not inherited listeners. Releasing a reservation
// before child startup is therefore unavoidable in these tests. Keep this
// binary's three port-lifecycle scenarios separate: a sibling's listener or
// outgoing gateway connection must not claim a temporarily released address.
// The guard lasts through child wait, strict rebind, and fixture cleanup.
static PORT_LIFECYCLE: Mutex<()> = Mutex::new(());

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        // The owned IPC socket must fit the platform's AF_UNIX path ceiling;
        // long macOS TMPDIR paths otherwise mask the login-binding scenario.
        #[cfg(unix)]
        let base = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let base = std::env::temp_dir();
        let path = base.join(format!("gp-startup-binding-{:016x}", rand::random::<u64>()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn spawn(
        &self,
        gateway: SocketAddr,
        http: SocketAddr,
        socks: SocketAddr,
        env: bool,
    ) -> Running {
        fs::write(self.0.join("proxy.toml"), format!(
            "gateway = 'https://{gateway}'\nhttp_listen = '{http}'\nsocks_listen = '{socks}'\ndomains = ['corp.example.test']\n"
        )).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
        command
            .env_clear()
            .current_dir(&self.0)
            .args(["--config", "proxy.toml"]);
        if env {
            let credentials = self.0.join("synthetic-credentials");
            fs::write(&credentials, format!("GP_USER=synthetic-user\nGP_PASSWORD=synthetic-password-62917\nGP_GATEWAY=https://{gateway}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&credentials, fs::Permissions::from_mode(0o600)).unwrap();
            }
            command.arg("--env-file").arg(credentials).arg("run");
        } else {
            command.args(["run", "--username", "synthetic-user", "--password-stdin"]);
        }
        Running(Some(
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Running(Option<Child>);
impl Running {
    fn finish(&mut self, gateway: &TcpListener) -> (Option<Output>, usize) {
        let started = Instant::now();
        let mut connections = 0;
        loop {
            // Immediately close any unauthorized startup attempt. The fake
            // endpoint neither accepts TLS nor asks for any password.
            while let Ok((stream, _)) = gateway.accept() {
                connections += 1;
                drop(stream);
            }
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return (
                    Some(self.0.take().unwrap().wait_with_output().unwrap()),
                    connections,
                );
            }
            if started.elapsed() >= Duration::from_secs(3) {
                return (None, connections);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}

fn occupied_case(env: bool) {
    let _port_lifecycle = PORT_LIFECYCLE.lock().unwrap();
    for occupy_http in [true, false] {
        let fixture = Fixture::new();
        let gateway = listener();
        gateway.set_nonblocking(true).unwrap();
        let http = listener();
        let socks = listener();
        let http_address = http.local_addr().unwrap();
        let socks_address = socks.local_addr().unwrap();
        let (occupied, unused_reservation) = if occupy_http {
            // HTTP fails first; the child never needs the SOCKS address.
            (http, Some(socks))
        } else {
            drop(http);
            (socks, None)
        };
        let mut running = fixture.spawn(
            gateway.local_addr().unwrap(),
            http_address,
            socks_address,
            env,
        );
        // In stdin mode deliberately leave the pipe open without a password:
        // an unusable listener must fail before prompting or blocking on input.
        let (output, connections) = running.finish(&gateway);
        let output = output.expect("occupied port waited for credentials instead of failing");
        assert_eq!(
            connections, 0,
            "occupied port triggered a gateway connection"
        );
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("AddrInUse"),
            "wrong startup failure: {stderr}"
        );
        assert!(!stderr.contains("62917"));
        drop((occupied, unused_reservation));
        // SOCKS bind failure must release the already-bound HTTP listener too.
        let _http = TcpListener::bind(http_address).unwrap();
        let _socks = TcpListener::bind(socks_address).unwrap();
    }
}

#[test]
fn occupied_listener_fails_before_reading_a_password() {
    occupied_case(false);
}

#[test]
fn occupied_listener_never_starts_gateway_authentication() {
    occupied_case(true);
}

#[test]
fn both_listeners_remain_reserved_while_login_is_pending() {
    let _port_lifecycle = PORT_LIFECYCLE.lock().unwrap();
    let fixture = Fixture::new();
    let gateway = listener();
    gateway.set_nonblocking(true).unwrap();
    let http = listener();
    let socks = listener();
    let http_address = http.local_addr().unwrap();
    let socks_address = socks.local_addr().unwrap();
    drop((http, socks));
    let mut running = fixture.spawn(
        gateway.local_addr().unwrap(),
        http_address,
        socks_address,
        false,
    );
    let mut input = running.0.as_mut().unwrap().stdin.take().unwrap();
    input.write_all(b"synthetic-password-62917\n").unwrap();
    drop(input);
    let started = Instant::now();
    let _transport: TcpStream = loop {
        match gateway.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("fake gateway accept failed: {error}"),
        }
        assert!(running.0.as_mut().unwrap().try_wait().unwrap().is_none());
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "login did not reach owned gateway"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    for address in [http_address, socks_address] {
        let error =
            TcpListener::bind(address).expect_err("port was released during authentication");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }
    drop(running); // Bounded kill/wait of our deliberately stalled test process.
    let _http = TcpListener::bind(http_address).unwrap();
    let _socks = TcpListener::bind(socks_address).unwrap();
}
