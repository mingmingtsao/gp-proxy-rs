//! Synthetic local fixtures only; no successful authentication is attempted.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        // The session-file cases start run and reserve its control socket.
        // macOS's per-user TMPDIR can exceed AF_UNIX pathname limits before
        // those cases reach the file validation they are intended to exercise.
        #[cfg(unix)]
        let base = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let base = std::env::temp_dir();
        let path = base.join(format!(
            "gp-proxy-secret-file-cli-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }
    fn invoke(&self, path: &Path, session: bool) -> Output {
        // run now reserves listeners before importing a session. Give concurrent
        // file-validation cases their own ports, never the user's defaults.
        let reserved = session.then(|| {
            (
                std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
                std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            )
        });
        let listeners = reserved.as_ref().map_or_else(String::new, |(http, socks)| {
            format!(
                "http_listen = '{}'\nsocks_listen = '{}'\n",
                http.local_addr().unwrap(),
                socks.local_addr().unwrap()
            )
        });
        let config = self.write(
            "proxy.toml",
            format!(
                "gateway = 'https://127.0.0.1:9'\ndomains = ['corp.example.test']\n{listeners}"
            )
            .as_bytes(),
        );
        let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
        command
            .env_clear()
            .current_dir(&self.0)
            .arg("--config")
            .arg(config);
        // Keep Windows' OS installation path for native socket-provider
        // initialization. Credentials and application settings stay cleared.
        #[cfg(windows)]
        command.env(
            "SystemRoot",
            std::env::var_os("SystemRoot").expect("Windows fixture requires SystemRoot"),
        );
        if session {
            command.args(["run", "--session-file"]).arg(path);
        } else {
            command.arg("--env-file").arg(path).arg("check");
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        drop(reserved);
        let mut running = Running(Some(command.spawn().unwrap()));
        let started = Instant::now();
        loop {
            if running.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return running.0.take().unwrap().wait_with_output().unwrap();
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "secret file read did not finish within 5 seconds"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Running(Option<Child>);
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(unix)]
const SESSION: &[u8] = br#"{"gateway":"https://127.0.0.1:8","user":"synthetic-user","authcookie":"synthetic-secret-351901","computer":"synthetic-host"}"#;
#[cfg(unix)]
const ENV: &[u8] = b"GP_GATEWAY=https://127.0.0.1:9\nGP_USER=synthetic-user\nGP_PASSWORD=synthetic-secret-351901\n";

#[cfg(unix)]
fn rejected_file(output: Output) {
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("private credential file"),
        "unexpected diagnostic: {stderr}"
    );
    assert!(!stderr.contains("351901"));
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn session_and_env_fifo_are_rejected_without_waiting_for_a_writer() {
    let fixture = Fixture::new();
    let fifo = fixture.0.join("synthetic.fifo");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    for session in [true, false] {
        rejected_file(fixture.invoke(&fifo, session));
    }
}

#[cfg(unix)]
#[test]
fn session_and_env_symlinks_are_rejected() {
    let fixture = Fixture::new();
    for (session, bytes) in [(true, SESSION), (false, ENV)] {
        let path = fixture.write("synthetic-source", bytes);
        let link = fixture.0.join("synthetic-link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        rejected_file(fixture.invoke(&link, session));
        fs::remove_file(link).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn session_and_env_hardlinks_are_rejected() {
    let fixture = Fixture::new();
    for (session, bytes) in [(true, SESSION), (false, ENV)] {
        let path = fixture.write("synthetic-source", bytes);
        let link = fixture.0.join("synthetic-link");
        fs::hard_link(&path, &link).unwrap();
        rejected_file(fixture.invoke(&link, session));
        fs::remove_file(link).unwrap();
    }
}

#[test]
fn malformed_session_json_fails_without_printing_its_contents() {
    let fixture = Fixture::new();
    let path = fixture.write(
        "synthetic-session",
        b"{\"authcookie\":\"synthetic-secret-351901\",\"bad\": }",
    );
    let output = fixture.invoke(&path, true);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("351901"));
    assert!(
        stderr.contains("invalid session JSON"),
        "unexpected synthetic-session diagnostic: {stderr}"
    );
}
