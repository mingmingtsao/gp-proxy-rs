#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]

//! Real CLI processes, synthetic same-user Unix peers, and an intentionally
//! open stdin pipe prove the password-read ordering. No gateway is contacted.
use gp_proxy::control_local::{LocalListener, LocalStream};
use serde_json::{json, Value};
use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    time::{sleep, timeout},
};

const GATEWAY: &str = "https://synthetic-vpn.invalid";
const PASSWORD: &str = "synthetic-password-never-sent-to-a-gateway";
const LIMIT: Duration = Duration::from_secs(5);
// Keep fork/exec from overlapping the test's exact namespace handoff. A child
// may transiently inherit a locked descriptor until exec applies CLOEXEC.
// This does not retry bind or serialize the asynchronous test conversations.
static SPAWN_REBIND: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        // Short enough for macOS sockaddr_un, with no inherited shared files.
        let path = Path::new("/tmp").join(format!("gpcli-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::write(
            path.join("config.toml"),
            format!("gateway = \"{GATEWAY}\"\ndomains = [\"synthetic-corp.invalid\"]\n"),
        )
        .unwrap();
        Self(path)
    }

    fn endpoint(&self) -> PathBuf {
        self.0.join("control")
    }

    fn spawn(&self, args: &[&str], explicit_control: bool) -> (Child, ChildStdin) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
        command
            .arg("--config")
            .arg(self.0.join("config.toml"))
            .env_remove("RUST_LOG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if explicit_control {
            command.arg("--control-dir").arg(self.endpoint());
        }
        command.args(args);
        let mut child = {
            let _guard = SPAWN_REBIND.lock().unwrap();
            command.spawn().unwrap()
        };
        // Child::wait may close its owned stdin; keep it outside the Child so
        // even that implementation detail cannot turn a blocked read into EOF.
        let stdin = child.stdin.take().unwrap();
        (child, stdin)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn finish(child: &mut Child) -> (ExitStatus, String, String) {
    let completed = timeout(LIMIT, async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let status = match completed {
        Ok(status) => status,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            panic!("CLI did not terminate while the synthetic stdin pipe remained open");
        }
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(8193)
        .read_to_end(&mut stdout)
        .await
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .take(8193)
        .read_to_end(&mut stderr)
        .await
        .unwrap();
    assert!(stdout.len() <= 8192 && stderr.len() <= 8192);
    let stdout = String::from_utf8(stdout).unwrap();
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(!stdout.contains(PASSWORD) && !stderr.contains(PASSWORD));
    (status, stdout, stderr)
}

fn hello(listener: &LocalListener, phase: &str) -> Value {
    json!({
        "version": gp_proxy::control::PROTOCOL_VERSION,
        "instance": listener.instance_id(),
        "challenge": ([7; 16]),
        "binding": {"mode": "direct", "gateway": GATEWAY},
        "phase": phase,
        "supports_stop": false,
                    "managed": null,
    })
}

async fn send(stream: &mut LocalStream, value: &Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    stream
        .write_u32(bytes.len().try_into().unwrap())
        .await
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
    stream.flush().await.unwrap();
}

async fn no_submission(stream: &mut LocalStream) {
    assert_eq!(
        timeout(LIMIT, stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

const STDIN_ARGS: &[&str] = &["reauth", "--username", "synthetic-user", "--password-stdin"];

#[tokio::test]
async fn missing_default_control_fails_without_reading_open_stdin_or_config() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.0.join("config.toml")).unwrap();
    let (mut child, _stdin_kept_open) = fixture.spawn(STDIN_ARGS, false);
    let (status, stdout, stderr) = finish(&mut child).await;
    assert!(!status.success());
    assert!(stdout.is_empty());
    assert!(stderr.contains("local control endpoint operation failed"));
    assert!(!stderr.contains("configuration file"));
}

#[tokio::test]
async fn missing_control_precedes_selected_environment_and_session_file_access() {
    let fixture = Fixture::new();
    for option in ["--env-file", "--session-file"] {
        // Intentionally absent synthetic files: if accessed first their fixed
        // secret-file error would replace the asserted endpoint error.
        let path = fixture.0.join("does-not-exist.synthetic");
        let args = ["reauth", option, path.to_str().unwrap()];
        let (mut child, _stdin_kept_open) = fixture.spawn(&args, true);
        let (status, stdout, stderr) = finish(&mut child).await;
        assert!(!status.success());
        assert!(stdout.is_empty());
        assert!(stderr.contains("local control endpoint operation failed"));
    }
}

#[tokio::test]
async fn rejected_hello_never_reads_password_or_submits_bytes() {
    for case in ["busy", "version", "instance", "unknown_field"] {
        let fixture = Fixture::new();
        let listener = LocalListener::bind(&fixture.endpoint()).unwrap();
        let mut message = hello(&listener, "waiting");
        match case {
            "busy" => message["phase"] = json!("active"),
            "version" => message["version"] = json!(gp_proxy::control::PROTOCOL_VERSION + 1),
            "instance" => message["instance"] = json!(([0; 16])),
            "unknown_field" => message["unrecognized"] = json!(true),
            _ => unreachable!(),
        }
        let (mut child, _stdin_kept_open) = fixture.spawn(STDIN_ARGS, true);
        let peer = async {
            let mut stream = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            send(&mut stream, &message).await;
            no_submission(&mut stream).await;
        };
        let ((), (status, _, stderr)) = tokio::join!(peer, finish(&mut child));
        assert!(!status.success(), "{case}");
        assert!(
            stderr.contains(if case == "busy" {
                "local service is busy"
            } else {
                "invalid local control message"
            }),
            "{case}"
        );
    }
}

#[tokio::test]
async fn configured_gateway_mismatch_fails_before_reading_password() {
    let fixture = Fixture::new();
    let listener = LocalListener::bind(&fixture.endpoint()).unwrap();
    let mut message = hello(&listener, "waiting");
    message["binding"]["gateway"] = json!("https://different-synthetic.invalid");
    let (mut child, _stdin_kept_open) = fixture.spawn(STDIN_ARGS, true);
    let peer = async {
        let mut stream = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        send(&mut stream, &message).await;
        no_submission(&mut stream).await;
    };
    let ((), (status, _, stderr)) = tokio::join!(peer, finish(&mut child));
    assert!(!status.success());
    assert!(stderr.contains("configured authentication binding differs"));
}

#[tokio::test]
async fn changed_service_after_prompt_rejects_without_sending_credentials() {
    for case in ["instance", "gateway", "busy"] {
        let fixture = Fixture::new();
        let mut listener = LocalListener::bind(&fixture.endpoint()).unwrap();
        let (mut child, mut stdin) = fixture.spawn(STDIN_ARGS, true);
        let peer = async {
            let mut first = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            send(&mut first, &hello(&listener, "waiting")).await;
            no_submission(&mut first).await;
            drop(first);
            if case == "instance" {
                let _guard = SPAWN_REBIND.lock().unwrap();
                drop(listener);
                listener = LocalListener::bind(&fixture.endpoint()).unwrap();
            }
            stdin
                .write_all(format!("{PASSWORD}\n").as_bytes())
                .await
                .unwrap();
            drop(stdin);
            let mut second = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
            let mut message = hello(&listener, if case == "busy" { "active" } else { "waiting" });
            if case == "gateway" {
                message["binding"]["gateway"] = json!("https://different-synthetic.invalid");
            }
            send(&mut second, &message).await;
            no_submission(&mut second).await;
        };
        let ((), (status, _, stderr)) = tokio::join!(peer, finish(&mut child));
        assert!(!status.success(), "{case}");
        assert!(
            stderr.contains(if case == "busy" {
                "local service is busy"
            } else {
                "local service changed"
            }),
            "{case}"
        );
    }
}

#[tokio::test]
async fn stable_service_submits_once_after_preflight_and_reports_acceptance() -> io::Result<()> {
    let fixture = Fixture::new();
    let listener = LocalListener::bind(&fixture.endpoint()).unwrap();
    let (mut child, mut stdin) = fixture.spawn(STDIN_ARGS, true);
    let peer = async {
        let mut first = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        send(&mut first, &hello(&listener, "waiting")).await;
        no_submission(&mut first).await;
        drop(first);
        stdin
            .write_all(format!("{PASSWORD}\n").as_bytes())
            .await
            .unwrap();
        drop(stdin);
        let mut second = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
        let mut message = hello(&listener, "waiting");
        message["challenge"] = json!(([9; 16]));
        send(&mut second, &message).await;
        let submitted = timeout(LIMIT, async {
            let length = second.read_u32().await.unwrap() as usize;
            assert!((1..=65536).contains(&length));
            let mut bytes = vec![0; length];
            second.read_exact(&mut bytes).await.unwrap();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(submitted["instance"], message["instance"]);
        assert_eq!(submitted["challenge"], message["challenge"]);
        assert_eq!(submitted["authentication"]["user"], "synthetic-user");
        assert_eq!(submitted["authentication"]["password"], PASSWORD);
        send(&mut second, &json!({"result": "accepted"})).await;
        no_submission(&mut second).await;
    };
    let ((), (status, stdout, stderr)) = tokio::join!(peer, finish(&mut child));
    assert!(status.success());
    assert!(stdout.contains("Authentication accepted"));
    assert!(stderr.contains("Authentication mode: direct gateway"));
    Ok(())
}

#[path = "support/portal_control_cli.rs"]
mod portal_tests;
