#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]

//! Fresh test processes open their own lock descriptions; no inherited/duplicated
//! file handle substitutes for a second owner. Only synthetic Unix IPC is used.
use gp_proxy::{
    control::{self, Authentication},
    control_local::LocalListener,
};
use std::{
    fs::{self, DirBuilder},
    io::{Read, Write},
    os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const CHILD_FLAG: &str = "GP_PROXY_SYNTHETIC_RECOVERY_CHILD";
const CHILD_VALUE: &str = "private-test-fixture-v2";
const LIMIT: Duration = Duration::from_secs(5);
const GATEWAY: &str = "https://synthetic-control-recovery.invalid";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn publish(path: &Path, bytes: &[u8]) {
    let temporary = path.with_extension("publishing");
    fs::write(&temporary, bytes).unwrap();
    fs::rename(temporary, path).unwrap();
}

// Default cargo test invocation does nothing here. Only a parent test supplies
// the explicit sentinel, exact test filter, and its own synthetic paths.
#[test]
fn recovery_child() {
    if std::env::var(CHILD_FLAG).ok().as_deref() != Some(CHILD_VALUE) {
        return;
    }
    let endpoint = PathBuf::from(std::env::var_os("GP_RECOVERY_ENDPOINT").unwrap());
    let ready = PathBuf::from(std::env::var_os("GP_RECOVERY_READY").unwrap());
    let mode = std::env::var("GP_RECOVERY_MODE").unwrap();
    assert!(matches!(mode.as_str(), "hold" | "probe" | "hello" | "race"));
    let runtime = runtime();
    let _entered = runtime.enter();
    if mode == "race" {
        publish(&ready, b"armed");
        let mut command = [0];
        std::io::stdin().read_exact(&mut command).unwrap();
        assert_eq!(command, [b'g']);
    }
    let listener = match LocalListener::bind(&endpoint) {
        Ok(listener) => listener,
        Err(error) => {
            publish(&ready, format!("error:{:?}", error.kind()).as_bytes());
            return;
        }
    };
    let id: String = listener
        .instance_id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    publish(&ready, format!("ready:{id}").as_bytes());
    if mode == "probe" {
        return;
    }
    if mode == "hello" {
        runtime.block_on(async {
            tokio::time::timeout(LIMIT, async {
                let mut stream = listener.accept().await.unwrap();
                let frame = serde_json::to_vec(&serde_json::json!({
                    "version": gp_proxy::control::PROTOCOL_VERSION,
                    "instance": listener.instance_id(),
                    "challenge": ([9; 16]),
                    "binding": {"mode": "direct", "gateway": GATEWAY},
                    "phase": "waiting",
                    "supports_stop": false,
                    "managed": null,
                }))
                .unwrap();
                stream
                    .write_u32(frame.len().try_into().unwrap())
                    .await
                    .unwrap();
                stream.write_all(&frame).await.unwrap();
                stream.flush().await.unwrap();
                // Both a preflight and a rejected stale preflight must close
                // without submitting a single credential frame byte.
                assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
            })
            .await
            .unwrap();
        });
        publish(&ready.with_extension("observed"), b"no-submission");
    }
    // A synchronous read intentionally leaves a bound holder not accepting any
    // requests. The parent owns stdin and a kill-and-wait guard on every path.
    let mut command = [0];
    std::io::stdin().read_exact(&mut command).unwrap();
    assert_eq!(command, [b'q']);
    drop(listener);
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = Path::new("/tmp").join(format!("gprp-{:016x}", rand::random::<u64>()));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn endpoint(&self) -> PathBuf {
        self.0.join("endpoint")
    }
    fn spawn(&self, endpoint: &Path, mode: &str) -> Process {
        let ready = self.0.join(format!("ready-{:016x}", rand::random::<u64>()));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_FLAG, CHILD_VALUE)
            .env("GP_RECOVERY_ENDPOINT", endpoint)
            .env("GP_RECOVERY_READY", &ready)
            .env("GP_RECOVERY_MODE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let mut process = Process {
            child,
            stdin,
            ready,
            result: String::new(),
            finished: false,
        };
        let until = Instant::now() + LIMIT;
        loop {
            if let Ok(value) = fs::read_to_string(&process.ready) {
                if value == "armed" || value.starts_with("error:") || value.len() == 38 {
                    process.result = value;
                    return process;
                }
            }
            assert!(
                Instant::now() < until,
                "child did not publish bounded readiness"
            );
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "child exited before readiness"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn holder(&self, endpoint: &Path, mode: &str) -> Process {
        let process = self.spawn(endpoint, mode);
        assert!(process.result.starts_with("ready:"), "{}", process.result);
        process
    }
    fn denied(&self, endpoint: &Path) {
        let mut process = self.spawn(endpoint, "probe");
        assert!(
            process.result.starts_with("error:"),
            "second owner was admitted"
        );
        assert!(process.wait().success());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this test's random top-level fixture, after child guards drop.
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Process {
    child: Child,
    stdin: Option<ChildStdin>,
    ready: PathBuf,
    result: String,
    finished: bool,
}
impl Process {
    fn await_binding(&mut self) {
        let until = Instant::now() + LIMIT;
        loop {
            if let Ok(value) = fs::read_to_string(&self.ready) {
                if value.starts_with("error:") || value.len() == 38 {
                    self.result = value;
                    return;
                }
            }
            assert!(
                Instant::now() < until,
                "child did not finish bounded binding"
            );
            assert!(self.child.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn wait(&mut self) -> ExitStatus {
        let until = Instant::now() + LIMIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.finished = true;
                return status;
            }
            assert!(
                Instant::now() < until,
                "child did not exit within its bound"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn stop(&mut self) {
        self.stdin.take().unwrap().write_all(b"q").unwrap();
        assert!(self.wait().success());
    }
    fn kill(&mut self) {
        self.child.kill().unwrap();
        assert!(!self.wait().success());
    }
    fn observed_no_submission(&mut self) {
        let path = self.ready.with_extension("observed");
        let until = Instant::now() + LIMIT;
        loop {
            if fs::read(&path).is_ok_and(|bytes| bytes == b"no-submission") {
                return;
            }
            assert!(
                Instant::now() < until,
                "child did not observe credential-free close"
            );
            assert!(self.child.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn identity(path: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

#[test]
fn live_nonaccepting_and_stopped_holder_is_not_replaced_then_sigkill_recovers() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    let mut first = fixture.holder(&endpoint, "hold");
    let original = fs::read(endpoint.join("instance")).unwrap();
    fixture.denied(&endpoint);
    assert_eq!(fs::read(endpoint.join("instance")).unwrap(), original);
    // Only a PID returned by our own spawn is signalled; no process discovery,
    // argv/environment inspection or external service is involved.
    let mut signal = Process {
        child: Command::new("/bin/kill")
            .args(["-STOP", &first.child.id().to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        stdin: None,
        ready: PathBuf::new(),
        result: String::new(),
        finished: false,
    };
    assert!(signal.wait().success());
    fixture.denied(&endpoint);
    assert_eq!(fs::read(endpoint.join("instance")).unwrap(), original);
    first.kill();
    let mut second = fixture.holder(&endpoint, "hold");
    assert_ne!(second.result, first.result);
    second.stop();
}

#[test]
fn normal_stop_preserves_the_lock_inode_and_restarts_with_new_instance() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    let mut first = fixture.holder(&endpoint, "hold");
    let lock = identity(&endpoint.join("lock"));
    let owner = fs::read(endpoint.join("owner")).unwrap();
    first.stop();
    assert!(endpoint.is_dir());
    assert!(!endpoint.join("instance").exists());
    assert!(!endpoint.join("control.sock").exists());
    assert_eq!(identity(&endpoint.join("lock")), lock);
    let mut second = fixture.holder(&endpoint, "hold");
    assert_ne!(second.result, first.result);
    assert_eq!(identity(&endpoint.join("lock")), lock);
    assert_eq!(fs::read(endpoint.join("owner")).unwrap(), owner);
    second.stop();
}

#[test]
fn a_preflight_from_the_killed_instance_never_submits_to_its_replacement() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    let runtime = runtime();
    let mut first = fixture.holder(&endpoint, "hello");
    let preflight = runtime.block_on(control::preflight(&endpoint)).unwrap();
    first.observed_no_submission();
    first.kill();
    let mut second = fixture.holder(&endpoint, "hello");
    assert_ne!(second.result, first.result);
    let error = runtime
        .block_on(control::authenticate(
            &endpoint,
            preflight,
            Authentication::Password {
                user: Zeroizing::new("synthetic-user".into()),
                password: Zeroizing::new("synthetic-never-submitted".into()),
                computer: "synthetic-computer".into(),
            },
        ))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    second.observed_no_submission();
    second.stop();
}

#[test]
fn replaced_lock_inode_is_not_adopted_or_removed_by_the_old_holder() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    let mut holder = fixture.holder(&endpoint, "hold");
    let lock = endpoint.join("lock");
    let saved = fixture.0.join("original-lock");
    let instance = identity(&endpoint.join("instance"));
    let socket = identity(&endpoint.join("control.sock"));
    fs::rename(&lock, &saved).unwrap();
    fs::copy(&saved, &lock).unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    assert_ne!(identity(&saved), identity(&lock));
    fixture.denied(&endpoint);
    holder.stop();
    assert_eq!(fs::read(&lock).unwrap(), fs::read(&saved).unwrap());
    assert_eq!(identity(&endpoint.join("instance")), instance);
    assert_eq!(identity(&endpoint.join("control.sock")), socket);
}

#[test]
fn crashed_endpoint_with_unknown_entry_is_preserved_without_partial_cleanup() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    let mut holder = fixture.holder(&endpoint, "hold");
    let instance = fs::read(endpoint.join("instance")).unwrap();
    let socket = identity(&endpoint.join("control.sock"));
    fs::write(endpoint.join("keep"), b"unrelated synthetic content").unwrap();
    holder.kill();
    fixture.denied(&endpoint);
    assert_eq!(
        fs::read(endpoint.join("keep")).unwrap(),
        b"unrelated synthetic content"
    );
    assert_eq!(fs::read(endpoint.join("instance")).unwrap(), instance);
    assert_eq!(identity(&endpoint.join("control.sock")), socket);
}

#[test]
fn renamed_parent_symlink_back_does_not_make_old_cleanup_follow_it() {
    let fixture = Fixture::new();
    let parent = fixture.0.join("parent");
    DirBuilder::new().mode(0o700).create(&parent).unwrap();
    let endpoint = parent.join("endpoint");
    let mut holder = fixture.holder(&endpoint, "hold");
    let instance = fs::read(endpoint.join("instance")).unwrap();
    let socket = identity(&endpoint.join("control.sock"));
    let moved = fixture.0.join("moved");
    fs::rename(&parent, &moved).unwrap();
    symlink(&moved, &parent).unwrap();
    holder.stop();
    assert!(parent.is_symlink());
    assert_eq!(fs::read(moved.join("endpoint/instance")).unwrap(), instance);
    assert_eq!(identity(&moved.join("endpoint/control.sock")), socket);
}

#[test]
fn empty_and_v1_directories_are_not_claimed_or_changed() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    DirBuilder::new().mode(0o700).create(&endpoint).unwrap();
    fixture.denied(&endpoint);
    assert_eq!(fs::read_dir(&endpoint).unwrap().count(), 0);
    fs::write(
        endpoint.join("instance"),
        b"0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    fs::set_permissions(endpoint.join("instance"), fs::Permissions::from_mode(0o600)).unwrap();
    let socket = std::os::unix::net::UnixListener::bind(endpoint.join("control.sock")).unwrap();
    fs::set_permissions(
        endpoint.join("control.sock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let old_socket = identity(&endpoint.join("control.sock"));
    fixture.denied(&endpoint);
    drop(socket);
    assert_eq!(fs::read_dir(&endpoint).unwrap().count(), 2);
    assert_eq!(identity(&endpoint.join("control.sock")), old_socket);
    assert_eq!(
        fs::read(endpoint.join("instance")).unwrap(),
        b"0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn four_simultaneous_first_binders_have_one_owner_and_preserve_its_lock() {
    let fixture = Fixture::new();
    for round in 0..3 {
        let endpoint = fixture.0.join(format!("endpoint-{round}"));
        let mut contenders = (0..4)
            .map(|_| fixture.spawn(&endpoint, "race"))
            .collect::<Vec<_>>();
        for contender in &mut contenders {
            assert_eq!(contender.result, "armed");
        }
        for contender in &mut contenders {
            contender.stdin.as_mut().unwrap().write_all(b"g").unwrap();
        }
        for contender in &mut contenders {
            contender.await_binding();
        }
        let winners = contenders
            .iter()
            .enumerate()
            .filter(|(_, process)| process.result.starts_with("ready:"))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(
            winners.len(),
            1,
            "concurrent first bind admitted multiple owners"
        );
        let winner = winners[0];
        for (index, contender) in contenders.iter_mut().enumerate() {
            if index != winner {
                assert!(contender.result.starts_with("error:"));
                assert!(contender.wait().success());
            }
        }
        let lock = identity(&endpoint.join("lock"));
        let instance = fs::read(endpoint.join("instance")).unwrap();
        fixture.denied(&endpoint);
        assert_eq!(fs::read(endpoint.join("instance")).unwrap(), instance);
        assert_eq!(identity(&endpoint.join("lock")), lock);
        let old_instance = contenders[winner].result.clone();
        contenders[winner].kill();
        let mut recovered = fixture.holder(&endpoint, "hold");
        assert_ne!(recovered.result, old_instance);
        assert_eq!(identity(&endpoint.join("lock")), lock);
        recovered.stop();
    }
}

#[test]
fn orphan_stages_remain_untouched_during_fresh_publication_and_recovery() {
    let fixture = Fixture::new();
    let endpoint = fixture.endpoint();
    let empty = fixture
        .0
        .join(".gp-control-stage-00000000000000000000000000000001");
    let partial = fixture
        .0
        .join(".gp-control-stage-00000000000000000000000000000002");
    let prepared = fixture
        .0
        .join(".gp-control-stage-00000000000000000000000000000003");
    DirBuilder::new().mode(0o700).create(&empty).unwrap();
    DirBuilder::new().mode(0o700).create(&partial).unwrap();
    fs::write(partial.join("owner"), b"gp-proxy-control-owner-v2\n").unwrap();
    fs::write(partial.join("keep"), b"unknown stage contents").unwrap();
    // Produce a real, fully initialized namespace on the same filesystem, then
    // move it to a stage-shaped sibling. Its records retain valid inode binding.
    // This models the bytes left before publication without reimplementing their
    // encoding. The private transport checkpoint tests exercise the actual kill.
    let seed = fixture.0.join("seed");
    let mut seed_owner = fixture.holder(&seed, "hold");
    seed_owner.stop();
    fs::rename(&seed, &prepared).unwrap();
    let empty_id = identity(&empty);
    let partial_id = identity(&partial);
    let prepared_id = identity(&prepared);
    let owner = fs::read(prepared.join("owner")).unwrap();
    let lock = fs::read(prepared.join("lock")).unwrap();
    let lock_id = identity(&prepared.join("lock"));

    let mut published = fixture.holder(&endpoint, "hold");
    fixture.denied(&endpoint);
    published.kill();
    let mut recovered = fixture.holder(&endpoint, "hold");
    recovered.stop();

    assert_eq!(identity(&empty), empty_id);
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
    assert_eq!(identity(&partial), partial_id);
    assert_eq!(fs::read_dir(&partial).unwrap().count(), 2);
    assert_eq!(
        fs::read(partial.join("owner")).unwrap(),
        b"gp-proxy-control-owner-v2\n"
    );
    assert_eq!(
        fs::read(partial.join("keep")).unwrap(),
        b"unknown stage contents"
    );
    assert_eq!(identity(&prepared), prepared_id);
    assert_eq!(identity(&prepared.join("lock")), lock_id);
    assert_eq!(fs::read(prepared.join("owner")).unwrap(), owner);
    assert_eq!(fs::read(prepared.join("lock")).unwrap(), lock);
    assert_eq!(fs::read_dir(&prepared).unwrap().count(), 2);
}
