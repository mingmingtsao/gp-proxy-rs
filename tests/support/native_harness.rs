#[path = "wait_auth_gateway.rs"]
mod gateway;

use futures_util::FutureExt;
use gp_proxy::{
    control,
    deployment::{self, DeploymentReport, ManageAction, Plan},
    deployment_store::Store,
    managed_protocol::ManagedIdentity,
    managed_release::{hexadecimal, parse_release, Source},
    managed_runtime::{self, Gate},
    status,
};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::{Child, Command},
    sync::Mutex,
    time::{sleep, timeout},
};

const SCENARIO: Duration = Duration::from_secs(300);
const CLEANUP: Duration = Duration::from_secs(120);
const CLI: Duration = Duration::from_secs(90);
const STEP: Duration = Duration::from_secs(10);
const OUTPUT: usize = 16 * 1024;
const PASSWORD: &[u8] = b"synthetic-cli-password-29483\n";
const EXACT_OPT_IN: &str = "1";

#[path = "native_faults.rs"]
mod faults;

#[derive(Clone, Copy)]
pub(super) enum Case {
    Normal,
    DaemonCrash,
    ManagerInterrupted,
}
impl Case {
    fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::DaemonCrash => "daemon_crash",
            Self::ManagerInterrupted => "manager_interrupted",
        }
    }
}

fn selected(name: &str) -> PathBuf {
    let path =
        PathBuf::from(std::env::var_os(name).expect("explicit native test path is required"));
    assert!(path.is_absolute());
    assert!(!path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir)));
    assert_ne!(path.file_name().unwrap(), ".env");
    path
}
fn artifact(path_name: &str, hash_name: &str) -> (PathBuf, [u8; 32]) {
    let path = selected(path_name);
    let hash =
        parse_release(&std::env::var(hash_name).expect("explicit frozen artifact SHA is required"))
            .unwrap();
    let source = Source::open(&path).unwrap();
    assert_eq!(source.digest(), hash);
    source.verify().unwrap();
    (path, hash)
}
fn copy_artifact(source: &Path, destination: &Path, expected: [u8; 32]) {
    let mut source = Source::open(source).unwrap();
    assert_eq!(source.digest(), expected);
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(destination)
        .unwrap();
    source.copy_into(&mut target).unwrap();
    target.sync_all().unwrap();
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(Source::open(destination).unwrap().digest(), expected);
    source.verify().unwrap();
}

struct Fixture {
    root: PathBuf,
    root_identity: (u64, u64),
    plan: Plan,
    release: PathBuf,
    release_hash: [u8; 32],
    http: SocketAddr,
    socks: SocketAddr,
    reservations: Option<[TcpListener; 2]>,
    intent: File,
    intent_lines: usize,
    native_effects_possible: bool,
    completed_uninstall: bool,
    remote_outcome_uncertain: bool,
    expected_remote_outcome_uncertain: bool,
    echo_bytes: AtomicUsize,
    service_kills: usize,
    manager_kills: usize,
    held_logout: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    local_cleanup_complete: bool,
    identities: Vec<ManagedIdentity>,
    commands: Commands,
}
impl Fixture {
    fn new(
        gateway: &gateway::Gateway,
        debug: &Path,
        debug_hash: [u8; 32],
        release: &Path,
        release_hash: [u8; 32],
    ) -> Self {
        let uid = rustix::process::geteuid().as_raw();
        assert_ne!(uid, 0, "native tests must never target the system domain");
        let selected = selected("GP_TEST_NATIVE_ROOT");
        assert!(!selected.exists(), "fixture leaf must not preexist");
        let parent = selected.parent().unwrap().canonicalize().unwrap();
        let metadata = fs::symlink_metadata(&parent).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(
            metadata.mode() & 0o7777,
            0o700,
            "outer runner must own a private parent"
        );
        let root = parent.join(selected.file_name().unwrap());
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let root_meta = fs::symlink_metadata(&root).unwrap();
        let binary = root.join("debug-gp-proxy");
        let release_copy = root.join("release-gp-proxy");
        copy_artifact(debug, &binary, debug_hash);
        copy_artifact(release, &release_copy, release_hash);
        fs::create_dir(root.join("cwd")).unwrap();
        fs::write(
            root.join("cwd/gp-proxy.toml"),
            b"invalid unused default configuration {{{",
        )
        .unwrap();
        // This explicitly synthetic sentinel is never read, and no real .env is
        // selected. Passwords enter only the explicit reauth child's stdin.
        fs::write(
            root.join("cwd/.env"),
            b"\xffsynthetic-env-must-not-be-discovered",
        )
        .unwrap();
        let agents = root.join("LaunchAgents");
        DirBuilder::new().mode(0o700).create(&agents).unwrap();
        assert_eq!(fs::metadata(&agents).unwrap().dev(), root_meta.dev());
        let ca = root.join("public-synthetic-ca.pem");
        fs::write(
            &ca,
            include_bytes!("../../src/gp/testdata/localhost-cert.pem"),
        )
        .unwrap();
        let config = root.join("config.toml");
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = TcpListener::bind("127.0.0.1:0").unwrap();
        let addresses = (http.local_addr().unwrap(), socks.local_addr().unwrap());
        fs::write(&config, format!("gateway = '{}'\nhttp_listen = '{}'\nsocks_listen = '{}'\nca_file = {}\nnetworks = ['10.77.0.0/24']\ndomains = ['synthetic-corp.invalid']\nmax_connections = 4\nconnect_timeout_secs = 3\nidle_timeout_secs = 20\n", gateway.origin, addresses.0, addresses.1, serde_json::to_string(&ca).unwrap())).unwrap();
        let state = root.join("state");
        let identity = ManagedIdentity {
            installation: rand::random(),
            generation: 1,
            release: debug_hash,
        };
        identity.validate().unwrap();
        let label = label(&identity);
        let plan = Plan {
            schema: 2,
            uid,
            state_directory: state.clone(),
            launch_agents_directory: agents.clone(),
            source_binary: binary,
            release_bytes: Source::open(debug).unwrap().len(),
            gate: Gate {
                version: 2,
                identity,
                enabled: false,
                binary: state
                    .join("versions")
                    .join(hexadecimal(&debug_hash))
                    .join("gp-proxy"),
                config,
                control: state.join("data/control"),
                logs: state.join("data/logs"),
            },
            label: label.clone(),
            plist: agents.join(format!("{label}.plist")),
        };
        plan.gate.validate().unwrap();
        let intent = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("native-intent.jsonl"))
            .unwrap();
        let mut result = Self {
            root,
            root_identity: (root_meta.dev(), root_meta.ino()),
            plan,
            release: release_copy,
            release_hash,
            http: addresses.0,
            socks: addresses.1,
            reservations: Some([http, socks]),
            intent,
            intent_lines: 0,
            native_effects_possible: false,
            completed_uninstall: false,
            remote_outcome_uncertain: false,
            expected_remote_outcome_uncertain: false,
            echo_bytes: AtomicUsize::new(0),
            service_kills: 0,
            manager_kills: 0,
            held_logout: None,
            local_cleanup_complete: false,
            identities: Vec::with_capacity(4),
            commands: Commands::default(),
        };
        result.event("ownership", serde_json::json!({"uid":uid,"installation":hexadecimal(&identity.installation),"state_directory":result.plan.state_directory,"plist_directory":result.plan.launch_agents_directory,"control_directory":result.plan.gate.control,"debug_sha256":hexadecimal(&debug_hash),"release_sha256":hexadecimal(&release_hash),"recovery_commands":[[result.plan.source_binary.to_str().unwrap(),"service","--state-dir",result.plan.state_directory.to_str().unwrap(),"recover"],[result.plan.source_binary.to_str().unwrap(),"service","--state-dir",result.plan.state_directory.to_str().unwrap(),"uninstall"]],"scope":"private plist path; no login discovery, Resume, enable or disable test"}));
        result
    }
    fn event(&mut self, kind: &str, value: serde_json::Value) {
        assert!(self.intent_lines < 32);
        let row = serde_json::json!({"schema":1,"kind":kind,"owned_root":self.root,"detail":value});
        let mut encoded = serde_json::to_vec(&row).unwrap();
        assert!(encoded.len() <= 4096);
        encoded.push(b'\n');
        self.intent.write_all(&encoded).unwrap();
        self.intent.sync_all().unwrap();
        self.intent_lines += 1;
        eprintln!("NATIVE_LAUNCHD stage={kind}");
    }
    fn report_event(&mut self, kind: &str, report: serde_json::Value) {
        // Preserve every numeric report before assertions or fixture cleanup.
        // A local retirement proof cannot erase remote logout uncertainty.
        self.remote_outcome_uncertain |= report["remote_outcome_unknown"].as_bool() != Some(false)
            || report["cleanup_unconfirmed_episodes"].as_u64() != Some(0)
            || report["logout_unconfirmed"].as_u64() != Some(0);
        self.event(kind, report);
    }
    fn release_logout(&mut self) {
        if let Some(gate) = self.held_logout.take() {
            gate.add_permits(1);
        }
    }
    fn verify_root(&self) -> io::Result<()> {
        let meta = fs::symlink_metadata(&self.root)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || (meta.dev(), meta.ino()) != self.root_identity
            || meta.uid() != self.plan.uid
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
    fn verify_installation(&self) -> io::Result<()> {
        self.verify_root()?;
        let store = Store::open_recovery(&self.plan.state_directory)?;
        let record = serde_json::to_value(store.record()).map_err(io::Error::other)?;
        let identity: [u8; 16] =
            serde_json::from_value(record["installation"].clone()).map_err(io::Error::other)?;
        let gate: Gate =
            serde_json::from_value(record["gate"].clone()).map_err(io::Error::other)?;
        if identity != self.plan.gate.identity.installation
            || gate.identity.installation != identity
            || gate.control != self.plan.gate.control
            || gate.logs != self.plan.gate.logs
            || gate.config != self.plan.gate.config
            || ![self.plan.gate.identity.release, self.release_hash]
                .contains(&gate.identity.release)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
    fn gate(&self) -> Gate {
        managed_runtime::read_gate(&self.plan.state_directory.join("runtime")).unwrap()
    }
    async fn ready(&mut self) -> control::ControlIdentity {
        let observed = control::inspect(&self.plan.gate.control).await.unwrap();
        let gate = self.gate();
        assert!(gate.enabled);
        assert_eq!(observed.managed, Some(gate.identity));
        assert_eq!(
            gate.identity.installation,
            self.plan.gate.identity.installation
        );
        assert!(observed.supports_stop);
        assert!(!status::query(self.http).await.unwrap().available);
        assert!(self.identities.len() < 4);
        self.identities.push(gate.identity);
        self.event("managed_ready", serde_json::json!({"managed":gate.identity,"instance":hexadecimal(&observed.instance),"label":label(&gate.identity)}));
        observed
    }
    async fn authenticate(&self) {
        let args = vec![
            "--config".into(),
            self.plan.gate.config.to_str().unwrap().into(),
            "--control-dir".into(),
            self.plan.gate.control.to_str().unwrap().into(),
            "reauth".into(),
            "--username".into(),
            "synthetic-user".into(),
            "--password-stdin".into(),
        ];
        let (code, _) = self
            .commands
            .run(
                &self.plan.source_binary,
                &args,
                &self.root.join("cwd"),
                Some(PASSWORD),
            )
            .await
            .unwrap();
        assert_eq!(code, Some(0));
        timeout(STEP, async {
            while !status::query(self.http).await.unwrap().available {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    fn verify_released(&self) -> io::Result<()> {
        self.verify_installation()?;
        let maintenance =
            managed_runtime::open_maintenance(&self.plan.state_directory.join("runtime"))?;
        if maintenance.read_gate()?.enabled {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        drop(maintenance.try_runtime()?);
        drop(maintenance);
        drop(TcpListener::bind(self.http)?);
        drop(TcpListener::bind(self.socks)?);
        if self.plan.gate.control.join("control.sock").exists() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let lock = self.plan.gate.logs.join("lock");
        match rustix::fs::open(
            &lock,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                file.try_lock().map_err(|_| io::ErrorKind::WouldBlock)?;
            }
            Err(rustix::io::Errno::NOENT) if !self.native_effects_possible => {}
            Err(error) => return Err(error.into()),
        }
        if fs::read_dir(&self.plan.launch_agents_directory)?
            .next()
            .is_some()
        {
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }
    async fn cleanup(&mut self) -> io::Result<()> {
        self.verify_root()?;
        if !self.plan.state_directory.exists() {
            return if self.native_effects_possible {
                Err(io::ErrorKind::NotFound.into())
            } else {
                self.local_cleanup_complete = true;
                Ok(())
            };
        }
        self.verify_installation()?;
        if !self.completed_uninstall {
            self.event(
                "cleanup_recover",
                serde_json::json!({"native_effects_possible":self.native_effects_possible}),
            );
            let recovered = deployment::recover(&self.plan.state_directory).await?;
            self.report_event(
                "cleanup_recover_completed",
                serde_json::to_value(&recovered).map_err(io::Error::other)?,
            );
            if recovered.pending_operation.is_some()
                || recovered.retired_jobs != 0
                || recovered.admission_open
            {
                return Err(io::ErrorKind::Other.into());
            }
            let removed =
                deployment::change(&self.plan.state_directory, ManageAction::Uninstall).await?;
            self.report_event(
                "cleanup_uninstall_completed",
                serde_json::to_value(&removed).map_err(io::Error::other)?,
            );
            if removed.installed
                || removed.admission_open
                || removed.pending_operation.is_some()
                || removed.retired_jobs != 0
            {
                return Err(io::ErrorKind::Other.into());
            }
            self.completed_uninstall = true;
        }
        self.verify_released()?;
        self.local_cleanup_complete = true;
        Ok(())
    }
}
// Intentionally no recursive-delete Drop: launchd may still reference these
// files after an unknown failure. The outer runner owns evidence retention and
// may remove this exact private root only after verified successful cleanup.

fn label(identity: &ManagedIdentity) -> String {
    format!(
        "io.gp-proxy.{}.g{:016x}",
        hexadecimal(&identity.installation),
        identity.generation
    )
}
async fn read_bounded(reader: impl AsyncRead + Unpin) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(OUTPUT + 1);
    reader
        .take((OUTPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > OUTPUT {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}
// The single CLI slot lives outside the cancellable scenario. A timeout may
// drop stdout readers and the command future, but finally still owns the Child
// and explicitly kills/waits it before touching the deployment transaction.
#[derive(Default)]
struct Commands {
    child: Mutex<Option<Child>>,
    spawned: AtomicUsize,
    reaped: AtomicUsize,
}
impl Commands {
    async fn run(
        &self,
        binary: &Path,
        args: &[String],
        cwd: &Path,
        input: Option<&[u8]>,
    ) -> io::Result<(Option<i32>, Vec<u8>)> {
        let mut slot = self.child.lock().await;
        assert!(slot.is_none(), "only one owned CLI operation may run");
        *slot = Some(
            Command::new(binary)
                .args(args)
                .env_clear()
                .current_dir(cwd)
                .stdin(if input.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?,
        );
        self.spawned.fetch_add(1, Ordering::SeqCst);
        let child = slot.as_mut().unwrap();
        let mut stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let result = timeout(CLI, async {
            if let Some(bytes) = input {
                let writer = stdin.as_mut().unwrap();
                writer.write_all(bytes).await?;
                writer.shutdown().await?;
            }
            drop(stdin);
            let (stdout, _stderr, exit) =
                tokio::try_join!(read_bounded(stdout), read_bounded(stderr), child.wait())?;
            Ok::<_, io::Error>((exit.code(), stdout))
        })
        .await;
        let output = match result {
            Ok(Ok(output)) => Ok(output),
            other => {
                let _ = child.start_kill();
                timeout(Duration::from_secs(3), child.wait())
                    .await
                    .map_err(|_| io::ErrorKind::TimedOut)??;
                match other {
                    Ok(Err(error)) => Err(error),
                    _ => Err(io::ErrorKind::TimedOut.into()),
                }
            }
        };
        slot.take();
        self.reaped.fetch_add(1, Ordering::SeqCst);
        output
    }
    async fn reap_pending(&self) -> io::Result<()> {
        let mut slot = self.child.lock().await;
        if let Some(child) = slot.as_mut() {
            let _ = child.start_kill();
            timeout(Duration::from_secs(3), child.wait())
                .await
                .map_err(|_| io::ErrorKind::TimedOut)??;
            slot.take();
            self.reaped.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
    /// The scenario dropped only the operation future; the outer registry still
    /// owns this exact Child. No PID discovery or signal to a daemon is involved.
    async fn kill_pending(&self) -> io::Result<std::process::ExitStatus> {
        let mut slot = self.child.lock().await;
        let child = slot.as_mut().ok_or(io::ErrorKind::NotFound)?;
        if child.try_wait()?.is_some() {
            // Preserve the handle for finally to reap/account on this failure.
            return Err(io::Error::other(
                "owned manager already exited before fault",
            ));
        }
        child.start_kill()?;
        let status = timeout(Duration::from_secs(2), child.wait())
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        slot.take();
        self.reaped.fetch_add(1, Ordering::SeqCst);
        Ok(status)
    }
}

async fn echo(f: &Fixture, socks: bool) -> TcpStream {
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
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                assert!(head.len() < 4096);
                head.push(stream.read_u8().await.unwrap());
            }
            assert!(head.starts_with(b"HTTP/1.1 200 "));
        }
        let bytes: Vec<_> = (0..8192)
            .map(|index| ((index + usize::from(socks)) % 251) as u8)
            .collect();
        stream.write_all(&bytes).await.unwrap();
        let mut received = vec![0; bytes.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, bytes);
        f.echo_bytes.fetch_add(bytes.len(), Ordering::SeqCst);
        stream
    })
    .await
    .unwrap()
}
async fn closed(stream: &mut TcpStream) {
    match timeout(STEP, stream.read(&mut [0; 1])).await.unwrap() {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        value => panic!("old native capability remained usable: {value:?}"),
    }
}
fn confirmed(report: &DeploymentReport, sessions: u64) {
    assert!(
        report.pending_operation.is_none()
            && !report.remote_outcome_unknown
            && report.cleanup_unconfirmed_episodes == 0
            && report.logout_unconfirmed == 0
            && report.retired_jobs == 0
    );
    let cleanup = report.cleanup.as_ref().unwrap();
    assert!(cleanup.local_cleanup_complete);
    assert_eq!(cleanup.cleanup.known_sessions, sessions);
    assert_eq!(cleanup.cleanup.logout_confirmed, sessions);
    assert_eq!(
        (
            cleanup.cleanup.logout_unconfirmed,
            cleanup.cleanup.remote_outcome_unknown
        ),
        (0, 0)
    );
}
async fn normal_scenario(f: &mut Fixture, gateway: &gateway::Gateway) {
    f.event("install_stopped", serde_json::json!({}));
    let installed = deployment::install(f.plan.clone(), false).await.unwrap();
    assert!(
        installed.installed && !installed.admission_open && installed.pending_operation.is_none()
    );
    assert!(!f.plan.plist.exists());
    assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
    assert!(!f.plan.gate.control.join("control.sock").exists());
    f.reservations.take();
    f.native_effects_possible = true;
    f.event("first_native_start", serde_json::json!({}));
    deployment::change(&f.plan.state_directory, ManageAction::Start)
        .await
        .unwrap();
    let first = f.ready().await;
    assert_eq!(gateway.state.accepted.load(Ordering::SeqCst), 0);
    f.authenticate().await;
    let (mut http, mut socks) = tokio::join!(echo(f, false), echo(f, true));
    f.event("first_stop", serde_json::json!({"echo_bytes":16384}));
    let stopped = deployment::change(&f.plan.state_directory, ManageAction::Stop)
        .await
        .unwrap();
    f.report_event(
        "first_stop_completed",
        serde_json::to_value(&stopped).unwrap(),
    );
    confirmed(&stopped, 1);
    tokio::join!(closed(&mut http), closed(&mut socks));
    f.verify_released().unwrap();
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 1);
    f.event("fresh_generation_start", serde_json::json!({}));
    deployment::change(&f.plan.state_directory, ManageAction::Start)
        .await
        .unwrap();
    let second = f.ready().await;
    assert_ne!(second.instance, first.instance);
    assert!(second.managed.unwrap().generation > first.managed.unwrap().generation);
    assert_eq!(gateway.state.logins.load(Ordering::SeqCst), 1);
    f.authenticate().await;
    let (mut upgrade_http, mut upgrade_socks) = tokio::join!(echo(f, false), echo(f, true));
    f.event(
        "different_sha_upgrade",
        serde_json::json!({"release_sha256":hexadecimal(&f.release_hash), "echo_bytes":32768}),
    );
    let args = vec![
        "service".into(),
        "--state-dir".into(),
        f.plan.state_directory.to_str().unwrap().into(),
        "upgrade".into(),
    ];
    let (code, output) = f
        .commands
        .run(&f.release, &args, &f.root.join("cwd"), None)
        .await
        .unwrap();
    assert_eq!(code, Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    f.report_event("upgrade_completed", report.clone());
    assert_eq!(report["release"], hexadecimal(&f.release_hash));
    assert!(report["pending_operation"].is_null());
    assert_eq!(report["cleanup"]["cleanup"]["known_sessions"], 1);
    assert_eq!(report["cleanup"]["cleanup"]["logout_confirmed"], 1);
    assert_eq!(report["cleanup"]["cleanup"]["logout_unconfirmed"], 0);
    assert_eq!(report["cleanup"]["cleanup"]["remote_outcome_unknown"], 0);
    assert_eq!(report["cleanup"]["local_cleanup_complete"], true);
    tokio::join!(closed(&mut upgrade_http), closed(&mut upgrade_socks));
    let third = f.ready().await;
    assert_ne!(third.instance, second.instance);
    assert!(third.managed.unwrap().generation > second.managed.unwrap().generation);
    assert_eq!(third.managed.unwrap().release, f.release_hash);
    assert_eq!(
        gateway.state.logins.load(Ordering::SeqCst),
        2,
        "upgrade must not submit prior credentials"
    );
    assert_eq!(gateway.state.logouts.load(Ordering::SeqCst), 2);
    f.authenticate().await;
    let (mut http, mut socks) = tokio::join!(echo(f, false), echo(f, true));
    f.event("uninstall", serde_json::json!({"echo_bytes":49152}));
    let removed = deployment::change(&f.plan.state_directory, ManageAction::Uninstall)
        .await
        .unwrap();
    f.report_event(
        "uninstall_completed",
        serde_json::to_value(&removed).unwrap(),
    );
    confirmed(&removed, 1);
    assert!(!removed.installed && !removed.admission_open);
    tokio::join!(closed(&mut http), closed(&mut socks));
    f.completed_uninstall = true;
    f.verify_released().unwrap();
    assert_eq!(
        (
            gateway.state.logins.load(Ordering::SeqCst),
            gateway.state.logouts.load(Ordering::SeqCst)
        ),
        (3, 3)
    );
}

pub(super) async fn run(case: Case) {
    assert_eq!(
        std::env::var("GP_TEST_NATIVE_LAUNCHD").as_deref(),
        Ok(EXACT_OPT_IN)
    );
    let (debug, debug_hash) =
        artifact("GP_TEST_NATIVE_DEBUG_BINARY", "GP_TEST_NATIVE_DEBUG_SHA256");
    let (release, release_hash) = artifact(
        "GP_TEST_NATIVE_RELEASE_BINARY",
        "GP_TEST_NATIVE_RELEASE_SHA256",
    );
    assert_ne!(debug_hash, release_hash);
    // Gateway is outside the caught scenario: it must remain available for a
    // late stop/logout during finally, even if the body panics or times out.
    let gateway = gateway::Gateway::start().await;
    let state = gateway.state.clone();
    let mut fixture = Fixture::new(&gateway, &debug, debug_hash, &release, release_hash);
    fixture.event("scenario", serde_json::json!({"case":case.name()}));
    let result = timeout(
        SCENARIO,
        AssertUnwindSafe(async {
            match case {
                Case::Normal => normal_scenario(&mut fixture, &gateway).await,
                Case::DaemonCrash => faults::daemon_crash(&mut fixture, &gateway).await,
                Case::ManagerInterrupted => {
                    faults::manager_interrupted(&mut fixture, &gateway).await
                }
            }
        })
        .catch_unwind(),
    )
    .await;
    let scenario_ok = matches!(&result, Ok(Ok(())));
    let mut errors = Vec::with_capacity(4);
    fixture.reservations.take();
    // A panic or timeout must never leave the synthetic logout response held
    // during finally. The real daemon's own cleanup deadline is unchanged.
    fixture.release_logout();
    *state.logout_gate.lock().unwrap() = None;
    let cleanup = timeout(
        CLEANUP,
        AssertUnwindSafe(async {
            fixture.commands.reap_pending().await?;
            fixture.cleanup().await
        })
        .catch_unwind(),
    )
    .await;
    let local_cleanup_verified = matches!(&cleanup, Ok(Ok(Ok(()))));
    // Known remote uncertainty is a required crash-test result, not permission
    // to remove its evidence. It stays distinct from verified local retirement.
    let cleanup_complete = local_cleanup_verified
        && !fixture.remote_outcome_uncertain
        && !fixture.expected_remote_outcome_uncertain;
    if !cleanup_complete {
        errors.push("owned_native_cleanup_unconfirmed");
    }
    let gateway_result = AssertUnwindSafe(gateway.close()).catch_unwind().await;
    let gateway_joined = gateway_result.is_ok();
    if !gateway_joined {
        errors.push("synthetic_gateway_natural_join_unconfirmed");
    }
    let completion = serde_json::json!({"schema":1,"case":case.name(),"fixture_root":fixture.root,"scenario_ok":scenario_ok,"cleanup_complete":cleanup_complete,"local_cleanup_complete":fixture.local_cleanup_complete,"remote_outcome_uncertain":fixture.remote_outcome_uncertain,"expected_remote_outcome_uncertain":fixture.expected_remote_outcome_uncertain,"service_sigkill_commands":fixture.service_kills,"owned_manager_sigkills":fixture.manager_kills,"safe_to_remove_fixture":scenario_ok && cleanup_complete && gateway_joined,"gateway_joined":gateway_joined,"cleanup_errors":errors,"installation":hexadecimal(&fixture.plan.gate.identity.installation),"managed_generations":fixture.identities,"synthetic_logins":state.logins.load(Ordering::SeqCst),"synthetic_logouts":state.logouts.load(Ordering::SeqCst),"gateway_workers":state.active_workers.load(Ordering::SeqCst),"gateway_tunnels":state.active_tunnels.load(Ordering::SeqCst),"echo_bytes":fixture.echo_bytes.load(Ordering::SeqCst),"owned_cli_children_spawned":fixture.commands.spawned.load(Ordering::SeqCst),"owned_cli_children_reaped":fixture.commands.reaped.load(Ordering::SeqCst),"daemon_waitpid_claimed":false,"login_directory_discovery_tested":false,"fixture_preserved":true});
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(fixture.root.join("native-completion.json"))
        .unwrap();
    serde_json::to_writer(&mut file, &completion).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
    eprintln!("NATIVE_LAUNCHD finished scenario_ok={scenario_ok} cleanup_complete={cleanup_complete} gateway_joined={gateway_joined} echo_bytes={} evidence_root={}",fixture.echo_bytes.load(Ordering::SeqCst),fixture.root.display());
    match result {
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("native scenario exceeded its unchanged 300 second fixture budget"),
        Ok(Ok(())) => {}
    }
    assert!(gateway_joined, "synthetic gateway join is unconfirmed");
    match case {
        Case::Normal | Case::ManagerInterrupted => {
            assert!(cleanup_complete, "native cleanup is unconfirmed")
        }
        Case::DaemonCrash => assert!(
            local_cleanup_verified
                && fixture.local_cleanup_complete
                && fixture.remote_outcome_uncertain
                && fixture.expected_remote_outcome_uncertain,
            "crash uncertainty must remain visible after verified local cleanup"
        ),
    }
}
