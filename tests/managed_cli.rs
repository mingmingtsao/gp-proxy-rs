//! Actual candidate CLI probes. No service manager, gateway or credentials.
use gp_proxy::managed_protocol::{Capabilities, MAX_CAPABILITIES_BYTES};
use std::{
    fs,
    io::Read,
    path::PathBuf,
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const STEP: Duration = Duration::from_secs(5);
const SYNTHETIC_ENV: &[u8] = b"\xffsynthetic-dotenv-must-not-be-read";
const SYNTHETIC_CONFIG: &[u8] = b"invalid TOML if accidentally discovered {{{";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("gp-managed-cli-{:016x}", rand::random::<u64>()));
        Self::at(path)
    }
    fn at(path: PathBuf) -> Self {
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(path.join(".env"), SYNTHETIC_ENV).unwrap();
        fs::write(path.join("gp-proxy.toml"), SYNTHETIC_CONFIG).unwrap();
        Self(path)
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
        command
            .env_clear()
            .current_dir(&self.0)
            .env("RUST_LOG", "trace")
            .env("GP_USER", "synthetic-user-must-not-be-discovered")
            .env(
                "GP_PASSWORD",
                "synthetic-environment-password-must-not-echo",
            )
            .env("GP_GATEWAY", "https://synthetic-env.invalid");
        command
    }
    fn unchanged(&self) {
        assert_eq!(fs::read(self.0.join(".env")).unwrap(), SYNTHETIC_ENV);
        assert_eq!(
            fs::read(self.0.join("gp-proxy.toml")).unwrap(),
            SYNTHETIC_CONFIG
        );
        let mut names: Vec<_> = fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, [".env", "gp-proxy.toml"]);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Running {
    child: Child,
    // Keep the pipe open outside Child: a premature secret read must not be
    // rescued by Child::wait closing stdin and turning the read into EOF.
    _stdin: ChildStdin,
}
struct Output {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
impl Running {
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        Self {
            child,
            _stdin: stdin,
        }
    }
    fn finish(self) -> Output {
        self.finish_with_limit(STEP)
    }
    fn finish_with_limit(mut self, limit: Duration) -> Output {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                start.elapsed() < limit,
                "candidate probe must exit while stdin remains open"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        fn read(pipe: impl Read) -> Vec<u8> {
            let mut bytes = Vec::new();
            pipe.take(8193).read_to_end(&mut bytes).unwrap();
            assert!(bytes.len() <= 8192, "bounded candidate probe output");
            assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-environment-password"));
            bytes
        }
        let stdout = read(self.child.stdout.take().unwrap());
        let stderr = read(self.child.stderr.take().unwrap());
        Output {
            status,
            stdout,
            stderr,
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn actual_plan_and_install_dispatch_are_offline_without_starting_a_service() {
    use gp_proxy::{
        managed_release::Source,
        managed_runtime::{self, Gate},
    };
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    let fixture = Fixture::at(PathBuf::from(format!(
        "/tmp/gp-plan-install-{:016x}",
        rand::random::<u64>()
    )));
    let base = fixture.0.canonicalize().unwrap();
    let isolated_home = base.join("isolated-home");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&isolated_home)
        .unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(isolated_home.join("Library"))
        .unwrap();
    let config = base.join("offline.toml");
    fs::write(&config, b"gateway = 'https://synthetic-management.invalid'\ndomains = ['synthetic-corp.invalid']\nnetworks = ['10.77.0.0/24']\n").unwrap();
    let state = base.join("state");
    let agents = isolated_home.join("Library/LaunchAgents");
    let command = |action: &str| {
        let mut command = fixture.command();
        // This child alone represents an isolated user's home. Never change
        // the test runner's environment or address the actual LaunchAgents.
        command
            .env("HOME", &isolated_home)
            .arg("--config")
            .arg(&config)
            .args(["service", "--state-dir"])
            .arg(&state)
            .arg(action);
        command
    };
    fn inventory(path: &std::path::Path) -> Vec<PathBuf> {
        fn walk(base: &std::path::Path, at: &std::path::Path, out: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(at).unwrap() {
                let entry = entry.unwrap();
                out.push(entry.path().strip_prefix(base).unwrap().to_owned());
                if entry.file_type().unwrap().is_dir() {
                    walk(base, &entry.path(), out);
                }
            }
        }
        let mut found = Vec::new();
        walk(path, path, &mut found);
        found.sort();
        found
    }
    let before = inventory(&base);
    let planned = Running::spawn(command("plan")).finish_with_limit(Duration::from_secs(60));
    assert_eq!(
        planned.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    let planned_gate: Gate = serde_json::from_value(plan["gate"].clone()).unwrap();
    assert!(!planned_gate.enabled);
    assert_eq!(plan["state_directory"], state.to_str().unwrap());
    assert_eq!(plan["launch_agents_directory"], agents.to_str().unwrap());
    assert_eq!(
        inventory(&base),
        before,
        "planning must not create any state"
    );
    assert!(!state.exists() && !agents.exists());

    let installed = Running::spawn(command("install")).finish_with_limit(Duration::from_secs(120));
    assert_eq!(
        installed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&installed.stdout).unwrap();
    assert_eq!(report["installed"], true);
    assert_eq!(report["admission_open"], false);
    assert!(report["pending_operation"].is_null() && report["pending_phase"].is_null());
    assert!(report["matched_instance"].is_null() && report["cleanup"].is_null());
    let maintenance = managed_runtime::open_maintenance(&state.join("runtime")).unwrap();
    let gate = maintenance.read_gate().unwrap();
    assert!(!gate.enabled);
    assert_eq!(gate.identity.generation, 1);
    assert_eq!(gate.identity.release, planned_gate.identity.release);
    assert_eq!(gate.config, config);
    drop(maintenance.try_runtime().unwrap());
    let copy = Source::open(&gate.binary).unwrap();
    assert_eq!(copy.digest(), gate.identity.release);
    assert_eq!(gate.binary, planned_gate.binary);
    for path in [
        &state,
        &state.join("versions"),
        gate.binary.parent().unwrap(),
    ] {
        let meta = fs::symlink_metadata(path).unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink());
        assert_eq!(meta.mode() & 0o077, 0);
        assert_eq!(meta.uid(), rustix::process::geteuid().as_raw());
    }
    let store = gp_proxy::deployment_store::Store::open(&state).unwrap();
    let record = serde_json::to_value(store.record()).unwrap();
    assert!(record["current"].is_object() && record["plist"].is_null());
    assert_eq!(record["gate"]["enabled"], false);
    assert!(store.pending().is_none());
    assert!(!gate.logs.exists() && !gate.control.exists() && !agents.exists());
    assert_eq!(fs::read(base.join(".env")).unwrap(), SYNTHETIC_ENV);
    assert_eq!(
        fs::read(base.join("gp-proxy.toml")).unwrap(),
        SYNTHETIC_CONFIG
    );
    eprintln!("MANAGED CLI plan_no_mutation=true install_dispatch=true admission_closed=true copied_release_verified=true plist_absent=true disk_log_and_control_stores_absent=true stdin_remained_open=true no_gateway_fixture=true children_reaped=true");
}
impl Drop for Running {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
fn assert_capability_output(output: Output) {
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.len() <= MAX_CAPABILITIES_BYTES);
    assert_eq!(output.stdout, Capabilities::current().encode().unwrap());
    assert!(output.stderr.is_empty());
    let declared: Capabilities = serde_json::from_slice(&output.stdout).unwrap();
    declared.validate().unwrap();
    assert_eq!(declared.managed_available, cfg!(target_os = "macos"));
    #[cfg(target_os = "macos")]
    assert!(Capabilities::parse(&output.stdout).is_ok());
    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        Capabilities::parse(&output.stdout).unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
}

#[test]
fn capability_probe_ignores_missing_configuration_and_ambient_credentials() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command
        .arg("--config")
        .arg(fixture.0.join("missing.toml"))
        .args(["service", "capabilities"]);
    assert_capability_output(Running::spawn(command).finish());
    // The ordinary package version from this very same binary is insufficient.
    let mut version = fixture.command();
    version.arg("--version");
    let output = Running::spawn(version).finish();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        concat!("gp-proxy ", env!("CARGO_PKG_VERSION"), "\n").as_bytes()
    );
    assert!(Capabilities::parse(&output.stdout).is_err());
    fixture.unchanged();
}

#[test]
fn capability_probe_ignores_invalid_default_files_without_creating_local_state() {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    // Default configuration and .env in this cwd are intentionally invalid.
    command.args(["service", "capabilities"]);
    assert_capability_output(Running::spawn(command).finish());
    fixture.unchanged();
}

#[test]
fn capability_probe_rejects_explicit_credentials_before_reading_any_file() {
    let fixture = Fixture::new();
    for flag in ["--env-file", "--portal-env-file", "--control-dir"] {
        for after in [false, true] {
            let mut command = fixture.command();
            command.arg("--config").arg(fixture.0.join("missing.toml"));
            if after {
                command.args(["service", "capabilities"]);
            }
            command
                .arg(flag)
                .arg(fixture.0.join("missing-credential-file"));
            if !after {
                command.args(["service", "capabilities"]);
            }
            let output = Running::spawn(command).finish();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            if flag == "--control-dir" {
                assert!(diagnostic.contains(
                    "service management uses the control directory recorded in its installation"
                ));
            } else {
                assert!(diagnostic.contains("service management does not accept credential files"));
            }
            fixture.unchanged();
        }
    }
}
