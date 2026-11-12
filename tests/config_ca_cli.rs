//! Offline startup checks using only newly created files and a public test CA.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const CONFIG: &str = "gateway = 'https://vpn.example.invalid'\ndomains = ['corp.example.test']\n";
const CA: &[u8] = include_bytes!("../src/gp/testdata/localhost-cert.pem");

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "gp-proxy-config-ca-cli-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        for child in ["selected", "target", "cwd"] {
            fs::create_dir(path.join(child)).unwrap();
        }
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        path
    }
    fn check(&self, config: &Path) -> Output {
        let mut child = Running(Some(
            Command::new(env!("CARGO_BIN_EXE_gp-proxy"))
                .env_clear()
                .current_dir(self.0.join("cwd"))
                .arg("--config")
                .arg(config)
                .arg("check")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        let start = Instant::now();
        loop {
            if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return child.0.take().unwrap().wait_with_output().unwrap();
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "offline file check blocked for 5 seconds"
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
fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("No gateway connection or system changes")
    );
}
fn assert_file_rejected(output: Output) {
    assert!(!output.status.success(), "unsafe file input was accepted");
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-secret-marker-71903"));
}

#[test]
fn oversized_but_valid_toml_is_rejected() {
    let f = Fixture::new();
    let mut source = format!("{CONFIG}#{}", "x".repeat(1024 * 1024 - CONFIG.len() - 1));
    let path = f.write("selected/proxy.toml", source.as_bytes());
    assert_success(f.check(&path));
    source.push('x');
    let path = f.write("selected/proxy.toml", source.as_bytes());
    assert_file_rejected(f.check(&path));
}

#[cfg(unix)]
#[test]
fn configuration_fifo_fails_without_a_writer() {
    let f = Fixture::new();
    let path = f.0.join("selected/synthetic-fifo");
    assert!(Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap()
        .success());
    assert_file_rejected(f.check(&path));
}

#[cfg(unix)]
#[test]
fn ca_fifo_fails_without_a_writer() {
    let f = Fixture::new();
    let ca = f.0.join("selected/synthetic-fifo");
    assert!(Command::new("mkfifo").arg(&ca).status().unwrap().success());
    let path = f.write(
        "selected/proxy.toml",
        format!("{CONFIG}ca_file = '{}'\n", ca.display()).as_bytes(),
    );
    assert_file_rejected(f.check(&path));
}

#[test]
fn relative_ca_uses_selected_configuration_directory_not_process_cwd() {
    let f = Fixture::new();
    f.write("selected/synthetic-ca.pem", CA);
    let config = f.write(
        "selected/proxy.toml",
        format!("{CONFIG}ca_file = 'synthetic-ca.pem'\n").as_bytes(),
    );
    assert_success(f.check(&config));
}

#[test]
fn absolute_public_ca_and_shared_permissions_remain_supported() {
    let f = Fixture::new();
    let ca = f.write("target/synthetic-ca.pem", CA);
    let config = f.write(
        "selected/proxy.toml",
        format!("{CONFIG}ca_file = '{}'\n", ca.display()).as_bytes(),
    );
    assert_success(f.check(&config));
}

#[cfg(unix)]
#[test]
fn configuration_and_ca_symlinks_remain_supported_with_the_selected_base() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let ca = f.write("target/synthetic-ca.pem", CA);
    let config = f.write(
        "target/proxy.toml",
        format!("{CONFIG}ca_file = 'synthetic-ca.pem'\n").as_bytes(),
    );
    let selected = f.0.join("selected/proxy.toml");
    symlink(&config, &selected).unwrap();
    symlink(&ca, f.0.join("selected/synthetic-ca.pem")).unwrap();
    assert_success(f.check(&selected));
}

#[test]
fn malformed_config_and_ca_diagnostics_do_not_echo_input() {
    let f = Fixture::new();
    let config = f.write("selected/proxy.toml", &[0xff, 0xfe]);
    assert_file_rejected(f.check(&config));
    let config = f.write("selected/proxy.toml", b"synthetic-secret-marker-71903 = [");
    assert_file_rejected(f.check(&config));
    let ca = f.write(
        "target/synthetic-ca.pem",
        b"-----BEGIN CERTIFICATE synthetic-secret-marker-71903\n",
    );
    let config = f.write(
        "selected/proxy.toml",
        format!("{CONFIG}ca_file = '{}'\n", ca.display()).as_bytes(),
    );
    assert_file_rejected(f.check(&config));
}
