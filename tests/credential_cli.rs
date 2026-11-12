//! All credential values and files in these tests are synthetic.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "gp-proxy-credential-cli-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }
    fn check(&self, config: &Path, credentials: Option<&Path>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gp-proxy"));
        command.current_dir(&self.0).arg("--config").arg(config);
        if let Some(path) = credentials {
            command.arg("--env-file").arg(path);
        }
        command.arg("check").output().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn check_loads_explicit_credentials_without_printing_them_or_authenticating() {
    let f = Fixture::new();
    // No TOML gateway: the explicitly selected credential file supplies it.
    let config = f.write("proxy.toml", "domains = ['corp.example.test']\n");
    let credentials = f.write("synthetic.env", "GP_USER=synthetic-user-48192\nGP_PASSWORD='synthetic-$#=\\-secret-48192'\nGP_GATEWAY=vpn.example.invalid:7777\n");
    let output = f.check(&config, Some(&credentials));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("No gateway connection or system changes made"));
    for secret in [
        "synthetic-user-48192",
        "secret-48192",
        "vpn.example.invalid",
    ] {
        assert!(!stdout.contains(secret));
        assert!(!stderr.contains(secret));
    }
}

#[test]
fn malformed_credential_file_fails_without_echoing_values() {
    let f = Fixture::new();
    let config = f.write("proxy.toml", "domains = ['corp.example.test']\n");
    let credentials = f.write("synthetic.env", "GP_USER=fake\nGP_PASSWORD=secret-never-echo-91823\nGP_PASSWORD=second-never-echo-91823\nGP_GATEWAY=vpn.example.invalid:7777\n");
    let output = f.check(&config, Some(&credentials));
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("91823"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("91823"));
}

#[test]
fn check_does_not_discover_implicit_dotenv() {
    let f = Fixture::new();
    let config = f.write(
        "proxy.toml",
        "gateway = 'https://vpn.example.invalid'\ndomains = ['corp.example.test']\n",
    );
    f.write(
        ".env",
        "this deliberately invalid synthetic file must not be opened\n",
    );
    assert!(f.check(&config, None).status.success());
}
