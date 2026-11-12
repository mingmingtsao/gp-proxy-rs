//! Synthetic local files only. No credentials or gateway connections.
use gp_proxy::{config::Config, gp::GatewayDomainRule, pac_history::PacHistory, policy::Policy};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("gp-pac-cli-{:016x}", rand::random::<u64>()));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("config")).unwrap();
        Self(path)
    }
    fn config(&self, extra: &str) -> PathBuf {
        let path = self.0.join("config/proxy.toml");
        fs::write(
            &path,
            format!(
                "gateway = 'https://vpn.example.invalid'\ndomains = ['new.corp.test']\n{extra}"
            ),
        )
        .unwrap();
        path
    }
    fn command(&self, subcommand: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_gp-proxy"))
            .current_dir(&self.0)
            .args(["--config", "config/proxy.toml", subcommand])
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cli_check_and_pac_are_read_only_and_default_history_is_beside_config() {
    let fixture = Fixture::new();
    let path = fixture.config("");
    let config = Config::read(&path).unwrap();
    let history_path = path.with_extension("pac-history.json");
    assert_eq!(config.pac_history_file.as_ref(), Some(&history_path));
    assert!(fixture.command("check").status.success());
    let initial = fixture.command("pac");
    assert!(initial.status.success());
    assert!(String::from_utf8_lossy(&initial.stdout).contains("new.corp.test"));
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);

    let retired = Policy::new(vec!["retired.corp.test".into()], Vec::new())
        .unwrap()
        .with_gateway_domains(
            vec![GatewayDomainRule::Exact("old.service.test".into())],
            Vec::new(),
        )
        .unwrap();
    drop(PacHistory::open(&history_path, &retired).unwrap());
    let contents = fs::read(&history_path).unwrap();
    let output = fixture.command("pac");
    assert!(output.status.success());
    let pac = String::from_utf8(output.stdout).unwrap();
    for name in ["retired.corp.test", "new.corp.test", "old.service.test"] {
        assert!(pac.contains(name), "{name}");
    }
    assert!(!pac.contains("dnsDomainIs(host, \".old.service.test\")"));
    assert!(!pac.contains("; DIRECT"));
    assert_eq!(fs::read(&history_path).unwrap(), contents);
    let current = Policy::new(config.domains, config.networks).unwrap();
    assert!(!current.allows_host("retired.corp.test"));
    assert!(!current.allows_host("old.service.test"));
}

#[test]
fn corrupt_or_removed_initialized_history_fails_without_outputting_partial_pac() {
    let fixture = Fixture::new();
    let path = fixture.config("pac_history_file = 'remember.pac-history.json'\n");
    let config = Config::read(&path).unwrap();
    let history_path = path.parent().unwrap().join("remember.pac-history.json");
    assert_eq!(config.pac_history_file.as_ref(), Some(&history_path));
    let retired = Policy::new(vec!["retired.corp.test".into()], Vec::new()).unwrap();
    drop(PacHistory::open(&history_path, &retired).unwrap());
    fs::write(&history_path, "{malformed-private-domain-never-echo").unwrap();
    for subcommand in ["check", "pac"] {
        let output = fixture.command(subcommand);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-domain-never-echo"));
    }
    fs::remove_file(&history_path).unwrap();
    let output = fixture.command("pac");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn offline_pac_never_invents_a_complete_authenticated_gateway_policy() {
    let fixture = Fixture::new();
    fixture.config("trust_gateway_routes = true\n");
    let output = fixture.command("pac");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires authentication"));
}
