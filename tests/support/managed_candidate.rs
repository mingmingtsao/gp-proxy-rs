//! Preflight orchestration tests use a fake runner and public synthetic files.
//! Actual pipe limits/cleanup are covered by the shared owned-helper tests.
use super::*;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

const DECLARATION: &[u8] = br#"{"schema":1,"control":5,"status":2,"log_store":1,"managed_contract":3,"managed_available":true,"version":"0.1.0"}"#;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let mut id = [0; 8];
        getrandom::fill(&mut id).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gp-candidate-{}",
            crate::managed_release::hexadecimal(&id)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let binary = path.join("candidate");
        fs::write(&binary, b"public synthetic executable bytes").unwrap();
        fs::set_permissions(binary, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn binary(&self) -> PathBuf {
        self.0.join("candidate")
    }
    fn config(&self) -> PathBuf {
        self.0.join("space & config.toml")
    }
    fn digest(&self) -> [u8; 32] {
        Source::open(&self.binary()).unwrap().digest()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Case {
    Good,
    Stderr,
    Invalid,
    Nonzero,
    CheckNonzero,
    Unknown,
    CheckUnknown,
    ReplaceCaps,
    ReplaceCheck,
}
struct Fake {
    case: Case,
    calls: AtomicUsize,
    commands: Mutex<Vec<Vec<OsString>>>,
}
impl Fake {
    fn new(case: Case) -> Self {
        Self {
            case,
            calls: AtomicUsize::new(0),
            commands: Mutex::new(Vec::new()),
        }
    }
}
impl Runner for Fake {
    async fn execute(
        &self,
        binary: &Path,
        arguments: &[OsString],
        capture: Capture,
    ) -> io::Result<Report> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.commands.lock().unwrap().push(arguments.to_vec());
        assert!(call < 2, "no retry is permitted");
        assert_eq!(
            capture,
            if call == 0 {
                Capture::Stdout(1024)
            } else {
                Capture::Discard
            }
        );
        let mut report = Report {
            outcome: Outcome::Exited {
                success: true,
                code: Some(0),
            },
            stdout: if call == 0 {
                DECLARATION.to_vec()
            } else {
                Vec::new()
            },
            stderr_bytes: 0,
        };
        match (self.case, call) {
            (Case::Stderr, 0) => report.stderr_bytes = 1,
            (Case::Invalid, 0) => report.stdout = b"public-untrusted-output-canary".to_vec(),
            (Case::Nonzero, 0) | (Case::CheckNonzero, 1) => {
                report.outcome = Outcome::Exited {
                    success: false,
                    code: Some(7),
                }
            }
            (Case::Unknown, 0) | (Case::CheckUnknown, 1) => {
                report.outcome = Outcome::Unknown {
                    reason: UnknownReason::Deadline,
                    child_reaped: true,
                }
            }
            (Case::ReplaceCaps, 0) | (Case::ReplaceCheck, 1) => {
                let replacement = binary.with_extension("new");
                fs::write(&replacement, b"different public synthetic executable").unwrap();
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
                fs::rename(replacement, binary).unwrap();
            }
            _ => {}
        }
        Ok(report)
    }
}

#[tokio::test]
async fn capabilities_then_config_check_use_only_fixed_arguments() {
    let f = Fixture::new();
    let runner = Fake::new(Case::Good);
    let result = validate_with(&f.binary(), f.digest(), &f.config(), &runner)
        .await
        .unwrap();
    assert_eq!(result, Capabilities::parse(DECLARATION).unwrap());
    assert_eq!(
        *runner.commands.lock().unwrap(),
        vec![
            vec![OsString::from("service"), OsString::from("capabilities")],
            vec![
                OsString::from("--config"),
                f.config().into_os_string(),
                OsString::from("check")
            ]
        ]
    );
}

#[tokio::test]
async fn hash_or_path_failure_does_not_execute_candidate() {
    let f = Fixture::new();
    let runner = Fake::new(Case::Good);
    assert!(validate_with(&f.binary(), [9; 32], &f.config(), &runner)
        .await
        .is_err());
    assert!(
        validate_with(&f.binary(), f.digest(), Path::new("relative"), &runner)
            .await
            .is_err()
    );
    assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
    let error = validate(&f.binary(), [9; 32], &f.config())
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "managed candidate preflight failed");
}

#[tokio::test]
async fn failed_or_changed_candidate_never_retries_or_continues_validation() {
    for (case, expected_calls) in [
        (Case::Stderr, 1),
        (Case::Invalid, 1),
        (Case::Nonzero, 1),
        (Case::Unknown, 1),
        (Case::ReplaceCaps, 1),
        (Case::CheckNonzero, 2),
        (Case::CheckUnknown, 2),
        (Case::ReplaceCheck, 2),
    ] {
        let f = Fixture::new();
        let runner = Fake::new(case);
        let error = validate_with(&f.binary(), f.digest(), &f.config(), &runner)
            .await
            .map_err(redact)
            .unwrap_err();
        assert_eq!(error.to_string(), "managed candidate preflight failed");
        assert_eq!(runner.calls.load(Ordering::SeqCst), expected_calls);
    }
}
