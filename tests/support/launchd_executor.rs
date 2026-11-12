//! Owned helper processes only; no test executes launchctl or manages a service.
use super::*;
use crate::managed_child as runner;
use crate::managed_child::{Capture, UnknownReason};
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};

const INSTALL: [u8; 16] = [0x12; 16];
const LABEL: &str = "io.gp-proxy.12121212121212121212121212121212.g0000000000000008";
const HELPER_MODE: &str = "GP_PROXY_LAUNCHD_EXECUTOR_TEST";
const ABSOLUTE_ROOT: &str = if cfg!(windows) { "C:/" } else { "/" };

fn absolute_fixture(path: &str) -> PathBuf {
    PathBuf::from(format!("{ABSOLUTE_ROOT}{path}"))
}

fn identity() -> ManagedIdentity {
    ManagedIdentity {
        installation: INSTALL,
        generation: 8,
        release: [0xab; 32],
    }
}

#[test]
fn generation_labels_are_exact_and_do_not_reuse_earlier_targets() {
    assert_eq!(label_for(&identity()).unwrap(), LABEL);
    let mut expected = std::collections::HashSet::new();
    for generation in [1, 8, u64::MAX] {
        let mut id = identity();
        id.generation = generation;
        let label = label_for(&id).unwrap();
        assert_eq!(
            label,
            format!("io.gp-proxy.{}.g{generation:016x}", "12".repeat(16))
        );
        assert!(expected.insert(label.clone()));
        assert!(Action::Bootout { uid: 501, label }.arguments().is_ok());
    }
    for invalid_field in 0..3 {
        let mut id = identity();
        match invalid_field {
            0 => id.installation = [0; 16],
            1 => id.generation = 0,
            _ => id.release = [0; 32],
        }
        assert!(label_for(&id).is_err());
    }
}

#[test]
fn generation_label_parser_rejects_legacy_and_noncanonical_targets() {
    for label in [
        "io.gp-proxy.12121212121212121212121212121212",
        "io.gp-proxy.12121212121212121212121212121212.g8",
        "io.gp-proxy.12121212121212121212121212121212.g0000000000000000",
        "io.gp-proxy.00000000000000000000000000000000.g0000000000000008",
        "io.gp-proxy.12121212121212121212121212121212.g000000000000000A",
        "io.gp-proxy.A2121212121212121212121212121212.g0000000000000008",
        "io.gp-proxy.12121212121212121212121212121212.g00000000000000008",
        "io.gp-proxy.12121212121212121212121212121212.g0000000000000008.extra",
        "io.gp-proxy.12121212121212121212121212121212.g0000000000000008/other",
    ] {
        assert!(Action::Bootout {
            uid: 501,
            label: label.into()
        }
        .arguments()
        .is_err());
    }
}

#[test]
fn typed_actions_have_only_exact_allowed_targets_and_arguments() {
    let plist = absolute_fixture("private/space & directory/agent.plist");
    let cases = [
        (Action::ProbeDomain { uid: 501 }, vec!["print", "gui/501"]),
        (
            Action::ProbeService {
                uid: 501,
                label: LABEL.into(),
            },
            vec![
                "print",
                "gui/501/io.gp-proxy.12121212121212121212121212121212.g0000000000000008",
            ],
        ),
        (
            Action::Bootstrap {
                uid: 501,
                plist: plist.clone(),
            },
            vec!["bootstrap", "gui/501", plist.to_str().unwrap()],
        ),
        (
            Action::Bootout {
                uid: 501,
                label: LABEL.into(),
            },
            vec![
                "bootout",
                "gui/501/io.gp-proxy.12121212121212121212121212121212.g0000000000000008",
            ],
        ),
        (
            Action::Enable {
                uid: 501,
                label: LABEL.into(),
            },
            vec![
                "enable",
                "gui/501/io.gp-proxy.12121212121212121212121212121212.g0000000000000008",
            ],
        ),
        (
            Action::Kickstart {
                uid: 501,
                label: LABEL.into(),
            },
            vec![
                "kickstart",
                "gui/501/io.gp-proxy.12121212121212121212121212121212.g0000000000000008",
            ],
        ),
    ];
    for (action, expected) in cases {
        assert_eq!(action.arguments().unwrap(), expected);
    }
    assert!(Action::ProbeDomain { uid: 0 }.arguments().is_err());
    for label in [
        "system",
        "io.gp-proxy.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "io.gp-proxy.1",
        "io.gp-proxy.12121212121212121212121212121212/other",
        "--help",
    ] {
        assert!(Action::Bootout {
            uid: 501,
            label: label.into()
        }
        .arguments()
        .is_err());
    }
    let maximum_path = format!("{ABSOLUTE_ROOT}{}", "x".repeat(1024 - ABSOLUTE_ROOT.len()));
    assert_eq!(maximum_path.len(), 1024);
    let oversized_path = format!("{maximum_path}x");
    assert_eq!(oversized_path.len(), 1025);
    for path in [
        PathBuf::from("relative.plist"),
        PathBuf::from(oversized_path),
        absolute_fixture("nul\0path"),
    ] {
        assert!(Action::Bootstrap {
            uid: 501,
            plist: path
        }
        .arguments()
        .is_err());
    }
    assert!(Action::Bootstrap {
        uid: 501,
        plist: maximum_path.into()
    }
    .arguments()
    .is_ok());
    #[cfg(windows)]
    for path in ["/rooted-only.plist", "C:relative.plist"] {
        assert!(Action::Bootstrap {
            uid: 501,
            plist: path.into(),
        }
        .arguments()
        .is_err());
    }
}

#[test]
fn plist_round_trips_exact_arguments_without_shell_or_ambient_settings() {
    let binary_path = absolute_fixture("private/合成 path/'<&>\"\r/gp-proxy");
    let directory_path = absolute_fixture("private/runtime & <管理>");
    let binary = binary_path.as_path();
    let directory = directory_path.as_path();
    let bytes = render_plist(501, LABEL, binary, directory, &identity()).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let document = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .unwrap();
    let dict = document.root_element().first_element_child().unwrap();
    let elements: Vec<_> = dict.children().filter(|node| node.is_element()).collect();
    let keys: Vec<_> = elements
        .iter()
        .step_by(2)
        .map(|node| node.text().unwrap())
        .collect();
    assert_eq!(
        keys,
        [
            "Label",
            "ProgramArguments",
            "RunAtLoad",
            "KeepAlive",
            "ThrottleInterval",
            "ExitTimeOut",
            "Umask",
            "StandardOutPath",
            "StandardErrorPath"
        ]
    );
    assert_eq!(elements[1].text(), Some(LABEL));
    let args: Vec<_> = elements[3]
        .children()
        .filter(|node| node.is_element())
        .map(|node| node.text().unwrap())
        .collect();
    assert_eq!(
        args,
        [
            binary.to_str().unwrap(),
            "managed-run",
            "--runtime-dir",
            directory.to_str().unwrap(),
            "--installation",
            "12121212121212121212121212121212",
            "--generation",
            "8",
            "--release",
            &"ab".repeat(32)
        ]
    );
    assert!(elements[5].has_tag_name("true"));
    let keep: Vec<_> = elements[7]
        .children()
        .filter(|node| node.is_element())
        .collect();
    assert_eq!(keep[0].text(), Some("SuccessfulExit"));
    assert!(keep[1].has_tag_name("false"));
    for (index, expected) in [
        (9, "30"),
        (11, "60"),
        (13, "63"),
        (15, "/dev/null"),
        (17, "/dev/null"),
    ] {
        assert_eq!(elements[index].text(), Some(expected));
    }
    let mut mismatch = identity();
    mismatch.installation = [0x13; 16];
    assert!(render_plist(501, LABEL, binary, directory, &mismatch).is_err());
    let mut mismatch = identity();
    mismatch.generation += 1;
    assert!(render_plist(501, LABEL, binary, directory, &mismatch).is_err());
    let mut invalid_id = identity();
    invalid_id.generation = 0;
    assert!(render_plist(501, LABEL, binary, directory, &invalid_id).is_err());
    assert!(render_plist(0, LABEL, binary, directory, &identity()).is_err());
    assert!(render_plist(
        501,
        LABEL,
        &absolute_fixture("bad\u{1}"),
        directory,
        &identity()
    )
    .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        assert!(render_plist(
            501,
            LABEL,
            Path::new(std::ffi::OsStr::from_bytes(b"/bad\xff")),
            directory,
            &identity()
        )
        .is_err());
    }
}

fn helper(mode: &str) -> tokio::process::Command {
    let mut command = runner::test_command(&std::env::current_exe().unwrap());
    command.args(["--exact", "launchd::tests::owned_helper", "--nocapture"]);
    command.env(HELPER_MODE, mode);
    command
}

#[test]
fn owned_helper() {
    let Some(mode) = std::env::var_os(HELPER_MODE) else {
        return;
    };
    match mode.to_str().unwrap() {
        "environment" => {
            let keys: std::collections::BTreeSet<_> =
                std::env::vars_os().map(|(key, _)| key).collect();
            assert_eq!(
                keys,
                ["PATH", "LANG", HELPER_MODE]
                    .into_iter()
                    .map(std::ffi::OsString::from)
                    .collect()
            );
            assert_eq!(std::env::var("PATH").unwrap(), "/usr/bin:/bin");
            assert_eq!(std::env::var("LANG").unwrap(), "C");
            assert_eq!(std::io::stdin().read(&mut [0_u8; 1]).unwrap(), 0);
            std::io::stdout()
                .write_all(b"public synthetic stdout\n")
                .unwrap();
            std::io::stderr()
                .write_all(b"public synthetic stderr\n")
                .unwrap();
            std::process::exit(0);
        }
        "nonzero" => std::process::exit(7),
        "both-pipes" => {
            let out = std::thread::spawn(|| {
                let _ = std::io::stdout().write_all(&[b'o'; 40 * 1024]);
            });
            let err = std::thread::spawn(|| {
                let _ = std::io::stderr().write_all(&[b'e'; 40 * 1024]);
            });
            out.join().unwrap();
            err.join().unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        "sleep" => std::thread::sleep(Duration::from_secs(30)),
        "large-output" | "large-output-sleep" => {
            // The successful case proves both writes completed, not merely
            // that the reader stopped counting after its old 64 KiB limit.
            let out = std::thread::spawn(|| {
                std::io::stdout().write_all(&[b'o'; 512 * 1024]).unwrap();
            });
            let err = std::thread::spawn(|| {
                std::io::stderr().write_all(&[b'e'; 512 * 1024]).unwrap();
            });
            out.join().unwrap();
            err.join().unwrap();
            if mode == "large-output-sleep" {
                std::thread::sleep(Duration::from_secs(30));
            }
            std::process::exit(0);
        }
        _ => panic!("unknown test helper mode"),
    }
}

#[tokio::test]
async fn uncaptured_large_output_preserves_the_owned_child_exit() {
    let report = runner::test_run(
        helper("large-output"),
        Capture::Null,
        runner::Limits::PRODUCTION,
    )
    .await
    .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Exited {
            success: true,
            code: Some(0)
        }
    );
    assert!(report.stdout.is_empty());
    assert_eq!(
        report.stderr_bytes, 0,
        "null output is intentionally unobserved"
    );
}

#[tokio::test]
async fn null_output_keeps_the_deadline_and_reaps_only_the_owned_child() {
    let started = Instant::now();
    let report = runner::test_run(
        helper("large-output-sleep"),
        Capture::Null,
        runner::Limits {
            deadline: Duration::from_millis(200),
            ..runner::Limits::PRODUCTION
        },
    )
    .await
    .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Unknown {
            reason: UnknownReason::Deadline,
            child_reaped: true,
        }
    );
    assert!(report.stdout.is_empty());
    assert_eq!(
        report.stderr_bytes, 0,
        "null output is intentionally unobserved"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let report = runner::test_run(helper("nonzero"), Capture::Null, runner::Limits::PRODUCTION)
        .await
        .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Exited {
            success: false,
            code: Some(7)
        }
    );
    assert!(report.stdout.is_empty());
    assert_eq!(report.stderr_bytes, 0);
}

#[tokio::test]
async fn owned_command_reaps_success_and_nonzero_without_interpreting_output() {
    let limits = runner::Limits::PRODUCTION;
    assert_eq!(
        runner::test_run(helper("environment"), Capture::Discard, limits)
            .await
            .unwrap()
            .outcome,
        Outcome::Exited {
            success: true,
            code: Some(0)
        }
    );
    assert_eq!(
        runner::test_run(helper("nonzero"), Capture::Discard, limits)
            .await
            .unwrap()
            .outcome,
        Outcome::Exited {
            success: false,
            code: Some(7)
        }
    );
}

#[tokio::test]
async fn aggregate_output_limit_cancels_and_reaps_only_owned_helper() {
    let started = Instant::now();
    assert_eq!(
        runner::test_run(
            helper("both-pipes"),
            Capture::Discard,
            runner::Limits::PRODUCTION
        )
        .await
        .unwrap()
        .outcome,
        Outcome::Unknown {
            reason: UnknownReason::OutputLimit,
            child_reaped: true
        }
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn deadline_is_unknown_even_after_successful_owned_child_reaping() {
    let started = Instant::now();
    let limits = runner::Limits {
        deadline: Duration::from_millis(200),
        ..runner::Limits::PRODUCTION
    };
    assert_eq!(
        runner::test_run(helper("sleep"), Capture::Discard, limits)
            .await
            .unwrap()
            .outcome,
        Outcome::Unknown {
            reason: UnknownReason::Deadline,
            child_reaped: true
        }
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn spawn_failure_is_redacted_and_native_rejects_before_any_execution() {
    let command = runner::test_command(Path::new("/nonexistent/gp-public-synthetic-launchctl"));
    let error = runner::test_run(command, Capture::Discard, runner::Limits::PRODUCTION)
        .await
        .err()
        .expect("expected spawn failure");
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        error.to_string(),
        "managed child process could not be started"
    );
    let error = Native
        .execute(Action::ProbeDomain { uid: 0 })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    #[cfg(target_os = "macos")]
    {
        let uid = rustix::process::geteuid().as_raw();
        let other_uid = if uid == u32::MAX { 1 } else { uid + 1 };
        let error = Native
            .execute(Action::ProbeDomain { uid: other_uid })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
    #[cfg(not(target_os = "macos"))]
    assert_eq!(
        Native
            .execute(Action::ProbeDomain { uid: 501 })
            .await
            .expect_err("expected failure")
            .kind(),
        io::ErrorKind::Unsupported
    );
}

#[tokio::test]
async fn bounded_capture_counts_stderr_and_discards_partial_unknown_output() {
    let report = runner::test_run(
        helper("environment"),
        Capture::Stdout(1024),
        runner::Limits::PRODUCTION,
    )
    .await
    .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Exited {
            success: true,
            code: Some(0)
        }
    );
    assert!(report.stdout.ends_with(b"public synthetic stdout\n"));
    assert_eq!(report.stderr_bytes, b"public synthetic stderr\n".len());
    let report = runner::test_run(
        helper("both-pipes"),
        Capture::Stdout(1024),
        runner::Limits::PRODUCTION,
    )
    .await
    .unwrap();
    assert_eq!(
        report.outcome,
        Outcome::Unknown {
            reason: UnknownReason::OutputLimit,
            child_reaped: true
        }
    );
    assert!(report.stdout.is_empty());
    let invalid = runner::test_run(
        runner::test_command(Path::new("/nonexistent/never-spawn")),
        Capture::Stdout(65537),
        runner::Limits::PRODUCTION,
    )
    .await;
    assert_eq!(
        invalid
            .err()
            .expect("invalid capture must fail before spawn")
            .kind(),
        io::ErrorKind::InvalidInput
    );
}
