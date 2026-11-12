use super::*;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "gp-proxy-secret-read-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("synthetic-secret")
    }
    fn write(&self, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(self.path()).unwrap().write_all(bytes).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn regular_utf8_files_have_exact_size_limits_and_redacted_errors() {
    let fixture = Fixture::new();
    fixture.write(&vec![b'a'; MAX_BYTES]);
    assert_eq!(read(&fixture.path()).unwrap().len(), MAX_BYTES);
    for bytes in [vec![b'a'; MAX_BYTES + 1], vec![0xff, 0xfe]] {
        fixture.write(&bytes);
        assert!(read(&fixture.path()).is_err());
    }
    assert!(read(&fixture.0).is_err());
    let missing = fixture.0.join("secret-text-must-not-appear-73157");
    let error = read(&missing).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(!error.to_string().contains("73157"));
}

#[cfg(unix)]
#[test]
fn permissions_and_hardlinks_are_checked_before_open() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.write(b"synthetic");
    for mode in [0o604, 0o640, 0o660, 0o700 | 0o010] {
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            read_with(&fixture.path(), |_| panic!("untrusted file reached open"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(&*read(&fixture.path()).unwrap(), "synthetic");
    fs::hard_link(fixture.path(), fixture.0.join("alias")).unwrap();
    assert!(read_with(&fixture.path(), |_| panic!("hardlinked file reached open")).is_err());
}

#[cfg(unix)]
#[test]
fn substitution_before_open_and_after_read_fails_closed() {
    for stage in [Stage::Inspected, Stage::Opened, Stage::Read] {
        let fixture = Fixture::new();
        fixture.write(b"first-synthetic-value");
        let result = read_with(&fixture.path(), |at| {
            if at == stage {
                fs::rename(fixture.path(), fixture.0.join("original")).unwrap();
                fixture.write(b"other-synthetic-value");
            }
        });
        assert!(result.is_err());
    }
}

#[cfg(unix)]
#[test]
fn symlink_substitution_is_never_followed() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fixture.write(b"synthetic");
    let result = read_with(&fixture.path(), |stage| {
        if stage == Stage::Inspected {
            fs::rename(fixture.path(), fixture.0.join("original")).unwrap();
            symlink(fixture.0.join("original"), fixture.path()).unwrap();
        }
    });
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn changing_permissions_or_contents_during_read_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    for stage in [Stage::Opened, Stage::Read] {
        for change in 0..3 {
            let fixture = Fixture::new();
            fixture.write(b"first-synthetic-value");
            let result = read_with(&fixture.path(), |at| {
                if at != stage {
                    return;
                }
                match change {
                    0 => fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o644))
                        .unwrap(),
                    1 => fixture.write(&vec![b'x'; MAX_BYTES + 1]),
                    _ => {
                        // Restoring length and mtime must not hide a content write:
                        // Unix ctime is independently checked at nanosecond precision.
                        let before = fs::metadata(fixture.path()).unwrap().modified().unwrap();
                        let file = OpenOptions::new().write(true).open(fixture.path()).unwrap();
                        (&file).write_all(b"other-synthetic-value").unwrap();
                        file.set_modified(before).unwrap();
                    }
                }
            });
            assert!(result.is_err());
        }
    }
}

#[cfg(unix)]
#[test]
fn fifo_swap_after_inspection_does_not_block() {
    use std::{
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    const ENV: &str = "GP_PROXY_SYNTHETIC_FIFO_TEST_DIR";
    if let Some(directory) = std::env::var_os(ENV) {
        let path = PathBuf::from(directory).join("synthetic-secret");
        let result = read_with(&path, |stage| {
            if stage == Stage::Inspected {
                fs::remove_file(&path).unwrap();
                assert!(Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success());
            }
        });
        assert!(result.is_err());
        return;
    }
    struct Running(Child);
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let fixture = Fixture::new();
    fixture.write(b"synthetic");
    let mut running = Running(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "secret_file::tests::fifo_swap_after_inspection_does_not_block",
                "--test-threads=1",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(ENV, &fixture.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    loop {
        if let Some(status) = running.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "FIFO replacement blocked secret open"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
