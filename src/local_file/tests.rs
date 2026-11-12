use super::*;
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "gp-proxy-public-file-test-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
    fn path(&self) -> PathBuf {
        self.0.join("synthetic-public-file")
    }
    fn write(&self, bytes: &[u8]) {
        fs::write(self.path(), bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.path(), fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn snapshot_reader_keeps_one_allocation_across_short_reads_and_interrupts() {
    struct Fragmented {
        offset: usize,
        base: Option<usize>,
        interrupted: bool,
    }
    impl Read for Fragmented {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            assert!(!output.is_empty());
            let base = output.as_ptr() as usize - self.offset;
            assert_eq!(*self.base.get_or_insert(base), base);
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.offset == SECRET_MAX_BYTES {
                return Ok(0);
            }
            let length = output.len().min(37).min(SECRET_MAX_BYTES - self.offset);
            for (index, byte) in output[..length].iter_mut().enumerate() {
                *byte = ((self.offset + index) % 251) as u8;
            }
            self.offset += length;
            Ok(length)
        }
    }
    let mut reader = Fragmented {
        offset: 0,
        base: None,
        interrupted: false,
    };
    let bytes = read_snapshot(&mut reader, SECRET_MAX_BYTES).unwrap();
    assert_eq!(bytes.len(), SECRET_MAX_BYTES);
    assert_eq!(Some(bytes.as_ptr() as usize), reader.base);
    assert!(bytes.capacity() > SECRET_MAX_BYTES);
    assert!(bytes.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
}

#[test]
fn snapshot_reader_limits_growth_and_redacts_partial_read_errors() {
    let mut grown = io::Cursor::new(b"old-snapshot-and-new-data");
    let bytes = read_snapshot(&mut grown, 3).unwrap();
    assert_eq!(&**bytes, b"old-");
    assert_eq!(grown.position(), 4);

    struct FailsAfterPrefix(bool);
    impl Read for FailsAfterPrefix {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if std::mem::replace(&mut self.0, true) {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "synthetic-secret-must-not-appear",
                ));
            }
            output[..6].copy_from_slice(b"secret");
            Ok(6)
        }
    }
    let error = read_snapshot(&mut FailsAfterPrefix(false), 64).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(error.to_string(), "cannot read local input file");
    assert!(read_snapshot(&mut io::empty(), 0).unwrap().is_empty());
}

#[test]
fn public_byte_input_has_an_exact_one_mib_limit() {
    let fixture = Fixture::new();
    fixture.write(&vec![0xff; PUBLIC_MAX_BYTES]);
    assert_eq!(
        read(&fixture.path(), Access::Public).unwrap().len(),
        PUBLIC_MAX_BYTES
    );
    fixture.write(&vec![b'x'; PUBLIC_MAX_BYTES + 1]);
    assert!(read(&fixture.path(), Access::Public).is_err());
    assert!(read(&fixture.0, Access::Public).is_err());
    let error = read(&fixture.0.join("secret-marker-82157"), Access::Public).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert!(!error.to_string().contains("82157"));
}

#[cfg(unix)]
#[test]
fn public_links_and_shared_permissions_do_not_relax_secret_policy() {
    let fixture = Fixture::new();
    fixture.write(b"synthetic public content");
    let symlink = fixture.0.join("symlink");
    let hardlink = fixture.0.join("hardlink");
    std::os::unix::fs::symlink(fixture.path(), &symlink).unwrap();
    fs::hard_link(fixture.path(), &hardlink).unwrap();
    for path in [fixture.path(), symlink, hardlink] {
        assert_eq!(
            read(&path, Access::Public).unwrap().as_slice(),
            b"synthetic public content"
        );
        assert!(read(&path, Access::Secret).is_err());
    }
}

#[cfg(unix)]
#[test]
fn public_symlink_is_resolved_once_to_a_consistent_snapshot() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fixture.write(b"old synthetic snapshot");
    let replacement = fixture.0.join("replacement");
    fs::write(&replacement, b"new synthetic snapshot").unwrap();
    let selected = fixture.0.join("selected");
    symlink(fixture.path(), &selected).unwrap();
    let bytes = read_with(&selected, Access::Public, |stage| {
        if stage == Stage::Inspected {
            fs::remove_file(&selected).unwrap();
            symlink(&replacement, &selected).unwrap();
        }
    })
    .unwrap();
    assert_eq!(bytes.as_slice(), b"old synthetic snapshot");
    assert_eq!(
        read(&selected, Access::Public).unwrap().as_slice(),
        b"new synthetic snapshot"
    );
}

#[cfg(unix)]
#[test]
fn public_target_replacement_and_growth_are_rejected() {
    for stage in [Stage::Inspected, Stage::Opened, Stage::Read] {
        for grow in [true, false] {
            let fixture = Fixture::new();
            fixture.write(b"synthetic public content");
            let result = read_with(&fixture.path(), Access::Public, |at| {
                if at != stage {
                    return;
                }
                if grow {
                    fixture.write(&vec![b'x'; PUBLIC_MAX_BYTES + 1]);
                } else {
                    fs::rename(fixture.path(), fixture.0.join("old")).unwrap();
                    fixture.write(b"different public content");
                }
            });
            assert!(result.is_err());
        }
    }
}

#[cfg(unix)]
#[test]
fn public_fifo_replacement_cannot_stall_open() {
    use std::{
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    const ENV: &str = "GP_PROXY_SYNTHETIC_PUBLIC_FIFO_TEST_DIR";
    if let Some(directory) = std::env::var_os(ENV) {
        let path = PathBuf::from(directory).join("synthetic-public-file");
        let result = read_with(&path, Access::Public, |stage| {
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
    fixture.write(b"synthetic public content");
    let mut running = Running(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "local_file::tests::public_fifo_replacement_cannot_stall_open",
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
    let start = Instant::now();
    loop {
        if let Some(status) = running.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "public input FIFO replacement blocked open"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
