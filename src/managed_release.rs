//! Bounded, stable executable snapshots; hashes identify bytes, not publishers.
#[cfg(unix)]
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
use std::{io, path::Path};

pub const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;

pub fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn parse_release(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let mut result = [0; 32];
    for (slot, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        fn digit(value: u8) -> u8 {
            if value <= b'9' {
                value - b'0'
            } else {
                value - b'a' + 10
            }
        }
        *slot = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    if result == [0; 32] {
        return Err(invalid());
    }
    Ok(result)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid managed executable snapshot",
    )
}
#[cfg(unix)]
fn redact(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "managed executable operation failed")
}

pub fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut state = hash();
    state.update(bytes);
    state
        .finish()
        .as_ref()
        .try_into()
        .expect("fixed SHA-256 output")
}

fn hash() -> Box<dyn rustls::crypto::hash::Context> {
    // Reuse the already locked AWS-LC SHA-256 implementation. This creates
    // no TLS session and accepts no runtime provider selection.
    rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("fixed TLS13 suite")
        .common
        .hash_provider
        .start()
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
#[cfg(unix)]
impl Stamp {
    fn of(meta: &fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.nlink() != 1
            || meta.len() == 0
            || meta.len() > MAX_BINARY_BYTES
            || meta.mode() & 0o7022 != 0
            || meta.mode() & 0o100 == 0
        {
            return Err(invalid());
        }
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        if meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw() {
            return Err(invalid());
        }
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            links: meta.nlink(),
            bytes: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        })
    }
}

/// Keeps the source descriptor pinned across preflight and copying. The caller
/// supplies only an already-owned destination; this type never chooses a path to overwrite.
#[cfg(unix)]
pub struct Source {
    path: PathBuf,
    file: File,
    stamp: Stamp,
    digest: [u8; 32],
}
#[cfg(unix)]
impl Source {
    pub fn open(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        if !path.is_absolute() {
            return Err(invalid());
        }
        let before = Stamp::of(&fs::symlink_metadata(path).map_err(redact)?)?;
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "macos")]
        options.custom_flags(0x4 | 0x100 | 0x20000);
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        options.custom_flags((1 << 11) | (1 << 17) | (1 << 8));
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        options.custom_flags((1 << 11) | (1 << 15) | (1 << 8));
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed executable snapshots are unavailable",
        ));
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            let file = options.open(path).map_err(redact)?;
            if Stamp::of(&file.metadata().map_err(redact)?)? != before {
                return Err(invalid());
            }
            let mut source = Self {
                path: path.to_owned(),
                file,
                stamp: before,
                digest: [0; 32],
            };
            source.verify()?;
            source.digest = source.read_into(&mut io::sink())?;
            Ok(source)
        }
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn len(&self) -> u64 {
        self.stamp.bytes
    }
    pub fn is_empty(&self) -> bool {
        self.stamp.bytes == 0
    }
    pub fn verify(&self) -> io::Result<()> {
        for meta in [
            fs::symlink_metadata(&self.path).map_err(redact)?,
            self.file.metadata().map_err(redact)?,
        ] {
            if Stamp::of(&meta)? != self.stamp {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn read_into(&mut self, destination: &mut impl Write) -> io::Result<[u8; 32]> {
        self.verify()?;
        self.file.seek(SeekFrom::Start(0)).map_err(redact)?;
        let mut buffer = [0; 65536];
        let mut remaining = self.stamp.bytes;
        let mut digest = hash();
        while remaining != 0 {
            let limit = (remaining as usize).min(buffer.len());
            let size = self.file.read(&mut buffer[..limit]).map_err(redact)?;
            if size == 0 {
                return Err(invalid());
            }
            digest.update(&buffer[..size]);
            destination.write_all(&buffer[..size]).map_err(redact)?;
            remaining -= size as u64;
        }
        if self.file.read(&mut buffer[..1]).map_err(redact)? != 0 {
            return Err(invalid());
        }
        self.verify()?;
        digest.finish().as_ref().try_into().map_err(|_| invalid())
    }
    pub fn copy_into(&mut self, destination: &mut impl Write) -> io::Result<()> {
        let digest = self.read_into(destination)?;
        if digest != self.digest {
            return Err(invalid());
        }
        Ok(())
    }
}

pub fn verify_running(binary: &Path, expected: &[u8; 32]) -> io::Result<()> {
    #[cfg(unix)]
    {
        if std::env::current_exe().map_err(redact)? != binary {
            return Err(invalid());
        }
        if Source::open(binary)?.digest() != *expected {
            return Err(invalid());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (binary, expected);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed executable verification is unavailable",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_sha256_vectors_and_strict_release_identity() {
        for (bytes, expected) in [
            (
                b"".as_slice(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".as_slice(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ] {
            let digest = digest_bytes(bytes);
            assert_eq!(hexadecimal(&digest), expected);
            assert_eq!(parse_release(expected).unwrap(), digest);
        }
        for invalid in [
            String::new(),
            "0".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "x".repeat(64),
            format!("{}\n", "a".repeat(64)),
        ] {
            assert!(parse_release(&invalid).is_err());
        }
    }

    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    mod files {
        use super::*;
        use std::{
            os::unix::fs::{symlink, DirBuilderExt, FileExt, MetadataExt, PermissionsExt},
            process::{Child, Command, ExitStatus, Stdio},
            thread,
            time::{Duration, Instant},
        };

        struct Fixture(PathBuf);
        impl Fixture {
            fn new() -> Self {
                let mut random = [0; 8];
                getrandom::fill(&mut random).unwrap();
                // macOS inherits the parent directory's group. The user's
                // temporary directory permits this user to retain SGID for the
                // rejection test; /tmp's wheel group silently clears that bit.
                let path = std::env::temp_dir().join(format!("gp-source-{}", hexadecimal(&random)));
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                Self(fs::canonicalize(path).unwrap())
            }
            fn file(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
                let path = self.0.join(name);
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                path
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        struct Process(Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        fn wait(process: &mut Process) -> ExitStatus {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    return status;
                }
                assert!(
                    Instant::now() < deadline,
                    "owned source helper exceeded deadline"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }

        #[test]
        fn genuine_file_snapshot_copies_exact_bytes_and_matches_known_digest() {
            let f = Fixture::new();
            let path = f.file("program", b"abc", 0o755);
            let mut source = Source::open(&path).unwrap();
            let mut bytes = Vec::new();
            assert_eq!(source.len(), 3);
            assert!(!source.is_empty());
            assert_eq!(
                hexadecimal(&source.digest()),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
            source.copy_into(&mut bytes).unwrap();
            assert_eq!(bytes, b"abc");
            source.verify().unwrap();
            let mut again = Vec::new();
            source.copy_into(&mut again).unwrap();
            assert_eq!(again, bytes);
        }

        #[test]
        fn links_nonregular_empty_and_unsafe_modes_are_rejected_without_altering_inputs() {
            let f = Fixture::new();
            let original = f.file("original", b"synthetic executable", 0o700);
            let symbolic = f.0.join("symbolic");
            symlink(&original, &symbolic).unwrap();
            assert!(Source::open(&symbolic).is_err());
            let hard = f.0.join("hard");
            fs::hard_link(&original, &hard).unwrap();
            assert!(Source::open(&hard).is_err());
            assert!(Source::open(&original).is_err());
            fs::remove_file(hard).unwrap();
            assert!(Source::open(&f.0).is_err());
            assert!(Source::open(Path::new("relative-program")).is_err());
            let empty = f.file("empty", b"", 0o700);
            assert!(Source::open(&empty).is_err());
            for mode in [0o600, 0o720, 0o702, 0o722, 0o4700, 0o2700, 0o1700] {
                fs::set_permissions(&original, fs::Permissions::from_mode(mode)).unwrap();
                assert_eq!(
                    fs::symlink_metadata(&original).unwrap().mode() & 0o7777,
                    mode,
                    "fixture must actually retain unsafe mode"
                );
                assert!(Source::open(&original).is_err(), "unsafe mode {mode:o}");
                assert_eq!(fs::read(&original).unwrap(), b"synthetic executable");
            }
            fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(Source::open(&original).is_ok());
        }

        #[test]
        fn fifo_reject_child() {
            let Some(path) = std::env::var_os("GP_SOURCE_TEST_FIFO") else {
                return;
            };
            assert!(Source::open(Path::new(&path)).is_err());
        }

        #[test]
        fn actual_fifo_is_rejected_without_waiting_for_a_writer() {
            let f = Fixture::new();
            let fifo = f.0.join("fifo");
            let mut create = Process(
                Command::new("/usr/bin/mkfifo")
                    .arg(&fifo)
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            assert!(wait(&mut create).success());
            fs::set_permissions(&fifo, fs::Permissions::from_mode(0o700)).unwrap();
            let metadata = fs::symlink_metadata(&fifo).unwrap();
            let inode = metadata.ino();
            use std::os::unix::fs::FileTypeExt;
            assert!(metadata.file_type().is_fifo());
            let mut probe = Process(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "managed_release::tests::files::fifo_reject_child",
                        "--nocapture",
                    ])
                    .env_clear()
                    .env("GP_SOURCE_TEST_FIFO", &fifo)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            assert!(wait(&mut probe).success());
            assert_eq!(fs::symlink_metadata(&fifo).unwrap().ino(), inode);
        }

        #[test]
        fn oversized_sparse_executable_is_rejected_before_copying() {
            let f = Fixture::new();
            let path = f.file("large", b"x", 0o700);
            let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len(MAX_BINARY_BYTES + 1).unwrap();
            let before = file.metadata().unwrap();
            assert_eq!(before.len(), MAX_BINARY_BYTES + 1);
            assert!(Source::open(&path).is_err());
            let after = file.metadata().unwrap();
            assert_eq!((after.ino(), after.len()), (before.ino(), before.len()));
            let mut first = [0];
            File::open(&path)
                .unwrap()
                .read_exact_at(&mut first, 0)
                .unwrap();
            assert_eq!(first, [b'x']);
        }

        struct MutatingWriter<'a> {
            path: &'a Path,
            saved: &'a Path,
            original: &'a [u8],
            replace: bool,
            changed: bool,
            output: Vec<u8>,
            max_slice: usize,
        }
        impl Write for MutatingWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.max_slice = self.max_slice.max(bytes.len());
                if !self.changed {
                    self.changed = true;
                    if self.replace {
                        fs::rename(self.path, self.saved)?;
                        fs::write(self.path, self.original)?;
                        fs::set_permissions(self.path, fs::Permissions::from_mode(0o700))?;
                    } else {
                        // Change already-read bytes without changing length.
                        // The eventual copy digest still matches the snapshot,
                        // so the identity/metadata postcheck must catch it.
                        thread::sleep(Duration::from_millis(2));
                        fs::OpenOptions::new()
                            .write(true)
                            .open(self.path)?
                            .write_all_at(b"!", 0)?;
                    }
                }
                self.output.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        #[test]
        fn rewrite_or_same_bytes_replacement_during_stream_copy_invalidates_snapshot() {
            for replace in [false, true] {
                let f = Fixture::new();
                let original = vec![b'q'; 131_089];
                let path = f.file("program", &original, 0o700);
                let mut source = Source::open(&path).unwrap();
                let expected = source.digest();
                let saved = f.0.join("original");
                let mut destination = MutatingWriter {
                    path: &path,
                    saved: &saved,
                    original: &original,
                    replace,
                    changed: false,
                    output: Vec::new(),
                    max_slice: 0,
                };
                assert!(source.copy_into(&mut destination).is_err());
                assert!(destination.changed);
                assert_eq!(destination.output, original);
                assert_eq!(digest_bytes(&destination.output), expected);
                assert!(destination.max_slice <= 65536);
                assert!(source.verify().is_err());
                if replace {
                    assert_eq!(fs::read(&path).unwrap(), original);
                    assert_eq!(fs::read(&saved).unwrap(), original);
                } else {
                    assert_eq!(fs::read(&path).unwrap()[0], b'!');
                }
            }
        }

        #[test]
        fn change_before_copy_writes_nothing_and_destination_failure_never_retries() {
            let f = Fixture::new();
            let path = f.file("program", b"synthetic original", 0o700);
            let mut source = Source::open(&path).unwrap();
            fs::rename(&path, f.0.join("old")).unwrap();
            f.file("program", b"synthetic original", 0o700);
            let mut destination = Vec::new();
            assert!(source.copy_into(&mut destination).is_err());
            assert!(destination.is_empty());

            struct FailingWriter {
                bytes: usize,
                calls: usize,
            }
            impl Write for FailingWriter {
                fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                    self.calls += 1;
                    if self.bytes == 0 {
                        let count = bytes.len().min(37);
                        self.bytes += count;
                        Ok(count)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "synthetic destination failure",
                        ))
                    }
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            let original = vec![b's'; 131_089];
            let path = f.file("stable", &original, 0o700);
            let mut source = Source::open(&path).unwrap();
            let mut destination = FailingWriter { bytes: 0, calls: 0 };
            let error = source.copy_into(&mut destination).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(destination.bytes, 37);
            assert_eq!(destination.calls, 2);
            assert!(!error.to_string().contains("synthetic destination"));
            source.verify().unwrap();
            let mut retry = Vec::new();
            source.copy_into(&mut retry).unwrap();
            assert_eq!(retry, original);
        }
    }
}
