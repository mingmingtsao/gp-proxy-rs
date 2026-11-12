//! Persistent positive PAC classification, never current tunnel authorization.
//! A lifetime sidecar lock serializes writers; the data file is replaced atomically.
use crate::{gp::GatewayDomainRule, policy::Policy};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_RULES: usize = 16384;
const MARKER: &[u8] = b"gp-proxy-pac-history-v1\n";

pub struct PacHistory {
    path: PathBuf,
    lock_path: PathBuf,
    // Never unlink this file: deleting a locked inode would permit a new writer.
    lock: File,
    state: Mutex<Policy>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    domains: Vec<String>,
    networks: Vec<IpNet>,
    gateway_domains: Vec<StoredDomain>,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "domain",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum StoredDomain {
    Exact(String),
    Subdomains(String),
}

impl PacHistory {
    pub fn open(path: &Path, initial: &Policy) -> io::Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| invalid("invalid PAC history path"))?;
        let parent = fs::canonicalize(parent(path))
            .map_err(|error| redact(error, "cannot locate PAC history directory"))?;
        let path = parent.join(name);
        let lock_path = sidecar(&path);
        let mut lock = match private_options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_regular(&lock_path, true, MARKER.len())?
            }
            Err(error) => return Err(redact(error, "cannot create PAC history lock")),
        };
        validate_metadata(&lock.metadata()?, MARKER.len())?;
        lock.try_lock().map_err(|error| {
            let error: io::Error = error.into();
            redact(error, "PAC history is locked or cannot be locked")
        })?;
        verify_identity(&lock_path, &lock, MARKER.len())?;
        let initialized = read_marker(&mut lock)?;
        let previous = load_history(&path, initialized)?;
        let merged = previous.merge_classification(initial)?;
        let bytes = encode(&merged)?;
        atomic_replace(&path, &bytes)?;
        // The marker is written only after the first complete data file is
        // durable. A crash with an empty sidecar can safely resume initialization.
        if !initialized {
            lock.rewind()
                .map_err(|error| redact(error, "cannot update PAC history marker"))?;
            lock.write_all(MARKER)
                .map_err(|error| redact(error, "cannot update PAC history marker"))?;
            lock.sync_all()
                .map_err(|error| redact(error, "cannot sync PAC history marker"))?;
            sync_directory(parent.as_path())?;
        }
        Ok(Self {
            path,
            lock_path,
            lock,
            state: Mutex::new(merged),
        })
    }

    /// Does not create a lock or data file, and can read while the writer runs.
    /// Atomic replacement guarantees a complete old or new data snapshot.
    pub fn read(path: &Path) -> io::Result<Policy> {
        let initialized = marker_present(path)?;
        let policy = load_history(path, initialized)?;
        // An empty startup marker may have become initialized between the first
        // read and observing a missing file. Do not declare an empty scope then.
        if !initialized
            && !path
                .try_exists()
                .map_err(|error| redact(error, "cannot inspect PAC history"))?
            && marker_present(path)?
        {
            return load_history(path, true);
        }
        Ok(policy)
    }

    /// Persist the expanded positive classification before exposing it to PAC.
    /// Neither on-disk history nor this return value is an egress capability.
    pub fn remember(&self, current: &Policy) -> io::Result<Policy> {
        self.remember_with(current, atomic_replace)
    }

    fn remember_with(
        &self,
        current: &Policy,
        commit: impl FnOnce(&Path, &[u8]) -> io::Result<()>,
    ) -> io::Result<Policy> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("PAC history state is unavailable"))?;
        verify_identity(&self.lock_path, &self.lock, MARKER.len())?;
        let disk = load_history(&self.path, true)?;
        // A prior rename can succeed even if directory fsync fails. Merge the
        // disk as well as memory so retrying cannot erase that persisted union.
        let merged = state
            .merge_classification(&disk)?
            .merge_classification(current)?;
        let bytes = encode(&merged)?;
        commit(&self.path, &bytes)?;
        *state = merged.clone();
        Ok(merged)
    }
}

fn sidecar(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    name.into()
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn empty() -> io::Result<Policy> {
    Policy::new(Vec::new(), Vec::new())
}

fn marker_present(path: &Path) -> io::Result<bool> {
    match open_regular(&sidecar(path), false, MARKER.len()) {
        Ok(mut file) => match file.try_lock_shared() {
            Ok(()) => read_marker(&mut file),
            // Do not read bytes covered by another descriptor's exclusive OS
            // lock (notably Windows LockFileEx). A live writer is sufficient
            // reason to forbid a missing history file being treated as empty.
            Err(fs::TryLockError::WouldBlock) => Ok(true),
            Err(fs::TryLockError::Error(error)) => {
                Err(redact(error, "cannot inspect PAC history lock"))
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn read_marker(file: &mut File) -> io::Result<bool> {
    file.rewind()
        .map_err(|error| redact(error, "cannot read PAC history marker"))?;
    let bytes = read_bounded(file, MARKER.len())?;
    match bytes.as_slice() {
        [] => Ok(false),
        MARKER => Ok(true),
        _ => Err(invalid("invalid PAC history initialization marker")),
    }
}

fn load_history(path: &Path, initialized: bool) -> io::Result<Policy> {
    let mut file = match open_regular(path, false, MAX_BYTES) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !initialized => return empty(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(invalid("initialized PAC history is missing"))
        }
        Err(error) => return Err(error),
    };
    let source = read_bounded(&mut file, MAX_BYTES)?;
    let stored: Stored =
        serde_json::from_slice(&source).map_err(|_| invalid("invalid PAC history JSON"))?;
    if stored.version != 1 {
        return Err(invalid("unsupported PAC history version"));
    }
    if stored.domains.len() + stored.networks.len() + stored.gateway_domains.len() > MAX_RULES {
        return Err(invalid("PAC history rule limit exceeded"));
    }
    let gateway = stored
        .gateway_domains
        .into_iter()
        .map(|rule| match rule {
            StoredDomain::Exact(domain) => GatewayDomainRule::Exact(domain),
            StoredDomain::Subdomains(domain) => GatewayDomainRule::Subdomains(domain),
        })
        .collect();
    Policy::new(stored.domains, stored.networks)
        .and_then(|policy| policy.with_gateway_domains(gateway, Vec::new()))
        .map_err(|_| invalid("invalid PAC history destination rule"))
}

fn encode(policy: &Policy) -> io::Result<Vec<u8>> {
    if policy.domains().len() + policy.networks().len() + policy.gateway_domains().len() > MAX_RULES
    {
        return Err(invalid("PAC history rule limit exceeded"));
    }
    let stored = Stored {
        version: 1,
        domains: policy.domains().to_vec(),
        networks: policy.networks().to_vec(),
        gateway_domains: policy
            .gateway_domains()
            .iter()
            .map(|rule| match rule {
                GatewayDomainRule::Exact(domain) => StoredDomain::Exact(domain.clone()),
                GatewayDomainRule::Subdomains(domain) => StoredDomain::Subdomains(domain.clone()),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&stored).map_err(|_| invalid("cannot encode PAC history"))?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid("PAC history exceeds 1 MiB limit"));
    }
    Ok(bytes)
}

fn private_options() -> OpenOptions {
    let options = OpenOptions::new();
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = options;
        options.mode(0o600);
        options
    };
    options
}

fn validate_metadata(metadata: &Metadata, limit: usize) -> io::Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit as u64 {
        return Err(invalid(
            "PAC history files must be bounded regular non-symlink files",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PAC history files must have private permissions",
            ));
        }
        if metadata.nlink() != 1 {
            return Err(invalid("PAC history files must not have hard links"));
        }
    }
    Ok(())
}

fn verify_identity(path: &Path, file: &File, limit: usize) -> io::Result<()> {
    let named = fs::symlink_metadata(path)
        .map_err(|error| redact(error, "cannot inspect PAC history file"))?;
    let opened = file
        .metadata()
        .map_err(|error| redact(error, "cannot inspect PAC history descriptor"))?;
    validate_metadata(&named, limit)?;
    validate_metadata(&opened, limit)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if named.dev() != opened.dev() || named.ino() != opened.ino() {
            return Err(invalid("PAC history file changed during access"));
        }
    }
    Ok(())
}

fn open_regular(path: &Path, writable: bool, limit: usize) -> io::Result<File> {
    open_regular_with(path, writable, limit, || Ok(()))
}

fn open_regular_with(
    path: &Path,
    writable: bool,
    limit: usize,
    after_inspection: impl FnOnce() -> io::Result<()>,
) -> io::Result<File> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| redact(error, "cannot inspect PAC history file"))?;
    validate_metadata(&before, limit)?;
    after_inspection()?;
    // A checked regular file can be replaced before open. In particular, a
    // read-only FIFO open must not wait for a writer before we can reject it.
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    let mut options = crate::private_fs::options();
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    let mut options = OpenOptions::new();
    let file = options
        .read(true)
        .write(writable)
        .open(path)
        .map_err(|error| redact(error, "cannot open PAC history file"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file
            .metadata()
            .map_err(|error| redact(error, "cannot inspect PAC history descriptor"))?;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(invalid("PAC history file changed before opening"));
        }
    }
    verify_identity(path, &file, limit)?;
    Ok(file)
}

fn read_bounded(file: &mut File, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| redact(error, "cannot read PAC history file"))?;
    if bytes.len() > limit {
        return Err(invalid("PAC history file exceeds size limit"));
    }
    Ok(bytes)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_replace_with(path, bytes, || Ok(()))
}

fn atomic_replace_with(
    path: &Path,
    bytes: &[u8],
    before_rename: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    // Validate an existing destination before replacing it. This is protection
    // against accidental misuse, not a same-UID adversarial directory guarantee.
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_metadata(&metadata, MAX_BYTES)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(redact(error, "cannot inspect PAC history destination")),
    }
    struct Temporary {
        path: PathBuf,
        remove: bool,
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            if self.remove {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
    let filename = path
        .file_name()
        .ok_or_else(|| invalid("invalid PAC history path"))?;
    let (mut file, mut temporary) = (0..16)
        .find_map(|_| {
            let mut name = filename.to_owned();
            name.push(format!(
                ".tmp-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let temp = parent(path).join(name);
            match private_options().write(true).create_new(true).open(&temp) {
                Ok(file) => Some(Ok((
                    file,
                    Temporary {
                        path: temp,
                        remove: true,
                    },
                ))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(redact(
                    error,
                    "cannot create PAC history temporary file",
                ))),
            }
        })
        .unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "cannot allocate PAC history temporary file",
            ))
        })?;
    file.write_all(bytes)
        .map_err(|error| redact(error, "cannot write PAC history"))?;
    file.sync_all()
        .map_err(|error| redact(error, "cannot sync PAC history"))?;
    before_rename()?;
    drop(file);
    fs::rename(&temporary.path, path)
        .map_err(|error| redact(error, "cannot replace PAC history"))?;
    temporary.remove = false;
    sync_directory(parent(path))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| redact(error, "cannot sync PAC history directory"))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn redact(error: io::Error, message: &'static str) -> io::Error {
    io::Error::new(error.kind(), message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "gp-proxy-pac-history-test-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("scope.json")
        }
        fn write(&self, bytes: &[u8]) {
            write_private(&self.path(), bytes);
        }
        fn entries(&self) -> usize {
            fs::read_dir(&self.0).unwrap().count()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn write_private(path: &Path, bytes: &[u8]) {
        private_options()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn policy(domain: &str) -> Policy {
        Policy::new(vec![domain.into()], Vec::new()).unwrap()
    }

    fn isolated_lock_lifetime_test(name: &str) -> bool {
        use std::{
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };
        const CHILD_TEST: &str = "GP_SYNTHETIC_PAC_LOCK_LIFETIME_TEST";
        let test = format!("pac_history::tests::{name}");
        if std::env::var_os(CHILD_TEST).as_deref() == Some(std::ffi::OsStr::new(&test)) {
            return false;
        }

        // The fixture must be created after exec: unrelated parallel tests may
        // fork while a lifetime lock is held, inheriting its file description
        // until their exec/exit. That is valid ownership, not a failed close.
        struct Running(Child);
        impl Drop for Running {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &test, "--test-threads=1", "--nocapture"])
            .env_clear()
            .env(CHILD_TEST, &test)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        // Keep only OS temporary-directory settings needed by Fixture::new.
        for key in ["TMPDIR", "TMP", "TEMP", "SystemRoot"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let mut process = Running(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = process.0.try_wait().unwrap() {
                assert!(status.success(), "isolated PAC lock test {name}: {status}");
                return true;
            }
            assert!(
                Instant::now() < deadline,
                "isolated PAC lock test {name} timed out"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn absent_read_is_empty_and_does_not_create_any_file() {
        let fixture = Fixture::new();
        assert_eq!(PacHistory::read(&fixture.path()).unwrap(), empty().unwrap());
        assert_eq!(fixture.entries(), 0);
    }

    #[test]
    fn restart_remembers_positive_scope_without_preserving_exclusions() {
        if isolated_lock_lifetime_test(
            "restart_remembers_positive_scope_without_preserving_exclusions",
        ) {
            return;
        }
        let fixture = Fixture::new();
        let original = Policy::new(
            vec!["Corp.Example.".into()],
            vec!["10.2.3.4/8".parse().unwrap()],
        )
        .unwrap()
        .with_gateway_domains(
            vec![
                GatewayDomainRule::Exact("jira.partner.example".into()),
                GatewayDomainRule::Subdomains("service.example".into()),
            ],
            vec![GatewayDomainRule::Exact("secret.corp.example".into())],
        )
        .unwrap()
        .with_excludes(vec!["10.9.0.0/16".parse().unwrap()]);
        let history = PacHistory::open(&fixture.path(), &original).unwrap();
        let next = policy("new.example");
        let remembered = history.remember(&next).unwrap();
        assert!(remembered.allows_host("secret.corp.example"));
        assert!(remembered.allows_host("10.9.2.3"));
        assert!(remembered.allows_host("jira.partner.example"));
        assert!(!remembered.allows_host("extra.jira.partner.example"));
        assert!(remembered.allows_host("api.service.example"));
        assert!(!remembered.allows_host("service.example"));
        // A read-only caller can export a complete snapshot with a live writer.
        assert_eq!(PacHistory::read(&fixture.path()).unwrap(), remembered);
        drop(history);
        assert!(sidecar(&fixture.path()).is_file());
        let reopened = PacHistory::open(&fixture.path(), &next).unwrap();
        assert_eq!(reopened.remember(&empty().unwrap()).unwrap(), remembered);
        let stored = fs::read_to_string(fixture.path()).unwrap();
        assert!(!stored.contains("secret.corp.example"));
        assert!(!stored.contains("excludes"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [fixture.path(), sidecar(&fixture.path())] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn exclusive_writer_lock_survives_shared_owner_and_threads_union_updates() {
        if isolated_lock_lifetime_test(
            "exclusive_writer_lock_survives_shared_owner_and_threads_union_updates",
        ) {
            return;
        }
        let fixture = Fixture::new();
        let history =
            Arc::new(PacHistory::open(&fixture.path(), &policy("original.example")).unwrap());
        let retained = history.clone();
        let mut workers = Vec::new();
        for id in 0..8 {
            let history = history.clone();
            workers.push(std::thread::spawn(move || {
                history
                    .remember(&policy(&format!("worker{id}.example")))
                    .unwrap()
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        drop(history);
        match PacHistory::open(&fixture.path(), &empty().unwrap()) {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
            Ok(_) => panic!("second writer acquired a live lock"),
        }
        let stored = PacHistory::read(&fixture.path()).unwrap();
        assert!(stored.allows_host("original.example"));
        for id in 0..8 {
            assert!(stored.allows_host(&format!("worker{id}.example")));
        }
        // On Unix, try_clone retains the same open file description as fork.
        // Dropping the final Arc must not explicitly unlock that shared lease.
        #[cfg(unix)]
        let inherited = retained.lock.try_clone().unwrap();
        drop(retained);
        #[cfg(unix)]
        {
            match PacHistory::open(&fixture.path(), &empty().unwrap()) {
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
                Ok(_) => panic!("writer acquired a lock still owned by a cloned descriptor"),
            }
            drop(inherited);
        }
        let reopened = PacHistory::open(&fixture.path(), &empty().unwrap()).unwrap();
        assert_eq!(reopened.remember(&empty().unwrap()).unwrap(), stored);
    }

    #[test]
    fn malformed_version_unknown_fields_and_illegal_hosts_fail_without_rewrite() {
        let fixture = Fixture::new();
        for source in [
            "",
            "{",
            "null",
            r#"{"version":2,"domains":[],"networks":[],"gateway_domains":[]}"#,
            r#"{"version":1,"version":1,"domains":[],"networks":[],"gateway_domains":[]}"#,
            r#"{"version":1,"domains":[],"networks":[],"gateway_domains":[],"extra":true}"#,
            r#"{"version":1,"domains":["bad host.example"],"networks":[],"gateway_domains":[]}"#,
            r#"{"version":1,"domains":[],"networks":[],"gateway_domains":[{"kind":"exact","domain":"*.example"}]}"#,
            r#"{"version":1,"domains":[],"networks":[],"gateway_domains":[{"kind":"subdomains","domain":"corp.example","port":443}]}"#,
        ] {
            fixture.write(source.as_bytes());
            assert!(PacHistory::read(&fixture.path()).is_err());
            assert!(PacHistory::open(&fixture.path(), &empty().unwrap()).is_err());
            assert_eq!(fs::read(fixture.path()).unwrap(), source.as_bytes());
        }
    }

    #[test]
    fn input_size_and_rule_counts_reject_instead_of_truncating() {
        let fixture = Fixture::new();
        fixture.write(&vec![b' '; MAX_BYTES + 1]);
        assert!(PacHistory::read(&fixture.path()).is_err());
        let excessive = Stored {
            version: 1,
            domains: vec!["corp.example".into(); MAX_RULES + 1],
            networks: Vec::new(),
            gateway_domains: Vec::new(),
        };
        fixture.write(&serde_json::to_vec(&excessive).unwrap());
        assert!(PacHistory::read(&fixture.path()).is_err());
        let long = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(60));
        let large = Policy::new(
            (0..6000).map(|index| format!("n{index}.{long}")).collect(),
            Vec::new(),
        )
        .unwrap();
        assert!(encode(&large).is_err());
    }

    #[test]
    fn initialized_history_removal_fails_both_reader_and_writer() {
        if isolated_lock_lifetime_test("initialized_history_removal_fails_both_reader_and_writer") {
            return;
        }
        let fixture = Fixture::new();
        let history = PacHistory::open(&fixture.path(), &policy("old.example")).unwrap();
        fs::remove_file(fixture.path()).unwrap();
        assert!(PacHistory::read(&fixture.path()).is_err());
        assert!(history.remember(&policy("new.example")).is_err());
        assert_eq!(*history.state.lock().unwrap(), policy("old.example"));
        drop(history);
        match PacHistory::open(&fixture.path(), &empty().unwrap()) {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("writer recreated an initialized history that was removed"),
        }
        assert_eq!(fs::read(sidecar(&fixture.path())).unwrap(), MARKER);
    }

    #[test]
    fn interrupted_initialization_with_empty_lock_preserves_any_completed_history() {
        for data_already_written in [false, true] {
            let fixture = Fixture::new();
            write_private(&sidecar(&fixture.path()), &[]);
            if data_already_written {
                fixture.write(&encode(&policy("old.example")).unwrap());
            }
            let expected = if data_already_written {
                policy("old.example")
            } else {
                empty().unwrap()
            };
            assert_eq!(PacHistory::read(&fixture.path()).unwrap(), expected);
            let history = PacHistory::open(&fixture.path(), &policy("new.example")).unwrap();
            assert_eq!(
                history.remember(&empty().unwrap()).unwrap(),
                expected
                    .merge_classification(&policy("new.example"))
                    .unwrap()
            );
            drop(history);
            assert_eq!(fs::read(sidecar(&fixture.path())).unwrap(), MARKER);
        }
    }

    #[test]
    fn readonly_export_does_not_return_empty_during_writer_initialization() {
        let fixture = Fixture::new();
        let lock = private_options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(sidecar(&fixture.path()))
            .unwrap();
        lock.try_lock().unwrap();
        assert!(PacHistory::read(&fixture.path()).is_err());
        // Once the complete file exists, an empty marker under the live lock
        // does not prevent a safe snapshot from being exported.
        fixture.write(&encode(&policy("ready.example")).unwrap());
        assert_eq!(
            PacHistory::read(&fixture.path()).unwrap(),
            policy("ready.example")
        );
    }

    #[test]
    fn failed_write_keeps_old_disk_memory_and_removes_temporary_file() {
        let fixture = Fixture::new();
        let history = PacHistory::open(&fixture.path(), &policy("old.example")).unwrap();
        let before = fs::read(fixture.path()).unwrap();
        let result = history.remember_with(&policy("new.example"), |path, bytes| {
            atomic_replace_with(path, bytes, || {
                Err(io::Error::other("synthetic pre-rename failure"))
            })
        });
        assert!(result.is_err());
        assert_eq!(*history.state.lock().unwrap(), policy("old.example"));
        assert_eq!(fs::read(fixture.path()).unwrap(), before);
        assert_eq!(fixture.entries(), 2);
        assert_eq!(
            PacHistory::read(&fixture.path()).unwrap(),
            policy("old.example")
        );
    }

    #[test]
    fn reported_failure_after_rename_does_not_lose_persisted_scope_on_retry() {
        let fixture = Fixture::new();
        let history = PacHistory::open(&fixture.path(), &policy("old.example")).unwrap();
        let result = history.remember_with(&policy("durable.example"), |path, bytes| {
            atomic_replace(path, bytes)?;
            Err(io::Error::other("synthetic error after successful rename"))
        });
        assert!(result.is_err());
        assert_eq!(*history.state.lock().unwrap(), policy("old.example"));
        let stored = history.remember(&policy("next.example")).unwrap();
        for domain in ["old.example", "durable.example", "next.example"] {
            assert!(stored.allows_host(domain));
        }
        assert_eq!(stored, PacHistory::read(&fixture.path()).unwrap());
    }

    #[test]
    fn nonregular_paths_and_invalid_lock_marker_fail_closed() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.path()).unwrap();
        assert!(PacHistory::read(&fixture.path()).is_err());
        assert!(PacHistory::open(&fixture.path(), &empty().unwrap()).is_err());
        fs::remove_dir(fixture.path()).unwrap();
        write_private(&sidecar(&fixture.path()), b"incomplete");
        assert!(PacHistory::read(&fixture.path()).is_err());
        assert!(PacHistory::open(&fixture.path(), &empty().unwrap()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_hardlinks_and_public_permissions_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let fixture = Fixture::new();
        let original = fixture.0.join("original");
        write_private(&original, &encode(&policy("original.example")).unwrap());
        symlink(&original, fixture.path()).unwrap();
        assert!(PacHistory::read(&fixture.path()).is_err());
        assert!(PacHistory::open(&fixture.path(), &empty().unwrap()).is_err());
        fs::remove_file(fixture.path()).unwrap();
        fs::hard_link(&original, fixture.path()).unwrap();
        assert!(PacHistory::read(&fixture.path()).is_err());
        fs::remove_file(fixture.path()).unwrap();
        fixture.write(&encode(&policy("private.example")).unwrap());
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(PacHistory::read(&fixture.path()).is_err());
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(sidecar(&fixture.path())).unwrap();
        symlink(&original, sidecar(&fixture.path())).unwrap();
        assert!(PacHistory::read(&fixture.path()).is_err());
        assert!(PacHistory::open(&fixture.path(), &empty().unwrap()).is_err());
    }

    #[test]
    fn checked_regular_history_and_marker_open_without_truncation() {
        for marker in [false, true] {
            for writable in [false, true] {
                let fixture = Fixture::new();
                let path = if marker {
                    sidecar(&fixture.path())
                } else {
                    fixture.path()
                };
                let bytes = if marker {
                    MARKER.to_vec()
                } else {
                    encode(&policy("unchanged.example")).unwrap()
                };
                let limit = if marker { MARKER.len() } else { MAX_BYTES };
                write_private(&path, &bytes);
                let mut file = open_regular(&path, writable, limit).unwrap();
                assert_eq!(file.stream_position().unwrap(), 0);
                assert_eq!(read_bounded(&mut file, limit).unwrap(), bytes);
                drop(file);
                assert_eq!(fs::read(path).unwrap(), bytes);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn checked_file_replacements_are_rejected_without_touching_either_inode() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        fn stamp(path: &Path) -> (u64, u64, u32, u64, u64) {
            let metadata = fs::symlink_metadata(path).unwrap();
            (
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.nlink(),
                metadata.len(),
            )
        }
        for marker in [false, true] {
            for writable in [false, true] {
                for replacement in ["regular", "symlink", "hardlink", "directory", "public"] {
                    let fixture = Fixture::new();
                    let path = if marker {
                        sidecar(&fixture.path())
                    } else {
                        fixture.path()
                    };
                    let parked = fixture.0.join("inspected-original");
                    let bytes = if marker {
                        MARKER.to_vec()
                    } else {
                        encode(&policy("unchanged.example")).unwrap()
                    };
                    let limit = if marker { MARKER.len() } else { MAX_BYTES };
                    write_private(&path, &bytes);
                    let mut installed = None;
                    let result = open_regular_with(&path, writable, limit, || {
                        // Retain the inspected inode, so the replacement cannot
                        // coincidentally receive the same recycled inode number.
                        fs::rename(&path, &parked)?;
                        match replacement {
                            "regular" | "public" => {
                                write_private(&path, &bytes);
                                assert_ne!(stamp(&path).1, stamp(&parked).1);
                                if replacement == "public" {
                                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
                                }
                            }
                            "symlink" => symlink(&parked, &path)?,
                            "hardlink" => fs::hard_link(&parked, &path)?,
                            "directory" => fs::create_dir(&path)?,
                            _ => unreachable!(),
                        }
                        installed = Some((stamp(&path), stamp(&parked)));
                        Ok(())
                    });
                    assert!(
                        result.is_err(),
                        "replacement accepted: marker={marker} writable={writable} {replacement}"
                    );
                    assert_eq!(installed.unwrap(), (stamp(&path), stamp(&parked)));
                    assert_eq!(fs::read(&parked).unwrap(), bytes);
                    if matches!(replacement, "regular" | "public") {
                        assert_eq!(fs::read(&path).unwrap(), bytes);
                    }
                }
            }
        }
    }

    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[test]
    fn checked_history_and_marker_fifo_swaps_never_wait_for_a_writer() {
        #[cfg(target_os = "linux")]
        use rustix::fs::{mkfifoat, Mode, CWD};
        use std::{
            os::unix::{fs::FileTypeExt, process::ExitStatusExt},
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };
        const DIRECTORY: &str = "GP_SYNTHETIC_PAC_FIFO_DIRECTORY";
        const MODE: &str = "GP_SYNTHETIC_PAC_FIFO_MODE";
        const READY: &[u8] = b"inspected-regular-then-installed-fifo";
        if let Some(directory) = std::env::var_os(DIRECTORY) {
            let directory = PathBuf::from(directory);
            let (marker, writable) = match std::env::var(MODE).unwrap().as_str() {
                "history" => (false, false),
                "marker" => (true, false),
                "history-writable" => (false, true),
                "marker-writable" => (true, true),
                _ => panic!("unknown synthetic FIFO mode"),
            };
            let history = directory.join("scope.json");
            let path = if marker { sidecar(&history) } else { history };
            let limit = if marker { MARKER.len() } else { MAX_BYTES };
            let result = open_regular_with(&path, writable, limit, || {
                fs::remove_file(&path)?;
                #[cfg(target_os = "linux")]
                mkfifoat(CWD, &path, Mode::RUSR | Mode::WUSR)?;
                // rustix 1.1.6 does not expose mkfifoat on Apple targets.
                #[cfg(target_os = "macos")]
                {
                    let mut fifo = Running(
                        Command::new("/usr/bin/mkfifo")
                            .args(["-m", "600"])
                            .arg(&path)
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .spawn()?,
                    );
                    let deadline = Instant::now() + Duration::from_secs(1);
                    loop {
                        if let Some(status) = fifo.0.try_wait()? {
                            fifo.0.wait()?;
                            if !status.success() {
                                return Err(io::Error::other("cannot create synthetic PAC FIFO"));
                            }
                            break;
                        }
                        if Instant::now() >= deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "synthetic PAC FIFO creation timed out",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                let stage = directory.join("ready.next");
                let mut ready = private_options()
                    .create_new(true)
                    .write(true)
                    .open(&stage)?;
                ready.write_all(READY)?;
                ready.sync_all()?;
                fs::rename(stage, directory.join("ready"))?;
                Ok(())
            });
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(fs::symlink_metadata(path).unwrap().file_type().is_fifo());
            return;
        }

        struct Running(Child);
        impl Drop for Running {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }
        let mut failures = Vec::new();
        for mode in ["history", "marker", "history-writable", "marker-writable"] {
            let fixture = Fixture::new();
            let marker = mode.starts_with("marker");
            let path = if marker {
                sidecar(&fixture.path())
            } else {
                fixture.path()
            };
            write_private(&path, if marker { MARKER } else { b"{}" });
            let mut process = Running(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "pac_history::tests::checked_history_and_marker_fifo_swaps_never_wait_for_a_writer",
                        "--test-threads=1",
                        "--nocapture",
                    ])
                    .env_clear()
                    .env(DIRECTORY, &fixture.0)
                    .env(MODE, mode)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            let ready = fixture.0.join("ready");
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() {
                assert!(
                    process.0.try_wait().unwrap().is_none(),
                    "child exited before checkpoint"
                );
                assert!(
                    Instant::now() < deadline,
                    "child never reached inspected FIFO checkpoint"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(fs::read(ready).unwrap(), READY);
            assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
            let deadline = Instant::now() + Duration::from_secs(2);
            let status = loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            if let Some(status) = status {
                process.0.wait().unwrap();
                eprintln!("PAC_FIFO mode={mode} checkpoint_ready=true natural_exit={:?} child_reaped=true", status.code());
                if !status.success() {
                    failures.push(mode);
                }
            } else {
                process.0.kill().unwrap();
                let killed = process.0.wait().unwrap();
                assert_eq!(killed.signal(), Some(9));
                eprintln!("PAC_FIFO mode={mode} checkpoint_ready=true still_running_at_deadline=true terminal_signal=9 child_reaped=true");
                failures.push(mode);
            }
            assert!(fs::symlink_metadata(path).unwrap().file_type().is_fifo());
        }
        assert!(
            failures.is_empty(),
            "checked FIFO replacements blocked or failed: {failures:?}"
        );
    }
}
