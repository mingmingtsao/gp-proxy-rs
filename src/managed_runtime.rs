//! Private admission and process-lifetime locks for managed deployments.
//!
//! A vacant runtime lock proves only that its prior descriptor is closed. It is
//! never a substitute for the instance-bound application stop receipt. A lease
//! admitted immediately before maintenance closes the gate may still start;
//! maintenance must retain its gate and observe that runtime's actual outcome.
use crate::control::StopReport;
pub use crate::managed_lifecycle::{
    Incarnation, IncarnationOutcome, LifecycleHistory, RunStamp, RuntimeLifecycleView,
};
use crate::managed_protocol::ManagedIdentity;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};

pub const MAX_GATE_BYTES: usize = 16 * 1024;

/// Credential-free, explicit startup paths; no environment discovery occurs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub version: u8,
    pub identity: ManagedIdentity,
    pub enabled: bool,
    pub binary: PathBuf,
    pub config: PathBuf,
    pub control: PathBuf,
    pub logs: PathBuf,
}

impl Gate {
    pub fn validate(&self) -> io::Result<()> {
        self.identity.validate()?;
        if self.version != 2 {
            return Err(invalid());
        }
        for path in [&self.binary, &self.config, &self.control, &self.logs] {
            let value = path.to_str().ok_or_else(invalid)?;
            if !path.is_absolute()
                || value.len() > 1024
                || value.chars().any(char::is_control)
                || path
                    .components()
                    .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            {
                return Err(invalid());
            }
        }
        let socket = self.control.join("control.sock");
        let maximum = if cfg!(target_os = "macos") { 103 } else { 107 };
        if socket.to_str().ok_or_else(invalid)?.len() > maximum {
            return Err(invalid());
        }
        Ok(())
    }
    fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        bytes.push(b'\n');
        if bytes.len() > MAX_GATE_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid managed runtime namespace or admission record",
    )
}
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "managed runtime locks are unavailable on this platform",
    )
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use platform::Namespace;

pub struct Maintenance {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    namespace: Namespace,
}

/// Exclusive evidence that no process currently holds this runtime lock.
/// This does not assert a successful logout or graceful process termination.
pub struct RetiredRuntime {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    _namespace: Namespace,
}

impl RetiredRuntime {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    pub(crate) fn verifies_path(&self, path: &Path) -> io::Result<()> {
        self._namespace.verify()?;
        if self._namespace.directory.path != path {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
enum BeginState {
    Unused,
    Failed,
    Started(RunStamp),
}

pub struct RuntimeLease {
    spec: Gate,
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    incarnation: std::sync::Mutex<BeginState>,
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    _namespace: Namespace,
}

// Statics are not dropped on normal function return, panic unwind or runtime
// shutdown. There is no release/reset API: the OS closes this lease on exit.
static PROCESS: OnceLock<RuntimeLease> = OnceLock::new();

pub fn current_identity() -> Option<ManagedIdentity> {
    PROCESS.get().map(|lease| lease.spec.identity)
}

/// Bind the already-admitted process to its control instance before any auth
/// task is started. This does not consult a gate that maintenance may close.
pub fn begin_current_incarnation(instance: [u8; 16]) -> io::Result<RunStamp> {
    PROCESS
        .get()
        .ok_or_else(invalid)?
        .begin_incarnation(instance)
}
/// Call only after every local task has joined, before releasing the control
/// namespace or replying to stop. Disk completion does not prove OS process exit.
pub fn finish_current_incarnation(stamp: &RunStamp, report: &StopReport) -> io::Result<()> {
    PROCESS
        .get()
        .ok_or_else(invalid)?
        .finish_incarnation(stamp, report)
}

pub fn initialize(path: &Path, gate: &Gate) -> io::Result<Maintenance> {
    gate.encode()?;
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        platform::initialize(path, gate, &mut |_| Ok(()))
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = path;
        Err(unsupported())
    }
}

/// Read admission without taking the long-lived maintenance lock. This is a
/// diagnostic snapshot, never a runtime lease or evidence of process exit.
pub fn read_gate(path: &Path) -> io::Result<Gate> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        Namespace::open(path)?.gate().map(|value| value.gate)
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = path;
        Err(unsupported())
    }
}

pub fn open_maintenance(path: &Path) -> io::Result<Maintenance> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        let namespace = Namespace::open(path)?;
        namespace
            .maintenance
            .file
            .try_lock()
            .map_err(platform::lock_error)?;
        namespace.verify()?;
        Ok(Maintenance { namespace })
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = path;
        Err(unsupported())
    }
}

impl Maintenance {
    /// Returns bounded detached values; its snapshot guard is already released.
    pub fn lifecycle(&self) -> io::Result<RuntimeLifecycleView> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            self.namespace.lifecycle()?.read()
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            Err(unsupported())
        }
    }
    pub fn retire_unfinished(
        &self,
        retired: &RetiredRuntime,
        expected: &RunStamp,
    ) -> io::Result<RuntimeLifecycleView> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            retired.verifies_path(&self.namespace.directory.path)?;
            if self.read_gate()?.enabled {
                return Err(invalid());
            }
            self.namespace.lifecycle()?.retire(expected)
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            let _ = (retired, expected);
            Err(unsupported())
        }
    }
    /// Explicit closed-state repair retains all verified history and marks
    /// metadata interruption unknown; it never restores a clean old snapshot.
    pub fn repair_lifecycle_closed(
        &self,
        retired: &RetiredRuntime,
    ) -> io::Result<RuntimeLifecycleView> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            retired.verifies_path(&self.namespace.directory.path)?;
            if self.read_gate()?.enabled {
                return Err(invalid());
            }
            self.namespace.lifecycle()?.repair()
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            let _ = retired;
            Err(unsupported())
        }
    }
    /// Reads a complete snapshot; an interrupted update fails closed.
    pub fn read_gate(&self) -> io::Result<Gate> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            self.namespace.gate().map(|record| record.gate)
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            Err(unsupported())
        }
    }
    pub fn set_gate(&mut self, gate: &Gate) -> io::Result<()> {
        gate.encode()?;
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            self.namespace.set_gate(gate, &mut |_| Ok(()))
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            Err(unsupported())
        }
    }
    /// Repair an interrupted owned snapshot using an independently validated,
    /// closed gate from the deployment transaction. Never opens admission.
    pub fn recover_next(&mut self, expected: &Gate) -> io::Result<()> {
        expected.encode()?;
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            self.namespace.recover_next(expected)
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            Err(unsupported())
        }
    }
    pub fn try_runtime(&self) -> io::Result<RetiredRuntime> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            self.namespace.verify()?;
            let namespace = Namespace::open(&self.namespace.directory.path)?;
            if namespace.record != self.namespace.record {
                return Err(invalid());
            }
            namespace
                .runtime
                .file
                .try_lock()
                .map_err(platform::lock_error)?;
            namespace.verify()?;
            Ok(RetiredRuntime {
                _namespace: namespace,
            })
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            Err(unsupported())
        }
    }
}

impl RuntimeLease {
    fn begin_incarnation(&self, instance: [u8; 16]) -> io::Result<RunStamp> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            let mut state = self.incarnation.lock().map_err(|_| invalid())?;
            match &*state {
                BeginState::Started(stamp) => {
                    return if stamp.instance() == instance {
                        Ok(stamp.clone())
                    } else {
                        Err(invalid())
                    }
                }
                BeginState::Failed => return Err(invalid()),
                BeginState::Unused => {}
            }
            // A lost write result never permits another process-local begin.
            *state = BeginState::Failed;
            let stamp = self
                ._namespace
                .lifecycle()?
                .begin(self.spec.identity, instance)?;
            self._namespace.verify()?;
            *state = BeginState::Started(stamp.clone());
            Ok(stamp)
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            let _ = instance;
            Err(unsupported())
        }
    }
    fn finish_incarnation(&self, stamp: &RunStamp, report: &StopReport) -> io::Result<()> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            let state = self.incarnation.lock().map_err(|_| invalid())?;
            if !matches!(&*state, BeginState::Started(actual) if actual == stamp) {
                return Err(invalid());
            }
            // spec.identity remains authoritative for this admitted process;
            // current Gate may already be a newer CLOSED generation.
            self._namespace.lifecycle()?.finish(stamp, report)?;
            self._namespace.verify()
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            let _ = (stamp, report);
            Err(unsupported())
        }
    }
    pub fn acquire(path: &Path, identity: &ManagedIdentity) -> io::Result<Self> {
        identity.validate()?;
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            platform::acquire(path, identity, &mut |_| Ok(()))
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            let _ = path;
            Err(unsupported())
        }
    }
    pub fn spec(&self) -> &Gate {
        &self.spec
    }
    pub fn install_process(self) -> io::Result<()> {
        PROCESS.set(self).map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "managed process lease is already installed",
            )
        })
    }
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod platform {
    use super::*;
    use crate::owned_snapshot::{OwnedSnapshot, SnapshotKind};
    use crate::private_fs::{self, Directory, Errors, Identity, Parents};
    use rustix::fs::{Mode, OFlags};
    use std::{
        ffi::OsString,
        fs::{self, File, Metadata},
        os::unix::fs::{FileExt, MetadataExt},
    };

    const ERRORS: Errors = Errors {
        denied: "managed namespace ownership or identity is invalid",
        invalid: "invalid managed runtime namespace or admission record",
        operation: "managed runtime filesystem operation failed",
    };
    const OWNER: &str = "owner";
    const MAINTENANCE: &str = "maintenance.lock";
    const RUNTIME: &str = "runtime.lock";
    const GATE: &str = "admission";
    const LIFECYCLE: &str = "lifecycle";
    const OWNER_LIMIT: usize = 2048;
    const LOCK_LIMIT: usize = 128;
    type Checkpoint<'a> = &'a mut dyn FnMut(&'static str) -> io::Result<()>;

    fn redact(error: io::Error) -> io::Error {
        ERRORS.redact(error)
    }
    pub(super) fn lock_error(error: fs::TryLockError) -> io::Error {
        redact(error.into())
    }
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Snapshot {
        identity: Identity,
        mode: u32,
        gid: u32,
        links: u64,
        bytes: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }
    impl Snapshot {
        fn of(meta: &Metadata) -> Self {
            Self {
                identity: Identity::of(meta),
                mode: meta.mode(),
                gid: meta.gid(),
                links: meta.nlink(),
                bytes: meta.len(),
                modified: (meta.mtime(), meta.mtime_nsec()),
                changed: (meta.ctime(), meta.ctime_nsec()),
            }
        }
    }
    pub(super) struct CheckedFile {
        pub file: File,
        snapshot: Snapshot,
        name: &'static str,
        limit: usize,
    }
    impl CheckedFile {
        fn open(
            directory: &Directory,
            name: &'static str,
            limit: usize,
            create: bool,
        ) -> io::Result<Self> {
            directory.verify()?;
            let before = if create {
                None
            } else {
                let meta = fs::symlink_metadata(directory.path.join(name)).map_err(redact)?;
                private_fs::regular(&meta, directory.uid, limit, ERRORS)?;
                Some(Snapshot::of(&meta))
            };
            let mut flags = OFlags::RDWR
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::NOCTTY
                | OFlags::CLOEXEC;
            if create {
                flags |= OFlags::CREATE | OFlags::EXCL;
            }
            let file = File::from(
                rustix::fs::openat(
                    &directory.file,
                    name,
                    flags,
                    Mode::from_bits_truncate(0o600),
                )
                .map_err(|e| redact(e.into()))?,
            );
            let meta = file.metadata().map_err(redact)?;
            private_fs::regular(&meta, directory.uid, limit, ERRORS)?;
            let snapshot = Snapshot::of(&meta);
            if before.is_some_and(|old| old != snapshot) {
                return Err(ERRORS.denied());
            }
            let result = Self {
                file,
                snapshot,
                name,
                limit,
            };
            result.verify(directory)?;
            Ok(result)
        }
        fn verify(&self, directory: &Directory) -> io::Result<()> {
            directory.verify()?;
            for meta in [
                fs::symlink_metadata(directory.path.join(self.name)).map_err(redact)?,
                self.file.metadata().map_err(redact)?,
            ] {
                private_fs::regular(&meta, directory.uid, self.limit, ERRORS)?;
                if Snapshot::of(&meta) != self.snapshot {
                    return Err(ERRORS.denied());
                }
            }
            Ok(())
        }
        fn bytes(&self, directory: &Directory) -> io::Result<Vec<u8>> {
            self.verify(directory)?;
            let mut bytes = vec![0; self.snapshot.bytes as usize];
            self.file.read_exact_at(&mut bytes, 0).map_err(redact)?;
            self.verify(directory)?;
            Ok(bytes)
        }
        fn wrote(&mut self, directory: &Directory, length: usize) -> io::Result<()> {
            let meta = self.file.metadata().map_err(redact)?;
            private_fs::regular(&meta, directory.uid, self.limit, ERRORS)?;
            if Identity::of(&meta) != self.snapshot.identity || meta.len() != length as u64 {
                return Err(ERRORS.denied());
            }
            self.snapshot = Snapshot::of(&meta);
            self.verify(directory)
        }
        fn fill(&mut self, directory: &Directory, bytes: &[u8]) -> io::Result<()> {
            if bytes.len() > self.limit || self.snapshot.bytes != 0 {
                return Err(invalid());
            }
            self.verify(directory)?;
            self.file.write_all_at(bytes, 0).map_err(redact)?;
            self.wrote(directory, bytes.len())?;
            self.file.sync_all().map_err(redact)
        }
    }

    #[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Owner {
        version: u8,
        installation: [u8; 16],
        directory: Identity,
        maintenance: Identity,
        runtime: Identity,
        admission: Identity,
        lifecycle: Identity,
    }
    fn marker(kind: &str, installation: &[u8; 16]) -> Vec<u8> {
        let id: String = installation.iter().map(|b| format!("{b:02x}")).collect();
        format!("gp-proxy-managed-{kind}-v3\n{id}\n").into_bytes()
    }
    pub(super) struct Namespace {
        pub directory: Directory,
        owner: CheckedFile,
        pub record: Owner,
        pub runtime: CheckedFile,
        // Maintenance is last: release its exclusive lock after other fields.
        pub maintenance: CheckedFile,
    }
    pub(super) struct GateRead {
        pub gate: Gate,
        sequence: u64,
        bytes: Vec<u8>,
    }

    impl Namespace {
        pub fn open(path: &Path) -> io::Result<Self> {
            let uid = rustix::process::geteuid().as_raw();
            let path = private_fs::directory_path(path, uid, ERRORS)?;
            let directory = Directory::open(path, uid, ERRORS)?;
            Self::existing(directory)
        }
        fn existing(directory: Directory) -> io::Result<Self> {
            let owner = CheckedFile::open(&directory, OWNER, OWNER_LIMIT, false)?;
            let owner_bytes = owner.bytes(&directory)?;
            #[derive(Deserialize)]
            struct Version {
                version: u8,
            }
            let version: Version = serde_json::from_slice(&owner_bytes).map_err(|_| invalid())?;
            if version.version == 2 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "managed runtime v2 requires an explicit migration or a new private directory",
                ));
            }
            let record: Owner = serde_json::from_slice(&owner_bytes).map_err(|_| invalid())?;
            if record.version != 3
                || record.installation.iter().all(|b| *b == 0)
                || record.directory != directory.identity
            {
                return Err(invalid());
            }
            let maintenance = CheckedFile::open(&directory, MAINTENANCE, LOCK_LIMIT, false)?;
            let runtime = CheckedFile::open(&directory, RUNTIME, LOCK_LIMIT, false)?;
            if maintenance.snapshot.identity != record.maintenance
                || runtime.snapshot.identity != record.runtime
                || maintenance.bytes(&directory)? != marker("maintenance", &record.installation)
                || runtime.bytes(&directory)? != marker("runtime", &record.installation)
            {
                return Err(invalid());
            }
            let result = Self {
                directory,
                owner,
                record,
                runtime,
                maintenance,
            };
            result.verify()?;
            Ok(result)
        }
        pub fn verify(&self) -> io::Result<()> {
            self.directory.verify()?;
            self.owner.verify(&self.directory)?;
            self.maintenance.verify(&self.directory)?;
            self.runtime.verify(&self.directory)?;
            if !self
                .record
                .admission
                .matches(&self.directory.path.join(GATE))
            {
                return Err(ERRORS.denied());
            }
            if !self
                .record
                .lifecycle
                .matches(&self.directory.path.join(LIFECYCLE))
            {
                return Err(ERRORS.denied());
            }
            let mut inventory = 0u8;
            for entry in fs::read_dir(&self.directory.path).map_err(redact)? {
                let name = entry.map_err(redact)?.file_name();
                let Some(index) = [OWNER, MAINTENANCE, RUNTIME, GATE, LIFECYCLE]
                    .iter()
                    .position(|expected| name == *expected)
                else {
                    return Err(invalid());
                };
                if inventory & (1 << index) != 0 {
                    return Err(invalid());
                }
                inventory |= 1 << index;
            }
            if inventory != 0x1f {
                return Err(invalid());
            }
            self.directory.verify()
        }
        pub fn lifecycle(&self) -> io::Result<crate::managed_lifecycle::Journal> {
            self.verify()?;
            let path = self.directory.path.join(LIFECYCLE);
            if !self.record.lifecycle.matches(&path) {
                return Err(ERRORS.denied());
            }
            let id = self.directory.identity;
            crate::managed_lifecycle::Journal::open(
                &path,
                self.record.installation,
                [id.device, id.inode, u64::from(id.uid)],
            )
        }
        fn snapshot(&self) -> io::Result<OwnedSnapshot> {
            self.verify()?;
            let path = self.directory.path.join(GATE);
            if !self.record.admission.matches(&path) {
                return Err(ERRORS.denied());
            }
            OwnedSnapshot::open(
                &path,
                self.record.installation,
                SnapshotKind::Runtime,
                MAX_GATE_BYTES,
            )
        }
        pub fn gate(&self) -> io::Result<GateRead> {
            let snapshot = self.snapshot()?;
            let guard = snapshot.lock()?;
            let value = guard.read()?;
            let gate: Gate = serde_json::from_slice(&value.payload).map_err(|_| invalid())?;
            gate.validate()?;
            if gate.identity.installation != self.record.installation {
                return Err(invalid());
            }
            self.verify()?;
            Ok(GateRead {
                gate,
                sequence: value.sequence,
                bytes: value.payload,
            })
        }
        pub fn set_gate(&mut self, gate: &Gate, checkpoint: Checkpoint<'_>) -> io::Result<()> {
            let snapshot = self.snapshot()?;
            let mut guard = snapshot.lock()?;
            let before = guard.read()?;
            let previous: Gate = serde_json::from_slice(&before.payload).map_err(|_| invalid())?;
            transition(&previous, gate)?;
            if gate.identity.installation != self.record.installation {
                return Err(invalid());
            }
            checkpoint("gate_before_write")?;
            guard.write(before.sequence, &gate.encode()?)?;
            checkpoint("gate_published")?;
            self.verify()
        }
        pub fn recover_next(&mut self, expected: &Gate) -> io::Result<()> {
            expected.validate()?;
            if expected.enabled || expected.identity.installation != self.record.installation {
                return Err(invalid());
            }
            let snapshot = self.snapshot()?;
            let mut guard = snapshot.lock()?;
            let view = guard.inspect()?;
            let before = view.highest_complete().ok_or_else(invalid)?;
            let previous: Gate = serde_json::from_slice(&before.payload).map_err(|_| invalid())?;
            previous.validate()?;
            transition(&previous, expected)?;
            guard.repair(&view, &expected.encode()?)?;
            self.verify()
        }
    }

    fn transition(before: &Gate, after: &Gate) -> io::Result<()> {
        after.validate()?;
        if before.identity.installation != after.identity.installation
            || after.identity.generation < before.identity.generation
        {
            return Err(invalid());
        }
        if after.identity.generation == before.identity.generation {
            // Same-generation closure is the only mutation; idempotent writes
            // are allowed. Paths and release cannot change behind an admission.
            let mut closed = before.clone();
            closed.enabled = false;
            if after != before && after != &closed {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(super) fn acquire(
        path: &Path,
        identity: &ManagedIdentity,
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<RuntimeLease> {
        let namespace = Namespace::open(path)?;
        let before = namespace.gate()?;
        if !before.gate.enabled || before.gate.identity != *identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed runtime admission is disabled or changed",
            ));
        }
        checkpoint("admission_read")?;
        namespace.runtime.file.try_lock().map_err(lock_error)?;
        checkpoint("runtime_locked")?;
        namespace.verify()?;
        let after = namespace.gate()?;
        if before.bytes != after.bytes || before.sequence != after.sequence {
            return Err(ERRORS.denied());
        }
        namespace.lifecycle()?.read_for_admission()?;
        Ok(RuntimeLease {
            spec: after.gate,
            incarnation: std::sync::Mutex::new(BeginState::Unused),
            _namespace: namespace,
        })
    }

    pub(super) fn initialize(
        path: &Path,
        gate: &Gate,
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<Maintenance> {
        let bytes = gate.encode()?;
        let uid = rustix::process::geteuid().as_raw();
        let path = private_fs::directory_path(path, uid, ERRORS)?;
        // initialize never adopts an existing final destination, even an empty
        // directory. Existing installations use open_maintenance explicitly.
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "managed runtime destination already exists",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(redact(e)),
        }
        let parents = Parents::capture(&path, uid, ERRORS)?;
        let parent = parents.open_parent()?;
        let mut name = OsString::from(".gp-managed-init-");
        name.push(path.file_name().ok_or_else(invalid)?);
        let stage = path.parent().ok_or_else(invalid)?.join(&name);
        let created = match rustix::fs::mkdirat(&parent, &name, Mode::from_bits_truncate(0o700)) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(e) => return Err(redact(e.into())),
        };
        checkpoint("stage_created")?;
        let directory = Directory::open(stage, uid, ERRORS)?;
        let mut namespace = if created {
            let mut maintenance = CheckedFile::open(&directory, MAINTENANCE, LOCK_LIMIT, true)?;
            maintenance.file.try_lock().map_err(lock_error)?;
            let mut runtime = CheckedFile::open(&directory, RUNTIME, LOCK_LIMIT, true)?;
            checkpoint("locks_created")?;
            maintenance.fill(
                &directory,
                &marker("maintenance", &gate.identity.installation),
            )?;
            runtime.fill(&directory, &marker("runtime", &gate.identity.installation))?;
            OwnedSnapshot::initialize(
                &directory.path.join(GATE),
                gate.identity.installation,
                SnapshotKind::Runtime,
                MAX_GATE_BYTES,
                &bytes,
            )?;
            let admission =
                Identity::of(&fs::symlink_metadata(directory.path.join(GATE)).map_err(redact)?);
            crate::managed_lifecycle::Journal::initialize(
                &directory.path.join(LIFECYCLE),
                gate.identity.installation,
            )?;
            let lifecycle = Identity::of(
                &fs::symlink_metadata(directory.path.join(LIFECYCLE)).map_err(redact)?,
            );
            let record = Owner {
                version: 3,
                installation: gate.identity.installation,
                directory: directory.identity,
                maintenance: maintenance.snapshot.identity,
                runtime: runtime.snapshot.identity,
                admission,
                lifecycle,
            };
            let mut owner = CheckedFile::open(&directory, OWNER, OWNER_LIMIT, true)?;
            let owner_bytes = serde_json::to_vec(&record).map_err(|_| invalid())?;
            owner.fill(&directory, &owner_bytes)?;
            directory.file.sync_all().map_err(redact)?;
            Namespace {
                directory,
                owner,
                record,
                runtime,
                maintenance,
            }
        } else {
            let result = Namespace::existing(directory)?;
            result.maintenance.file.try_lock().map_err(lock_error)?;
            result
        };
        let actual = namespace.gate()?;
        if actual.gate != *gate || actual.bytes != bytes {
            return Err(invalid());
        }
        checkpoint("stage_ready")?;
        namespace.verify()?;
        parents.verify()?;
        rustix::fs::renameat_with(
            &parent,
            &name,
            &parent,
            path.file_name().ok_or_else(invalid)?,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|e| redact(e.into()))?;
        namespace.directory.path = path;
        checkpoint("namespace_published")?;
        parent.sync_all().map_err(redact)?;
        namespace.verify()?;
        Ok(Maintenance { namespace })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            io::Read,
            os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
            process::{Child, Command, Stdio},
            thread,
            time::{Duration, Instant},
        };

        struct Fixture(PathBuf);
        impl Fixture {
            fn new() -> Self {
                let mut id = [0u8; 8];
                getrandom::fill(&mut id).unwrap();
                let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
                let path = PathBuf::from(format!("/tmp/gp-mr-{id}"));
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                Self(path)
            }
            fn path(&self) -> PathBuf {
                self.0.join("runtime")
            }
            fn gate(&self) -> Gate {
                gate_for(&self.0)
            }
            fn stage(&self) -> PathBuf {
                self.0.join(".gp-managed-init-runtime")
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        fn gate_for(base: &Path) -> Gate {
            Gate {
                version: 2,
                identity: ManagedIdentity {
                    installation: [1; 16],
                    generation: 1,
                    release: [2; 32],
                },
                enabled: true,
                binary: base.join("program"),
                config: base.join("config.toml"),
                control: base.join("control"),
                logs: base.join("logs"),
            }
        }
        fn error_kind<T>(result: io::Result<T>) -> io::ErrorKind {
            match result {
                Ok(_) => panic!("expected an error"),
                Err(error) => error.kind(),
            }
        }
        fn snapshot(path: &Path) -> Vec<(OsString, Identity, u32, Vec<u8>)> {
            fn collect(base: &Path, at: &Path, out: &mut Vec<(OsString, Identity, u32, Vec<u8>)>) {
                for entry in fs::read_dir(at).unwrap() {
                    let entry = entry.unwrap();
                    let meta = entry.metadata().unwrap();
                    out.push((
                        entry
                            .path()
                            .strip_prefix(base)
                            .unwrap()
                            .as_os_str()
                            .to_owned(),
                        Identity::of(&meta),
                        meta.mode() & 0o7777,
                        if meta.is_file() {
                            fs::read(entry.path()).unwrap()
                        } else {
                            Vec::new()
                        },
                    ));
                    if meta.is_dir() {
                        collect(base, &entry.path(), out);
                    }
                }
            }
            let mut result = Vec::new();
            collect(path, path, &mut result);
            result.sort_by(|a, b| a.0.cmp(&b.0));
            result
        }
        fn corrupt_inactive_slot(path: &Path) {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(path.join(GATE).join("slot-0"))
                .unwrap();
            file.write_all_at(&[0; 8], 0).unwrap();
            file.sync_all().unwrap();
        }

        #[test]
        fn validated_gate_and_fixed_namespace_exclude_unbounded_or_ambiguous_inputs() {
            let f = Fixture::new();
            let gate = f.gate();
            let maintenance = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
            assert_eq!(maintenance.read_gate().unwrap(), gate);
            let files = snapshot(&f.path());
            assert_eq!(
                files.iter().map(|row| row.0.clone()).collect::<Vec<_>>(),
                [
                    "admission",
                    "admission/lock",
                    "admission/owner",
                    "admission/slot-0",
                    "admission/slot-1",
                    "lifecycle",
                    "lifecycle/lock",
                    "lifecycle/owner",
                    "lifecycle/slot-0",
                    "lifecycle/slot-1",
                    "maintenance.lock",
                    "owner",
                    "runtime.lock"
                ]
                .map(OsString::from)
            );
            assert!(files.iter().all(|row| row.2
                == if row.0 == GATE || row.0 == LIFECYCLE {
                    0o700
                } else {
                    0o600
                }));
            // Two bounded 16KiB admission frames, two bounded 4KiB lifecycle
            // frames, three owners, four fixed locks and four 64-byte headers.
            assert!(
                files.iter().map(|row| row.3.len()).sum::<usize>()
                    <= 2 * MAX_GATE_BYTES + 2 * 4096 + 3 * OWNER_LIMIT + 4 * LOCK_LIMIT + 256
            );
            assert_eq!(
                error_kind(open_maintenance(&f.path())),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(
                error_kind(super::initialize(&f.path(), &gate, &mut |_| Ok(()))),
                io::ErrorKind::AlreadyExists
            );
            for field in 0..9 {
                let mut invalid = gate.clone();
                match field {
                    0 => invalid.version = 1,
                    1 => invalid.identity.generation = 0,
                    2 => invalid.identity.installation = [0; 16],
                    3 => invalid.identity.release = [0; 32],
                    4 => invalid.binary = "relative".into(),
                    5 => invalid.config = "/tmp/a/../secret".into(),
                    6 => invalid.logs = format!("/{}", "a".repeat(1024)).into(),
                    7 => invalid.control = format!("/{}", "a".repeat(103)).into(),
                    _ => invalid.logs = "/tmp/log\nfile".into(),
                }
                assert!(invalid.validate().is_err(), "invalid gate {field}");
                assert!(
                    super::initialize(&f.0.join("invalid"), &invalid, &mut |_| Ok(())).is_err()
                );
                assert!(!f.0.join("invalid").exists());
            }
            let mut value = serde_json::to_value(&gate).unwrap();
            value["unknown"] = true.into();
            assert!(serde_json::from_value::<Gate>(value).is_err());
            let bytes = String::from_utf8(gate.encode().unwrap()).unwrap();
            let duplicate = bytes.replacen("\"version\":2", "\"version\":2,\"version\":2", 1);
            assert!(serde_json::from_str::<Gate>(&duplicate).is_err());
            assert_eq!(snapshot(&f.path()), files);
        }

        #[test]
        fn permanent_locks_and_monotonic_gate_prevent_stale_admission() {
            let f = Fixture::new();
            let gate = f.gate();
            let mut m = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
            let permanent: Vec<_> = snapshot(&f.path())
                .into_iter()
                .filter(|x| !Path::new(&x.0).starts_with(GATE))
                .collect();
            let lease = RuntimeLease::acquire(&f.path(), &gate.identity).unwrap();
            assert_eq!(lease.spec(), &gate);
            assert_eq!(error_kind(m.try_runtime()), io::ErrorKind::WouldBlock);
            assert_eq!(
                error_kind(RuntimeLease::acquire(&f.path(), &gate.identity)),
                io::ErrorKind::WouldBlock
            );
            let mut closed = gate.clone();
            closed.enabled = false;
            m.set_gate(&closed).unwrap();
            // Already admitted leases retain their identity; closure cannot
            // pretend that a startup in flight has already exited.
            assert_eq!(lease.spec(), &gate);
            assert!(m.try_runtime().is_err());
            drop(lease);
            let retired = m.try_runtime().unwrap();
            assert!(RuntimeLease::acquire(&f.path(), &gate.identity).is_err());
            assert!(m.set_gate(&gate).is_err());
            let mut next = gate.clone();
            next.identity.generation = 2;
            m.set_gate(&next).unwrap();
            assert!(RuntimeLease::acquire(&f.path(), &next.identity).is_err());
            drop(retired);
            let next_lease = RuntimeLease::acquire(&f.path(), &next.identity).unwrap();
            assert!(RuntimeLease::acquire(&f.path(), &gate.identity).is_err());
            let mut changed = next.clone();
            changed.config = f.0.join("other.toml");
            assert!(m.set_gate(&changed).is_err());
            changed = next.clone();
            changed.identity.installation = [9; 16];
            assert!(m.set_gate(&changed).is_err());
            assert!(m.set_gate(&closed).is_err());
            assert_eq!(
                snapshot(&f.path())
                    .into_iter()
                    .filter(|x| !Path::new(&x.0).starts_with(GATE))
                    .collect::<Vec<_>>(),
                permanent
            );
            drop(next_lease);
        }

        #[test]
        fn admission_is_rechecked_after_both_observable_race_boundaries() {
            for cut in ["admission_read", "runtime_locked"] {
                let f = Fixture::new();
                let gate = f.gate();
                let mut m = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
                let mut closed = gate.clone();
                closed.enabled = false;
                let result = super::acquire(&f.path(), &gate.identity, &mut |stage| {
                    if stage == cut {
                        m.set_gate(&closed)?;
                    }
                    Ok(())
                });
                assert!(result.is_err(), "closure at {cut} must deny");
                let _retired = m.try_runtime().unwrap();
            }
        }

        #[test]
        fn interrupted_owned_slot_refuses_admission_and_repairs_only_to_closed_gate() {
            let f = Fixture::new();
            let gate = f.gate();
            let mut m = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
            corrupt_inactive_slot(&f.path());
            assert!(m.read_gate().is_err());
            assert!(RuntimeLease::acquire(&f.path(), &gate.identity).is_err());
            assert!(m.set_gate(&gate).is_err());
            let saved = snapshot(&f.path());
            assert!(m.recover_next(&gate).is_err());
            assert_eq!(snapshot(&f.path()), saved);
            let mut closed = gate.clone();
            closed.enabled = false;
            m.recover_next(&closed).unwrap();
            assert_eq!(m.read_gate().unwrap(), closed);
            assert!(RuntimeLease::acquire(&f.path(), &gate.identity).is_err());
            assert!(m.set_gate(&gate).is_err());
            let mut next = gate.clone();
            next.identity.generation += 1;
            m.set_gate(&next).unwrap();
            drop(RuntimeLease::acquire(&f.path(), &next.identity).unwrap());
        }

        #[test]
        fn unknown_files_links_copied_locks_and_parent_replacement_fail_closed() {
            for fault in 0..6 {
                let f = Fixture::new();
                let gate = f.gate();
                let m = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
                let path = f.path().join(RUNTIME);
                let original = fs::read(&path).unwrap();
                match fault {
                    0 => {
                        fs::write(f.path().join("unknown"), b"keep me").unwrap();
                    }
                    1 => {
                        fs::rename(&path, f.0.join("original")).unwrap();
                        fs::write(&path, &original).unwrap();
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                    2 => {
                        fs::rename(&path, f.0.join("original")).unwrap();
                        symlink(f.0.join("original"), &path).unwrap();
                    }
                    3 => {
                        fs::hard_link(&path, f.0.join("hardlink")).unwrap();
                    }
                    4 => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                    }
                    _ => {
                        fs::rename(f.path(), f.0.join("moved")).unwrap();
                        fs::DirBuilder::new().mode(0o700).create(f.path()).unwrap();
                    }
                }
                assert!(m.read_gate().is_err());
                assert!(m.try_runtime().is_err());
                assert!(RuntimeLease::acquire(&f.path(), &gate.identity).is_err());
                assert!(open_maintenance(&f.path()).is_err());
                if fault < 5 {
                    assert_eq!(fs::read(path).unwrap(), original);
                }
            }
            let f = Fixture::new();
            let gate = f.gate();
            let m = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
            let moved = f.0.with_extension("moved");
            fs::rename(&f.0, &moved).unwrap();
            fs::DirBuilder::new().mode(0o700).create(&f.0).unwrap();
            assert!(m.read_gate().is_err());
            assert!(m.try_runtime().is_err());
            drop(m);
            fs::remove_dir_all(moved).unwrap();
        }

        #[test]
        fn initialization_never_overwrites_a_racing_final_or_adopts_partial_stage() {
            let f = Fixture::new();
            let gate = f.gate();
            let result = super::initialize(&f.path(), &gate, &mut |stage| {
                if stage == "stage_ready" {
                    fs::DirBuilder::new().mode(0o700).create(f.path())?;
                    fs::write(f.path().join("foreign"), b"preserved")?;
                }
                Ok(())
            });
            assert_eq!(error_kind(result), io::ErrorKind::AlreadyExists);
            assert_eq!(fs::read(f.path().join("foreign")).unwrap(), b"preserved");
            assert!(f.stage().is_dir());
            for cut in ["stage_created", "locks_created", "stage_ready"] {
                let f = Fixture::new();
                let gate = f.gate();
                assert!(super::initialize(&f.path(), &gate, &mut |stage| {
                    if stage == cut {
                        Err(io::Error::other("synthetic initialization interruption"))
                    } else {
                        Ok(())
                    }
                })
                .is_err());
                assert!(!f.path().exists());
                let before = snapshot(&f.stage());
                let resumed = super::initialize(&f.path(), &gate, &mut |_| Ok(()));
                if cut == "stage_ready" {
                    assert_eq!(resumed.unwrap().read_gate().unwrap(), gate);
                } else {
                    assert!(resumed.is_err());
                    assert_eq!(snapshot(&f.stage()), before);
                }
            }
        }

        struct Process(Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let input = self.0.stdin.take();
                let _ = self.0.kill();
                let _ = self.0.wait();
                drop(input);
            }
        }
        fn wait_for_kill(mut input: impl Read) -> io::Result<()> {
            // read_exact retries Interrupted. Neither EOF nor an unexpected
            // byte releases a crash cutpoint into the next mutation.
            input.read_exact(&mut [0; 1])?;
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected crash-cutpoint input",
            ))
        }
        fn spawn(f: &Fixture, mode: &str) -> Process {
            Process(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "managed_runtime::platform::tests::owned_process_helper",
                        "--nocapture",
                    ])
                    .env_clear()
                    .env("GP_MANAGED_TEST_BASE", &f.0)
                    .env("GP_MANAGED_TEST_MODE", mode)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }
        fn wait_ready(process: &mut Process, ready: &Path) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() {
                assert!(
                    process.0.try_wait().unwrap().is_none(),
                    "owned helper exited before checkpoint"
                );
                assert!(
                    Instant::now() < deadline,
                    "owned helper checkpoint timed out"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
        fn wait_exit(process: &mut Process) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline, "owned helper exit timed out");
                thread::sleep(Duration::from_millis(10));
            }
        }

        #[test]
        fn owned_process_helper() {
            let Some(base) = std::env::var_os("GP_MANAGED_TEST_BASE") else {
                return;
            };
            let base = PathBuf::from(base);
            let path = base.join("runtime");
            let gate = gate_for(&base);
            let mode = std::env::var("GP_MANAGED_TEST_MODE").unwrap();
            let mut signal = |point: &'static str| -> io::Result<()> {
                if point == mode {
                    // Existence is the parent's wakeup condition: publish the
                    // marker only after all bytes have been written.
                    fs::write(base.join("ready.next"), point.as_bytes())?;
                    fs::rename(base.join("ready.next"), base.join("ready"))?;
                    let result = wait_for_kill(std::io::stdin());
                    if mode == "static"
                        && result
                            .as_ref()
                            .is_err_and(|error| error.kind() == io::ErrorKind::UnexpectedEof)
                    {
                        return Ok(()); // the normal-exit test explicitly closes its writer
                    }
                    return result;
                }
                Ok(())
            };
            if mode.starts_with("life_case_") {
                match mode.as_str() {
                    "life_case_restart" => lifecycle_case_restart(),
                    "life_case_closed_gate" => lifecycle_case_closed_gate(),
                    "life_case_dirty" => lifecycle_case_dirty(),
                    "life_case_ownership" => lifecycle_case_ownership(),
                    "life_case_sigkill" => lifecycle_case_sigkill(),
                    _ => panic!("unexpected lifecycle test mode"),
                }
                return;
            }
            if mode.starts_with("life_") {
                RuntimeLease::acquire(&path, &gate.identity)
                    .unwrap()
                    .install_process()
                    .unwrap();
                let token = begin_current_incarnation([31; 16]).unwrap();
                if mode == "life_active" {
                    signal("life_active").unwrap();
                } else if mode == "life_finished" {
                    finish_current_incarnation(&token, &lifecycle_report(false)).unwrap();
                    signal("life_finished").unwrap();
                } else {
                    let wanted = mode.strip_prefix("life_finish_").unwrap();
                    PROCESS
                        .get()
                        .unwrap()
                        ._namespace
                        .lifecycle()
                        .unwrap()
                        .finish_checkpoint(&token, &lifecycle_report(false), &mut |point| {
                            if point == wanted {
                                fs::write(base.join("ready.next"), mode.as_bytes())?;
                                fs::rename(base.join("ready.next"), base.join("ready"))?;
                                wait_for_kill(std::io::stdin())?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }
            } else if mode == "static" {
                let m = super::initialize(&path, &gate, &mut |_| Ok(())).unwrap();
                drop(m);
                fn install(path: &Path, gate: &Gate) {
                    RuntimeLease::acquire(path, &gate.identity)
                        .unwrap()
                        .install_process()
                        .unwrap();
                }
                install(&path, &gate);
                assert_eq!(current_identity(), Some(gate.identity));
                let second_path = base.join("second");
                let mut second = gate.clone();
                second.identity.installation = [3; 16];
                let second_m = super::initialize(&second_path, &second, &mut |_| Ok(())).unwrap();
                let second_lease = RuntimeLease::acquire(&second_path, &second.identity).unwrap();
                assert_eq!(
                    error_kind(second_lease.install_process()),
                    io::ErrorKind::AlreadyExists
                );
                drop(second_m.try_runtime().unwrap()); // failed installation dropped only its own lease
                assert_eq!(current_identity(), Some(gate.identity));
                drop(second_m);
                signal("static").unwrap();
            } else if mode == "slot_dirty" {
                corrupt_inactive_slot(&path);
                signal("slot_dirty").unwrap();
            } else if mode == "gate_published" {
                let mut m = open_maintenance(&path).unwrap();
                let mut closed = gate.clone();
                closed.enabled = false;
                m.namespace.set_gate(&closed, &mut signal).unwrap();
            } else {
                let _m = super::initialize(&path, &gate, &mut signal).unwrap();
            }
        }

        #[test]
        fn installed_static_lease_survives_function_return_until_owned_process_exit() {
            for killed in [false, true] {
                let f = Fixture::new();
                let mut process = spawn(&f, "static");
                wait_ready(&mut process, &f.0.join("ready"));
                let maintenance = open_maintenance(&f.path()).unwrap();
                assert_eq!(
                    error_kind(maintenance.try_runtime()),
                    io::ErrorKind::WouldBlock
                );
                assert!(RuntimeLease::acquire(&f.path(), &f.gate().identity).is_err());
                if killed {
                    use std::os::unix::process::ExitStatusExt;
                    let input = process.0.stdin.take().unwrap();
                    process.0.kill().unwrap();
                    let status = process.0.wait().unwrap();
                    assert_eq!(status.signal(), Some(9));
                    drop(input);
                } else {
                    drop(process.0.stdin.take());
                    wait_exit(&mut process);
                }
                let _retired = maintenance.try_runtime().unwrap();
                // A killed process frees the lock too; no cleanup receipt is
                // synthesized by this API in either exit mode.
            }
            assert!(current_identity().is_none());
        }

        #[test]
        fn owned_sigkill_at_initialization_and_update_boundaries_has_explicit_recovery() {
            for cut in [
                "stage_created",
                "locks_created",
                "stage_ready",
                "namespace_published",
                "slot_dirty",
                "gate_published",
            ] {
                let f = Fixture::new();
                let gate = f.gate();
                let updating = cut == "slot_dirty" || cut == "gate_published";
                if updating {
                    drop(super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap());
                }
                let mut process = spawn(&f, cut);
                wait_ready(&mut process, &f.0.join("ready"));
                assert_eq!(fs::read(f.0.join("ready")).unwrap(), cut.as_bytes());
                assert!(process.0.try_wait().unwrap().is_none());
                let paused_path = if updating || cut == "namespace_published" {
                    f.path()
                } else {
                    f.stage()
                };
                let paused = snapshot(&paused_path);
                let input = process.0.stdin.take().unwrap();
                process.0.kill().unwrap();
                let status = process.0.wait().unwrap();
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9));
                drop(input);
                assert_eq!(snapshot(&paused_path), paused);
                if updating {
                    let mut m = open_maintenance(&f.path()).unwrap();
                    assert!(RuntimeLease::acquire(&f.path(), &gate.identity).is_err());
                    let mut closed = gate.clone();
                    closed.enabled = false;
                    if cut == "slot_dirty" {
                        assert!(m.read_gate().is_err());
                        m.recover_next(&closed).unwrap();
                    }
                    assert_eq!(m.read_gate().unwrap(), closed);
                } else if cut == "namespace_published" {
                    assert_eq!(
                        open_maintenance(&f.path()).unwrap().read_gate().unwrap(),
                        gate
                    );
                } else {
                    let before = snapshot(&f.stage());
                    let result = super::initialize(&f.path(), &gate, &mut |_| Ok(()));
                    if cut == "stage_ready" {
                        assert_eq!(result.unwrap().read_gate().unwrap(), gate);
                    } else {
                        assert!(result.is_err());
                        assert_eq!(snapshot(&f.stage()), before);
                    }
                }
            }
        }

        #[test]
        fn crash_barrier_retries_interrupted_and_eof_never_publishes_the_partial_gate() {
            struct InterruptedThenEof(usize);
            impl Read for InterruptedThenEof {
                fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                    self.0 += 1;
                    if self.0 == 1 {
                        Err(io::Error::from(io::ErrorKind::Interrupted))
                    } else {
                        Ok(0)
                    }
                }
            }
            let mut input = InterruptedThenEof(0);
            assert_eq!(
                wait_for_kill(&mut input).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert_eq!(input.0, 2);
            assert_eq!(
                wait_for_kill(b"x".as_slice()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            let f = Fixture::new();
            let gate = f.gate();
            drop(super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap());
            let mut process = spawn(&f, "slot_dirty");
            wait_ready(&mut process, &f.0.join("ready"));
            let before = snapshot(&f.path());
            drop(process.0.stdin.take()); // deliberately inject EOF, never a release instruction
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < deadline, "EOF helper failed to terminate");
                thread::sleep(Duration::from_millis(10));
            };
            assert!(!status.success());
            assert_eq!(snapshot(&f.path()), before);
            let mut maintenance = open_maintenance(&f.path()).unwrap();
            let mut closed = gate.clone();
            closed.enabled = false;
            assert!(maintenance.read_gate().is_err());
            maintenance.recover_next(&closed).unwrap();
            assert_eq!(maintenance.read_gate().unwrap(), closed);
        }
        fn lifecycle_report(unconfirmed: bool) -> StopReport {
            StopReport {
                local_cleanup_complete: true,
                cleanup: crate::service::CleanupSummary {
                    known_sessions: 1,
                    logout_confirmed: u64::from(!unconfirmed),
                    logout_unconfirmed: u64::from(unconfirmed),
                    remote_outcome_unknown: u64::from(unconfirmed),
                },
            }
        }
        fn isolated_lifecycle_case(mode: &str) {
            let f = Fixture::new();
            let mut process = spawn(&f, mode);
            let until = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    assert!(status.success(), "isolated lifecycle case failed: {mode}");
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "isolated lifecycle case timed out: {mode}"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
        fn lifecycle_case_restart() {
            let f = Fixture::new();
            let gate = f.gate();
            let m = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
            let a = RuntimeLease::acquire(&f.path(), &gate.identity).unwrap();
            let token_a = a.begin_incarnation([11; 16]).unwrap();
            assert_eq!(a.begin_incarnation([11; 16]).unwrap(), token_a);
            assert!(a.begin_incarnation([12; 16]).is_err());
            assert_eq!(m.lifecycle().unwrap().ordinal_highwater, 1);
            let incomplete = StopReport {
                local_cleanup_complete: false,
                cleanup: crate::service::CleanupSummary::default(),
            };
            assert!(a.finish_incarnation(&token_a, &incomplete).is_err());
            assert!(matches!(
                m.lifecycle().unwrap().current.unwrap().outcome,
                IncarnationOutcome::Active
            ));
            drop(a); // OS-lock release alone does not fabricate completion.
            let b = RuntimeLease::acquire(&f.path(), &gate.identity).unwrap();
            let token_b = b.begin_incarnation([12; 16]).unwrap();
            let view = m.lifecycle().unwrap();
            assert_eq!(view.history.unfinished_incarnations, 1);
            assert_eq!(view.last_unfinished.unwrap(), token_a);
            assert!(view.history.remote_uncertainty());
            assert!(b
                .finish_incarnation(&token_a, &lifecycle_report(false))
                .is_err());
            let empty = StopReport {
                local_cleanup_complete: true,
                cleanup: crate::service::CleanupSummary::default(),
            };
            b.finish_incarnation(&token_b, &empty).unwrap();
            let before = m.lifecycle().unwrap();
            b.finish_incarnation(&token_b, &empty).unwrap();
            assert_eq!(m.lifecycle().unwrap().sequence, before.sequence);
            assert!(b
                .finish_incarnation(&token_b, &lifecycle_report(false))
                .is_err());
            drop(b);
            let c = RuntimeLease::acquire(&f.path(), &gate.identity).unwrap();
            let token_c = c.begin_incarnation([13; 16]).unwrap();
            c.finish_incarnation(&token_c, &lifecycle_report(true))
                .unwrap();
            let final_view = m.lifecycle().unwrap();
            assert_eq!(final_view.history.unfinished_incarnations, 1);
            assert_eq!(final_view.history.finished_incarnations, 2);
            assert_eq!(final_view.history.unconfirmed_finished_incarnations, 1);
            assert_eq!(final_view.history.completed.known_sessions, 1);
            assert_eq!(final_view.history.completed.logout_unconfirmed, 1);
            assert_eq!(final_view.history.completed.remote_outcome_unknown, 1);
        }
        fn lifecycle_case_closed_gate() {
            let f = Fixture::new();
            let gate = f.gate();
            let mut m = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
            let a = RuntimeLease::acquire(&f.path(), &gate.identity).unwrap();
            let mut closed = gate.clone();
            closed.enabled = false;
            closed.identity.generation += 1;
            m.set_gate(&closed).unwrap();
            // Admission already happened. Both late begin and late finish must
            // remain bound to A, not to the new closed admission generation.
            let token = a.begin_incarnation([17; 16]).unwrap();
            assert_eq!(token.managed(), gate.identity);
            a.finish_incarnation(&token, &lifecycle_report(false))
                .unwrap();
            assert!(m.try_runtime().is_err());
            assert_eq!(
                m.lifecycle()
                    .unwrap()
                    .finished_for(&gate.identity, &[17; 16]),
                Some(&lifecycle_report(false))
            );
            assert!(m
                .lifecycle()
                .unwrap()
                .finished_for(&closed.identity, &[17; 16])
                .is_none());
            drop(a);
            let retired = m.try_runtime().unwrap();
            let before = m.lifecycle().unwrap().sequence;
            m.retire_unfinished(&retired, &token).unwrap();
            assert_eq!(m.lifecycle().unwrap().sequence, before);
        }
        fn lifecycle_case_dirty() {
            let f = Fixture::new();
            let gate = f.gate();
            let mut m = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
            let a = RuntimeLease::acquire(&f.path(), &gate.identity).unwrap();
            let token = a.begin_incarnation([21; 16]).unwrap();
            drop(a);
            let retired = m.try_runtime().unwrap();
            // Select the actually older frame, then invalidate its commit magic.
            let mut slots: Vec<_> = (0..2)
                .map(|n| {
                    let path = f.path().join(LIFECYCLE).join(format!("slot-{n}"));
                    let bytes = fs::read(&path).unwrap();
                    (u64::from_be_bytes(bytes[8..16].try_into().unwrap()), path)
                })
                .collect();
            slots.sort_by_key(|v| v.0);
            let file = fs::OpenOptions::new()
                .write(true)
                .open(&slots[0].1)
                .unwrap();
            file.write_all_at(&[0; 8], 0).unwrap();
            file.sync_all().unwrap();
            assert!(m.lifecycle().is_err());
            assert!(
                m.repair_lifecycle_closed(&retired).is_err(),
                "enabled gate cannot repair"
            );
            let mut closed = gate.clone();
            closed.enabled = false;
            m.set_gate(&closed).unwrap(); // journal corruption does not block fencing.
            let repaired = m.repair_lifecycle_closed(&retired).unwrap();
            assert!(repaired.history.metadata_interrupted);
            assert_eq!(repaired.history.unfinished_incarnations, 1);
            assert_eq!(repaired.last_unfinished.unwrap(), token);
            assert!(repaired.current.is_none());
            let seq = repaired.sequence;
            assert_eq!(m.repair_lifecycle_closed(&retired).unwrap().sequence, seq);
            drop(retired);
            assert!(RuntimeLease::acquire(&f.path(), &gate.identity).is_err());
        }
        fn lifecycle_case_ownership() {
            let a = Fixture::new();
            let b = Fixture::new();
            let gate = a.gate();
            let mut ma = super::initialize(&a.path(), &gate, &mut |_| Ok(())).unwrap();
            let mb = super::initialize(&b.path(), &b.gate(), &mut |_| Ok(())).unwrap();
            let process = RuntimeLease::acquire(&a.path(), &gate.identity).unwrap();
            let token = process.begin_incarnation([25; 16]).unwrap();
            drop(process);
            let foreign = mb.try_runtime().unwrap();
            let mut closed = gate.clone();
            closed.enabled = false;
            ma.set_gate(&closed).unwrap();
            assert!(ma.retire_unfinished(&foreign, &token).is_err());
            let before = snapshot(&a.path());
            let owned = ma.try_runtime().unwrap();
            ma.retire_unfinished(&owned, &token).unwrap();
            let view = ma.lifecycle().unwrap();
            assert_eq!(view.history.unfinished_incarnations, 1);
            assert_eq!(
                ma.retire_unfinished(&owned, &token).unwrap().sequence,
                view.sequence
            );
            assert_ne!(snapshot(&a.path()), before);
            drop(owned);
            drop(ma);
            let owner_path = a.path().join(OWNER);
            let mut owner: serde_json::Value =
                serde_json::from_slice(&fs::read(&owner_path).unwrap()).unwrap();
            owner["version"] = 2.into();
            owner.as_object_mut().unwrap().remove("lifecycle");
            fs::write(&owner_path, serde_json::to_vec(&owner).unwrap()).unwrap();
            let before = snapshot(&a.path());
            assert_eq!(
                error_kind(open_maintenance(&a.path())),
                io::ErrorKind::Unsupported
            );
            assert_eq!(snapshot(&a.path()), before);
        }
        fn lifecycle_case_sigkill() {
            for cut in [
                "life_active",
                "life_finished",
                "life_finish_slot_invalidated",
                "life_finish_slot_partial_payload",
                "life_finish_slot_prepared",
                "life_finish_slot_committed",
            ] {
                let f = Fixture::new();
                let gate = f.gate();
                let mut m = super::initialize(&f.path(), &gate, &mut |_| Ok(())).unwrap();
                let mut process = spawn(&f, cut);
                wait_ready(&mut process, &f.0.join("ready"));
                assert_eq!(fs::read(f.0.join("ready")).unwrap(), cut.as_bytes());
                assert!(m.try_runtime().is_err());
                let before = snapshot(&f.path());
                let input = process.0.stdin.take().unwrap();
                process.0.kill().unwrap();
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(process.0.wait().unwrap().signal(), Some(9));
                drop(input);
                assert_eq!(snapshot(&f.path()), before);
                let partial =
                    cut.starts_with("life_finish_slot_") && cut != "life_finish_slot_committed";
                if partial {
                    assert!(
                        m.lifecycle().is_err(),
                        "dirty {cut} silently read old snapshot"
                    );
                    assert!(RuntimeLease::acquire(&f.path(), &gate.identity).is_err());
                    let mut closed = gate.clone();
                    closed.enabled = false;
                    m.set_gate(&closed).unwrap();
                    let retired = m.try_runtime().unwrap();
                    let view = m.repair_lifecycle_closed(&retired).unwrap();
                    assert!(view.history.metadata_interrupted);
                    assert_eq!(view.history.unfinished_incarnations, 1);
                    assert_eq!(view.history.completed.known_sessions, 0);
                } else {
                    let b = RuntimeLease::acquire(&f.path(), &gate.identity).unwrap();
                    let stamp = b.begin_incarnation([32; 16]).unwrap();
                    let empty = StopReport {
                        local_cleanup_complete: true,
                        cleanup: crate::service::CleanupSummary::default(),
                    };
                    b.finish_incarnation(&stamp, &empty).unwrap();
                    let view = m.lifecycle().unwrap();
                    assert_eq!(
                        view.history.unfinished_incarnations,
                        u64::from(cut == "life_active")
                    );
                    assert_eq!(
                        view.history.completed.known_sessions,
                        u64::from(cut != "life_active")
                    );
                    assert_eq!(
                        view.history.completed.logout_confirmed,
                        u64::from(cut != "life_active")
                    );
                }
            }
        }
        #[test]
        fn lifecycle_restarts_keep_old_unknown_and_count_finished_once() {
            isolated_lifecycle_case("life_case_restart");
        }
        #[test]
        fn lifecycle_late_begin_and_finish_use_admitted_identity_after_fencing() {
            isolated_lifecycle_case("life_case_closed_gate");
        }
        #[test]
        fn lifecycle_dirty_snapshot_requires_closed_explicit_conservative_repair() {
            isolated_lifecycle_case("life_case_dirty");
        }
        #[test]
        fn lifecycle_ownership_retirement_and_v2_refusal_preserve_unknown_files() {
            isolated_lifecycle_case("life_case_ownership");
        }
        #[test]
        fn lifecycle_owned_sigkill_keeps_active_or_exact_finished_and_partial_boundaries() {
            isolated_lifecycle_case("life_case_sigkill");
        }
    }
}
