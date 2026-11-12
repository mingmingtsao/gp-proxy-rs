//! Credential-free deployment files. This module never invokes launchctl,
//! signals a service, authenticates, or treats an idle lock as a stop receipt.
#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]

use crate::{
    control::StopReport,
    managed_plist::Pool,
    managed_protocol::ManagedIdentity,
    managed_release::{self, Source},
    managed_runtime::{self, Gate},
    owned_snapshot::{OwnedSnapshot, SnapshotKind},
    private_fs::{self, Directory, Errors, Identity, Parents},
};
use rustix::fs::{Mode, OFlags};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const ERRORS: Errors = Errors {
    denied: "deployment ownership or identity is invalid",
    invalid: "invalid deployment store",
    operation: "deployment filesystem operation failed",
};
const META_LIMIT: usize = 32 * 1024;
const PLIST_LIMIT: usize = 16 * 1024;
const MAX_VERSIONS: usize = 3;
const STATE_LIMIT: usize = 128 * 1024;
const MAX_RETIRED_JOBS: usize = 2;
type Checkpoint<'a> = &'a mut dyn FnMut(&'static str) -> io::Result<()>;
fn invalid() -> io::Error {
    ERRORS.invalid()
}
fn redact(e: io::Error) -> io::Error {
    ERRORS.redact(e)
}
fn interrupted() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "deployment update needs explicit recovery",
    )
}
fn encode<T: Serialize>(value: &T, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    bytes.push(b'\n');
    if bytes.len() > maximum {
        return Err(invalid());
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(|_| invalid())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRef {
    pub(crate) release: [u8; 32],
    pub(crate) bytes: u64,
    directory: Identity,
    binary: Identity,
    metadata: Identity,
}
impl ReleaseRef {
    pub fn digest(&self) -> [u8; 32] {
        self.release
    }
    pub fn len(&self) -> u64 {
        self.bytes
    }
    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }
}
pub use crate::managed_plist::OwnedPlist;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub(crate) version: u8,
    pub(crate) installation: [u8; 16],
    pub(crate) current: Option<ReleaseRef>,
    pub(crate) previous: Option<ReleaseRef>,
    pub(crate) gate: Gate,
    pub(crate) label: String,
    pub(crate) plist_path: Option<PathBuf>,
    pub(crate) plist: Option<OwnedPlist>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Install,
    Start,
    Resume,
    Stop,
    Upgrade,
    Uninstall,
    Recover,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prepared,
    Maintenance,
    StopRequested,
    Stopped,
    RuntimeRetired,
    OldJobRemovalRequested,
    OldJobRemoved,
    PlistPublished,
    NewJobLoadRequested,
    NewJobLoaded,
    AdmissionOpened,
    Ready,
    Configured,
    OutcomeUnknown,
    RollingBack,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CleanupEvidenceSource {
    Ipc,
    RuntimeTerminal { ordinal: u64, sequence: u64 },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopEvidence {
    pub(crate) instance: [u8; 16],
    pub(crate) managed: ManagedIdentity,
    pub(crate) report: StopReport,
    pub(crate) source: CleanupEvidenceSource,
}
impl StopEvidence {
    pub fn ipc(instance: [u8; 16], managed: ManagedIdentity, report: StopReport) -> Self {
        Self {
            instance,
            managed,
            report,
            source: CleanupEvidenceSource::Ipc,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub(crate) version: u8,
    pub(crate) installation: [u8; 16],
    pub(crate) operation: Operation,
    pub(crate) phase: Phase,
    pub(crate) previous: Record,
    pub(crate) next: Record,
    pub(crate) stop: Option<StopEvidence>,
    pub(crate) id: u64,
    pub(crate) next_stop: Option<StopEvidence>,
    pub(crate) previous_unknown: Option<UnknownCleanup>,
    pub(crate) next_unknown: Option<UnknownCleanup>,
    pub(crate) outcome: Option<UnknownOutcome>,
    pub(crate) previous_instance: Option<[u8; 16]>,
    accounted_cleanup: [Option<[u8; 32]>; 4],
    pub(crate) load_child_may_live: bool,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupTarget {
    Previous,
    Attempted,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    OperationFailed,
    MetadataInterrupted,
    StopUnobserved,
    RuntimeRetiredWithoutReceipt,
    UnobservedIncarnation,
    ServiceManagerUnconfirmed,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownCleanup {
    pub(crate) managed: ManagedIdentity,
    pub(crate) instance: Option<[u8; 16]>,
    pub(crate) reason: UnknownReason,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownOutcome {
    pub(crate) at_phase: Phase,
    pub(crate) reason: UnknownReason,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredJob {
    pub(crate) managed: ManagedIdentity,
    pub(crate) label: String,
    pub(crate) plist: OwnedPlist,
    pub(crate) release: ReleaseRef,
    pub(crate) removal_unknown: bool,
    pub(crate) anchor_pinned: bool,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryLedger {
    pub(crate) unconfirmed_episodes: u64,
    pub(crate) remote_outcome_unknown: bool,
    pub(crate) metadata_interrupted: bool,
    pub(crate) logout_unconfirmed: u64,
    pub(crate) last_unknown: Option<UnknownCleanup>,
    pub(crate) last_previous_stop: Option<StopEvidence>,
    pub(crate) last_next_stop: Option<StopEvidence>,
    pub(crate) last_applied_transaction: u64,
    pub(crate) retired_jobs: Vec<RetiredJob>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    record: Record,
    pending: Option<Transaction>,
    ledger: RecoveryLedger,
    generation_highwater: u64,
    garbage: Vec<ReleaseRef>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u8,
    installation: [u8; 16],
    directory: Identity,
    lock: Identity,
    versions: Identity,
    runtime: Identity,
    state: Identity,
    plists: Identity,
    data: Identity,
    destination: PathBuf,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VersionRecord {
    version: u8,
    installation: [u8; 16],
    store: Identity,
    release: ReleaseRef,
}

struct Pinned {
    file: File,
    identity: Identity,
    bytes: Vec<u8>,
}
fn open_file(directory: &Directory, name: &str, maximum: usize, create: bool) -> io::Result<File> {
    directory.verify()?;
    let before = if create {
        None
    } else {
        let meta = fs::symlink_metadata(directory.path.join(name)).map_err(redact)?;
        private_fs::regular(&meta, directory.uid, maximum, ERRORS)?;
        Some(Identity::of(&meta))
    };
    let mut flags =
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
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
    private_fs::regular(&meta, directory.uid, maximum, ERRORS)?;
    if before.is_some_and(|id| id != Identity::of(&meta)) {
        return Err(ERRORS.denied());
    }
    verify_file(directory, name, &file, Identity::of(&meta), maximum)?;
    Ok(file)
}
fn verify_file(
    directory: &Directory,
    name: &str,
    file: &File,
    identity: Identity,
    maximum: usize,
) -> io::Result<()> {
    directory.verify()?;
    for meta in [
        fs::symlink_metadata(directory.path.join(name)).map_err(redact)?,
        file.metadata().map_err(redact)?,
    ] {
        private_fs::regular(&meta, directory.uid, maximum, ERRORS)?;
        if Identity::of(&meta) != identity {
            return Err(ERRORS.denied());
        }
    }
    Ok(())
}
fn read_file(directory: &Directory, name: &str, maximum: usize) -> io::Result<Pinned> {
    let mut file = open_file(directory, name, maximum, false)?;
    let meta = file.metadata().map_err(redact)?;
    let identity = Identity::of(&meta);
    let mut bytes = Vec::with_capacity(meta.len() as usize + 1);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(redact)?;
    if bytes.len() > maximum
        || bytes.len() as u64 != meta.len()
        || file.metadata().map_err(redact)?.len() != meta.len()
    {
        return Err(invalid());
    }
    verify_file(directory, name, &file, identity, maximum)?;
    Ok(Pinned {
        file,
        identity,
        bytes,
    })
}
/// The non-cloneable permanent store lock spans the caller's entire transaction.
/// Drop only closes descriptors. It never rolls back, removes, starts or stops.
/// After any mutation error, discard this value and reopen: a rename may have
/// succeeded before a later sync/read error, leaving these cached views stale.
pub struct Store {
    directory: Directory,
    versions: Directory,
    owner: Pinned,
    ownership: Owner,
    record: Record,
    pending: Option<Transaction>,
    snapshot: OwnedSnapshot,
    plists: Pool,
    revision: u64,
    ledger: RecoveryLedger,
    generation_highwater: u64,
    needs_repair: bool,
    garbage: Vec<ReleaseRef>,
    lock: Pinned,
}

impl Store {
    pub fn initialize(root: &Path, gate: &Gate) -> io::Result<Self> {
        Self::initialize_with(root, gate, &mut |_| Ok(()))
    }
    fn initialize_with(root: &Path, gate: &Gate, checkpoint: Checkpoint<'_>) -> io::Result<Self> {
        gate.validate()?;
        if gate.enabled {
            return Err(invalid());
        }
        let uid = rustix::process::geteuid().as_raw();
        let root = private_fs::directory_path(root, uid, ERRORS)?;
        match fs::symlink_metadata(&root) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "deployment destination already exists",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(redact(e)),
        }
        let parents = Parents::capture(&root, uid, ERRORS)?;
        let parent = parents.open_parent()?;
        let mut name = OsString::from(".gp-deploy-init-");
        name.push(root.file_name().ok_or_else(invalid)?);
        let stage = root.parent().ok_or_else(invalid)?.join(&name);
        let created = match rustix::fs::mkdirat(&parent, &name, Mode::from_bits_truncate(0o700)) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(e) => return Err(redact(e.into())),
        };
        checkpoint("store_stage_created")?;
        if created {
            let directory = Directory::open(stage.clone(), uid, ERRORS)?;
            let mut lock = open_file(&directory, "store.lock", 128, true)?;
            lock.try_lock().map_err(|e| redact(e.into()))?;
            lock.write_all(&lock_marker(&gate.identity.installation))
                .map_err(redact)?;
            lock.sync_all().map_err(redact)?;
            rustix::fs::mkdirat(&directory.file, "versions", Mode::from_bits_truncate(0o700))
                .map_err(|e| redact(e.into()))?;
            let versions = Directory::open(stage.join("versions"), uid, ERRORS)?;
            drop(managed_runtime::initialize(&stage.join("runtime"), gate)?);
            let runtime = Directory::open(stage.join("runtime"), uid, ERRORS)?;
            let record = Record {
                version: 2,
                installation: gate.identity.installation,
                current: None,
                previous: None,
                gate: gate.clone(),
                label: crate::launchd::label_for(&gate.identity)?,
                plist_path: None,
                plist: None,
            };
            let initial = State {
                version: 3,
                record,
                pending: None,
                ledger: RecoveryLedger::default(),
                generation_highwater: gate.identity.generation,
                garbage: Vec::new(),
            };
            drop(OwnedSnapshot::initialize(
                &stage.join("state"),
                gate.identity.installation,
                SnapshotKind::Deployment,
                STATE_LIMIT,
                &encode(&initial, STATE_LIMIT)?,
            )?);
            let state = Directory::open(stage.join("state"), uid, ERRORS)?;
            drop(Pool::initialize(
                &stage.join("plists"),
                gate.identity.installation,
            )?);
            let plists = Directory::open(stage.join("plists"), uid, ERRORS)?;
            rustix::fs::mkdirat(&directory.file, "data", Mode::from_bits_truncate(0o700))
                .map_err(|error| redact(error.into()))?;
            let data = Directory::open(stage.join("data"), uid, ERRORS)?;
            data.file.sync_all().map_err(redact)?;
            let ownership = Owner {
                version: 2,
                installation: gate.identity.installation,
                directory: directory.identity,
                lock: Identity::of(&lock.metadata().map_err(redact)?),
                versions: versions.identity,
                runtime: runtime.identity,
                state: state.identity,
                plists: plists.identity,
                data: data.identity,
                destination: root.clone(),
            };
            let mut owner = open_file(&directory, "owner", META_LIMIT, true)?;
            owner
                .write_all(&encode(&ownership, META_LIMIT)?)
                .map_err(redact)?;
            owner.sync_all().map_err(redact)?;
            versions.file.sync_all().map_err(redact)?;
            directory.file.sync_all().map_err(redact)?;
            // Close the staging descriptors before reopening the complete
            // namespace. No external action has occurred at this point.
        }
        let store = Self::open(&stage)?;
        if store.record.gate != *gate || store.record.current.is_some() || store.pending.is_some() {
            return Err(invalid());
        }
        store.no_updates()?;
        checkpoint("store_stage_ready")?;
        store.verify()?;
        parents.verify()?;
        rustix::fs::renameat_with(
            &parent,
            &name,
            &parent,
            root.file_name().ok_or_else(invalid)?,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|e| redact(e.into()))?;
        checkpoint("store_published")?;
        parent.sync_all().map_err(redact)?;
        drop(store);
        Self::open(&root)
    }

    pub fn open(root: &Path) -> io::Result<Self> {
        Self::open_with(root, false)
    }
    pub fn open_recovery(root: &Path) -> io::Result<Self> {
        Self::open_with(root, true)
    }
    fn open_with(root: &Path, recovery: bool) -> io::Result<Self> {
        let uid = rustix::process::geteuid().as_raw();
        let root = private_fs::directory_path(root, uid, ERRORS)?;
        let directory = Directory::open(root, uid, ERRORS)?;
        let owner = read_file(&directory, "owner", META_LIMIT)?;
        let header: serde_json::Value = decode(&owner.bytes)?;
        if header.get("version").and_then(|v| v.as_u64()) != Some(2) {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "deployment v1 requires explicit clean removal with its original version; no automatic migration"));
        }
        let ownership: Owner = decode(&owner.bytes)?;
        if ownership.installation == [0; 16] || ownership.directory != directory.identity {
            return Err(invalid());
        }
        if !ownership.destination.is_absolute()
            || private_fs::directory_path(&ownership.destination, uid, ERRORS)?
                != ownership.destination
        {
            return Err(invalid());
        }
        let mut stage_name = OsString::from(".gp-deploy-init-");
        stage_name.push(ownership.destination.file_name().ok_or_else(invalid)?);
        let expected_stage = ownership
            .destination
            .parent()
            .ok_or_else(invalid)?
            .join(stage_name);
        if directory.path != ownership.destination && directory.path != expected_stage {
            return Err(ERRORS.denied());
        }
        let lock = read_file(&directory, "store.lock", 128)?;
        if lock.identity != ownership.lock || lock.bytes != lock_marker(&ownership.installation) {
            return Err(invalid());
        }
        lock.file.try_lock().map_err(|e| redact(e.into()))?;
        let versions = Directory::open(directory.path.join("versions"), uid, ERRORS)?;
        if versions.identity != ownership.versions {
            return Err(invalid());
        }
        let state_directory = Directory::open(directory.path.join("state"), uid, ERRORS)?;
        if state_directory.identity != ownership.state {
            return Err(invalid());
        }
        let plist_directory = Directory::open(directory.path.join("plists"), uid, ERRORS)?;
        if plist_directory.identity != ownership.plists {
            return Err(invalid());
        }
        let plists = Pool::open(&plist_directory.path, ownership.installation)?;
        let snapshot = OwnedSnapshot::open(
            &state_directory.path,
            ownership.installation,
            SnapshotKind::Deployment,
            STATE_LIMIT,
        )?;
        let (value, needs_repair) = {
            let guard = snapshot.lock()?;
            match guard.read() {
                Ok(value) => (value, false),
                Err(error) if recovery && error.kind() == io::ErrorKind::Interrupted => (
                    guard
                        .inspect()?
                        .highest_complete()
                        .cloned()
                        .ok_or_else(interrupted)?,
                    true,
                ),
                Err(error) => return Err(error),
            }
        };
        #[derive(Deserialize)]
        struct StateVersion {
            version: u8,
        }
        let version: StateVersion = decode(&value.payload)?;
        if version.version == 2 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "deployment state v2 requires an explicit migration or a new private directory",
            ));
        }
        let state: State = decode(&value.payload)?;
        let store = Self {
            directory,
            versions,
            owner,
            ownership,
            lock,
            snapshot,
            plists,
            record: state.record,
            pending: state.pending,
            ledger: state.ledger,
            generation_highwater: state.generation_highwater,
            revision: value.sequence,
            needs_repair,
            garbage: state.garbage,
        };
        if state.version != 3 {
            return Err(invalid());
        }
        store.verify_namespace()?;
        store.validate_state()?;
        for release in [&store.record.current, &store.record.previous]
            .into_iter()
            .flatten()
        {
            store.verify_release(release)?;
        }
        for job in &store.ledger.retired_jobs {
            store.verify_release(&job.release)?;
        }
        Ok(store)
    }
    pub fn root(&self) -> &Path {
        &self.directory.path
    }
    pub fn runtime_path(&self) -> PathBuf {
        self.directory.path.join("runtime")
    }
    pub fn record(&self) -> &Record {
        &self.record
    }
    pub fn pending(&self) -> Option<&Transaction> {
        self.pending.as_ref()
    }
    pub fn ledger(&self) -> &RecoveryLedger {
        &self.ledger
    }
    pub fn has_garbage(&self) -> bool {
        !self.garbage.is_empty()
    }
    pub fn generation_highwater(&self) -> u64 {
        self.generation_highwater
    }
    pub fn reserve_generation(&mut self) -> io::Result<u64> {
        let mut state = self.state();
        state.generation_highwater = state
            .generation_highwater
            .checked_add(1)
            .ok_or_else(invalid)?;
        let result = state.generation_highwater;
        self.persist(state)?;
        Ok(result)
    }
    pub fn recovery_token(&self) -> io::Result<[u8; 32]> {
        self.verify_namespace()?;
        let view = self.snapshot.lock()?.inspect()?;
        let mut bytes = encode(&self.state(), STATE_LIMIT)?;
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        bytes.extend_from_slice(&view.fingerprint());
        Ok(managed_release::digest_bytes(&bytes))
    }
    fn validate_state_value(&self, state: &State) -> io::Result<()> {
        if state.version != 3
            || state.generation_highwater < state.record.gate.identity.generation
            || state.ledger.retired_jobs.len() > MAX_RETIRED_JOBS
            || state.garbage.len() > MAX_VERSIONS
        {
            return Err(invalid());
        }
        self.validate_record(&state.record)?;
        if let Some(tx) = &state.pending {
            self.validate_transaction(tx)?;
            if state.record != tx.previous && state.record != tx.next
                || state.generation_highwater < tx.next.gate.identity.generation
            {
                return Err(invalid());
            }
        }
        for (index, job) in state.ledger.retired_jobs.iter().enumerate() {
            if job.managed.installation != self.ownership.installation
                || job.managed.release != job.release.release
                || job.managed.generation > state.generation_highwater
                || job.label != crate::launchd::label_for(&job.managed)?
            {
                return Err(invalid());
            }
            validate_plist_ref(&job.plist, self.directory.uid)?;
            self.plists.validate_reference(&job.plist)?;
            valid_plist_path(&job.plist.path, &job.label)?;
            if state.ledger.retired_jobs[..index]
                .iter()
                .any(|old| old.label == job.label)
            {
                return Err(invalid());
            }
        }
        for (index, release) in state.garbage.iter().enumerate() {
            if release.release == [0; 32]
                || release.bytes == 0
                || release.bytes > managed_release::MAX_BINARY_BYTES
                || [release.directory, release.binary, release.metadata]
                    .iter()
                    .any(|id| id.uid != self.directory.uid)
                || state.garbage[..index]
                    .iter()
                    .any(|old| old.release == release.release)
                || [&state.record.current, &state.record.previous]
                    .into_iter()
                    .flatten()
                    .any(|kept| kept.release == release.release)
                || state
                    .ledger
                    .retired_jobs
                    .iter()
                    .any(|job| job.release.release == release.release)
            {
                return Err(invalid());
            }
        }
        for unknown in [&state.ledger.last_unknown].into_iter().flatten() {
            unknown.managed.validate()?;
            if unknown.managed.installation != self.ownership.installation
                || unknown.instance == Some([0; 16])
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn validate_state(&self) -> io::Result<()> {
        self.validate_state_value(&self.state())
    }
    pub fn note_unknown(&mut self, reason: UnknownReason) -> io::Result<()> {
        let mut tx = self.pending.clone().ok_or_else(invalid)?;
        tx.outcome = Some(UnknownOutcome {
            at_phase: tx.phase,
            reason,
        });
        self.save_transaction(tx)
    }
    pub fn mark_load_child(&mut self, may_live: bool) -> io::Result<()> {
        let mut tx = self.pending.clone().ok_or_else(invalid)?;
        tx.load_child_may_live = may_live;
        self.save_transaction(tx)
    }
    pub fn observe_previous_instance(&mut self, instance: [u8; 16]) -> io::Result<()> {
        if instance == [0; 16] {
            return Err(invalid());
        }
        let mut tx = self.pending.clone().ok_or_else(invalid)?;
        if tx
            .previous_instance
            .is_some_and(|previous| previous != instance)
        {
            return Err(invalid());
        }
        tx.previous_instance = Some(instance);
        self.save_transaction(tx)
    }
    pub fn record_cleanup(&mut self, target: CleanupTarget, proof: StopEvidence) -> io::Result<()> {
        if proof.source != CleanupEvidenceSource::Ipc {
            return Err(invalid());
        }
        self.record_cleanup_with_source(target, proof)
    }
    /// This is a persisted terminal observation, never receipt of an IPC reply.
    /// The view must come from this Store's owner-bound runtime namespace.
    pub fn record_durable_cleanup(
        &mut self,
        target: CleanupTarget,
        view: &managed_runtime::RuntimeLifecycleView,
        managed: ManagedIdentity,
        instance: [u8; 16],
    ) -> io::Result<StopEvidence> {
        let runtime = self.ownership.runtime;
        if view.installation != self.ownership.installation
            || !view.belongs_to_runtime([runtime.device, runtime.inode, u64::from(runtime.uid)])
        {
            return Err(invalid());
        }
        let (stamp, report) = view.last_finished().ok_or_else(invalid)?;
        if stamp.managed() != managed || stamp.instance() != instance {
            return Err(invalid());
        }
        let proof = StopEvidence {
            instance,
            managed,
            report: report.clone(),
            source: CleanupEvidenceSource::RuntimeTerminal {
                ordinal: stamp.ordinal(),
                sequence: view.sequence,
            },
        };
        self.record_cleanup_with_source(target, proof.clone())?;
        Ok(proof)
    }
    fn record_cleanup_with_source(
        &mut self,
        target: CleanupTarget,
        mut proof: StopEvidence,
    ) -> io::Result<()> {
        let mut state = self.state();
        let tx = state.pending.as_mut().ok_or_else(invalid)?;
        if target == CleanupTarget::Previous
            && tx
                .previous_instance
                .is_some_and(|instance| instance != proof.instance)
        {
            return Err(invalid());
        }
        let (slot, unknown, identity) = match target {
            CleanupTarget::Previous => (
                &mut tx.stop,
                &mut tx.previous_unknown,
                tx.previous.gate.identity,
            ),
            CleanupTarget::Attempted => (
                &mut tx.next_stop,
                &mut tx.next_unknown,
                tx.next.gate.identity,
            ),
        };
        validate_stop(&proof, identity)?;
        if let Some(old) = slot.as_ref() {
            if old.instance == proof.instance {
                if old.managed != proof.managed || old.report != proof.report {
                    return Err(invalid());
                }
                if old.source == CleanupEvidenceSource::Ipc {
                    proof.source = CleanupEvidenceSource::Ipc;
                }
            } else {
                let index = match target {
                    CleanupTarget::Previous => 0,
                    CleanupTarget::Attempted => 1,
                };
                let fingerprint = evidence_fingerprint(old)?;
                if tx.accounted_cleanup[index] != Some(fingerprint) {
                    tx.accounted_cleanup[index] = Some(fingerprint);
                }
                match target {
                    CleanupTarget::Previous => state.ledger.last_previous_stop = Some(old.clone()),
                    CleanupTarget::Attempted => state.ledger.last_next_stop = Some(old.clone()),
                }
            }
        }
        if unknown.as_ref().is_some_and(|pending| {
            pending.managed == proof.managed
                && pending.instance == Some(proof.instance)
                && matches!(
                    pending.reason,
                    UnknownReason::StopUnobserved
                        | UnknownReason::RuntimeRetiredWithoutReceipt
                        | UnknownReason::UnobservedIncarnation
                )
        }) {
            *unknown = None;
        }
        *slot = Some(proof);
        self.persist(state)
    }
    pub fn record_cleanup_unknown(
        &mut self,
        target: CleanupTarget,
        unknown: UnknownCleanup,
    ) -> io::Result<()> {
        let mut tx = self.pending.clone().ok_or_else(invalid)?;
        let (slot, identity) = match target {
            CleanupTarget::Previous => (&mut tx.previous_unknown, tx.previous.gate.identity),
            CleanupTarget::Attempted => (&mut tx.next_unknown, tx.next.gate.identity),
        };
        if unknown.managed != identity || unknown.instance == Some([0; 16]) {
            return Err(invalid());
        }
        if slot.is_none() {
            *slot = Some(unknown);
        }
        self.save_transaction(tx)
    }
    pub fn repair_metadata(&mut self) -> io::Result<()> {
        self.verify_namespace()?;
        if !self.needs_repair {
            return self.verify();
        }
        let mut state = self.state();
        state.ledger.metadata_interrupted = true;
        state.ledger.remote_outcome_unknown = true;
        if let Some(tx) = &mut state.pending {
            tx.outcome = Some(UnknownOutcome {
                at_phase: tx.phase,
                reason: UnknownReason::MetadataInterrupted,
            });
            if tx.previous.current.is_some()
                && tx.previous.gate.enabled
                && tx.previous_unknown.is_none()
            {
                tx.previous_unknown = Some(UnknownCleanup {
                    managed: tx.previous.gate.identity,
                    instance: None,
                    reason: UnknownReason::MetadataInterrupted,
                });
            }
            if tx.next.gate.enabled && tx.next_unknown.is_none() {
                tx.next_unknown = Some(UnknownCleanup {
                    managed: tx.next.gate.identity,
                    instance: None,
                    reason: UnknownReason::MetadataInterrupted,
                });
            }
        }
        self.validate_state_value(&state)?;
        let value = {
            let mut guard = self.snapshot.lock()?;
            let observed = guard.inspect()?;
            let highest = observed.highest_complete().ok_or_else(interrupted)?;
            if highest.sequence != self.revision
                || highest.payload != encode(&self.state(), STATE_LIMIT)?
            {
                return Err(ERRORS.denied());
            }
            guard.repair(&observed, &encode(&state, STATE_LIMIT)?)?
        };
        self.revision = value.sequence;
        self.record = state.record;
        self.pending = state.pending;
        self.ledger = state.ledger;
        self.generation_highwater = state.generation_highwater;
        self.garbage = state.garbage;
        self.needs_repair = false;
        self.verify()
    }
    pub fn retain_retired_job(&mut self, job: RetiredJob) -> io::Result<()> {
        if let Some(index) = self
            .ledger
            .retired_jobs
            .iter()
            .position(|old| old.label == job.label)
        {
            let old = &self.ledger.retired_jobs[index];
            let mut same = job.clone();
            same.removal_unknown = old.removal_unknown;
            same.anchor_pinned = old.anchor_pinned;
            if old != &same || old.removal_unknown && !job.removal_unknown {
                return Err(invalid());
            }
            if job.anchor_pinned && !old.anchor_pinned {
                let mut state = self.state();
                state.ledger.retired_jobs[index].anchor_pinned = true;
                return self.persist(state);
            }
            return self.no_updates();
        }
        if self.ledger.retired_jobs.len() >= MAX_RETIRED_JOBS {
            return Err(io::Error::other(
                "retired job capacity reached; explicit resolution required",
            ));
        }
        self.verify_release(&job.release)?;
        let mut state = self.state();
        state.ledger.retired_jobs.push(job);
        self.validate_state_value(&state)?;
        self.persist(state)
    }
    pub fn confirm_retired_job_removal(&mut self, job: &RetiredJob) -> io::Result<RetiredJob> {
        let mut state = self.state();
        let retained = state
            .ledger
            .retired_jobs
            .iter_mut()
            .find(|old| *old == job)
            .ok_or_else(invalid)?;
        retained.removal_unknown = false;
        let result = retained.clone();
        self.persist(state)?;
        Ok(result)
    }
    pub fn forget_retired_job(&mut self, job: &RetiredJob) -> io::Result<()> {
        if job.removal_unknown {
            return Err(invalid());
        }
        let mut state = self.state();
        let index = state
            .ledger
            .retired_jobs
            .iter()
            .position(|old| old == job)
            .ok_or_else(invalid)?;
        // A pending transaction can reconstruct this job after a crash. Keep
        // its positive removal fact until clearing that transaction atomically.
        if state.pending.is_some() || job.anchor_pinned {
            return self.no_updates();
        }
        state.ledger.retired_jobs.remove(index);
        if ![&state.record.current, &state.record.previous]
            .into_iter()
            .flatten()
            .any(|release| release.release == job.release.release)
            && !state
                .ledger
                .retired_jobs
                .iter()
                .any(|retained| retained.release.release == job.release.release)
            && !state
                .garbage
                .iter()
                .any(|release| release.release == job.release.release)
        {
            state.garbage.push(job.release.clone());
        }
        self.persist(state)
    }
    /// The caller must close and verify the runtime gate before acquiring this
    /// capability. Its existence is exclusion evidence, never a logout receipt.
    pub fn finish_recovery(
        &mut self,
        target: Record,
        retired: &managed_runtime::RetiredRuntime,
    ) -> io::Result<()> {
        self.finish_recovery_with(target, retired, &mut |_| Ok(()))
    }
    fn finish_recovery_with(
        &mut self,
        target: Record,
        retired: &managed_runtime::RetiredRuntime,
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<()> {
        self.no_updates()?;
        retired.verifies_path(&self.runtime_path())?;
        if self.pending.is_none() && self.record == target && !target.gate.enabled {
            return self.drain_garbage_with(retired, checkpoint);
        }
        let mut tx = self.pending.clone().ok_or_else(invalid)?;
        if target.gate.enabled
            || target.current != self.record.current
            || target.plist.is_some()
            || target.gate.identity.generation != self.generation_highwater
            || target.gate.identity.generation <= self.record.gate.identity.generation
        {
            return Err(invalid());
        }
        self.validate_record(&target)?;
        for job in &self.ledger.retired_jobs {
            if !job.removal_unknown {
                self.plists.remove(&job.plist)?;
            }
        }
        let mut state = self.state();
        merge_ledger(&mut state.ledger, &mut tx)?;
        let released_jobs: Vec<_> = state
            .ledger
            .retired_jobs
            .iter()
            .filter(|job| !job.removal_unknown && !job.anchor_pinned)
            .map(|job| job.release.clone())
            .collect();
        state
            .ledger
            .retired_jobs
            .retain(|job| job.removal_unknown || job.anchor_pinned);
        let mut candidates: Vec<_> = [
            &tx.previous.current,
            &tx.previous.previous,
            &tx.next.current,
            &tx.next.previous,
            &self.record.current,
            &self.record.previous,
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect();
        candidates.extend(released_jobs);
        for release in candidates {
            if [&target.current, &target.previous]
                .into_iter()
                .flatten()
                .any(|kept| kept.release == release.release)
                || state
                    .ledger
                    .retired_jobs
                    .iter()
                    .any(|job| job.release.release == release.release)
            {
                continue;
            }
            if let Some(known) = state
                .garbage
                .iter()
                .find(|old| old.release == release.release)
            {
                if known != &release {
                    return Err(invalid());
                }
            } else {
                state.garbage.push(release);
            }
        }
        state.record = target;
        state.pending = None;
        self.persist_with(state, checkpoint)?;
        checkpoint("garbage_enqueued")?;
        self.drain_garbage_with(retired, checkpoint)
    }
    pub fn drain_garbage(&mut self, retired: &managed_runtime::RetiredRuntime) -> io::Result<()> {
        self.drain_garbage_with(retired, &mut |_| Ok(()))
    }
    fn drain_garbage_with(
        &mut self,
        retired: &managed_runtime::RetiredRuntime,
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<()> {
        self.no_updates()?;
        retired.verifies_path(&self.runtime_path())?;
        while let Some(release) = self.garbage.first().cloned() {
            self.remove_release_with(&release, checkpoint)?;
            checkpoint("garbage_files_removed")?;
            let mut state = self.state();
            state.garbage.remove(0);
            self.persist_with(state, checkpoint)?;
            checkpoint("garbage_queue_recorded")?;
        }
        Ok(())
    }
    pub fn version_path(&self, release: &ReleaseRef) -> PathBuf {
        self.versions
            .path
            .join(managed_release::hexadecimal(&release.release))
            .join("gp-proxy")
    }

    fn verify(&self) -> io::Result<()> {
        self.verify_namespace()?;
        if self.needs_repair {
            return Err(interrupted());
        }
        let value = self.snapshot.lock()?.read()?;
        if value.sequence != self.revision || value.payload != encode(&self.state(), STATE_LIMIT)? {
            return Err(ERRORS.denied());
        }
        Ok(())
    }
    fn verify_namespace(&self) -> io::Result<()> {
        self.directory.verify()?;
        self.versions.verify()?;
        for (name, known, limit) in [
            ("owner", &self.owner, META_LIMIT),
            ("store.lock", &self.lock, 128),
        ] {
            verify_file(&self.directory, name, &known.file, known.identity, limit)?;
            let now = read_file(&self.directory, name, limit)?;
            if now.identity != known.identity || now.bytes != known.bytes {
                return Err(ERRORS.denied());
            }
        }
        let runtime = Directory::open(self.runtime_path(), self.directory.uid, ERRORS)?;
        if runtime.identity != self.ownership.runtime {
            return Err(ERRORS.denied());
        }
        let mut found = 0u16;
        for entry in fs::read_dir(&self.directory.path).map_err(redact)? {
            let name = entry.map_err(redact)?.file_name();
            let Some(index) = [
                "owner",
                "store.lock",
                "state",
                "runtime",
                "versions",
                "plists",
                "data",
            ]
            .iter()
            .position(|value| name == *value) else {
                return Err(invalid());
            };
            if found & (1 << index) != 0 {
                return Err(invalid());
            }
            found |= 1 << index;
        }
        if found != 0x7f {
            return Err(invalid());
        }
        let data = Directory::open(self.directory.path.join("data"), self.directory.uid, ERRORS)?;
        if data.identity != self.ownership.data {
            return Err(ERRORS.denied());
        }
        let plist_directory = Directory::open(
            self.directory.path.join("plists"),
            self.directory.uid,
            ERRORS,
        )?;
        if plist_directory.identity != self.ownership.plists {
            return Err(ERRORS.denied());
        }
        self.plists.verify_references(&self.plist_references())?;
        self.version_names()?;
        Ok(())
    }
    fn no_updates(&self) -> io::Result<()> {
        self.verify()
    }
    fn validate_record(&self, record: &Record) -> io::Result<()> {
        record.gate.validate()?;
        if record.version != 2
            || record.installation != self.ownership.installation
            || record.gate.identity.installation != record.installation
            || record.label != crate::launchd::label_for(&record.gate.identity)?
            || record.gate.control != self.ownership.destination.join("data/control")
            || record.gate.logs != self.ownership.destination.join("data/logs")
        {
            return Err(invalid());
        }
        for release in [&record.current, &record.previous].into_iter().flatten() {
            if release.release == [0; 32]
                || release.bytes == 0
                || release.bytes > managed_release::MAX_BINARY_BYTES
                || [release.directory, release.binary, release.metadata]
                    .iter()
                    .any(|id| id.uid != self.directory.uid)
            {
                return Err(invalid());
            }
        }
        if let Some(current) = &record.current {
            if record.gate.identity.release != current.release
                || record.gate.binary != self.version_path(current)
            {
                return Err(invalid());
            }
            if record
                .previous
                .as_ref()
                .is_some_and(|p| p.release == current.release)
            {
                return Err(invalid());
            }
        }
        if let Some(path) = &record.plist_path {
            valid_plist_path(path, &record.label)?;
        }
        if let Some(plist) = &record.plist {
            validate_plist_ref(plist, self.directory.uid)?;
            self.plists.validate_reference(plist)?;
            if record.plist_path.as_ref() != Some(&plist.path) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn validate_transaction(&self, tx: &Transaction) -> io::Result<()> {
        self.validate_record(&tx.previous)?;
        self.validate_record(&tx.next)?;
        if tx.version != 3
            || tx.installation != self.ownership.installation
            || tx.next.gate.identity.generation < tx.previous.gate.identity.generation
        {
            return Err(invalid());
        }
        let shape = match tx.operation {
            Operation::Install => {
                tx.previous.current.is_none()
                    && tx.next.current.is_some()
                    && !tx.next.gate.enabled
                    && tx.next.plist.is_none()
            }
            Operation::Start => tx.next.current.is_some() && tx.next.gate.enabled,
            Operation::Resume => {
                tx.next == tx.previous
                    && tx.next.current.is_some()
                    && tx.next.gate.enabled
                    && tx.next.plist.is_some()
                    && tx
                        .stop
                        .as_ref()
                        .is_none_or(|proof| tx.previous_instance == Some(proof.instance))
                    && matches!(
                        tx.phase,
                        Phase::Prepared
                            | Phase::NewJobLoadRequested
                            | Phase::NewJobLoaded
                            | Phase::Ready
                            | Phase::OutcomeUnknown
                    )
            }
            Operation::Stop => tx.next.current == tx.previous.current && !tx.next.gate.enabled,
            Operation::Upgrade => tx.previous.current.is_some() && tx.next.current.is_some(),
            Operation::Uninstall => {
                tx.next.current.is_none() && !tx.next.gate.enabled && tx.next.plist.is_none()
            }
            Operation::Recover => {
                tx.next.current == tx.previous.current
                    && !tx.next.gate.enabled
                    && tx.next.plist.is_none()
            }
        };
        if !shape
            || tx.previous_instance == Some([0; 16])
            || tx.id == 0
            || tx.id <= self.ledger.last_applied_transaction && self.record != tx.next
        {
            return Err(invalid());
        }
        if let Some(outcome) = &tx.outcome {
            if outcome.at_phase != tx.phase || tx.phase == Phase::OutcomeUnknown {
                return Err(invalid());
            }
        }
        if let Some(stop) = &tx.next_stop {
            validate_stop(stop, tx.next.gate.identity)?;
        }
        for (unknown, expected) in [
            (&tx.previous_unknown, tx.previous.gate.identity),
            (&tx.next_unknown, tx.next.gate.identity),
        ] {
            if let Some(unknown) = unknown {
                if unknown.managed != expected || unknown.instance == Some([0; 16]) {
                    return Err(invalid());
                }
            }
        }
        if let Some(stop) = &tx.stop {
            validate_stop(stop, tx.previous.gate.identity)?;
            if tx
                .previous_instance
                .is_some_and(|instance| instance != stop.instance)
            {
                return Err(invalid());
            }
            let cleanup = stop.report.cleanup;
            if stop.instance == [0; 16]
                || stop.managed != tx.previous.gate.identity
                || !stop.report.local_cleanup_complete
                || cleanup
                    .logout_confirmed
                    .checked_add(cleanup.logout_unconfirmed)
                    != Some(cleanup.known_sessions)
            {
                return Err(invalid());
            }
        }
        let needs_stop = tx.operation != Operation::Resume
            && tx.previous.current.is_some()
            && tx.previous.gate.enabled
            && matches!(
                tx.phase,
                Phase::Stopped
                    | Phase::RuntimeRetired
                    | Phase::OldJobRemovalRequested
                    | Phase::OldJobRemoved
                    | Phase::PlistPublished
                    | Phase::NewJobLoadRequested
                    | Phase::NewJobLoaded
                    | Phase::AdmissionOpened
                    | Phase::Ready
                    | Phase::Configured
            );
        if needs_stop && tx.stop.is_none() {
            return Err(invalid());
        }
        Ok(())
    }

    fn version_names(&self) -> io::Result<Vec<String>> {
        self.versions.verify()?;
        let mut names = Vec::new();
        let mut candidate = false;
        for entry in fs::read_dir(&self.versions.path).map_err(redact)? {
            let name = entry
                .map_err(redact)?
                .file_name()
                .into_string()
                .map_err(|_| invalid())?;
            let directory =
                Directory::open(self.versions.path.join(&name), self.directory.uid, ERRORS)?;
            if name != ".candidate" {
                let digest = managed_release::parse_release(&name)?;
                names.push(name.clone());
                if names.len() > MAX_VERSIONS {
                    return Err(invalid());
                }
                let obsolete = self
                    .garbage
                    .iter()
                    .find(|release| release.release == digest)
                    .or_else(|| {
                        self.pending
                            .as_ref()
                            .filter(|tx| self.record == tx.next && committable(tx))
                            .and_then(|tx| {
                                [&tx.previous.current, &tx.previous.previous]
                                    .into_iter()
                                    .flatten()
                                    .find(|r| r.release == digest && !self.referenced_by_record(r))
                            })
                    });
                if let Some(known) = obsolete {
                    self.partial_release_entries(&directory, known)?;
                } else if self.version_at(directory)?.release != digest {
                    return Err(invalid());
                }
            } else {
                // Only a complete, owned candidate is readable for explicit
                // SHA-based reuse. Partial/unknown staging blocks mutations.
                self.version_at(directory).map_err(|_| interrupted())?;
                candidate = true;
            }
        }
        if names.len() + usize::from(candidate) > MAX_VERSIONS {
            return Err(invalid());
        }
        Ok(names)
    }
    fn version_at(&self, directory: Directory) -> io::Result<ReleaseRef> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&directory.path).map_err(redact)? {
            names.push(entry.map_err(redact)?.file_name());
            if names.len() > 2 {
                return Err(invalid());
            }
        }
        names.sort();
        if names != [OsString::from("gp-proxy"), OsString::from("release.json")] {
            return Err(invalid());
        }
        let metadata = read_file(&directory, "release.json", META_LIMIT)?;
        let record: VersionRecord = decode(&metadata.bytes)?;
        if record.version != 1
            || record.installation != self.ownership.installation
            || record.store != self.directory.identity
            || record.release.directory != directory.identity
            || record.release.metadata != metadata.identity
        {
            return Err(invalid());
        }
        let path = directory.path.join("gp-proxy");
        let info = fs::symlink_metadata(&path).map_err(redact)?;
        if Identity::of(&info) != record.release.binary
            || info.uid() != self.directory.uid
            || info.mode() & 0o7777 != 0o700
        {
            return Err(ERRORS.denied());
        }
        let source = Source::open(&path)?;
        if source.digest() != record.release.release || source.len() != record.release.bytes {
            return Err(invalid());
        }
        directory.verify()?;
        Ok(record.release)
    }
    fn verify_release(&self, release: &ReleaseRef) -> io::Result<()> {
        let dir = Directory::open(
            self.version_path(release)
                .parent()
                .ok_or_else(invalid)?
                .to_owned(),
            self.directory.uid,
            ERRORS,
        )?;
        if self.version_at(dir)? != *release {
            return Err(ERRORS.denied());
        }
        Ok(())
    }

    pub fn prepare_release(&mut self, source: &mut Source) -> io::Result<ReleaseRef> {
        self.prepare_with(source, &mut |_| Ok(()))
    }
    fn prepare_with(
        &mut self,
        source: &mut Source,
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<ReleaseRef> {
        self.no_updates()?;
        if self.pending.is_some() || !self.garbage.is_empty() {
            return Err(interrupted());
        }
        source.verify()?;
        let name = managed_release::hexadecimal(&source.digest());
        let final_path = self.versions.path.join(&name);
        if fs::symlink_metadata(&final_path).is_ok() {
            let release =
                self.version_at(Directory::open(final_path, self.directory.uid, ERRORS)?)?;
            if release.release != source.digest() || release.bytes != source.len() {
                return Err(invalid());
            }
            return Ok(release);
        }
        if self.version_names()?.len() >= MAX_VERSIONS {
            return Err(io::Error::other(
                "deployment version capacity reached; explicit recovery or pruning required",
            ));
        }
        let created = match rustix::fs::mkdirat(
            &self.versions.file,
            ".candidate",
            Mode::from_bits_truncate(0o700),
        ) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(e) => return Err(redact(e.into())),
        };
        checkpoint("candidate_created")?;
        let mut directory = Directory::open(
            self.versions.path.join(".candidate"),
            self.directory.uid,
            ERRORS,
        )?;
        let release = if created {
            let mut binary = File::from(
                rustix::fs::openat(
                    &directory.file,
                    "gp-proxy",
                    OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::RDWR
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_bits_truncate(0o700),
                )
                .map_err(|e| redact(e.into()))?,
            );
            source.copy_into(&mut binary)?;
            binary.sync_all().map_err(redact)?;
            checkpoint("candidate_copied")?;
            let mut metadata = open_file(&directory, "release.json", META_LIMIT, true)?;
            let release = ReleaseRef {
                release: source.digest(),
                bytes: source.len(),
                directory: directory.identity,
                binary: Identity::of(&binary.metadata().map_err(redact)?),
                metadata: Identity::of(&metadata.metadata().map_err(redact)?),
            };
            let record = VersionRecord {
                version: 1,
                installation: self.ownership.installation,
                store: self.directory.identity,
                release: release.clone(),
            };
            metadata
                .write_all(&encode(&record, META_LIMIT)?)
                .map_err(redact)?;
            metadata.sync_all().map_err(redact)?;
            directory.file.sync_all().map_err(redact)?;
            release
        } else {
            self.version_at(Directory::open(
                directory.path.clone(),
                self.directory.uid,
                ERRORS,
            )?)?
        };
        if release.release != source.digest() || release.bytes != source.len() {
            return Err(invalid());
        }
        checkpoint("candidate_ready")?;
        self.verify()?;
        directory.verify()?;
        source.verify()?;
        rustix::fs::renameat_with(
            &self.versions.file,
            ".candidate",
            &self.versions.file,
            &name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|e| redact(e.into()))?;
        directory.path = final_path;
        checkpoint("candidate_published")?;
        self.versions.file.sync_all().map_err(redact)?;
        self.verify_release(&release)?;
        Ok(release)
    }

    fn state(&self) -> State {
        State {
            version: 3,
            record: self.record.clone(),
            pending: self.pending.clone(),
            ledger: self.ledger.clone(),
            generation_highwater: self.generation_highwater,
            garbage: self.garbage.clone(),
        }
    }
    fn persist(&mut self, state: State) -> io::Result<()> {
        self.persist_with(state, &mut |_| Ok(()))
    }
    fn persist_with(&mut self, state: State, checkpoint: Checkpoint<'_>) -> io::Result<()> {
        self.no_updates()?;
        self.validate_state_value(&state)?;
        let payload = encode(&state, STATE_LIMIT)?;
        let value = self
            .snapshot
            .lock()?
            .write_with(self.revision, &payload, checkpoint)?;
        self.revision = value.sequence;
        self.record = state.record;
        self.pending = state.pending;
        self.ledger = state.ledger;
        self.generation_highwater = state.generation_highwater;
        self.garbage = state.garbage;
        self.validate_state()
    }
    fn save_transaction(&mut self, tx: Transaction) -> io::Result<()> {
        self.validate_transaction(&tx)?;
        let mut state = self.state();
        state.generation_highwater = state
            .generation_highwater
            .max(tx.next.gate.identity.generation);
        state.pending = Some(tx);
        self.persist(state)
    }
    pub fn begin(&mut self, operation: Operation, next: Record) -> io::Result<()> {
        self.no_updates()?;
        if self.pending.is_some() || !self.garbage.is_empty() {
            return Err(interrupted());
        }
        if operation == Operation::Resume {
            self.verify_current_plist()?;
        }
        self.validate_record(&next)?;
        for release in [&next.current, &next.previous].into_iter().flatten() {
            self.verify_release(release)?;
        }
        self.save_transaction(Transaction {
            version: 3,
            installation: self.ownership.installation,
            operation,
            phase: Phase::Prepared,
            previous: self.record.clone(),
            next,
            stop: None,
            id: self.revision.checked_add(1).ok_or_else(invalid)?,
            next_stop: None,
            previous_unknown: None,
            next_unknown: None,
            outcome: None,
            previous_instance: None,
            accounted_cleanup: [None; 4],
            load_child_may_live: false,
        })
    }
    pub fn advance(&mut self, phase: Phase, stop: Option<StopEvidence>) -> io::Result<()> {
        self.no_updates()?;
        if phase == Phase::OutcomeUnknown {
            return self.note_unknown(UnknownReason::OperationFailed);
        }
        let mut tx = self.pending.clone().ok_or_else(invalid)?;
        tx.phase = phase;
        if let Some(outcome) = &mut tx.outcome {
            outcome.at_phase = phase;
        }
        if let Some(proof) = stop {
            if proof.source != CleanupEvidenceSource::Ipc {
                return Err(invalid());
            }
            tx.stop = Some(proof);
        }
        self.save_transaction(tx)
    }
    pub fn commit(&mut self) -> io::Result<()> {
        self.no_updates()?;
        let tx = self.pending.clone().ok_or_else(invalid)?;
        self.validate_transaction(&tx)?;
        if !committable(&tx) {
            return Err(invalid());
        }
        self.validate_record(&tx.next)?;
        let mut state = self.state();
        state.record = tx.next.clone();
        merge_ledger(
            &mut state.ledger,
            state.pending.as_mut().ok_or_else(invalid)?,
        )?;
        if encode(&state, STATE_LIMIT)? != encode(&self.state(), STATE_LIMIT)? {
            self.persist(state)?;
        }
        // Keep the journal until all exact obsolete objects are removed. A
        // restarted commit can finish a partially removed known version.
        for old in [&tx.previous.current, &tx.previous.previous]
            .into_iter()
            .flatten()
        {
            if !self.referenced_by_record(old) {
                self.remove_release(old)?;
            }
        }
        self.remove_transaction()?;
        Ok(())
    }
    pub fn rollback_record(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "use explicit closed-state recovery; old enabled records are never restored",
        ))
    }
    fn remove_transaction(&mut self) -> io::Result<()> {
        let mut state = self.state();
        state.pending = None;
        self.persist(state)
    }
    fn referenced_by_record(&self, release: &ReleaseRef) -> bool {
        [&self.record.current, &self.record.previous]
            .into_iter()
            .flatten()
            .any(|r| r.release == release.release)
            || self
                .ledger
                .retired_jobs
                .iter()
                .any(|job| job.release.release == release.release)
    }
    pub fn discard_candidate(&mut self, release: &ReleaseRef) -> io::Result<()> {
        self.no_updates()?;
        if self.referenced_by_record(release) || self.pending.is_some() || !self.garbage.is_empty()
        {
            return Err(invalid());
        }
        self.verify_release(release)?;
        self.remove_release(release)
    }
    fn remove_release(&self, release: &ReleaseRef) -> io::Result<()> {
        self.remove_release_with(release, &mut |_| Ok(()))
    }
    fn remove_release_with(
        &self,
        release: &ReleaseRef,
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<()> {
        let name = managed_release::hexadecimal(&release.release);
        let path = self.versions.path.join(&name);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return self.versions.file.sync_all().map_err(redact)
            }
            Err(e) => return Err(redact(e)),
            Ok(_) => {}
        }
        let directory = Directory::open(path, self.directory.uid, ERRORS)?;
        let entries = self.partial_release_entries(&directory, release)?;
        for name in entries {
            directory.verify()?;
            rustix::fs::unlinkat(&directory.file, &name, rustix::fs::AtFlags::empty())
                .map_err(|e| redact(e.into()))?;
            checkpoint(if name == "gp-proxy" {
                "garbage_binary_removed"
            } else {
                "garbage_metadata_removed"
            })?;
        }
        directory.file.sync_all().map_err(redact)?;
        self.versions.verify()?;
        if !release.directory.matches(&directory.path) {
            return Err(ERRORS.denied());
        }
        rustix::fs::unlinkat(&self.versions.file, &name, rustix::fs::AtFlags::REMOVEDIR)
            .map_err(|e| redact(e.into()))?;
        self.versions.file.sync_all().map_err(redact)?;
        checkpoint("garbage_directory_removed")
    }
    fn partial_release_entries(
        &self,
        directory: &Directory,
        release: &ReleaseRef,
    ) -> io::Result<Vec<OsString>> {
        if directory.identity != release.directory {
            return Err(ERRORS.denied());
        }
        let mut entries = Vec::new();
        for item in fs::read_dir(&directory.path).map_err(redact)? {
            let item = item.map_err(redact)?;
            let name = item.file_name();
            let (expected, executable) = if name == "gp-proxy" {
                (release.binary, true)
            } else if name == "release.json" {
                (release.metadata, false)
            } else {
                return Err(invalid());
            };
            let meta = fs::symlink_metadata(item.path()).map_err(redact)?;
            if Identity::of(&meta) != expected
                || !meta.is_file()
                || meta.file_type().is_symlink()
                || meta.nlink() != 1
                || meta.mode() & 0o7777 != if executable { 0o700 } else { 0o600 }
            {
                return Err(ERRORS.denied());
            }
            if executable {
                let source = Source::open(&item.path())?;
                if source.digest() != release.release || source.len() != release.bytes {
                    return Err(invalid());
                }
            } else {
                let observed: VersionRecord =
                    decode(&read_file(directory, "release.json", META_LIMIT)?.bytes)?;
                if observed.version != 1
                    || observed.installation != self.ownership.installation
                    || observed.store != self.directory.identity
                    || observed.release != *release
                {
                    return Err(invalid());
                }
            }
            entries.push(name);
        }
        Ok(entries)
    }

    fn plist_references(&self) -> Vec<&OwnedPlist> {
        let mut refs = Vec::with_capacity(5);
        if let Some(plist) = &self.record.plist {
            refs.push(plist);
        }
        if let Some(tx) = &self.pending {
            if let Some(plist) = &tx.previous.plist {
                refs.push(plist);
            }
            if let Some(plist) = &tx.next.plist {
                refs.push(plist);
            }
        }
        for job in &self.ledger.retired_jobs {
            refs.push(&job.plist);
        }
        refs
    }
    pub fn publish_plist(
        &mut self,
        path: &Path,
        bytes: &[u8],
        expected: Option<&OwnedPlist>,
    ) -> io::Result<OwnedPlist> {
        self.no_updates()?;
        let mut tx = self.pending.clone().ok_or_else(invalid)?;
        if matches!(tx.operation, Operation::Resume | Operation::Recover)
            || expected != tx.previous.plist.as_ref()
        {
            return Err(invalid());
        }
        let mut proof = tx.clone();
        proof.phase = Phase::Stopped;
        proof.outcome = None;
        self.validate_transaction(&proof)?;
        if tx.next.plist_path.as_deref() != Some(path) {
            return Err(invalid());
        }
        valid_plist_path(path, &tx.next.label)?;
        if bytes
            != crate::launchd::render_plist(
                self.directory.uid,
                &tx.next.label,
                &tx.next.gate.binary,
                &self.runtime_path(),
                &tx.next.gate.identity,
            )?
        {
            return Err(invalid());
        }

        let refs = self.plist_references();
        let slot = (0..crate::managed_plist::SLOT_COUNT)
            .find(|slot| {
                !refs
                    .iter()
                    .any(|reference| usize::from(reference.slot) == *slot)
            })
            .ok_or_else(|| io::Error::other("managed plist capacity reached"))?;
        let planned = self.plists.plan(slot as u8, path, bytes)?;
        tx.next.plist = Some(planned.clone());
        self.save_transaction(tx)?;
        self.plists.write_and_publish(&planned, bytes)?;
        Ok(planned)
    }
    pub fn recover_plist(&mut self) -> io::Result<OwnedPlist> {
        self.no_updates()?;
        let tx = self.pending.as_ref().ok_or_else(invalid)?;
        if matches!(tx.operation, Operation::Resume | Operation::Recover) {
            return Err(invalid());
        }
        let planned = tx.next.plist.as_ref().ok_or_else(invalid)?;
        let bytes = crate::launchd::render_plist(
            self.directory.uid,
            &tx.next.label,
            &tx.next.gate.binary,
            &self.runtime_path(),
            &tx.next.gate.identity,
        )?;
        self.plists.write_and_publish(planned, &bytes)?;
        Ok(planned.clone())
    }
    pub fn remove_plist(&mut self, expected: &OwnedPlist) -> io::Result<()> {
        self.no_updates()?;
        let tx = self.pending.as_ref().ok_or_else(invalid)?;
        if tx.operation == Operation::Resume || tx.previous.plist.as_ref() != Some(expected) {
            return Err(invalid());
        }
        let mut proof = tx.clone();
        proof.phase = Phase::Stopped;
        proof.outcome = None;
        self.validate_transaction(&proof)?;
        self.plists.remove(expected)
    }
    pub fn remove_unstarted_plist(
        &mut self,
        expected: &OwnedPlist,
        retired: &managed_runtime::RetiredRuntime,
    ) -> io::Result<()> {
        self.no_updates()?;
        retired.verifies_path(&self.runtime_path())?;
        let tx = self.pending.as_ref().ok_or_else(invalid)?;
        if tx.operation == Operation::Resume
            || tx.next.plist.as_ref() != Some(expected)
            || tx.previous.plist.as_ref() == Some(expected)
            || !matches!(
                tx.phase,
                Phase::Prepared
                    | Phase::Maintenance
                    | Phase::StopRequested
                    | Phase::Stopped
                    | Phase::RuntimeRetired
                    | Phase::OldJobRemovalRequested
                    | Phase::OldJobRemoved
                    | Phase::PlistPublished
                    | Phase::Configured
            )
        {
            return Err(invalid());
        }
        self.plists.remove(expected)
    }
    pub fn remove_retired_plist(&mut self, job: &RetiredJob) -> io::Result<()> {
        self.no_updates()?;
        if job.removal_unknown || !self.ledger.retired_jobs.contains(job) {
            return Err(invalid());
        }
        self.plists.remove(&job.plist)
    }
    pub fn verify_current_plist(&self) -> io::Result<()> {
        self.no_updates()?;
        self.plists
            .verify(self.record.plist.as_ref().ok_or_else(invalid)?)
    }
}

fn validate_stop(stop: &StopEvidence, identity: ManagedIdentity) -> io::Result<()> {
    if matches!(
        stop.source,
        CleanupEvidenceSource::RuntimeTerminal { ordinal: 0, .. }
            | CleanupEvidenceSource::RuntimeTerminal { sequence: 0, .. }
    ) {
        return Err(invalid());
    }
    let cleanup = stop.report.cleanup;
    if stop.instance == [0; 16]
        || stop.managed != identity
        || !stop.report.local_cleanup_complete
        || cleanup
            .logout_confirmed
            .checked_add(cleanup.logout_unconfirmed)
            != Some(cleanup.known_sessions)
    {
        return Err(invalid());
    }
    Ok(())
}
fn evidence_fingerprint<T: Serialize>(evidence: &T) -> io::Result<[u8; 32]> {
    Ok(managed_release::digest_bytes(&encode(
        evidence, META_LIMIT,
    )?))
}
fn merge_ledger(ledger: &mut RecoveryLedger, tx: &mut Transaction) -> io::Result<()> {
    for (index, unknown) in [&tx.previous_unknown, &tx.next_unknown]
        .into_iter()
        .enumerate()
    {
        if let Some(unknown) = unknown {
            let fingerprint = evidence_fingerprint(unknown)?;
            if tx.accounted_cleanup[index + 2] != Some(fingerprint) {
                ledger.unconfirmed_episodes = ledger.unconfirmed_episodes.saturating_add(1);
                ledger.remote_outcome_unknown = true;
                ledger.last_unknown = Some(unknown.clone());
                tx.accounted_cleanup[index + 2] = Some(fingerprint);
            }
        }
    }
    for (index, stop) in [&tx.stop, &tx.next_stop].into_iter().enumerate() {
        if let Some(stop) = stop {
            let fingerprint = evidence_fingerprint(stop)?;
            if tx.accounted_cleanup[index] != Some(fingerprint) {
                tx.accounted_cleanup[index] = Some(fingerprint);
            }
        }
    }
    if tx.stop.is_some() {
        ledger.last_previous_stop = tx.stop.clone();
    }
    if tx.next_stop.is_some() {
        ledger.last_next_stop = tx.next_stop.clone();
    }
    ledger.last_applied_transaction = ledger.last_applied_transaction.max(tx.id);
    Ok(())
}

fn committable(tx: &Transaction) -> bool {
    match tx.operation {
        Operation::Install | Operation::Uninstall => tx.phase == Phase::Configured,
        Operation::Recover => false,
        Operation::Stop => matches!(tx.phase, Phase::Configured | Phase::RuntimeRetired),
        Operation::Start | Operation::Resume => tx.phase == Phase::Ready,
        Operation::Upgrade => {
            tx.phase == Phase::Ready
                || (tx.phase == Phase::Configured
                    && !tx.previous.gate.enabled
                    && !tx.next.gate.enabled)
        }
    }
}
fn lock_marker(installation: &[u8; 16]) -> Vec<u8> {
    format!(
        "gp-proxy-deployment-lock-v2\n{}\n",
        managed_release::hexadecimal(installation)
    )
    .into_bytes()
}
fn validate_plist_ref(plist: &OwnedPlist, uid: u32) -> io::Result<()> {
    let path = plist.path.to_str().ok_or_else(invalid)?;
    if !plist.path.is_absolute()
        || path.len() > 1024
        || path.chars().any(char::is_control)
        || plist.identity.uid != uid
        || plist.bytes == 0
        || plist.bytes > PLIST_LIMIT
        || usize::from(plist.slot) >= crate::managed_plist::SLOT_COUNT
    {
        return Err(invalid());
    }
    Ok(())
}
fn valid_plist_path(path: &Path, label: &str) -> io::Result<()> {
    let value = path.to_str().ok_or_else(invalid)?;
    if !path.is_absolute()
        || value.len() > 1024
        || value.chars().any(char::is_control)
        || path.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
        || path.file_name() != Some(std::ffi::OsStr::new(&format!("{label}.plist")))
    {
        return Err(invalid());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::CleanupSummary;
    use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 8];
            getrandom::fill(&mut random).unwrap();
            let base = PathBuf::from(format!(
                "/tmp/gp-ds-{}",
                managed_release::hexadecimal(&random)
            ));
            fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
            Self(fs::canonicalize(base).unwrap())
        }
        fn root(&self) -> PathBuf {
            self.0.join("state")
        }
        fn source(&self, id: u8) -> Source {
            let path = self.0.join(format!("binary-{id}"));
            fs::write(&path, [id; 4096]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Source::open(&path).unwrap()
        }
        fn gate(&self, source: &Source) -> Gate {
            Gate {
                version: 2,
                identity: ManagedIdentity {
                    installation: [4; 16],
                    generation: 1,
                    release: source.digest(),
                },
                enabled: false,
                binary: self
                    .root()
                    .join("versions")
                    .join(managed_release::hexadecimal(&source.digest()))
                    .join("gp-proxy"),
                config: self.0.join("selected.toml"),
                control: self.root().join("data/control"),
                logs: self.root().join("data/logs"),
            }
        }
        fn installed(&self) -> Store {
            let mut source = self.source(1);
            let gate = self.gate(&source);
            let mut store = Store::initialize(&self.root(), &gate).unwrap();
            let release = store.prepare_release(&mut source).unwrap();
            let mut next = store.record().clone();
            next.current = Some(release);
            store.begin(Operation::Install, next).unwrap();
            store.advance(Phase::Configured, None).unwrap();
            store.commit().unwrap();
            store
        }
        fn plist(&self, store: &Store) -> PathBuf {
            let mut identity = store.record.gate.identity;
            identity.generation += 1;
            self.0.join(format!(
                "{}.plist",
                crate::launchd::label_for(&identity).unwrap()
            ))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn proof(record: &Record) -> StopEvidence {
        StopEvidence {
            source: CleanupEvidenceSource::Ipc,
            instance: [5; 16],
            managed: record.gate.identity,
            report: StopReport {
                local_cleanup_complete: true,
                cleanup: CleanupSummary::default(),
            },
        }
    }
    fn start_next(store: &Store) -> Record {
        let mut next = store.record.clone();
        next.gate.identity.generation += 1;
        next.label = crate::launchd::label_for(&next.gate.identity).unwrap();
        next.gate.enabled = true;
        next
    }
    fn planned_plist(store: &Store) -> Vec<u8> {
        let next = &store.pending().unwrap().next;
        crate::launchd::render_plist(
            store.directory.uid,
            &next.label,
            &next.gate.binary,
            &store.runtime_path(),
            &next.gate.identity,
        )
        .unwrap()
    }
    fn tree(path: &Path) -> Vec<(PathBuf, u64, u32, Vec<u8>)> {
        fn visit(path: &Path, result: &mut Vec<(PathBuf, u64, u32, Vec<u8>)>) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let meta = fs::symlink_metadata(entry.path()).unwrap();
                let bytes = if meta.is_file() {
                    fs::read(entry.path()).unwrap()
                } else {
                    Vec::new()
                };
                result.push((entry.path(), meta.ino(), meta.mode() & 0o7777, bytes));
                if meta.is_dir() {
                    visit(&entry.path(), result);
                }
            }
        }
        let mut result = Vec::new();
        visit(path, &mut result);
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    #[test]
    fn configured_install_and_repeated_upgrades_keep_two_versions_and_user_data() {
        let f = Fixture::new();
        let mut store = f.installed();
        assert!(!store.record.gate.enabled);
        assert!(store.record.plist.is_none());
        assert!(store.pending().is_none());
        assert_eq!(store.version_names().unwrap().len(), 1);
        let owner = read_file(&store.directory, "owner", META_LIMIT)
            .unwrap()
            .identity;
        let lock = read_file(&store.directory, "store.lock", 128)
            .unwrap()
            .identity;
        let runtime_before = tree(&store.runtime_path());
        for path in [
            store.record.gate.config.clone(),
            f.0.join("public-ca.pem"),
            f.0.join("pac-history"),
            f.0.join("pac-history.lock"),
        ] {
            fs::write(path, b"synthetic preserved reference").unwrap();
        }
        for name in ["control", "logs"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(f.root().join("data").join(name))
                .unwrap();
            fs::write(
                f.root()
                    .join("data")
                    .join(name)
                    .join("owned-by-another-protocol"),
                b"preserve",
            )
            .unwrap();
        }
        let retained = [
            tree(&f.root().join("data/control")),
            tree(&f.root().join("data/logs")),
        ];
        for id in 2..=5 {
            let mut source = f.source(id);
            let release = store.prepare_release(&mut source).unwrap();
            let mut next = store.record.clone();
            next.previous = next.current.take();
            next.current = Some(release.clone());
            next.gate.identity.generation += 1;
            next.label = crate::launchd::label_for(&next.gate.identity).unwrap();
            next.gate.identity.release = release.release;
            next.gate.binary = store.version_path(&release);
            next.gate.enabled = true;
            let old = store.record.clone();
            store.begin(Operation::Upgrade, next).unwrap();
            if old.gate.enabled {
                assert!(store.advance(Phase::RuntimeRetired, None).is_err());
            }
            store
                .advance(Phase::Ready, old.gate.enabled.then(|| proof(&old)))
                .unwrap();
            store.commit().unwrap();
            assert_eq!(store.version_names().unwrap().len(), 2);
            assert_eq!(
                read_file(&store.directory, "owner", META_LIMIT)
                    .unwrap()
                    .identity,
                owner
            );
            assert_eq!(
                read_file(&store.directory, "store.lock", 128)
                    .unwrap()
                    .identity,
                lock
            );
        }
        assert_eq!(tree(&store.runtime_path()), runtime_before);
        assert_eq!(tree(&f.root().join("data/control")), retained[0]);
        assert_eq!(tree(&f.root().join("data/logs")), retained[1]);
        assert_eq!(
            fs::read(&store.record.gate.config).unwrap(),
            b"synthetic preserved reference"
        );
        drop(store);
        let store = Store::open(&f.root()).unwrap();
        assert_eq!(store.version_names().unwrap().len(), 2);
    }

    #[test]
    fn maintenance_and_three_version_budget_are_real_and_candidates_are_never_overwritten() {
        let f = Fixture::new();
        let mut first = f.source(1);
        let mut store = Store::initialize(&f.root(), &f.gate(&first)).unwrap();
        assert!(Store::open(&f.root()).is_err());
        let one = store.prepare_release(&mut first).unwrap();
        let before = tree(&store.versions.path);
        assert_eq!(store.prepare_release(&mut first).unwrap(), one);
        assert_eq!(tree(&store.versions.path), before);
        let two = store.prepare_release(&mut f.source(2)).unwrap();
        let three = store.prepare_release(&mut f.source(3)).unwrap();
        assert!(store.prepare_release(&mut f.source(4)).is_err());
        assert_eq!(store.version_names().unwrap().len(), 3);
        store.discard_candidate(&two).unwrap();
        assert_eq!(store.version_names().unwrap().len(), 2);
        store.prepare_release(&mut f.source(4)).unwrap();
        assert!(store.version_path(&three).exists());
    }

    #[test]
    fn partial_candidate_and_changed_source_are_preserved_without_new_staging_names() {
        for cut in [
            "candidate_created",
            "candidate_copied",
            "candidate_ready",
            "candidate_published",
        ] {
            let f = Fixture::new();
            let mut source = f.source(1);
            let mut store = Store::initialize(&f.root(), &f.gate(&source)).unwrap();
            assert!(store
                .prepare_with(&mut source, &mut |point| if point == cut {
                    Err(io::Error::other("synthetic copy interruption"))
                } else {
                    Ok(())
                })
                .is_err());
            let before = tree(&store.versions.path);
            drop(store);
            if matches!(cut, "candidate_ready" | "candidate_published") {
                let mut store = Store::open(&f.root()).unwrap();
                let recovered = store.prepare_release(&mut source);
                assert_eq!(recovered.unwrap().release, source.digest());
            } else {
                assert!(Store::open(&f.root()).is_err());
                assert_eq!(tree(&f.root().join("versions")), before);
            }
        }
        let f = Fixture::new();
        let mut source = f.source(1);
        let mut store = Store::initialize(&f.root(), &f.gate(&source)).unwrap();
        fs::write(f.0.join("binary-1"), b"changed").unwrap();
        assert!(store.prepare_release(&mut source).is_err());
        assert!(store.version_names().unwrap().is_empty());
        assert!(!store.versions.path.join(".candidate").exists());
    }

    #[test]
    fn interrupted_snapshot_requires_explicit_recovery_and_keeps_unknown_facts() {
        for cut in [
            "slot_invalidated",
            "slot_partial_payload",
            "slot_prepared",
            "slot_committed",
        ] {
            let f = Fixture::new();
            let mut store = f.installed();
            store.begin(Operation::Start, start_next(&store)).unwrap();
            let mut state = store.state();
            state.pending.as_mut().unwrap().phase = Phase::NewJobLoadRequested;
            assert!(store
                .persist_with(state, &mut |point| {
                    if point == cut {
                        Err(io::Error::other("synthetic snapshot interruption"))
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(store);
            if cut == "slot_committed" {
                assert_eq!(
                    Store::open(&f.root()).unwrap().pending().unwrap().phase,
                    Phase::NewJobLoadRequested
                );
            } else {
                assert!(Store::open(&f.root()).is_err());
                let mut store = Store::open_recovery(&f.root()).unwrap();
                assert!(store.note_unknown(UnknownReason::OperationFailed).is_err());
                store.repair_metadata().unwrap();
                assert!(store.ledger.metadata_interrupted);
                assert!(store.ledger.remote_outcome_unknown);
                let tx = store.pending().unwrap();
                assert_eq!(tx.phase, Phase::Prepared);
                assert!(tx.outcome.is_some());
                assert!(tx.next_unknown.is_some());
                assert_eq!(
                    tx.next_unknown.as_ref().unwrap().managed,
                    tx.next.gate.identity
                );
            }
        }
    }

    #[test]
    fn live_identity_changes_links_and_unknown_objects_block_mutations() {
        for fault in 0..5 {
            let f = Fixture::new();
            let mut store = f.installed();
            let target = f.root().join("state/slot-0");
            match fault {
                0 => {
                    fs::write(f.root().join("unknown"), b"untouched").unwrap();
                }
                1 => {
                    fs::rename(&target, f.0.join("original")).unwrap();
                    fs::copy(f.0.join("original"), &target).unwrap();
                }
                2 => {
                    fs::rename(&target, f.0.join("original")).unwrap();
                    symlink(f.0.join("original"), &target).unwrap();
                }
                3 => {
                    fs::hard_link(&target, f.0.join("extra-link")).unwrap();
                }
                _ => {
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
            let before = tree(&f.root());
            assert!(store.begin(Operation::Start, start_next(&store)).is_err());
            assert_eq!(tree(&f.root()), before);
        }
        for stage in [false, true] {
            for kind in 0..3 {
                let f = Fixture::new();
                let store = f.installed();
                let path = store.versions.path.join(if stage {
                    ".candidate".to_owned()
                } else {
                    "a".repeat(64)
                });
                match kind {
                    0 => fs::write(&path, b"foreign").unwrap(),
                    1 => symlink(f.0.join("binary-1"), &path).unwrap(),
                    _ => {
                        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                        fs::write(path.join("unknown"), b"preserve").unwrap();
                    }
                }
                let before = tree(&f.root());
                drop(store);
                assert!(Store::open(&f.root()).is_err());
                assert_eq!(tree(&f.root()), before);
            }
        }
    }

    #[test]
    fn plist_has_exact_ownership_and_active_record_requires_bound_stop_evidence() {
        let f = Fixture::new();
        let mut store = f.installed();
        let path = f.plist(&store);
        let mut next = start_next(&store);
        next.plist_path = Some(path.clone());
        store.begin(Operation::Start, next).unwrap();
        let plist_bytes = planned_plist(&store);
        fs::write(&path, b"foreign file").unwrap();
        assert!(store.publish_plist(&path, &plist_bytes, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"foreign file");
        fs::remove_file(&path).unwrap();
        let owned = store.publish_plist(&path, &plist_bytes, None).unwrap();
        assert_eq!(store.pending().unwrap().next.plist.as_ref(), Some(&owned));
        assert_eq!(store.recover_plist().unwrap(), owned);
        store.advance(Phase::Ready, None).unwrap();
        store.commit().unwrap();
        let mut next = store.record.clone();
        next.gate.enabled = false;
        next.current = None;
        next.previous = store.record.current.clone();
        next.plist = None;
        let previous = store.record.clone();
        store.begin(Operation::Uninstall, next).unwrap();
        assert!(store.remove_plist(&owned).is_err());
        assert!(store.advance(Phase::RuntimeRetired, None).is_err());
        let mut bad = proof(&previous);
        bad.managed.generation += 1;
        assert!(store.advance(Phase::Stopped, Some(bad)).is_err());
        let mut uncertain = proof(&previous);
        uncertain.report.cleanup = CleanupSummary {
            known_sessions: 1,
            logout_confirmed: 0,
            logout_unconfirmed: 1,
            remote_outcome_unknown: 2,
        };
        store
            .advance(Phase::OldJobRemoved, Some(uncertain))
            .unwrap();
        fs::rename(&path, f.0.join("original-plist")).unwrap();
        fs::copy(f.0.join("original-plist"), &path).unwrap();
        assert!(store.remove_plist(&owned).is_err());
        assert_eq!(fs::read(&path).unwrap(), plist_bytes);
        fs::remove_file(&path).unwrap();
        fs::rename(f.0.join("original-plist"), &path).unwrap();
        store.remove_plist(&owned).unwrap();
        store.advance(Phase::Configured, None).unwrap();
        store.commit().unwrap();
        assert!(!path.exists());
        assert!(store.record.current.is_none());
        assert!(store.record.previous.is_some());
        assert!(f.root().join("owner").exists());
        assert!(store.runtime_path().exists());
    }

    #[test]
    fn owned_store_cutpoint_helper() {
        let Some(base) = std::env::var_os("GP_DEPLOYMENT_TEST_BASE") else {
            return;
        };
        // The parent owns fixture cleanup. An unexpected checkpoint EOF must
        // not unwind this child's Fixture and delete the parent's evidence.
        let fixture = std::mem::ManuallyDrop::new(Fixture(PathBuf::from(base)));
        let point = std::env::var("GP_DEPLOYMENT_TEST_POINT").unwrap();
        let mut checkpoint = |at: &'static str| -> io::Result<()> {
            if at == point {
                // The parent observes existence, so create/write must finish
                // under another name before publishing this marker atomically.
                fs::write(fixture.0.join("ready.next"), at.as_bytes())?;
                fs::rename(fixture.0.join("ready.next"), fixture.0.join("ready"))?;
                // Retries Interrupted; EOF is an error, never permission to
                // proceed past a crash cutpoint into the next mutation.
                std::io::stdin().read_exact(&mut [0; 1])?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected crash-cutpoint input",
                ));
            }
            Ok(())
        };
        if point.starts_with("store_") {
            let source = Source::open(&fixture.0.join("binary-1")).unwrap();
            Store::initialize_with(&fixture.root(), &fixture.gate(&source), &mut checkpoint)
                .unwrap();
        } else {
            let mut store = Store::open(&fixture.root()).unwrap();
            if point.starts_with("finish_") {
                store.begin(Operation::Start, start_next(&store)).unwrap();
                store.advance(Phase::NewJobLoadRequested, None).unwrap();
                let managed = store.pending().unwrap().next.gate.identity;
                store
                    .record_cleanup_unknown(
                        CleanupTarget::Attempted,
                        UnknownCleanup {
                            managed,
                            instance: None,
                            reason: UnknownReason::StopUnobserved,
                        },
                    )
                    .unwrap();
                let target = closed_target(&mut store);
                let mut maintenance =
                    managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
                maintenance.set_gate(&target.gate).unwrap();
                let retired = maintenance.try_runtime().unwrap();
                store
                    .finish_recovery_with(target, &retired, &mut |at| {
                        let named = match at {
                            "slot_invalidated" => "finish_invalidated",
                            "slot_partial_payload" => "finish_partial",
                            "slot_prepared" => "finish_prepared",
                            "slot_committed" => "finish_committed",
                            _ => return Ok(()),
                        };
                        checkpoint(named)
                    })
                    .unwrap();
            } else if point.starts_with("candidate_") {
                let mut source = Source::open(&fixture.0.join("binary-2")).unwrap();
                store.prepare_with(&mut source, &mut checkpoint).unwrap();
            } else {
                store.begin(Operation::Start, start_next(&store)).unwrap();
                let mut state = store.state();
                state.pending.as_mut().unwrap().phase = Phase::NewJobLoadRequested;
                store.persist_with(state, &mut checkpoint).unwrap();
            }
        }
    }

    #[test]
    fn real_owned_sigkill_preserves_each_durable_file_boundary() {
        use std::{
            process::{Child, Command, Stdio},
            thread,
            time::{Duration, Instant},
        };
        struct Process(Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let input = self.0.stdin.take();
                let _ = self.0.kill();
                let _ = self.0.wait();
                drop(input);
            }
        }
        for cut in [
            "store_stage_created",
            "store_stage_ready",
            "store_published",
            "candidate_created",
            "candidate_copied",
            "candidate_ready",
            "candidate_published",
            "slot_invalidated",
            "slot_partial_payload",
            "slot_prepared",
            "slot_committed",
            "finish_invalidated",
            "finish_partial",
            "finish_prepared",
            "finish_committed",
        ] {
            let f = Fixture::new();
            if cut.starts_with("store_") {
                drop(f.source(1));
            } else {
                drop(f.installed());
                drop(f.source(2));
            }
            let mut process = Process(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "deployment_store::tests::owned_store_cutpoint_helper",
                        "--nocapture",
                    ])
                    .env_clear()
                    .env("GP_DEPLOYMENT_TEST_BASE", &f.0)
                    .env("GP_DEPLOYMENT_TEST_POINT", cut)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            while !f.0.join("ready").exists() {
                assert!(
                    process.0.try_wait().unwrap().is_none(),
                    "helper exited before {cut}"
                );
                assert!(Instant::now() < deadline, "helper deadline at {cut}");
                thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(fs::read(f.0.join("ready")).unwrap(), cut.as_bytes());
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "helper left cutpoint {cut}"
            );
            let paused = tree(&f.0);
            let next_length: Option<u64> = None;
            let input = process.0.stdin.take().unwrap();
            process.0.kill().unwrap();
            let status = process.0.wait().unwrap();
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9), "cut {cut}");
            drop(input);
            assert_eq!(
                tree(&f.0),
                paused,
                "cutpoint mutated before termination: {cut}"
            );
            eprintln!("store cutpoint {cut}: next_bytes={next_length:?}, terminal_signal={:?}, snapshot_unchanged=true", status.signal());
            if cut.starts_with("store_") {
                let source = Source::open(&f.0.join("binary-1")).unwrap();
                match cut {
                    "store_stage_created" => {
                        let before = tree(&f.0);
                        assert!(Store::initialize(&f.root(), &f.gate(&source)).is_err());
                        assert_eq!(tree(&f.0), before);
                    }
                    "store_stage_ready" => {
                        assert_eq!(
                            Store::initialize(&f.root(), &f.gate(&source))
                                .unwrap()
                                .record
                                .gate,
                            f.gate(&source)
                        );
                    }
                    _ => {
                        assert!(Store::open(&f.root()).is_ok());
                    }
                }
            } else if cut.starts_with("candidate_") {
                let before = tree(&f.root());
                if matches!(cut, "candidate_created" | "candidate_copied") {
                    assert!(Store::open(&f.root()).is_err());
                    assert_eq!(tree(&f.root()), before);
                } else {
                    let mut store = Store::open(&f.root()).unwrap();
                    let mut source = Source::open(&f.0.join("binary-2")).unwrap();
                    assert_eq!(
                        store.prepare_release(&mut source).unwrap().release,
                        source.digest()
                    );
                }
            } else if cut.starts_with("finish_") {
                let mut store = Store::open_recovery(&f.root()).unwrap();
                store.repair_metadata().unwrap();
                let maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
                let gate = maintenance.read_gate().unwrap();
                assert!(!gate.enabled);
                let mut target = store.record.clone();
                target.gate = gate;
                target.label = crate::launchd::label_for(&target.gate.identity).unwrap();
                target.plist = None;
                let retired = maintenance.try_runtime().unwrap();
                store.finish_recovery(target, &retired).unwrap();
                assert!(store.pending.is_none());
                assert_eq!(store.ledger.unconfirmed_episodes, 1);
                assert!(store.ledger.remote_outcome_unknown);
            } else if cut == "slot_committed" {
                assert_eq!(
                    Store::open(&f.root()).unwrap().pending().unwrap().phase,
                    Phase::NewJobLoadRequested
                );
            } else {
                assert!(Store::open(&f.root()).is_err());
                let mut store = Store::open_recovery(&f.root()).unwrap();
                store.repair_metadata().unwrap();
                assert!(store.pending().unwrap().outcome.is_some());
                assert!(store.ledger.metadata_interrupted);
            }
        }
    }

    #[test]
    fn inactive_upgrade_commits_configured_and_recovers_only_journal_owned_prune_fragments() {
        for foreign in [false, true] {
            let f = Fixture::new();
            let mut store = f.installed();
            let oldest = store.record.current.clone().unwrap();
            for id in [2, 3] {
                let release = store.prepare_release(&mut f.source(id)).unwrap();
                let mut next = store.record.clone();
                next.previous = next.current.take();
                next.current = Some(release.clone());
                next.gate.identity.release = release.release;
                next.gate.identity.generation += 1;
                next.label = crate::launchd::label_for(&next.gate.identity).unwrap();
                next.gate.binary = store.version_path(&release);
                assert!(!next.gate.enabled);
                store.begin(Operation::Upgrade, next.clone()).unwrap();
                store.advance(Phase::Configured, None).unwrap();
                if id == 2 {
                    store.commit().unwrap();
                } else {
                    // Simulate interruption after the durable new record and
                    // first exact obsolete unlink, while retaining its journal.
                    let mut state = store.state();
                    state.record = next;
                    merge_ledger(&mut state.ledger, state.pending.as_mut().unwrap()).unwrap();
                    store.persist(state).unwrap();
                    fs::remove_file(store.version_path(&oldest)).unwrap();
                    if foreign {
                        fs::write(
                            store
                                .version_path(&oldest)
                                .parent()
                                .unwrap()
                                .join("foreign"),
                            b"preserve",
                        )
                        .unwrap();
                    }
                }
            }
            drop(store);
            let before = tree(&f.root());
            let reopened = Store::open(&f.root());
            if foreign {
                assert!(reopened.is_err());
                assert_eq!(tree(&f.root()), before);
            } else {
                let mut store = reopened.unwrap();
                assert!(store.pending.is_some());
                store.commit().unwrap();
                assert_eq!(store.version_names().unwrap().len(), 2);
                assert!(!store.version_path(&oldest).parent().unwrap().exists());
                assert!(!store.record.gate.enabled);
                assert!(store.record.plist.is_none());
            }
        }
    }

    #[test]
    fn resume_requires_current_plist_and_never_changes_files_or_generation() {
        let f = Fixture::new();
        let mut store = f.installed();
        let path = f.plist(&store);
        let mut next = start_next(&store);
        next.plist_path = Some(path.clone());
        store.begin(Operation::Start, next).unwrap();
        let plist_bytes = planned_plist(&store);
        let owned = store.publish_plist(&path, &plist_bytes, None).unwrap();
        store.advance(Phase::Ready, None).unwrap();
        store.commit().unwrap();
        store.verify_current_plist().unwrap();
        let expected = store.record.clone();
        let before = tree(&f.root());
        let mut changed = expected.clone();
        changed.gate.identity.generation += 1;
        assert!(store.begin(Operation::Resume, changed).is_err());
        assert_eq!(tree(&f.root()), before);
        fs::rename(&path, f.0.join("known-plist")).unwrap();
        fs::copy(f.0.join("known-plist"), &path).unwrap();
        assert!(store.verify_current_plist().is_err());
        assert!(store.begin(Operation::Resume, expected.clone()).is_err());
        assert_eq!(fs::read(&path).unwrap(), plist_bytes);
        fs::remove_file(&path).unwrap();
        fs::rename(f.0.join("known-plist"), &path).unwrap();
        store.begin(Operation::Resume, expected.clone()).unwrap();
        assert!(store.advance(Phase::Stopped, None).is_err());
        assert!(store
            .publish_plist(&path, b"forbidden update", Some(&owned))
            .is_err());
        assert!(store.remove_plist(&owned).is_err());
        assert!(store.recover_plist().is_err());
        assert!(store.begin(Operation::Resume, expected.clone()).is_err());
        store.advance(Phase::NewJobLoadRequested, None).unwrap();
        store.advance(Phase::NewJobLoaded, None).unwrap();
        store.advance(Phase::Ready, None).unwrap();
        store.commit().unwrap();
        assert_eq!(store.record, expected);
        let stable = |entries: Vec<(PathBuf, u64, u32, Vec<u8>)>| {
            entries
                .into_iter()
                .filter(|(path, ..)| !path.starts_with(f.root().join("state")))
                .collect::<Vec<_>>()
        };
        assert!(
            stable(tree(&f.root())) == stable(before),
            "resume changed non-snapshot deployment objects"
        );
        store.verify_current_plist().unwrap();
    }
    fn closed_target(store: &mut Store) -> Record {
        let mut target = store.record.clone();
        target.gate.identity.generation = store.reserve_generation().unwrap();
        target.gate.enabled = false;
        target.label = crate::launchd::label_for(&target.gate.identity).unwrap();
        target.plist = None;
        target.plist_path = target.plist_path.as_ref().map(|path| {
            path.parent()
                .unwrap()
                .join(format!("{}.plist", target.label))
        });
        target
    }
    fn attempted_proof(store: &Store, instance: u8, unconfirmed: u64) -> StopEvidence {
        StopEvidence {
            source: CleanupEvidenceSource::Ipc,
            instance: [instance; 16],
            managed: store.pending().unwrap().next.gate.identity,
            report: StopReport {
                local_cleanup_complete: true,
                cleanup: CleanupSummary {
                    known_sessions: unconfirmed,
                    logout_confirmed: 0,
                    logout_unconfirmed: unconfirmed,
                    remote_outcome_unknown: unconfirmed,
                },
            },
        }
    }

    #[test]
    fn cleanup_receipts_are_instance_bound_and_only_clear_matching_temporary_unknown() {
        let f = Fixture::new();
        let mut store = f.installed();
        store.begin(Operation::Start, start_next(&store)).unwrap();
        store.advance(Phase::NewJobLoadRequested, None).unwrap();
        store.observe_previous_instance([7; 16]).unwrap();
        store.observe_previous_instance([7; 16]).unwrap();
        assert!(store.observe_previous_instance([8; 16]).is_err());
        let proof_a = attempted_proof(&store, 8, 1);
        store
            .record_cleanup_unknown(
                CleanupTarget::Attempted,
                UnknownCleanup {
                    managed: proof_a.managed,
                    instance: Some(proof_a.instance),
                    reason: UnknownReason::StopUnobserved,
                },
            )
            .unwrap();
        let old = proof(&store.record);
        assert!(store.record_cleanup(CleanupTarget::Attempted, old).is_err());
        store
            .record_cleanup(CleanupTarget::Attempted, proof_a.clone())
            .unwrap();
        assert!(store.pending().unwrap().next_unknown.is_none());
        store
            .record_cleanup(CleanupTarget::Attempted, proof_a)
            .unwrap();
        assert_eq!(store.ledger.logout_unconfirmed, 0);
        let proof_b = attempted_proof(&store, 9, 0);
        store
            .record_cleanup_unknown(
                CleanupTarget::Attempted,
                UnknownCleanup {
                    managed: proof_b.managed,
                    instance: None,
                    reason: UnknownReason::MetadataInterrupted,
                },
            )
            .unwrap();
        store
            .record_cleanup(CleanupTarget::Attempted, proof_b)
            .unwrap();
        assert_eq!(store.ledger.logout_unconfirmed, 0);
        assert!(!store.ledger.remote_outcome_unknown);
        assert!(store.pending().unwrap().next_unknown.is_some());
        store.note_unknown(UnknownReason::OperationFailed).unwrap();
        assert_eq!(store.pending().unwrap().phase, Phase::NewJobLoadRequested);
        assert_eq!(
            store.pending().unwrap().outcome.as_ref().unwrap().at_phase,
            Phase::NewJobLoadRequested
        );
    }

    #[test]
    fn committed_ledger_is_not_counted_again_when_pending_pruning_resumes() {
        let f = Fixture::new();
        let mut store = f.installed();
        store.begin(Operation::Start, start_next(&store)).unwrap();
        let proof = attempted_proof(&store, 9, 1);
        store
            .record_cleanup(CleanupTarget::Attempted, proof.clone())
            .unwrap();
        store
            .record_cleanup_unknown(
                CleanupTarget::Attempted,
                UnknownCleanup {
                    managed: proof.managed,
                    instance: None,
                    reason: UnknownReason::UnobservedIncarnation,
                },
            )
            .unwrap();
        store.advance(Phase::Ready, None).unwrap();
        let mut state = store.state();
        state.record = state.pending.as_ref().unwrap().next.clone();
        merge_ledger(&mut state.ledger, state.pending.as_mut().unwrap()).unwrap();
        store.persist(state).unwrap();
        assert_eq!(store.ledger.unconfirmed_episodes, 1);
        assert_eq!(store.ledger.logout_unconfirmed, 0);
        drop(store);
        let mut store = Store::open(&f.root()).unwrap();
        store.commit().unwrap();
        assert_eq!(store.ledger.unconfirmed_episodes, 1);
        assert_eq!(store.ledger.logout_unconfirmed, 0);
        assert!(store.ledger.remote_outcome_unknown);
        assert!(store.pending.is_none());
        assert!(store.commit().is_err());
        assert_eq!(store.ledger.unconfirmed_episodes, 1);
    }

    #[test]
    fn finish_recovery_interruption_is_reentrant_and_never_restores_enabled_state() {
        for cut in [
            "slot_invalidated",
            "slot_partial_payload",
            "slot_prepared",
            "slot_committed",
        ] {
            let f = Fixture::new();
            let mut store = f.installed();
            store.begin(Operation::Start, start_next(&store)).unwrap();
            store.advance(Phase::NewJobLoadRequested, None).unwrap();
            let managed = store.pending().unwrap().next.gate.identity;
            store
                .record_cleanup_unknown(
                    CleanupTarget::Attempted,
                    UnknownCleanup {
                        managed,
                        instance: Some([9; 16]),
                        reason: UnknownReason::StopUnobserved,
                    },
                )
                .unwrap();
            let target = closed_target(&mut store);
            let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
            maintenance.set_gate(&target.gate).unwrap();
            let retired = maintenance.try_runtime().unwrap();
            assert!(store
                .finish_recovery_with(target.clone(), &retired, &mut |point| {
                    if point == cut {
                        Err(io::Error::other("synthetic finish interruption"))
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            drop(store);
            let mut store = Store::open_recovery(&f.root()).unwrap();
            store.repair_metadata().unwrap();
            store.finish_recovery(target.clone(), &retired).unwrap();
            let ledger = encode(store.ledger(), META_LIMIT).unwrap();
            store.finish_recovery(target.clone(), &retired).unwrap();
            assert_eq!(encode(store.ledger(), META_LIMIT).unwrap(), ledger);
            assert_eq!(store.record, target);
            assert!(store.pending.is_none());
            assert!(store.ledger.remote_outcome_unknown);
            assert_eq!(store.ledger.unconfirmed_episodes, 1);
            assert!(!maintenance.read_gate().unwrap().enabled);
        }
    }

    fn retired_job(f: &Fixture, store: &mut Store, slot: u8) -> RetiredJob {
        let mut managed = store.record.gate.identity;
        managed.generation = store.reserve_generation().unwrap();
        let label = crate::launchd::label_for(&managed).unwrap();
        let path = f.0.join(format!("{label}.plist"));
        let bytes = crate::launchd::render_plist(
            store.directory.uid,
            &label,
            &store.record.gate.binary,
            &store.runtime_path(),
            &managed,
        )
        .unwrap();
        RetiredJob {
            managed,
            label,
            plist: store.plists.plan(slot, &path, &bytes).unwrap(),
            release: store.record.current.clone().unwrap(),
            removal_unknown: true,
            anchor_pinned: false,
        }
    }

    #[test]
    fn retired_capacity_and_positive_removal_survive_repeated_recovery_until_atomic_finish() {
        let f = Fixture::new();
        let mut store = f.installed();
        let a = retired_job(&f, &mut store, 0);
        let b = retired_job(&f, &mut store, 1);
        let c = retired_job(&f, &mut store, 2);
        store.retain_retired_job(a.clone()).unwrap();
        store.retain_retired_job(b.clone()).unwrap();
        assert!(store.retain_retired_job(c).is_err());
        let target = closed_target(&mut store);
        store.begin(Operation::Recover, target.clone()).unwrap();
        let confirmed = store.confirm_retired_job_removal(&a).unwrap();
        store.remove_retired_plist(&confirmed).unwrap();
        store.forget_retired_job(&confirmed).unwrap();
        assert_eq!(store.ledger.retired_jobs.len(), 2);
        drop(store);
        let mut store = Store::open(&f.root()).unwrap();
        store.retain_retired_job(a.clone()).unwrap();
        assert!(!store.ledger.retired_jobs[0].removal_unknown);
        let mut wrong = a;
        wrong.managed.generation += 1;
        assert!(store.retain_retired_job(wrong).is_err());
        let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
        maintenance.set_gate(&target.gate).unwrap();
        let retired = maintenance.try_runtime().unwrap();
        store.finish_recovery(target, &retired).unwrap();
        assert_eq!(store.ledger.retired_jobs, [b]);
        assert!(store
            .version_path(&store.ledger.retired_jobs[0].release)
            .exists());
    }

    #[test]
    fn generation_exhaustion_and_wrong_retirement_namespace_do_not_mutate() {
        let f = Fixture::new();
        let other = Fixture::new();
        let mut store = f.installed();
        let other_store = other.installed();
        let target = closed_target(&mut store);
        store.begin(Operation::Recover, target.clone()).unwrap();
        let maintenance = managed_runtime::open_maintenance(&other_store.runtime_path()).unwrap();
        let wrong = maintenance.try_runtime().unwrap();
        let before = store.recovery_token().unwrap();
        assert!(store.finish_recovery(target, &wrong).is_err());
        assert_eq!(store.recovery_token().unwrap(), before);
        let mut state = store.state();
        state.generation_highwater = u64::MAX;
        store.persist(state).unwrap();
        let before = store.recovery_token().unwrap();
        assert!(store.reserve_generation().is_err());
        assert_eq!(store.recovery_token().unwrap(), before);
    }

    #[test]
    fn reinstall_uses_retained_ownership_generation_and_uncertainty_without_v1_adoption() {
        let f = Fixture::new();
        let mut store = f.installed();
        let identities = (
            store.ownership.directory,
            store.ownership.lock,
            store.ownership.runtime,
        );
        let mut removed = store.record.clone();
        removed.current = None;
        removed.previous = None;
        store.begin(Operation::Uninstall, removed).unwrap();
        let managed = store.record.gate.identity;
        store
            .record_cleanup_unknown(
                CleanupTarget::Previous,
                UnknownCleanup {
                    managed,
                    instance: None,
                    reason: UnknownReason::UnobservedIncarnation,
                },
            )
            .unwrap();
        store.advance(Phase::Configured, None).unwrap();
        store.commit().unwrap();
        drop(store);
        let mut store = Store::open(&f.root()).unwrap();
        let mut source = f.source(2);
        let release = store.prepare_release(&mut source).unwrap();
        let mut next = closed_target(&mut store);
        next.current = Some(release.clone());
        next.gate.identity.release = release.release;
        next.gate.binary = store.version_path(&release);
        store.begin(Operation::Install, next.clone()).unwrap();
        let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
        let _retired = maintenance.try_runtime().unwrap();
        maintenance.set_gate(&next.gate).unwrap();
        store.advance(Phase::Configured, None).unwrap();
        store.commit().unwrap();
        assert_eq!(
            (
                store.ownership.directory,
                store.ownership.lock,
                store.ownership.runtime
            ),
            identities
        );
        assert_eq!(store.ledger.unconfirmed_episodes, 1);
        assert!(store.ledger.remote_outcome_unknown);
        assert_eq!(store.generation_highwater, 2);
        assert_eq!(store.record.installation, managed.installation);
        drop(store);
        let path = f.root().join("owner");
        let mut v1: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        v1["version"] = 1.into();
        fs::write(&path, serde_json::to_vec(&v1).unwrap()).unwrap();
        let before = tree(&f.root());
        assert_eq!(
            Store::open(&f.root()).err().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(
            tree(&f.root()) == before,
            "v1 namespace must not be modified"
        );
    }
    #[test]
    fn cleanup_observed_after_record_commit_is_merged_without_recounting_old_evidence() {
        let f = Fixture::new();
        let mut store = f.installed();
        store.begin(Operation::Start, start_next(&store)).unwrap();
        let earlier = attempted_proof(&store, 8, 1);
        store
            .record_cleanup(CleanupTarget::Attempted, earlier)
            .unwrap();
        store.advance(Phase::Ready, None).unwrap();
        let mut state = store.state();
        state.record = state.pending.as_ref().unwrap().next.clone();
        merge_ledger(&mut state.ledger, state.pending.as_mut().unwrap()).unwrap();
        store.persist(state).unwrap();
        assert_eq!(store.ledger.logout_unconfirmed, 0);
        let later = attempted_proof(&store, 9, 2);
        store
            .record_cleanup(CleanupTarget::Attempted, later.clone())
            .unwrap();
        assert_eq!(
            store.ledger.logout_unconfirmed, 0,
            "runtime histories must not also be added through Store receipts"
        );
        store
            .record_cleanup_unknown(
                CleanupTarget::Attempted,
                UnknownCleanup {
                    managed: later.managed,
                    instance: None,
                    reason: UnknownReason::UnobservedIncarnation,
                },
            )
            .unwrap();
        let target = closed_target(&mut store);
        let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
        maintenance.set_gate(&target.gate).unwrap();
        let retired = maintenance.try_runtime().unwrap();
        store.finish_recovery(target.clone(), &retired).unwrap();
        assert_eq!(store.ledger.logout_unconfirmed, 0);
        assert_eq!(store.ledger.unconfirmed_episodes, 1);
        assert_eq!(
            store.ledger.last_next_stop.as_ref().unwrap().instance,
            [9; 16]
        );
        assert!(store.ledger.remote_outcome_unknown);
        store.finish_recovery(target, &retired).unwrap();
        assert_eq!(store.ledger.logout_unconfirmed, 0);
    }

    #[test]
    fn unreaped_load_pins_known_anchor_and_release_even_after_confirmed_job_removal() {
        let f = Fixture::new();
        let mut store = f.installed();
        let mut job = retired_job(&f, &mut store, 0);
        store.retain_retired_job(job.clone()).unwrap();
        job.anchor_pinned = true;
        store.retain_retired_job(job.clone()).unwrap();
        let mut downgrade = job.clone();
        downgrade.anchor_pinned = false;
        store.retain_retired_job(downgrade).unwrap();
        assert!(store.ledger.retired_jobs[0].anchor_pinned);
        let confirmed = store.confirm_retired_job_removal(&job).unwrap();
        store.remove_retired_plist(&confirmed).unwrap();
        store.forget_retired_job(&confirmed).unwrap();
        assert_eq!(store.ledger.retired_jobs.len(), 1);
        let target = closed_target(&mut store);
        store.begin(Operation::Recover, target.clone()).unwrap();
        store.mark_load_child(true).unwrap();
        assert!(store.pending().unwrap().load_child_may_live);
        store.mark_load_child(false).unwrap();
        assert!(!store.pending().unwrap().load_child_may_live);
        let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
        maintenance.set_gate(&target.gate).unwrap();
        let retired = maintenance.try_runtime().unwrap();
        store.finish_recovery(target, &retired).unwrap();
        assert_eq!(store.ledger.retired_jobs, [confirmed]);
        assert!(store.version_path(&job.release).exists());
    }
    #[test]
    fn exact_garbage_queue_survives_each_delete_and_snapshot_boundary() {
        for cut in [
            "garbage_binary_removed",
            "garbage_metadata_removed",
            "garbage_directory_removed",
            "garbage_files_removed",
            "slot_invalidated",
            "slot_partial_payload",
            "slot_prepared",
            "slot_committed",
            "garbage_queue_recorded",
        ] {
            let f = Fixture::new();
            let mut store = f.installed();
            let original = store.record.current.clone().unwrap();
            let candidate = store.prepare_release(&mut f.source(2)).unwrap();
            let mut next = start_next(&store);
            next.current = Some(candidate.clone());
            next.previous = Some(original.clone());
            next.gate.identity.release = candidate.release;
            next.gate.binary = store.version_path(&candidate);
            store.begin(Operation::Upgrade, next).unwrap();
            store.advance(Phase::NewJobLoadRequested, None).unwrap();
            let target = closed_target(&mut store);
            let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
            maintenance.set_gate(&target.gate).unwrap();
            let retired = maintenance.try_runtime().unwrap();
            assert!(store
                .finish_recovery_with(target.clone(), &retired, &mut |point| {
                    if point == "garbage_enqueued" {
                        Err(io::Error::other("synthetic enqueue cut"))
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            assert_eq!(store.garbage, std::slice::from_ref(&candidate));
            assert!(store.pending.is_none());
            assert!(store.prepare_release(&mut f.source(3)).is_err());
            assert!(store.begin(Operation::Recover, target).is_err());
            assert!(
                store
                    .drain_garbage_with(&retired, &mut |point| {
                        if point == cut {
                            Err(io::Error::other("synthetic garbage cut"))
                        } else {
                            Ok(())
                        }
                    })
                    .is_err(),
                "{cut}"
            );
            drop(store);
            let mut store = Store::open_recovery(&f.root()).unwrap();
            store.repair_metadata().unwrap();
            store.drain_garbage(&retired).unwrap();
            assert!(!store.has_garbage());
            assert!(!store.version_path(&candidate).parent().unwrap().exists());
            assert!(store.version_path(&original).exists());
            assert_eq!(store.version_names().unwrap().len(), 1);
            assert_eq!(store.record.current.as_ref(), Some(&original));
            store.prepare_release(&mut f.source(3)).unwrap();
            assert_eq!(store.version_names().unwrap().len(), 2);
        }
    }

    #[test]
    fn garbage_never_deletes_unknown_entries_and_forgetting_unreferenced_job_enqueues_ownership() {
        for foreign in [false, true] {
            let f = Fixture::new();
            let mut store = f.installed();
            let candidate = store.prepare_release(&mut f.source(2)).unwrap();
            let mut managed = store.record.gate.identity;
            managed.generation = store.reserve_generation().unwrap();
            managed.release = candidate.release;
            let label = crate::launchd::label_for(&managed).unwrap();
            let path = f.0.join(format!("{label}.plist"));
            let bytes = crate::launchd::render_plist(
                store.directory.uid,
                &label,
                &store.version_path(&candidate),
                &store.runtime_path(),
                &managed,
            )
            .unwrap();
            let job = RetiredJob {
                managed,
                label,
                plist: store.plists.plan(0, &path, &bytes).unwrap(),
                release: candidate.clone(),
                removal_unknown: true,
                anchor_pinned: false,
            };
            store.retain_retired_job(job.clone()).unwrap();
            let confirmed = store.confirm_retired_job_removal(&job).unwrap();
            store.remove_retired_plist(&confirmed).unwrap();
            store.forget_retired_job(&confirmed).unwrap();
            assert_eq!(store.garbage, std::slice::from_ref(&candidate));
            assert!(store.ledger.retired_jobs.is_empty());
            let maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
            let retired = maintenance.try_runtime().unwrap();
            if foreign {
                let unknown = store
                    .version_path(&candidate)
                    .parent()
                    .unwrap()
                    .join("foreign");
                fs::write(&unknown, b"must stay").unwrap();
                let before = tree(&f.root());
                assert!(store.drain_garbage(&retired).is_err());
                drop(store);
                assert!(Store::open_recovery(&f.root()).is_err());
                assert!(
                    tree(&f.root()) == before,
                    "unknown entry and known neighbors must remain unchanged"
                );
                assert_eq!(fs::read(unknown).unwrap(), b"must stay");
            } else {
                store.drain_garbage(&retired).unwrap();
                assert!(!store.has_garbage());
                assert!(!store.version_path(&candidate).parent().unwrap().exists());
            }
        }
    }

    #[test]
    fn first_canonical_start_reopens_at_each_load_and_commit_boundary() {
        let f = Fixture::new();
        let mut store = f.installed();
        let mut next = start_next(&store);
        let path = f.plist(&store);
        next.plist_path = Some(path.clone());
        store.begin(Operation::Start, next).unwrap();
        let bytes = planned_plist(&store);
        store.publish_plist(&path, &bytes, None).unwrap();
        store.advance(Phase::NewJobLoadRequested, None).unwrap();
        store.mark_load_child(true).unwrap();
        drop(store);
        let mut store = Store::open(&f.root()).unwrap();
        assert!(store.pending().unwrap().load_child_may_live);
        store.mark_load_child(false).unwrap();
        store.advance(Phase::NewJobLoaded, None).unwrap();
        store.advance(Phase::Ready, None).unwrap();
        drop(store);
        let mut store = Store::open(&f.root()).unwrap();
        store.commit().unwrap();
        drop(store);
        let store = Store::open(&f.root()).unwrap();
        assert!(store.pending().is_none());
        assert!(store.record.gate.enabled);
        store.verify_current_plist().unwrap();
    }
    #[test]
    fn delegated_data_staging_does_not_disable_management_or_expand_root_ownership() {
        let f = Fixture::new();
        let mut store = f.installed();
        let data = f.root().join("data");
        let stage = data.join(".gp-log-init-logs");
        fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
        fs::write(stage.join("partial-subsystem-owned-state"), b"preserve").unwrap();
        fs::write(data.join("unrecognized-data"), b"not managed by deployment").unwrap();
        let before = tree(&data);
        let target = closed_target(&mut store);
        store.begin(Operation::Recover, target.clone()).unwrap();
        let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
        maintenance.set_gate(&target.gate).unwrap();
        let retired = maintenance.try_runtime().unwrap();
        store.finish_recovery(target, &retired).unwrap();
        assert!(
            tree(&data) == before,
            "deployment must neither adopt nor remove subsystem staging"
        );
        drop(store);
        let store = Store::open(&f.root()).unwrap();
        assert!(!store.record.gate.enabled);
        fs::write(f.root().join(".gp-log-init-logs"), b"unknown root object").unwrap();
        let root_before = tree(&f.root());
        assert!(store.verify().is_err());
        assert!(
            tree(&f.root()) == root_before,
            "root prefix is not an ownership grant"
        );
        fs::remove_file(f.root().join(".gp-log-init-logs")).unwrap();
        fs::rename(&data, f.0.join("original-data")).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&data).unwrap();
        assert!(store.verify().is_err());
        drop(store);
        assert!(Store::open_recovery(&f.root()).is_err());
        assert!(
            tree(&f.0.join("original-data"))
                == before
                    .into_iter()
                    .map(|(path, ino, mode, bytes)| (
                        f.0.join("original-data")
                            .join(path.strip_prefix(&data).unwrap()),
                        ino,
                        mode,
                        bytes
                    ))
                    .collect::<Vec<_>>()
        );
    }
    #[test]
    fn runtime_terminal_provenance_is_exact_and_receipts_never_recount_history() {
        let f = Fixture::new();
        let mut store = f.installed();
        let next = start_next(&store);
        let managed = next.gate.identity;
        store.begin(Operation::Start, next.clone()).unwrap();
        let mut maintenance = managed_runtime::open_maintenance(&store.runtime_path()).unwrap();
        maintenance.set_gate(&next.gate).unwrap();
        let runtime_lease =
            managed_runtime::RuntimeLease::acquire(&store.runtime_path(), &managed).unwrap();
        let id = store.ownership.runtime;
        let journal = crate::managed_lifecycle::Journal::open(
            &store.runtime_path().join("lifecycle"),
            managed.installation,
            [id.device, id.inode, u64::from(id.uid)],
        )
        .unwrap();
        let stamp = journal.begin(managed, [45; 16]).unwrap();
        let report = StopReport {
            local_cleanup_complete: true,
            cleanup: CleanupSummary {
                known_sessions: 1,
                logout_confirmed: 0,
                logout_unconfirmed: 1,
                remote_outcome_unknown: 2,
            },
        };
        journal.finish(&stamp, &report).unwrap();
        let view = maintenance.lifecycle().unwrap();
        let durable = store
            .record_durable_cleanup(CleanupTarget::Attempted, &view, managed, [45; 16])
            .unwrap();
        assert_eq!(
            durable.source,
            CleanupEvidenceSource::RuntimeTerminal {
                ordinal: 1,
                sequence: view.sequence
            }
        );
        assert!(
            store
                .record_cleanup(CleanupTarget::Attempted, durable.clone())
                .is_err(),
            "disk evidence cannot enter IPC API"
        );
        store
            .record_durable_cleanup(CleanupTarget::Attempted, &view, managed, [45; 16])
            .unwrap();
        store
            .record_cleanup(
                CleanupTarget::Attempted,
                StopEvidence::ipc([45; 16], managed, report.clone()),
            )
            .unwrap();
        // Re-reading a durable fact cannot fabricate a new IPC receipt or
        // downgrade the provenance of the reply that really was received.
        store
            .record_durable_cleanup(CleanupTarget::Attempted, &view, managed, [45; 16])
            .unwrap();
        assert_eq!(
            store.pending().unwrap().next_stop.as_ref().unwrap().source,
            CleanupEvidenceSource::Ipc
        );
        assert!(store
            .record_durable_cleanup(CleanupTarget::Attempted, &view, managed, [46; 16])
            .is_err());
        let mut different = report.clone();
        different.cleanup.remote_outcome_unknown = 3;
        assert!(store
            .record_cleanup(
                CleanupTarget::Attempted,
                StopEvidence::ipc([45; 16], managed, different)
            )
            .is_err());
        store.advance(Phase::Ready, None).unwrap();
        store.commit().unwrap();
        assert_eq!(store.ledger.logout_unconfirmed, 0);
        assert!(!store.ledger.remote_outcome_unknown);
        let final_view = maintenance.lifecycle().unwrap();
        assert_eq!(final_view.history.finished_incarnations, 1);
        assert_eq!(final_view.history.unconfirmed_finished_incarnations, 1);
        assert_eq!(final_view.history.completed.logout_unconfirmed, 1);
        assert_eq!(final_view.history.completed.remote_outcome_unknown, 2);
        let mut closed = store.record().clone();
        closed.gate.enabled = false;
        store.begin(Operation::Stop, closed).unwrap();
        store.observe_previous_instance([45; 16]).unwrap();
        assert!(
            store
                .record_cleanup(
                    CleanupTarget::Previous,
                    StopEvidence::ipc([46; 16], managed, report.clone())
                )
                .is_err(),
            "B must not replace observed A"
        );
        store
            .record_cleanup_unknown(
                CleanupTarget::Previous,
                UnknownCleanup {
                    managed,
                    instance: Some([45; 16]),
                    reason: UnknownReason::RuntimeRetiredWithoutReceipt,
                },
            )
            .unwrap();
        store
            .record_durable_cleanup(CleanupTarget::Previous, &view, managed, [45; 16])
            .unwrap();
        assert!(store.pending().unwrap().previous_unknown.is_none());
        assert_eq!(
            store.pending().unwrap().stop.as_ref().unwrap().source,
            durable.source
        );
        let foreign = f.0.join("foreign-journal");
        crate::managed_lifecycle::Journal::initialize(&foreign, managed.installation).unwrap();
        let other =
            crate::managed_lifecycle::Journal::open(&foreign, managed.installation, [0, 1, 2])
                .unwrap();
        let other_stamp = other.begin(managed, [45; 16]).unwrap();
        other.finish(&other_stamp, &report).unwrap();
        assert!(store
            .record_durable_cleanup(
                CleanupTarget::Previous,
                &other.read().unwrap(),
                managed,
                [45; 16]
            )
            .is_err());
        drop(runtime_lease);
    }
    #[test]
    fn prior_state_payload_is_rejected_without_implicit_adoption() {
        let f = Fixture::new();
        let store = f.installed();
        let mut old = store.state();
        old.version = 2;
        {
            let mut guard = store.snapshot.lock().unwrap();
            let current = guard.read().unwrap();
            guard
                .write(current.sequence, &encode(&old, STATE_LIMIT).unwrap())
                .unwrap();
        }
        drop(store);
        let before = tree(&f.root());
        assert_eq!(
            Store::open(&f.root()).err().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(tree(&f.root()), before);
    }
}
