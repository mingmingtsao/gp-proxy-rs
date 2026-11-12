//! Credential-free, inode-bound snapshots. A damaged slot is never a reason to
//! silently use an older state. Recovery requires an independent expected value.
#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]

use crate::{
    managed_release::digest_bytes,
    private_fs::{self, Directory, Errors, Identity, Parents},
};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::{self, File, Metadata},
    io,
    os::unix::fs::{FileExt, MetadataExt},
    path::Path,
};

const ERRORS: Errors = Errors {
    denied: "snapshot ownership or identity changed",
    invalid: "invalid owned snapshot",
    operation: "snapshot filesystem operation failed",
};
const OWNER_LIMIT: usize = 2048;
pub(crate) const MAX_PAYLOAD: usize = 128 * 1024;
const HEADER: usize = 64;
const MAGIC: &[u8; 8] = b"GPSNAP2\n";
const NAMES: [&str; 4] = ["owner", "lock", "slot-0", "slot-1"];
type Checkpoint<'a> = &'a mut dyn FnMut(&'static str) -> io::Result<()>;

fn invalid() -> io::Error {
    ERRORS.invalid()
}
fn redact(error: io::Error) -> io::Error {
    ERRORS.redact(error)
}
fn dirty() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "snapshot requires explicit recovery",
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SnapshotKind {
    Deployment,
    Runtime,
    RuntimeLifecycle,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u8,
    binding: [u8; 16],
    kind: SnapshotKind,
    maximum: usize,
    directory: Identity,
    lock: Identity,
    slots: [Identity; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Value {
    pub(crate) sequence: u64,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    identity: Identity,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl Stamp {
    fn of(metadata: &Metadata) -> Self {
        Self {
            identity: Identity::of(metadata),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

/// Diagnostic bytes are not permission to replay an external side effect. The
/// token is bound to this exact namespace and both observed file contents.
pub(crate) struct RecoveryView {
    owner: Identity,
    stamps: [Stamp; 2],
    hashes: [[u8; 32]; 2],
    complete: [Option<Value>; 2],
}
impl RecoveryView {
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(&self.owner.device.to_be_bytes());
        bytes.extend_from_slice(&self.owner.inode.to_be_bytes());
        for (stamp, hash) in self.stamps.iter().zip(self.hashes) {
            bytes.extend_from_slice(&stamp.identity.inode.to_be_bytes());
            bytes.extend_from_slice(&stamp.length.to_be_bytes());
            bytes.extend_from_slice(&stamp.modified.0.to_be_bytes());
            bytes.extend_from_slice(&stamp.modified.1.to_be_bytes());
            bytes.extend_from_slice(&stamp.changed.0.to_be_bytes());
            bytes.extend_from_slice(&stamp.changed.1.to_be_bytes());
            bytes.extend_from_slice(&hash);
        }
        digest_bytes(&bytes)
    }
    pub(crate) fn highest_complete(&self) -> Option<&Value> {
        self.complete
            .iter()
            .flatten()
            .max_by_key(|value| value.sequence)
    }
    pub(crate) fn dirty_slots(&self) -> usize {
        self.complete.iter().filter(|value| value.is_none()).count()
    }
    fn valid(&self) -> bool {
        self.dirty_slots() == 0
            && matches!(&self.complete, [Some(a), Some(b)] if a.sequence.abs_diff(b.sequence) == 1)
    }
}

/// Open descriptors do not hold the snapshot lock. The outer deployment and
/// runtime maintenance locks are separate capabilities owned by their callers.
pub(crate) struct OwnedSnapshot {
    directory: Directory,
    owner: File,
    owner_identity: Identity,
    owner_bytes: Vec<u8>,
    ownership: Owner,
    lock: File,
    slots: [File; 2],
}

/// Keep this guard only around bounded local filesystem operations, never while
/// waiting for IPC, a service manager, or an executable probe.
pub(crate) struct SnapshotGuard<'a> {
    snapshot: &'a OwnedSnapshot,
    _lock: SnapshotLock,
}

/// The short critical section ends with this guard, even if a concurrently
/// forked child temporarily inherited the same open file description before
/// exec closes its CLOEXEC descriptor. Permanent process leases intentionally
/// keep their distinct close-on-process-exit behavior.
struct SnapshotLock {
    file: File,
}
impl SnapshotLock {
    fn acquire(file: File) -> io::Result<Self> {
        file.try_lock().map_err(|error| redact(error.into()))?;
        Ok(Self { file })
    }
}
impl Drop for SnapshotLock {
    fn drop(&mut self) {
        // A failure conservatively retains the lock until all descriptors close;
        // Drop cannot report it, and must never panic or retry a snapshot write.
        let _ = self.file.unlock();
    }
}

fn validate_arguments(binding: [u8; 16], maximum: usize) -> io::Result<()> {
    if binding == [0; 16] || !(1..=MAX_PAYLOAD).contains(&maximum) {
        return Err(invalid());
    }
    Ok(())
}

fn open_file(directory: &Directory, name: &str, limit: usize, create: bool) -> io::Result<File> {
    directory.verify()?;
    let prior = if create {
        None
    } else {
        let metadata = fs::symlink_metadata(directory.path.join(name)).map_err(redact)?;
        private_fs::regular(&metadata, directory.uid, limit, ERRORS)?;
        Some(Identity::of(&metadata))
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
        .map_err(|error| redact(error.into()))?,
    );
    let metadata = file.metadata().map_err(redact)?;
    private_fs::regular(&metadata, directory.uid, limit, ERRORS)?;
    if prior.is_some_and(|identity| identity != Identity::of(&metadata)) {
        return Err(ERRORS.denied());
    }
    verify_file(directory, name, &file, Identity::of(&metadata), limit)?;
    Ok(file)
}

fn verify_file(
    directory: &Directory,
    name: &str,
    file: &File,
    identity: Identity,
    limit: usize,
) -> io::Result<Stamp> {
    directory.verify()?;
    let named = fs::symlink_metadata(directory.path.join(name)).map_err(redact)?;
    let opened = file.metadata().map_err(redact)?;
    for metadata in [&named, &opened] {
        private_fs::regular(metadata, directory.uid, limit, ERRORS)?;
        if Identity::of(metadata) != identity {
            return Err(ERRORS.denied());
        }
    }
    if Stamp::of(&named) != Stamp::of(&opened) {
        return Err(ERRORS.denied());
    }
    Ok(Stamp::of(&opened))
}

fn bytes(file: &File, limit: usize) -> io::Result<Vec<u8>> {
    let before = Stamp::of(&file.metadata().map_err(redact)?);
    if before.length > limit as u64 {
        return Err(invalid());
    }
    let mut result = vec![0; before.length as usize];
    file.read_exact_at(&mut result, 0).map_err(redact)?;
    if Stamp::of(&file.metadata().map_err(redact)?) != before {
        return Err(ERRORS.denied());
    }
    Ok(result)
}

fn checksum(sequence: u64, payload: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(16 + payload.len());
    input.extend_from_slice(&sequence.to_be_bytes());
    input.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    input.extend_from_slice(payload);
    digest_bytes(&input)
}

fn frame(sequence: u64, payload: &[u8], maximum: usize) -> io::Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > maximum {
        return Err(invalid());
    }
    let mut result = vec![0; HEADER + maximum];
    result[..8].copy_from_slice(MAGIC);
    result[8..16].copy_from_slice(&sequence.to_be_bytes());
    result[16..24].copy_from_slice(&(payload.len() as u64).to_be_bytes());
    result[24..56].copy_from_slice(&checksum(sequence, payload));
    result[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    Ok(result)
}

fn parse_frame(bytes: &[u8], maximum: usize) -> Option<Value> {
    if bytes.len() != HEADER + maximum || &bytes[..8] != MAGIC || bytes[56..64] != [0; 8] {
        return None;
    }
    let sequence = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
    let length = usize::try_from(u64::from_be_bytes(bytes[16..24].try_into().ok()?)).ok()?;
    if length == 0 || length > maximum || bytes[HEADER + length..].iter().any(|byte| *byte != 0) {
        return None;
    }
    let payload = &bytes[HEADER..HEADER + length];
    if bytes[24..56] != checksum(sequence, payload) {
        return None;
    }
    Some(Value {
        sequence,
        payload: payload.to_vec(),
    })
}

impl OwnedSnapshot {
    pub(crate) fn initialize(
        path: &Path,
        binding: [u8; 16],
        kind: SnapshotKind,
        maximum: usize,
        initial: &[u8],
    ) -> io::Result<Self> {
        Self::initialize_with(path, binding, kind, maximum, initial, &mut |_| Ok(()))
    }

    fn initialize_with(
        path: &Path,
        binding: [u8; 16],
        kind: SnapshotKind,
        maximum: usize,
        initial: &[u8],
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<Self> {
        validate_arguments(binding, maximum)?;
        let frames = [frame(0, initial, maximum)?, frame(1, initial, maximum)?];
        let uid = rustix::process::geteuid().as_raw();
        let path = private_fs::directory_path(path, uid, ERRORS)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(redact(error)),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "snapshot namespace already exists",
                ))
            }
        }
        let parents = Parents::capture(&path, uid, ERRORS)?;
        let parent = parents.open_parent()?;
        let mut name = OsString::from(".gp-snapshot-init-");
        name.push(path.file_name().ok_or_else(invalid)?);
        let stage = path.parent().ok_or_else(invalid)?.join(&name);
        let created = match rustix::fs::mkdirat(&parent, &name, Mode::from_bits_truncate(0o700)) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => return Err(redact(error.into())),
        };
        checkpoint("stage_created")?;
        if created {
            let directory = Directory::open(stage.clone(), uid, ERRORS)?;
            let lock = SnapshotLock::acquire(open_file(&directory, "lock", 64, true)?)?;
            lock.file
                .write_all_at(b"gp-owned-snapshot-lock-v2\n", 0)
                .map_err(redact)?;
            lock.file.sync_all().map_err(redact)?;
            let slots = [
                open_file(&directory, "slot-0", HEADER + maximum, true)?,
                open_file(&directory, "slot-1", HEADER + maximum, true)?,
            ];
            for (slot, frame) in slots.iter().zip(&frames) {
                slot.write_all_at(frame, 0).map_err(redact)?;
                slot.sync_all().map_err(redact)?;
            }
            checkpoint("slots_written")?;
            let ownership = Owner {
                version: 2,
                binding,
                kind,
                maximum,
                directory: directory.identity,
                lock: Identity::of(&lock.file.metadata().map_err(redact)?),
                slots: [
                    Identity::of(&slots[0].metadata().map_err(redact)?),
                    Identity::of(&slots[1].metadata().map_err(redact)?),
                ],
            };
            let mut encoded = serde_json::to_vec(&ownership).map_err(|_| invalid())?;
            encoded.push(b'\n');
            if encoded.len() > OWNER_LIMIT {
                return Err(invalid());
            }
            let owner = open_file(&directory, "owner", OWNER_LIMIT, true)?;
            owner.write_all_at(&encoded, 0).map_err(redact)?;
            owner.sync_all().map_err(redact)?;
            directory.file.sync_all().map_err(redact)?;
        }
        let staging = Self::open(&stage, binding, kind, maximum)?;
        let guard = staging.lock()?;
        let view = guard.inspect()?;
        if !view.valid()
            || view.complete[0].as_ref()
                != Some(&Value {
                    sequence: 0,
                    payload: initial.to_vec(),
                })
            || view.complete[1].as_ref()
                != Some(&Value {
                    sequence: 1,
                    payload: initial.to_vec(),
                })
        {
            return Err(invalid());
        }
        checkpoint("stage_ready")?;
        staging.verify()?;
        parents.verify()?;
        rustix::fs::renameat_with(
            &parent,
            &name,
            &parent,
            path.file_name().ok_or_else(invalid)?,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| redact(error.into()))?;
        checkpoint("published")?;
        parent.sync_all().map_err(redact)?;
        let result = Self::open(&path, binding, kind, maximum)?;
        drop(guard);
        Ok(result)
    }

    pub(crate) fn open(
        path: &Path,
        binding: [u8; 16],
        kind: SnapshotKind,
        maximum: usize,
    ) -> io::Result<Self> {
        validate_arguments(binding, maximum)?;
        let uid = rustix::process::geteuid().as_raw();
        let path = private_fs::directory_path(path, uid, ERRORS)?;
        let directory = Directory::open(path, uid, ERRORS)?;
        let owner = open_file(&directory, "owner", OWNER_LIMIT, false)?;
        let owner_identity = Identity::of(&owner.metadata().map_err(redact)?);
        let owner_bytes = bytes(&owner, OWNER_LIMIT)?;
        let ownership: Owner = serde_json::from_slice(&owner_bytes).map_err(|_| invalid())?;
        if ownership.version != 2
            || ownership.binding != binding
            || ownership.kind != kind
            || ownership.maximum != maximum
            || ownership.directory != directory.identity
        {
            return Err(invalid());
        }
        let lock = open_file(&directory, "lock", 64, false)?;
        let slots = [
            open_file(&directory, "slot-0", HEADER + maximum, false)?,
            open_file(&directory, "slot-1", HEADER + maximum, false)?,
        ];
        let result = Self {
            directory,
            owner,
            owner_identity,
            owner_bytes,
            ownership,
            lock,
            slots,
        };
        result.verify()?;
        Ok(result)
    }

    pub(crate) fn lock(&self) -> io::Result<SnapshotGuard<'_>> {
        self.verify()?;
        // A separately opened descriptor makes nested/concurrent attempts real
        // contenders; flock on a cloned descriptor could reuse the same lock.
        let lock = open_file(&self.directory, "lock", 64, false)?;
        verify_file(&self.directory, "lock", &lock, self.ownership.lock, 64)?;
        let lock = SnapshotLock::acquire(lock)?;
        self.verify()?;
        Ok(SnapshotGuard {
            snapshot: self,
            _lock: lock,
        })
    }

    fn verify(&self) -> io::Result<()> {
        self.directory.verify()?;
        let mut seen = 0u8;
        for entry in fs::read_dir(&self.directory.path).map_err(redact)? {
            let name = entry.map_err(redact)?.file_name();
            let index = NAMES
                .iter()
                .position(|expected| name == *expected)
                .ok_or_else(invalid)?;
            if seen & (1 << index) != 0 {
                return Err(invalid());
            }
            seen |= 1 << index;
        }
        if seen != 15 {
            return Err(invalid());
        }
        verify_file(
            &self.directory,
            "owner",
            &self.owner,
            self.owner_identity,
            OWNER_LIMIT,
        )?;
        if bytes(&self.owner, OWNER_LIMIT)? != self.owner_bytes {
            return Err(ERRORS.denied());
        }
        verify_file(&self.directory, "lock", &self.lock, self.ownership.lock, 64)?;
        if bytes(&self.lock, 64)? != b"gp-owned-snapshot-lock-v2\n" {
            return Err(invalid());
        }
        for (index, slot) in self.slots.iter().enumerate() {
            verify_file(
                &self.directory,
                NAMES[index + 2],
                slot,
                self.ownership.slots[index],
                HEADER + self.ownership.maximum,
            )?;
        }
        Ok(())
    }
}

impl SnapshotGuard<'_> {
    pub(crate) fn inspect(&self) -> io::Result<RecoveryView> {
        let snapshot = self.snapshot;
        snapshot.verify()?;
        let mut stamps = [
            Stamp::of(&snapshot.slots[0].metadata().map_err(redact)?),
            Stamp::of(&snapshot.slots[1].metadata().map_err(redact)?),
        ];
        let mut hashes = [[0; 32]; 2];
        let mut complete = [None, None];
        for (index, slot) in snapshot.slots.iter().enumerate() {
            stamps[index] = verify_file(
                &snapshot.directory,
                NAMES[index + 2],
                slot,
                snapshot.ownership.slots[index],
                HEADER + snapshot.ownership.maximum,
            )?;
            let observed = bytes(slot, HEADER + snapshot.ownership.maximum)?;
            if Stamp::of(&slot.metadata().map_err(redact)?) != stamps[index] {
                return Err(ERRORS.denied());
            }
            hashes[index] = digest_bytes(&observed);
            complete[index] = parse_frame(&observed, snapshot.ownership.maximum);
        }
        snapshot.verify()?;
        Ok(RecoveryView {
            owner: snapshot.owner_identity,
            stamps,
            hashes,
            complete,
        })
    }

    pub(crate) fn read(&self) -> io::Result<Value> {
        let view = self.inspect()?;
        if !view.valid() {
            return Err(dirty());
        }
        view.highest_complete().cloned().ok_or_else(dirty)
    }

    pub(crate) fn write(&mut self, expected_sequence: u64, payload: &[u8]) -> io::Result<Value> {
        self.write_with(expected_sequence, payload, &mut |_| Ok(()))
    }

    pub(crate) fn write_with(
        &mut self,
        expected_sequence: u64,
        payload: &[u8],
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<Value> {
        let view = self.inspect()?;
        if !view.valid() {
            return Err(dirty());
        }
        let current = view.highest_complete().ok_or_else(dirty)?;
        if current.sequence != expected_sequence {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "snapshot revision changed",
            ));
        }
        let sequence = current.sequence.checked_add(1).ok_or_else(invalid)?;
        let index = usize::from(
            view.complete[0].as_ref().ok_or_else(dirty)?.sequence
                > view.complete[1].as_ref().ok_or_else(dirty)?.sequence,
        );
        self.write_slot(index, sequence, payload, checkpoint)?;
        self.read()
    }

    /// `expected` must come from the caller's separately validated recovery
    /// decision, never by silently promoting highest_complete(). The guard and
    /// observation are required together so a changed inode/body is not adopted.
    pub(crate) fn repair(&mut self, observed: &RecoveryView, expected: &[u8]) -> io::Result<Value> {
        self.repair_with(observed, expected, &mut |_| Ok(()))
    }

    fn repair_with(
        &mut self,
        observed: &RecoveryView,
        expected: &[u8],
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<Value> {
        let now = self.inspect()?;
        if now.owner != observed.owner
            || now.stamps != observed.stamps
            || now.hashes != observed.hashes
        {
            return Err(ERRORS.denied());
        }
        let highest = now.highest_complete().ok_or_else(dirty)?;
        let end = highest.sequence.checked_add(2).ok_or_else(invalid)?;
        // Keep one complete slot throughout repair. Both damaged is outside an
        // interruption of this writer and is retained for explicit inspection.
        let first = match &now.complete {
            [None, Some(_)] => 0,
            [Some(_), None] => 1,
            [Some(a), Some(b)] => usize::from(a.sequence > b.sequence),
            [None, None] => return Err(dirty()),
        };
        self.write_slot(first, end - 1, expected, checkpoint)?;
        checkpoint("repair_first_complete")?;
        self.write_slot(1 - first, end, expected, checkpoint)?;
        self.read()
    }

    fn write_slot(
        &self,
        index: usize,
        sequence: u64,
        payload: &[u8],
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<()> {
        let snapshot = self.snapshot;
        let image = frame(sequence, payload, snapshot.ownership.maximum)?;
        snapshot.verify()?;
        let slot = &snapshot.slots[index];
        // Commit magic is written LAST. Replacing the whole header from byte 0
        // could briefly restore old valid metadata over a repeated payload.
        slot.write_all_at(&[0; 8], 0).map_err(redact)?;
        slot.sync_all().map_err(redact)?;
        checkpoint("slot_invalidated")?;
        let half = HEADER + snapshot.ownership.maximum / 2;
        slot.write_all_at(&image[HEADER..half], HEADER as u64)
            .map_err(redact)?;
        checkpoint("slot_partial_payload")?;
        slot.write_all_at(&image[half..], half as u64)
            .map_err(redact)?;
        slot.write_all_at(&image[8..HEADER], 8).map_err(redact)?;
        slot.sync_all().map_err(redact)?;
        checkpoint("slot_prepared")?;
        snapshot.verify()?;
        slot.write_all_at(MAGIC, 0).map_err(redact)?;
        slot.sync_all().map_err(redact)?;
        checkpoint("slot_committed")?;
        snapshot.verify()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        os::unix::{
            fs::{symlink, DirBuilderExt, PermissionsExt},
            process::ExitStatusExt,
        },
        path::PathBuf,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    const BINDING: [u8; 16] = [41; 16];
    const LIMIT: usize = 1024;
    const ENABLED: &[u8] = b"synthetic-enabled";
    const CLOSED: &[u8] = b"independently-expected-closed";

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let name = format!(
                "gp-owned-snapshot-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(name);
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
        fn path(&self) -> PathBuf {
            self.0.join("snapshot")
        }
        fn initialize(&self) -> OwnedSnapshot {
            OwnedSnapshot::initialize(&self.path(), BINDING, SnapshotKind::Runtime, LIMIT, ENABLED)
                .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn open(f: &Fixture) -> io::Result<OwnedSnapshot> {
        OwnedSnapshot::open(&f.path(), BINDING, SnapshotKind::Runtime, LIMIT)
    }
    fn contents(path: &Path) -> Vec<(String, Vec<u8>, Identity)> {
        let mut result = Vec::new();
        for name in NAMES {
            let file = path.join(name);
            result.push((
                name.to_owned(),
                fs::read(&file).unwrap(),
                Identity::of(&fs::symlink_metadata(file).unwrap()),
            ));
        }
        result
    }

    #[test]
    fn completed_guard_releases_short_lock_while_a_duplicate_descriptor_stays_open() {
        let f = Fixture::new();
        let snapshot = f.initialize();
        let before = contents(&f.path());
        let guard = snapshot.lock().unwrap();
        // A duplicate refers to the same open file description, as an inherited
        // fork descriptor does. It does not itself acquire or release the lock.
        let inherited = guard._lock.file.try_clone().unwrap();
        assert_eq!(
            snapshot.lock().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(guard);
        let next = snapshot.lock();
        let result = next.as_ref().map(|_| ()).map_err(io::Error::kind);
        drop(next);
        // Reclaim our duplicate before asserting even against the old behavior.
        drop(inherited);
        assert_eq!(contents(&f.path()), before);
        assert_eq!(
            result,
            Ok(()),
            "completed short guard still held by duplicate"
        );
    }

    #[test]
    fn alternating_updates_are_bounded_and_compare_revisions() {
        let f = Fixture::new();
        let snapshot = f.initialize();
        let ids = snapshot.ownership.slots;
        let mut guard = snapshot.lock().unwrap();
        assert_eq!(
            guard.read().unwrap(),
            Value {
                sequence: 1,
                payload: ENABLED.to_vec()
            }
        );
        assert_eq!(
            snapshot.lock().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        let separately_opened = open(&f).unwrap();
        assert_eq!(
            separately_opened.lock().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        let before = contents(&f.path());
        assert!(guard.write(0, CLOSED).is_err());
        assert!(guard.write(1, &[]).is_err());
        assert!(guard.write(1, &vec![0; LIMIT + 1]).is_err());
        assert_eq!(contents(&f.path()), before);
        for sequence in 1..16 {
            let payload = if sequence % 2 == 0 { ENABLED } else { CLOSED };
            assert_eq!(
                guard.write(sequence, payload).unwrap(),
                Value {
                    sequence: sequence + 1,
                    payload: payload.to_vec()
                }
            );
            for (index, id) in ids.iter().enumerate() {
                let metadata = fs::metadata(f.path().join(NAMES[index + 2])).unwrap();
                assert_eq!(Identity::of(&metadata), *id);
                assert_eq!(metadata.len(), (HEADER + LIMIT) as u64);
            }
        }
    }

    #[test]
    fn every_interrupted_write_requires_explicit_recovery_without_old_enabled_fallback() {
        for cut in [
            "slot_invalidated",
            "slot_partial_payload",
            "slot_prepared",
            "slot_committed",
        ] {
            let f = Fixture::new();
            let snapshot = f.initialize();
            let mut guard = snapshot.lock().unwrap();
            let error = guard
                .write_with(1, CLOSED, &mut |point| {
                    if point == cut {
                        Err(io::Error::other("synthetic cut"))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Other);
            let observed = guard.inspect().unwrap();
            if cut == "slot_committed" {
                assert_eq!(guard.read().unwrap().payload, CLOSED);
                assert_eq!(observed.dirty_slots(), 0);
            } else {
                assert_eq!(guard.read().unwrap_err().kind(), io::ErrorKind::Interrupted);
                assert_eq!(observed.highest_complete().unwrap().payload, ENABLED);
                assert_eq!(observed.dirty_slots(), 1);
            }
            let recovered = guard.repair(&observed, CLOSED).unwrap();
            assert_eq!(recovered.payload, CLOSED);
            assert!(guard.inspect().unwrap().complete.iter().all(|value| value
                .as_ref()
                .unwrap()
                .payload
                == CLOSED));
        }
    }

    #[test]
    fn repair_observation_cannot_be_reused_after_bytes_change_or_across_namespaces() {
        let a = Fixture::new();
        let b = Fixture::new();
        let sa = a.initialize();
        let sb = b.initialize();
        let mut ga = sa.lock().unwrap();
        let mut gb = sb.lock().unwrap();
        let observed = ga.inspect().unwrap();
        assert!(gb.repair(&observed, CLOSED).is_err());
        sa.slots[0].write_all_at(b"X", HEADER as u64).unwrap();
        assert!(ga.repair(&observed, CLOSED).is_err());
        assert!(ga.read().is_err());
        let dirty = ga.inspect().unwrap();
        assert_eq!(ga.repair(&dirty, CLOSED).unwrap().payload, CLOSED);
    }

    #[test]
    fn unknown_objects_binding_replacements_and_links_are_preserved_and_rejected() {
        for mutation in [
            "unknown", "replace", "symlink", "hardlink", "mode", "oversize",
        ] {
            let f = Fixture::new();
            let snapshot = f.initialize();
            let guard = snapshot.lock().unwrap();
            let slot = f.path().join("slot-0");
            match mutation {
                "unknown" => fs::write(f.path().join("foreign"), b"keep").unwrap(),
                "replace" => {
                    fs::rename(&slot, f.0.join("original")).unwrap();
                    fs::copy(f.0.join("original"), &slot).unwrap();
                }
                "symlink" => {
                    fs::rename(&slot, f.0.join("original")).unwrap();
                    symlink(f.0.join("original"), &slot).unwrap();
                }
                "hardlink" => fs::hard_link(&slot, f.0.join("other-link")).unwrap(),
                "mode" => fs::set_permissions(&slot, fs::Permissions::from_mode(0o644)).unwrap(),
                "oversize" => snapshot.slots[0]
                    .set_len((HEADER + LIMIT + 1) as u64)
                    .unwrap(),
                _ => unreachable!(),
            }
            let bytes_before = fs::read(&slot).unwrap();
            assert!(guard.inspect().is_err(), "{mutation}");
            assert!(open(&f).is_err(), "{mutation}");
            assert_eq!(fs::read(slot).unwrap(), bytes_before);
        }
        let f = Fixture::new();
        let _snapshot = f.initialize();
        assert!(OwnedSnapshot::open(&f.path(), [42; 16], SnapshotKind::Runtime, LIMIT).is_err());
        assert!(OwnedSnapshot::open(&f.path(), BINDING, SnapshotKind::Deployment, LIMIT).is_err());
        assert!(OwnedSnapshot::open(&f.path(), BINDING, SnapshotKind::Runtime, LIMIT + 1).is_err());
    }

    #[test]
    fn no_complete_slot_and_sequence_exhaustion_never_reset_or_write() {
        let f = Fixture::new();
        let snapshot = f.initialize();
        let mut guard = snapshot.lock().unwrap();
        for (index, slot) in snapshot.slots.iter().enumerate() {
            slot.write_all_at(
                &frame(u64::MAX - 1 + index as u64, ENABLED, LIMIT).unwrap(),
                0,
            )
            .unwrap();
        }
        let before = contents(&f.path());
        let observed = guard.inspect().unwrap();
        assert!(guard.write(u64::MAX, CLOSED).is_err());
        assert!(guard.repair(&observed, CLOSED).is_err());
        assert_eq!(contents(&f.path()), before);
        for slot in &snapshot.slots {
            slot.write_all_at(&[0; 8], 0).unwrap();
        }
        let observed = guard.inspect().unwrap();
        let before = contents(&f.path());
        assert_eq!(observed.dirty_slots(), 2);
        assert!(guard.repair(&observed, CLOSED).is_err());
        assert_eq!(contents(&f.path()), before);
    }

    #[test]
    fn interrupted_repair_keeps_a_complete_slot_and_unknown_initial_stage_is_not_removed() {
        let f = Fixture::new();
        let snapshot = f.initialize();
        let mut guard = snapshot.lock().unwrap();
        let initial = guard.inspect().unwrap();
        assert!(guard
            .repair_with(&initial, CLOSED, &mut |point| {
                if point == "repair_first_complete" {
                    Err(io::Error::other("synthetic repair cut"))
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert_eq!(guard.read().unwrap().payload, CLOSED);
        let observed = guard.inspect().unwrap();
        assert_eq!(guard.repair(&observed, CLOSED).unwrap().payload, CLOSED);
        let other = Fixture::new();
        let stage = other.0.join(".gp-snapshot-init-snapshot");
        fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
        fs::write(stage.join("foreign"), b"untouched").unwrap();
        assert!(OwnedSnapshot::initialize(
            &other.path(),
            BINDING,
            SnapshotKind::Runtime,
            LIMIT,
            ENABLED
        )
        .is_err());
        assert_eq!(fs::read(stage.join("foreign")).unwrap(), b"untouched");
        assert!(!other.path().exists());
    }

    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let stdin = self.0.stdin.take();
            let _ = self.0.kill();
            let _ = self.0.wait();
            drop(stdin);
        }
    }
    fn checkpoint(base: &Path, target: &str, point: &str) -> io::Result<()> {
        if target == point {
            fs::write(base.join("ready.next"), point.as_bytes())?;
            fs::rename(base.join("ready.next"), base.join("ready"))?;
            // read_exact retries EINTR; EOF and an unexpected byte fail closed.
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected checkpoint release",
            ));
        }
        Ok(())
    }
    #[test]
    fn owned_snapshot_process_helper() {
        let Some(base) = std::env::var_os("GP_SNAPSHOT_TEST_BASE") else {
            return;
        };
        let base = PathBuf::from(base);
        let target = std::env::var("GP_SNAPSHOT_TEST_CUT").unwrap();
        let mode = std::env::var("GP_SNAPSHOT_TEST_MODE").unwrap();
        let path = base.join("snapshot");
        if mode == "initialize" {
            OwnedSnapshot::initialize_with(
                &path,
                BINDING,
                SnapshotKind::Runtime,
                LIMIT,
                ENABLED,
                &mut |point| checkpoint(&base, &target, point),
            )
            .unwrap();
        } else {
            let snapshot =
                OwnedSnapshot::open(&path, BINDING, SnapshotKind::Runtime, LIMIT).unwrap();
            let mut guard = snapshot.lock().unwrap();
            if mode == "write" {
                guard
                    .write_with(1, CLOSED, &mut |point| checkpoint(&base, &target, point))
                    .unwrap();
            } else {
                let view = guard.inspect().unwrap();
                guard
                    .repair_with(&view, CLOSED, &mut |point| {
                        checkpoint(&base, &target, point)
                    })
                    .unwrap();
            }
        }
    }

    fn launch(f: &Fixture, mode: &str, cut: &str) -> Process {
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "owned_snapshot::tests::owned_snapshot_process_helper",
                "--nocapture",
            ])
            .env_remove("SSLKEYLOGFILE")
            .env("GP_SNAPSHOT_TEST_BASE", &f.0)
            .env("GP_SNAPSHOT_TEST_MODE", mode)
            .env("GP_SNAPSHOT_TEST_CUT", cut)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut process = Process(child);
        let start = Instant::now();
        while !f.0.join("ready").exists() {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "helper exited before {mode}/{cut}"
            );
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "checkpoint {mode}/{cut} not reached"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(fs::read(f.0.join("ready")).unwrap(), cut.as_bytes());
        assert!(process.0.try_wait().unwrap().is_none());
        process
    }
    fn kill(process: &mut Process) {
        let stdin = process.0.stdin.take();
        process.0.kill().unwrap();
        let status = process.0.wait().unwrap();
        drop(stdin);
        assert_eq!(status.signal(), Some(9));
    }

    #[test]
    fn owned_sigkill_initialization_write_and_repair_preserve_exact_states() {
        for cut in ["stage_created", "slots_written", "stage_ready", "published"] {
            let f = Fixture::new();
            let mut child = launch(&f, "initialize", cut);
            kill(&mut child);
            if cut == "published" {
                assert_eq!(
                    open(&f).unwrap().lock().unwrap().read().unwrap().payload,
                    ENABLED
                );
                assert!(OwnedSnapshot::initialize(
                    &f.path(),
                    BINDING,
                    SnapshotKind::Runtime,
                    LIMIT,
                    ENABLED
                )
                .is_err());
            } else if cut == "stage_ready" {
                assert_eq!(
                    f.initialize().lock().unwrap().read().unwrap().payload,
                    ENABLED
                );
            } else {
                assert!(!f.path().exists());
                assert!(OwnedSnapshot::initialize(
                    &f.path(),
                    BINDING,
                    SnapshotKind::Runtime,
                    LIMIT,
                    ENABLED
                )
                .is_err());
                assert!(f.0.join(".gp-snapshot-init-snapshot").exists());
            }
            eprintln!("owned_snapshot initialize cut={cut} signal=9");
        }
        for cut in [
            "slot_invalidated",
            "slot_partial_payload",
            "slot_prepared",
            "slot_committed",
            "repair_first_complete",
        ] {
            let f = Fixture::new();
            drop(f.initialize());
            let mode = if cut == "repair_first_complete" {
                "repair"
            } else {
                "write"
            };
            let mut child = launch(&f, mode, cut);
            let before = contents(&f.path());
            kill(&mut child);
            assert_eq!(contents(&f.path()), before, "paused bytes changed at {cut}");
            let snapshot = open(&f).unwrap();
            let mut guard = snapshot.lock().unwrap();
            if matches!(cut, "slot_committed" | "repair_first_complete") {
                assert_eq!(guard.read().unwrap().payload, CLOSED);
            } else {
                assert!(
                    guard.read().is_err(),
                    "must not use enabled predecessor at {cut}"
                );
            }
            let observed = guard.inspect().unwrap();
            assert_eq!(guard.repair(&observed, CLOSED).unwrap().payload, CLOSED);
            eprintln!("owned_snapshot update cut={cut} signal=9 snapshot_unchanged=true");
        }
    }

    #[test]
    fn checkpoint_eof_exits_without_completing_the_slot() {
        let f = Fixture::new();
        drop(f.initialize());
        let mut child = launch(&f, "write", "slot_partial_payload");
        let before = contents(&f.path());
        drop(child.0.stdin.take());
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(!status.success());
        assert_eq!(contents(&f.path()), before);
        assert!(open(&f).unwrap().lock().unwrap().read().is_err());
    }
}
