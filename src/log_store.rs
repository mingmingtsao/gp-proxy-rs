//! Four permanently named, identity-bound log slots. Diagnostic retention is
//! best effort; neither metadata checks nor file locks isolate hostile same-UID
//! writers. All synchronous work belongs on the logging owner/worker thread.
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::atomic::AtomicBool,
};

pub const SLOT_COUNT: usize = 4;
pub const MIN_SLOT_BYTES: u64 = 65_536;
pub const DEFAULT_SLOT_BYTES: u64 = 4_194_304;
pub const MAX_SLOT_BYTES: u64 = 16_777_216;

pub(crate) struct FileRing {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    inner: platform::Ring,
}
impl FileRing {
    pub(crate) fn open(
        directory: PathBuf,
        requested_slot_bytes: Option<u64>,
        cancelled: &AtomicBool,
    ) -> io::Result<Self> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            Ok(Self {
                inner: platform::Ring::open(
                    directory,
                    requested_slot_bytes,
                    cancelled,
                    &mut |_| Ok(()),
                )?,
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
            let _ = (directory, requested_slot_bytes, cancelled);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "private disk logging unavailable on this platform",
            ))
        }
    }
}
impl Write for FileRing {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_all(bytes).map(|()| bytes.len())
    }
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            self.inner.record(bytes)
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            let _ = bytes;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "private disk logging unavailable on this platform",
            ))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            self.inner.flush_checked()
        }
        #[cfg(not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        {
            Ok(())
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
mod platform {
    use super::*;
    use crate::private_fs::{self, Errors, Identity, Parents};
    use rustix::fs::{Mode, OFlags};
    use serde::{Deserialize, Serialize};
    use std::{
        ffi::OsString,
        fs::{self, File, Metadata},
        os::unix::fs::{FileExt, MetadataExt},
        sync::atomic::Ordering,
    };

    const ERRORS: Errors = Errors {
        denied: "private log ownership or permissions are invalid",
        invalid: "invalid private log store",
        operation: "private log store operation failed",
    };
    const OWNER: &str = "owner";
    const LOCK: &str = "lock";
    const META_LIMIT: usize = 8192;
    const MAX_RECORD_BYTES: usize = 4096;
    const HEADER_LEN: usize = 72;
    const MAGIC: &str = "gp-proxy-log-v1";
    const LOCK_MAGIC: &str = "gp-proxy-log-lock-v1\n";
    const SLOTS: [&str; SLOT_COUNT] = ["log-0.txt", "log-1.txt", "log-2.txt", "log-3.txt"];
    type Checkpoint<'a> = &'a mut dyn FnMut(&'static str) -> io::Result<()>;

    fn invalid() -> io::Error {
        ERRORS.invalid()
    }
    fn redact(error: io::Error) -> io::Error {
        ERRORS.redact(error)
    }
    fn check_cancel(cancelled: &AtomicBool) -> io::Result<()> {
        if cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "private log initialization cancelled",
            ));
        }
        Ok(())
    }
    fn capacity(value: u64) -> io::Result<u64> {
        if !(MIN_SLOT_BYTES..=MAX_SLOT_BYTES).contains(&value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private log slot size is outside allowed bounds",
            ));
        }
        Ok(value)
    }
    fn hexadecimal(bytes: &[u8; 16]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn valid_id(value: &str) -> bool {
        value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn header(id: &str, slot: usize, sequence: u64) -> Vec<u8> {
        format!("{MAGIC} {id} {slot} {sequence:020}\n").into_bytes()
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

    struct Directory {
        path: PathBuf,
        file: File,
        identity: Identity,
        parents: Parents,
        uid: u32,
    }
    impl Directory {
        fn open(path: PathBuf, parent: &File, parents: Parents, uid: u32) -> io::Result<Self> {
            parents.verify()?;
            let named = fs::symlink_metadata(&path).map_err(redact)?;
            private_fs::private(&named, uid, 0o700, ERRORS)?;
            if !named.is_dir() {
                return Err(invalid());
            }
            let fd = rustix::fs::openat(
                parent,
                path.file_name().ok_or_else(invalid)?,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| redact(e.into()))?;
            let file = File::from(fd);
            let opened = file.metadata().map_err(redact)?;
            if Identity::of(&named) != Identity::of(&opened) {
                return Err(ERRORS.denied());
            }
            let directory = Self {
                path,
                file,
                identity: Identity::of(&opened),
                parents,
                uid,
            };
            directory.verify()?;
            Ok(directory)
        }
        fn verify(&self) -> io::Result<()> {
            self.parents.verify()?;
            for meta in [
                fs::symlink_metadata(&self.path).map_err(redact)?,
                self.file.metadata().map_err(redact)?,
            ] {
                private_fs::private(&meta, self.uid, 0o700, ERRORS)?;
                if !meta.is_dir() || Identity::of(&meta) != self.identity {
                    return Err(ERRORS.denied());
                }
            }
            Ok(())
        }
        fn inventory(&self) -> io::Result<()> {
            self.verify()?;
            let mut seen = 0u8;
            for item in fs::read_dir(&self.path).map_err(redact)? {
                let name = item.map_err(redact)?.file_name();
                let Some(index) = [OWNER, LOCK, SLOTS[0], SLOTS[1], SLOTS[2], SLOTS[3]]
                    .iter()
                    .position(|expected| name == *expected)
                else {
                    return Err(invalid());
                };
                if seen & (1 << index) != 0 {
                    return Err(invalid());
                }
                seen |= 1 << index;
            }
            if seen != 0x3f {
                return Err(invalid());
            }
            self.verify()
        }
    }

    struct OwnedFile {
        file: File,
        snapshot: Snapshot,
        limit: usize,
        name: &'static str,
    }
    impl OwnedFile {
        fn open(
            directory: &Directory,
            name: &'static str,
            limit: usize,
            create: bool,
            cancelled: Option<&AtomicBool>,
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
            if create {
                check_cancel(cancelled.ok_or_else(invalid)?)?;
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
            if before.is_some_and(|previous| previous != snapshot) {
                return Err(ERRORS.denied());
            }
            let owned = Self {
                file,
                snapshot,
                limit,
                name,
            };
            owned.verify(directory)?;
            Ok(owned)
        }
        fn verify(&self, directory: &Directory) -> io::Result<()> {
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
        fn changed(&mut self, directory: &Directory, bytes: u64) -> io::Result<()> {
            let meta = self.file.metadata().map_err(redact)?;
            private_fs::regular(&meta, directory.uid, self.limit, ERRORS)?;
            if Identity::of(&meta) != self.snapshot.identity
                || meta.len() != bytes
                || meta.mode() != self.snapshot.mode
                || meta.gid() != self.snapshot.gid
                || meta.nlink() != self.snapshot.links
            {
                return Err(ERRORS.denied());
            }
            self.snapshot = Snapshot::of(&meta);
            self.verify(directory)
        }
        fn bytes(&self) -> io::Result<Vec<u8>> {
            let mut bytes = vec![0; self.snapshot.bytes as usize];
            self.file.read_exact_at(&mut bytes, 0).map_err(redact)?;
            Ok(bytes)
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Owner {
        version: u8,
        id: String,
        slot_bytes: u64,
        directory: Identity,
        lock: Identity,
        slots: [Identity; SLOT_COUNT],
    }
    impl Owner {
        fn lock_bytes(&self) -> Vec<u8> {
            format!("{LOCK_MAGIC}{}\n", self.id).into_bytes()
        }
    }

    pub(super) struct Ring {
        directory: Directory,
        owner: OwnedFile,
        slots: [OwnedFile; SLOT_COUNT],
        record: Owner,
        next_sequence: u64,
        active: Option<usize>,
        disabled: bool,
        // Release exclusivity only after every slot/owner descriptor closes.
        lock: OwnedFile,
    }
    impl Ring {
        pub(super) fn open(
            directory: PathBuf,
            requested: Option<u64>,
            cancelled: &AtomicBool,
            checkpoint: Checkpoint<'_>,
        ) -> io::Result<Self> {
            if let Some(size) = requested {
                capacity(size)?;
            }
            check_cancel(cancelled)?;
            let uid = rustix::process::geteuid().as_raw();
            let directory = private_fs::directory_path(&directory, uid, ERRORS)?;
            let parents = Parents::capture(&directory, uid, ERRORS)?;
            let parent = parents.open_parent()?;
            match fs::symlink_metadata(&directory) {
                Ok(_) => {
                    let result = Self::existing(
                        Directory::open(directory, &parent, parents, uid)?,
                        requested,
                    )?;
                    check_cancel(cancelled)?;
                    return Ok(result);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(redact(e)),
            }
            let mut stage_name = OsString::from(".gp-log-init-");
            stage_name.push(directory.file_name().ok_or_else(invalid)?);
            let stage = directory.parent().ok_or_else(invalid)?.join(&stage_name);
            parents.verify()?;
            check_cancel(cancelled)?;
            let created =
                match rustix::fs::mkdirat(&parent, &stage_name, Mode::from_bits_truncate(0o700)) {
                    Ok(()) => true,
                    Err(rustix::io::Errno::EXIST) => false,
                    Err(error) => return Err(redact(error.into())),
                };
            if created {
                checkpoint("stage_directory")?;
            }
            let stage = Directory::open(stage, &parent, parents, uid)?;
            let mut result = if created {
                Self::initialize(
                    stage,
                    requested.unwrap_or(DEFAULT_SLOT_BYTES),
                    cancelled,
                    checkpoint,
                )?
            } else {
                Self::existing(stage, requested)?
            };
            result.verify()?;
            // A valid stage never contains log payload: it is a small, complete
            // initializer, not an old store silently moved into this namespace.
            if result
                .slots
                .iter()
                .any(|file| file.snapshot.bytes != HEADER_LEN as u64)
                || result.next_sequence != SLOT_COUNT as u64
            {
                return Err(invalid());
            }
            checkpoint("stage_ready")?;
            result.directory.parents.verify()?;
            check_cancel(cancelled)?;
            rustix::fs::renameat_with(
                &parent,
                &stage_name,
                &parent,
                directory.file_name().ok_or_else(invalid)?,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|error| redact(error.into()))?;
            result.directory.path = directory;
            checkpoint("published")?;
            check_cancel(cancelled)?;
            parent.sync_all().map_err(redact)?;
            result.verify()?;
            Ok(result)
        }

        fn initialize(
            directory: Directory,
            slot_bytes: u64,
            cancelled: &AtomicBool,
            checkpoint: Checkpoint<'_>,
        ) -> io::Result<Self> {
            capacity(slot_bytes)?;
            check_cancel(cancelled)?;
            let mut lock = OwnedFile::open(&directory, LOCK, META_LIMIT, true, Some(cancelled))?;
            lock.file.try_lock().map_err(|error| redact(error.into()))?;
            checkpoint("lock_created")?;
            let mut files = Vec::with_capacity(SLOT_COUNT);
            for name in SLOTS {
                check_cancel(cancelled)?;
                files.push(OwnedFile::open(
                    &directory,
                    name,
                    slot_bytes as usize,
                    true,
                    Some(cancelled),
                )?);
            }
            let mut slots: [OwnedFile; SLOT_COUNT] = files.try_into().map_err(|_| invalid())?;
            let mut id = [0; 16];
            getrandom::fill(&mut id)
                .map_err(|_| io::Error::other("cannot create private log identity"))?;
            let record = Owner {
                version: 1,
                id: hexadecimal(&id),
                slot_bytes,
                directory: directory.identity,
                lock: lock.snapshot.identity,
                slots: std::array::from_fn(|i| slots[i].snapshot.identity),
            };
            let lock_bytes = record.lock_bytes();
            check_cancel(cancelled)?;
            lock.file.write_all_at(&lock_bytes, 0).map_err(redact)?;
            lock.changed(&directory, lock_bytes.len() as u64)?;
            check_cancel(cancelled)?;
            lock.file.sync_all().map_err(redact)?;
            for (index, slot) in slots.iter_mut().enumerate() {
                let bytes = header(&record.id, index, index as u64);
                if bytes.len() != HEADER_LEN {
                    return Err(invalid());
                }
                check_cancel(cancelled)?;
                slot.file.write_all_at(&bytes, 0).map_err(redact)?;
                slot.changed(&directory, bytes.len() as u64)?;
                check_cancel(cancelled)?;
                slot.file.sync_all().map_err(redact)?;
            }
            checkpoint("slots_prepared")?;
            let bytes = serde_json::to_vec(&record).map_err(|_| invalid())?;
            if bytes
                .len()
                .checked_add(lock_bytes.len())
                .is_none_or(|n| n > META_LIMIT)
            {
                return Err(invalid());
            }
            check_cancel(cancelled)?;
            let mut owner = OwnedFile::open(&directory, OWNER, META_LIMIT, true, Some(cancelled))?;
            check_cancel(cancelled)?;
            owner.file.write_all_at(&bytes, 0).map_err(redact)?;
            owner.changed(&directory, bytes.len() as u64)?;
            check_cancel(cancelled)?;
            owner.file.sync_all().map_err(redact)?;
            check_cancel(cancelled)?;
            directory.file.sync_all().map_err(redact)?;
            let result = Self {
                directory,
                owner,
                lock,
                slots,
                record,
                next_sequence: SLOT_COUNT as u64,
                active: None,
                disabled: false,
            };
            result.verify()?;
            Ok(result)
        }

        fn existing(directory: Directory, requested: Option<u64>) -> io::Result<Self> {
            directory.inventory()?;
            let owner = OwnedFile::open(&directory, OWNER, META_LIMIT, false, None)?;
            let lock = OwnedFile::open(&directory, LOCK, META_LIMIT, false, None)?;
            lock.file.try_lock().map_err(|error| redact(error.into()))?;
            owner.verify(&directory)?;
            lock.verify(&directory)?;
            if owner
                .snapshot
                .bytes
                .checked_add(lock.snapshot.bytes)
                .is_none_or(|n| n > META_LIMIT as u64)
            {
                return Err(invalid());
            }
            let record: Owner = serde_json::from_slice(&owner.bytes()?).map_err(|_| invalid())?;
            if record.version != 1
                || !valid_id(&record.id)
                || record.directory != directory.identity
                || record.lock != lock.snapshot.identity
            {
                return Err(invalid());
            }
            capacity(record.slot_bytes)?;
            if requested.is_some_and(|size| size != record.slot_bytes) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private log slot size differs from existing store",
                ));
            }
            if lock.bytes()? != record.lock_bytes() {
                return Err(invalid());
            }
            let mut files = Vec::with_capacity(SLOT_COUNT);
            for (index, name) in SLOTS.iter().enumerate() {
                let file =
                    OwnedFile::open(&directory, name, record.slot_bytes as usize, false, None)?;
                if file.snapshot.identity != record.slots[index] {
                    return Err(invalid());
                }
                files.push(file);
            }
            let slots = files.try_into().map_err(|_| invalid())?;
            let mut result = Self {
                directory,
                owner,
                lock,
                slots,
                record,
                next_sequence: 0,
                active: None,
                disabled: false,
            };
            result.next_sequence = result.inspect_headers()?;
            result.verify()?;
            Ok(result)
        }

        fn inspect_headers(&self) -> io::Result<u64> {
            let mut complete = Vec::with_capacity(SLOT_COUNT);
            let mut partial = None;
            for (index, slot) in self.slots.iter().enumerate() {
                let length = (slot.snapshot.bytes as usize).min(HEADER_LEN);
                let mut bytes = vec![0; length];
                slot.file.read_exact_at(&mut bytes, 0).map_err(redact)?;
                if length < HEADER_LEN {
                    if partial.replace((index, bytes)).is_some() {
                        return Err(invalid());
                    }
                    continue;
                }
                let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
                let sequence = text
                    .split_ascii_whitespace()
                    .last()
                    .ok_or_else(invalid)?
                    .parse::<u64>()
                    .map_err(|_| invalid())?;
                if sequence % SLOT_COUNT as u64 != index as u64
                    || bytes != header(&self.record.id, index, sequence)
                {
                    return Err(invalid());
                }
                complete.push(sequence);
            }
            complete.sort_unstable();
            let maximum = *complete.last().ok_or_else(invalid)?;
            if complete
                .windows(2)
                .any(|pair| pair[0].checked_add(1) != Some(pair[1]))
            {
                return Err(invalid());
            }
            let next = maximum.checked_add(1).ok_or_else(invalid)?;
            if let Some((index, bytes)) = partial {
                if complete.len() != SLOT_COUNT - 1
                    || maximum < (SLOT_COUNT - 1) as u64
                    || index as u64 != next % SLOT_COUNT as u64
                    || !header(&self.record.id, index, next).starts_with(&bytes)
                {
                    return Err(invalid());
                }
            } else if complete.len() != SLOT_COUNT || maximum < (SLOT_COUNT - 1) as u64 {
                return Err(invalid());
            }
            Ok(next)
        }

        fn verify(&self) -> io::Result<()> {
            self.directory.inventory()?;
            self.owner.verify(&self.directory)?;
            self.lock.verify(&self.directory)?;
            for slot in &self.slots {
                slot.verify(&self.directory)?;
            }
            self.directory.verify()
        }
        fn rotate(&mut self, checkpoint: Checkpoint<'_>) -> io::Result<()> {
            let sequence = self.next_sequence;
            let next = sequence.checked_add(1).ok_or_else(invalid)?;
            let index = (sequence % SLOT_COUNT as u64) as usize;
            self.verify()?;
            let bytes = header(&self.record.id, index, sequence);
            let slot = &mut self.slots[index];
            slot.file.set_len(0).map_err(redact)?;
            slot.changed(&self.directory, 0)?;
            checkpoint("rotation_empty")?;
            slot.file
                .write_all_at(&bytes[..HEADER_LEN / 2], 0)
                .map_err(redact)?;
            slot.changed(&self.directory, (HEADER_LEN / 2) as u64)?;
            checkpoint("rotation_partial")?;
            slot.file
                .write_all_at(&bytes[HEADER_LEN / 2..], (HEADER_LEN / 2) as u64)
                .map_err(redact)?;
            slot.changed(&self.directory, HEADER_LEN as u64)?;
            checkpoint("rotation_header")?;
            self.active = Some(index);
            self.next_sequence = next;
            self.verify()
        }
        fn record_inner(&mut self, bytes: &[u8], checkpoint: Checkpoint<'_>) -> io::Result<()> {
            if bytes.is_empty() {
                return Ok(());
            }
            if bytes.len() > MAX_RECORD_BYTES {
                return Err(invalid());
            }
            self.verify()?;
            if self.active.is_none_or(|i| {
                self.slots[i]
                    .snapshot
                    .bytes
                    .checked_add(bytes.len() as u64)
                    .is_none_or(|size| size > self.record.slot_bytes)
            }) {
                self.rotate(checkpoint)?;
            }
            let index = self.active.ok_or_else(invalid)?;
            let slot = &mut self.slots[index];
            let offset = slot.snapshot.bytes;
            let end = offset.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
            if end > self.record.slot_bytes {
                return Err(invalid());
            }
            slot.file.write_all_at(bytes, offset).map_err(redact)?;
            slot.changed(&self.directory, end)?;
            self.verify()
        }
        pub(super) fn record(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.record_with(bytes, &mut |_| Ok(()))
        }
        fn record_with(&mut self, bytes: &[u8], checkpoint: Checkpoint<'_>) -> io::Result<()> {
            if self.disabled {
                return Err(io::Error::other("private log sink disabled"));
            }
            let result = self.record_inner(bytes, checkpoint);
            self.disabled |= result.is_err();
            result
        }
        pub(super) fn flush_checked(&mut self) -> io::Result<()> {
            if self.disabled {
                return Err(io::Error::other("private log sink disabled"));
            }
            // Regular File writes have no userspace buffer. Do not add a
            // per-batch fsync or imply power-loss durability for diagnostics.
            let result = self.verify();
            self.disabled |= result.is_err();
            result
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            io::Read,
            os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
            path::Path,
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };

        struct Fixture(PathBuf);
        impl FileRing {
            fn slots_bytes(&self) -> u64 {
                self.inner
                    .slots
                    .iter()
                    .map(|slot| slot.snapshot.bytes)
                    .sum()
            }
        }
        impl Fixture {
            fn new() -> Self {
                let path = Path::new("/tmp").join(format!("gp-log-{:016x}", rand::random::<u64>()));
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                Self(path)
            }
            fn directory(&self) -> PathBuf {
                self.0.join("logs")
            }
            fn stage(&self) -> PathBuf {
                self.0.join(".gp-log-init-logs")
            }
            fn open(&self) -> FileRing {
                FileRing::open(
                    self.directory(),
                    Some(MIN_SLOT_BYTES),
                    &AtomicBool::new(false),
                )
                .unwrap()
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        fn inventory(path: &Path) -> Vec<(OsString, Identity, u32, Vec<u8>)> {
            let mut result: Vec<_> = fs::read_dir(path)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    let meta = fs::symlink_metadata(entry.path()).unwrap();
                    (
                        entry.file_name(),
                        Identity::of(&meta),
                        meta.mode(),
                        if meta.is_file() {
                            fs::read(entry.path()).unwrap()
                        } else {
                            Vec::new()
                        },
                    )
                })
                .collect();
            result.sort_by(|left, right| left.0.cmp(&right.0));
            result
        }
        fn seq(bytes: &[u8]) -> u64 {
            std::str::from_utf8(&bytes[..HEADER_LEN])
                .unwrap()
                .split_ascii_whitespace()
                .last()
                .unwrap()
                .parse()
                .unwrap()
        }

        #[test]
        fn fixed_slots_rotate_whole_records_with_hard_capacity_and_restart_on_next_slot() {
            let fixture = Fixture::new();
            let mut ring = fixture.open();
            let initial = inventory(&fixture.directory());
            let mut record = vec![b'x'; MAX_RECORD_BYTES];
            *record.last_mut().unwrap() = b'\n';
            for _ in 0..300 {
                ring.write_all(&record).unwrap();
            }
            ring.flush().unwrap();
            let after = inventory(&fixture.directory());
            assert_eq!(initial.len(), 6);
            assert_eq!(after.len(), 6);
            for (before, after) in initial.iter().zip(&after) {
                assert_eq!(before.0, after.0);
                assert_eq!(before.1, after.1);
                assert_eq!(after.2 & 0o7777, 0o600);
            }
            assert!(ring.slots_bytes() <= SLOT_COUNT as u64 * MIN_SLOT_BYTES);
            for slot in &ring.inner.slots {
                let bytes = fs::read(fixture.directory().join(slot.name)).unwrap();
                assert!(seq(&bytes) >= 20);
                assert!(bytes.len() <= MIN_SLOT_BYTES as usize);
                assert!(bytes[HEADER_LEN..]
                    .chunks(MAX_RECORD_BYTES)
                    .all(|part| part == record));
            }
            let maximum = ring.inner.next_sequence - 1;
            drop(ring);
            let mut reopened =
                FileRing::open(fixture.directory(), None, &AtomicBool::new(false)).unwrap();
            reopened.write_all(b"new process\n").unwrap();
            assert_eq!(reopened.inner.next_sequence, maximum + 2);
            assert_eq!(reopened.inner.record.slot_bytes, MIN_SLOT_BYTES);
            assert!(FileRing::open(fixture.directory(), None, &AtomicBool::new(false)).is_err());
            drop(reopened);
            let snapshot = inventory(&fixture.directory());
            assert!(FileRing::open(
                fixture.directory(),
                Some(MIN_SLOT_BYTES * 2),
                &AtomicBool::new(false)
            )
            .is_err());
            assert_eq!(snapshot, inventory(&fixture.directory()));
        }

        #[test]
        fn invalid_cap_or_pre_cancelled_initialization_creates_nothing() {
            for size in [0, MIN_SLOT_BYTES - 1, MAX_SLOT_BYTES + 1, u64::MAX] {
                let fixture = Fixture::new();
                assert!(
                    FileRing::open(fixture.directory(), Some(size), &AtomicBool::new(false))
                        .is_err()
                );
                assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
            }
            let fixture = Fixture::new();
            assert!(FileRing::open(fixture.directory(), None, &AtomicBool::new(true)).is_err());
            assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
        }

        #[test]
        fn runtime_slot_replacement_truncation_metadata_change_and_extra_entries_latch_failure() {
            for fault in 0..5 {
                let fixture = Fixture::new();
                let mut ring = fixture.open();
                ring.write_all(b"one synthetic record\n").unwrap();
                let slot = fixture.directory().join(SLOTS[3]);
                match fault {
                    0 => {
                        fs::rename(&slot, fixture.0.join("old-slot")).unwrap();
                        fs::copy(fixture.0.join("old-slot"), &slot).unwrap();
                    }
                    1 => {
                        fs::OpenOptions::new()
                            .write(true)
                            .open(&slot)
                            .unwrap()
                            .set_len(0)
                            .unwrap();
                    }
                    2 => fs::set_permissions(&slot, fs::Permissions::from_mode(0o640)).unwrap(),
                    3 => fs::write(fixture.directory().join("unknown"), b"keep unknown").unwrap(),
                    4 => {
                        std::thread::sleep(Duration::from_millis(2));
                        let file = fs::OpenOptions::new().write(true).open(&slot).unwrap();
                        file.write_all_at(b"X", HEADER_LEN as u64 - 2).unwrap();
                    }
                    _ => unreachable!(),
                }
                let before = inventory(&fixture.directory());
                assert!(ring.write_all(b"must not be appended\n").is_err());
                assert!(ring.inner.disabled);
                assert!(ring.flush().is_err());
                assert!(ring.write_all(b"no automatic retry\n").is_err());
                assert_eq!(before, inventory(&fixture.directory()));
            }
        }

        #[test]
        fn links_special_files_and_unknown_directories_are_never_adopted_or_truncated() {
            for fault in 0..5 {
                let fixture = Fixture::new();
                let ring = fixture.open();
                drop(ring);
                let slot = fixture.directory().join(SLOTS[2]);
                fs::rename(&slot, fixture.0.join("original-slot")).unwrap();
                match fault {
                    0 => symlink(fixture.0.join("original-slot"), &slot).unwrap(),
                    1 => fs::hard_link(fixture.0.join("original-slot"), &slot).unwrap(),
                    2 => fs::create_dir(&slot).unwrap(),
                    3 => {
                        struct Reap(Child);
                        impl Drop for Reap {
                            fn drop(&mut self) {
                                let _ = self.0.kill();
                                let _ = self.0.wait();
                            }
                        }
                        let mut child = Reap(
                            Command::new("/usr/bin/mkfifo")
                                .args(["-m", "600"])
                                .arg(&slot)
                                .env_clear()
                                .stdin(Stdio::null())
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .spawn()
                                .unwrap(),
                        );
                        let end = Instant::now() + Duration::from_secs(3);
                        loop {
                            if let Some(status) = child.0.try_wait().unwrap() {
                                assert!(status.success());
                                break;
                            }
                            assert!(Instant::now() < end, "owned mkfifo deadline");
                            std::thread::sleep(Duration::from_millis(2));
                        }
                    }
                    4 => {
                        fs::copy(fixture.0.join("original-slot"), &slot).unwrap();
                    }
                    _ => unreachable!(),
                }
                let original = fs::read(fixture.0.join("original-slot")).unwrap();
                let start = Instant::now();
                assert!(
                    FileRing::open(fixture.directory(), None, &AtomicBool::new(false)).is_err()
                );
                assert!(start.elapsed() < Duration::from_secs(1));
                assert_eq!(fs::read(fixture.0.join("original-slot")).unwrap(), original);
            }
            let fixture = Fixture::new();
            fs::create_dir(fixture.directory()).unwrap();
            fs::write(fixture.directory().join("foreign"), b"retain").unwrap();
            assert!(FileRing::open(fixture.directory(), None, &AtomicBool::new(false)).is_err());
            assert_eq!(
                fs::read(fixture.directory().join("foreign")).unwrap(),
                b"retain"
            );
        }

        #[test]
        fn parent_or_store_replacement_disables_old_capability() {
            for parent in [false, true] {
                let fixture = Fixture::new();
                let mut ring = fixture.open();
                let moved = fixture.0.with_extension("moved");
                if parent {
                    fs::rename(&fixture.0, &moved).unwrap();
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&fixture.0)
                        .unwrap();
                } else {
                    fs::rename(fixture.directory(), fixture.0.join("old")).unwrap();
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(fixture.directory())
                        .unwrap();
                }
                assert!(ring.write_all(b"forbidden\n").is_err());
                drop(ring);
                if parent {
                    fs::remove_dir_all(moved).unwrap();
                }
            }
        }

        #[test]
        fn known_partial_rotation_recovers_only_the_expected_slot_and_header_prefix() {
            for stage in ["rotation_empty", "rotation_partial", "rotation_header"] {
                let fixture = Fixture::new();
                let mut ring = fixture.open();
                assert!(ring
                    .inner
                    .record_with(b"not fully reached\n", &mut |point| if point == stage {
                        Err(io::Error::other("synthetic write failure"))
                    } else {
                        Ok(())
                    })
                    .is_err());
                assert!(ring.inner.disabled);
                drop(ring);
                let mut reopened =
                    FileRing::open(fixture.directory(), None, &AtomicBool::new(false)).unwrap();
                reopened.write_all(b"after crash\n").unwrap();
                assert!(reopened.slots_bytes() <= 4 * MIN_SLOT_BYTES);
            }
            for fault in 0..5 {
                let fixture = Fixture::new();
                let ring = fixture.open();
                let id = ring.inner.record.id.clone();
                drop(ring);
                match fault {
                    0 => {
                        fs::write(fixture.directory().join(SLOTS[1]), b"").unwrap();
                    }
                    1 => {
                        fs::write(fixture.directory().join(SLOTS[0]), b"wrong prefix").unwrap();
                    }
                    2 => {
                        fs::write(fixture.directory().join(SLOTS[0]), b"").unwrap();
                        fs::write(fixture.directory().join(SLOTS[1]), b"").unwrap();
                    }
                    3 => {
                        fs::write(fixture.directory().join(SLOTS[0]), header(&id, 0, 8)).unwrap();
                    }
                    4 => {
                        fs::write(
                            fixture.directory().join(SLOTS[0]),
                            &header(&id, 0, 8)[..HEADER_LEN - 1],
                        )
                        .unwrap();
                    }
                    _ => unreachable!(),
                }
                let before = inventory(&fixture.directory());
                assert!(
                    FileRing::open(fixture.directory(), None, &AtomicBool::new(false)).is_err()
                );
                assert_eq!(before, inventory(&fixture.directory()));
            }
        }

        #[test]
        fn sequence_overflow_and_oversized_record_never_wrap_or_grow_store() {
            let fixture = Fixture::new();
            let ring = fixture.open();
            let id = ring.inner.record.id.clone();
            drop(ring);
            for (index, name) in SLOTS.iter().enumerate() {
                fs::write(
                    fixture.directory().join(name),
                    header(&id, index, u64::MAX - 3 + index as u64),
                )
                .unwrap();
            }
            let before = inventory(&fixture.directory());
            assert!(FileRing::open(fixture.directory(), None, &AtomicBool::new(false)).is_err());
            assert_eq!(before, inventory(&fixture.directory()));
            let fixture = Fixture::new();
            let mut ring = fixture.open();
            let before = inventory(&fixture.directory());
            assert!(ring.write_all(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
            assert_eq!(before, inventory(&fixture.directory()));
        }

        #[test]
        fn initialization_cancellation_and_no_replace_preserve_bounded_staging() {
            for point in [
                "stage_directory",
                "lock_created",
                "slots_prepared",
                "stage_ready",
            ] {
                let fixture = Fixture::new();
                let cancelled = AtomicBool::new(false);
                let result = Ring::open(
                    fixture.directory(),
                    Some(MIN_SLOT_BYTES),
                    &cancelled,
                    &mut |stage| {
                        if stage == point {
                            cancelled.store(true, Ordering::Release);
                        }
                        Ok(())
                    },
                );
                assert!(result.is_err());
                assert!(!fixture.directory().exists());
                assert!(fixture.stage().exists());
                let before = inventory(&fixture.stage());
                let result = FileRing::open(fixture.directory(), None, &AtomicBool::new(false));
                if point == "stage_ready" {
                    assert!(result.is_ok());
                    assert!(!fixture.stage().exists());
                } else {
                    assert!(result.is_err());
                    assert_eq!(before, inventory(&fixture.stage()));
                }
                assert!(fs::read_dir(&fixture.0).unwrap().count() <= 1);
            }
            let fixture = Fixture::new();
            let result = Ring::open(
                fixture.directory(),
                None,
                &AtomicBool::new(false),
                &mut |stage| {
                    if stage == "stage_ready" {
                        fs::DirBuilder::new()
                            .mode(0o700)
                            .create(fixture.directory())?;
                        fs::write(fixture.directory().join("foreign"), b"not replaced")?;
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert_eq!(
                fs::read(fixture.directory().join("foreign")).unwrap(),
                b"not replaced"
            );
            assert!(fixture.stage().is_dir());
        }

        #[test]
        fn crash_checkpoint_child() {
            if std::env::var("GP_LOG_CRASH_CHILD").ok().as_deref() != Some("public-v1") {
                return;
            }
            let path = PathBuf::from(std::env::var_os("GP_LOG_PATH").unwrap());
            let ready = PathBuf::from(std::env::var_os("GP_LOG_READY").unwrap());
            let chosen = std::env::var("GP_LOG_STAGE").unwrap();
            let mut checkpoint = |point: &'static str| {
                if point == chosen {
                    fs::write(&ready, point.as_bytes())?;
                    std::io::stdin().read_exact(&mut [0; 1])?;
                }
                Ok(())
            };
            let mut ring = Ring::open(
                path,
                Some(MIN_SLOT_BYTES),
                &AtomicBool::new(false),
                &mut checkpoint,
            )
            .unwrap();
            ring.record_with(b"public crash record\n", &mut checkpoint)
                .unwrap();
            panic!("checkpoint child was not stopped");
        }

        #[test]
        fn real_sigkill_initialization_and_rotation_cutpoints_reopen_without_more_stages() {
            struct Process(Child);
            impl Drop for Process {
                fn drop(&mut self) {
                    let input = self.0.stdin.take();
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                    drop(input);
                }
            }
            for stage in [
                "stage_directory",
                "lock_created",
                "slots_prepared",
                "stage_ready",
                "published",
                "rotation_empty",
                "rotation_partial",
                "rotation_header",
            ] {
                let fixture = Fixture::new();
                let ready = fixture.0.join("ready");
                let mut child = Process(
                    Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "log_store::platform::tests::crash_checkpoint_child",
                            "--test-threads=1",
                        ])
                        .env_clear()
                        .env("GP_LOG_CRASH_CHILD", "public-v1")
                        .env("GP_LOG_PATH", fixture.directory())
                        .env("GP_LOG_READY", &ready)
                        .env("GP_LOG_STAGE", stage)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap(),
                );
                let end = Instant::now() + Duration::from_secs(5);
                while fs::read(&ready).ok().as_deref() != Some(stage.as_bytes()) {
                    assert!(
                        child.0.try_wait().unwrap().is_none(),
                        "child exited at {stage}"
                    );
                    assert!(Instant::now() < end, "child ready deadline: {stage}");
                    std::thread::sleep(Duration::from_millis(2));
                }
                let input = child.0.stdin.take().unwrap();
                child.0.kill().unwrap();
                let status = child.0.wait().unwrap();
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9), "cut {stage}");
                drop(input);
                let opened = FileRing::open(fixture.directory(), None, &AtomicBool::new(false));
                if ["stage_directory", "lock_created", "slots_prepared"].contains(&stage) {
                    assert!(opened.is_err());
                    let snapshot = inventory(&fixture.stage());
                    assert!(
                        FileRing::open(fixture.directory(), None, &AtomicBool::new(false)).is_err()
                    );
                    assert_eq!(snapshot, inventory(&fixture.stage()));
                    assert!(!fixture.directory().exists());
                } else {
                    let mut ring = opened.unwrap();
                    ring.write_all(b"recovered\n").unwrap();
                    ring.flush().unwrap();
                    assert!(ring.slots_bytes() <= 4 * MIN_SLOT_BYTES);
                    assert!(!fixture.stage().exists());
                }
            }
        }
    }
}
