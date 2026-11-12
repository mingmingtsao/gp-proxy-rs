//! Fixed, inode-bound anchors for immutable external launch-agent files.
//!
//! The caller holds the installation's store lock and persists an OwnedPlist
//! intent before writing. It also decides when a slot has no remaining current,
//! pending or retired references. Pool initialization must finish before use;
//! an incomplete pool is retained and rejected, never silently adopted.
#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]

use crate::{
    managed_release,
    private_fs::{self, Directory, Errors, Identity, Parents},
};
use rustix::fs::{AtFlags, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, Metadata},
    io,
    os::unix::fs::{FileExt, MetadataExt},
    path::{Component, Path, PathBuf},
};

pub(crate) const SLOT_COUNT: usize = 3;
pub(crate) const MAX_PLIST_BYTES: usize = 16 * 1024;
const OWNER_LIMIT: usize = 4096;
const SLOT_NAMES: [&str; SLOT_COUNT] = ["slot-0", "slot-1", "slot-2"];
const ERRORS: Errors = Errors {
    denied: "managed plist ownership or identity is invalid",
    invalid: "invalid managed plist pool",
    operation: "managed plist filesystem operation failed",
};
type Checkpoint<'a> = &'a mut dyn FnMut(&'static str) -> io::Result<()>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedPlist {
    pub(crate) slot: u8,
    pub(crate) path: PathBuf,
    pub(crate) identity: Identity,
    pub(crate) digest: [u8; 32],
    pub(crate) bytes: usize,
}

impl OwnedPlist {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u8,
    installation: [u8; 16],
    directory: Identity,
    slots: [Identity; SLOT_COUNT],
}

pub(crate) struct Pool {
    directory: Directory,
    owner_file: File,
    owner_identity: Identity,
    owner_bytes: Vec<u8>,
    owner: Owner,
    slots: [File; SLOT_COUNT],
}

fn redact(error: io::Error) -> io::Error {
    ERRORS.redact(error)
}

fn open_at(directory: &File, name: &std::ffi::OsStr, create: bool) -> io::Result<File> {
    let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if create {
        flags |= OFlags::CREATE | OFlags::EXCL;
    }
    rustix::fs::openat(directory, name, flags, Mode::from_bits_truncate(0o600))
        .map(File::from)
        .map_err(|error| redact(error.into()))
}

fn bytes_at(file: &File, maximum: usize) -> io::Result<Vec<u8>> {
    let length =
        usize::try_from(file.metadata().map_err(redact)?.len()).map_err(|_| ERRORS.invalid())?;
    if length > maximum {
        return Err(ERRORS.invalid());
    }
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, 0).map_err(redact)?;
    if file.metadata().map_err(redact)?.len() != length as u64 {
        return Err(ERRORS.denied());
    }
    Ok(bytes)
}

fn anchor_metadata(meta: &Metadata, uid: u32, identity: Identity) -> io::Result<()> {
    private_fs::private(meta, uid, 0o600, ERRORS)?;
    if !meta.is_file()
        || Identity::of(meta) != identity
        || !(1..=2).contains(&meta.nlink())
        || meta.len() > MAX_PLIST_BYTES as u64
    {
        return Err(ERRORS.denied());
    }
    Ok(())
}

impl Pool {
    pub(crate) fn initialize(root: &Path, installation: [u8; 16]) -> io::Result<Self> {
        if installation == [0; 16] {
            return Err(ERRORS.invalid());
        }
        let uid = rustix::process::geteuid().as_raw();
        let root = private_fs::directory_path(root, uid, ERRORS)?;
        let parents = Parents::capture(&root, uid, ERRORS)?;
        let parent = parents.open_parent()?;
        rustix::fs::mkdirat(
            &parent,
            root.file_name().ok_or_else(|| ERRORS.invalid())?,
            Mode::from_bits_truncate(0o700),
        )
        .map_err(|error| redact(error.into()))?;
        let directory = Directory::open(root.clone(), uid, ERRORS)?;
        let mut identities = Vec::with_capacity(SLOT_COUNT);
        for name in SLOT_NAMES {
            let file = open_at(&directory.file, name.as_ref(), true)?;
            let meta = file.metadata().map_err(redact)?;
            private_fs::regular(&meta, uid, MAX_PLIST_BYTES, ERRORS)?;
            if meta.len() != 0 {
                return Err(ERRORS.invalid());
            }
            identities.push(Identity::of(&meta));
            file.sync_all().map_err(redact)?;
        }
        let owner = Owner {
            version: 1,
            installation,
            directory: directory.identity,
            slots: identities.try_into().map_err(|_| ERRORS.invalid())?,
        };
        let mut bytes = serde_json::to_vec(&owner).map_err(|_| ERRORS.invalid())?;
        bytes.push(b'\n');
        if bytes.len() > OWNER_LIMIT {
            return Err(ERRORS.invalid());
        }
        let file = open_at(&directory.file, "owner".as_ref(), true)?;
        file.write_all_at(&bytes, 0).map_err(redact)?;
        file.sync_all().map_err(redact)?;
        directory.file.sync_all().map_err(redact)?;
        parents.verify()?;
        parent.sync_all().map_err(redact)?;
        Self::open(&root, installation)
    }

    pub(crate) fn open(root: &Path, installation: [u8; 16]) -> io::Result<Self> {
        if installation == [0; 16] {
            return Err(ERRORS.invalid());
        }
        let uid = rustix::process::geteuid().as_raw();
        let root = private_fs::directory_path(root, uid, ERRORS)?;
        let directory = Directory::open(root, uid, ERRORS)?;
        let owner_file = open_at(&directory.file, "owner".as_ref(), false)?;
        let meta = owner_file.metadata().map_err(redact)?;
        private_fs::regular(&meta, uid, OWNER_LIMIT, ERRORS)?;
        let owner_bytes = bytes_at(&owner_file, OWNER_LIMIT)?;
        let owner: Owner = serde_json::from_slice(&owner_bytes).map_err(|_| ERRORS.invalid())?;
        if owner.version != 1
            || owner.installation != installation
            || owner.directory != directory.identity
            || owner.slots.iter().any(|identity| identity.uid != uid)
            || owner.slots[0] == owner.slots[1]
            || owner.slots[0] == owner.slots[2]
            || owner.slots[1] == owner.slots[2]
        {
            return Err(ERRORS.invalid());
        }
        let mut slots = Vec::with_capacity(SLOT_COUNT);
        for name in SLOT_NAMES {
            slots.push(open_at(&directory.file, name.as_ref(), false)?);
        }
        let result = Self {
            directory,
            owner_file,
            owner_identity: Identity::of(&meta),
            owner_bytes,
            owner,
            slots: slots.try_into().map_err(|_| ERRORS.invalid())?,
        };
        result.verify_pool()?;
        Ok(result)
    }

    fn verify_pool(&self) -> io::Result<()> {
        self.directory.verify()?;
        let mut inventory = Vec::new();
        for entry in fs::read_dir(&self.directory.path).map_err(redact)? {
            inventory.push(entry.map_err(redact)?.file_name());
            if inventory.len() > SLOT_COUNT + 1 {
                return Err(ERRORS.invalid());
            }
        }
        inventory.sort();
        if inventory != ["owner", "slot-0", "slot-1", "slot-2"] {
            return Err(ERRORS.invalid());
        }
        for meta in [
            self.owner_file.metadata().map_err(redact)?,
            fs::symlink_metadata(self.directory.path.join("owner")).map_err(redact)?,
        ] {
            private_fs::regular(&meta, self.directory.uid, OWNER_LIMIT, ERRORS)?;
            if Identity::of(&meta) != self.owner_identity {
                return Err(ERRORS.denied());
            }
        }
        if bytes_at(&self.owner_file, OWNER_LIMIT)? != self.owner_bytes {
            return Err(ERRORS.denied());
        }
        for slot in 0..SLOT_COUNT {
            self.slot_metadata(slot)?;
        }
        self.directory.verify()
    }

    fn slot_metadata(&self, slot: usize) -> io::Result<Metadata> {
        let file = self.slots.get(slot).ok_or_else(|| ERRORS.invalid())?;
        let opened = file.metadata().map_err(redact)?;
        let named =
            fs::symlink_metadata(self.directory.path.join(SLOT_NAMES[slot])).map_err(redact)?;
        for meta in [&opened, &named] {
            anchor_metadata(meta, self.directory.uid, self.owner.slots[slot])?;
        }
        if opened.nlink() != named.nlink() || opened.len() != named.len() {
            return Err(ERRORS.denied());
        }
        Ok(opened)
    }

    fn destination(&self, path: &Path) -> io::Result<(Parents, File)> {
        let value = path.to_str().ok_or_else(|| ERRORS.invalid())?;
        if !path.is_absolute()
            || value.len() > 1024
            || value.chars().any(char::is_control)
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(ERRORS.invalid());
        }
        let prefix = format!(
            "io.gp-proxy.{:032x}.g",
            u128::from_be_bytes(self.owner.installation)
        );
        let generation = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|name| name.strip_suffix(".plist"))
            .ok_or_else(|| ERRORS.invalid())?;
        if generation.len() != 16
            || !generation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || u64::from_str_radix(generation, 16).map_err(|_| ERRORS.invalid())? == 0
            || private_fs::directory_path(path, self.directory.uid, ERRORS)? != path
        {
            return Err(ERRORS.invalid());
        }
        let parents = Parents::capture(path, self.directory.uid, ERRORS)?;
        let parent = parents.open_parent()?;
        let meta = parent.metadata().map_err(redact)?;
        if meta.uid() != self.directory.uid {
            return Err(ERRORS.denied());
        }
        // Necessary preflight, not a promise that a later link cannot return EXDEV.
        if meta.dev() != self.directory.identity.device {
            return Err(io::Error::new(
                io::ErrorKind::CrossesDevices,
                "managed plist publication cannot cross filesystems",
            ));
        }
        Ok((parents, parent))
    }

    fn reference(&self, expected: &OwnedPlist) -> io::Result<usize> {
        let slot = usize::from(expected.slot);
        if slot >= SLOT_COUNT
            || expected.identity != self.owner.slots[slot]
            || expected.bytes == 0
            || expected.bytes > MAX_PLIST_BYTES
        {
            return Err(ERRORS.invalid());
        }
        Ok(slot)
    }

    /// Validate a durable plan even when its anchor is still empty or contains
    /// an interrupted private write. Publication is a separate state check.
    pub(crate) fn validate_reference(&self, expected: &OwnedPlist) -> io::Result<()> {
        self.verify_pool()?;
        self.reference(expected)?;
        let (parents, _) = self.destination(&expected.path)?;
        parents.verify()
    }

    /// Account for every external alias using the caller's complete durable
    /// reference set. A one-link anchor may be unpublished or already removed;
    /// deciding which transition is permitted remains the store's job.
    pub(crate) fn verify_references(&self, references: &[&OwnedPlist]) -> io::Result<()> {
        self.verify_pool()?;
        let mut known: [Option<&OwnedPlist>; SLOT_COUNT] = [None; SLOT_COUNT];
        for reference in references {
            self.validate_reference(reference)?;
            let slot = self.reference(reference)?;
            if known[slot].is_some_and(|previous| previous != *reference)
                || known.iter().flatten().any(|previous| {
                    previous.path == reference.path && previous.slot != reference.slot
                })
            {
                return Err(ERRORS.denied());
            }
            known[slot] = Some(reference);
        }
        for (slot, reference) in known.into_iter().enumerate() {
            if self.slot_metadata(slot)?.nlink() == 2 {
                self.verify(reference.ok_or_else(|| ERRORS.denied())?)?;
            }
        }
        Ok(())
    }

    pub(crate) fn plan(&self, slot: u8, path: &Path, bytes: &[u8]) -> io::Result<OwnedPlist> {
        self.verify_pool()?;
        if bytes.is_empty() || bytes.len() > MAX_PLIST_BYTES {
            return Err(ERRORS.invalid());
        }
        let index = usize::from(slot);
        if self.slot_metadata(index)?.nlink() != 1 {
            return Err(ERRORS.denied());
        }
        let (parents, _) = self.destination(path)?;
        absent(path)?;
        parents.verify()?;
        Ok(OwnedPlist {
            slot,
            path: path.to_owned(),
            identity: self.owner.slots[index],
            digest: managed_release::digest_bytes(bytes),
            bytes: bytes.len(),
        })
    }

    /// Caller must already have persisted this exact reference and must retain
    /// that intent if this operation errors. Only unpublished (one-link) anchors
    /// may be rewritten after an interrupted private write.
    pub(crate) fn write_and_publish(&self, expected: &OwnedPlist, bytes: &[u8]) -> io::Result<()> {
        self.publish_inner(expected, bytes, &mut |_| Ok(()))
    }

    fn publish_inner(
        &self,
        expected: &OwnedPlist,
        bytes: &[u8],
        checkpoint: Checkpoint<'_>,
    ) -> io::Result<()> {
        self.verify_pool()?;
        let slot = self.reference(expected)?;
        if bytes.len() != expected.bytes || managed_release::digest_bytes(bytes) != expected.digest
        {
            return Err(ERRORS.invalid());
        }
        let (parents, parent) = self.destination(&expected.path)?;
        match fs::symlink_metadata(&expected.path) {
            Ok(_) => {
                self.verify(expected)?;
                self.slots[slot].sync_all().map_err(redact)?;
                parent.sync_all().map_err(redact)?;
                return self.verify(expected);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(redact(error)),
        }
        if self.slot_metadata(slot)?.nlink() != 1 {
            return Err(ERRORS.denied());
        }
        let file = &self.slots[slot];
        file.set_len(0).map_err(redact)?;
        checkpoint("slot_truncated")?;
        let halfway = bytes.len() / 2;
        file.write_all_at(&bytes[..halfway], 0).map_err(redact)?;
        checkpoint("slot_partial")?;
        file.write_all_at(&bytes[halfway..], halfway as u64)
            .map_err(redact)?;
        file.sync_all().map_err(redact)?;
        self.directory.file.sync_all().map_err(redact)?;
        checkpoint("slot_synced")?;
        self.verify_pool()?;
        if self.slot_metadata(slot)?.nlink() != 1 || bytes_at(file, MAX_PLIST_BYTES)? != bytes {
            return Err(ERRORS.denied());
        }
        absent(&expected.path)?;
        parents.verify()?;
        rustix::fs::linkat(
            &self.directory.file,
            SLOT_NAMES[slot],
            &parent,
            expected.path.file_name().ok_or_else(|| ERRORS.invalid())?,
            AtFlags::empty(),
        )
        .map_err(|error| redact(error.into()))?;
        checkpoint("linked")?;
        file.sync_all().map_err(redact)?;
        parent.sync_all().map_err(redact)?;
        checkpoint("published_synced")?;
        self.verify(expected)
    }

    pub(crate) fn verify(&self, expected: &OwnedPlist) -> io::Result<()> {
        self.verify_pool()?;
        let slot = self.reference(expected)?;
        let (parents, parent) = self.destination(&expected.path)?;
        let file = open_at(
            &parent,
            expected.path.file_name().ok_or_else(|| ERRORS.invalid())?,
            false,
        )?;
        for meta in [
            self.slot_metadata(slot)?,
            file.metadata().map_err(redact)?,
            fs::symlink_metadata(&expected.path).map_err(redact)?,
        ] {
            anchor_metadata(&meta, self.directory.uid, expected.identity)?;
            if meta.nlink() != 2 || meta.len() != expected.bytes as u64 {
                return Err(ERRORS.denied());
            }
        }
        if managed_release::digest_bytes(&bytes_at(&file, MAX_PLIST_BYTES)?) != expected.digest {
            return Err(ERRORS.denied());
        }
        let after = fs::symlink_metadata(&expected.path).map_err(redact)?;
        anchor_metadata(&after, self.directory.uid, expected.identity)?;
        if after.nlink() != 2 || after.len() != expected.bytes as u64 {
            return Err(ERRORS.denied());
        }
        self.slot_metadata(slot)?;
        parents.verify()
    }

    pub(crate) fn remove(&self, expected: &OwnedPlist) -> io::Result<()> {
        self.remove_inner(expected, &mut |_| Ok(()))
    }

    fn remove_inner(&self, expected: &OwnedPlist, checkpoint: Checkpoint<'_>) -> io::Result<()> {
        self.verify_pool()?;
        let slot = self.reference(expected)?;
        let (parents, parent) = self.destination(&expected.path)?;
        match fs::symlink_metadata(&expected.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if self.slot_metadata(slot)?.nlink() != 1 {
                    return Err(ERRORS.denied());
                }
                parent.sync_all().map_err(redact)?;
                return parents.verify();
            }
            Err(error) => return Err(redact(error)),
            Ok(_) => {}
        }
        self.verify(expected)?;
        parents.verify()?;
        rustix::fs::unlinkat(
            &parent,
            expected.path.file_name().ok_or_else(|| ERRORS.invalid())?,
            AtFlags::empty(),
        )
        .map_err(|error| redact(error.into()))?;
        checkpoint("unlinked")?;
        parent.sync_all().map_err(redact)?;
        self.slots[slot].sync_all().map_err(redact)?;
        absent(&expected.path)?;
        if self.slot_metadata(slot)?.nlink() != 1 {
            return Err(ERRORS.denied());
        }
        parents.verify()
    }
}

fn absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(redact(error)),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "managed plist destination already exists",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const INSTALLATION: [u8; 16] = [0x31; 16];
    struct Fixture {
        root: PathBuf,
        external: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("gp-plist-pool-{:016x}", rand::random::<u64>()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let root = fs::canonicalize(root).unwrap();
            let external = root.join("LaunchAgents");
            fs::create_dir(&external).unwrap();
            fs::set_permissions(&external, fs::Permissions::from_mode(0o700)).unwrap();
            Self { root, external }
        }
        fn pool(&self) -> Pool {
            Pool::initialize(&self.root.join("plists"), INSTALLATION).unwrap()
        }
        fn path(&self, generation: u64) -> PathBuf {
            self.external.join(format!(
                "io.gp-proxy.{}.g{generation:016x}.plist",
                "31".repeat(16)
            ))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    #[test]
    fn exact_two_links_publish_and_remove_without_replacing_anchor() {
        let fixture = Fixture::new();
        let pool = fixture.pool();
        for slot in 0..SLOT_COUNT as u8 {
            let bytes = vec![b'p'; MAX_PLIST_BYTES - usize::from(slot)];
            let reference = pool
                .plan(slot, &fixture.path(u64::from(slot) + 1), &bytes)
                .unwrap();
            assert!(!reference.path.exists());
            pool.write_and_publish(&reference, &bytes).unwrap();
            pool.write_and_publish(&reference, &bytes).unwrap();
            pool.verify(&reference).unwrap();
            assert_eq!(fs::read(&reference.path).unwrap(), bytes);
            assert_eq!(fs::metadata(&reference.path).unwrap().nlink(), 2);
            assert!(pool.plan(slot, &fixture.path(50), b"new").is_err());
            pool.remove(&reference).unwrap();
            pool.remove(&reference).unwrap();
            let meta = pool.slot_metadata(usize::from(slot)).unwrap();
            assert_eq!(meta.nlink(), 1);
            assert_eq!(Identity::of(&meta), reference.identity);
            let next = pool
                .plan(slot, &fixture.path(u64::from(slot) + 10), b"new")
                .unwrap();
            pool.write_and_publish(&next, b"new").unwrap();
            pool.verify(&next).unwrap();
        }
        assert!(pool.plan(3, &fixture.path(99), b"x").is_err());
        assert!(pool.plan(0, &fixture.path(99), b"").is_err());
        assert!(pool
            .plan(0, &fixture.path(99), &vec![0; MAX_PLIST_BYTES + 1])
            .is_err());
    }

    #[test]
    fn every_publish_cut_reopens_and_recovers_from_durable_reference() {
        for cut in [
            "slot_truncated",
            "slot_partial",
            "slot_synced",
            "linked",
            "published_synced",
        ] {
            let fixture = Fixture::new();
            let pool = fixture.pool();
            let bytes = b"public expected immutable plist bytes";
            let reference = pool.plan(0, &fixture.path(1), bytes).unwrap();
            let persisted = serde_json::to_vec(&reference).unwrap();
            let mut reached = false;
            assert!(pool
                .publish_inner(&reference, bytes, &mut |point| {
                    if point == cut {
                        reached = true;
                        Err(io::ErrorKind::Interrupted.into())
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            assert!(reached);
            drop(pool);
            let pool = Pool::open(&fixture.root.join("plists"), INSTALLATION).unwrap();
            let reference = serde_json::from_slice(&persisted).unwrap();
            pool.write_and_publish(&reference, bytes).unwrap();
            pool.verify(&reference).unwrap();
            assert_eq!(fs::read(&reference.path).unwrap(), bytes);
        }
    }

    #[test]
    fn removal_cut_is_idempotent_but_does_not_remove_unknown_replacement() {
        let fixture = Fixture::new();
        let pool = fixture.pool();
        let reference = pool.plan(0, &fixture.path(1), b"old").unwrap();
        pool.write_and_publish(&reference, b"old").unwrap();
        assert!(pool
            .remove_inner(&reference, &mut |_| Err(io::ErrorKind::Interrupted.into()))
            .is_err());
        pool.remove(&reference).unwrap();
        fs::write(&reference.path, b"unknown").unwrap();
        fs::set_permissions(&reference.path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(pool.remove(&reference).is_err());
        assert!(pool.write_and_publish(&reference, b"old").is_err());
        assert_eq!(fs::read(&reference.path).unwrap(), b"unknown");
    }

    #[test]
    fn extra_links_wrong_bytes_or_foreign_destinations_never_get_rewritten() {
        for variant in 0..4 {
            let fixture = Fixture::new();
            let pool = fixture.pool();
            let reference = pool.plan(0, &fixture.path(1), b"expected").unwrap();
            match variant {
                0 => {
                    fs::write(&reference.path, b"foreign").unwrap();
                }
                1 => {
                    symlink(pool.directory.path.join("slot-0"), &reference.path).unwrap();
                }
                2 => {
                    fs::create_dir(&reference.path).unwrap();
                }
                _ => {
                    pool.write_and_publish(&reference, b"expected").unwrap();
                    fs::hard_link(&reference.path, fixture.root.join("extra-link")).unwrap();
                }
            }
            assert!(pool.write_and_publish(&reference, b"expected").is_err());
            assert!(pool.remove(&reference).is_err());
            assert!(fs::symlink_metadata(&reference.path).is_ok());
        }
        let fixture = Fixture::new();
        let pool = fixture.pool();
        let reference = pool.plan(0, &fixture.path(1), b"expected").unwrap();
        assert!(pool.write_and_publish(&reference, b"mismatch").is_err());
        assert_eq!(pool.slot_metadata(0).unwrap().len(), 0);
        pool.write_and_publish(&reference, b"expected").unwrap();
        pool.slots[0].write_all_at(b"replaced", 0).unwrap();
        assert!(pool.verify(&reference).is_err());
        assert!(pool.write_and_publish(&reference, b"expected").is_err());
        assert_eq!(fs::read(&reference.path).unwrap(), b"replaced");
    }

    #[test]
    fn incomplete_initialization_and_changed_anchor_identity_are_retained() {
        let fixture = Fixture::new();
        let root = fixture.root.join("partial");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("slot-0"), b"partial").unwrap();
        assert!(Pool::open(&root, INSTALLATION).is_err());
        assert!(Pool::initialize(&root, INSTALLATION).is_err());
        assert_eq!(fs::read(root.join("slot-0")).unwrap(), b"partial");
        let pool = fixture.pool();
        assert!(Pool::open(&pool.directory.path, [0x32; 16]).is_err());
        let anchor = pool.directory.path.join("slot-0");
        fs::remove_file(&anchor).unwrap();
        fs::write(&anchor, b"").unwrap();
        fs::set_permissions(&anchor, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(pool.plan(0, &fixture.path(1), b"x").is_err());
        assert!(Pool::open(&pool.directory.path, INSTALLATION).is_err());
    }

    #[test]
    fn durable_reference_inventory_rejects_unknown_aliases_and_conflicting_slots() {
        let fixture = Fixture::new();
        let pool = fixture.pool();
        let first = pool.plan(0, &fixture.path(1), b"expected").unwrap();
        pool.validate_reference(&first).unwrap();
        pool.verify_references(&[&first, &first]).unwrap();
        let mut forged = first.clone();
        forged.identity.inode ^= 1;
        assert!(pool.validate_reference(&forged).is_err());
        let mut reused = first.clone();
        reused.path = fixture.path(2);
        assert!(pool.verify_references(&[&first, &reused]).is_err());
        let conflicting = pool.plan(1, &fixture.path(1), b"expected").unwrap();
        assert!(pool.verify_references(&[&first, &conflicting]).is_err());
        pool.write_and_publish(&first, b"expected").unwrap();
        assert!(pool.verify_references(&[]).is_err());
        pool.verify_references(&[&first]).unwrap();
        pool.remove(&first).unwrap();
        pool.slots[0].set_len(2).unwrap();
        pool.validate_reference(&first).unwrap();
        pool.verify_references(&[&first]).unwrap();
    }
}
