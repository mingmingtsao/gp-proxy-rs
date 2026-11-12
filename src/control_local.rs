//! Same-user local control transport. No credentials are stored here.
//!
//! The caller owns framing, instance-ID confirmation, deadlines and its bounded
//! worker pool. Construction requires a Tokio runtime with I/O enabled. This
//! module neither spawns tasks nor takes over unknown endpoint directories.
use std::{io, path::Path};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait LocalIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> LocalIo for T {}
pub type LocalStream = Box<dyn LocalIo>;

pub struct LocalConnection {
    pub stream: LocalStream,
    /// Compare with the authenticated protocol Hello before sending secrets.
    pub instance_id: [u8; 16],
}

/// Retains this instance's private namespace lock after its acceptor closes.
/// This is not proof of cleanup: only the service owner may decide when to
/// release it, after joining all tasks and before sending a completion report.
pub struct NamespaceLease {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    _inner: unix::NamespaceLease,
}

impl NamespaceLease {
    /// Consume this capability after joining local work, before reporting
    /// completion. Unsupported platforms carry no namespace resource.
    pub fn release(self) {}
}

pub struct LocalListener {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    inner: unix::Listener,
    instance_id: [u8; 16],
}

impl LocalListener {
    /// Create or recover an exclusively locked v2 endpoint namespace.
    /// Unknown and legacy directories are never adopted. New namespaces are
    /// prepared privately and published with an atomic no-replace rename.
    pub fn bind(directory: &Path) -> io::Result<Self> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            let inner = unix::Listener::bind(directory)?;
            Ok(Self {
                instance_id: inner.instance_id,
                inner,
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
            let _ = directory;
            Err(unsupported())
        }
    }

    pub fn instance_id(&self) -> [u8; 16] {
        self.instance_id
    }

    pub fn retain_namespace(&self) -> NamespaceLease {
        NamespaceLease {
            #[cfg(any(
                target_os = "macos",
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            _inner: self.inner.retain_namespace(),
        }
    }

    /// Accept and check identity only; never wait for client protocol bytes.
    /// Caller must cap concurrent protocol handshakes independently.
    pub async fn accept(&self) -> io::Result<LocalStream> {
        #[cfg(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            self.inner.accept().await
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

/// Verify local ownership before and after connecting, then verify peer UID.
/// Apply the caller's handshake timeout around this and the protocol exchange.
pub async fn connect(directory: &Path) -> io::Result<LocalConnection> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        unix::connect(directory).await
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = directory;
        Err(unsupported())
    }
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
        "authenticated local control transport is unavailable on this platform",
    )
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod unix {
    use super::*;
    use crate::private_fs::{self, Identity, Parents};
    use std::{
        fs::{self, DirBuilder, File, Metadata, OpenOptions},
        io::Write,
        os::unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        },
        path::PathBuf,
        sync::Arc,
    };
    use tokio::net::{UnixListener, UnixStream};

    const SOCKET: &str = "control.sock";
    const MARKER: &str = "instance";
    const OWNER: &str = "owner";
    const LOCK: &str = "lock";
    const OWNER_MAGIC: &str = "gp-proxy-control-owner-v2\n";
    const LOCK_MAGIC: &str = "gp-proxy-control-lock-v2\n";
    const OWNER_MAX: usize = 192;
    const STAGING_PREFIX: &str = ".gp-control-stage-";

    fn denied() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local control endpoint ownership or permissions are invalid",
        )
    }
    fn invalid() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, "invalid local control endpoint")
    }
    fn redact(error: io::Error) -> io::Error {
        io::Error::new(error.kind(), "local control endpoint operation failed")
    }

    fn own_uid() -> io::Result<u32> {
        // SO_PEERCRED (Linux) / getpeereid (macOS), through Tokio's safe API,
        // report the credentials at socketpair creation. No inherited socket,
        // environment user name, external process or unsafe syscall is used.
        let (left, right) = UnixStream::pair().map_err(redact)?;
        let left = left.peer_cred().map_err(redact)?;
        let right = right.peer_cred().map_err(redact)?;
        if left.uid() != right.uid()
            || left.pid() != Some(std::process::id() as i32)
            || right.pid() != Some(std::process::id() as i32)
        {
            return Err(denied());
        }
        Ok(left.uid())
    }

    fn metadata(path: &Path) -> io::Result<Metadata> {
        fs::symlink_metadata(path).map_err(redact)
    }
    const FS_ERRORS: private_fs::Errors = private_fs::Errors {
        denied: "local control endpoint ownership or permissions are invalid",
        invalid: "invalid local control endpoint",
        operation: "local control endpoint operation failed",
    };
    fn private(meta: &Metadata, uid: u32, mode: u32) -> io::Result<()> {
        private_fs::private(meta, uid, mode, FS_ERRORS)
    }
    fn directory_path(directory: &Path, uid: u32) -> io::Result<PathBuf> {
        private_fs::directory_path(directory, uid, FS_ERRORS)
    }
    fn options() -> OpenOptions {
        private_fs::options()
    }
    fn regular(meta: &Metadata, uid: u32, limit: usize) -> io::Result<()> {
        private_fs::regular(meta, uid, limit, FS_ERRORS)
    }
    fn open_private(path: &Path, uid: u32, limit: usize, write: bool) -> io::Result<File> {
        let before = metadata(path)?;
        regular(&before, uid, limit)?;
        let file = options().write(write).open(path).map_err(redact)?;
        let opened = file.metadata().map_err(redact)?;
        regular(&opened, uid, limit)?;
        if Identity::of(&opened) != Identity::of(&before) || !Identity::of(&before).matches(path) {
            return Err(denied());
        }
        Ok(file)
    }

    fn encode_id(id: &[u8; 16]) -> String {
        id.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    fn is_hex(bytes: &[u8]) -> bool {
        bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    }
    fn decode_id(value: &str) -> io::Result<[u8; 16]> {
        if value.len() != 32 || !is_hex(value.as_bytes()) {
            return Err(invalid());
        }
        let mut id = [0; 16];
        for (out, pair) in id.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            *out = digit(pair[0]) * 16 + digit(pair[1]);
        }
        Ok(id)
    }

    #[derive(Clone, PartialEq)]
    struct OwnerRecord {
        directory: Identity,
        lock: Identity,
        id: [u8; 16],
    }
    impl OwnerRecord {
        fn encode(&self) -> String {
            format!(
                "{OWNER_MAGIC}{} {} {} {}\n{}\n",
                self.directory.device,
                self.directory.inode,
                self.lock.device,
                self.lock.inode,
                encode_id(&self.id)
            )
        }
        fn lock_bytes(&self) -> String {
            format!("{LOCK_MAGIC}{}\n", encode_id(&self.id))
        }
        fn parse(source: &str, uid: u32) -> io::Result<Self> {
            let rest = source.strip_prefix(OWNER_MAGIC).ok_or_else(invalid)?;
            let (numbers, id) = rest.split_once('\n').ok_or_else(invalid)?;
            let mut numbers = numbers.split(' ');
            let mut number = || {
                numbers
                    .next()
                    .ok_or_else(invalid)?
                    .parse::<u64>()
                    .map_err(|_| invalid())
            };
            let record = Self {
                directory: Identity {
                    device: number()?,
                    inode: number()?,
                    uid,
                },
                lock: Identity {
                    device: number()?,
                    inode: number()?,
                    uid,
                },
                id: decode_id(id.strip_suffix('\n').ok_or_else(invalid)?)?,
            };
            if numbers.next().is_some() || record.encode() != source {
                return Err(invalid());
            }
            Ok(record)
        }
    }

    struct Owned {
        directory: PathBuf,
        directory_id: Identity,
        parents: Parents,
        uid: u32,
        socket: Option<Identity>,
        marker: Option<Identity>,
        owner: Option<Identity>,
        lock: Option<Identity>,
        record: Option<OwnerRecord>,
        owns_lock: bool,
        published: bool,
        // Retained descriptors pin inodes; the lock is released only after Drop
        // has finished its identity-checked endpoint cleanup.
        _directory_file: File,
        _marker_file: Option<File>,
        _owner_file: Option<File>,
        _lock_file: Option<File>,
    }
    impl Owned {
        fn open_directory(
            directory: PathBuf,
            parents: Parents,
            uid: u32,
            published: bool,
        ) -> io::Result<Self> {
            parents.verify()?;
            let meta = metadata(&directory)?;
            private(&meta, uid, 0o700)?;
            if !meta.is_dir() {
                return Err(denied());
            }
            let directory_file = options().open(&directory).map_err(redact)?;
            if Identity::of(&directory_file.metadata().map_err(redact)?) != Identity::of(&meta) {
                return Err(denied());
            }
            let owned = Self {
                directory,
                directory_id: Identity::of(&meta),
                parents,
                uid,
                socket: None,
                marker: None,
                owner: None,
                lock: None,
                record: None,
                owns_lock: false,
                published,
                _directory_file: directory_file,
                _marker_file: None,
                _owner_file: None,
                _lock_file: None,
            };
            owned.verify_directory()?;
            Ok(owned)
        }

        fn open_existing(directory: PathBuf, parents: Parents, uid: u32) -> io::Result<Self> {
            let mut owned = Self::open_directory(directory, parents, uid, true)?;
            let owner_path = owned.directory.join(OWNER);
            let owner = open_private(&owner_path, uid, OWNER_MAX, false)?;
            owned.owner = Some(Identity::of(&owner.metadata().map_err(redact)?));
            owned._owner_file = Some(owner);
            let record =
                OwnerRecord::parse(&crate::secret_file::read(&owner_path).map_err(redact)?, uid)?;
            let lock = open_private(
                &owned.directory.join(LOCK),
                uid,
                LOCK_MAGIC.len() + 33,
                true,
            )?;
            owned.lock = Some(Identity::of(&lock.metadata().map_err(redact)?));
            owned._lock_file = Some(lock);
            owned.record = Some(record);
            owned.verify_namespace()?;
            owned.lock()?;
            Ok(owned)
        }

        fn prepare_and_publish(
            directory: PathBuf,
            parents: Parents,
            uid: u32,
            checkpoint: &mut impl FnMut(&'static str),
        ) -> io::Result<Self> {
            let parent = directory.parent().ok_or_else(invalid)?;
            // Both rename operands are relative to the same pinned descriptor.
            // NOREPLACE is one kernel operation; an unsupported filesystem or
            // kernel is an error, never a check-then-plain-rename fallback.
            let parent_file = parents.open_parent()?;
            let mut stage = None;
            for _ in 0..4 {
                let mut id = [0; 16];
                getrandom::fill(&mut id).map_err(|_| {
                    io::Error::other("cannot create local control staging identifier")
                })?;
                let path = parent.join(format!("{STAGING_PREFIX}{}", encode_id(&id)));
                parents.verify()?;
                match DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {
                        stage = Some(path);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(redact(error)),
                }
            }
            let stage = stage.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "cannot reserve local control staging",
                )
            })?;
            // The directory starts at most 0700, even under a restrictive umask.
            // Until identity pinning succeeds, an error may leave a private
            // orphan. It never occupies or is promoted to the final path.
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).map_err(redact)?;
            let mut owned = Self::open_directory(stage, parents, uid, false)?;
            checkpoint("directory");
            let lock = options()
                .write(true)
                .create_new(true)
                .open(owned.directory.join(LOCK))
                .map_err(redact)?;
            owned.lock = Some(Identity::of(&lock.metadata().map_err(redact)?));
            owned._lock_file = Some(lock);
            owned.lock()?;
            let mut id = [0; 16];
            getrandom::fill(&mut id).map_err(|_| {
                io::Error::other("cannot create local control ownership identifier")
            })?;
            let record = OwnerRecord {
                directory: owned.directory_id,
                lock: owned.lock.ok_or_else(invalid)?,
                id,
            };
            let lock = owned._lock_file.as_mut().ok_or_else(invalid)?;
            lock.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(redact)?;
            lock.write_all(record.lock_bytes().as_bytes())
                .map_err(redact)?;
            lock.sync_all().map_err(redact)?;
            checkpoint("lock");
            let owner = options()
                .write(true)
                .create_new(true)
                .open(owned.directory.join(OWNER))
                .map_err(redact)?;
            owned.owner = Some(Identity::of(&owner.metadata().map_err(redact)?));
            owned._owner_file = Some(owner);
            let owner = owned._owner_file.as_mut().ok_or_else(invalid)?;
            owner
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(redact)?;
            let bytes = record.encode();
            owner
                .write_all(&bytes.as_bytes()[..OWNER_MAGIC.len()])
                .map_err(redact)?;
            checkpoint("partial_owner");
            owner
                .write_all(&bytes.as_bytes()[OWNER_MAGIC.len()..])
                .map_err(redact)?;
            owner.sync_all().map_err(redact)?;
            owned.record = Some(record);
            owned._directory_file.sync_all().map_err(redact)?;
            checkpoint("owner_prepared");
            owned.verify_namespace()?;
            let source_name = owned.directory.file_name().ok_or_else(invalid)?;
            let final_name = directory.file_name().ok_or_else(invalid)?;
            match rustix::fs::renameat_with(
                &parent_file,
                source_name,
                &parent_file,
                final_name,
                rustix::fs::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {
                    // Keep these infallible updates adjacent to the successful
                    // rename. Any later error must retain permanent owner/lock
                    // and clean only this generation's disposable endpoints.
                    owned.directory = directory;
                    owned.published = true;
                    checkpoint("directory_published");
                    parent_file.sync_all().map_err(redact)?;
                    owned.verify_namespace()?;
                    Ok(owned)
                }
                Err(rustix::io::Errno::EXIST) => {
                    // A concurrent creator won. Clean only our unpublished
                    // stage, then apply the full existing-namespace protocol.
                    // No recursive cleanup, retries, or overwrites of final.
                    let parents = owned.parents.clone();
                    drop(owned);
                    parents.verify()?;
                    Self::open_existing(directory, parents, uid)
                }
                Err(error) => Err(redact(error.into())),
            }
        }

        fn verify_directory(&self) -> io::Result<()> {
            self.parents.verify()?;
            let meta = metadata(&self.directory)?;
            private(&meta, self.uid, 0o700)?;
            if !meta.is_dir() || Identity::of(&meta) != self.directory_id {
                return Err(denied());
            }
            Ok(())
        }
        fn verify_namespace(&self) -> io::Result<()> {
            self.verify_directory()?;
            let record = self.record.as_ref().ok_or_else(invalid)?;
            for (name, identity, max) in [
                (OWNER, self.owner, OWNER_MAX),
                (LOCK, self.lock, LOCK_MAGIC.len() + 33),
            ] {
                let path = self.directory.join(name);
                let meta = metadata(&path)?;
                regular(&meta, self.uid, max)?;
                if Some(Identity::of(&meta)) != identity {
                    return Err(denied());
                }
                let text = crate::secret_file::read(&path).map_err(redact)?;
                let expected = if name == OWNER {
                    record.encode()
                } else {
                    record.lock_bytes()
                };
                if *text != expected {
                    return Err(invalid());
                }
            }
            if record.directory != self.directory_id || Some(record.lock) != self.lock {
                return Err(denied());
            }
            self.parents.verify()
        }
        fn lock(&mut self) -> io::Result<()> {
            self._lock_file
                .as_ref()
                .ok_or_else(invalid)?
                .try_lock()
                .map_err(|error| {
                    let error: io::Error = error.into();
                    io::Error::new(
                        error.kind(),
                        "local control endpoint is in use or cannot be locked",
                    )
                })?;
            self.owns_lock = true;
            Ok(())
        }
        fn recover(&mut self) -> io::Result<()> {
            self.verify_namespace()?;
            // Validate the entire bounded namespace before deleting anything.
            // A valid lock does not authorize removing arbitrary user files.
            let mut count = 0;
            for entry in fs::read_dir(&self.directory).map_err(redact)? {
                let name = entry.map_err(redact)?.file_name();
                count += 1;
                if count > 4
                    || ![OWNER, LOCK, SOCKET, MARKER]
                        .iter()
                        .any(|known| name == *known)
                {
                    return Err(invalid());
                }
            }
            let optional = |name| match fs::symlink_metadata(self.directory.join(name)) {
                Ok(meta) => Ok(Some(meta)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(redact(error)),
            };
            let marker = optional(MARKER)?;
            if let Some(meta) = &marker {
                regular(meta, self.uid, 32)?;
                let value =
                    crate::secret_file::read(&self.directory.join(MARKER)).map_err(redact)?;
                if !is_hex(value.as_bytes()) {
                    return Err(invalid());
                }
            }
            let socket = optional(SOCKET)?;
            if let Some(meta) = &socket {
                // bind precedes chmod on Unix. An unpublished socket may still
                // have umask-derived access bits inside the verified 0700 dir.
                if !meta.file_type().is_socket()
                    || meta.uid() != self.uid
                    || meta.nlink() != 1
                    || meta.mode() & 0o7000 != 0
                {
                    return Err(denied());
                }
            }
            self.socket = socket.as_ref().map(Identity::of);
            self.marker = marker.as_ref().map(Identity::of);
            for (name, id) in [(SOCKET, self.socket), (MARKER, self.marker)] {
                if let Some(id) = id {
                    self.verify_namespace()?;
                    let path = self.directory.join(name);
                    if !id.matches(&path) {
                        return Err(denied());
                    }
                    fs::remove_file(path).map_err(redact)?;
                }
            }
            self.socket = None;
            self.marker = None;
            Ok(())
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            if self.verify_directory().is_err() {
                return;
            }
            if self.published && (!self.owns_lock || self.verify_namespace().is_err()) {
                return;
            }
            for (name, identity) in [(SOCKET, self.socket), (MARKER, self.marker)] {
                let path = self.directory.join(name);
                if self.verify_directory().is_ok() && identity.is_some_and(|id| id.matches(&path)) {
                    let _ = fs::remove_file(path);
                }
            }
            if !self.published {
                // Only this process's never-published bootstrap may be removed.
                // After publication owner/lock/namespace are permanent.
                for (name, identity) in [(OWNER, self.owner), (LOCK, self.lock)] {
                    let path = self.directory.join(name);
                    if self.verify_directory().is_ok()
                        && identity.is_some_and(|id| id.matches(&path))
                    {
                        let _ = fs::remove_file(path);
                    }
                }
                if self.verify_directory().is_ok() {
                    let _ = fs::remove_dir(&self.directory);
                }
            }
        }
    }

    pub(super) struct Listener {
        // Close the socket first; Owned retains the permanent lock through its
        // endpoint cleanup, and never unlinks the directory/lock after publish.
        listener: UnixListener,
        owned: Arc<Owned>,
        pub(super) instance_id: [u8; 16],
        uid: u32,
    }

    pub(super) struct NamespaceLease {
        _owned: Arc<Owned>,
    }

    impl Listener {
        pub(super) fn retain_namespace(&self) -> NamespaceLease {
            NamespaceLease {
                _owned: self.owned.clone(),
            }
        }
        pub(super) fn bind(directory: &Path) -> io::Result<Self> {
            Self::bind_with(directory, |_| {})
        }
        fn bind_with(
            directory: &Path,
            mut checkpoint: impl FnMut(&'static str),
        ) -> io::Result<Self> {
            let uid = own_uid()?;
            let directory = directory_path(directory, uid)?;
            let maximum = if cfg!(target_os = "macos") { 103 } else { 107 };
            if directory.join(SOCKET).as_os_str().as_bytes().len() > maximum {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "local control socket path is too long; use a shorter --control-dir",
                ));
            }
            let parents = Parents::capture(&directory, uid, FS_ERRORS)?;
            let mut owned = match fs::symlink_metadata(&directory) {
                Ok(_) => Owned::open_existing(directory, parents, uid)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    Owned::prepare_and_publish(directory, parents, uid, &mut checkpoint)?
                }
                Err(error) => return Err(redact(error)),
            };
            owned.verify_namespace()?;
            checkpoint("owner_published");
            owned.recover()?;
            let mut instance_id = [0; 16];
            getrandom::fill(&mut instance_id)
                .map_err(|_| io::Error::other("cannot create local control instance identifier"))?;
            let marker = options()
                .write(true)
                .create_new(true)
                .open(owned.directory.join(MARKER))
                .map_err(redact)?;
            owned.marker = Some(Identity::of(&marker.metadata().map_err(redact)?));
            owned._marker_file = Some(marker);
            let marker = owned._marker_file.as_mut().ok_or_else(invalid)?;
            marker
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(redact)?;
            checkpoint("empty_instance");
            let encoded = encode_id(&instance_id);
            marker.write_all(&encoded.as_bytes()[..7]).map_err(redact)?;
            checkpoint("partial_instance");
            marker.write_all(&encoded.as_bytes()[7..]).map_err(redact)?;
            marker.sync_all().map_err(redact)?;
            checkpoint("instance");
            owned.verify_namespace()?;
            let socket_path = owned.directory.join(SOCKET);
            let listener = UnixListener::bind(&socket_path).map_err(redact)?;
            owned.socket = Some(Identity::of(&metadata(&socket_path)?));
            checkpoint("socket");
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).map_err(redact)?;
            let result = Self {
                listener,
                owned: Arc::new(owned),
                instance_id,
                uid,
            };
            result.verify()?;
            checkpoint("published");
            Ok(result)
        }

        fn verify(&self) -> io::Result<()> {
            self.owned.verify_namespace()?;
            let observed = inspect(&self.owned.directory, self.uid)?;
            if observed.directory != self.owned.directory_id
                || Some(observed.socket) != self.owned.socket
                || Some(observed.marker) != self.owned.marker
                || observed.instance_id != self.instance_id
            {
                return Err(denied());
            }
            self.owned.parents.verify()
        }

        pub(super) async fn accept(&self) -> io::Result<LocalStream> {
            self.verify().map_err(|_| invalid())?;
            let (stream, _) = self.listener.accept().await.map_err(redact)?;
            let credentials = stream.peer_cred();
            // Namespace damage is still fatal, even if this peer has closed.
            self.verify().map_err(|_| invalid())?;
            // macOS can report NotConnected when a queued peer closes before
            // the credential query. No verified UID means reject this peer;
            // it does not mean our listening endpoint is broken. The caller
            // applies its existing bounded denial backoff before accepting more.
            if credentials.map_err(|_| denied())?.uid() != self.uid {
                return Err(denied());
            }
            Ok(Box::new(stream))
        }
    }

    #[derive(PartialEq)]
    struct Observed {
        directory: Identity,
        socket: Identity,
        marker: Identity,
        instance_id: [u8; 16],
    }

    fn inspect(directory: &Path, uid: u32) -> io::Result<Observed> {
        let dir = metadata(directory)?;
        private(&dir, uid, 0o700)?;
        if !dir.is_dir() {
            return Err(invalid());
        }
        let socket = metadata(&directory.join(SOCKET))?;
        private(&socket, uid, 0o600)?;
        if !socket.file_type().is_socket() || socket.nlink() != 1 {
            return Err(invalid());
        }
        let path = directory.join(MARKER);
        let marker = metadata(&path)?;
        private(&marker, uid, 0o600)?;
        if !marker.is_file() || marker.nlink() != 1 || marker.len() != 32 {
            return Err(invalid());
        }
        // Reuse the secret reader's NOFOLLOW/NONBLOCK and identity checks, even
        // though this random instance marker is public metadata, not a secret.
        let encoded = crate::secret_file::read(&path).map_err(redact)?;
        if encoded.len() != 32
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        let mut instance_id = [0; 16];
        for (output, pair) in instance_id
            .iter_mut()
            .zip(encoded.as_bytes().chunks_exact(2))
        {
            let digit = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            *output = digit(pair[0]) * 16 + digit(pair[1]);
        }
        if Identity::of(&metadata(directory)?) != Identity::of(&dir)
            || Identity::of(&metadata(&path)?) != Identity::of(&marker)
            || Identity::of(&metadata(&directory.join(SOCKET))?) != Identity::of(&socket)
        {
            return Err(denied());
        }
        Ok(Observed {
            directory: Identity::of(&dir),
            socket: Identity::of(&socket),
            marker: Identity::of(&marker),
            instance_id,
        })
    }

    pub(super) async fn connect(directory: &Path) -> io::Result<LocalConnection> {
        let uid = own_uid()?;
        let directory = directory_path(directory, uid)?;
        let parents = Parents::capture(&directory, uid, FS_ERRORS)?;
        let before = inspect(&directory, uid)?;
        let stream = UnixStream::connect(directory.join(SOCKET))
            .await
            .map_err(redact)?;
        if stream.peer_cred().map_err(redact)?.uid() != uid || inspect(&directory, uid)? != before {
            return Err(denied());
        }
        parents.verify()?;
        Ok(LocalConnection {
            stream: Box::new(stream),
            instance_id: before.instance_id,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, OpenOptionsExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        struct Fixture(PathBuf);
        impl Fixture {
            fn new() -> Self {
                // Keep sockaddr_un below macOS's small pathname bound.
                let path = Path::new("/tmp").join(format!("gpc-{:016x}", rand::random::<u64>()));
                DirBuilder::new().mode(0o700).create(&path).unwrap();
                Self(path)
            }
            fn endpoint(&self) -> PathBuf {
                self.0.join("endpoint")
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn assert_idle(endpoint: &Path) {
            assert!(endpoint.is_dir());
            assert!(!endpoint.join(SOCKET).exists());
            assert!(!endpoint.join(MARKER).exists());
            let mut entries: Vec<_> = fs::read_dir(endpoint)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            entries.sort();
            assert_eq!(entries, [LOCK, OWNER]);
        }

        #[tokio::test]
        async fn namespace_lease_outlives_acceptor_and_blocks_rebinding() {
            const CHILD: &str = "GP_SYNTHETIC_NAMESPACE_LEASE";
            if std::env::var(CHILD).ok().as_deref() != Some("isolated-v1") {
                use std::{
                    io::Read,
                    process::{Child, Command, Stdio},
                    time::{Duration, Instant},
                };
                struct Process(Child);
                impl Drop for Process {
                    fn drop(&mut self) {
                        let _ = self.0.kill();
                        let _ = self.0.wait();
                    }
                }
                // Other lib tests spawn children concurrently. CLOEXEC does
                // not forbid a descriptor reference before exec. Create the
                // listener only inside this single-test child, which never
                // spawns, so immediate close/rebind assertions stay strict.
                // This isolates a possible interference source; it does not
                // identify which process held an fd in an earlier failed run.
                let fixture = Fixture::new();
                let output = fixture.0.join("namespace-child.log");
                let log = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&output)
                    .unwrap();
                let mut child = Process(Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "control_local::unix::tests::namespace_lease_outlives_acceptor_and_blocks_rebinding", "--test-threads=1"])
                    .env_clear()
                    .env(CHILD, "isolated-v1")
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log.try_clone().unwrap()))
                    .stderr(Stdio::from(log))
                    .spawn().unwrap());
                let end = Instant::now() + Duration::from_secs(5);
                let status = loop {
                    assert!(
                        fs::metadata(&output).unwrap().len() <= 64 * 1024,
                        "namespace child output limit"
                    );
                    if let Some(status) = child.0.try_wait().unwrap() {
                        break status;
                    }
                    assert!(Instant::now() < end, "namespace child deadline");
                    std::thread::sleep(Duration::from_millis(2));
                };
                if !status.success() {
                    let mut detail = String::new();
                    File::open(&output)
                        .unwrap()
                        .take(64 * 1024)
                        .read_to_string(&mut detail)
                        .unwrap();
                    panic!("isolated namespace check failed: {status}: {detail}");
                }
                // Do not echo successful child libtest summaries into the
                // parent's output, which would double-count suite totals.
                return;
            }
            let fixture = Fixture::new();
            let endpoint = fixture.endpoint();
            let server = LocalListener::bind(&endpoint).unwrap();
            let instance = server.instance_id();
            let lock = Identity::of(&metadata(&endpoint.join(LOCK)).unwrap());
            let lease = server.retain_namespace();
            drop(server);
            // The listening fd is closed, but completion has not released the
            // owner's namespace capability. Socket disappearance is irrelevant.
            assert!(UnixStream::connect(endpoint.join(SOCKET)).await.is_err());
            assert!(LocalListener::bind(&endpoint).is_err());
            assert!(lock.matches(&endpoint.join(LOCK)));
            assert_eq!(
                fs::read_to_string(endpoint.join(MARKER)).unwrap(),
                encode_id(&instance)
            );
            drop(lease);
            assert_idle(&endpoint);
            let next = LocalListener::bind(&endpoint).unwrap();
            assert_ne!(instance, next.instance_id());
            assert!(lock.matches(&endpoint.join(LOCK)));
            drop(next);
            assert_idle(&endpoint);
        }

        #[tokio::test]
        async fn pair_credentials_match_owned_directory_and_roundtrip_has_no_tasks() {
            let fixture = Fixture::new();
            let uid = own_uid().unwrap();
            assert_eq!(metadata(&fixture.0).unwrap().uid(), uid);
            let endpoint = fixture.endpoint();
            let server = LocalListener::bind(&endpoint).unwrap();
            let mut client = super::connect(&endpoint).await.unwrap();
            assert_eq!(client.instance_id, server.instance_id());
            let mut accepted = server.accept().await.unwrap();
            client.stream.write_all(b"synthetic request").await.unwrap();
            let mut bytes = [0; 17];
            accepted.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"synthetic request");
            accepted.write_all(b"ok").await.unwrap();
            let mut reply = [0; 2];
            client.stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"ok");
            assert_eq!(metadata(&endpoint).unwrap().mode() & 0o7777, 0o700);
            for name in [SOCKET, MARKER] {
                assert_eq!(
                    metadata(&endpoint.join(name)).unwrap().mode() & 0o7777,
                    0o600
                );
            }
            drop((accepted, client, server));
            assert_idle(&endpoint);
            let next = LocalListener::bind(&endpoint).unwrap();
            drop(next);
            assert_idle(&endpoint);
        }

        #[tokio::test]
        async fn closed_peer_does_not_turn_into_a_listener_failure() {
            let fixture = Fixture::new();
            let endpoint = fixture.endpoint();
            let server = LocalListener::bind(&endpoint).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                // Queue a connection, then close it before the acceptor can
                // inspect credentials. macOS may no longer provide peer PID.
                let client = UnixStream::connect(endpoint.join(SOCKET)).await.unwrap();
                drop(client);
                match server.accept().await {
                    Ok(mut stream) => {
                        // Some kernels retain verified credentials after EOF.
                        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
                    }
                    Err(error) => assert_eq!(
                        error.kind(),
                        io::ErrorKind::PermissionDenied,
                        "an unverifiable peer must be rejected without killing the listener"
                    ),
                }
                let mut client = super::connect(&endpoint).await.unwrap();
                let mut accepted = server.accept().await.unwrap();
                client.stream.write_all(b"live").await.unwrap();
                let mut bytes = [0; 4];
                accepted.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"live");
            })
            .await
            .unwrap();
            drop(server);
            assert_idle(&endpoint);
        }

        #[tokio::test]
        async fn existing_directory_or_symlink_is_never_removed_or_reused() {
            let fixture = Fixture::new();
            let endpoint = fixture.endpoint();
            fs::create_dir(&endpoint).unwrap();
            fs::write(endpoint.join("keep"), b"keep").unwrap();
            assert!(LocalListener::bind(&endpoint).is_err());
            assert_eq!(fs::read(endpoint.join("keep")).unwrap(), b"keep");
            let link = fixture.0.join("link");
            symlink(&endpoint, &link).unwrap();
            assert!(LocalListener::bind(&link).is_err());
            assert!(link.is_symlink());
        }

        #[tokio::test]
        async fn client_rejects_permissions_links_marker_shape_and_wrong_expected_uid() {
            let fixture = Fixture::new();
            let endpoint = fixture.endpoint();
            let server = LocalListener::bind(&endpoint).unwrap();
            let uid = own_uid().unwrap();
            assert!(inspect(&endpoint, uid.wrapping_add(1)).is_err());
            for (path, good, bad) in [
                (endpoint.clone(), 0o700, 0o750),
                (endpoint.join(SOCKET), 0o600, 0o660),
                (endpoint.join(MARKER), 0o600, 0o640),
            ] {
                fs::set_permissions(&path, fs::Permissions::from_mode(bad)).unwrap();
                assert!(super::connect(&endpoint).await.is_err());
                fs::set_permissions(path, fs::Permissions::from_mode(good)).unwrap();
            }
            let marker = endpoint.join(MARKER);
            let original = fs::read(&marker).unwrap();
            for bad in [vec![b'f'; 31], vec![b'F'; 32], vec![b'0'; 33]] {
                fs::write(&marker, bad).unwrap();
                assert!(super::connect(&endpoint).await.is_err());
            }
            fs::write(&marker, original).unwrap();
            let saved = endpoint.join("saved");
            fs::rename(&marker, &saved).unwrap();
            symlink(&saved, &marker).unwrap();
            assert!(super::connect(&endpoint).await.is_err());
            fs::remove_file(&marker).unwrap();
            fs::rename(saved, marker).unwrap();
            drop(server);
        }

        #[tokio::test]
        async fn marker_hard_links_and_socket_substitutions_are_rejected() {
            let fixture = Fixture::new();
            let endpoint = fixture.endpoint();
            let server = LocalListener::bind(&endpoint).unwrap();
            let marker_alias = fixture.0.join("marker-alias");
            fs::hard_link(endpoint.join(MARKER), &marker_alias).unwrap();
            assert!(super::connect(&endpoint).await.is_err());
            assert!(server.accept().await.is_err());
            fs::remove_file(marker_alias).unwrap();

            let socket = endpoint.join(SOCKET);
            let saved = endpoint.join("saved-socket");
            fs::rename(&socket, &saved).unwrap();
            symlink(&saved, &socket).unwrap();
            assert!(super::connect(&endpoint).await.is_err());
            assert!(server.accept().await.is_err());
            fs::remove_file(&socket).unwrap();
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&socket)
                .unwrap();
            assert!(super::connect(&endpoint).await.is_err());
            assert!(server.accept().await.is_err());
            drop(server);
            assert!(socket.is_file(), "cleanup must preserve replacement");
        }

        #[tokio::test]
        async fn idle_client_does_not_block_another_accept_and_marker_changes_fail_closed() {
            let fixture = Fixture::new();
            let endpoint = fixture.endpoint();
            // Ordinary non-writable shared ancestors are valid deployment paths.
            fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(
                directory_path(Path::new("./control-test-not-created"), own_uid().unwrap()).is_ok()
            );
            let server = LocalListener::bind(&endpoint).unwrap();
            let idle = super::connect(&endpoint).await.unwrap();
            let accepted_idle =
                tokio::time::timeout(std::time::Duration::from_secs(1), server.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let second = super::connect(&endpoint).await.unwrap();
            let accepted_second =
                tokio::time::timeout(std::time::Duration::from_secs(1), server.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut changed_id = server.instance_id();
            changed_id[0] ^= 1;
            let changed: String = changed_id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            fs::write(endpoint.join(MARKER), changed).unwrap();
            assert!(server.accept().await.is_err());
            drop((idle, accepted_idle, second, accepted_second, server));
            assert_idle(&endpoint);
        }

        #[tokio::test]
        async fn bind_failure_cleans_only_the_new_owned_directory() {
            let fixture = Fixture::new();
            let endpoint = fixture.0.join("x".repeat(100));
            let error = LocalListener::bind(&endpoint).err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                "local control socket path is too long; use a shorter --control-dir"
            );
            assert!(!error.to_string().contains(endpoint.to_str().unwrap()));
            assert!(
                !endpoint.exists(),
                "failed long socket path must not leave a marker"
            );
            assert!(fixture.0.is_dir());
        }

        #[tokio::test]
        async fn unsafe_parent_rejected_and_owned_cleanup_preserves_replacements() {
            let fixture = Fixture::new();
            let endpoint = fixture.endpoint();
            fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(LocalListener::bind(&endpoint).is_err());
            assert!(!endpoint.exists());
            fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
            let server = LocalListener::bind(&endpoint).unwrap();
            let marker = endpoint.join(MARKER);
            fs::remove_file(&marker).unwrap();
            fs::write(&marker, b"foreign replacement").unwrap();
            drop(server);
            assert_eq!(fs::read(&marker).unwrap(), b"foreign replacement");
            assert!(endpoint.exists());
            assert!(!endpoint.join(SOCKET).exists());
        }

        #[tokio::test]
        async fn directory_replacement_and_extra_files_are_never_recursively_removed() {
            let fixture = Fixture::new();
            let endpoint = fixture.endpoint();
            let server = LocalListener::bind(&endpoint).unwrap();
            let moved = fixture.0.join("moved");
            fs::rename(&endpoint, &moved).unwrap();
            fs::create_dir(&endpoint).unwrap();
            fs::write(endpoint.join("keep"), b"keep").unwrap();
            drop(server);
            assert_eq!(fs::read(endpoint.join("keep")).unwrap(), b"keep");
            assert!(moved.join(SOCKET).exists() && moved.join(MARKER).exists());
            let second = fixture.0.join("second");
            let server = LocalListener::bind(&second).unwrap();
            fs::write(second.join("keep"), b"keep").unwrap();
            drop(server);
            assert_eq!(fs::read(second.join("keep")).unwrap(), b"keep");
            assert!(!second.join(SOCKET).exists() && !second.join(MARKER).exists());
        }

        #[tokio::test]
        async fn stale_hex_prefixes_recover_but_invalid_records_remain_untouched() {
            let fixture = Fixture::new();
            let endpoint = fixture.endpoint();
            drop(LocalListener::bind(&endpoint).unwrap());
            let owner = fs::read(endpoint.join(OWNER)).unwrap();
            let lock_id = Identity::of(&metadata(&endpoint.join(LOCK)).unwrap());
            for value in [
                "",
                "a",
                "0123456789abcdef",
                "0123456789abcdef0123456789abcdef",
            ] {
                let mut marker = options()
                    .write(true)
                    .create_new(true)
                    .open(endpoint.join(MARKER))
                    .unwrap();
                marker.write_all(value.as_bytes()).unwrap();
                drop(marker);
                let server = LocalListener::bind(&endpoint).unwrap();
                assert_eq!(fs::read(endpoint.join(OWNER)).unwrap(), owner);
                assert!(lock_id.matches(&endpoint.join(LOCK)));
                drop(server);
                assert_idle(&endpoint);
            }
            for value in ["F", "g", "0123456789abcdef0123456789abcdef0"] {
                let mut marker = options()
                    .write(true)
                    .create_new(true)
                    .open(endpoint.join(MARKER))
                    .unwrap();
                marker.write_all(value.as_bytes()).unwrap();
                drop(marker);
                assert!(LocalListener::bind(&endpoint).is_err());
                assert_eq!(fs::read(endpoint.join(MARKER)).unwrap(), value.as_bytes());
                assert_eq!(fs::read(endpoint.join(OWNER)).unwrap(), owner);
                assert!(lock_id.matches(&endpoint.join(LOCK)));
                fs::remove_file(endpoint.join(MARKER)).unwrap();
            }
        }

        #[tokio::test]
        async fn namespace_lock_and_owner_corruption_never_delete_endpoint_files() {
            let fixture = Fixture::new();
            for name in [OWNER, LOCK] {
                let endpoint = fixture.0.join(name);
                let server = LocalListener::bind(&endpoint).unwrap();
                let path = endpoint.join(name);
                let original = fs::read(&path).unwrap();
                fs::write(&path, b"unknown synthetic ownership bytes").unwrap();
                assert!(server.accept().await.is_err());
                assert!(LocalListener::bind(&endpoint).is_err());
                drop(server);
                assert!(endpoint.join(SOCKET).exists() && endpoint.join(MARKER).exists());
                assert_eq!(
                    fs::read(&path).unwrap(),
                    b"unknown synthetic ownership bytes"
                );
                fs::write(&path, original).unwrap();
                drop(LocalListener::bind(&endpoint).unwrap());
                assert_idle(&endpoint);
            }
        }

        #[tokio::test]
        async fn final_appearing_after_stage_preparation_is_never_overwritten() {
            let fixture = Fixture::new();
            for with_file in [false, true] {
                let endpoint = fixture.0.join(if with_file { "unknown" } else { "empty" });
                let mut original = None;
                let error = Listener::bind_with(&endpoint, |stage| {
                    if stage == "owner_prepared" {
                        DirBuilder::new().mode(0o700).create(&endpoint).unwrap();
                        if with_file {
                            fs::write(endpoint.join("keep"), b"synthetic original").unwrap();
                        }
                        original = Some(Identity::of(&metadata(&endpoint).unwrap()));
                    }
                })
                .err()
                .unwrap();
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
                assert!(original.unwrap().matches(&endpoint));
                let entries = fs::read_dir(&endpoint).unwrap().count();
                assert_eq!(entries, usize::from(with_file));
                if with_file {
                    assert_eq!(
                        fs::read(endpoint.join("keep")).unwrap(),
                        b"synthetic original"
                    );
                }
                assert!(
                    fs::read_dir(&fixture.0).unwrap().all(|entry| {
                        !entry
                            .unwrap()
                            .file_name()
                            .to_str()
                            .unwrap()
                            .starts_with(STAGING_PREFIX)
                    }),
                    "losing caller must clean only its own unpublished stage"
                );
            }
        }

        // Invoked only by the exact-filtered parent process below. Normal test
        // discovery does nothing; neither branch reads a credentials file.
        #[tokio::test]
        async fn crash_stage_child() {
            if std::env::var("GP_SYNTHETIC_CONTROL_CRASH").ok().as_deref() != Some("v2-test-only") {
                return;
            }
            use std::io::Read;
            let endpoint = PathBuf::from(std::env::var_os("GP_SYNTHETIC_CONTROL_PATH").unwrap());
            let ready = PathBuf::from(std::env::var_os("GP_SYNTHETIC_CONTROL_READY").unwrap());
            let selected = std::env::var("GP_SYNTHETIC_CONTROL_STAGE").unwrap();
            let _listener = Listener::bind_with(&endpoint, |stage| {
                if stage == selected {
                    fs::write(&ready, stage.as_bytes()).unwrap();
                    std::io::stdin().read_exact(&mut [0; 1]).unwrap();
                }
            })
            .unwrap();
            panic!("parent did not kill the selected checkpoint child");
        }

        #[test]
        fn subprocess_sigkill_bootstrap_boundary_and_published_recovery() {
            use std::{
                process::{Child, Command, Stdio},
                time::{Duration, Instant},
            };
            struct Process(Child);
            impl Drop for Process {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            fn snapshot(path: &Path) -> Vec<(std::ffi::OsString, u64, u32, Vec<u8>)> {
                let mut result: Vec<_> = fs::read_dir(path)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        let meta = entry.metadata().unwrap();
                        let bytes = if meta.is_file() {
                            fs::read(entry.path()).unwrap()
                        } else {
                            vec![]
                        };
                        (entry.file_name(), meta.ino(), meta.mode(), bytes)
                    })
                    .collect();
                result.sort();
                result
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _entered = runtime.enter();
            let mut recovered = 0;
            for (stage, published) in [
                ("directory", false),
                ("lock", false),
                ("partial_owner", false),
                ("owner_prepared", false),
                ("directory_published", true),
                ("owner_published", true),
                ("empty_instance", true),
                ("partial_instance", true),
                ("instance", true),
                ("socket", true),
                ("published", true),
            ] {
                let fixture = Fixture::new();
                let endpoint = fixture.endpoint();
                let ready = fixture.0.join(format!("{stage}.ready"));
                let mut child = Process(
                    Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "control_local::unix::tests::crash_stage_child",
                            "--test-threads=1",
                        ])
                        .env_clear()
                        .env("GP_SYNTHETIC_CONTROL_CRASH", "v2-test-only")
                        .env("GP_SYNTHETIC_CONTROL_PATH", &endpoint)
                        .env("GP_SYNTHETIC_CONTROL_READY", &ready)
                        .env("GP_SYNTHETIC_CONTROL_STAGE", stage)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap(),
                );
                let until = Instant::now() + Duration::from_secs(5);
                while fs::read(&ready).ok().as_deref() != Some(stage.as_bytes()) {
                    assert!(
                        child.0.try_wait().unwrap().is_none(),
                        "checkpoint child exited: {stage}"
                    );
                    assert!(
                        Instant::now() < until,
                        "checkpoint child not ready: {stage}"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                assert_eq!(fs::read(&ready).unwrap(), stage.as_bytes());
                child.0.kill().unwrap();
                let until = Instant::now() + Duration::from_secs(5);
                while child.0.try_wait().unwrap().is_none() {
                    assert!(Instant::now() < until, "killed child did not exit: {stage}");
                    std::thread::sleep(Duration::from_millis(2));
                }
                let orphan = fs::read_dir(&fixture.0)
                    .unwrap()
                    .filter_map(|entry| {
                        let entry = entry.unwrap();
                        entry
                            .file_name()
                            .to_str()
                            .unwrap()
                            .starts_with(STAGING_PREFIX)
                            .then_some(entry.path())
                    })
                    .collect::<Vec<_>>();
                if published {
                    assert!(endpoint.is_dir());
                    assert!(orphan.is_empty(), "published stage path remained: {stage}");
                } else {
                    assert!(
                        !endpoint.exists(),
                        "partial bootstrap occupies final path: {stage}"
                    );
                    assert_eq!(orphan.len(), 1);
                }
                let before = orphan.first().map(|path| snapshot(path));
                let server = LocalListener::bind(&endpoint).unwrap();
                drop(server);
                assert_idle(&endpoint);
                if let Some(orphan) = orphan.first() {
                    assert_eq!(
                        snapshot(orphan),
                        before.unwrap(),
                        "orphan stage was modified"
                    );
                }
                recovered += 1;
            }
            assert_eq!(recovered, 11);
            eprintln!(
                "control atomic recovery checkpoints: 11 real child SIGKILLs; 4 prepublish stages left final absent and retry succeeded with orphan preserved; 7 published-namespace states recovered; all children reaped"
            );
        }
    }
}

#[cfg(all(
    test,
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))
))]
mod unsupported_tests {
    use super::*;
    #[tokio::test]
    async fn unsupported_platform_has_no_fallback_or_filesystem_side_effects() {
        let path = std::env::temp_dir().join("gp-control-unsupported-not-created");
        assert!(!path.exists());
        assert!(
            matches!(LocalListener::bind(&path), Err(error) if error.kind() == io::ErrorKind::Unsupported)
        );
        assert!(
            matches!(connect(&path).await, Err(error) if error.kind() == io::ErrorKind::Unsupported)
        );
        assert!(!path.exists());
    }
}
