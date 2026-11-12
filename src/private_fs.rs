//! Private-directory identity primitives shared by local control and log storage.
#![cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]

use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy)]
pub(crate) struct Errors {
    pub denied: &'static str,
    pub invalid: &'static str,
    pub operation: &'static str,
}
impl Errors {
    pub fn denied(self) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, self.denied)
    }
    pub fn invalid(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self.invalid)
    }
    pub fn redact(self, error: io::Error) -> io::Error {
        io::Error::new(error.kind(), self.operation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}
impl Identity {
    pub fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        }
    }
    pub fn matches(self, path: &Path) -> bool {
        fs::symlink_metadata(path)
            .is_ok_and(|meta| !meta.file_type().is_symlink() && self == Self::of(&meta))
    }
}

pub(crate) fn private(meta: &Metadata, uid: u32, mode: u32, errors: Errors) -> io::Result<()> {
    if meta.file_type().is_symlink() || meta.uid() != uid || meta.mode() & 0o7777 != mode {
        return Err(errors.denied());
    }
    Ok(())
}

pub(crate) fn regular(meta: &Metadata, uid: u32, limit: usize, errors: Errors) -> io::Result<()> {
    private(meta, uid, 0o600, errors)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > limit as u64 {
        return Err(errors.invalid());
    }
    Ok(())
}

pub(crate) fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).mode(0o600);
    // NONBLOCK | NOFOLLOW | NOCTTY: the same audited platform ABI as local_file.
    #[cfg(target_os = "macos")]
    options.custom_flags(0x4 | 0x100 | 0x20000);
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    options.custom_flags((1 << 11) | (1 << 17) | (1 << 8));
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    options.custom_flags((1 << 11) | (1 << 15) | (1 << 8));
    options
}

pub(crate) fn directory_path(directory: &Path, uid: u32, errors: Errors) -> io::Result<PathBuf> {
    let Some(Component::Normal(name)) = directory.components().next_back() else {
        return Err(errors.invalid());
    };
    let parent = directory
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|error| errors.redact(error))?;
    for ancestor in parent.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|error| errors.redact(error))?;
        Parents::safe(&meta, uid, errors)?;
    }
    Ok(parent.join(name))
}

#[derive(Clone)]
pub(crate) struct Parents {
    entries: Vec<(PathBuf, Identity)>,
    uid: u32,
    errors: Errors,
}
impl Parents {
    pub fn capture(directory: &Path, uid: u32, errors: Errors) -> io::Result<Self> {
        let mut entries = Vec::new();
        for path in directory
            .parent()
            .ok_or_else(|| errors.invalid())?
            .ancestors()
        {
            let meta = fs::symlink_metadata(path).map_err(|error| errors.redact(error))?;
            Self::safe(&meta, uid, errors)?;
            entries.push((path.to_owned(), Identity::of(&meta)));
        }
        Ok(Self {
            entries,
            uid,
            errors,
        })
    }
    fn safe(meta: &Metadata, uid: u32, errors: Errors) -> io::Result<()> {
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || (meta.uid() != 0 && meta.uid() != uid)
            || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0)
        {
            return Err(errors.denied());
        }
        Ok(())
    }
    pub fn open_parent(&self) -> io::Result<File> {
        self.verify()?;
        let (path, id) = self.entries.first().ok_or_else(|| self.errors.invalid())?;
        let file = options()
            .open(path)
            .map_err(|error| self.errors.redact(error))?;
        let meta = file.metadata().map_err(|error| self.errors.redact(error))?;
        Self::safe(&meta, self.uid, self.errors)?;
        if Identity::of(&meta) != *id {
            return Err(self.errors.denied());
        }
        self.verify()?;
        Ok(file)
    }
    pub fn verify(&self) -> io::Result<()> {
        for (path, id) in &self.entries {
            let current = fs::symlink_metadata(path).map_err(|error| self.errors.redact(error))?;
            Self::safe(&current, self.uid, self.errors)?;
            if Identity::of(&current) != *id {
                return Err(self.errors.denied());
            }
        }
        Ok(())
    }
}

/// A private directory capability with both its descriptor and named ancestry
/// checked. Namespace-specific inventory and file policies stay with callers.
pub(crate) struct Directory {
    pub path: PathBuf,
    pub file: File,
    pub identity: Identity,
    pub uid: u32,
    parents: Parents,
    errors: Errors,
}

impl Directory {
    pub fn open(path: PathBuf, uid: u32, errors: Errors) -> io::Result<Self> {
        let parents = Parents::capture(&path, uid, errors)?;
        let parent = parents.open_parent()?;
        let named = fs::symlink_metadata(&path).map_err(|e| errors.redact(e))?;
        private(&named, uid, 0o700, errors)?;
        if !named.is_dir() {
            return Err(errors.invalid());
        }
        let file = File::from(
            rustix::fs::openat(
                &parent,
                path.file_name().ok_or_else(|| errors.invalid())?,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|e| errors.redact(e.into()))?,
        );
        let identity = Identity::of(&named);
        if identity != Identity::of(&file.metadata().map_err(|e| errors.redact(e))?) {
            return Err(errors.denied());
        }
        let result = Self {
            path,
            file,
            identity,
            uid,
            parents,
            errors,
        };
        result.verify()?;
        Ok(result)
    }

    pub fn verify(&self) -> io::Result<()> {
        self.parents.verify()?;
        for meta in [
            fs::symlink_metadata(&self.path).map_err(|e| self.errors.redact(e))?,
            self.file.metadata().map_err(|e| self.errors.redact(e))?,
        ] {
            private(&meta, self.uid, 0o700, self.errors)?;
            if !meta.is_dir() || Identity::of(&meta) != self.identity {
                return Err(self.errors.denied());
            }
        }
        Ok(())
    }
}
