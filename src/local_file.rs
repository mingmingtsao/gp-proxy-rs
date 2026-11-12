//! Bounded file snapshots for public configuration/CA inputs and private secrets.
//! Public inputs resolve a deployment symlink once; private inputs never do.
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

pub(crate) const SECRET_MAX_BYTES: usize = 64 * 1024;
pub(crate) const PUBLIC_MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Secret,
    Public,
}
impl Access {
    fn limit(self) -> usize {
        match self {
            Self::Secret => SECRET_MAX_BYTES,
            Self::Public => PUBLIC_MAX_BYTES,
        }
    }
    fn size_error(self) -> io::Error {
        invalid(match self {
            Self::Secret => "local input file exceeds 64 KiB limit",
            Self::Public => "local input file exceeds 1 MiB limit",
        })
    }
}

pub(crate) fn read(path: &Path, access: Access) -> io::Result<Zeroizing<Vec<u8>>> {
    read_with(path, access, |_| {})
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Inspected,
    Opened,
    Read,
}

pub(crate) fn read_with(
    path: &Path,
    access: Access,
    mut checkpoint: impl FnMut(Stage),
) -> io::Result<Zeroizing<Vec<u8>>> {
    // Validate platform/path support before canonicalization (notably Windows
    // device/UNC paths), and validate the resolved destination again below.
    options(path, access)?;
    let selected = match access {
        Access::Secret => path.to_path_buf(),
        Access::Public => {
            fs::canonicalize(path).map_err(|e| redact(e, "cannot resolve local input file"))?
        }
    };
    let path = selected.as_path();
    let options = options(path, access)?;
    let before = named_metadata(path)?;
    validate(&before, access)?;
    checkpoint(Stage::Inspected);
    let mut file = options
        .open(path)
        .map_err(|e| redact(e, "cannot open local input file"))?;
    verify(path, &file, &before, access)?;
    checkpoint(Stage::Opened);
    // Allocate before reading any input. Growing a secret-bearing Vec could
    // release an old allocation which its final Zeroizing owner cannot wipe.
    // The snapshot length is already bounded by validate(); one extra byte
    // detects growth without reading an arbitrarily enlarged file.
    let source = read_snapshot(&mut file, before.len() as usize)?;
    if source.len() > access.limit() {
        return Err(access.size_error());
    }
    checkpoint(Stage::Read);
    verify(path, &file, &before, access)?;
    if source.len() as u64 != before.len() {
        return Err(invalid("local input file changed during reading"));
    }
    Ok(source)
}

fn read_snapshot(reader: &mut impl Read, expected: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut source = Zeroizing::new(vec![0; expected + 1]);
    let mut filled = 0;
    while filled < source.len() {
        match reader.read(&mut source[filled..]) {
            Ok(0) => break,
            Ok(size) => filled += size,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(redact(error, "cannot read local input file")),
        }
    }
    source.truncate(filled);
    Ok(source)
}

fn named_metadata(path: &Path) -> io::Result<Metadata> {
    fs::symlink_metadata(path).map_err(|e| redact(e, "cannot inspect local input file"))
}
fn validate(metadata: &Metadata, access: Access) -> io::Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "local input file must be regular and not a symlink",
        ));
    }
    if metadata.len() > access.limit() as u64 {
        return Err(access.size_error());
    }
    #[cfg(unix)]
    if access == Access::Secret {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local input file permissions must exclude group and other users; use chmod 600",
            ));
        }
        if metadata.nlink() != 1 {
            return Err(invalid("local input file must not have hard links"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT, checked after resolving public links.
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("local input file must not be a reparse point"));
        }
    }
    Ok(())
}
fn verify(path: &Path, file: &File, before: &Metadata, access: Access) -> io::Result<()> {
    let named = named_metadata(path)?;
    let opened = file
        .metadata()
        .map_err(|e| redact(e, "cannot inspect opened local input file"))?;
    for current in [&named, &opened] {
        validate(current, access)?;
        if !same_snapshot(before, current)? {
            return Err(invalid("local input file changed during access"));
        }
    }
    Ok(())
}
fn same_snapshot(before: &Metadata, after: &Metadata) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.mode() != after.mode()
            || before.uid() != after.uid()
            || before.gid() != after.gid()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Ok(false);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Stable std does not expose Windows file ID/link count or ACLs.
        // These fields are additional consistency checks, not an inode proof.
        if before.creation_time() != after.creation_time()
            || before.file_attributes() != after.file_attributes()
        {
            return Ok(false);
        }
    }
    let modified = |m: &Metadata| {
        m.modified()
            .map_err(|e| redact(e, "cannot inspect local input file modification time"))
    };
    Ok(before.len() == after.len() && modified(before)? == modified(after)?)
}

fn options(path: &Path, access: Access) -> io::Result<OpenOptions> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Apple XNU bsd/sys/fcntl.h: O_NONBLOCK | O_NOFOLLOW | O_NOCTTY.
        // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fcntl.h
        options.custom_flags(0x4 | 0x100 | 0x20000);
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux UAPI asm-generic/fcntl.h on x86_64:
        // O_NONBLOCK | O_NOFOLLOW | O_NOCTTY. Other Linux ABIs may differ.
        // https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/fcntl.h
        options.custom_flags((1 << 11) | (1 << 17) | (1 << 8));
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // arm64 overrides O_NOFOLLOW to 1 << 15 for AArch32 compatibility.
        // https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/fcntl.h
        options.custom_flags((1 << 11) | (1 << 15) | (1 << 8));
    }
    #[cfg(windows)]
    {
        use std::{
            os::windows::fs::OpenOptionsExt,
            path::{Component, Prefix},
        };
        for component in path.components() {
            if let Component::Prefix(prefix) = component {
                if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
                    return Err(invalid("local input file must use a local disk path"));
                }
            }
        }
        // Microsoft CreateFileW: OPEN_REPARSE_POINT and
        // SECURITY_ANONYMOUS (0) with SECURITY_SQOS_PRESENT set by std.
        // Public inputs allow concurrent readers (FILE_SHARE_READ = 1),
        // but neither writers nor replacement; secrets retain no sharing.
        // https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
        options
            .custom_flags(0x0020_0000)
            .share_mode(if access == Access::Secret { 0 } else { 1 })
            .security_qos_flags(0);
    }
    #[cfg(not(windows))]
    let _ = (path, access);
    if !cfg!(any(
        windows,
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "safe local input file opening is unavailable on this platform",
        ));
    }
    Ok(options)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn redact(error: io::Error, message: &'static str) -> io::Error {
    io::Error::new(error.kind(), message)
}
#[cfg(test)]
mod tests;
