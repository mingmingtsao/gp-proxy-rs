//! Private-secret policy over the shared bounded local-file reader.
use crate::local_file::{self, Access, Stage};
use std::{io, path::Path};
use zeroize::Zeroizing;

pub(crate) const MAX_BYTES: usize = local_file::SECRET_MAX_BYTES;

pub(crate) fn read(path: &Path) -> io::Result<Zeroizing<String>> {
    read_with(path, |_| {})
}

fn read_with(path: &Path, checkpoint: impl FnMut(Stage)) -> io::Result<Zeroizing<String>> {
    let mut bytes = local_file::read_with(path, Access::Secret, checkpoint).map_err(|error| {
        // The shared reader's diagnostics contain only static descriptions.
        io::Error::new(error.kind(), format!("private credential file: {error}"))
    })?;
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(source) => Ok(Zeroizing::new(source)),
        Err(error) => {
            let _discard = Zeroizing::new(error.into_bytes());
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot read private credential file as UTF-8",
            ))
        }
    }
}

#[cfg(test)]
mod tests;
