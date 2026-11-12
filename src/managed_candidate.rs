//! Execute only a pinned, explicitly selected candidate, with fixed arguments.
//! A matching digest and self-declared capabilities do not authenticate a
//! publisher or make hostile executable code safe to run.

use crate::managed_protocol::Capabilities;
use std::{io, path::Path};

pub(crate) async fn validate(
    binary: &Path,
    expected: [u8; 32],
    config: &Path,
) -> io::Result<Capabilities> {
    #[cfg(unix)]
    {
        validate_with(binary, expected, config, &Native)
            .await
            .map_err(redact)
    }
    #[cfg(not(unix))]
    {
        let _ = (binary, expected, config);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed candidate preflight is unavailable",
        ))
    }
}

#[cfg(unix)]
fn redact(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "managed candidate preflight failed")
}

#[cfg(unix)]
use crate::{
    managed_child::{self, Capture, Outcome, Report, UnknownReason},
    managed_protocol::MAX_CAPABILITIES_BYTES,
    managed_release::Source,
};
#[cfg(unix)]
use std::{ffi::OsString, future::Future};

#[cfg(unix)]
trait Runner {
    fn execute(
        &self,
        binary: &Path,
        arguments: &[OsString],
        capture: Capture,
    ) -> impl Future<Output = io::Result<Report>> + Send;
}
#[cfg(unix)]
struct Native;
#[cfg(unix)]
impl Runner for Native {
    async fn execute(
        &self,
        binary: &Path,
        arguments: &[OsString],
        capture: Capture,
    ) -> io::Result<Report> {
        managed_child::run(binary, arguments, capture).await
    }
}

#[cfg(unix)]
fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|text| text.len() <= 1024 && !text.chars().any(char::is_control))
}

#[cfg(unix)]
fn success(report: &Report) -> io::Result<()> {
    match report.outcome {
        Outcome::Exited {
            success: true,
            code: Some(0),
        } => Ok(()),
        Outcome::Unknown {
            reason: UnknownReason::Deadline,
            ..
        } => Err(io::ErrorKind::TimedOut.into()),
        Outcome::Unknown {
            reason: UnknownReason::Transport,
            ..
        } => Err(io::ErrorKind::Other.into()),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

#[cfg(unix)]
async fn validate_with(
    binary: &Path,
    expected: [u8; 32],
    config: &Path,
    runner: &impl Runner,
) -> io::Result<Capabilities> {
    if !valid_path(binary) || !valid_path(config) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let source = Source::open(binary)?;
    if source.digest() != expected {
        return Err(io::ErrorKind::InvalidData.into());
    }
    source.verify()?;
    let declaration = runner
        .execute(
            binary,
            &["service".into(), "capabilities".into()],
            Capture::Stdout(MAX_CAPABILITIES_BYTES),
        )
        .await;
    source.verify()?;
    let declaration = declaration?;
    success(&declaration)?;
    if declaration.stderr_bytes != 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let capabilities = Capabilities::parse(&declaration.stdout)?;
    source.verify()?;
    let check = runner
        .execute(
            binary,
            &[
                "--config".into(),
                config.as_os_str().to_owned(),
                "check".into(),
            ],
            Capture::Discard,
        )
        .await;
    source.verify()?;
    success(&check?)?;
    Ok(capabilities)
}

#[cfg(all(test, unix))]
#[path = "../tests/support/managed_candidate.rs"]
mod tests;
