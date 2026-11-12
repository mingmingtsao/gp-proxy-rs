//! Typed, bounded launchctl transport. Exit facts are not application readiness.
//!
//! No output text is used as a process, service, or authorization identity.

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    test
))]
use crate::managed_protocol::ManagedIdentity;
use std::{
    future::Future,
    io,
    path::{Path, PathBuf},
};

const LABEL_PREFIX: &str = "io.gp-proxy.";
const MAX_PATH_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    ProbeDomain { uid: u32 },
    ProbeService { uid: u32, label: String },
    Bootstrap { uid: u32, plist: PathBuf },
    Bootout { uid: u32, label: String },
    Enable { uid: u32, label: String },
    Kickstart { uid: u32, label: String },
}

impl Action {
    #[cfg(target_os = "macos")]
    fn uid(&self) -> u32 {
        match self {
            Self::ProbeDomain { uid }
            | Self::ProbeService { uid, .. }
            | Self::Bootstrap { uid, .. }
            | Self::Bootout { uid, .. }
            | Self::Enable { uid, .. }
            | Self::Kickstart { uid, .. } => *uid,
        }
    }

    fn arguments(&self) -> io::Result<Vec<String>> {
        let (uid, command, suffix) = match self {
            Self::ProbeDomain { uid } => (*uid, "print", None),
            Self::ProbeService { uid, label } => (*uid, "print", Some(label)),
            Self::Bootstrap { uid, .. } => (*uid, "bootstrap", None),
            Self::Bootout { uid, label } => (*uid, "bootout", Some(label)),
            Self::Enable { uid, label } => (*uid, "enable", Some(label)),
            Self::Kickstart { uid, label } => (*uid, "kickstart", Some(label)),
        };
        validate_uid(uid)?;
        let mut target = format!("gui/{uid}");
        if let Some(label) = suffix {
            validate_label(label)?;
            target.push('/');
            target.push_str(label);
        }
        let mut arguments = vec![command.to_owned(), target];
        if let Self::Bootstrap { plist, .. } = self {
            arguments.push(validate_path(plist)?.to_owned());
        }
        Ok(arguments)
    }
}

pub(crate) use crate::managed_child::Outcome;

pub trait Executor {
    fn execute(&self, action: Action) -> impl Future<Output = io::Result<Outcome>> + Send;
}

pub(crate) struct Native;

impl Executor for Native {
    async fn execute(&self, action: Action) -> io::Result<Outcome> {
        let arguments = action.arguments()?;
        #[cfg(target_os = "macos")]
        {
            let uid = rustix::process::geteuid().as_raw();
            if uid == 0 || action.uid() != uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "launchd management requires the current non-root user",
                ));
            }
            crate::managed_child::run(
                Path::new("/bin/launchctl"),
                &arguments,
                crate::managed_child::Capture::Null,
            )
            .await
            .map(|report| report.outcome)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = arguments;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "launchd management is unavailable on this platform",
            ))
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid launchd management request",
    )
}

fn validate_uid(uid: u32) -> io::Result<()> {
    if uid == 0 {
        Err(invalid())
    } else {
        Ok(())
    }
}

fn validate_label(label: &str) -> io::Result<()> {
    let Some(suffix) = label.strip_prefix(LABEL_PREFIX) else {
        return Err(invalid());
    };
    let Some((installation, generation)) = suffix.split_once(".g") else {
        return Err(invalid());
    };
    if installation.len() != 32
        || generation.len() != 16
        || [installation, generation].into_iter().any(|part| {
            part.bytes().all(|byte| byte == b'0')
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(invalid());
    }
    Ok(())
}

/// A job label is never reused for a different admitted generation. A delayed
/// removal of a retired job therefore cannot name its replacement.
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    test
))]
pub(crate) fn label_for(identity: &ManagedIdentity) -> io::Result<String> {
    identity.validate().map_err(|_| invalid())?;
    Ok(format!(
        "{LABEL_PREFIX}{:032x}.g{:016x}",
        u128::from_be_bytes(identity.installation),
        identity.generation
    ))
}

fn validate_path(path: &Path) -> io::Result<&str> {
    let value = path.to_str().ok_or_else(invalid)?;
    if !path.is_absolute() || value.len() > MAX_PATH_BYTES || !value.chars().all(xml_character) {
        return Err(invalid());
    }
    Ok(value)
}

fn xml_character(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    test
))]
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    test
))]
fn xml_string(output: &mut String, value: &str) {
    output.push_str("<string>");
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            // Character references preserve CR rather than XML newline normalization.
            '\r' => output.push_str("&#13;"),
            _ => output.push(character),
        }
    }
    output.push_str("</string>\n");
}

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    test
))]
pub(crate) fn render_plist(
    uid: u32,
    label: &str,
    binary: &Path,
    runtime_dir: &Path,
    identity: &ManagedIdentity,
) -> io::Result<Vec<u8>> {
    validate_uid(uid)?;
    validate_label(label)?;
    if label != label_for(identity)? {
        return Err(invalid());
    }
    let binary = validate_path(binary)?;
    let runtime_dir = validate_path(runtime_dir)?;
    let installation = hex(&identity.installation);
    let generation = identity.generation.to_string();
    let release = hex(&identity.release);
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key>\n");
    xml_string(&mut output, label);
    output.push_str("<key>ProgramArguments</key><array>\n");
    for argument in [
        binary,
        "managed-run",
        "--runtime-dir",
        runtime_dir,
        "--installation",
        &installation,
        "--generation",
        &generation,
        "--release",
        &release,
    ] {
        xml_string(&mut output, argument);
    }
    output.push_str("</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>30</integer>\n<key>ExitTimeOut</key><integer>60</integer>\n<key>Umask</key><integer>63</integer>\n<key>StandardOutPath</key><string>/dev/null</string>\n<key>StandardErrorPath</key><string>/dev/null</string>\n</dict></plist>\n");
    Ok(output.into_bytes())
}

#[cfg(test)]
#[path = "../tests/support/launchd_executor.rs"]
mod tests;
