//! Bounded owned-child transport shared by launchctl and candidate preflight.
//! Captured bytes are never formatted into diagnostics.

/// An observed exit is a fact, not proof of readiness or an operation's effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Exited {
        success: bool,
        code: Option<i32>,
    },
    Unknown {
        reason: UnknownReason,
        child_reaped: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownReason {
    Deadline,
    OutputLimit,
    Transport,
}

#[cfg(any(target_os = "macos", test))]
pub(crate) use runner::Capture;
#[cfg(target_os = "macos")]
pub(crate) use runner::{run, Report};
#[cfg(test)]
pub(crate) use runner::{test_command, test_run, Limits};

#[cfg(any(target_os = "macos", test))]
mod runner {
    use super::{Outcome, UnknownReason};
    use crate::lease::Lease;
    #[cfg(target_os = "macos")]
    use std::ffi::OsStr;
    use std::{
        io,
        path::Path,
        process::{ExitStatus, Stdio},
        time::Duration,
    };
    use tokio::{
        io::AsyncReadExt,
        process::{Child, Command},
    };

    const OUTPUT_LIMIT: usize = 64 * 1024;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Capture {
        /// Connect both output descriptors to the null device before spawning.
        /// No output bytes are observed or included in the pipe output budget.
        Null,
        /// Drain bounded pipes without retaining their contents.
        Discard,
        Stdout(usize),
    }

    /// Deliberately no Debug: caller output is not a diagnostic string.
    pub(crate) struct Report {
        pub outcome: Outcome,
        pub stdout: Vec<u8>,
        /// Always zero for Null because stderr is not observed, not because the
        /// child necessarily wrote zero bytes.
        pub stderr_bytes: usize,
    }

    #[derive(Clone, Copy)]
    pub(crate) struct Limits {
        pub deadline: Duration,
        pub cleanup: Duration,
    }
    impl Limits {
        pub const PRODUCTION: Self = Self {
            deadline: Duration::from_secs(10),
            cleanup: Duration::from_secs(1),
        };
    }

    fn command(program: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }

    #[cfg(target_os = "macos")]
    pub(crate) async fn run(
        program: &Path,
        arguments: &[impl AsRef<OsStr> + Sync],
        capture: Capture,
    ) -> io::Result<Report> {
        let mut command = command(program);
        command.args(arguments);
        run_command(command, capture, Limits::PRODUCTION).await
    }

    #[cfg(test)]
    pub(crate) fn test_command(program: &Path) -> Command {
        command(program)
    }

    #[cfg(test)]
    pub(crate) async fn test_run(
        command: Command,
        capture: Capture,
        limits: Limits,
    ) -> io::Result<Report> {
        run_command(command, capture, limits).await
    }

    async fn reap(child: &mut Child, cleanup: Duration) -> bool {
        if let Ok(Some(_)) = child.try_wait() {
            return true;
        }
        // This targets only our child, never a launchd service. Already-submitted
        // effects cannot be undone by terminating the command process.
        let _ = child.start_kill();
        matches!(tokio::time::timeout(cleanup, child.wait()).await, Ok(Ok(_)))
    }

    async fn run_command(
        mut command: Command,
        capture: Capture,
        limits: Limits,
    ) -> io::Result<Report> {
        let maximum = match capture {
            Capture::Null | Capture::Discard => 0,
            Capture::Stdout(limit) if limit <= OUTPUT_LIMIT => limit,
            Capture::Stdout(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "managed child capture limit is invalid",
                ))
            }
        };
        let mut captured = Vec::new();
        captured.try_reserve_exact(maximum).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "managed child capture allocation failed",
            )
        })?;
        let lease = Lease::new();
        let deadline = lease.deadline_after(limits.deadline).map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "managed child deadline unavailable",
            )
        })?;
        if capture == Capture::Null {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        let mut child = command.spawn().map_err(|error| {
            io::Error::new(error.kind(), "managed child process could not be started")
        })?;
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let mut status: Option<ExitStatus> = None;
        let mut stderr_bytes = 0usize;
        let observed = lease
            .run_until(Some(deadline), async {
                if capture == Capture::Null {
                    return child.wait().await.map_err(|_| UnknownReason::Transport);
                }
                let stdout = stdout.as_mut().expect("piped stdout configured");
                let stderr = stderr.as_mut().expect("piped stderr configured");
                let (mut out_done, mut err_done) = (false, false);
                let mut out = [0_u8; 4096];
                let mut err = [0_u8; 4096];
                let mut bytes = 0_usize;
                loop {
                    if out_done && err_done {
                        if let Some(status) = status {
                            return Ok(status);
                        }
                    }
                    let (count, is_stdout) = tokio::select! {
                        result = child.wait(), if status.is_none() => {
                            status = Some(result.map_err(|_| UnknownReason::Transport)?);
                            continue;
                        }
                        result = stdout.read(&mut out), if !out_done => {
                            let count = result.map_err(|_| UnknownReason::Transport)?;
                            out_done = count == 0;
                            (count, true)
                        }
                        result = stderr.read(&mut err), if !err_done => {
                            let count = result.map_err(|_| UnknownReason::Transport)?;
                            err_done = count == 0;
                            (count, false)
                        }
                    };
                    bytes = bytes.checked_add(count).ok_or(UnknownReason::OutputLimit)?;
                    if bytes > OUTPUT_LIMIT {
                        return Err(UnknownReason::OutputLimit);
                    }
                    if is_stdout {
                        if let Capture::Stdout(_) = capture {
                            if count > maximum - captured.len() {
                                return Err(UnknownReason::OutputLimit);
                            }
                            captured.extend_from_slice(&out[..count]);
                        }
                    } else {
                        stderr_bytes += count; // Combined bytes have already passed the fixed bound.
                    }
                }
            })
            .await;
        drop(stdout);
        drop(stderr);
        let outcome = match observed {
            Ok(Ok(status)) => Outcome::Exited {
                success: status.success(),
                code: status.code(),
            },
            failed => {
                let reason = match failed {
                    Ok(Err(reason)) => reason,
                    Err(_) => UnknownReason::Deadline,
                    Ok(Ok(_)) => unreachable!(),
                };
                let child_reaped = status.is_some() || reap(&mut child, limits.cleanup).await;
                captured.clear();
                Outcome::Unknown {
                    reason,
                    child_reaped,
                }
            }
        };
        Ok(Report {
            outcome,
            stdout: captured,
            stderr_bytes,
        })
    }
}
